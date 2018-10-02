// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <bench.h>
#include <compiler.h>
#include <initcall.h>
#include <io.h>
#include <kernel/linker.h>
#include <kernel/msg_param.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/task.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/tee_cryp_utl.h>
#include <tee/uuid.h>
#include <util.h>

#define SHM_CACHE_ATTRS	\
	(uint32_t)(core_mmu_is_shm_cached() ?  OPTEE_SMC_SHM_CACHED : 0)

/* Cancellation related constants: */
/* Keep a buffer of at most this many cancellation requests that refer to a
 * task that is not currently registered. This is to properly handle
 * cancellation requests that arrive before the corresponding task is actually
 * registered.
 * TODO: Convert this into an actual configuration value.
 */
#define CFG_MAX_PENDING_CANCELLATIONS 5
/* Discard pending cancellation requests after this many seconds. */
#define CANCELLATION_TIMEOUT_SECONDS 2

/* Sessions opened from normal world */
static struct tee_ta_session_head tee_open_sessions =
TAILQ_HEAD_INITIALIZER(tee_open_sessions);

static struct mobj *shm_mobj;
#ifdef CFG_SECURE_DATA_PATH
static struct mobj **sdp_mem_mobjs;
#endif

static unsigned int session_pnum;

/* Cancellation-related types: */
struct cancel_info {
	uint32_t context_id;
	uint32_t cancel_id;
};

struct pending_cancellation {
	bool used;
	struct cancel_info cancel_info;
	TEE_Time timestamp;
};

struct registered_task {
	bool used;
	struct task *task;
	uint32_t session;
	struct cancel_info cancel_info;
};

enum registration_result { REGISTERED, NOT_NEEDED, CANCEL };

/* Cancellation-related local variables: */
static struct registered_task registered_tasks[CFG_NUM_THREADS];
static struct pending_cancellation cancellations[CFG_MAX_PENDING_CANCELLATIONS];
static struct mutex cancel_mutex = MUTEX_INITIALIZER;

/* Cancellation-related local functions: */
static bool match_cancel_info(const struct cancel_info info,
		const struct optee_msg_arg *arg)
{
	return info.context_id == arg->context_id
		&& info.cancel_id == arg->cancel_id;
}

static bool cancellation_expired(const struct pending_cancellation *pend,
		TEE_Time now)
{
	uint32_t thresh;

	if (SUB_OVERFLOW(now.seconds, CANCELLATION_TIMEOUT_SECONDS, &thresh))
		return true;

	if (pend->timestamp.seconds < thresh)
		return true;
	else if (pend->timestamp.seconds == thresh)
		return pend->timestamp.millis < now.millis;
	else
		return false;
}

static bool try_remove_pending_cancellation(const struct optee_msg_arg *arg)
{
	/* cancel_mutex must be held when calling this function. */
	for (size_t i = 0; i < CFG_MAX_PENDING_CANCELLATIONS; i++) {
		struct pending_cancellation *pend = &cancellations[i];

		if (pend->used && match_cancel_info(pend->cancel_info, arg)) {
			pend->used = false;

			return true;
		}
	}

	return false;
}

static void invalidate_pending_cancellations(uint32_t context_id)
{
	assert(context_id != 0);

	mutex_lock(&cancel_mutex);
	for (size_t i = 0; i < CFG_MAX_PENDING_CANCELLATIONS; i++) {
		struct pending_cancellation *pend = &cancellations[i];

		if (pend->used && pend->cancel_info.context_id == context_id)
			pend->used = false;
	}
	mutex_unlock(&cancel_mutex);
}

static enum registration_result register_task_per_task(struct task *task,
		const struct optee_msg_arg *arg)
{
	int tid;
	enum registration_result res;
	bool prev_used = false;

	if (arg->cancel_id == 0)
		return NOT_NEEDED;

	tid = thread_get_id();

	mutex_lock(&cancel_mutex);
	if (try_remove_pending_cancellation(arg)) {
		/* The task was cancelled before it was registered. */
		res = CANCEL;
	} else {
		/* No cancellation pending, register the task. */
		struct registered_task *reg = &registered_tasks[tid];

		reg->task = task;
		reg->cancel_info.context_id = arg->context_id;
		reg->cancel_info.cancel_id = arg->cancel_id;
		reg->session = 0;
		prev_used = reg->used;
		reg->used = true;

		res = REGISTERED;
	}
	mutex_unlock(&cancel_mutex);

	assert(!prev_used);

	return res;
}

static enum registration_result register_task_per_session(struct task *task,
		const struct optee_msg_arg *arg)
{
	int tid = thread_get_id();
	bool prev_used;
	struct registered_task *reg = &registered_tasks[tid];

	mutex_lock(&cancel_mutex);
	reg->task = task;
	reg->cancel_info.context_id = 0;
	reg->cancel_info.cancel_id = 0;
	reg->session = arg->session;
	prev_used = reg->used;
	reg->used = true;
	mutex_unlock(&cancel_mutex);

	assert(!prev_used);

	return REGISTERED;
}

static enum registration_result register_cancellable_task(struct task *task,
		const struct optee_msg_arg *arg)
{
	assert(task != NULL);
	assert(arg != NULL);

	if (arg->context_id != 0) {
		/* new-style per-task cancellations */
		return register_task_per_task(task, arg);
	} else if (arg->session != 0) {
		/* old-style per-session cancellations */
		return register_task_per_session(task, arg);
	} else {
		return NOT_NEEDED;
	}
}

static void unregister_cancellable_task(struct task *task)
{
	int tid = thread_get_id();
	bool prev_used;
	struct task *prev_task;

	assert(task != NULL);

	mutex_lock(&cancel_mutex);
	prev_used = registered_tasks[tid].used;
	registered_tasks[tid].used = false;
	prev_task = registered_tasks[tid].task;
	registered_tasks[tid].task = NULL;
	mutex_unlock(&cancel_mutex);

	assert(prev_used);
	assert(prev_task == task);
}

static TEE_Result cancel_request_per_task(const struct optee_msg_arg *arg)
{
	TEE_Result res;
	TEE_Time now;
	struct pending_cancellation *pend;
	int free_slot;

	res = tee_time_get_sys_time(&now);
	if (res != TEE_SUCCESS)
		return res;

	mutex_lock(&cancel_mutex);

	/* First: Check if a matching task is currently registered. */
	for (size_t i = 0; i < CFG_NUM_THREADS; i++) {
		struct registered_task *reg = &registered_tasks[i];

		if (reg->used && match_cancel_info(reg->cancel_info, arg)) {
			task_cancel(reg->task);
			thread_kill(i);
			res = TEE_SUCCESS;

			goto out;
		}
	}

	/* Otherwise: Check if there's already a pending cancellation. */
	free_slot = -1;
	for (size_t i = 0; i < CFG_MAX_PENDING_CANCELLATIONS; i++) {
		pend = &cancellations[i];

		if (pend->used) {
			if (match_cancel_info(pend->cancel_info, arg)) {
				pend->timestamp = now;
				res = TEE_SUCCESS;

				goto out;
			} else if (cancellation_expired(pend, now)) {
				/* Use the opportunity to do some garbage
				 * collection.
				 */
				pend->used = false;
			}
		} else {
			free_slot = i;
		}
	}

	/* Last option: Add a new pending cancellation. */
	if (free_slot == -1) {
		/* All pending cancellation slots in use. */
		res = TEE_ERROR_BUSY;

		goto out;
	}

	pend = &cancellations[free_slot];
	pend->cancel_info.context_id = arg->context_id;
	pend->cancel_info.cancel_id = arg->cancel_id;
	pend->timestamp = now;
	pend->used = true;

	res = TEE_SUCCESS;

out:
	mutex_unlock(&cancel_mutex);

	return res;
}

static TEE_Result cancel_request_per_session(const struct optee_msg_arg *arg)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&cancel_mutex);
	for (size_t i = 0; i < CFG_NUM_THREADS; i++) {
		struct registered_task *reg = &registered_tasks[i];

		if (reg->used && reg->session == arg->session) {
			task_cancel(reg->task);
			res = TEE_SUCCESS;
		}
	}
	mutex_unlock(&cancel_mutex);

	return res;
}
/* End of cancellation-related functions. */

static bool param_mem_from_mobj(struct param_mem *mem, struct mobj *mobj,
				const paddr_t pa, const size_t sz)
{
	paddr_t b;

	if (mobj_get_pa(mobj, 0, 0, &b) != TEE_SUCCESS)
		panic("mobj_get_pa failed");

	if (!core_is_buffer_inside(pa, MAX(sz, 1UL), b, mobj->size))
		return false;

	mem->mobj = mobj;
	mem->offs = pa - b;
	mem->size = sz;
	return true;
}

/* fill 'struct param_mem' structure if buffer matches a valid memory object */
static TEE_Result set_tmem_param(const struct optee_msg_param_tmem *tmem,
				 uint32_t attr, struct param_mem *mem,
				 uint64_t *shm_ref_ret)
{
	struct mobj __maybe_unused **mobj;
	paddr_t pa = READ_ONCE(tmem->buf_ptr);
	size_t sz = READ_ONCE(tmem->size);

	/* NULL Memory Rerefence? */
	if (!pa && !sz) {
		mem->mobj = NULL;
		mem->offs = 0;
		mem->size = 0;
		return TEE_SUCCESS;
	}

	/* Non-contigous buffer from non sec DDR? */
	if (attr & OPTEE_MSG_ATTR_NONCONTIG) {
		uint64_t shm_ref = READ_ONCE(tmem->shm_ref);

		mem->mobj = msg_param_mobj_from_noncontig(pa, sz, shm_ref,
							  false);
		if (!mem->mobj)
			return TEE_ERROR_BAD_PARAMETERS;
		mem->offs = 0;
		mem->size = sz;
		*shm_ref_ret = shm_ref;
		return TEE_SUCCESS;
	}

	/* Belongs to nonsecure shared memory? */
	if (param_mem_from_mobj(mem, shm_mobj, pa, sz))
		return TEE_SUCCESS;

#ifdef CFG_SECURE_DATA_PATH
	/* Belongs to SDP memories? */
	for (mobj = sdp_mem_mobjs; *mobj; mobj++)
		if (param_mem_from_mobj(mem, *mobj, pa, sz))
			return TEE_SUCCESS;
#endif

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result set_rmem_param(const struct optee_msg_param_rmem *rmem,
				 struct param_mem *mem, uint64_t *shm_ref_ret)
{
	uint64_t shm_ref = READ_ONCE(rmem->shm_ref);

	mem->mobj = mobj_reg_shm_get_by_cookie(shm_ref);
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = READ_ONCE(rmem->offs);
	mem->size = READ_ONCE(rmem->size);
	*shm_ref_ret = shm_ref;

	return TEE_SUCCESS;
}

static TEE_Result copy_in_params(const struct optee_msg_param *params,
				 uint32_t num_params,
				 struct tee_ta_param *ta_param,
				 uint64_t *saved_attr, uint64_t *saved_shm_ref)
{
	TEE_Result res;
	size_t n;
	uint8_t pt[TEE_NUM_PARAMS] = { 0 };

	if (num_params > TEE_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(ta_param, 0, sizeof(*ta_param));

	for (n = 0; n < num_params; n++) {
		uint32_t attr;

		saved_attr[n] = READ_ONCE(params[n].attr);

		if (saved_attr[n] & OPTEE_MSG_ATTR_META)
			return TEE_ERROR_BAD_PARAMETERS;

		attr = saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK;
		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			pt[n] = TEE_PARAM_TYPE_NONE;
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			pt[n] = TEE_PARAM_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			ta_param->u[n].val.a = READ_ONCE(params[n].u.value.a);
			ta_param->u[n].val.b = READ_ONCE(params[n].u.value.b);
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			res = set_tmem_param(&params[n].u.tmem, saved_attr[n],
					     &ta_param->u[n].mem,
					     saved_shm_ref + n);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			break;
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			res = set_rmem_param(&params[n].u.rmem,
					     &ta_param->u[n].mem,
					     saved_shm_ref + n);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	ta_param->types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return TEE_SUCCESS;
}

static void cleanup_shm_refs(const uint64_t *saved_attr,
			     const uint64_t *saved_shm_ref, uint32_t num_params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (saved_attr[n]) {
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			if (saved_attr[n] & OPTEE_MSG_ATTR_NONCONTIG)
				mobj_reg_shm_free_by_cookie(saved_shm_ref[n]);
			break;

		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			mobj_reg_shm_put_by_cookie(saved_shm_ref[n]);
			break;
		default:
			break;
		}
	}
}

static void copy_out_param(struct tee_ta_param *ta_param, uint32_t num_params,
			   struct optee_msg_param *params, uint64_t *saved_attr)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(ta_param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			switch (saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK) {
			case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
				params[n].u.tmem.size = ta_param->u[n].mem.size;
				break;
			case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
				params[n].u.rmem.size = ta_param->u[n].mem.size;
				break;
			default:
				break;
			}
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = ta_param->u[n].val.a;
			params[n].u.value.b = ta_param->u[n].val.b;
			break;
		default:
			break;
		}
	}
}

/*
 * Extracts mandatory parameter for open session.
 *
 * Returns
 * false : mandatory parameter wasn't found or malformatted
 * true  : paramater found and OK
 */
static TEE_Result get_open_session_meta(size_t num_params,
					struct optee_msg_param *params,
					size_t *num_meta, TEE_UUID *uuid,
					TEE_Identity *clnt_id)
{
	const uint32_t req_attr = OPTEE_MSG_ATTR_META |
				  OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;

	if (num_params < 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].attr != req_attr || params[1].attr != req_attr)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_uuid_from_octets(uuid, (void *)&params[0].u.value);
	clnt_id->login = params[1].u.value.c;
	switch (clnt_id->login) {
	case TEE_LOGIN_PUBLIC:
		memset(&clnt_id->uuid, 0, sizeof(clnt_id->uuid));
		break;
	case TEE_LOGIN_USER:
	case TEE_LOGIN_GROUP:
	case TEE_LOGIN_APPLICATION:
	case TEE_LOGIN_APPLICATION_USER:
	case TEE_LOGIN_APPLICATION_GROUP:
		tee_uuid_from_octets(&clnt_id->uuid,
				     (void *)&params[1].u.value);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*num_meta = 2;
	return TEE_SUCCESS;
}

static void entry_open_session(struct thread_smc_args *smc_args,
			       struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s = NULL;
	TEE_Identity clnt_id;
	TEE_UUID uuid;
	struct tee_ta_param param;
	size_t num_meta;
	uint64_t saved_attr[TEE_NUM_PARAMS];
	uint64_t saved_shm_ref[TEE_NUM_PARAMS];

	res = get_open_session_meta(num_params, arg->params, &num_meta, &uuid,
				    &clnt_id);
	if (res != TEE_SUCCESS)
		goto out;

	res = copy_in_params(arg->params + num_meta, num_params - num_meta,
			     &param, saved_attr, saved_shm_ref);
	if (res != TEE_SUCCESS)
		goto cleanup_shm_refs;

	res = tee_ta_open_session(&err_orig, &s, &tee_open_sessions, &uuid,
				  &clnt_id, &param);
	if (res != TEE_SUCCESS)
		s = NULL;
	copy_out_param(&param, num_params - num_meta, arg->params + num_meta,
		       saved_attr);

	/*
	 * The occurrence of open/close session command is usually
	 * un-predictable, using this property to increase randomness
	 * of prng
	 */
	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

cleanup_shm_refs:
	cleanup_shm_refs(saved_attr, saved_shm_ref, num_params - num_meta);

out:
	if (s)
		arg->session = (vaddr_t)s;
	else
		arg->session = 0;
	arg->ret = res;
	arg->ret_origin = err_orig;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_close_session(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

	s = (struct tee_ta_session *)(vaddr_t)arg->session;
	res = tee_ta_close_session(s, &tee_open_sessions, NSAPP_IDENTITY);
out:
	arg->ret = res;
	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_invoke_command(struct thread_smc_args *smc_args,
				 struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s;
	struct tee_ta_param param = { 0 };
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };
	uint64_t saved_shm_ref[TEE_NUM_PARAMS] = { 0 };

	bm_timestamp();

	res = copy_in_params(arg->params, num_params, &param, saved_attr,
			     saved_shm_ref);
	if (res != TEE_SUCCESS)
		goto out;

	s = tee_ta_get_session(arg->session, true, &tee_open_sessions);
	if (!s) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = tee_ta_invoke_command(&err_orig, s, NSAPP_IDENTITY,
				    arg->func, &param);

	bm_timestamp();

	tee_ta_put_session(s);

	copy_out_param(&param, num_params, arg->params, saved_attr);

out:
	cleanup_shm_refs(saved_attr, saved_shm_ref, num_params);

	arg->ret = res;
	arg->ret_origin = err_orig;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_cancel(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (arg->context_id != 0) {
		/* new-style per-task cancellations */
		if (arg->cancel_id != 0)
			res = cancel_request_per_task(arg);
		else
			res = TEE_ERROR_BAD_PARAMETERS;
	} else if (arg->session != 0) {
		/* old-style per-session cancellations */
		res = cancel_request_per_session(arg);
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
	}

out:
	arg->ret = res;
	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_invalidate_cancellations(struct thread_smc_args *smc_args,
		struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res = TEE_SUCCESS;

	if (num_params != 0 || arg->context_id == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;

		goto out;
	}

	invalidate_pending_cancellations(arg->context_id);

out:
	arg->ret = res;
	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void register_shm(struct thread_smc_args *smc_args,
			 struct optee_msg_arg *arg, uint32_t num_params)
{
	if (num_params != 1 ||
	    (arg->params[0].attr !=
	     (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT | OPTEE_MSG_ATTR_NONCONTIG))) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	/* We don't need mobj pointer there, we only care if it was created */
	if (!msg_param_mobj_from_noncontig(arg->params[0].u.tmem.buf_ptr,
					   arg->params[0].u.tmem.size,
					   arg->params[0].u.tmem.shm_ref,
					   false))
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
	else
		arg->ret = TEE_SUCCESS;

	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void unregister_shm(struct thread_smc_args *smc_args,
			   struct optee_msg_arg *arg, uint32_t num_params)
{
	if (num_params == 1) {
		uint64_t cookie = arg->params[0].u.rmem.shm_ref;
		TEE_Result res = mobj_reg_shm_release_by_cookie(cookie);

		if (res)
			EMSG("Can't find mapping with given cookie");
		arg->ret = res;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}

	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static struct mobj *map_cmd_buffer(paddr_t parg, uint32_t *num_params)
{
	struct mobj *mobj;
	struct optee_msg_arg *arg;
	size_t args_size;

	assert(!(parg & SMALL_PAGE_MASK));
	/* mobj_mapped_shm_alloc checks if parg resides in nonsec ddr */
	mobj = mobj_mapped_shm_alloc(&parg, 1, 0, 0);
	if (!mobj)
		return NULL;

	arg = mobj_get_va(mobj, 0);
	if (!arg) {
		mobj_free(mobj);
		return NULL;
	}

	*num_params = READ_ONCE(arg->num_params);
	args_size = OPTEE_MSG_GET_ARG_SIZE(*num_params);
	if (args_size > SMALL_PAGE_SIZE) {
		EMSG("Command buffer spans across page boundary");
		mobj_free(mobj);
		return NULL;
	}

	return mobj;
}

static struct mobj *get_cmd_buffer(paddr_t parg, uint32_t *num_params)
{
	struct optee_msg_arg *arg;
	size_t args_size;

	arg = phys_to_virt(parg, MEM_AREA_NSEC_SHM);
	if (!arg)
		return NULL;

	*num_params = READ_ONCE(arg->num_params);
	args_size = OPTEE_MSG_GET_ARG_SIZE(*num_params);

	return mobj_shm_alloc(parg, args_size);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak tee_entry_std(struct thread_smc_args *smc_args)
{
	/* TODO: this function has become too long, split it up */
	paddr_t parg;
	struct optee_msg_arg *arg = NULL;	/* fix gcc warning */
	uint32_t num_params = 0;		/* fix gcc warning */
	struct mobj *mobj;
	enum registration_result reg_res = NOT_NEEDED;
	struct task *task = NULL;


	if (smc_args->a0 != OPTEE_SMC_CALL_WITH_ARG) {
		EMSG("Unknown SMC 0x%" PRIx64, (uint64_t)smc_args->a0);
		DMSG("Expected 0x%x\n", OPTEE_SMC_CALL_WITH_ARG);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		return;
	}
	parg = (uint64_t)smc_args->a1 << 32 | smc_args->a2;

	/* Check if this region is in static shared space */
	if (core_pbuf_is(CORE_MEM_NSEC_SHM, parg,
			  sizeof(struct optee_msg_arg))) {
		mobj = get_cmd_buffer(parg, &num_params);
	} else {
		if (parg & SMALL_PAGE_MASK) {
			smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
			return;
		}
		mobj = map_cmd_buffer(parg, &num_params);
	}

	if (!mobj || !ALIGNMENT_IS_OK(parg, struct optee_msg_arg)) {
		EMSG("Bad arg address 0x%" PRIxPA, parg);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;

		goto out;
	}

	arg = mobj_get_va(mobj, 0);
	assert(arg && mobj_is_nonsec(mobj));

	/* Begin new task if necessary. */
	if (arg->cmd == OPTEE_MSG_CMD_OPEN_SESSION
			|| arg->cmd == OPTEE_MSG_CMD_INVOKE_COMMAND
			|| arg->cmd == OPTEE_MSG_CMD_CLOSE_SESSION) {
		TEE_Result res;

		res = task_begin(true, &task);
		if (res != TEE_SUCCESS) {
			smc_args->a0 = OPTEE_SMC_RETURN_OK;
			arg->ret = res;
			arg->ret_origin = TEE_ORIGIN_TEE;

			goto out;
		}

		/* Additionally, OpenSession and InvokeCommand are cancellable
		 * commands and have to be registered.
		 */
		if (arg->cmd != OPTEE_MSG_CMD_CLOSE_SESSION) {
			reg_res = register_cancellable_task(task, arg);
			if (reg_res == CANCEL) {
				/* The task had a pending cancellation request
				 * and must not be executed.
				 */
				smc_args->a0 = OPTEE_SMC_RETURN_OK;
				arg->ret = TEE_ERROR_CANCEL;
				arg->ret_origin = TEE_ORIGIN_TEE;

				goto out;
			}
		}
	}


	/* Enable foreign interrupts for STD calls */
	thread_set_foreign_intr(true);
	switch (arg->cmd) {
	case OPTEE_MSG_CMD_OPEN_SESSION:
		entry_open_session(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_CLOSE_SESSION:
		entry_close_session(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_INVOKE_COMMAND:
		entry_invoke_command(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_CANCEL:
		entry_cancel(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_REGISTER_SHM:
		register_shm(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_UNREGISTER_SHM:
		unregister_shm(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_INVALIDATE_CANCELLATIONS:
		entry_invalidate_cancellations(smc_args, arg, num_params);
		break;

	default:
		EMSG("Unknown cmd 0x%x\n", arg->cmd);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
	}

out:
	if (reg_res == REGISTERED)
		unregister_cancellable_task(task);

	if (task != NULL)
		task_end(true, task);

	mobj_free(mobj);
}

static TEE_Result default_mobj_init(void)
{
	shm_mobj = mobj_phys_alloc(default_nsec_shm_paddr,
				   default_nsec_shm_size, SHM_CACHE_ATTRS,
				   CORE_MEM_NSEC_SHM);
	if (!shm_mobj)
		panic("Failed to register shared memory");

	mobj_sec_ddr = mobj_phys_alloc(tee_mm_sec_ddr.lo,
				       tee_mm_sec_ddr.hi - tee_mm_sec_ddr.lo,
				       SHM_CACHE_ATTRS, CORE_MEM_TA_RAM);
	if (!mobj_sec_ddr)
		panic("Failed to register secure ta ram");

	mobj_tee_ram = mobj_phys_alloc(TEE_RAM_START,
				       VCORE_UNPG_RW_PA + VCORE_UNPG_RW_SZ -
						TEE_RAM_START,
				       TEE_MATTR_CACHE_CACHED,
				       CORE_MEM_TEE_RAM);
	if (!mobj_tee_ram)
		panic("Failed to register tee ram");

#ifdef CFG_SECURE_DATA_PATH
	sdp_mem_mobjs = core_sdp_mem_create_mobjs();
	if (!sdp_mem_mobjs)
		panic("Failed to register SDP memory");
#endif

	return TEE_SUCCESS;
}

driver_init_late(default_mobj_init);
