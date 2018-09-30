// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/task.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

static void update_current_ctx(struct thread_specific_data *tsd)
{
	struct tee_ta_ctx *ctx = NULL;
	struct tee_ta_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		if (is_pseudo_ta_ctx(s->ctx))
			s = TAILQ_NEXT(s, link_tsd);

		if (s)
			ctx = s->ctx;
	}

	if (tsd->ctx != ctx)
		tee_mmu_set_ctx(ctx);
	/*
	 * If ctx->mmu == NULL we must not have user mapping active,
	 * if ctx->mmu != NULL we must have user mapping active.
	 */
	if (((ctx && is_user_ta_ctx(ctx) ?
			to_user_ta_ctx(ctx)->vm_info : NULL) == NULL) ==
					core_mmu_user_mapping_is_active())
		panic("unexpected active mapping");
}

void tee_ta_push_current_session(struct tee_ta_session *sess)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	TAILQ_INSERT_HEAD(&tsd->sess_stack, sess, link_tsd);
	update_current_ctx(tsd);
}

struct tee_ta_session *tee_ta_pop_current_session(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_ta_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		TAILQ_REMOVE(&tsd->sess_stack, s, link_tsd);
		update_current_ctx(tsd);
	}
	return s;
}

TEE_Result task_get_session(struct tee_ta_session **sess)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (!s)
		return TEE_ERROR_BAD_STATE;
	*sess = s;
	return TEE_SUCCESS;
}

struct tee_ta_session *tee_ta_get_calling_session(void)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s)
		s = TAILQ_NEXT(s, link_tsd);
	return s;
}

void set_invoke_timeout(struct tee_ta_session *sess, uint32_t cancel_req_to)
{
	TEE_Time current_time;
	TEE_Time cancel_time;

	if (cancel_req_to == TEE_TIMEOUT_INFINITE)
		goto infinite;

	if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		goto infinite;

	if (ADD_OVERFLOW(current_time.seconds, cancel_req_to / 1000,
			 &cancel_time.seconds))
		goto infinite;

	cancel_time.millis = current_time.millis + cancel_req_to % 1000;
	if (cancel_time.millis > 1000) {
		if (ADD_OVERFLOW(current_time.seconds, 1,
				 &cancel_time.seconds))
			goto infinite;

		cancel_time.seconds++;
		cancel_time.millis -= 1000;
	}

	sess->cancel_time = cancel_time;
	return;

infinite:
	sess->cancel_time.seconds = UINT32_MAX;
	sess->cancel_time.millis = UINT32_MAX;
}

bool tee_ta_session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time)
{
	TEE_Time current_time;

	if (s->cancel_mask)
		return false;

	if (s->cancel)
		return true;

	if (s->cancel_time.seconds == UINT32_MAX)
		return false;

	if (curr_time != NULL)
		current_time = *curr_time;
	else if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		return false;

	if (current_time.seconds > s->cancel_time.seconds ||
	    (current_time.seconds == s->cancel_time.seconds &&
	     current_time.millis >= s->cancel_time.millis)) {
		return true;
	}

	return false;
}

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id)
{
	*err = TEE_ORIGIN_TEE;

	sess->cancel = true;
	return TEE_SUCCESS;
}
