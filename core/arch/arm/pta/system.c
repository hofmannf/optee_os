// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/task.h>
#include <kernel/user_ta.h>
#include <pta_system.h>
#include <crypto/crypto.h>
#include <util.h>

#define MAX_ENTROPY_IN			32u

static unsigned int system_pnum;

static TEE_Result system_rng_reseed(struct tee_ta_session *s __unused,
				uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	size_t entropy_sz;
	uint8_t *entropy_input;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	entropy_input = params[0].memref.buffer;
	entropy_sz = params[0].memref.size;

	/* Fortuna PRNG requires seed <= 32 bytes */
	if (!entropy_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	entropy_sz = MIN(entropy_sz, MAX_ENTROPY_IN);

	crypto_rng_add_event(CRYPTO_RNG_SRC_NONSECURE, &system_pnum,
			     entropy_input, entropy_sz);
	return TEE_SUCCESS;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct tee_ta_session *s;

	/* Check that we're called from a user TA */
	s = task_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session *s = task_get_calling_session();

	switch (cmd_id) {
	case PTA_SYSTEM_ADD_RNG_ENTROPY:
		return system_rng_reseed(s, param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SYSTEM_UUID, .name = "system.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
