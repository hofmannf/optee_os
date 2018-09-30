// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef TASK_H
#define TASK_H

#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

void tee_ta_push_current_session(struct tee_ta_session *sess);
struct tee_ta_session *tee_ta_pop_current_session(void);

TEE_Result task_get_session(struct tee_ta_session **sess);

struct tee_ta_session *tee_ta_get_calling_session(void);

void set_invoke_timeout(struct tee_ta_session *sess, uint32_t cancel_req_to);

bool tee_ta_session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time);

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id);

#endif
