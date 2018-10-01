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

struct task;

/* task_begin() and task_end() must be called in matched pairs. */
TEE_Result task_begin(bool top_level_task, struct task **out_task);
void task_end(bool top_level_task, struct task *task);

/* task_set_session() and task_unset_session() must be called in matched pairs.
 */
void task_set_session(struct tee_ta_session *session);
struct tee_ta_session *task_unset_session(void);
TEE_Result task_get_session(struct tee_ta_session **out_sess);
struct tee_ta_session *task_get_calling_session(void);
bool task_set_cancellation_mask(bool mask);
void task_set_timeout(uint32_t timeout);
bool task_is_cancelled(TEE_Time *curr_time);

void task_cancel(struct task *task);

#endif
