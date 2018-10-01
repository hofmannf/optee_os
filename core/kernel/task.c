// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/task.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

struct task {
	struct tee_ta_session *session;
	bool cancelled;
	bool cancel_mask;
	TEE_Time cancel_time;
	SLIST_ENTRY(task) link_tsd;
};

TEE_Result task_begin(bool top_level_task, struct task **out_task)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct task *task;

	assert(!top_level_task || SLIST_EMPTY(&thread_data->task_stack));

	task = calloc(1, sizeof(*task));
	if (task == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	task->cancel_mask = true;

	SLIST_INSERT_HEAD(&thread_data->task_stack, task, link_tsd);
	thread_data->task_current_session = NULL;

	if (out_task != NULL)
		*out_task = task;

	return TEE_SUCCESS;
}

void task_end(bool top_level_task, struct task *task)
{
	struct thread_specific_data *thread_data = thread_get_tsd();

	assert(task != NULL);
	assert(task->session == NULL);
	assert(task == SLIST_FIRST(&thread_data->task_stack));
	SLIST_REMOVE_HEAD(&thread_data->task_stack, link_tsd);
	assert(!top_level_task || SLIST_EMPTY(&thread_data->task_stack));
	free(task);
}

static struct task *current_task(void)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct task *task;

	task = SLIST_FIRST(&thread_data->task_stack);
	assert(task != NULL);

	return task;
}

static void update_current_ctx(struct task *task)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct tee_ta_ctx *ctx = NULL;
	bool seen_pta = false;

	/* Starting with 'task', look for the most recent task that has a
	 * session assigned to it. If that task happens to be a pseudo TA, fall
	 * back to the next most recent task with a session, regardless of
	 * whether it is a pseudo or a user TA.
	 */
	for (; task != NULL; task = SLIST_NEXT(task, link_tsd)) {
		if (task->session != NULL) {
			if (!is_pseudo_ta_ctx(task->session->ctx) || seen_pta) {
				ctx = task->session->ctx;
				break;
			} else {
				seen_pta = true;
			}
		}
	}

	if (thread_data->ctx != ctx)
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

void task_set_session(struct tee_ta_session *session)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct task *task = current_task();

	assert(session != NULL);
	assert(task->session == NULL);

	task->session = session;
	thread_data->task_current_session = session;
	update_current_ctx(task);
}

struct tee_ta_session *task_unset_session(void)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct task *task = current_task();
	struct task *parent_task = SLIST_NEXT(task, link_tsd);
	struct tee_ta_session *retval = task->session;
	struct tee_ta_session *prev_session = NULL;

	assert(task->session != NULL);
	task->session = NULL;

	/* Update task_current_session to point to the most recent session. */
	for (struct task *t = parent_task;
			t != NULL;
			t = SLIST_NEXT(t, link_tsd)) {
		if (t->session != NULL) {
			prev_session = t->session;
			break;
		}
	}
	thread_data->task_current_session = prev_session;

	update_current_ctx(parent_task);

	return retval;
}

TEE_Result task_get_session(struct tee_ta_session **out_sess)
{
	struct thread_specific_data *thread_data = thread_get_tsd();

	if (thread_data->task_current_session != NULL) {
		*out_sess = thread_data->task_current_session;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_STATE;
}

struct tee_ta_session *task_get_calling_session(void)
{
	struct thread_specific_data *thread_data = thread_get_tsd();
	struct task *task;
	bool found_first = false;

	SLIST_FOREACH(task, &thread_data->task_stack, link_tsd) {
		if (task->session != NULL) {
			if (!found_first)
				found_first = true;
			else
				return task->session;
		}
	}

	return NULL;
}

bool task_set_cancellation_mask(bool mask)
{
	struct task *task = current_task();
	bool oldval = task->cancel_mask;

	task->cancel_mask = mask;

	return oldval;
}

void task_set_timeout(uint32_t millis)
{
	struct task *task = current_task();
	TEE_Time current_time;
	TEE_Time cancel_time;

	if (millis == TEE_TIMEOUT_INFINITE)
		goto disable_timeout;

	if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		goto disable_timeout;

	if (ADD_OVERFLOW(current_time.seconds, millis / 1000,
			 &cancel_time.seconds))
		goto disable_timeout;

	cancel_time.millis = current_time.millis + millis % 1000;
	if (cancel_time.millis > 1000) {
		if (ADD_OVERFLOW(current_time.seconds, 1,
				 &cancel_time.seconds))
			goto disable_timeout;

		cancel_time.seconds++;
		cancel_time.millis -= 1000;
	}

	task->cancel_time = cancel_time;

	return;

disable_timeout:
	task->cancel_time.seconds = 0;
	task->cancel_time.millis = 0;
}

bool task_is_cancelled(TEE_Time *curr_time)
{
	struct task *task = current_task();
	TEE_Time current_time;

	/* task->cancelled is accessed through an __atomic* function because
	 * task_cancel() could have been executed on a different core. All
	 * other variables (cancel_mask, etc.) are assumed to only get changed
	 * by the current thread.
	 */

	if (task->cancel_mask)
		return false;

	if (__atomic_load_n(&task->cancelled, __ATOMIC_CONSUME))
		return true;

	if (task->cancel_time.seconds == 0)
		return false;

	if (curr_time != NULL)
		current_time = *curr_time;
	else if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		return false;

	if (current_time.seconds > task->cancel_time.seconds ||
	    (current_time.seconds == task->cancel_time.seconds &&
	     current_time.millis >= task->cancel_time.millis)) {
		return true;
	}

	return false;
}

void task_cancel(struct task *task)
{
	assert(task != NULL);
	__atomic_store_n(&task->cancelled, true, __ATOMIC_RELEASE);
}
