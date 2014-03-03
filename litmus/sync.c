/* litmus/sync.c - Support for synchronous and asynchronous task system releass.
 */

#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/completion.h>

#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/jobs.h>

#include <litmus/sched_trace.h>
#include <litmus/budget.h>

struct ts_release_wait {
	struct list_head list;
	struct completion completion;
	lt_t ts_release_time;
};

#define DECLARE_TS_RELEASE_WAIT(symb)					\
	struct ts_release_wait symb =					\
	{								\
		LIST_HEAD_INIT(symb.list),				\
		COMPLETION_INITIALIZER_ONSTACK(symb.completion),	\
		0							\
	}

static LIST_HEAD(task_release_list);
static DEFINE_MUTEX(task_release_lock);

static long do_wait_for_ts_release(struct timespec *wake)
{
	DECLARE_TS_RELEASE_WAIT(wait);

	long ret = -ERESTARTSYS;

	struct task_struct *t = current;
	int is_rt = is_realtime(t);

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
	DECLARE_WORKER_VIS_FLAGS(vis_flags);
#endif

	if (mutex_lock_interruptible(&task_release_lock))
		goto out;

	list_add(&wait.list, &task_release_list);

	mutex_unlock(&task_release_lock);

	if (is_rt) {
#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
		hide_from_workers(t, &vis_flags);
#endif
		bt_flag_set(t, BTF_WAITING_FOR_RELEASE);
		mb();
		budget_state_machine(t, on_exit); /* TODO: maybe call in schedule() */
	}

	TRACE_TASK(t, "waiting for ts release.\n");

	if (is_rt)
		BUG_ON(!bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE));

	/* We are enqueued, now we wait for someone to wake us up. */
	ret = wait_for_completion_interruptible(&wait.completion);

	TRACE_TASK(t, "released by ts release!\n");

	if (is_rt) {
		bt_flag_clear(t, BTF_WAITING_FOR_RELEASE);
#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
		show_to_workers(t, &vis_flags);
#endif
	}

	if (!ret) {
		/* Completion succeeded, setup release time. */
		if (is_rt) {
			lt_t phased_release = wait.ts_release_time + get_rt_phase(current);
			*wake = ns_to_timespec(phased_release);
			ret = litmus->wait_for_release_at(phased_release);
		}
		else {
			/* Not a real-time task, so we can't use litmus to manage the
			   release. Just sleep until the appropriate time.
			   Note: Phased releases are not supported.
			*/
			lt_t now = litmus_clock();
			if (now < wait.ts_release_time) {
				ktime_t remaining =
						ns_to_ktime(wait.ts_release_time - now);
				schedule_hrtimeout(&remaining, HRTIMER_MODE_REL);
			}
			*wake = ns_to_timespec(wait.ts_release_time);
		}
	} else {
		/* We were interrupted, must cleanup list. */
		mutex_lock(&task_release_lock);
		if (!wait.completion.done)
			list_del(&wait.list);
		mutex_unlock(&task_release_lock);
	}

out:
	return ret;
}

int count_tasks_waiting_for_release(void)
{
	int task_count = 0;
	struct list_head *pos;

	mutex_lock(&task_release_lock);

	list_for_each(pos, &task_release_list) {
		task_count++;
	}

	mutex_unlock(&task_release_lock);


	return task_count;
}

static long do_release_ts(lt_t start)
{
	long  task_count = 0;

	struct list_head	*pos, *safe;
	struct ts_release_wait	*wait;

	if (mutex_lock_interruptible(&task_release_lock)) {
		task_count = -ERESTARTSYS;
		goto out;
	}

	TRACE("<<<<<< synchronous task system release >>>>>>\n");
	sched_trace_sys_release(&start);

	task_count = 0;
	list_for_each_safe(pos, safe, &task_release_list) {
		wait = (struct ts_release_wait*)
			list_entry(pos, struct ts_release_wait, list);

		task_count++;

		wait->ts_release_time = start;
		complete(&wait->completion);
	}

	/* clear stale list */
	INIT_LIST_HEAD(&task_release_list);

	mutex_unlock(&task_release_lock);

out:
	return task_count;
}


asmlinkage long sys_wait_for_ts_release(struct timespec __user *__wake)
{
	struct timespec wake;
	long ret = -EPERM;

	ret = do_wait_for_ts_release(&wake);

	if (__wake && access_ok(VERIFY_WRITE, __wake, sizeof(struct timespec)))
		__copy_to_user(__wake, &wake, sizeof(wake));

	return ret;
}

#define ONE_MS 1000000

asmlinkage long sys_release_ts(lt_t __user *__delay)
{
	long ret = 0;
	lt_t delay = 0;
	lt_t start_time;

	/* FIXME: check capabilities... */

	if (__delay)
		ret = copy_from_user(&delay, __delay, sizeof(delay));

	if (ret == 0) {
		/* round up to next larger integral millisecond */
		start_time = litmus_clock();
		do_div(start_time, ONE_MS);
		start_time *= ONE_MS;
		ret = do_release_ts(start_time + delay);
	}

	return ret;
}
