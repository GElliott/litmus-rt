/* litmus/jobs.c - common job control code
 */

#include <linux/sched.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>

void setup_release(struct task_struct *t, lt_t release)
{
	/* prepare next release */
	t->rt_param.job_params.release = release;
	t->rt_param.job_params.deadline = release + get_rt_relative_deadline(t);
	t->rt_param.job_params.exec_time = 0;

#if 0 /* PORT CHECK */
	/* kludge - TODO: Move this to budget.h/.c */
	if (t->rt_param.budget.ops)
		bt_flags_reset(t);
#endif

	/* update job sequence number */
	t->rt_param.job_params.job_no++;

	TRACE_TASK(t, "preparing for next job: %d\n",
					t->rt_param.job_params.job_no);
}

void prepare_for_next_period(struct task_struct *t)
{
	BUG_ON(!t);

	/* Record lateness before we set up the next job's
	 * release and deadline. Lateness may be negative.
	 */
	t->rt_param.job_params.lateness =
		(long long)litmus_clock() -
		(long long)t->rt_param.job_params.deadline;

	if (tsk_rt(t)->sporadic_release) {
		TRACE_TASK(t, "sporadic release at %llu\n",
			   tsk_rt(t)->sporadic_release_time);
		/* sporadic release */
		setup_release(t, tsk_rt(t)->sporadic_release_time);
		tsk_rt(t)->sporadic_release = 0;
	} else {
		/* periodic release => add period */
		setup_release(t, get_release(t) + get_rt_period(t));
	}
}

void release_at(struct task_struct *t, lt_t start)
{
	BUG_ON(!t);
	setup_release(t, start);
	tsk_rt(t)->completed = 0;
}

long default_wait_for_release_at(lt_t release_time)
{
	struct task_struct *t = current;
	unsigned long flags;

	local_irq_save(flags);
	tsk_rt(t)->sporadic_release_time = release_time;
	smp_wmb();
	tsk_rt(t)->sporadic_release = 1;
	local_irq_restore(flags);

	return complete_job();
}

/*
 *	Deactivate current task until the beginning of the next period.
 */
long complete_job(void)
{
	/* Mark that we do not excute anymore */
	tsk_rt(current)->completed = 1;
	/* call schedule, this will return when a new job arrives
	 * it also takes care of preparing for the next release
	 */
	schedule();
	return 0;
}

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
void hide_from_workers(struct task_struct *t, worker_visibility_t *wv)
{
#ifdef CONFIG_REALTIME_AUX_TASKS
	if (tsk_rt(t)->has_aux_tasks) {
		if (wv) {
			wv->aux_hide = tsk_rt(t)->hide_from_aux_tasks;
			wv->do_aux_restore = 1;
		}
		tsk_rt(t)->hide_from_aux_tasks = 1;
	}
#endif
#ifdef CONFIG_LITMUS_NVIDIA
	if (tsk_rt(t)->held_gpus) {
		if (wv) {
			wv->gpu_hide = tsk_rt(t)->hide_from_gpu;
			wv->do_gpu_restore = 1;
		}
		tsk_rt(t)->hide_from_gpu = 1;
	}
#endif
}

void show_to_workers(struct task_struct *t, worker_visibility_t *wv)
{
	if (wv) {
#ifdef CONFIG_REALTIME_AUX_TASKS
		if (wv->do_aux_restore)
			tsk_rt(t)->hide_from_aux_tasks = wv->aux_hide;
#endif
#ifdef CONFIG_LITMUS_NVIDIA
		if (wv->do_gpu_restore)
			tsk_rt(t)->hide_from_gpu = wv->gpu_hide;
#endif
	}
	else {
#ifdef CONFIG_REALTIME_AUX_TASKS
		if (tsk_rt(t)->has_aux_tasks)
			tsk_rt(t)->hide_from_aux_tasks = 0;
#endif
#ifdef CONFIG_LITMUS_NVIDIA
		if (tsk_rt(t)->held_gpus)
			tsk_rt(t)->hide_from_gpu = 0;
#endif
	}
}

#endif /* REALTIME_AUX_TASKS || LITMUS_NVIDIA */
