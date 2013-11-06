/* This file is included from kernel/sched.c */

#include "sched.h"

#include <litmus/trace.h>
#include <litmus/sched_trace.h>

#include <litmus/litmus.h>
#include <litmus/budget.h>
#include <litmus/sched_plugin.h>
#include <litmus/preempt.h>

#ifdef CONFIG_LITMUS_AFFINITY_AWARE_GPU_ASSINGMENT
#include <litmus/gpu_affinity.h>
#endif

static void update_time_litmus(struct rq *rq, struct task_struct *p)
{
	u64 delta = rq->clock - p->se.exec_start;
	if (unlikely((s64)delta < 0))
		delta = 0;
	/* per job counter */
	p->rt_param.job_params.exec_time += delta;
	/* task counter */
	p->se.sum_exec_runtime += delta;
	/* sched_clock() */
	p->se.exec_start = rq->clock;
	cpuacct_charge(p, delta);
}

static void double_rq_lock(struct rq *rq1, struct rq *rq2);
static void double_rq_unlock(struct rq *rq1, struct rq *rq2);

/*
 * litmus_tick gets called by scheduler_tick() with HZ freq
 * Interrupts are disabled
 */
void litmus_tick(struct rq *rq, struct task_struct *p)
{
	TS_PLUGIN_TICK_START;

	if (is_realtime(p))
		update_time_litmus(rq, p);

	/* plugin tick */
	litmus->tick(p);

	TS_PLUGIN_TICK_END;

	return;
}

static struct task_struct *
litmus_schedule(struct rq *rq, struct task_struct *prev)
{
	struct task_struct *next;

#ifdef CONFIG_SMP
	struct rq* other_rq;
	long was_running;
	lt_t _maybe_deadlock = 0;
#endif

	/* let the plugin schedule */
	next = litmus->schedule(prev);

	sched_state_plugin_check();

#ifdef CONFIG_SMP
	/* check if a global plugin pulled a task from a different RQ */
	if (next && task_rq(next) != rq) {
		/* we need to migrate the task */
		other_rq = task_rq(next);
		TRACE_TASK(next, "migrate from %d\n", other_rq->cpu);

		/* while we drop the lock, the prev task could change its
		 * state
		 */
		was_running = is_running(prev);
		mb();
		raw_spin_unlock(&rq->lock);

		/* Don't race with a concurrent switch.  This could deadlock in
		 * the case of cross or circular migrations.  It's the job of
		 * the plugin to make sure that doesn't happen.
		 */
		TRACE_TASK(next, "stack_in_use=%d\n",
			   next->rt_param.stack_in_use);
		if (next->rt_param.stack_in_use != NO_CPU) {
			TRACE_TASK(next, "waiting to deschedule\n");
			_maybe_deadlock = litmus_clock();
		}
		while (next->rt_param.stack_in_use != NO_CPU) {
			cpu_relax();
			mb();
			if (next->rt_param.stack_in_use == NO_CPU)
				TRACE_TASK(next,"descheduled. Proceeding.\n");

			if (lt_before(_maybe_deadlock + 1000000000L,
					  litmus_clock())) {
				/* We've been spinning for 1s.
				 * Something can't be right!
				 * Let's abandon the task and bail out; at least
				 * we will have debug info instead of a hard
				 * deadlock.
				 */
#ifdef CONFIG_BUG_ON_MIGRATION_DEADLOCK
				BUG();
#else
				TRACE_TASK(next,"stack too long in use. "
					   "Deadlock?\n");
				next = NULL;

				/* bail out */
				raw_spin_lock(&rq->lock);
				return next;
#endif
			}
		}
#ifdef  __ARCH_WANT_UNLOCKED_CTXSW
		if (next->on_cpu)
			TRACE_TASK(next, "waiting for !oncpu");
		while (next->on_cpu) {
			cpu_relax();
			mb();
		}
#endif
		double_rq_lock(rq, other_rq);
		mb();
		if (is_realtime(prev) && is_running(prev) != was_running) {
			TRACE_TASK(prev,
				   "state changed while we dropped"
				   " the lock: is_running=%d, was_running=%d\n",
				   is_running(prev), was_running);
			if (is_running(prev) && !was_running) {
				/* prev task became unblocked
				 * we need to simulate normal sequence of events
				 * to scheduler plugins.
				 */
				litmus->task_block(prev);
				litmus->task_wake_up(prev);
			}
		}

		/* DEBUG: now that we have the lock we need to make sure a
		 *  couple of things still hold:
		 *  - it is still a real-time task
		 *  - it is still runnable (could have been stopped)
		 * If either is violated, then the active plugin is
		 * doing something wrong.
		 */
		if (unlikely(!is_realtime(next) || !is_running(next))) {
			/* BAD BAD BAD */
			TRACE_TASK(next,"BAD: migration invariant FAILED: "
				   "rt=%d running=%d\n",
				   is_realtime(next),
				   is_running(next));
			/* drop the task */
			next = NULL;
		}
		else {
			set_task_cpu(next, smp_processor_id());
		}

		/* release the other CPU's runqueue, but keep ours */
		raw_spin_unlock(&other_rq->lock);
	}
#endif

	if (next) {
#ifdef CONFIG_SMP
		next->rt_param.stack_in_use = rq->cpu;
#else
		next->rt_param.stack_in_use = 0;
#endif
		next->se.exec_start = rq->clock;

		if (is_realtime(next)) {
			budget_state_machine(next, on_scheduled);
#ifdef CONFIG_LITMUS_AFFINITY_AWARE_GPU_ASSINGMENT
			/* turn GPU tracking back on if needed */
			if(tsk_rt(next)->held_gpus && (0 == tsk_rt(next)->gpu_time_stamp))
				start_gpu_tracker(next);
#endif
		}
	}

	return next;
}

void litmus_handle_budget_exhaustion(struct task_struct *t)
{
	/* We're unlikely to pick a task that has an exhausted budget, so this
	 * provides a failsafe. */

	/* BUG: Virtual unlock of OMLP-family locking protocols is not triggered.
	 *
	 * TODO-FIX: Add a new virtual-unlock call to budget state machine and do
	 * the virtual unlock in plugin::schedule(), instead of in budget
	 * timer handler. This bug should only be raised EXTREMELY infrequently.
	 */

	int handle_exhausion = 1;

	BUG_ON(current != t);

	if (is_np(t) && bt_flag_is_set(t, BTF_BUDGET_EXHAUSTED)) {
		/* ignore. will handle exhausion in the future. */
		TRACE_TASK(t, "Task is np and already flagged as exhausted. "
					"Allow scheduling.\n");
		return;
	}

	if (unlikely(bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE))) {
		TRACE_TASK(t, "Waiting for release. Skipping exhaustion.\n");
		return;
	}

	if (budget_precisely_tracked(t)) {
		if (cancel_enforcement_timer(t) < 0) {
			TRACE_TASK(t, "schedule() raced with timer. Deferring to timer.\n");
			handle_exhausion = 0;
		}
	}

	if (handle_exhausion) {
		if (likely(!is_np(t))) {
			TRACE_TASK(t, "picked task without budget => FORCE_RESCHED.\n");
			litmus_reschedule_local();
		}
		else if (is_user_np(t)) {
			TRACE_TASK(t, "is non-preemptable, preemption delayed.\n");
			request_exit_np(t);
		}
	}
}

static void enqueue_task_litmus(struct rq *rq, struct task_struct *p,
				int flags)
{
	if (flags & ENQUEUE_WAKEUP) {
		sched_trace_task_resume(p);
		tsk_rt(p)->present = 1;
		/* LITMUS^RT plugins need to update the state
		 * _before_ making it available in global structures.
		 * Linux gets away with being lazy about the task state
		 * update. We can't do that, hence we update the task
		 * state already here.
		 *
		 * WARNING: this needs to be re-evaluated when porting
		 *		  to newer kernel versions.
		 */
		p->state = TASK_RUNNING;
		litmus->task_wake_up(p);

		rq->litmus.nr_running++;
	} else
		TRACE_TASK(p, "ignoring an enqueue, not a wake up.\n");
}

static void dequeue_task_litmus(struct rq *rq, struct task_struct *p,
				int flags)
{
	if (flags & DEQUEUE_SLEEP) {
		litmus->task_block(p);
		tsk_rt(p)->present = 0;
		sched_trace_task_block(p);

		rq->litmus.nr_running--;
	} else
		TRACE_TASK(p, "ignoring a dequeue, not going to sleep.\n");
}

static void yield_task_litmus(struct rq *rq)
{
	TS_SYSCALL_IN_START;
	TS_SYSCALL_IN_END;

	BUG_ON(rq->curr != current);
	/* sched_yield() is called to trigger delayed preemptions.
	 * Thus, mark the current task as needing to be rescheduled.
	 * This will cause the scheduler plugin to be invoked, which can
	 * then determine if a preemption is still required.
	 */
	clear_exit_np(current);
	litmus_reschedule_local();

	TS_SYSCALL_OUT_START;
}

/* Plugins are responsible for this.
 */
static void check_preempt_curr_litmus(struct rq *rq, struct task_struct *p, int flags)
{
}

static void put_prev_task_litmus(struct rq *rq, struct task_struct *p)
{
}

#ifdef CONFIG_SMP
static void pre_schedule_litmus(struct rq *rq, struct task_struct *prev)
{
	update_time_litmus(rq, prev);
	if (!is_running(prev))
		tsk_rt(prev)->present = 0;
}
#endif

/* pick_next_task_litmus() - litmus_schedule() function
 *
 * return the next task to be scheduled
 */
static struct task_struct *pick_next_task_litmus(struct rq *rq)
{
	/* get the to-be-switched-out task (prev) */
	struct task_struct *prev = rq->litmus.prev;
	struct task_struct *next;

	/* if not called from schedule() but from somewhere
	 * else (e.g., migration), return now!
	 */
	if(!rq->litmus.prev)
		return NULL;

	rq->litmus.prev = NULL;

	TS_PLUGIN_SCHED_START;
	next = litmus_schedule(rq, prev);
	TS_PLUGIN_SCHED_END;

	return next;
}

static void task_tick_litmus(struct rq *rq, struct task_struct *p, int queued)
{
	/* nothing to do; tick related tasks are done by litmus_tick() */
	return;
}

static void switched_to_litmus(struct rq *rq, struct task_struct *p)
{
}

static void prio_changed_litmus(struct rq *rq, struct task_struct *p,
				int oldprio)
{
}

unsigned int get_rr_interval_litmus(struct rq *rq, struct task_struct *p)
{
	/* return infinity */
	return 0;
}

/* This is called when a task became a real-time task, either due to a SCHED_*
 * class transition or due to PI mutex inheritance. We don't handle Linux PI
 * mutex inheritance yet (and probably never will). Use LITMUS provided
 * synchronization primitives instead.
 */
static void set_curr_task_litmus(struct rq *rq)
{
	rq->curr->se.exec_start = rq->clock;
}


#ifdef CONFIG_SMP
/* execve tries to rebalance task in this scheduling domain.
 * We don't care about the scheduling domain; can gets called from
 * exec, fork, wakeup.
 */
static int
select_task_rq_litmus(struct task_struct *p, int sd_flag, int flags)
{
	/* preemption is already disabled.
	 * We don't want to change cpu here
	 */
	return task_cpu(p);
}
#endif

const struct sched_class litmus_sched_class = {
	/* From 34f971f6 the stop/migrate worker threads have a class on
	 * their own, which is the highest prio class. We don't support
	 * cpu-hotplug or cpu throttling. Allows Litmus to use up to 1.0
	 * CPU capacity.
	 */
	.next			= &stop_sched_class,
	.enqueue_task		= enqueue_task_litmus,
	.dequeue_task		= dequeue_task_litmus,
	.yield_task		= yield_task_litmus,

	.check_preempt_curr	= check_preempt_curr_litmus,

	.pick_next_task		= pick_next_task_litmus,
	.put_prev_task		= put_prev_task_litmus,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_litmus,

	.pre_schedule		= pre_schedule_litmus,
#endif

	.set_curr_task		 = set_curr_task_litmus,
	.task_tick		= task_tick_litmus,

	.get_rr_interval	= get_rr_interval_litmus,

	.prio_changed		= prio_changed_litmus,
	.switched_to		= switched_to_litmus,
};
