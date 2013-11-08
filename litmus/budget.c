#include <linux/sched.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/signal.h>

#include <litmus/litmus.h>
#include <litmus/preempt.h>
#include <litmus/sched_plugin.h>
#include <litmus/budget.h>
#include <litmus/signal.h>

int cancel_enforcement_timer(struct task_struct* t)
{
	struct enforcement_timer* et;
	int ret = 0;
	unsigned long flags;

	BUG_ON(!t);
	BUG_ON(!is_realtime(t));

	et = &tsk_rt(t)->budget.timer;

	TRACE_TASK(t, "canceling enforcement timer.\n");

	if (et->armed) {
		raw_spin_lock_irqsave(&et->lock, flags);
		if (et->armed) {
			ret = hrtimer_try_to_cancel(&et->timer);
			if (ret < 0)
				TRACE_TASK(t, "timer already running. failed to cancel.\n");
			else {
				TRACE_TASK(t, "canceled timer with %lld ns remaining.\n",
					ktime_to_ns(hrtimer_expires_remaining(&et->timer)));
				et->armed = 0;
			}
		}
		else
			TRACE_TASK(t, "timer was not armed (race).\n");
		raw_spin_unlock_irqrestore(&et->lock, flags);
	}
	else
		TRACE_TASK(t, "timer was not armed.\n");

	return ret;
}

inline static void arm_enforcement_timer(struct task_struct* t, int force)
{
	struct enforcement_timer* et;
	lt_t when_to_fire, remaining_budget;
	lt_t now;
	unsigned long flags;

	BUG_ON(!t);
	BUG_ON(!is_realtime(t));

	et = &tsk_rt(t)->budget.timer;
	if (et->armed) {
		TRACE_TASK(t, "timer already armed!\n");
		return;
	}

	if (!force) {
		if ( (!budget_enforced(t) ||
				(budget_enforced(t) &&
					bt_flag_is_set(t, BTF_BUDGET_EXHAUSTED)))
				&&
			(!budget_signalled(t) ||
				(budget_signalled(t) &&
					bt_flag_is_set(t, BTF_SIG_BUDGET_SENT)))) {
			TRACE_TASK(t,
					"trying to arm timer when budget "
					"has already been exhausted.\n");
			return;
		}
	}

	TRACE_TASK(t, "arming enforcement timer.\n");

	/* __hrtimer_start_range_ns() cancels the timer
	 * anyway, so we don't have to check whether it is still armed */
	raw_spin_lock_irqsave(&et->lock, flags);

	if (et->armed) {
		TRACE_TASK(t, "timer already armed (race)!\n");
		goto out;
	}

	now = litmus_clock();
	remaining_budget = budget_remaining(t);
	when_to_fire = now + remaining_budget;

	TRACE_TASK(t, "budget remaining: %ld, when_to_fire: %ld\n",
					remaining_budget, when_to_fire);

	__hrtimer_start_range_ns(&et->timer,
				 ns_to_ktime(when_to_fire),
				 0 /* delta */,
				 HRTIMER_MODE_ABS_PINNED,  /* TODO: need to use non-pinned? */
				 0 /* no wakeup */);
	et->armed = 1;

out:
	raw_spin_unlock_irqrestore(&et->lock, flags);
}

void send_sigbudget(struct task_struct* t)
{
	if (!bt_flag_test_and_set(t, BTF_SIG_BUDGET_SENT)) {
		/* signal has not yet been sent and we are responsible for sending
		 * since we just set the sent-bit when it was previously 0. */

		TRACE_TASK(t, "SIG_BUDGET being sent!\n");
		send_sig(SIG_BUDGET, t, 1); /* '1' denotes signal sent from kernel */
	}
}

/*
 * DRAIN_SIMPLE
 */

void simple_on_scheduled(struct task_struct* t)
{
	BUG_ON(!t);

	if(budget_precisely_tracked(t) && !bt_flag_is_set(t, BTF_SIG_BUDGET_SENT))
		if (!tsk_rt(t)->budget.timer.armed)
			arm_enforcement_timer(t, 0);
}

inline static void __simple_on_unscheduled(struct task_struct* t)
{
	BUG_ON(!t);

	if (budget_precisely_tracked(t))
		cancel_enforcement_timer(t);
}

void simple_on_blocked(struct task_struct* t)
{
	__simple_on_unscheduled(t);
}

void simple_on_preempt(struct task_struct* t)
{
	__simple_on_unscheduled(t);
}

void simple_on_sleep(struct task_struct* t)
{
	__simple_on_unscheduled(t);
}

void simple_on_exit(struct task_struct* t)
{
	__simple_on_unscheduled(t);
}

/*
 * DRAIN_SIMPLE_IO
 */

void simple_io_on_blocked(struct task_struct* t)
{
	/* hiding is turned on by locking protocols, so if there isn't any
	   hiding, then we're blocking for some other reason.  assume it's I/O. */
	int for_io = 0;
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	for_io |= !tsk_rt(t)->blocked_lock;
#endif
#ifdef CONFIG_REALTIME_AUX_TASKS
	for_io |= tsk_rt(t)->has_aux_tasks && !tsk_rt(t)->hide_from_aux_tasks;
#endif
#ifdef CONFIG_LITMUS_NVIDIA
	for_io |= tsk_rt(t)->held_gpus && !tsk_rt(t)->hide_from_gpu;
#endif

	/* we drain budget for io-based suspensions */
	if (for_io) {
		/* there is a fraction of time where we're double-counting the
		 * time tracked by the rq and suspension time.
		 * TODO: Do this recording closer to suspension time. */
		tsk_rt(t)->budget.suspend_timestamp = litmus_clock();

		TRACE_TASK(t, "blocking for I/O.\n");

		if (!tsk_rt(t)->budget.timer.armed) {
			bt_flag_clear(t, BTF_BUDGET_EXHAUSTED);

			if (likely(!bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE))) {
				TRACE_TASK(t, "budget timer not armed. "
						   "Raced with exhaustion-resched? Re-arming.\n");
				arm_enforcement_timer(t, 1);
			}
			else {
				TRACE_TASK(t, "not arming timer because task is waiting "
						   "for release.\n");
			}
		}
	}
	else {
		TRACE_TASK(t, "blocking for litmus lock. stop draining.\n");
		simple_on_blocked(t);
	}
}

void simple_io_on_wakeup(struct task_struct* t)
{
	/* we're waking up from an io-based suspension */
	if (tsk_rt(t)->budget.suspend_timestamp) {
		lt_t suspend_cost = litmus_clock() -
				tsk_rt(t)->budget.suspend_timestamp;
		tsk_rt(t)->budget.suspend_timestamp = 0;
		TRACE_TASK(t, "budget consumed while io-suspended: %llu\n",
						suspend_cost);
		get_exec_time(t) += suspend_cost;
	}
	else {
		TRACE_TASK(t, "waking from non-io blocking\n");
	}
}


/*
 * DRAIN_SOBLIV
 */

void sobliv_on_blocked(struct task_struct* t)
{
	if (bt_flag_is_set(t, BTF_IS_TOP_M)) {
		/* there is a fraction of time where we're double-counting the
		 * time tracked by the rq and suspension time.
		 * TODO: Do this recording closer to suspension time. */
		tsk_rt(t)->budget.suspend_timestamp = litmus_clock();

		if (!tsk_rt(t)->budget.timer.armed) {
			/* budget exhaustion timer fired as t was waking up, so budget
			 * routine thought t was running. We need to re-trigger the budget
			 * exhastion routine via timer. Schedulers do not call
			 * job_completion() when a task blocks, even if t's budget has been
			 * exhausted. Unfortunately, we cannot rerun the exhaustion routine
			 * here due to spinlock ordering issues. Just re-arm the timer with
			 * the exhausted time, re-running the timer routine immediately once
			 * interrupts have been re-enabled. */

			/* clear the exhausted flag so handle will re-run. this will not
			 * trigger another exhaustion signal since signals are controled by
			 * BTF_SIG_BUDGET_SENT. */
			bt_flag_clear(t, BTF_BUDGET_EXHAUSTED);

			if (likely(!bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE))) {
				TRACE_TASK(t, "budget timer not armed. "
						   "Raced with exhaustion-resched? Re-arming.\n");
				arm_enforcement_timer(t, 1);
			}
			else {
				TRACE_TASK(t, "not arming timer because task is waiting "
								"for release.\n");
			}
		}
	}
}

void sobliv_on_wakeup(struct task_struct* t)
{
	if (bt_flag_is_set(t, BTF_IS_TOP_M)) {
		/* we're waking up while in top-m.  record the time spent
		 * suspended while draining in exec_cost. suspend_timestamp was
		 * either set when we entered top-m while asleep, or when we
		 * blocked. */
		if (tsk_rt(t)->budget.suspend_timestamp) {
			lt_t suspend_cost = litmus_clock() -
					tsk_rt(t)->budget.suspend_timestamp;
			tsk_rt(t)->budget.suspend_timestamp = 0;
			TRACE_TASK(t, "budget consumed while suspended: %llu\n",
					suspend_cost);
			get_exec_time(t) += suspend_cost;
		}
		else {
			WARN_ON(!bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE));
		}
	}
}

void sobliv_on_inherit(struct task_struct* t, struct task_struct* prio_inh)
{
	/* TODO: Budget credit accounting. */
	BUG_ON(!prio_inh);
}

void sobliv_on_disinherit(struct task_struct* t, struct task_struct* prio_inh)
{
	/* TODO: Budget credit accounting. */
}

void sobliv_on_enter_top_m(struct task_struct* t)
{
	if (!bt_flag_is_set(t, BTF_SIG_BUDGET_SENT)) {
		if (tsk_rt(t)->budget.timer.armed)
			TRACE_TASK(t, "budget timer already armed.\n");
		else {
			/* if we're blocked, then record the time at which we
			   started measuring */
			if (!is_running(t))
				tsk_rt(t)->budget.suspend_timestamp = litmus_clock();

			/* the callback will handle it if it is executing */
			if (!hrtimer_callback_running(&tsk_rt(t)->budget.timer.timer)) {
				arm_enforcement_timer(t, 0);
			}
			else {
				TRACE_TASK(t,
					"within callback context. deferring timer arm.\n");
			}
		}
	}
}

void sobliv_on_exit_top_m(struct task_struct* t)
{
	if (budget_precisely_tracked(t)) {
		if (tsk_rt(t)->budget.timer.armed) {

			if (!is_running(t)) {
				/* the time at which we started draining budget while
				 * suspended is recorded in evt_timestamp.  evt_timestamp
				 * was set either when 't' exited the top-m while suspended
				 * or when 't' blocked. */
				lt_t suspend_cost;
				BUG_ON(!tsk_rt(t)->budget.suspend_timestamp);
				suspend_cost = litmus_clock() -
						tsk_rt(t)->budget.suspend_timestamp;
				TRACE_TASK(t, "budget consumed while suspended: %llu\n",
								suspend_cost);
				get_exec_time(t) += suspend_cost;

				/* timer should have fired before now */
				if (get_exec_time(t) + 1000000/10 > get_exec_cost(t)) {
					TRACE_TASK(t,
						"budget overrun while suspended by over 1/10 "
						"millisecond! timer should have already fired!\n");
					WARN_ON(1);
				}
			}

			TRACE_TASK(t, "stops draining budget\n");
			/* the callback will handle it if it is executing */
			if (!hrtimer_callback_running(&tsk_rt(t)->budget.timer.timer)) {
				/* TODO: record a timestamp if the task isn't running */
				cancel_enforcement_timer(t);
			}
			else {
				TRACE_TASK(t,
					"within callback context. skipping operation.\n");
			}
		}
		else {
			TRACE_TASK(t, "was not draining budget\n");
		}
	}
}

void reevaluate_inheritance(struct task_struct* t)
{
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	struct litmus_lock *blocked_lock = NULL;

	TRACE_TASK(t, "reevaluating locks in light of budget exhaustion.\n");

	/* do we need to inherit from any tasks now that our own
	 * priority has decreased? */
	raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);
	if (holds_locks(t)) {
		struct task_struct* hp_blocked =
				top_priority(&tsk_rt(t)->hp_blocked_tasks);

		if (litmus->compare(hp_blocked, t))
			litmus->increase_prio(t, effective_priority(hp_blocked));
	}
	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);

	/* do we need to tell the lock we're blocked on about our
	 * changed priority? */
	blocked_lock = tsk_rt(t)->blocked_lock;
	if(blocked_lock) {
		if(blocked_lock->ops->supports_budget_exhaustion) {
			TRACE_TASK(t, "Lock %d supports budget exhaustion.\n",
					   blocked_lock->ident);
			blocked_lock->ops->budget_exhausted(blocked_lock, t);
		}
	}
	else {
		TRACE_TASK(t,
			"Budget exhausted while task not blocked on Litmus lock.\n");
	}
#else
	/* prio-reeval currently relies upon nested locking infrastructure */
	TRACE_TASK(t,
		"Unable to check if sleeping task is blocked "
		"on Litmus lock without "
		"CONFIG_LITMUS_NESTED_LOCKING enabled.\n");
#endif
}



static enum hrtimer_restart __on_timeout(struct hrtimer *timer)
{
	enum hrtimer_restart restart = HRTIMER_NORESTART;
	unsigned long flags;

	struct budget_tracker* bt =
		container_of(
			container_of(timer,
				struct enforcement_timer,
				timer),
			struct budget_tracker,
			timer);

	struct task_struct* t =
		container_of(
			container_of(bt, struct rt_param, budget),
			struct task_struct,
			rt_param);

	TRACE_TASK(t, "budget timer interrupt fired at time %lu\n",
					litmus_clock());

	raw_spin_lock_irqsave(&bt->timer.lock, flags);
	tsk_rt(t)->budget.timer.armed = 0;
	raw_spin_unlock_irqrestore(&bt->timer.lock, flags);

	if (unlikely(bt_flag_is_set(t, BTF_WAITING_FOR_RELEASE))) {
		TRACE_TASK(t,
			"spurious exhastion while waiting for release. dropping.\n");
		goto out;
	}

	restart = bt->ops->on_exhausted(t,!IN_SCHEDULE);

	raw_spin_lock_irqsave(&bt->timer.lock, flags);
	tsk_rt(t)->budget.timer.armed = (restart == HRTIMER_RESTART);
	raw_spin_unlock_irqrestore(&bt->timer.lock, flags);

out:
	return restart;
}

void init_budget_tracker(struct budget_tracker* bt,
				const struct budget_tracker_ops* ops)
{
	BUG_ON(!bt);

	memset(bt, 0, sizeof(*bt));
	raw_spin_lock_init(&bt->timer.lock);
	hrtimer_init(&bt->timer.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	bt->timer.timer.function = __on_timeout;
	bt->ops = ops;
	INIT_BINHEAP_NODE(&bt->top_m_node);
}
