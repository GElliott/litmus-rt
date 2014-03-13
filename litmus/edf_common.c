/*
 * kernel/edf_common.c
 *
 * Common functions for EDF based scheduler.
 */

#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/list.h>

#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/sched_trace.h>

#include <litmus/edf_common.h>

#ifdef CONFIG_LITMUS_NESTED_LOCKING
#include <litmus/locking.h>
#endif

#ifdef CONFIG_EDF_TIE_BREAK_LATENESS_NORM
#include <litmus/fpmath.h>
#endif

#ifdef CONFIG_EDF_TIE_BREAK_HASH
#include <linux/hash.h>
static inline long edf_hash(const struct task_struct *t)
{
	/* pid is 32 bits, so normally we would shove that into the
	 * upper 32-bits and and put the job number in the bottom
	 * and hash the 64-bit number with hash_64(). Sadly,
	 * in testing, hash_64() doesn't distribute keys were the
	 * upper bits are close together (as would be the case with
	 * pids) and job numbers are equal (as would be the case with
	 * synchronous task sets with all relative deadlines equal).
	 *
	 * A 2006 Linux patch proposed the following solution
	 * (but for some reason it wasn't accepted...).
	 *
	 * At least this workaround works for 32-bit systems as well.
	 */
	return hash_32(hash_32((u32)tsk_rt(t)->job_params.job_no, 32) ^
					t->pid, 32);
}
#endif


/* edf_higher_prio -  returns true if first has a higher EDF priority
 *                    than second. Deadline ties are broken by PID.
 *
 * both first and second may be NULL
 */
#ifdef CONFIG_LITMUS_NESTED_LOCKING
int __edf_higher_prio(
	const struct task_struct* first, comparison_mode_t first_mode,
	const struct task_struct* second, comparison_mode_t second_mode)
#else
int edf_higher_prio(const struct task_struct* first, const struct task_struct* second)
#endif
{
	const struct task_struct *first_task = first;
	const struct task_struct *second_task = second;

	/* There is no point in comparing a task to itself. */
	if (unlikely(first && first == second)) {
		TRACE_CUR("WARNING: pointless edf priority comparison: %s/%d\n",
			first->comm, first->pid);
		return 0;
	}

	/* Quick and dirty priority comparisons: exists? real-time? */

	/* check for NULL tasks */
	if (!first || !second)
		return first && !second;
	/* check for non-realtime */
	if (!is_realtime(first) || !is_realtime(second))
		return is_realtime(first) && !is_realtime(second);

	/* Harder priority comparions... */

	/* There is some goofy stuff in this code here. There are three
	   subclasses within the SCHED_LITMUS scheduling class:
	   1) Auxiliary tasks: COTS helper threads from the application level
	      that are forced to be real-time.
	   2) klmirqd interrupt threads: Litmus threaded interrupt handlers.
	   3) Normal Litmus tasks.

	   At their base priorities, #3 > #2 > #1.  However, #1 and #2 threads
	   might inherit a priority from a task of #3.

	   The code proceeds in the following manner:
	   1) Make aux and klmirqd threads with base-priorities have low
	      priorities.
	   2) Determine effective priorities.
	   3) Perform priority comparison. Favor #3 over #1 & #2 in case of tie. */

#if defined(CONFIG_REALTIME_AUX_TASK_PRIORITY_BOOSTED)
	/* run aux tasks at max priority */
	if (tsk_rt(first)->is_aux_task != tsk_rt(second)->is_aux_task) {
		return (tsk_rt(first)->is_aux_task > tsk_rt(second)->is_aux_task);
	}
#elif defined(CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE)
	{
		int first_lo_aux = tsk_rt(first)->is_aux_task &&
				!tsk_rt(first)->inh_task;
		int second_lo_aux = tsk_rt(second)->is_aux_task &&
				!tsk_rt(second)->inh_task;

		/* prioritize aux tasks without inheritance below real-time tasks */
		if (first_lo_aux || second_lo_aux) {
			/* one of these is an aux task without inheritance. */
			if (first_lo_aux != second_lo_aux) {
				/* non-lo-aux has higher priority. */
				return (first_lo_aux < second_lo_aux);
			}
			else {
				/* both MUST be lo_aux. tie-break. */
				goto aux_tie_break;
			}
		}

		if (tsk_rt(first)->is_aux_task && tsk_rt(second)->is_aux_task &&
			tsk_rt(first)->inh_task == tsk_rt(second)->inh_task) {
			/* inh_task is !NULL for both tasks since neither was a lo_aux
			   task. Both aux tasks inherit from the same task, so tie-break
			   by base priority of the aux tasks. */
			goto aux_tie_break;
		}
	}
#endif

#ifdef CONFIG_LITMUS_SOFTIRQD
	{
		int first_lo_klmirqd = tsk_rt(first)->is_interrupt_thread &&
				!tsk_rt(first)->inh_task;
		int second_lo_klmirqd = tsk_rt(second)->is_interrupt_thread &&
				!tsk_rt(second)->inh_task;

		/* prioritize aux tasks without inheritance below real-time tasks */
		if (first_lo_klmirqd || second_lo_klmirqd) {
			/* one of these is an klmirqd thread without inheritance. */
			if (first_lo_klmirqd != second_lo_klmirqd) {
				/* non-klmirqd has higher priority */
				return (first_lo_klmirqd < second_lo_klmirqd);
			}
			else {
				/* both MUST be klmirqd. tie-break. */
				goto klmirqd_tie_break;
			}
		}

		if (tsk_rt(first)->is_interrupt_thread &&
			tsk_rt(second)->is_interrupt_thread &&
			(tsk_rt(first)->inh_task == tsk_rt(second)->inh_task)) {
			/* inh_task is !NULL for both tasks since neither was a lo_klmirqd
			   task. Both klmirqd tasks inherit from the same task, so
			   tie-break by base priority of the klmirqd tasks. */
			goto klmirqd_tie_break;
		}
	}
#endif


#ifdef CONFIG_LITMUS_LOCKING
	/* Check for EFFECTIVE priorities. Change task
	 * used for comparison in such a case.
	 */
	if (unlikely(tsk_rt(first)->inh_task)
#ifdef CONFIG_LITMUS_NESTED_LOCKING
		&& (first_mode == EFFECTIVE)
#endif
		) {
		first_task = tsk_rt(first)->inh_task;
	}
	if (unlikely(tsk_rt(second)->inh_task)
#ifdef CONFIG_LITMUS_NESTED_LOCKING
		&& (second_mode == EFFECTIVE)
#endif
		) {
		second_task = tsk_rt(second)->inh_task;
	}

	/* Check for priority boosting. Tie-break by start of boosting.
	 */
	if (unlikely(is_priority_boosted(first_task))) {
		/* first_task is boosted, how about second_task? */
		if (!is_priority_boosted(second_task) ||
		    lt_before(get_boost_start(first_task),
					  get_boost_start(second_task))) {
			return 1;
		}
		else {
			return 0;
		}
	}
	else if (unlikely(is_priority_boosted(second_task))) {
		/* second_task is boosted, first is not*/
		return 0;
	}
#endif

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
aux_tie_break:
#endif
#ifdef CONFIG_LITMUS_SOFTIRQD
klmirqd_tie_break:
#endif

	if (earlier_deadline(first_task, second_task))
		return 1;
	else if (get_deadline(first_task) == get_deadline(second_task)) {
		/* Backlog from budget exhaustion masks lateness.
		   Tie-break on backlog first. */
		lt_t first_bl_time;
		lt_t second_bl_time;

		first_bl_time = get_exec_cost(first_task)*get_backlog(first_task);
		second_bl_time = get_exec_cost(second_task)*get_backlog(second_task);

		/* the one with the greatest backlog gets to run */
		if (first_bl_time > second_bl_time)
			return 1;
		else if (first_bl_time == second_bl_time) {
			/* Need to tie break. All methods must set pid_break to 0/1 if
			 * first_task does not have priority over second_task.
			 */
			int pid_break;

#if defined(CONFIG_EDF_TIE_BREAK_LATENESS)
			/* Tie break by lateness. Jobs with greater lateness get
			 * priority. This should spread tardiness across all tasks,
			 * especially in task sets where all tasks have the same
			 * period and relative deadlines.
			 */
			if (get_lateness(first_task) > get_lateness(second_task))
				return 1;
			pid_break = (get_lateness(first_task) == get_lateness(second_task));

#elif defined(CONFIG_EDF_TIE_BREAK_LATENESS_NORM)
			/* Tie break by lateness, normalized by relative deadline. Jobs with
			   greater normalized lateness get priority.

			   Note: Considered using the algebraically equivalent
			     lateness(first)*relative_deadline(second) >
			        lateness(second)*relative_deadline(first)
			   to avoid fixed-point math, but values are prone to overflow if
			   inputs are on the order of several seconds, even in 64-bit.
			 */
			fp_t fnorm = _frac(get_lateness(first_task),
							get_rt_relative_deadline(first_task));
			fp_t snorm = _frac(get_lateness(second_task),
							get_rt_relative_deadline(second_task));
			if (_gt(fnorm, snorm))
				return 1;
			pid_break = _eq(fnorm, snorm);

#elif defined(CONFIG_EDF_TIE_BREAK_HASH)
			/* Tie break by comparing hashs of (pid, job#) tuple. There should
			   be a 50% chance that first_task has a higher priority than
			   second_task. */
			long fhash = edf_hash(first_task);
			long shash = edf_hash(second_task);
			if (fhash < shash)
				return 1;
			pid_break = (fhash == shash);
#else
			/* CONFIG_EDF_PID_TIE_BREAK */
			pid_break = 1; /* fall through to tie-break by pid */
#endif

			/* Tie break by pid */
			if(pid_break) {
				if (first_task->pid < second_task->pid) {
					return 1;
				}
				else if (first_task->pid == second_task->pid) {
					/* there is inheritance going on. consider inheritors. */
#ifdef CONFIG_LITMUS_SOFTIRQD
					/* non-interrupt thread gets prio */
					if (!tsk_rt(first)->is_interrupt_thread &&
									tsk_rt(second)->is_interrupt_thread) {
						return 1;
					}
					else if (tsk_rt(first)->is_interrupt_thread ==
									tsk_rt(second)->is_interrupt_thread) { /**/
#endif

#if defined(CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE)
					/* non-aux thread gets prio */
					if (!tsk_rt(first)->is_aux_task &&
									tsk_rt(second)->is_aux_task) {
						return 1;
					}
					else if (tsk_rt(first_task)->is_aux_task ==
									tsk_rt(second_task)->is_aux_task) { /**/
#endif
					/* if both tasks inherit from the same task */
					if (tsk_rt(first)->inh_task == tsk_rt(second)->inh_task) {
						/* TODO: Make a recurive call to edf_higher_prio,
						   comparing base priorities. */
						return (first->pid < second->pid);
					}
					else {
						/* At least one task must inherit */
						BUG_ON(!tsk_rt(first)->inh_task &&
							   !tsk_rt(second)->inh_task);

						/* The task withOUT the inherited priority wins. */
						if (tsk_rt(second)->inh_task) {
							return 1;
						}
					}
#if defined(CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE)
					}
#endif
#ifdef CONFIG_LITMUS_SOFTIRQD
					}
#endif
				}
			}
		}
	}

	return 0; /* fall-through. prio(second_task) > prio(first_task) */
}

#ifdef CONFIG_LITMUS_NESTED_LOCKING
int edf_higher_prio(const struct task_struct* first, const struct task_struct* second)
{
	return __edf_higher_prio(first, EFFECTIVE, second, EFFECTIVE);
}

int edf_max_heap_order(const struct binheap_node *a, const struct binheap_node *b)
{
	const struct nested_info *l_a = (struct nested_info *)binheap_entry(a,
					struct nested_info, hp_binheap_node);
	const struct nested_info *l_b = (struct nested_info *)binheap_entry(b,
					struct nested_info, hp_binheap_node);

	return __edf_higher_prio(l_a->hp_waiter_eff_prio, EFFECTIVE,
					l_b->hp_waiter_eff_prio, EFFECTIVE);
}

int edf_min_heap_order(const struct binheap_node *a, const struct binheap_node *b)
{
	return edf_max_heap_order(b, a);  /* swap comparison */
}

int edf_max_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	const struct nested_info *l_a = (struct nested_info *)binheap_entry(a,
					struct nested_info, hp_binheap_node);
	const struct nested_info *l_b = (struct nested_info *)binheap_entry(b,
					struct nested_info, hp_binheap_node);

	return __edf_higher_prio(l_a->hp_waiter_eff_prio, BASE,
					l_b->hp_waiter_eff_prio, BASE);
}

int edf_min_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	return edf_max_heap_base_priority_order(b, a);  /* swap comparison */
}
#endif

int edf_ready_order(const struct bheap_node* a, const struct bheap_node* b)
{
	return edf_higher_prio(bheap2task(a), bheap2task(b));
}

void edf_domain_init(rt_domain_t* rt, check_resched_needed_t resched,
				release_jobs_t release)
{
	rt_domain_init(rt,  edf_ready_order, resched, release);
}

/* need_to_preempt - check whether the task t needs to be preempted
 *                   call only with irqs disabled and with  ready_lock acquired
 *                   THIS DOES NOT TAKE NON-PREEMPTIVE SECTIONS INTO ACCOUNT!
 */
int edf_preemption_needed(rt_domain_t* rt, struct task_struct *t)
{
	/* we need the read lock for edf_ready_queue */
	/* no need to preempt if there is nothing pending */
	if (!__jobs_pending(rt))
		return 0;
	/* we need to reschedule if t doesn't exist */
	if (!t)
		return 1;

	/* NOTE: We cannot check for non-preemptibility since we
	 *       don't know what address space we're currently in.
	 */

	/* make sure to get non-rt stuff out of the way */
	return !is_realtime(t) || edf_higher_prio(__next_ready(rt), t);
}
