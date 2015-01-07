/*
 * litmus/sched_cedf.c
 *
 * Implementation of the C-EDF scheduling algorithm.
 *
 * This implementation is based on G-EDF:
 * - CPUs are clustered around L2 or L3 caches.
 * - Clusters topology is automatically detected (this is arch dependent
 *   and is working only on x86 at the moment --- and only with modern
 *   cpus that exports cpuid4 information)
 * - The plugins _does not_ attempt to put tasks in the right cluster i.e.
 *   the programmer needs to be aware of the topology to place tasks
 *   in the desired cluster
 * - default clustering is around L2 cache (cache index = 2)
 *   supported clusters are: L1 (private cache: pedf), L2, L3, ALL (all
 *   online_cpus are placed in a single cluster).
 *
 *   For details on functions, take a look at sched_gsn_edf.c
 *
 * Currently, we do not support changes in the number of online cpus.
 * If the num_online_cpus() dynamically changes, the plugin is broken.
 *
 * This version uses the simple approach and serializes all scheduling
 * decisions by the use of a queue lock. This is probably not the
 * best way to do it, but it should suffice for now.
 */

#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/module.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/preempt.h>
#include <litmus/budget.h>
#include <litmus/sched_plugin.h>
#include <litmus/edf_common.h>
#include <litmus/sched_trace.h>

#include <litmus/clustered.h>

#include <litmus/bheap.h>
#include <litmus/binheap.h>
#include <litmus/sbinheap.h>
#include <litmus/trace.h>

/* to configure the cluster size */
#include <litmus/litmus_proc.h>

#ifdef CONFIG_SCHED_CPU_AFFINITY
#include <litmus/affinity.h>
#endif

#ifdef CONFIG_SCHED_PGM
#include <litmus/pgm.h>
#endif

#ifdef CONFIG_LITMUS_LOCKING
#include <litmus/kfmlp_lock.h>
#endif

#ifdef CONFIG_LITMUS_NESTED_LOCKING
#include <litmus/fifo_lock.h>
#include <litmus/prioq_lock.h>
#include <litmus/r2dglp_lock.h>
#endif

#ifdef CONFIG_REALTIME_AUX_TASKS
#include <litmus/aux_tasks.h>
#endif

#ifdef CONFIG_LITMUS_SOFTIRQD
#include <litmus/klmirqd.h>
#endif

#ifdef CONFIG_LITMUS_NVIDIA
#include <litmus/nvidia_info.h>
#endif

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#endif

/* Reference configuration variable. Determines which cache level is used to
 * group CPUs into clusters.  GLOBAL_CLUSTER, which is the default, means that
 * all CPUs form a single cluster (just like GSN-EDF).
 */
static enum cache_level cluster_config = GLOBAL_CLUSTER;

struct clusterdomain;

/* cpu_entry_t - maintain the linked and scheduled state
 *
 * A cpu also contains a pointer to the cedf_domain_t cluster
 * that owns it (struct clusterdomain*)
 */
typedef struct  {
	int 			cpu;
	struct clusterdomain*	cluster;	/* owning cluster */
	struct task_struct*	linked;		/* only RT tasks */
	struct task_struct*	scheduled;	/* only RT tasks */
	atomic_t		will_schedule;	/* prevent unneeded IPIs */
	sbinheap_node_t	hn;
} cpu_entry_t;

/* one cpu_entry_t per CPU */
DEFINE_PER_CPU(cpu_entry_t, cedf_cpu_entries);

#define set_will_schedule() \
	(atomic_set(&__get_cpu_var(cedf_cpu_entries).will_schedule, 1))
#define clear_will_schedule() \
	(atomic_set(&__get_cpu_var(cedf_cpu_entries).will_schedule, 0))
#define test_will_schedule(cpu) \
	(atomic_read(&per_cpu(cedf_cpu_entries, cpu).will_schedule))

/*
 * In C-EDF there is a cedf domain _per_ cluster
 * The number of clusters is dynamically determined accordingly to the
 * total cpu number and the cluster size
 */
typedef struct clusterdomain {
	/* rt_domain for this cluster */
	rt_domain_t	domain;
	/* cpus in this cluster */
	cpu_entry_t*	*cpus;
	/* map of this cluster cpus */
	cpumask_var_t	cpu_map;
	/* the cpus queue themselves according to priority in here */
	struct sbinheap cpu_heap;

#define cluster_lock domain.ready_lock

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t dgl_lock;
#endif

	struct sbinheap top_m;
	struct binheap	not_top_m;

} cedf_domain_t;


/* a cedf_domain per cluster; allocation is done at init/activation time */
cedf_domain_t *cedf;

#define remote_cluster(cpu)	\
		((cedf_domain_t *) per_cpu(cedf_cpu_entries, cpu).cluster)
#define task_cpu_cluster(task)	remote_cluster(get_partition(task))

/* total number of cluster */
static int num_clusters;
/* we do not support cluster of different sizes */
static unsigned int cluster_size;

static int clusters_allocated = 0;


#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
static int num_gpu_clusters;
static unsigned int gpu_cluster_size;
#endif

inline static const struct task_struct* binheap_node_to_task(const struct binheap_node *bn)
{
	const struct budget_tracker *bt =
		binheap_entry(bn, struct budget_tracker, not_top_m_node);
	const struct task_struct *t =
		container_of(
			 container_of(bt, struct rt_param, budget),
				 struct task_struct,
				 rt_param);
	return t;
}

static int cedf_max_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	const struct task_struct* t_a = binheap_node_to_task(a);
	const struct task_struct* t_b = binheap_node_to_task(b);
	return __edf_higher_prio(t_a, BASE, t_b, BASE);
}

inline static const struct task_struct* sbinheap_node_to_task(const struct sbinheap_node *bn)
{
	const struct budget_tracker *bt =
		sbinheap_entry(bn, struct budget_tracker, top_m_node);
	const struct task_struct *t =
		container_of(
			 container_of(bt, struct rt_param, budget),
				 struct task_struct,
				 rt_param);
	return t;
}

static int cedf_min_heap_base_priority_order(const struct sbinheap_node *a,
				const struct sbinheap_node *b)
{
	const struct task_struct* t_a = sbinheap_node_to_task(a);
	const struct task_struct* t_b = sbinheap_node_to_task(b);
	return __edf_higher_prio(t_b, BASE, t_a, BASE);
}

static void cedf_track_in_top_m(struct task_struct *t)
{
	/* cluster lock must be held */
	cedf_domain_t *cluster = task_cpu_cluster(t);
	struct budget_tracker *bt;
	struct task_struct *mth_highest;

	if (sbinheap_is_in_heap(&tsk_rt(t)->budget.top_m_node) ||
		binheap_is_in_heap(&tsk_rt(t)->budget.not_top_m_node))
		return;

	/* TODO: do cluster_size-1 if release master is in this cluster */
	if (cluster->top_m.size < cluster_size) {
		sbinheap_add(&tsk_rt(t)->budget.top_m_node, &cluster->top_m,
					struct budget_tracker, top_m_node);
		bt_flag_set(t, BTF_IS_TOP_M);
		budget_state_machine(t,on_enter_top_m);

		return;
	}

	BUG_ON(sbinheap_empty(&cluster->top_m));

	bt = sbinheap_top_entry(&cluster->top_m, struct budget_tracker, top_m_node);
	mth_highest =
		container_of(
			container_of(bt, struct rt_param, budget),
				struct task_struct,
				rt_param);

	if (__edf_higher_prio(t, BASE, mth_highest, BASE)) {
		/* remove m-th task from the top_m heap and add
		   it to the not-top-m heap */
		sbinheap_delete_root(&cluster->top_m, struct budget_tracker, top_m_node);
		INIT_SBINHEAP_NODE(&tsk_rt(mth_highest)->budget.top_m_node);

		binheap_add(&tsk_rt(mth_highest)->budget.not_top_m_node,
					&cluster->not_top_m,
					struct budget_tracker, not_top_m_node);
		budget_state_machine(mth_highest,on_exit_top_m);
		bt_flag_clear(mth_highest, BTF_IS_TOP_M);

		/* add t to the top_m heap */
		sbinheap_add(&tsk_rt(t)->budget.top_m_node, &cluster->top_m,
					struct budget_tracker, top_m_node);
		bt_flag_set(t, BTF_IS_TOP_M);
		budget_state_machine(t,on_enter_top_m);
	}
	else {
		binheap_add(&tsk_rt(t)->budget.not_top_m_node,
					&cluster->not_top_m,
					struct budget_tracker, not_top_m_node);
	}
}

static void cedf_untrack_in_top_m(struct task_struct *t)
{
	/* cluster lock must be held */
	cedf_domain_t *cluster = task_cpu_cluster(t);
	int exited_top_m = 0;

	BUG_ON(sbinheap_is_in_heap(&tsk_rt(t)->budget.top_m_node) &&
	       binheap_is_in_heap(&tsk_rt(t)->budget.not_top_m_node));

	if (sbinheap_is_in_heap(&tsk_rt(t)->budget.top_m_node)) {
		exited_top_m = bt_flag_is_set(t, BTF_IS_TOP_M);
		WARN_ON_ONCE(!exited_top_m);

		sbinheap_delete(&tsk_rt(t)->budget.top_m_node, &cluster->top_m);
		INIT_SBINHEAP_NODE(&tsk_rt(t)->budget.top_m_node);

		if (likely(exited_top_m)) {
			budget_state_machine(t,on_exit_top_m);
			bt_flag_clear(t, BTF_IS_TOP_M);
		}
	}
	else if(likely(binheap_is_in_heap(&tsk_rt(t)->budget.not_top_m_node))) {
		binheap_delete(&tsk_rt(t)->budget.not_top_m_node, &cluster->not_top_m);
		INIT_BINHEAP_NODE(&tsk_rt(t)->budget.not_top_m_node);
	}

	/* move a task over from the overflow heap */
	if(!sbinheap_full(&cluster->top_m) &&
	   !binheap_empty(&cluster->not_top_m)) {
		struct budget_tracker *bt =
			binheap_top_entry(&cluster->not_top_m, struct budget_tracker,
				not_top_m_node);
		struct task_struct *to_move =
			container_of(
				 container_of(bt, struct rt_param, budget),
					 struct task_struct,
					 rt_param);

		/* task should have already been moved into the top m */
		WARN_ON_ONCE(!exited_top_m);

		binheap_delete_root(&cluster->not_top_m, struct budget_tracker,
					not_top_m_node);
		INIT_BINHEAP_NODE(&tsk_rt(to_move)->budget.not_top_m_node);

		sbinheap_add(&tsk_rt(to_move)->budget.top_m_node,
					&cluster->top_m,
					struct budget_tracker, top_m_node);
		bt_flag_set(to_move, BTF_IS_TOP_M);
		budget_state_machine(to_move,on_enter_top_m);
	}
}


#ifdef CONFIG_LITMUS_DGL_SUPPORT
static raw_spinlock_t* cedf_get_dgl_spinlock(struct task_struct *t)
{
	cedf_domain_t *cluster = task_cpu_cluster(t);
	return(&cluster->dgl_lock);
}
#endif


/* Uncomment WANT_ALL_SCHED_EVENTS if you want to see all scheduling
 * decisions in the TRACE() log; uncomment VERBOSE_INIT for verbose
 * information during the initialization of the plugin (e.g., topology)
#define WANT_ALL_SCHED_EVENTS
 */
#define VERBOSE_INIT

static int cpu_lower_prio(const struct sbinheap_node *_a,
		const struct sbinheap_node *_b)
{
	const cpu_entry_t *a = sbinheap_entry(_a, cpu_entry_t, hn);
	const cpu_entry_t *b = sbinheap_entry(_b, cpu_entry_t, hn);

	/* Note that a and b are inverted: we want the lowest-priority CPU at
	 * the top of the heap.
	 */
	return edf_higher_prio(b->linked, a->linked);
}

/* update_cpu_position - Move the cpu entry to the correct place to maintain
 *                       order in the cpu queue. Caller must hold cedf lock.
 */
static void update_cpu_position(cpu_entry_t *entry)
{
	cedf_domain_t *cluster = entry->cluster;

	if (likely(sbinheap_is_in_heap(&entry->hn))) {
		sbinheap_delete(&entry->hn, &cluster->cpu_heap);
	}

	sbinheap_add(&entry->hn, &cluster->cpu_heap, cpu_entry_t, hn);
}

/* caller must hold cedf lock */
static cpu_entry_t* lowest_prio_cpu(cedf_domain_t *cluster)
{
	return sbinheap_top_entry(&cluster->cpu_heap, cpu_entry_t, hn);
}

static noinline void unlink(struct task_struct* t);

/* link_task_to_cpu - Update the link of a CPU.
 *                    Handles the case where the to-be-linked task is already
 *                    scheduled on a different CPU.
 */
static noinline void link_task_to_cpu(struct task_struct* linked,
				      cpu_entry_t *entry)
{
	cpu_entry_t *sched;
	struct task_struct* tmp;
	int on_cpu;

	BUG_ON(linked && !is_realtime(linked));

	/* Currently linked task is set to be unlinked. */
	if (entry->linked) {
		entry->linked->rt_param.linked_on = NO_CPU;

#ifdef CONFIG_LITMUS_LOCKING
		if (tsk_rt(entry->linked)->inh_task) {
			clear_inh_task_linkback(entry->linked,
							tsk_rt(entry->linked)->inh_task);
		}
#endif
	}

	/* Link new task to CPU. */
	if (linked) {
		/* handle task is already scheduled somewhere! */
		on_cpu = linked->rt_param.scheduled_on;
		if (on_cpu != NO_CPU) {
			sched = &per_cpu(cedf_cpu_entries, on_cpu);

			BUG_ON(sched->linked == linked);

			/* If we are already scheduled on the CPU to which we
			 * wanted to link, we don't need to do the swap --
			 * we just link ourselves to the CPU and depend on
			 * the caller to get things right.
			 */
			if (entry != sched) {
				TRACE_TASK(linked,
					   "already scheduled on %d, updating link.\n",
					   sched->cpu);
				tmp = sched->linked;
				linked->rt_param.linked_on = sched->cpu;
				sched->linked = linked;

				/* EDF-compare may complain that we compare a task
				 * to itself. This is possible since 'linked' is
				 * temporarily linked to two CPUs while we perform
				 * this update. This is fixed just a few lines below. */
				update_cpu_position(sched);
				linked = tmp;
			}
		}
		if (linked) { /* might be NULL due to swap */
			linked->rt_param.linked_on = entry->cpu;

#ifdef CONFIG_LITMUS_LOCKING
			if (tsk_rt(linked)->inh_task)
				set_inh_task_linkback(linked, tsk_rt(linked)->inh_task);
#endif
		}
	}
	entry->linked = linked;
#ifdef WANT_ALL_SCHED_EVENTS
	if (linked)
		TRACE_TASK(linked, "linked to %d.\n", entry->cpu);
	else
		TRACE("NULL linked to %d.\n", entry->cpu);
#endif
	update_cpu_position(entry);
}

/* unlink - Make sure a task is not linked any longer to an entry
 *          where it was linked before. Must hold cluster_lock.
 */
static noinline void unlink(struct task_struct* t)
{
	if (t->rt_param.linked_on != NO_CPU) {
		/* unlink */
		cpu_entry_t *entry = &per_cpu(cedf_cpu_entries, t->rt_param.linked_on);
		t->rt_param.linked_on = NO_CPU;
		link_task_to_cpu(NULL, entry);
	} else if (is_queued(t)) {
		/* This is an interesting situation: t is scheduled,
		 * but was just recently unlinked.  It cannot be
		 * linked anywhere else (because then it would have
		 * been relinked to this CPU), thus it must be in some
		 * queue. We must remove it from the list in this
		 * case.
		 *
		 * in C-EDF case is should be somewhere in the queue for
		 * its domain, therefore and we can get the domain using
		 * task_cpu_cluster
		 */
		remove(&(task_cpu_cluster(t))->domain, t);
	}
}


/* preempt - force a CPU to reschedule
 */
static void preempt(cpu_entry_t *entry)
{
	preempt_if_preemptable(entry->scheduled, entry->cpu);
}

/* requeue - Put an unlinked task into gsn-edf domain.
 *           Caller must hold cluster_lock.
 */
static noinline void requeue(struct task_struct* task)
{
	cedf_domain_t *cluster = task_cpu_cluster(task);
	BUG_ON(!task);
	/* sanity check before insertion */
	BUG_ON(is_queued(task));

	if (is_early_releasing(task) || is_released(task, litmus_clock()) ||
					tsk_rt(task)->job_params.is_backlogged_job) {
#ifdef CONFIG_REALTIME_AUX_TASKS
		if (unlikely(tsk_rt(task)->is_aux_task &&
				task->state != TASK_RUNNING && !tsk_rt(task)->aux_ready)) {
			/* aux_task probably transitioned to real-time while blocked */
			TRACE_CUR("aux task %s/%d is not ready!\n", task->comm, task->pid);
			tsk_rt(task)->aux_ready = 1; /* limit to once per aux task */
		}
		else
#endif
			__add_ready(&cluster->domain, task);
	}
	else {
		TRACE_TASK(task, "not requeueing not-yet-released job\n");
	}
}

#ifdef CONFIG_SCHED_CPU_AFFINITY
static cpu_entry_t* cedf_get_nearest_available_cpu(
				cedf_domain_t *cluster, cpu_entry_t *start)
{
	cpu_entry_t *affinity;

	get_nearest_available_cpu(affinity, start, cedf_cpu_entries,
#ifdef CONFIG_RELEASE_MASTER
		cluster->domain.release_master
#else
		NO_CPU
#endif
		);

	/* make sure CPU is in our cluster */
	if (affinity && cpu_isset(affinity->cpu, *cluster->cpu_map))
		return(affinity);
	else
		return(NULL);
}
#endif /* end SCHED_CPU_AFFINITY */


/* check for any necessary preemptions */
static void check_for_preemptions(cedf_domain_t *cluster)
{
	struct task_struct *task;
	cpu_entry_t *last;

	int loop_guard;

#ifdef CONFIG_PREFER_LOCAL_LINKING
	cpu_entry_t *local;

	/* Before linking to other CPUs, check first whether the local CPU is
	 * idle. */
	local = &__get_cpu_var(cedf_cpu_entries);
	task  = __peek_ready(&cluster->domain);

	if (task && !local->linked
#ifdef CONFIG_RELEASE_MASTER
	    && likely(local->cpu != cluster->domain.release_master)
#endif
		) {
		task = __take_ready(&cluster->domain);
		TRACE_TASK(task, "linking to local CPU %d to avoid IPI\n", local->cpu);
		link_task_to_cpu(task, local);
		preempt(local);
	}
#endif

	for(last = lowest_prio_cpu(cluster), loop_guard = 0;
	    edf_preemption_needed(&cluster->domain, last->linked);
	    last = lowest_prio_cpu(cluster), ++loop_guard) {

		/* preemption necessary */
		task = __take_ready(&cluster->domain);
		TRACE("attempting to link task %d to %d\n",
		      task->pid, last->cpu);

		/* we've looped too many times. start print dbg info on tasks */
		if (loop_guard >= cluster_size)
		{
			TRACE_TASK(task, "!!!! abs_dead:%llu  is_aux:%d  is_isrh:%d  inherits:%d  backlog:%d\n",
				get_deadline(task),
				tsk_rt(task)->is_aux_task,
				tsk_rt(task)->is_interrupt_task,
				((tsk_rt(task)->inh_task != NULL) ? 1 : 0),
				get_backlog(task)
				);

			if (tsk_rt(task)->inh_task != NULL)
			{
				TRACE_TASK(task, "!!!! INH: (%s/%d): dead:%llu is_aux:%d  is_isrh:%d  backlog:%d\n",
					tsk_rt(task)->inh_task->comm, tsk_rt(task)->inh_task->pid,
					get_deadline(tsk_rt(task)->inh_task),
					tsk_rt(tsk_rt(task)->inh_task)->is_aux_task,
					tsk_rt(tsk_rt(task)->inh_task)->is_interrupt_task,
					get_backlog(tsk_rt(task)->inh_task)
					);
			}
		}

#ifdef CONFIG_SCHED_CPU_AFFINITY
		{
			cpu_entry_t *affinity =
					cedf_get_nearest_available_cpu(cluster,
						&per_cpu(cedf_cpu_entries, task_cpu(task)));
			if(affinity)
				last = affinity;
			else if(requeue_preempted_job(last->linked))
				requeue(last->linked);
		}
#else
		if (requeue_preempted_job(last->linked))
			requeue(last->linked);
#endif
		link_task_to_cpu(task, last);
		preempt(last);
	}
}

/* cedf_job_arrival: task is either resumed or released */
static noinline void cedf_job_arrival(struct task_struct* task)
{
	cedf_domain_t *cluster = task_cpu_cluster(task);
	BUG_ON(!task);

	requeue(task);
	check_for_preemptions(cluster);
}

static void cedf_track_on_release(struct bheap_node* n, void* dummy)
{
	struct task_struct* t = bheap2task(n);
	cedf_track_in_top_m(t);
}

static void cedf_release_jobs(rt_domain_t* rt, struct bheap* tasks)
{
	cedf_domain_t* cluster = container_of(rt, cedf_domain_t, domain);
	unsigned long flags;

	raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);

	bheap_for_each(tasks, cedf_track_on_release, NULL);

	__merge_ready(&cluster->domain, tasks);
	check_for_preemptions(cluster);

	raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);
}

/* Uncomment to not discard remaining budget upon backlog completion. Allowing
 * consumption of remaining budget may affect schedulability analysis where
 * locking protocols are concerned.
 *
 * Probably best to leave this disabled for now.
 *
#define DONT_DISCARD_REMAINING_BUDGET
*/

/* caller holds cluster_lock */
static noinline void job_completion(struct task_struct *t, int forced)
{
	int do_release = 0;
	int backlogged = 0;
	lt_t now;

	BUG_ON(!t);

	now = litmus_clock();

	/* DO BACKLOG TRACKING */

	/* job completed with budget remaining */
	if (!is_sporadic(t) && !is_daemon(t)) {
		/* only jobs we know that will call sleep_next_job()
		   can use backlogging */
		if (!forced) {
			/* was it a backlogged job that completed? */
			if (tsk_rt(t)->job_params.is_backlogged_job) {
				TRACE_TASK(t, "completed backlogged job\n");
				if (get_backlog(t)) {
					--get_backlog(t);
					/* is_backlogged_job remains asserted */
				}
				else {
					/* caught up completely */
					TRACE_TASK(t, "completely caught up.\n");
					tsk_rt(t)->job_params.is_backlogged_job = 0;
					/* we now look like a normally completing job. */
				}
			}
		}
		else {
			++get_backlog(t);
			TRACE_TASK(t, "adding backlogged job\n");
		}

		backlogged = has_backlog(t);
		TRACE_TASK(t, "number of backlogged jobs: %u\n",
				   get_backlog(t));
	}

	/* SETUP FOR THE NEXT JOB */

	sched_trace_task_completion(t, forced);

	TRACE_TASK(t, "job_completion() at %llu (forced = %d).\n", now, forced);

	/* set flags */
	tsk_rt(t)->completed = 0;

#ifdef DONT_DISCARD_REMAINING_BUDGET
	if (unlikely(!forced && backlogged)) {
		/* Don't advance deadline/refresh budget. Use the remaining budget for
		 * the backlogged job.
		 *
		 * NOTE: Allowing backlogged jobs comsume remaining budget may affect
		 * blocking bound analysis.
		 */
	}
	else if (unlikely(!forced && tsk_rt(t)->job_params.is_backlogged_job)) {
		/* we've just about caught up, but we still have the job of this
		 * budget's allocation to do (even if it's for the future)... */
		TRACE_TASK(t, "Releasing final catch-up job.\n");
		backlogged = 1;
	}
	else {
#endif
		cedf_untrack_in_top_m(t);
		prepare_for_next_period(t);

		do_release = (is_early_releasing(t) || is_released(t, now));

		if (backlogged) {
			TRACE_TASK(t, "refreshing budget with early "
					   "release for backlogged job.\n");
		}
		if (do_release || backlogged) {
			/* log here to capture overheads */
			sched_trace_task_release(t);
		}
#ifdef DONT_DISCARD_REMAINING_BUDGET
	}
#endif

	unlink(t);

	/* release or arm next job */
	if (is_running(t)) {
		/* is our next job a backlogged job? */
		if (backlogged) {
			TRACE_TASK(t, "next job is a backlogged job.\n");
			tsk_rt(t)->job_params.is_backlogged_job = 1;
		}
		else {
			TRACE_TASK(t, "next job is a regular job.\n");
			tsk_rt(t)->job_params.is_backlogged_job = 0;
		}

		if (do_release || backlogged) {
			cedf_track_in_top_m(t);
			cedf_job_arrival(t);
		}
		else {
			add_release(&task_cpu_cluster(t)->domain, t);
		}
	}
	else {
		BUG_ON(!forced);
		/* budget was refreshed and job early released */
		TRACE_TASK(t, "job exhausted budget while sleeping\n");
		cedf_track_in_top_m(t);
	}
}

static enum hrtimer_restart cedf_simple_on_exhausted(struct task_struct *t,
				int in_schedule)
{
	/* Assumption: t is scheduled on the CPU executing this callback */

	if (in_schedule) {
		BUG_ON(tsk_rt(t)->scheduled_on != smp_processor_id());
		if (budget_precisely_tracked(t) && cancel_enforcement_timer(t) < 0) {
			TRACE_TASK(t, "raced with timer. deffering to timer.\n");
			goto out;
		}
	}

	if (budget_signalled(t) && !bt_flag_is_set(t, BTF_SIG_BUDGET_SENT)) {
		/* signal exhaustion */
		send_sigbudget(t); /* will set BTF_SIG_BUDGET_SENT */
	}

	if (budget_enforced(t) && !bt_flag_test_and_set(t, BTF_BUDGET_EXHAUSTED)) {
		if (likely(!is_np(t))) {
			/* np tasks will be preempted when they become
			 * preemptable again
			 */
			if (!in_schedule) {
				TRACE_TASK(t, "is preemptable => FORCE_RESCHED\n");
				litmus_reschedule_local();
				set_will_schedule();
			}
		} else if (is_user_np(t)) {
			TRACE_TASK(t, "is non-preemptable, preemption delayed.\n");
			request_exit_np(t);
		}
	}

out:
	return HRTIMER_NORESTART;
}


static enum hrtimer_restart cedf_simple_io_on_exhausted(struct task_struct *t,
				int in_schedule)
{
	enum hrtimer_restart restart = HRTIMER_NORESTART;

	if (in_schedule) {
		BUG_ON(tsk_rt(t)->scheduled_on != smp_processor_id());
		if (budget_precisely_tracked(t) && cancel_enforcement_timer(t) == -1) {
			TRACE_TASK(t, "raced with timer. deffering to timer.\n");
			goto out;
		}
	}

	/* t may or may not be scheduled */

	if (budget_signalled(t) && !bt_flag_is_set(t, BTF_SIG_BUDGET_SENT)) {
		/* signal exhaustion */

		/* Tasks should block SIG_BUDGET if they cannot gracefully respond to
		 * the signal while suspended. SIG_BUDGET is an rt-signal, so it will
		 * be queued and received when SIG_BUDGET is unblocked */
		send_sigbudget(t); /* will set BTF_SIG_BUDGET_SENT */
	}

	if (budget_enforced(t) && !bt_flag_is_set(t, BTF_BUDGET_EXHAUSTED)) {
		int cpu = (tsk_rt(t)->linked_on != NO_CPU) ?
			tsk_rt(t)->linked_on : tsk_rt(t)->scheduled_on;

		if (is_np(t) && is_user_np(t)) {
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			TRACE_TASK(t, "is non-preemptable, preemption delayed.\n");
			request_exit_np(t);
		}
		/* where do we need to call resched? */
		else if (cpu == smp_processor_id()) {
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			if (!in_schedule) {
				TRACE_TASK(t, "is preemptable => FORCE_RESCHED\n");
				litmus_reschedule_local();
				set_will_schedule();
			}
		}
		else if (cpu != NO_CPU) {
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			if (!in_schedule) {
				TRACE_TASK(t, "is preemptable on remote cpu "
						"(%d) => FORCE_RESCHED\n", cpu);
				litmus_reschedule(cpu);
			}
		}
		else if (unlikely(tsk_rt(t)->blocked_lock)) {
			/* we shouldn't be draining while waiting for litmus lock, but we
			 * could have raced with the budget timer (?). */
			WARN_ON(1);
		}
		else {
			lt_t remaining;
			cedf_domain_t *cluster;
			unsigned long flags, kludge_flags;

			BUG_ON(in_schedule);

			cluster = task_cpu_cluster(t);

			/*
			  1) refresh budget through job completion
			  2) if holds locks, tell the locking protocol to re-eval priority
			  3) -- the LP must undo any inheritance relations if appropriate
			 */

			/* force job completion */
			TRACE_TASK(t, "blocked, postponing deadline\n");

			local_irq_save(kludge_flags);

			/* Outermost lock of the cluster. Recursive lock calls are
			 * possible on this code path. This should be the _ONLY_
			 * scenario where recursive calls are made. */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			/* Unfortunately, we _might_ need to grab the DGL lock, so we
			 * must grab it every time since it must be take before the
			 * cluster lock. */
			raw_spin_lock_irqsave(&cluster->dgl_lock, flags);
			raw_readyq_lock(&cluster->cluster_lock);
#else
			raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);
#endif

			job_completion(t, 1); /* refreshes budget and pushes out deadline */

#ifdef CONFIG_LITMUS_LOCKING
			{
				int i;
				/* any linked task that inherits from 't' needs to have their
				 * cpu-position re-evaluated. we have to do this in two passes.
				 * pass 1: remove nodes from heap s.t. heap is in known
				 *         good state.
				 * pass 2: re-add nodes.
				 *
				 */
				for (i = find_first_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots));
					 i < BITS_PER_LONG;
					 i = find_next_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots),
						i+1))
				{
					struct task_struct *to_update =
							tsk_rt(t)->inh_task_linkbacks[i];
					BUG_ON(!to_update);
					if (tsk_rt(to_update)->linked_on != NO_CPU) {
						cpu_entry_t *entry = &per_cpu(cedf_cpu_entries,
										tsk_rt(to_update)->linked_on);
						BUG_ON(!sbinheap_is_in_heap(&entry->hn));
						sbinheap_delete(&entry->hn, &cluster->cpu_heap);
					}
				}
				for (i = find_first_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots));
					 i < BITS_PER_LONG;
					 i = find_next_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots),
						i+1))
				{
					struct task_struct *to_update =
							tsk_rt(t)->inh_task_linkbacks[i];
					BUG_ON(!to_update);
					if (tsk_rt(to_update)->linked_on != NO_CPU) {
						cpu_entry_t *entry = &per_cpu(cedf_cpu_entries,
										tsk_rt(to_update)->linked_on);
						sbinheap_add(&entry->hn, &cluster->cpu_heap,
										cpu_entry_t, hn);
					}
				}
			}

			/* Check our inheritance and propagate any changes forward. */
			reevaluate_inheritance(t);
#endif /* end LITMUS_LOCKING */
			/* No need to recheck priority of AUX tasks. They will always
			 * inherit from 't' if they are enabled. Their prio change was
			 * captured by the cpu-heap operations above. */

#ifdef CONFIG_LITMUS_NVIDIA
			/* Re-eval priority of GPU interrupt threads. */
			if(tsk_rt(t)->held_gpus && !tsk_rt(t)->hide_from_gpu)
				gpu_owner_decrease_priority(t);
#endif

#ifdef CONFIG_LITMUS_LOCKING
			/* double-check that everything is okay */
			check_for_preemptions(cluster);
#endif

			/* should be the outermost unlock call */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			raw_readyq_unlock(&cluster->cluster_lock);
			raw_spin_unlock_irqrestore(&cluster->dgl_lock, flags);
#else
			raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);
#endif
			flush_pending_wakes();
			local_irq_restore(kludge_flags);

			/* we need to set up the budget timer since we're
			   within the callback. */
			hrtimer_forward_now(&get_budget_timer(t).timer.timer,
							ns_to_ktime(budget_remaining(t)));
			remaining=hrtimer_get_expires_ns(&get_budget_timer(t).timer.timer);

			TRACE_TASK(t, "rearmed timer to %ld\n", remaining);
			restart = HRTIMER_RESTART;
		}
	}

out:
	return restart;
}


#ifdef CONFIG_LITMUS_LOCKING
static void __cedf_trigger_vunlock(struct task_struct *t)
{
	TRACE_TASK(t, "triggering virtual unlock of lock %d\n",
					tsk_rt(t)->outermost_lock->ident);
	tsk_rt(t)->outermost_lock->ops->omlp_virtual_unlock(
					tsk_rt(t)->outermost_lock, t);
}

static void cedf_trigger_vunlock(struct task_struct *t)
{
	cedf_domain_t *cluster = task_cpu_cluster(t);
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	unsigned long flags;

	/* Unfortunately, we _might_ need to grab the DGL lock, so we
	 * must grab it every time since it must be take before the
	 * cluster lock. */
	raw_spin_lock_irqsave(&cluster->dgl_lock, flags);
#endif

	__cedf_trigger_vunlock(t);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spin_unlock_irqrestore(&cluster->dgl_lock, flags);
#endif
}
#endif /* end LITMUS_LOCKING */

static enum hrtimer_restart cedf_sobliv_on_exhausted(struct task_struct *t,
				int in_schedule)
{
	enum hrtimer_restart restart = HRTIMER_NORESTART;

	if (in_schedule) {
		BUG_ON(tsk_rt(t)->scheduled_on != smp_processor_id());
		if (budget_precisely_tracked(t) && cancel_enforcement_timer(t) == -1) {
			TRACE_TASK(t, "raced with timer. deffering to timer.\n");
			goto out;
		}
	}

	/* t may or may not be scheduled */

	if (budget_signalled(t) && !bt_flag_is_set(t, BTF_SIG_BUDGET_SENT)) {
		/* signal exhaustion */

		/* Tasks should block SIG_BUDGET if they cannot gracefully respond to
		 * the signal while suspended. SIG_BUDGET is an rt-signal, so it will
		 * be queued and received when SIG_BUDGET is unblocked */
		send_sigbudget(t); /* will set BTF_SIG_BUDGET_SENT */
	}

	if (budget_enforced(t) && !bt_flag_is_set(t, BTF_BUDGET_EXHAUSTED)) {
		int cpu = (tsk_rt(t)->linked_on != NO_CPU) ?
				tsk_rt(t)->linked_on : tsk_rt(t)->scheduled_on;

#ifdef CONFIG_LITMUS_LOCKING
		/* if 't' running, trigger a virtual unlock of outermost held lock
		 * if supported. Case where 't' not running handled later in function.
		 */
		if (cpu != NO_CPU &&
			tsk_rt(t)->outermost_lock &&
			tsk_rt(t)->outermost_lock->ops->is_omlp_family)
				cedf_trigger_vunlock(t);
#endif

		if (is_np(t) && is_user_np(t)) {
			TRACE_TASK(t, "is non-preemptable, preemption delayed.\n");
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			request_exit_np(t);
		}
		/* where do we need to call resched? */
		else if (cpu == smp_processor_id()) {
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			if (!in_schedule) {
				TRACE_TASK(t, "is preemptable => FORCE_RESCHED\n");
				litmus_reschedule_local();
				set_will_schedule();
			}
		}
		else if (cpu != NO_CPU) {
			bt_flag_set(t, BTF_BUDGET_EXHAUSTED);
			if (!in_schedule) {
				litmus_reschedule(cpu);
				TRACE_TASK(t, "is preemptable on remote cpu "
						"(%d) => FORCE_RESCHED\n",
						cpu);
			}
		}
		else {
			lt_t remaining;
			cedf_domain_t *cluster;
			unsigned long flags, kludge_flags;

			BUG_ON(in_schedule);

			cluster = task_cpu_cluster(t);

			/*
			  1) refresh budget through job completion
			  2) if holds locks, tell the locking protocol to re-eval priority
			  3) -- the LP must undo any inheritance relations if appropriate
			 */

			/* force job completion */
			TRACE_TASK(t, "blocked, postponing deadline\n");

			local_irq_save(kludge_flags);

			/* Outermost lock of the cluster. Recursive lock calls are
			 * possible on this code path. This should be the _ONLY_
			 * scenario where recursive calls are made. */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			/* Unfortunately, we _might_ need to grab the DGL lock, so we
			 * must grab it every time since it must be take before the
			 * cluster lock. */
			raw_spin_lock_irqsave(&cluster->dgl_lock, flags);
			raw_readyq_lock(&cluster->cluster_lock);
#else
			raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);
#endif

			job_completion(t, 1); /* refreshes budget and pushes out deadline */

#ifdef CONFIG_LITMUS_LOCKING
			{
				int i;
				/* any linked task that inherits from 't' needs to have their
				 * cpu-position re-evaluated. we have to do this in two passes.
				 * pass 1: remove nodes from heap s.t. heap is in known
				 *         good state.
				 * pass 2: re-add nodes.
				 *
				 */
				for (i = find_first_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots));
					 i < BITS_PER_LONG;
					 i = find_next_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots),
						i+1))
				{
					struct task_struct *to_update =
							tsk_rt(t)->inh_task_linkbacks[i];
					BUG_ON(!to_update);
					if (tsk_rt(to_update)->linked_on != NO_CPU) {
						cpu_entry_t *entry = &per_cpu(cedf_cpu_entries,
										tsk_rt(to_update)->linked_on);
						BUG_ON(!sbinheap_is_in_heap(&entry->hn));
						sbinheap_delete(&entry->hn, &cluster->cpu_heap);
					}
				}
				for (i = find_first_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots));
					 i < BITS_PER_LONG;
					 i = find_next_bit(&tsk_rt(t)->used_linkback_slots,
						BITS_PER_BYTE*sizeof(&tsk_rt(t)->used_linkback_slots),
						i+1))
				{
					struct task_struct *to_update =
							tsk_rt(t)->inh_task_linkbacks[i];
					BUG_ON(!to_update);
					if (tsk_rt(to_update)->linked_on != NO_CPU) {
						cpu_entry_t *entry = &per_cpu(cedf_cpu_entries,
										tsk_rt(to_update)->linked_on);
						sbinheap_add(&entry->hn, &cluster->cpu_heap,
										cpu_entry_t, hn);
					}
				}
			}

			/* Check our inheritance and propagate any changes forward. */
			reevaluate_inheritance(t);

			if (tsk_rt(t)->outermost_lock &&
				tsk_rt(t)->outermost_lock->ops->is_omlp_family)
				__cedf_trigger_vunlock(t);
#endif /* end LITMUS_LOCKING */
			/* No need to recheck priority of AUX tasks. They will always
			 * inherit from 't' if they are enabled. Their prio change was
			 * captured by the cpu-heap operations above. */

#ifdef CONFIG_LITMUS_NVIDIA
			/* Re-eval priority of GPU interrupt threads. */
			if(tsk_rt(t)->held_gpus && !tsk_rt(t)->hide_from_gpu)
				gpu_owner_decrease_priority(t);
#endif

#ifdef CONFIG_LITMUS_LOCKING
			/* double-check that everything is okay */
			check_for_preemptions(cluster);
#endif

			/* should be the outermost unlock call */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			raw_readyq_unlock(&cluster->cluster_lock);
			raw_spin_unlock_irqrestore(&cluster->dgl_lock, flags);
#else
			raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);
#endif
			flush_pending_wakes();
			local_irq_restore(kludge_flags);

			/* we need to set up the budget timer since we're
			   within the callback. */
			if (bt_flag_is_set(t, BTF_IS_TOP_M)) {
				hrtimer_forward_now(&get_budget_timer(t).timer.timer,
									ns_to_ktime(budget_remaining(t)));
				remaining =
					hrtimer_get_expires_ns(&get_budget_timer(t).timer.timer);
				TRACE_TASK(t, "rearmed timer to %ld\n", remaining);
				restart = HRTIMER_RESTART;
			}
		}
	}

out:
	return restart;
}


/* cedf_tick - this function is called for every local timer
 *                         interrupt.
 *
 *                   checks whether the current task has expired and checks
 *                   whether we need to preempt it if it has not expired
 */
static void cedf_tick(struct task_struct* t)
{
	if (is_realtime(t) &&
		tsk_rt(t)->budget.ops && budget_quantum_tracked(t) &&
		budget_exhausted(t)) {
		TRACE_TASK(t, "budget exhausted\n");
		budget_state_machine2(t,on_exhausted,!IN_SCHEDULE);
	}
}

#ifdef CONFIG_LITMUS_LOCKING
static int __increase_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh);
#endif

/* Getting schedule() right is a bit tricky. schedule() may not make any
 * assumptions on the state of the current task since it may be called for a
 * number of reasons. The reasons include a scheduler_tick() determined that it
 * was necessary, because sys_exit_np() was called, because some Linux
 * subsystem determined so, or even (in the worst case) because there is a bug
 * hidden somewhere. Thus, we must take extreme care to determine what the
 * current state is.
 *
 * The CPU could currently be scheduling a task (or not), be linked (or not).
 *
 * The following assertions for the scheduled task could hold:
 *
 *  - !is_running(scheduled)    // the job blocks
 *	- scheduled->timeslice == 0	// the job completed (forcefully)
 *	- is_completed()            // the job completed (by syscall)
 * 	- linked != scheduled       // we need to reschedule (for any reason)
 * 	- is_np(scheduled)          // rescheduling must be delayed,
 *                              // sys_exit_np must be requested
 *
 * Any of these can occur together.
 */
static struct task_struct* cedf_schedule(struct task_struct * prev)
{
	cpu_entry_t* entry = &__get_cpu_var(cedf_cpu_entries);
	cedf_domain_t *cluster = entry->cluster;
	int out_of_time, sleep, preempt, np, exists, blocks;
	struct task_struct* next = NULL;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	int recheck_inheritance;
#endif

#ifdef CONFIG_RELEASE_MASTER
	/* Bail out early if we are the release master.
	 * The release master never schedules any real-time tasks.
	 */
	if (unlikely(cluster->domain.release_master == entry->cpu)) {
		sched_state_task_picked();
		return NULL;
	}
#endif

	/* Detect and handle budget exhaustion if it hasn't already been done.
	 * Do this before acquring any spinlocks. */
	if (prev && is_realtime(prev) &&
		budget_exhausted(prev)    &&
		!is_completed(prev)       && /* don't bother jobs on their way out */
		((budget_enforced(prev)   &&
			!bt_flag_is_set(prev, BTF_BUDGET_EXHAUSTED)) ||
		 (budget_signalled(prev)  &&
			!bt_flag_is_set(prev, BTF_SIG_BUDGET_SENT))) ) {
		TRACE_TASK(prev, "handling exhaustion in schedule() at %llu\n",
						litmus_clock());
		budget_state_machine2(prev,on_exhausted,IN_SCHEDULE);
	}

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	/* prevent updates to inheritance relations while we work with 'prev' */
	/* recheck inheritance if the task holds locks, is running, and will
	 * have its deadline pushed out by job_completion() */
	recheck_inheritance =
			prev                &&
			is_realtime(prev)   &&
			holds_locks(prev)   &&
			!is_np(prev)        &&
			!is_completed(prev) &&
			is_running(prev)    &&
			budget_enforced(prev) &&
			bt_flag_is_set(prev, BTF_BUDGET_EXHAUSTED);
	if (recheck_inheritance) {
#ifdef CONFIG_LITMUS_DGL_SUPPORT
		raw_spin_lock(&cluster->dgl_lock);
#endif
		raw_spin_lock(&tsk_rt(prev)->hp_blocked_tasks_lock);
	}
#endif

	raw_readyq_lock(&cluster->cluster_lock);
	clear_will_schedule();

	/* sanity checking */
	BUG_ON(entry->scheduled && entry->scheduled != prev);
	BUG_ON(entry->scheduled && !is_realtime(prev));
	BUG_ON(is_realtime(prev) && !entry->scheduled);

	/* (0) Determine state */
	exists      = entry->scheduled != NULL;
	blocks      = exists && !is_running(entry->scheduled);
	out_of_time = exists &&
				  budget_enforced(entry->scheduled) &&
				  bt_flag_is_set(entry->scheduled, BTF_BUDGET_EXHAUSTED);
	np 	    = exists && is_np(entry->scheduled);
	sleep	    = exists && is_completed(entry->scheduled);
	preempt     = entry->scheduled != entry->linked;

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "invoked cedf_schedule.\n");
#endif

	if (exists) {
		TRACE_TASK(prev,
			   "blocks:%d out_of_time:%d np:%d completed:%d preempt:%d "
			   "state:%d sig:%d is_boosted:%d is_aux:%d is_intr:%d\n",
			   blocks, out_of_time, np, sleep, preempt,
			   prev->state, signal_pending(prev),
			   is_priority_boosted(entry->scheduled),
			   tsk_rt(prev)->is_aux_task,
			   tsk_rt(prev)->is_interrupt_task);
	}
	if (entry->linked && preempt)
		TRACE_TASK(prev, "will be preempted by %s/%d\n",
			   entry->linked->comm, entry->linked->pid);

#ifdef CONFIG_SCHED_PGM
	if (exists) {
		if (is_pgm_sending(entry->scheduled)) {
			if (!is_pgm_satisfied(entry->scheduled)) {
				if (!is_priority_boosted(entry->scheduled)) {
					TRACE_TASK(entry->scheduled, "is sending PGM tokens and needs boosting.\n");
					BUG_ON(is_pgm_satisfied(entry->scheduled));

					/* We are either sending tokens or waiting for tokes.
					   If waiting: Boost priority so we'll be scheduled
						immediately when needed tokens arrive.
					   If sending: Boost priority so no one (specifically, our
						consumers) will preempt us while signalling the token
						transmission.
					*/
					tsk_rt(entry->scheduled)->priority_boosted = 1;
					tsk_rt(entry->scheduled)->boost_start_time = litmus_clock();

					if (likely(!blocks)) {
						unlink(entry->scheduled);
						cedf_job_arrival(entry->scheduled);
						/* we may regain the processor */
						if (preempt) {
							preempt = entry->scheduled != entry->linked;
							if (!preempt) {
								TRACE_TASK(entry->scheduled, "blocked preemption by lazy boosting.\n");
							}
						}
					}
				}
			}
			else { /* sending is satisfied */
				tsk_rt(entry->scheduled)->ctrl_page->pgm_sending = 0;
				tsk_rt(entry->scheduled)->ctrl_page->pgm_satisfied = 0;

				if (is_priority_boosted(entry->scheduled)) {
					TRACE_TASK(entry->scheduled,
							"is done sending PGM tokens must relinquish boosting.\n");
					/* clear boosting */
					tsk_rt(entry->scheduled)->priority_boosted = 0;
					if(likely(!blocks)) {
						/* recheck priority */
						unlink(entry->scheduled);
						cedf_job_arrival(entry->scheduled);
						/* we may lose the processor */
						if (!preempt) {
							preempt = entry->scheduled != entry->linked;
							if (preempt) {
								TRACE_TASK(entry->scheduled, "preempted by lazy unboosting.\n");
							}
						}
					}
				}
			}
		}
	}
#endif

#ifdef CONFIG_REALTIME_AUX_TASKS
	if (tsk_rt(prev)->is_aux_task &&
		(prev->state == TASK_INTERRUPTIBLE) &&
		!blocks) {
		TRACE_TASK(prev, "Deferring descheduling of aux task %s/%d.\n",
						prev->comm, prev->pid);
		next = prev; /* allow prev to continue. */
		goto out_set_state;
	}
#endif

	/* Do budget stuff */
	if (blocks) {
		if (likely(!bt_flag_is_set(prev, BTF_WAITING_FOR_RELEASE)))
			budget_state_machine(prev,on_blocked);
		else {
			/* waiting for release. 'exit' the scheduler. */
			cedf_untrack_in_top_m(prev);
			budget_state_machine(prev,on_exit);
		}
	}
	else if (sleep)
		budget_state_machine(prev,on_sleep);
	else if (preempt)
		budget_state_machine(prev,on_preempt);

	/* If a task blocks we have no choice but to reschedule.
	 */
	if (blocks)
		unlink(entry->scheduled);

#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_AFFINITY_LOCKING)
	if(exists && is_realtime(entry->scheduled) &&
					tsk_rt(entry->scheduled)->held_gpus) {
		if(!blocks || tsk_rt(entry->scheduled)->suspend_gpu_tracker_on_block) {
			// don't track preemptions or locking protocol suspensions.
			TRACE_TASK(entry->scheduled, "stopping GPU tracker.\n");
			stop_gpu_tracker(entry->scheduled);
		}
		else if(blocks &&
			!tsk_rt(entry->scheduled)->suspend_gpu_tracker_on_block) {
			TRACE_TASK(entry->scheduled,
				"GPU tracker remains on during suspension.\n");
		}
	}
#endif

	/* Request a sys_exit_np() call if we would like to preempt but cannot.
	 * We need to make sure to update the link structure anyway in case
	 * that we are still linked. Multiple calls to request_exit_np() don't
	 * hurt.
	 */
	if (np) {
		if (out_of_time || sleep)
			unlink(entry->scheduled);
		if (out_of_time || sleep || preempt)
			request_exit_np(entry->scheduled);
	}

	/* Any task that is preemptable and either exhausts its execution
	 * budget or wants to sleep completes. We may have to reschedule after
	 * this. Don't do a job completion if we block (can't have timers running
	 * for blocked jobs).
	 */
	if (!np && (out_of_time || sleep) && !blocks) {
		job_completion(entry->scheduled, !sleep);
#ifdef CONFIG_LITMUS_NESTED_LOCKING
		/* check if job completion enables an inheritance relation. no need to
		 * recheck if task already inherits a priority since job_completion()
		 * will not enable a higher-prio relation */
		if (unlikely(recheck_inheritance &&
				!tsk_rt(entry->scheduled)->inh_task)) {
			struct task_struct *hp_blocked;
			TRACE_TASK(entry->scheduled, "rechecking inheritance.\n");
			hp_blocked =
				top_priority(&tsk_rt(entry->scheduled)->hp_blocked_tasks);
			/* hp_blocked_tasks_lock is held */
			if (edf_higher_prio(hp_blocked, entry->scheduled)) {
				__increase_priority_inheritance(entry->scheduled,
						effective_priority(hp_blocked));
			}
		}
#endif
	}

	/* Link pending task if we became unlinked.
	 */
	if (!entry->linked)
		link_task_to_cpu(__take_ready(&cluster->domain), entry);

	/* The final scheduling decision. Do we need to switch for some reason?
	 * If linked is different from scheduled, then select linked as next.
	 */
	if ((!np || blocks) &&
	    entry->linked != entry->scheduled) {
		/* Schedule a linked job? */
		if (entry->linked) {
			entry->linked->rt_param.scheduled_on = entry->cpu;
			next = entry->linked;
		}
		if (entry->scheduled) {
			/* not gonna be scheduled soon */
			entry->scheduled->rt_param.scheduled_on = NO_CPU;
			TRACE_TASK(entry->scheduled, "scheduled_on = NO_CPU\n");
		}
	}
	else {
		/* Only override Linux scheduler if we have a real-time task
		 * scheduled that needs to continue.
		 */
		if (exists) {
			next = prev;
		}
	}

#ifdef CONFIG_REALTIME_AUX_TASKS
out_set_state:
#endif

	sched_state_task_picked();
	raw_readyq_unlock(&cluster->cluster_lock);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	if (recheck_inheritance) {
		raw_spin_unlock(&tsk_rt(prev)->hp_blocked_tasks_lock);
#ifdef CONFIG_LITMUS_DGL_SUPPORT
		raw_spin_unlock(&cluster->dgl_lock);
#endif
	}
#endif

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE("cluster_lock released, next=0x%p\n", next);

	if (next)
		TRACE_TASK(next, "scheduled at %llu\n", litmus_clock());
	else if (exists && !next)
		TRACE("becomes idle at %llu.\n", litmus_clock());
#endif

	return next;
}


/* _finish_switch - we just finished the switch away from prev
 */
static void cedf_finish_switch(struct task_struct *prev)
{
	cpu_entry_t* 	entry = &__get_cpu_var(cedf_cpu_entries);

	entry->scheduled = is_realtime(current) ? current : NULL;
#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "switched away from\n");
#endif
}


/*	Prepare a task for running in RT mode
 */
static void cedf_task_new(struct task_struct * t, int on_rq, int is_scheduled)
{
	unsigned long 		flags;
	cpu_entry_t* 		entry;
	cedf_domain_t*		cluster;

	TRACE("c-edf: task new %d (param running = %d, is_running = %d)\n",
					t->pid, is_scheduled, is_running(t));

	/* the cluster doesn't change even if t is running */
	cluster = task_cpu_cluster(t);

	raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);

	/* setup job params */
	release_at(t, litmus_clock());

	if (is_scheduled) {
		entry = &per_cpu(cedf_cpu_entries, task_cpu(t));
		BUG_ON(entry->scheduled);

#ifdef CONFIG_RELEASE_MASTER
		if (entry->cpu != cluster->domain.release_master) {
#endif
			entry->scheduled = t;
			tsk_rt(t)->scheduled_on = task_cpu(t);
#ifdef CONFIG_RELEASE_MASTER
		} else {
			/* do not schedule on release master */
			preempt(entry); /* force resched */
			tsk_rt(t)->scheduled_on = NO_CPU;
		}
#endif
	} else {
		t->rt_param.scheduled_on = NO_CPU;
	}
	t->rt_param.linked_on = NO_CPU;

	if (is_running(t)) {
		cedf_track_in_top_m(t);
		cedf_job_arrival(t);
	}

	raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);
}

static void cedf_task_wake_up(struct task_struct *t)
{
	unsigned long flags;
	cedf_domain_t *cluster;
	lt_t now;

	TRACE_TASK(t, "wake_up at %llu\n", litmus_clock());

	cluster = task_cpu_cluster(t);

	raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);

	set_task_state(t, TASK_RUNNING);

	now = litmus_clock();
	if (is_sporadic(t) && is_tardy(t, now)) {
		/* release the next sporadic job */
		release_at(t, now);
		sched_trace_task_release(t);
	}
	else if (is_daemon(t)) {
		if (is_tardy(t, now) && wants_new_job_on_wake(t)) {
			/* clear the request for a new release */
			TRACE_TASK(t, "releasing new job on wake.\n");
			clear_new_job_on_wake(t);
			release_at(t, now);
			sched_trace_task_release(t);
		}
		else if (tsk_rt(t)->is_aux_task &&
			(is_tardy(t, now) || budget_exhausted(t))) {

			/* aux tasks can't tell us when they need new jobs
			   with set_new_job_on_wake(), so we can only release
			   new jobs the best we can. */
			TRACE_TASK(t, "refreshing budget for aux task. tardy:%d exhausted:%d\n",
				is_tardy(t, now),
				budget_exhausted(t));

			if (!is_tardy(t, now)) {
				/* exhausted budget before deadline. just end this job */
				prepare_for_next_period(t);
			}
			else {
				/* we're passed the minimum separation time, so release a new job. */
				release_at(t, now);
			}
			sched_trace_task_release(t);
		}
	}
	else {
		/* periodic task model.  don't force job to end. rely on user to say
		   when jobs complete or when budget expires. */
		tsk_rt(t)->completed = 0;
	}

#ifdef CONFIG_SCHED_PGM
	if (is_pgm_waiting_with_deadline_shift(t)) {
		/* shift out release/deadline, if needed */
		setup_pgm_release(t);
	}
#endif

#ifdef CONFIG_REALTIME_AUX_TASKS
	if (tsk_rt(t)->has_aux_tasks && !tsk_rt(t)->hide_from_aux_tasks) {
		TRACE_CUR("%s/%d is ready so aux tasks may not inherit.\n",
						t->comm, t->pid);
		disable_aux_task_owner(t);
	}
#endif

#ifdef CONFIG_LITMUS_NVIDIA
	if (tsk_rt(t)->held_gpus && !tsk_rt(t)->hide_from_gpu) {
		TRACE_CUR("%s/%d is ready so gpu klmirqd tasks may not inherit.\n",
						t->comm, t->pid);
		disable_gpu_owner(t);
	}
#endif

	budget_state_machine(t,on_wakeup);
	cedf_job_arrival(t);

	raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);
}

static void cedf_task_block(struct task_struct *t)
{
	unsigned long flags;
	cedf_domain_t *cluster;

	TRACE_TASK(t, "block at %llu\n", litmus_clock());

	cluster = task_cpu_cluster(t);

	/* unlink if necessary */
	raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);

	unlink(t);

#ifdef CONFIG_REALTIME_AUX_TASKS
	if (tsk_rt(t)->has_aux_tasks &&
	    !tsk_rt(t)->hide_from_aux_tasks
#ifdef CONFIG_SCHED_PGM
	    /* Don't enable aux tasks if we're dealing with tokens.
	       We know that no aux tasks are involved. */
	    && !(is_pgm_waiting(t) || is_pgm_sending(t))
#endif
	   ) {
		TRACE_CUR("%s/%d is blocked so aux tasks may inherit.\n",
						t->comm, t->pid);
		enable_aux_task_owner(t);
	}
#endif

#ifdef CONFIG_LITMUS_NVIDIA
	if (tsk_rt(t)->held_gpus &&
	    !tsk_rt(t)->hide_from_gpu
#ifdef CONFIG_SCHED_PGM
	    /* Don't enable klmirqd threads if we're dealing with tokens.
	       We know that no gpu interrupts are involved. */
	    && !(is_pgm_waiting(t) || is_pgm_sending(t))
#endif
	   ) {
		TRACE_CUR("%s/%d is blocked so klmirqd threads may inherit.\n",
						t->comm, t->pid);
		enable_gpu_owner(t);
	}
#endif

	raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);

	BUG_ON(!is_realtime(t));
}


static void cedf_task_exit(struct task_struct * t)
{
	unsigned long flags;
	cedf_domain_t *cluster = task_cpu_cluster(t);

	/* unlink if necessary */
	raw_readyq_lock_irqsave(&cluster->cluster_lock, flags);

	if (tsk_rt(t)->inh_task) {
		WARN_ON(1);
		clear_inh_task_linkback(t, tsk_rt(t)->inh_task);
	}

	/* disable budget enforcement */
	cedf_untrack_in_top_m(t);
	budget_state_machine(t,on_exit);

#ifdef CONFIG_REALTIME_AUX_TASKS
	/* make sure we clean up on our way out */
	if (unlikely(tsk_rt(t)->is_aux_task))
		exit_aux_task(t);
	else if(tsk_rt(t)->has_aux_tasks)
		disable_aux_task_owner(t);
#endif

#ifdef CONFIG_LITMUS_NVIDIA
	/* make sure we clean up on our way out */
	if(tsk_rt(t)->held_gpus)
		disable_gpu_owner(t);
#endif

	unlink(t);
	if (tsk_rt(t)->scheduled_on != NO_CPU) {
		cpu_entry_t *cpu;
		cpu = &per_cpu(cedf_cpu_entries, tsk_rt(t)->scheduled_on);
		cpu->scheduled = NULL;
		tsk_rt(t)->scheduled_on = NO_CPU;
	}
	raw_readyq_unlock_irqrestore(&cluster->cluster_lock, flags);

	BUG_ON(!is_realtime(t));
	TRACE_TASK(t, "RIP\n");
}


static struct budget_tracker_ops cedf_drain_simple_ops =
{
	.on_scheduled = simple_on_scheduled,
	.on_blocked = simple_on_blocked,
	.on_preempt = simple_on_preempt,
	.on_sleep = simple_on_sleep,
	.on_exit = simple_on_exit,

	.on_wakeup = NULL,
	.on_inherit = NULL,
	.on_disinherit = NULL,
	.on_enter_top_m = NULL,
	.on_exit_top_m = NULL,

	.on_exhausted = cedf_simple_on_exhausted,
};

static struct budget_tracker_ops cedf_drain_simple_io_ops =
{
	.on_scheduled = simple_io_on_scheduled,
	.on_blocked = simple_io_on_blocked,
	.on_preempt = simple_io_on_preempt,
	.on_sleep = simple_io_on_sleep,
	.on_exit = simple_io_on_exit,

	.on_wakeup = simple_io_on_wakeup,
	.on_inherit = NULL,
	.on_disinherit = NULL,
	.on_enter_top_m = NULL,
	.on_exit_top_m = NULL,

	.on_exhausted = cedf_simple_io_on_exhausted,
};

static struct budget_tracker_ops cedf_drain_sobliv_ops =
{
	.on_scheduled = NULL,
	.on_preempt = NULL,
	.on_sleep = NULL,

	.on_blocked = sobliv_on_blocked,
	.on_wakeup = sobliv_on_wakeup,
	.on_exit = sobliv_on_exit,
	.on_inherit = sobliv_on_inherit,
	.on_disinherit = sobliv_on_disinherit,
	.on_enter_top_m = sobliv_on_enter_top_m,
	.on_exit_top_m = sobliv_on_exit_top_m,

	.on_exhausted = cedf_sobliv_on_exhausted,
};

static long cedf_admit_task(struct task_struct* tsk)
{
	struct budget_tracker_ops* ops = NULL;

#ifdef CONFIG_SCHED_DEBUG_TRACE
	if (remote_cluster(task_cpu(tsk)) != task_cpu_cluster(tsk)) {
		int want = task_cpu_cluster(tsk) - cedf;
		int have = remote_cluster(task_cpu(tsk)) - cedf;
		TRACE_TASK(tsk,
			"WARNING: Incorrect cluster. In cluster %d wants cluster %d\n",
				want, have);
	}
#endif

	if (budget_enforced(tsk) || budget_signalled(tsk)) {
		switch(get_drain_policy(tsk)) {
		case DRAIN_SIMPLE:
			ops = &cedf_drain_simple_ops;
			break;
		case DRAIN_SIMPLE_IO:
			ops = &cedf_drain_simple_io_ops;
			break;
		case DRAIN_SOBLIV:
			/* budget_policy and budget_signal_policy cannot be quantum-based */
			if (!budget_quantum_tracked(tsk) && budget_precisely_tracked(tsk)) {
				ops = &cedf_drain_sobliv_ops;
			}
			else {
				printk("rejected admit: "
					"QUANTUM_ENFORCEMENT and QUANTUM_SIGNALS is "
					"unsupported with DRAIN_SOBLIV.\n");
				return -EINVAL;
			}
			break;
		default:
			printk("rejected admit: Unsupported budget draining mode.\n");
			return -EINVAL;
		}
	}

	/* always init the budget tracker, even if we're not using timers */
	init_budget_tracker(&tsk_rt(tsk)->budget, ops);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	INIT_BINHEAP_HANDLE(&tsk_rt(tsk)->hp_blocked_tasks,
						edf_max_heap_base_priority_order);
#endif

	return 0;
}

#ifdef CONFIG_LITMUS_LOCKING
#include <litmus/fdso.h>

/* called with IRQs off */
static int __increase_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh)
{
	int success = 1;
	int linked_on;
	int check_preempt = 0;
	cedf_domain_t* cluster;
	struct task_struct* old_prio_inh = tsk_rt(t)->inh_task;

	if (prio_inh && prio_inh == effective_priority(t)) {
		/* relationship already established. */
		TRACE_TASK(t, "already has effective priority of %s/%d\n",
				   prio_inh->comm, prio_inh->pid);
		goto out;
	}

	if (prio_inh && (effective_priority(prio_inh) != prio_inh)) {
		TRACE_TASK(t,
			"Inheriting from %s/%d instead of the eff_prio = %s/%d!\n",
			prio_inh->comm, prio_inh->pid,
			effective_priority(prio_inh)->comm,
			effective_priority(prio_inh)->pid);
#ifndef CONFIG_LITMUS_NESTED_LOCKING
		/* Tasks should only inherit the base priority of a task.
		   If 't' inherits a priority, then tsk_rt(t)->inh_task should
		   be passed to this function instead. This includes transitive
		   inheritance relations (tsk_rt(tsk_rt(...)->inh_task)->inh_task). */
		BUG();
#else
		/* Not a bug with nested locking since inheritance propagation is
		   not atomic. */
#endif
	}

	cluster = task_cpu_cluster(t);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	/* this sanity check allows for weaker locking in protocols */
	/* TODO (klmirqd): Skip this check if 't' is a proxy thread (???) */
	if(__edf_higher_prio(prio_inh, BASE, t, EFFECTIVE)) {
#endif
		sched_trace_eff_prio_change(t, prio_inh);

		/* clear out old inheritance relation */
		if (old_prio_inh) {
			budget_state_machine_chgprio(t,old_prio_inh,on_disinherit);
			clear_inh_task_linkback(t, old_prio_inh);
		}

		TRACE_TASK(t, "inherits priority from %s/%d\n",
				   prio_inh->comm, prio_inh->pid);
		tsk_rt(t)->inh_task = prio_inh;

		/* update inheritance relation */
		if (prio_inh)
			budget_state_machine_chgprio(t,prio_inh,on_inherit);

		linked_on  = tsk_rt(t)->linked_on;

		/* If it is scheduled, then we need to reorder the CPU heap. */
		if (linked_on != NO_CPU) {
			TRACE_TASK(t, "%s: linked on %d\n",
					   __FUNCTION__, linked_on);
			/* Holder is scheduled; need to re-order CPUs.
			 * We can't use heap_decrease() here since
			 * the cpu_heap is ordered in reverse direction, so
			 * it is actually an increase. */
			sbinheap_delete(&per_cpu(cedf_cpu_entries, linked_on).hn,
						   &cluster->cpu_heap);
			sbinheap_add(&per_cpu(cedf_cpu_entries, linked_on).hn,
						&cluster->cpu_heap, cpu_entry_t, hn);

			/* tell prio_inh that we're __running__ with its priority */
			set_inh_task_linkback(t, prio_inh);
		}
		else {
			/* holder may be queued: first stop queue changes */
			raw_spin_lock(&cluster->domain.release_lock);
			if (is_queued(t)) {
				TRACE_TASK(t, "%s: is queued\n",
						   __FUNCTION__);
				/* We need to update the position of holder in some
				 * heap. Note that this could be a release heap if we
				 * budget enforcement is used and this job overran. */
				check_preempt =
					!bheap_decrease(edf_ready_order, tsk_rt(t)->heap_node);
			} else {
				/* Nothing to do: if it is not queued and not linked
				 * then it is either sleeping or currently being moved
				 * by other code (e.g., a timer interrupt handler) that
				 * will use the correct priority when enqueuing the
				 * task. */
				TRACE_TASK(t, "%s: is NOT queued => Done.\n",
						   __FUNCTION__);
			}
			raw_spin_unlock(&cluster->domain.release_lock);

#ifdef CONFIG_REALTIME_AUX_TASKS
			/* propagate to aux tasks */
			if (tsk_rt(t)->has_aux_tasks) {
				aux_task_owner_increase_priority(t);
			}
#endif

#ifdef CONFIG_LITMUS_NVIDIA
			/* propagate to gpu klmirqd */
			if (tsk_rt(t)->held_gpus) {
				gpu_owner_increase_priority(t);
			}
#endif

			/* If holder was enqueued in a release heap, then the following
			 * preemption check is pointless, but we can't easily detect
			 * that case. If you want to fix this, then consider that
			 * simply adding a state flag requires O(n) time to update when
			 * releasing n tasks, which conflicts with the goal to have
			 * O(log n) merges. */
			if (check_preempt) {
				/* heap_decrease() hit the top level of the heap: make
				 * sure preemption checks get the right task, not the
				 * potentially stale cache. */
				bheap_uncache_min(edf_ready_order,
								&cluster->domain.ready_queue);
				check_for_preemptions(cluster);
			}
		}
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	}
	else {
		/* Occurance is okay under two scenarios:
		 * 1. Fine-grain nested locks (no compiled DGL support): Concurrent
		 *    updates are chasing each other through the wait-for chain.
		 * 2. Budget exhausion caused the HP waiter to loose its priority, but
		 *    the lock structure hasn't yet been updated (but soon will be).
		 */
		TRACE_TASK(t,
			"Spurious invalid priority increase. "
			"Inheritance request: %s/%d [eff_prio = %s/%d] to inherit from "
			"%s/%d. Occurance is likely okay: probably due to (hopefully safe) "
			"concurrent priority updates.\n",
			t->comm, t->pid,
			effective_priority(t)->comm, effective_priority(t)->pid,
			(prio_inh) ? prio_inh->comm : "null",
			(prio_inh) ? prio_inh->pid : 0);
		WARN_ON(!prio_inh);
		success = 0;
	}
#endif

out:
	return success;
}

/* called with IRQs off */
static void increase_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh)
{
	cedf_domain_t* cluster = task_cpu_cluster(t);

	raw_readyq_lock(&cluster->cluster_lock);

	TRACE_TASK(t, "to inherit from %s/%d\n", prio_inh->comm, prio_inh->pid);

	__increase_priority_inheritance(t, prio_inh);

	raw_readyq_unlock(&cluster->cluster_lock);
}

/* called with IRQs off */
static int __decrease_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh,
				int budget_tiggered)
{
	cedf_domain_t* cluster;
	int success = 1;
	struct task_struct* old_prio_inh = tsk_rt(t)->inh_task;

	if (prio_inh == old_prio_inh) {
		/* relationship already established. */
		TRACE_TASK(t, "already inherits priority from %s/%d\n",
				   (prio_inh) ? prio_inh->comm : "(null)",
				   (prio_inh) ? prio_inh->pid : 0);
		goto out;
	}

	if (prio_inh && (effective_priority(prio_inh) != prio_inh)) {
		TRACE_TASK(t,
			"Inheriting from %s/%d instead of the eff_prio = %s/%d!\n",
			prio_inh->comm, prio_inh->pid,
			effective_priority(prio_inh)->comm,
			effective_priority(prio_inh)->pid);
#ifndef CONFIG_LITMUS_NESTED_LOCKING
		/* Tasks should only inherit the base priority of a task.
		   If 't' inherits a priority, then tsk_rt(t)->inh_task should
		   be passed to this function instead. This includes transitive
		   inheritance relations (tsk_rt(tsk_rt(...)->inh_task)->inh_task). */
		BUG();
#else
		/* Not a bug with nested locking since inheritance propagation is
		   not atomic. */
#endif
	}

	cluster = task_cpu_cluster(t);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	if(budget_tiggered || __edf_higher_prio(t, EFFECTIVE, prio_inh, BASE)) {
#endif
		sched_trace_eff_prio_change(t, prio_inh);

		if (budget_tiggered) {
			BUG_ON(!old_prio_inh);
			TRACE_TASK(t, "budget-triggered 'decrease' in priority. "
					   "%s/%d's budget should have just been exhuasted.\n",
					   old_prio_inh->comm, old_prio_inh->pid);
		}

		/* clear out old inheritance relation */
		if (old_prio_inh) {
			budget_state_machine_chgprio(t,old_prio_inh,on_disinherit);
			clear_inh_task_linkback(t, old_prio_inh);
		}

		/* A job only stops inheriting a priority when it releases a
		 * resource. Thus we can make the following assumption.*/
		if(prio_inh)
			TRACE_TASK(t, "EFFECTIVE priority decreased to %s/%d\n",
					   prio_inh->comm, prio_inh->pid);
		else
			TRACE_TASK(t, "base priority restored.\n");

		/* set up new inheritance relation */
		tsk_rt(t)->inh_task = prio_inh;

		if (prio_inh)
			budget_state_machine_chgprio(t,prio_inh,on_inherit);

		if(tsk_rt(t)->linked_on != NO_CPU) {
			TRACE_TASK(t, "is linked on %d and scheduled on %d.\n",
				tsk_rt(t)->linked_on, tsk_rt(t)->scheduled_on);

			/* link back to new inheritance */
			if (prio_inh)
				set_inh_task_linkback(t, prio_inh);

			/* Check if rescheduling is necessary. We can't use heap_decrease()
			 * since the priority was effectively lowered. */
			unlink(t);
			cedf_job_arrival(t);
		}
		else {
			/* task is queued */
			raw_spin_lock(&cluster->domain.release_lock);
			if (is_queued(t)) {
				TRACE_TASK(t, "is queued.\n");

				BUG_ON(
					!is_released(t, litmus_clock()) &&
					!tsk_rt(t)->job_params.is_backlogged_job &&
					!is_early_releasing(t));

				unlink(t);
				cedf_job_arrival(t);
			}
			else {
				TRACE_TASK(t, "is not in scheduler. "
					"Probably on wait queue somewhere.\n");
			}
			raw_spin_unlock(&cluster->domain.release_lock);
		}

#ifdef CONFIG_REALTIME_AUX_TASKS
		/* propagate to aux tasks */
		if (tsk_rt(t)->has_aux_tasks)
			aux_task_owner_decrease_priority(t);
#endif

#ifdef CONFIG_LITMUS_NVIDIA
		/* propagate to gpu */
		if (tsk_rt(t)->held_gpus)
			gpu_owner_decrease_priority(t);
#endif

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	}
	else {
		TRACE_TASK(t,
			"Spurious invalid priority decrease. "
			"Inheritance request: %s/%d [eff_prio = %s/%d] to inherit from "
			"%s/%d. Occurance is likely okay: probably due to (hopefully safe) "
			"concurrent priority updates.\n",
			t->comm, t->pid,
			effective_priority(t)->comm, effective_priority(t)->pid,
			(prio_inh) ? prio_inh->comm : "null",
			(prio_inh) ? prio_inh->pid : 0);
		success = 0;
	}
#endif

out:
	return success;
}

static void decrease_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh,
				int budget_tiggered)
{
	cedf_domain_t* cluster = task_cpu_cluster(t);

	raw_readyq_lock(&cluster->cluster_lock);

	TRACE_TASK(t, "to inherit from %s/%d (decrease)\n",
			(prio_inh) ? prio_inh->comm : "null",
			(prio_inh) ? prio_inh->pid : 0);

	__decrease_priority_inheritance(t, prio_inh, budget_tiggered);

	raw_readyq_unlock(&cluster->cluster_lock);
}


#ifdef CONFIG_LITMUS_NESTED_LOCKING
/* called with IRQs off */
/* preconditions:
 (1) The 'hp_blocked_tasks_lock' of task 't' is held.
 (2) The lock 'to_unlock' is held.
 */
static void nested_increase_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh,
				raw_spinlock_t *to_unlock,
				unsigned long irqflags)
{
	struct litmus_lock *blocked_lock = tsk_rt(t)->blocked_lock;

	if(tsk_rt(t)->inh_task != prio_inh) { /* shield redundent calls. */
		/* increase our prio */
		increase_priority_inheritance(t, prio_inh);
	}

	/* note: cluster lock is not held continuously during propagation, so
	   there may be momentary inconsistencies while nested priority
	   propagation 'chases' other updates. */

	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock); /* unlock t's heap. */

	if(blocked_lock) {
		if(blocked_lock->ops->supports_nesting) {
			TRACE_TASK(t, "Inheritor is blocked (...perhaps). "
				"Checking lock %d.\n",
				blocked_lock->ident);

			/* beware: recursion */
			blocked_lock->ops->propagate_increase_inheritance(blocked_lock,
							t, to_unlock, irqflags);
		}
		else {
			TRACE_TASK(t, "Inheritor is blocked on litmus lock (%d) "
				"that does not support nesting!\n",
				blocked_lock->ident);
			unlock_fine_irqrestore(to_unlock, irqflags);
		}
	}
	else {
		TRACE_TASK(t, "is not blocked on litmus lock. No propagation.\n");
		unlock_fine_irqrestore(to_unlock, irqflags);
	}
}

/* called with IRQs off */
/* preconditions:
 (1) The 'hp_blocked_tasks_lock' of task 't' is held.
 (2) The lock 'to_unlock' is held.
 */
static void nested_decrease_priority_inheritance(struct task_struct* t,
				struct task_struct* prio_inh,
				raw_spinlock_t *to_unlock,
				unsigned long irqflags,
				int budget_tiggered)
{
	struct litmus_lock *blocked_lock = tsk_rt(t)->blocked_lock;
	decrease_priority_inheritance(t, prio_inh, budget_tiggered);

	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);  /* unlock t's heap. */

	if(blocked_lock) {
		if(blocked_lock->ops->supports_nesting) {
			TRACE_TASK(t, "Inheritor is blocked. Checking lock %d.\n",
					blocked_lock->ident);
			/* beware: recursion */
			blocked_lock->ops->propagate_decrease_inheritance(blocked_lock, t,
							to_unlock, irqflags, budget_tiggered);
		}
		else {
			TRACE_TASK(t, "Inheritor is blocked on lock (%p) that does "
					"not support nesting!\n",
					blocked_lock);
			unlock_fine_irqrestore(to_unlock, irqflags);
		}
	}
	else {
		TRACE_TASK(t, "is not blocked.  No propagation.\n");
		unlock_fine_irqrestore(to_unlock, irqflags);
	}
}

/* ******************** FIFO MUTEX ********************** */

static struct litmus_lock_ops cedf_fifo_mutex_lock_ops = {
	.lock   = fifo_mutex_lock,
	.unlock = fifo_mutex_unlock,
	.should_yield_lock = fifo_mutex_should_yield_lock,
	.close  = fifo_mutex_close,
	.deallocate = fifo_mutex_free,

	.budget_exhausted = fifo_mutex_budget_exhausted,
	.propagate_increase_inheritance = fifo_mutex_propagate_increase_inheritance,
	.propagate_decrease_inheritance = fifo_mutex_propagate_decrease_inheritance,

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.dgl_lock = fifo_mutex_dgl_lock,
	.is_owner = fifo_mutex_is_owner,
	.get_owner = fifo_mutex_get_owner,
	.enable_priority = fifo_mutex_enable_priority,

	.dgl_can_quick_lock = NULL,
	.dgl_quick_lock = NULL,

	.supports_dgl = 1,
	.requires_atomic_dgl = 0,
#endif
	.supports_nesting = 1,
	.supports_budget_exhaustion = 1,
	.is_omlp_family = 0,
};

static struct litmus_lock* cedf_new_fifo_mutex(void)
{
	return fifo_mutex_new(&cedf_fifo_mutex_lock_ops);
}

/* ******************** PRIOQ MUTEX ********************** */

static struct litmus_lock_ops cedf_prioq_mutex_lock_ops = {
	.lock   = prioq_mutex_lock,
	.unlock = prioq_mutex_unlock,
	.should_yield_lock = prioq_mutex_should_yield_lock,
	.close  = prioq_mutex_close,
	.deallocate = prioq_mutex_free,

	.budget_exhausted = prioq_mutex_budget_exhausted,
	.propagate_increase_inheritance=prioq_mutex_propagate_increase_inheritance,
	.propagate_decrease_inheritance=prioq_mutex_propagate_decrease_inheritance,

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.dgl_lock = prioq_mutex_dgl_lock,
	.is_owner = prioq_mutex_is_owner,
	.get_owner = prioq_mutex_get_owner,
	.enable_priority = prioq_mutex_enable_priority,

	.dgl_can_quick_lock = prioq_mutex_dgl_can_quick_lock,
	.dgl_quick_lock = prioq_mutex_dgl_quick_lock,

	.supports_dgl = 1,
	.requires_atomic_dgl = 1,
#endif
	.supports_nesting = 1,
	.supports_budget_exhaustion = 1,
	.is_omlp_family = 0,
};

static struct litmus_lock* cedf_new_prioq_mutex(void)
{
	return prioq_mutex_new(&cedf_prioq_mutex_lock_ops);
}

/* ******************** R2DGLP ********************** */

static struct litmus_lock_ops cedf_r2dglp_lock_ops = {
	.lock   = r2dglp_lock,
	.unlock = r2dglp_unlock,
	.should_yield_lock = NULL,
	.close  = r2dglp_close,
	.deallocate = r2dglp_free,

	.budget_exhausted		= r2dglp_budget_exhausted,
	.omlp_virtual_unlock	= r2dglp_virtual_unlock,

	// r2dglp can only be an outer-most lock.
	.propagate_increase_inheritance = NULL,
	.propagate_decrease_inheritance = NULL,

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.supports_dgl = 0,
	.requires_atomic_dgl = 0,
#endif
	.supports_nesting = 0,
	.supports_budget_exhaustion = 1,
	.is_omlp_family = 1,
};

static struct litmus_lock* cedf_new_r2dglp(void* __user arg)
{
	/* assumes clusters of uniform size. */
	return r2dglp_new(cluster_size, &cedf_r2dglp_lock_ops, arg);
}
#endif /* end LITMUS_NESTED_LOCKING */

/* ******************** KFMLP support ********************** */

static struct litmus_lock_ops cedf_kfmlp_lock_ops = {
	.lock   = kfmlp_lock,
	.unlock = kfmlp_unlock,
	.should_yield_lock = NULL,
	.close  = kfmlp_close,
	.deallocate = kfmlp_free,

	// kfmlp can only be an outer-most lock.
	.propagate_increase_inheritance = NULL,
	.propagate_decrease_inheritance = NULL,

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.supports_dgl = 0,
	.requires_atomic_dgl = 0,
#endif
	.supports_nesting = 0,
	.supports_budget_exhaustion = 0,
	.is_omlp_family = 0,
};


static struct litmus_lock* cedf_new_kfmlp(void* __user arg)
{
	return kfmlp_new(&cedf_kfmlp_lock_ops, arg);
}

/* **** lock constructor **** */

static long cedf_allocate_lock(struct litmus_lock **lock, int type,
				void* __user args)
{
	int err;

	switch (type) {
#ifdef CONFIG_LITMUS_NESTED_LOCKING
		case FIFO_MUTEX:
			*lock = cedf_new_fifo_mutex();
			break;

		case PRIOQ_MUTEX:
			*lock = cedf_new_prioq_mutex();
			break;

		case R2DGLP_SEM:
			*lock = cedf_new_r2dglp(args);
			break;
#endif
		case KFMLP_SEM:
			*lock = cedf_new_kfmlp(args);
			break;

		default:
			err = -ENXIO;
			goto UNSUPPORTED_LOCK;
	};

	if (*lock)
		err = 0;
	else
		err = -ENOMEM;

UNSUPPORTED_LOCK:
	return err;
}
#endif  /* end LITMUS_LOCKING */


#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
static struct affinity_observer_ops
cedf_kfmlp_affinity_ops __attribute__ ((unused)) = {
	.close = kfmlp_aff_obs_close,
	.deallocate = kfmlp_aff_obs_free,
};

#ifdef CONFIG_LITMUS_NESTED_LOCKING
static struct affinity_observer_ops
cedf_r2dglp_affinity_ops __attribute__ ((unused)) = {
	.close = r2dglp_aff_obs_close,
	.deallocate = r2dglp_aff_obs_free,
};
#endif

static long cedf_allocate_affinity_observer(struct affinity_observer **aff_obs,
				int type,
				void* __user args)
{
	int err;

	switch (type) {
#ifdef CONFIG_LITMUS_NVIDIA
		case KFMLP_SIMPLE_GPU_AFF_OBS:
			*aff_obs = kfmlp_simple_gpu_aff_obs_new(&cedf_kfmlp_affinity_ops,
							args);
			break;

		case KFMLP_GPU_AFF_OBS:
			*aff_obs = kfmlp_gpu_aff_obs_new(&cedf_kfmlp_affinity_ops, args);
			break;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
		case R2DGLP_SIMPLE_GPU_AFF_OBS:
			*aff_obs = r2dglp_simple_gpu_aff_obs_new(&cedf_r2dglp_affinity_ops,
							args);
			break;

		case R2DGLP_GPU_AFF_OBS:
			*aff_obs = r2dglp_gpu_aff_obs_new(&cedf_r2dglp_affinity_ops, args);
			break;
#endif /* end LITMUS_NESTED_LOCKING */
#endif /* end LITMUS_NVIDIA */
		default:
			err = -ENXIO;
			goto UNSUPPORTED_AFF_OBS;
	};

	if (*aff_obs)
		err = 0;
	else
		err = -ENOMEM;

UNSUPPORTED_AFF_OBS:
	return err;
}
#endif /* end LITMUS_AFFINITY_LOCKING */


#ifdef VERBOSE_INIT
static void print_cluster_topology(cpumask_var_t mask, int cpu)
{
	int chk;
	char buf[255];

	chk = cpulist_scnprintf(buf, 254, mask);
	buf[chk] = '\0';
	printk(KERN_INFO "CPU = %d, shared cpu(s) = %s\n", cpu, buf);

}
#endif

static void cleanup_cedf(void)
{
	int i;

	if (clusters_allocated) {
		for (i = 0; i < num_clusters; i++) {
			kfree(cedf[i].cpus);
			kfree(cedf[i].cpu_heap.buf);
			kfree(cedf[i].top_m.buf);
			free_cpumask_var(cedf[i].cpu_map);
		}

		kfree(cedf);
	}
}

static struct domain_proc_info cedf_domain_proc_info;
static long cedf_get_domain_proc_info(struct domain_proc_info **ret)
{
	*ret = &cedf_domain_proc_info;
	return 0;
}

static void cedf_setup_domain_proc(void)
{
	int i, cpu, domain;
#ifdef CONFIG_RELEASE_MASTER
	int release_master = atomic_read(&release_master_cpu);
	/* skip over the domain with the release master if cluster size is 1 */
	int skip_domain = (1 == cluster_size && release_master != NO_CPU) ?
			release_master : NO_CPU;
#else
	int release_master = NO_CPU;
	int skip_domain = NO_CPU;
#endif
	int num_rt_cpus = num_online_cpus() - (release_master != NO_CPU);
	int num_rt_domains = num_clusters - (skip_domain != NO_CPU);
	struct cd_mapping *map;

	memset(&cedf_domain_proc_info, sizeof(cedf_domain_proc_info), 0);
	init_domain_proc_info(&cedf_domain_proc_info, num_rt_cpus, num_rt_domains);
	cedf_domain_proc_info.num_cpus = num_rt_cpus;
	cedf_domain_proc_info.num_domains = num_rt_domains;

	for (cpu = 0, i = 0; cpu < num_online_cpus(); ++cpu) {
		if (cpu == release_master)
			continue;
		map = &cedf_domain_proc_info.cpu_to_domains[i];
		/* pointer math to figure out the domain index */
		domain = remote_cluster(cpu) - cedf;
		map->id = cpu;
		cpumask_set_cpu(domain, map->mask);
		++i;
	}

	for (domain = 0, i = 0; domain < num_clusters; ++domain) {
		if (domain == skip_domain)
			continue;
		map = &cedf_domain_proc_info.domain_to_cpus[i];
		map->id = i;
		cpumask_copy(map->mask, cedf[domain].cpu_map);
		++i;
	}
}

#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
static int cedf_map_gpu_to_cpu(int gpu)
{
	int default_cpu;
	int cpu_cluster = gpu / gpu_cluster_size;

	/* bonham-specific hack for the fully partitioned case (both CPUs and GPUs
	   partitioned) */
	/* TODO: Make this aware of the NUMA topology generically */
	if(num_clusters == 12 && num_gpu_clusters == 8) {
		if(gpu >= 4) {
			cpu_cluster += 2; /* assign the GPU to CPU on the same NUMA node */
		}
	}

	default_cpu = cedf[cpu_cluster].cpus[0]->cpu; /* first CPU in cluster */

	TRACE("CPU %d is default for GPU %d interrupt threads.\n",
					default_cpu, gpu);

	return default_cpu;
}
#endif

static long cedf_activate_plugin(void)
{
	int i, j, cpu, ccpu, cpu_count;
	cpu_entry_t *entry;

	cpumask_var_t mask;
	int chk = 0;

	/* de-allocate old clusters, if any */
	cleanup_cedf();

	printk(KERN_INFO "C-EDF: Activate Plugin, cluster configuration = %d\n",
			cluster_config);

	/* need to get cluster_size first */
	if(!zalloc_cpumask_var(&mask, GFP_ATOMIC))
		return -ENOMEM;

	if (cluster_config == GLOBAL_CLUSTER) {
		cluster_size = num_online_cpus();
	} else {
		chk = get_shared_cpu_map(mask, 0, cluster_config);
		if (chk) {
			/* if chk != 0 then it is the max allowed index */
			printk(KERN_INFO "C-EDF: Cluster configuration = %d "
			       "is not supported on this hardware.\n",
			       cluster_config);
			/* User should notice that the configuration failed, so
			 * let's bail out. */
			return -EINVAL;
		}

		cluster_size = cpumask_weight(mask);
	}

	if ((num_online_cpus() % cluster_size) != 0) {
		/* this can't be right, some cpus are left out */
		printk(KERN_ERR "C-EDF: Trying to group %d cpus in %d!\n",
				num_online_cpus(), cluster_size);
		return -1;
	}

	num_clusters = num_online_cpus() / cluster_size;
	printk(KERN_INFO "C-EDF: %d cluster(s) of size = %d\n",
			num_clusters, cluster_size);


#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
	num_gpu_clusters = min(num_clusters, num_online_gpus());
	gpu_cluster_size = num_online_gpus() / num_gpu_clusters;

	if (((num_online_gpus() % gpu_cluster_size) != 0) ||
		(num_gpu_clusters != num_clusters)) {
		printk(KERN_WARNING "C-EDF: GPUs not uniformly distributed "
			"among CPU clusters.\n");
	}
#endif

	/* initialize clusters */
	cedf = kmalloc(num_clusters * sizeof(cedf_domain_t), GFP_ATOMIC);
	for (i = 0; i < num_clusters; i++) {

		cedf[i].cpus = kmalloc(cluster_size * sizeof(cpu_entry_t),
				GFP_ATOMIC);

		cedf[i].cpu_heap.compare = cpu_lower_prio;
		cedf[i].cpu_heap.size = 0;
		cedf[i].cpu_heap.max_size = cluster_size;
		cedf[i].cpu_heap.buf =
			kmalloc(cluster_size * sizeof(struct sbinheap_node), GFP_ATOMIC);
		INIT_SBINHEAP(&(cedf[i].cpu_heap));

		edf_domain_init(&(cedf[i].domain), NULL, cedf_release_jobs);

		if(!zalloc_cpumask_var(&cedf[i].cpu_map, GFP_ATOMIC))
			return -ENOMEM;
#ifdef CONFIG_RELEASE_MASTER
		cedf[i].domain.release_master = atomic_read(&release_master_cpu);
#endif
	}

	/* cycle through cluster and add cpus to them */
	for (i = 0; i < num_clusters; i++) {

#ifdef CONFIG_LITMUS_DGL_SUPPORT
		raw_spin_lock_init(&cedf[i].dgl_lock);
#endif

#ifdef RECURSIVE_READY_QUEUE_LOCK
		cedf[i].recursive_depth = 0;
		atomic_set(&cedf[i].owner_cpu, NO_CPU);
#endif

		cedf[i].top_m.compare = cedf_min_heap_base_priority_order;
		cedf[i].top_m.size = 0;
		cedf[i].top_m.max_size = cluster_size;
		cedf[i].top_m.buf =
			kmalloc(cluster_size * sizeof(struct sbinheap_node), GFP_ATOMIC);
		INIT_SBINHEAP(&(cedf[i].top_m));

		INIT_BINHEAP_HANDLE(&cedf[i].not_top_m,
						cedf_max_heap_base_priority_order);

		for_each_online_cpu(cpu) {
			/* check if the cpu is already in a cluster */
			for (j = 0; j < num_clusters; j++)
				if (cpumask_test_cpu(cpu, cedf[j].cpu_map))
					break;
			/* if it is in a cluster go to next cpu */
			if (j < num_clusters &&
					cpumask_test_cpu(cpu, cedf[j].cpu_map))
				continue;

			/* this cpu isn't in any cluster */
			/* get the shared cpus */
			if (unlikely(cluster_config == GLOBAL_CLUSTER))
				cpumask_copy(mask, cpu_online_mask);
			else
				get_shared_cpu_map(mask, cpu, cluster_config);

			cpumask_copy(cedf[i].cpu_map, mask);
#ifdef VERBOSE_INIT
			print_cluster_topology(mask, cpu);
#endif
			/* add cpus to current cluster and init cpu_entry_t */
			cpu_count = 0;
			for_each_cpu(ccpu, cedf[i].cpu_map) {

				entry = &per_cpu(cedf_cpu_entries, ccpu);
				cedf[i].cpus[cpu_count] = entry;

				memset(entry, 0, sizeof(*entry));
				entry->cpu = ccpu;
				entry->cluster = &cedf[i];
				INIT_SBINHEAP_NODE(&entry->hn);
				mb();

				++cpu_count;

#ifdef CONFIG_RELEASE_MASTER
				/* only add CPUs that should schedule jobs */
				if (entry->cpu != entry->cluster->domain.release_master)
#endif
					update_cpu_position(entry);
			}
			/* done with this cluster */
			break;
		}
	}

#ifdef CONFIG_LITMUS_NVIDIA
	init_nvidia_info();
#endif

	clusters_allocated = 1;
	free_cpumask_var(mask);

	cedf_setup_domain_proc();

	return 0;
}

static long cedf_deactivate_plugin(void)
{
	destroy_domain_proc_info(&cedf_domain_proc_info);
	return 0;
}

/*	Plugin object	*/
static struct sched_plugin cedf_plugin __cacheline_aligned_in_smp = {
	.plugin_name		= "C-EDF",
	.finish_switch		= cedf_finish_switch,
	.tick			= cedf_tick,
	.task_new		= cedf_task_new,
	.complete_job		= complete_job,
	.task_exit		= cedf_task_exit,
	.schedule		= cedf_schedule,
	.task_wake_up		= cedf_task_wake_up,
	.task_block		= cedf_task_block,
	.admit_task		= cedf_admit_task,
	.activate_plugin	= cedf_activate_plugin,
	.deactivate_plugin	= cedf_deactivate_plugin,
	.get_domain_proc_info	= cedf_get_domain_proc_info,
#ifdef CONFIG_LITMUS_LOCKING
	.compare		= edf_higher_prio,
	.allocate_lock		= cedf_allocate_lock,
	.increase_prio		= increase_priority_inheritance,
	.decrease_prio		= decrease_priority_inheritance,
	.__increase_prio	= __increase_priority_inheritance,
	.__decrease_prio	= __decrease_priority_inheritance,
#endif
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	.nested_increase_prio		= nested_increase_priority_inheritance,
	.nested_decrease_prio		= nested_decrease_priority_inheritance,
	.__compare		= __edf_higher_prio,
#endif
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.get_dgl_spinlock = cedf_get_dgl_spinlock,
#endif
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	.allocate_aff_obs = cedf_allocate_affinity_observer,
#endif
#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
	.map_gpu_to_cpu = cedf_map_gpu_to_cpu,
#endif
};

static struct proc_dir_entry *cluster_file = NULL, *cedf_dir = NULL;

static int __init init_cedf(void)
{
	int err, fs;

	err = register_sched_plugin(&cedf_plugin);
	if (!err) {
		fs = make_plugin_proc_dir(&cedf_plugin, &cedf_dir);
		if (!fs)
			cluster_file = create_cluster_file(cedf_dir, &cluster_config);
		else
			printk(KERN_ERR "Could not allocate C-EDF procfs dir.\n");
	}
	return err;
}

static void clean_cedf(void)
{
	cleanup_cedf();
	if (cluster_file)
		remove_proc_entry("cluster", cedf_dir);
	if (cedf_dir)
		remove_plugin_proc_dir(&cedf_plugin);
}

module_init(init_cedf);
module_exit(clean_cedf);
