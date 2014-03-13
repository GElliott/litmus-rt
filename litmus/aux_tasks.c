#include <litmus/sched_plugin.h>
#include <litmus/trace.h>
#include <litmus/litmus.h>

#ifdef CONFIG_REALTIME_AUX_TASKS
#include <litmus/rt_param.h>
#include <litmus/aux_tasks.h>

#include <linux/time.h>

#define AUX_SLICE_NR_JIFFIES 4
#define AUX_SLICE_NS ((NSEC_PER_SEC / HZ) * AUX_SLICE_NR_JIFFIES)

static int admit_aux_task(struct task_struct *t)
{
	int retval = 0;
	struct task_struct *leader = t->group_leader;

	/* budget enforcement increments job numbers.  job numbers are used in
	 * tie-breaking of aux_tasks.  method helps ensure:
	 * 1) aux threads with no inherited priority can starve another (they share
	 *	the CPUs equally.
	 * 2) aux threads that inherit the same priority cannot starve each other.
	 *
	 * Assuming aux threads are well-behavied (they do very little work and
	 * suspend), risk of starvation should not be an issue, but this is a
	 * fail-safe.
	 */
	struct rt_task tp = {
		.exec_cost = AUX_SLICE_NS,
		.period = AUX_SLICE_NS,
		.relative_deadline = AUX_SLICE_NS,
		.phase = 0,
		.cpu = task_cpu(leader),  /* take CPU of group leader */
		.priority = LITMUS_LOWEST_PRIORITY,
		.cls = RT_CLASS_BEST_EFFORT,
		.budget_policy = QUANTUM_ENFORCEMENT,
		.drain_policy = DRAIN_SIMPLE,
		.budget_signal_policy = NO_SIGNALS,
		/* use SPORADIC instead of EARLY since util = 1.0 */
		.release_policy = TASK_SPORADIC,
	};

	struct sched_param param = { .sched_priority = 0};

	tsk_rt(t)->task_params = tp;
	retval = sched_setscheduler_nocheck(t, SCHED_LITMUS, &param);

	return retval;
}

int exit_aux_task(struct task_struct *t)
{
	int retval = 0;

	BUG_ON(!tsk_rt(t)->is_aux_task);

	TRACE_CUR("Aux task %s/%d is exiting from %s/%d.\n",
				t->comm, t->pid,
				t->group_leader->comm, t->group_leader->pid);

	tsk_rt(t)->is_aux_task = 0;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	list_del(&tsk_rt(t)->aux_task_node);
	if (tsk_rt(t)->inh_task) {
		litmus->__decrease_prio(t, NULL, 0);
	}
#endif

	return retval;
}

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
static int aux_tasks_increase_priority(struct task_struct *leader,
				struct task_struct *hp)
{
	int retval = 0;

	struct list_head *pos;

	list_for_each(pos, &tsk_aux(leader)->aux_tasks) {
		struct task_struct *aux =
			container_of(list_entry(pos, struct rt_param, aux_task_node),
						struct task_struct, rt_param);

		if (!is_realtime(aux)) {
			TRACE_CUR("skipping non-real-time aux task %s/%d\n",
							aux->comm, aux->pid);
		}
		else if(tsk_rt(aux)->inh_task == hp) {
			TRACE_CUR("skipping real-time aux task %s/%d that already "
					"inherits from %s/%d\n",
					aux->comm, aux->pid, hp->comm, hp->pid);
		}
		else {
			/* aux tasks don't touch rt locks, so no nested call needed. */
			retval = litmus->__increase_prio(aux, hp);
		}
	}

	return retval;
}

static int aux_tasks_decrease_priority(struct task_struct *leader,
				struct task_struct *hp)
{
	int retval = 0;

	struct list_head *pos;

	list_for_each(pos, &tsk_aux(leader)->aux_tasks) {
		struct task_struct *aux =
			container_of(list_entry(pos, struct rt_param, aux_task_node),
						 struct task_struct, rt_param);

		if (!is_realtime(aux)) {
			TRACE_CUR("skipping non-real-time aux task %s/%d\n",
							aux->comm, aux->pid);
		}
		else {
			retval = litmus->__decrease_prio(aux, hp, 0);
		}
	}

	return retval;
}
#endif

int aux_task_owner_increase_priority(struct task_struct *t)
{
	int retval = 0;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	struct task_struct *leader;
	struct task_struct *hp = NULL;
	struct task_struct *hp_eff = NULL;

	int increase_aux = 0;

	BUG_ON(!is_realtime(t));
	BUG_ON(!tsk_rt(t)->has_aux_tasks);

	leader = t->group_leader;

	if (!binheap_is_in_heap(&tsk_rt(t)->aux_task_owner_node)) {
		TRACE_CUR("aux tasks may not inherit from %s/%d in group %s/%d\n",
						t->comm, t->pid, leader->comm, leader->pid);
		goto out;
	}

	hp = container_of(
			binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
					struct rt_param, aux_task_owner_node),
			struct task_struct, rt_param);
	hp_eff = effective_priority(hp);

	if (hp != t) {
		/* our position in the heap may have changed.
		   hp is already at the root. */
		binheap_decrease(&tsk_rt(t)->aux_task_owner_node,
						&tsk_aux(leader)->aux_task_owners);
	}
	else {
		/* unconditionally propagate - t already has the updated eff
		   and is at the root, so we can't detect a change in
		   inheritance, but we know that priority has indeed
		   increased/changed. */
		increase_aux = 1;
	}

	hp = container_of(
			binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
					struct rt_param, aux_task_owner_node),
			struct task_struct, rt_param);

	/* check if the eff. prio. of hp has changed */
	if (increase_aux || (effective_priority(hp) != hp_eff)) {
		hp_eff = effective_priority(hp);
		retval = aux_tasks_increase_priority(leader, hp_eff);
	}
out:

#endif
	return retval;
}

int aux_task_owner_decrease_priority(struct task_struct *t)
{
	int retval = 0;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	struct task_struct *leader;
	struct task_struct *hp = NULL;
	struct task_struct *hp_eff = NULL;

	BUG_ON(!is_realtime(t));
	BUG_ON(!tsk_rt(t)->has_aux_tasks);

	leader = t->group_leader;

	if (!binheap_is_in_heap(&tsk_rt(t)->aux_task_owner_node)) {
		//WARN_ON(!is_running(t));
		TRACE_CUR("aux tasks may not inherit from %s/%d in group %s/%d\n",
						t->comm, t->pid, leader->comm, leader->pid);
		goto out;
	}

	hp = container_of(
			binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
			struct rt_param, aux_task_owner_node),
			struct task_struct, rt_param);
	hp_eff = effective_priority(hp);
	binheap_delete(&tsk_rt(t)->aux_task_owner_node,
					&tsk_aux(leader)->aux_task_owners);
	binheap_add(&tsk_rt(t)->aux_task_owner_node,
			&tsk_aux(leader)->aux_task_owners,
			struct rt_param, aux_task_owner_node);

	if (hp == t) { /* t was originally the hp */
		struct task_struct *new_hp =
			container_of(
				binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
						struct rt_param, aux_task_owner_node),
				struct task_struct, rt_param);
		/* if the new_hp is still t, or if the effective priority has changed */
		if ((new_hp == t) || (effective_priority(new_hp) != hp_eff)) {
			hp_eff = effective_priority(new_hp);
			retval = aux_tasks_decrease_priority(leader, hp_eff);
		}
	}
out:

#endif
	return retval;
}

int make_aux_task_if_required(struct task_struct *t)
{
	struct task_struct *leader;
	int retval = 0;

	read_lock_irq(&tasklist_lock);

	leader = t->group_leader;

	if(!tsk_aux(leader)->initialized || !tsk_aux(leader)->aux_future)
		goto out;

	TRACE_CUR("Making %s/%d in %s/%d an aux thread.\n",
					t->comm, t->pid, leader->comm, leader->pid);

	INIT_LIST_HEAD(&tsk_rt(t)->aux_task_node);
	INIT_BINHEAP_NODE(&tsk_rt(t)->aux_task_owner_node);

	retval = admit_aux_task(t);
	if (retval == 0) {
		tsk_rt(t)->is_aux_task = 1;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
		list_add_tail(&tsk_rt(t)->aux_task_node, &tsk_aux(leader)->aux_tasks);

		if (!binheap_empty(&tsk_aux(leader)->aux_task_owners)) {
			struct task_struct *hp =
				container_of(
					binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
							struct rt_param, aux_task_owner_node),
					struct task_struct, rt_param);

			TRACE_CUR("hp in group: %s/%d\n", hp->comm, hp->pid);

			retval = litmus->__increase_prio(t,
							(tsk_rt(hp)->inh_task)? tsk_rt(hp)->inh_task : hp);

			if (retval != 0) {
				/* don't know how to recover from bugs with prio inheritance.
				   better just crash. */
				read_unlock_irq(&tasklist_lock);
				BUG();
			}
		}
#endif
	}

out:
	read_unlock_irq(&tasklist_lock);

	return retval;
}

long enable_aux_task_owner(struct task_struct *t)
{
	long retval = 0;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	struct task_struct *leader = t->group_leader;
	struct task_struct *hp;

	if (!tsk_rt(t)->has_aux_tasks) {
		TRACE_CUR("task %s/%d is not an aux owner\n", t->comm, t->pid);
		return -1;
	}

	BUG_ON(!is_realtime(t));

	if (binheap_is_in_heap(&tsk_rt(t)->aux_task_owner_node)) {
		TRACE_CUR("task %s/%d is already active\n", t->comm, t->pid);
		goto out;
	}

	binheap_add(&tsk_rt(t)->aux_task_owner_node,
				&tsk_aux(leader)->aux_task_owners,
				struct rt_param, aux_task_owner_node);

	hp = container_of(
			binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
					struct rt_param, aux_task_owner_node),
			struct task_struct, rt_param);
	if (hp == t) {
		/* we're the new hp */
		TRACE_CUR("%s/%d is new hp in group %s/%d.\n",
						t->comm, t->pid, leader->comm, leader->pid);

		retval = aux_tasks_increase_priority(leader,
					   (tsk_rt(hp)->inh_task)? tsk_rt(hp)->inh_task : hp);
	}
out:

#endif
	return retval;
}

long disable_aux_task_owner(struct task_struct *t)
{
	long retval = 0;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	struct task_struct *leader = t->group_leader;
	struct task_struct *hp;
	struct task_struct *new_hp = NULL;

	if (!tsk_rt(t)->has_aux_tasks) {
		TRACE_CUR("task %s/%d is not an aux owner\n", t->comm, t->pid);
		return -1;
	}

	BUG_ON(!is_realtime(t));

	if (!binheap_is_in_heap(&tsk_rt(t)->aux_task_owner_node)) {
		TRACE_CUR("task %s/%d is already not active\n", t->comm, t->pid);
		goto out;
	}

	TRACE_CUR("task %s/%d exiting from group %s/%d.\n",
					t->comm, t->pid, leader->comm, leader->pid);

	hp = container_of(
			binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
					struct rt_param, aux_task_owner_node),
			struct task_struct, rt_param);
	binheap_delete(&tsk_rt(t)->aux_task_owner_node,
					&tsk_aux(leader)->aux_task_owners);

	if (!binheap_empty(&tsk_aux(leader)->aux_task_owners)) {
		new_hp = container_of(
					binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
							struct rt_param, aux_task_owner_node),
					struct task_struct, rt_param);
	}

	if (hp == t && new_hp != t) {
		struct task_struct *to_inh = NULL;

		TRACE_CUR("%s/%d is no longer hp in group %s/%d.\n",
						t->comm, t->pid, leader->comm, leader->pid);

		if (new_hp) {
			to_inh = (tsk_rt(new_hp)->inh_task) ?
					tsk_rt(new_hp)->inh_task : new_hp;
		}

		retval = aux_tasks_decrease_priority(leader, to_inh);
	}
out:

#endif
	return retval;
}

static int aux_task_owner_max_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	const struct task_struct *d_a =
			container_of(binheap_entry(a, struct rt_param, aux_task_owner_node),
				struct task_struct, rt_param);
	const struct task_struct *d_b =
			container_of(binheap_entry(b, struct rt_param, aux_task_owner_node),
				struct task_struct, rt_param);

	BUG_ON(!d_a);
	BUG_ON(!d_b);

	return litmus->compare(d_a, d_b);
}

static long __do_enable_aux_tasks(int flags)
{
	long retval = 0;
	struct task_struct *leader;
	struct task_struct *t;
	int aux_tasks_added = 0;

	leader = current->group_leader;

	if (!tsk_aux(leader)->initialized) {
		INIT_LIST_HEAD(&tsk_aux(leader)->aux_tasks);
		INIT_BINHEAP_HANDLE(&tsk_aux(leader)->aux_task_owners,
						aux_task_owner_max_priority_order);
		tsk_aux(leader)->initialized = 1;
	}

	if (flags & AUX_FUTURE) {
		tsk_aux(leader)->aux_future = 1;
	}

	t = leader;
	do {
		if (!tsk_rt(t)->has_aux_tasks && !tsk_rt(t)->is_aux_task) {
			/* This may harmlessly reinit unused nodes.
				TODO: Don't reinit already init nodes. */
			/* Doesn't hurt to initialize both nodes */
			INIT_LIST_HEAD(&tsk_rt(t)->aux_task_node);
			INIT_BINHEAP_NODE(&tsk_rt(t)->aux_task_owner_node);
		}

		TRACE_CUR("Checking task in %s/%d: %s/%d = (p = %llu):\n",
				  leader->comm, leader->pid, t->comm, t->pid,
				  tsk_rt(t)->task_params.period);

		/* inspect period to see if it is an rt task */
		if (tsk_rt(t)->task_params.period == 0) {
			if (flags && AUX_CURRENT) {
				if (!tsk_rt(t)->is_aux_task) {
					int admit_ret;

					TRACE_CUR("AUX task in %s/%d: %s/%d:\n",
						leader->comm, leader->pid, t->comm, t->pid);

					admit_ret = admit_aux_task(t);

					if (admit_ret == 0) {
						/* hasn't been aux_tasks_increase_priorityted
						   into rt. make it a aux. */
						tsk_rt(t)->is_aux_task = 1;
						aux_tasks_added = 1;

#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
						list_add_tail(&tsk_rt(t)->aux_task_node,
										&tsk_aux(leader)->aux_tasks);
#endif
					}
				}
				else {
					TRACE_CUR("AUX task in %s/%d is already set up: %s/%d\n",
						leader->comm, leader->pid, t->comm, t->pid);
				}
			}
			else {
				TRACE_CUR("Not changing thread in %s/%d to AUX task: %s/%d\n",
						leader->comm, leader->pid, t->comm, t->pid);
			}
		}
		/* don't let aux tasks get aux tasks get aux tasks of their own */
		else if (!tsk_rt(t)->is_aux_task) {
			if (!tsk_rt(t)->has_aux_tasks) {
				TRACE_CUR("task in %s/%d: %s/%d:\n",
					leader->comm, leader->pid, t->comm, t->pid);
				tsk_rt(t)->has_aux_tasks = 1;
			}
			else {
				TRACE_CUR("task in %s/%d is already set up: %s/%d\n",
					leader->comm, leader->pid, t->comm, t->pid);
			}
		}

		t = next_thread(t);
	} while(t != leader);


#ifdef CONFIG_REALTIME_AUX_TASK_PRIORITY_INHERITANCE
	if (aux_tasks_added && !binheap_empty(&tsk_aux(leader)->aux_task_owners)) {
		struct task_struct *hp = container_of(
				binheap_top_entry(&tsk_aux(leader)->aux_task_owners,
						struct rt_param, aux_task_owner_node),
				struct task_struct, rt_param);
		TRACE_CUR("hp in group: %s/%d\n", hp->comm, hp->pid);
		retval = aux_tasks_increase_priority(leader,
						(tsk_rt(hp)->inh_task)? tsk_rt(hp)->inh_task : hp);
	}
#endif

	return retval;
}

static long __do_disable_aux_tasks(int flags)
{
	long retval = 0;
	struct task_struct *leader;
	struct task_struct *t;

	leader = current->group_leader;

	if (flags & AUX_FUTURE) {
		tsk_aux(leader)->aux_future = 0;
	}

	if (flags & AUX_CURRENT) {
		t = leader;
		do {
			if (tsk_rt(t)->is_aux_task) {

				TRACE_CUR("%s/%d is an aux task.\n", t->comm, t->pid);

				if (is_realtime(t)) {
					long temp_retval;
					struct sched_param param = { .sched_priority = 0};

					TRACE_CUR("%s/%d is real-time. "
						"Changing policy to SCHED_NORMAL.\n",
						t->comm, t->pid);

					temp_retval =
							sched_setscheduler_nocheck(t, SCHED_NORMAL, &param);

					if (temp_retval != 0) {
						TRACE_CUR("error changing policy of %s/%d "
							"to SCHED_NORMAL\n", t->comm, t->pid);
						if (retval == 0) {
							retval = temp_retval;
						}
						else {
							TRACE_CUR("prior error (%d) masks new error (%d)\n",
								retval, temp_retval);
						}
					}
				}
				else {
					TRACE_CUR("%s/%d is not a real-time task.\n",
						t->comm, t->pid);
				}

				tsk_rt(t)->task_params.period = 0;
				tsk_rt(t)->is_aux_task = 0;
			}
			else {
				TRACE_CUR("%s/%d is not an aux task.\n", t->comm, t->pid);
			}

			t = next_thread(t);
		} while(t != leader);
	}

	return retval;
}

asmlinkage long sys_set_aux_tasks(int flags)
{
	long retval;

	read_lock_irq(&tasklist_lock);

	if (flags & AUX_ENABLE) {
		TRACE_CUR("enabling aux tasks\n");
		retval = __do_enable_aux_tasks(flags);
	}
	else {
		TRACE_CUR("DISabling aux tasks\n");
		retval = __do_disable_aux_tasks(flags);
	}

	read_unlock_irq(&tasklist_lock);

	return retval;
}

#else

asmlinkage long sys_set_aux_tasks(int flags)
{
	printk("Unsupported. Recompile with CONFIG_REALTIME_AUX_TASKS.\n");
	return -EINVAL;
}

#endif
