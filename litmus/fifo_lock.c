#include <linux/slab.h>
#include <linux/uaccess.h>

#include <litmus/trace.h>
#include <litmus/sched_trace.h>
#include <litmus/sched_plugin.h>
#include <litmus/fifo_lock.h>

#include <litmus/litmus_proc.h>

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#endif


/* caller is responsible for locking */
static struct task_struct* fifo_mutex_find_hp_waiter(struct fifo_mutex *mutex,
											 struct task_struct* skip)
{
	wait_queue_t		*q;
	struct list_head	*pos;
	struct task_struct  *queued = NULL, *found = NULL;

	list_for_each(pos, &mutex->wait.task_list) {
		q = list_entry(pos, wait_queue_t, task_list);

		queued = get_queued_task(q);

		/* Compare task prios, find high prio task. */
		if (queued &&
			(queued != skip) &&
			(tsk_rt(queued)->blocked_lock == &mutex->litmus_lock) &&
			litmus->compare(queued, found)) {
			found = queued;
		}
	}
	return found;
}


#ifdef CONFIG_LITMUS_DGL_SUPPORT

int fifo_mutex_is_owner(struct litmus_lock *l, struct task_struct *t)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	return(mutex->owner == t);
}

struct task_struct* fifo_mutex_get_owner(struct litmus_lock *l)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	return(mutex->owner);
}

// return 1 if resource was immediatly acquired.
// Assumes mutex->lock is held.
// Must set task state to TASK_UNINTERRUPTIBLE if task blocks.
int fifo_mutex_dgl_lock(struct litmus_lock *l, dgl_wait_state_t* dgl_wait,
					   wait_queue_t* wq_node)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	struct task_struct *t = dgl_wait->task;

	int acquired_immediatly = 0;

	BUG_ON(t != current);

	if (mutex->owner) {
		TRACE_TASK(t, "Enqueuing on lock %d (held by %s/%d).\n",
					l->ident, mutex->owner->comm, mutex->owner->pid);

		init_dgl_waitqueue_entry(wq_node, dgl_wait);

		set_task_state(t, TASK_UNINTERRUPTIBLE);
		__add_wait_queue_tail_exclusive(&mutex->wait, wq_node);
	} else {
		TRACE_TASK(t, "Acquired lock %d with no blocking.\n", l->ident);

		/* it's ours now */
		mutex->owner = t;

		raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);
		binheap_add(&l->nest.hp_binheap_node, &tsk_rt(t)->hp_blocked_tasks,
					struct nested_info, hp_binheap_node);
		raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);

		acquired_immediatly = 1;
	}

	return acquired_immediatly;
}

void fifo_mutex_enable_priority(struct litmus_lock *l,
							   dgl_wait_state_t* dgl_wait)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	struct task_struct *t = dgl_wait->task;
	struct task_struct *owner = mutex->owner;
	unsigned long flags = 0;  // these are unused under DGL coarse-grain locking

	/**************************************
	 * This code looks like it supports fine-grain locking, but it does not!
	 * TODO: Gaurantee that mutex->lock is held by the caller to support fine-grain locking.
	 **************************************/

	BUG_ON(owner == t);

	tsk_rt(t)->blocked_lock = l;
	mb();

	if (litmus->compare(t, mutex->hp_waiter)) {

		struct task_struct *old_max_eff_prio;
		struct task_struct *new_max_eff_prio;
		struct task_struct *new_prio = NULL;

		if(mutex->hp_waiter)
			TRACE_TASK(t, "has higher prio than hp_waiter (%s/%d).\n",
					   mutex->hp_waiter->comm, mutex->hp_waiter->pid);
		else
			TRACE_TASK(t, "has higher prio than hp_waiter (NIL).\n");

		raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

		old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);
		mutex->hp_waiter = t;
		l->nest.hp_waiter_eff_prio = effective_priority(mutex->hp_waiter);
		binheap_decrease(&l->nest.hp_binheap_node,
						 &tsk_rt(owner)->hp_blocked_tasks);
		new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

		if(new_max_eff_prio != old_max_eff_prio) {
			TRACE_TASK(t, "is new hp_waiter.\n");

			if ((effective_priority(owner) == old_max_eff_prio) ||
				(litmus->__compare(new_max_eff_prio, BASE, owner, EFFECTIVE))){
				new_prio = new_max_eff_prio;
			}
		}
		else {
			TRACE_TASK(t, "no change in max_eff_prio of heap.\n");
		}

		if(new_prio) {
			litmus->nested_increase_prio(owner, new_prio,
										 &mutex->lock, flags);  // unlocks lock.
		}
		else {
			raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
			unlock_fine_irqrestore(&mutex->lock, flags);
		}
	}
	else {
		TRACE_TASK(t, "no change in hp_waiter.\n");
		unlock_fine_irqrestore(&mutex->lock, flags);
	}
}

static void select_next_lock_if_primary(struct litmus_lock *l,
										dgl_wait_state_t *dgl_wait)
{
	if(tsk_rt(dgl_wait->task)->blocked_lock == l) {
		TRACE_CUR("Lock %d in DGL was primary for %s/%d.\n",
				  l->ident, dgl_wait->task->comm, dgl_wait->task->pid);
		tsk_rt(dgl_wait->task)->blocked_lock = NULL;
		mb();
		select_next_lock(dgl_wait /*, l*/);  // pick the next lock to be blocked on
	}
	else {
		TRACE_CUR("Got lock early! Lock %d in DGL was NOT primary for %s/%d.\n",
				  l->ident, dgl_wait->task->comm, dgl_wait->task->pid);
	}
}
#endif




int fifo_mutex_lock(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct task_struct *owner;
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	wait_queue_t wait;
	unsigned long flags;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock;
#endif

	if (!is_realtime(t))
		return -EPERM;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	lock_global_irqsave(dgl_lock, flags);
	lock_fine_irqsave(&mutex->lock, flags);

	if (mutex->owner) {
		TRACE_TASK(t, "Blocking on lock %d (held by %s/%d).\n",
						l->ident, mutex->owner->comm, mutex->owner->pid);

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
		// KLUDGE: don't count this suspension as time in the critical gpu
		// critical section
		if(tsk_rt(t)->held_gpus) {
			tsk_rt(t)->suspend_gpu_tracker_on_block = 1;
		}
#endif

		/* resource is not free => must suspend and wait */

		owner = mutex->owner;

		init_waitqueue_entry(&wait, t);

		tsk_rt(t)->blocked_lock = l;  /* record where we are blocked */
		mb();  // needed?

		/* FIXME: interruptible would be nice some day */
		set_task_state(t, TASK_UNINTERRUPTIBLE);

		__add_wait_queue_tail_exclusive(&mutex->wait, &wait);

		/* check if we need to activate priority inheritance */
		if (litmus->compare(t, mutex->hp_waiter)) {

			struct task_struct *old_max_eff_prio;
			struct task_struct *new_max_eff_prio;
			struct task_struct *new_prio = NULL;

			if(mutex->hp_waiter)
				TRACE_TASK(t, "has higher prio than hp_waiter (%s/%d).\n",
						   mutex->hp_waiter->comm, mutex->hp_waiter->pid);
			else
				TRACE_TASK(t, "has higher prio than hp_waiter (NIL).\n");

			raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

			old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);
			mutex->hp_waiter = t;
			l->nest.hp_waiter_eff_prio = effective_priority(mutex->hp_waiter);
			binheap_decrease(&l->nest.hp_binheap_node,
							 &tsk_rt(owner)->hp_blocked_tasks);
			new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			if(new_max_eff_prio != old_max_eff_prio) {
				TRACE_TASK(t, "is new hp_waiter.\n");

				if ((effective_priority(owner) == old_max_eff_prio) ||
					(litmus->__compare(new_max_eff_prio, BASE, owner, EFFECTIVE))){
					new_prio = new_max_eff_prio;
				}
			}
			else {
				TRACE_TASK(t, "no change in max_eff_prio of heap.\n");
			}

			if(new_prio) {
				litmus->nested_increase_prio(owner, new_prio, &mutex->lock,
											 flags);  // unlocks lock.
			}
			else {
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				unlock_fine_irqrestore(&mutex->lock, flags);
			}
		}
		else {
			TRACE_TASK(t, "no change in hp_waiter.\n");

			unlock_fine_irqrestore(&mutex->lock, flags);
		}

		unlock_global_irqrestore(dgl_lock, flags);

		TS_LOCK_SUSPEND;

		/* We depend on the FIFO order.  Thus, we don't need to recheck
		 * when we wake up; we are guaranteed to have the lock since
		 * there is only one wake up per release.
		 */

		suspend_for_lock();

		TS_LOCK_RESUME;

		/* Since we hold the lock, no other task will change
		 * ->owner. We can thus check it without acquiring the spin
		 * lock. */
		BUG_ON(mutex->owner != t);

		TRACE_TASK(t, "Acquired lock %d.\n", l->ident);

	} else {
		TRACE_TASK(t, "Acquired lock %d with no blocking.\n", l->ident);

		/* it's ours now */
		mutex->owner = t;

		raw_spin_lock(&tsk_rt(mutex->owner)->hp_blocked_tasks_lock);
		binheap_add(&l->nest.hp_binheap_node, &tsk_rt(t)->hp_blocked_tasks,
					struct nested_info, hp_binheap_node);
		raw_spin_unlock(&tsk_rt(mutex->owner)->hp_blocked_tasks_lock);


		unlock_fine_irqrestore(&mutex->lock, flags);
		unlock_global_irqrestore(dgl_lock, flags);
	}

	return 0;
}

int fifo_mutex_unlock(struct litmus_lock* l)
{
	struct task_struct *t = current, *next = NULL;
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	unsigned long flags;

	struct task_struct *old_max_eff_prio;

	int wake_up_task = 1;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	dgl_wait_state_t *dgl_wait = NULL;
	raw_spinlock_t *dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	int err = 0;

	if (mutex->owner != t) {
		TRACE_TASK(t, "does not hold fifo mutex %d\n", l->ident);
		err = -EINVAL;
		return err;
	}

	lock_global_irqsave(dgl_lock, flags);
	lock_fine_irqsave(&mutex->lock, flags);

	raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);

	TRACE_TASK(t, "Freeing lock %d\n", l->ident);

	old_max_eff_prio = top_priority(&tsk_rt(t)->hp_blocked_tasks);
	binheap_delete(&l->nest.hp_binheap_node, &tsk_rt(t)->hp_blocked_tasks);

	if(tsk_rt(t)->inh_task){
		struct task_struct *new_max_eff_prio =
			top_priority(&tsk_rt(t)->hp_blocked_tasks);

		if((new_max_eff_prio == NULL) ||
			  /* there was a change in eff prio */
		   (  (new_max_eff_prio != old_max_eff_prio) &&
			/* and owner had the old eff prio */
			  (effective_priority(t) == old_max_eff_prio))  )
		{
			// old_max_eff_prio > new_max_eff_prio
			if(litmus->__compare(new_max_eff_prio, BASE, t, EFFECTIVE)) {
				TRACE_TASK(t, "new_max_eff_prio > task's eff_prio-- new_max_eff_prio: %s/%d   task: %s/%d [%s/%d]\n",
						   new_max_eff_prio->comm, new_max_eff_prio->pid,
						   t->comm, t->pid, tsk_rt(t)->inh_task->comm,
						   tsk_rt(t)->inh_task->pid);
				WARN_ON(1);
			}

			litmus->decrease_prio(t, new_max_eff_prio, 0);
		}
	}

	if(binheap_empty(&tsk_rt(t)->hp_blocked_tasks) &&
	   tsk_rt(t)->inh_task != NULL)
	{
		WARN_ON(tsk_rt(t)->inh_task != NULL);
		TRACE_TASK(t, "No more locks are held, but eff_prio = %s/%d\n",
				   tsk_rt(t)->inh_task->comm, tsk_rt(t)->inh_task->pid);
	}

	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);


	/* check if there are jobs waiting for this resource */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	next = __waitqueue_dgl_remove_first(&mutex->wait, &dgl_wait);
#else
	next = __waitqueue_remove_first(&mutex->wait);
#endif
	if (next) {
		/* next becomes the resouce holder */
		mutex->owner = next;
		TRACE_CUR("lock %d ownership passed to %s/%d\n", l->ident, next->comm, next->pid);

		/* determine new hp_waiter if necessary */
		if (next == mutex->hp_waiter) {

			TRACE_TASK(next, "was highest-prio waiter\n");
			/* next has the highest priority --- it doesn't need to
			 * inherit.  However, we need to make sure that the
			 * next-highest priority in the queue is reflected in
			 * hp_waiter. */
			mutex->hp_waiter = fifo_mutex_find_hp_waiter(mutex, next);
			l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
				effective_priority(mutex->hp_waiter) :
				NULL;

			if (mutex->hp_waiter)
				TRACE_TASK(mutex->hp_waiter, "is new highest-prio waiter\n");
			else
				TRACE("no further waiters\n");

			raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);

			binheap_add(&l->nest.hp_binheap_node,
						&tsk_rt(next)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
			if(dgl_wait) {
				// we normally do this tracing in locking.c, but that code
				// doesn't have visibility into this hand-off.
				sched_trace_lock(dgl_wait->task, l->ident, 1);

				select_next_lock_if_primary(l, dgl_wait);
				--(dgl_wait->nr_remaining);
				wake_up_task = (dgl_wait->nr_remaining == 0);
			}
#endif
			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
		}
		else {
			/* Well, if 'next' is not the highest-priority waiter,
			 * then it (probably) ought to inherit the highest-priority
			 * waiter's priority. */
			TRACE_TASK(next, "is not hp_waiter of lock %d.\n", l->ident);

			raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);

			binheap_add(&l->nest.hp_binheap_node,
						&tsk_rt(next)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
			if(dgl_wait) {
				select_next_lock_if_primary(l, dgl_wait);
				--(dgl_wait->nr_remaining);
				wake_up_task = (dgl_wait->nr_remaining == 0);
			}
#endif

			/* It is possible that 'next' *should* be the hp_waiter, but isn't
			 * because that update hasn't yet executed (update operation is
			 * probably blocked on mutex->lock). So only inherit if the top of
			 * 'next's top heap node is indeed the effective prio. of hp_waiter.
			 * (We use l->hp_waiter_eff_prio instead of effective_priority(hp_waiter)
			 * since the effective priority of hp_waiter can change (and the
			 * update has not made it to this lock).)
			 */
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			if((l->nest.hp_waiter_eff_prio != NULL) &&
			   (top_priority(&tsk_rt(next)->hp_blocked_tasks) ==
													l->nest.hp_waiter_eff_prio))
			{
				if(dgl_wait && tsk_rt(next)->blocked_lock) {
					BUG_ON(wake_up_task);
					if(litmus->__compare(l->nest.hp_waiter_eff_prio, BASE, next, EFFECTIVE)) {
						litmus->nested_increase_prio(next,
							l->nest.hp_waiter_eff_prio, &mutex->lock, flags);  // unlocks lock && hp_blocked_tasks_lock.
						goto out;  // all spinlocks are released.  bail out now.
					}
				}
				else {
					litmus->increase_prio(next, l->nest.hp_waiter_eff_prio);
				}
			}

			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
#else
			if(likely(top_priority(&tsk_rt(next)->hp_blocked_tasks) ==
													l->nest.hp_waiter_eff_prio))
			{
				litmus->increase_prio(next, l->nest.hp_waiter_eff_prio);
			}
			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
#endif
		}

		if(wake_up_task) {
			TRACE_TASK(next, "waking up since it is no longer blocked.\n");

			tsk_rt(next)->blocked_lock = NULL;
			mb();

			wake_up_for_lock(next);
		}
		else {
			TRACE_TASK(next, "is still blocked.\n");
		}
	}
	else {
		/* becomes available */
		mutex->owner = NULL;
	}

	unlock_fine_irqrestore(&mutex->lock, flags);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
out:
#endif
	unlock_global_irqrestore(dgl_lock, flags);

	return err;
}

int fifo_mutex_should_yield_lock(struct litmus_lock* l)
{
	int should_yield;
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	struct task_struct *t = current;
	unsigned long flags;

	if (unlikely(mutex->owner != t))
		return -EINVAL;

	local_irq_save(flags);

	/* Yield if someone is waiting. Check does not need to be atomic. */
	should_yield = waitqueue_active(&mutex->wait);

	local_irq_restore(flags);

	return should_yield;
}


void fifo_mutex_propagate_increase_inheritance(struct litmus_lock* l,
						struct task_struct* t,
						raw_spinlock_t* to_unlock,
						unsigned long irqflags)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);

	// relay-style locking
	lock_fine(&mutex->lock);
	unlock_fine(to_unlock);

	if(tsk_rt(t)->blocked_lock == l) {  // prevent race on tsk_rt(t)->blocked
		struct task_struct *owner = mutex->owner;

		struct task_struct *old_max_eff_prio;
		struct task_struct *new_max_eff_prio;

		raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

		old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

		if((t != mutex->hp_waiter) && litmus->compare(t, mutex->hp_waiter)) {
			TRACE_TASK(t, "is new highest-prio waiter by propagation.\n");
			mutex->hp_waiter = t;
		}
		if(t == mutex->hp_waiter) {
			// reflect the decreased priority in the heap node.
			l->nest.hp_waiter_eff_prio = effective_priority(mutex->hp_waiter);

			BUG_ON(!binheap_is_in_heap(&l->nest.hp_binheap_node));
			BUG_ON(!binheap_is_in_this_heap(&l->nest.hp_binheap_node,
											&tsk_rt(owner)->hp_blocked_tasks));

			binheap_decrease(&l->nest.hp_binheap_node,
							 &tsk_rt(owner)->hp_blocked_tasks);
		}

		new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);


		if(new_max_eff_prio != old_max_eff_prio) {
			// new_max_eff_prio > old_max_eff_prio holds.
			if ((effective_priority(owner) == old_max_eff_prio) ||
				(litmus->__compare(new_max_eff_prio, BASE, owner, EFFECTIVE))) {
				TRACE_CUR("Propagating inheritance to holder of lock %d.\n",
						  l->ident);

				// beware: recursion
				litmus->nested_increase_prio(owner, new_max_eff_prio,
											 &mutex->lock, irqflags);  // unlocks mutex->lock
			}
			else {
				TRACE_CUR("Lower priority than holder %s/%d.  No propagation.\n",
						  owner->comm, owner->pid);
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				unlock_fine_irqrestore(&mutex->lock, irqflags);
			}
		}
		else {
			TRACE_TASK(mutex->owner, "No change in maxiumum effective priority.\n");
			raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
			unlock_fine_irqrestore(&mutex->lock, irqflags);
		}
	}
	else {
		struct litmus_lock *still_blocked = tsk_rt(t)->blocked_lock;

		TRACE_TASK(t, "is not blocked on lock %d.\n", l->ident);
		if(still_blocked) {
			TRACE_TASK(t, "is still blocked on a lock though (lock %d).\n",
					   still_blocked->ident);
			if(still_blocked->ops->propagate_increase_inheritance) {
				/* due to relay-style nesting of spinlocks (acq. A, acq. B, free A, free B)
				 we know that task 't' has not released any locks behind us in this
				 chain.  Propagation just needs to catch up with task 't'. */
				still_blocked->ops->propagate_increase_inheritance(still_blocked,
																   t,
																   &mutex->lock,
																   irqflags);
			}
			else {
				TRACE_TASK(t,
						   "Inheritor is blocked on lock (%p) that does not "
						   "support nesting!\n",
						   still_blocked);
				unlock_fine_irqrestore(&mutex->lock, irqflags);
			}
		}
		else {
			unlock_fine_irqrestore(&mutex->lock, irqflags);
		}
	}
}


inline static void __fifo_mutex_propagate_decrease_inheritance(
						struct litmus_lock* l,
						struct task_struct* t,
						unsigned long irqflags,
						int budget_tiggered)
{
	/* assumes mutex->lock is already held */
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	if(tsk_rt(t)->blocked_lock == l) {  // prevent race on tsk_rt(t)->blocked
		if(t == mutex->hp_waiter) {
			struct task_struct *owner = mutex->owner;

			struct task_struct *old_max_eff_prio;
			struct task_struct *new_max_eff_prio;

			raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

			old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			binheap_delete(&l->nest.hp_binheap_node, &tsk_rt(owner)->hp_blocked_tasks);
			mutex->hp_waiter = fifo_mutex_find_hp_waiter(mutex, NULL);
			l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
			effective_priority(mutex->hp_waiter) : NULL;
			binheap_add(&l->nest.hp_binheap_node,
						&tsk_rt(owner)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);

			new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			if((old_max_eff_prio != new_max_eff_prio) &&
			   (effective_priority(owner) == old_max_eff_prio))
			{
				// Need to set new effective_priority for owner

				struct task_struct *decreased_prio;

				TRACE_TASK(t, "Propagating decreased inheritance to holder of lock %d.\n",
						  l->ident);

				if(litmus->__compare(new_max_eff_prio, BASE, owner, BASE)) {
					TRACE_TASK(t, "%s/%d has greater base priority than base priority of owner (%s/%d) of lock %d.\n",
							  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
							  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
							  owner->comm,
							  owner->pid,
							  l->ident);

					decreased_prio = new_max_eff_prio;
				}
				else {
					TRACE_TASK(t, "%s/%d has lesser base priority than base priority of owner (%s/%d) of lock %d.\n",
							  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
							  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
							  owner->comm,
							  owner->pid,
							  l->ident);

					decreased_prio = NULL;
				}

				// beware: recursion
				// will trigger reschedule of owner, if needed.
				litmus->nested_decrease_prio(owner, decreased_prio, &mutex->lock, irqflags, budget_tiggered); // will unlock mutex->lock
			}
			else {
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				unlock_fine_irqrestore(&mutex->lock, irqflags);
			}
		}
		else {
			TRACE_TASK(t, "is not hp_waiter.  No propagation.\n");
			unlock_fine_irqrestore(&mutex->lock, irqflags);
		}
	}
	else {
		struct litmus_lock *still_blocked = tsk_rt(t)->blocked_lock;

		/* TODO: is this code path valid for budgets? */
		if (budget_tiggered)
			WARN_ON(1);

		TRACE_TASK(t, "is not blocked on lock %d.\n", l->ident);
		if(still_blocked) {
			TRACE_TASK(t, "is still blocked on a lock though (lock %d).\n",
					   still_blocked->ident);
			if(still_blocked->ops->propagate_decrease_inheritance) {
				/* due to linked nesting of spinlocks (acq. A, acq. B, free A, free B)
				 we know that task 't' has not released any locks behind us in this
				 chain.  propagation just needs to catch up with task 't' */
				still_blocked->ops->propagate_decrease_inheritance(still_blocked,
																   t,
																   &mutex->lock,
																   irqflags,
																   budget_tiggered);
			}
			else {
				TRACE_TASK(t, "Inheritor is blocked on lock (%p) that does not support nesting!\n",
						   still_blocked);
				unlock_fine_irqrestore(&mutex->lock, irqflags);
			}
		}
		else {
			unlock_fine_irqrestore(&mutex->lock, irqflags);
		}
	}
}

void fifo_mutex_propagate_decrease_inheritance(struct litmus_lock* l,
						struct task_struct* t,
						raw_spinlock_t* to_unlock,
						unsigned long irqflags,
						int budget_tiggered)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);

	// relay-style locking
	lock_fine(&mutex->lock);
	unlock_fine(to_unlock);

	// unlocks mutex->lock
	__fifo_mutex_propagate_decrease_inheritance(&mutex->litmus_lock, t, irqflags, budget_tiggered);
}


/* t's base priority has (already) been decreased due to budget exhaustion */
void fifo_mutex_budget_exhausted(struct litmus_lock* l, struct task_struct* t)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	unsigned long flags = 0;

	/* DGL lock must already be held on this code path if DGLs are enabled. */
	lock_fine_irqsave(&mutex->lock, flags);

	TRACE_TASK(t, "handling budget exhaustion for FIFO lock %d\n", l->ident);

	/* unlocks mutex->lock */
	__fifo_mutex_propagate_decrease_inheritance(&mutex->litmus_lock, t, flags, 1);
}


int fifo_mutex_close(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct fifo_mutex *mutex = fifo_mutex_from_lock(l);
	unsigned long flags;

	int owner;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	lock_global_irqsave(dgl_lock, flags);
	lock_fine_irqsave(&mutex->lock, flags);

	owner = (mutex->owner == t);

	unlock_fine_irqrestore(&mutex->lock, flags);
	unlock_global_irqrestore(dgl_lock, flags);

	/*
	 TODO: Currently panic.  FIX THIS!
	if (owner)
		fifo_mutex_unlock(l);
	*/

	return 0;
}

void fifo_mutex_free(struct litmus_lock* lock)
{
	kfree(fifo_mutex_from_lock(lock));
}

#if 0
/* The following may race if DGLs are enabled.  Only examine /proc if things
   appear to be locked up.  TODO: FIX THIS! Must find an elegant way to transmit
   DGL lock to function. */
static int fifo_proc_print(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct fifo_mutex *mutex = fifo_mutex_from_lock((struct litmus_lock*)data);

	int attempts = 0;
	const int max_attempts = 10;
	int locked = 0;
	unsigned long flags;

	int size = count;
	char *next = page;
	int w;

	while(attempts < max_attempts)
	{
		locked = raw_spin_trylock_irqsave(&mutex->lock, flags);

		if (unlikely(!locked)) {
			++attempts;
			cpu_relax();
		}
		else {
			break;
		}
	}

	if (locked) {
		w = scnprintf(next, size, "%s (mutex: %p, data: %p):\n", mutex->litmus_lock.name, mutex, data);
		size -= w;
		next += w;

		w = scnprintf(next, size,
						"owner: %s/%d (inh: %s/%d)\n",
							(mutex->owner) ?
								mutex->owner->comm : "null",
							(mutex->owner) ?
								mutex->owner->pid : 0,
							(mutex->owner && tsk_rt(mutex->owner)->inh_task) ?
								tsk_rt(mutex->owner)->inh_task->comm : "null",
							(mutex->owner && tsk_rt(mutex->owner)->inh_task) ?
								tsk_rt(mutex->owner)->inh_task->pid : 0);
		size -= w;
		next += w;

		w = scnprintf(next, size,
						"hp waiter: %s/%d (inh: %s/%d)\n",
							(mutex->hp_waiter) ?
								mutex->hp_waiter->comm : "null",
							(mutex->hp_waiter) ?
								mutex->hp_waiter->pid : 0,
							(mutex->hp_waiter && tsk_rt(mutex->hp_waiter)->inh_task) ?
								tsk_rt(mutex->hp_waiter)->inh_task->comm : "null",
							(mutex->hp_waiter && tsk_rt(mutex->hp_waiter)->inh_task) ?
								tsk_rt(mutex->hp_waiter)->inh_task->pid : 0);
		size -= w;
		next += w;

		w = scnprintf(next, size, "\nblocked tasks, front to back:\n");
		size -= w;
		next += w;

		if (waitqueue_active(&mutex->wait)) {
			wait_queue_t *q;
			struct list_head *pos;
#ifdef CONFIG_LITMUS_DGL_SUPPORT
			dgl_wait_state_t	*dgl_wait = NULL;
#endif
			list_for_each(pos, &mutex->wait.task_list) {
				struct task_struct *blocked_task;
#ifdef CONFIG_LITMUS_DGL_SUPPORT
				int enabled = 1;
#endif
				q = list_entry(pos, wait_queue_t, task_list);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
				if(q->func == dgl_wake_up) {
					dgl_wait = (dgl_wait_state_t*) q->private;
					blocked_task = dgl_wait->task;

					if(tsk_rt(blocked_task)->blocked_lock != &mutex->litmus_lock)
						enabled = 0;
				}
				else {
					blocked_task = (struct task_struct*) q->private;
				}
#else
				blocked_task = (struct task_struct*) q->private;
#endif

				w = scnprintf(next, size,
						"\t%s/%d (inh: %s/%d)"
#ifdef CONFIG_LITMUS_DGL_SUPPORT
						" DGL enabled: %d"
#endif
						"\n",
						blocked_task->comm, blocked_task->pid,
						(tsk_rt(blocked_task)->inh_task) ?
							tsk_rt(blocked_task)->inh_task->comm : "null",
						(tsk_rt(blocked_task)->inh_task) ?
							tsk_rt(blocked_task)->inh_task->pid : 0
#ifdef CONFIG_LITMUS_DGL_SUPPORT
						, enabled
#endif
						);
				size -= w;
				next += w;
			}
		}
		else {
			w = scnprintf(next, size, "\t<NONE>\n");
			size -= w;
			next += w;
		}

		raw_spin_unlock_irqrestore(&mutex->lock, flags);
	}
	else {
		w = scnprintf(next, size, "%s is busy.\n", mutex->litmus_lock.name);
		size -= w;
		next += w;
	}

	return count - size;
}

static void fifo_proc_add(struct litmus_lock* l)
{
	if (!l->name)
		l->name = kmalloc(LOCK_NAME_LEN*sizeof(char), GFP_KERNEL);
	snprintf(l->name, LOCK_NAME_LEN, "fifo-%d", l->ident);
	litmus_add_proc_lock(l, fifo_proc_print);
}

static void fifo_proc_remove(struct litmus_lock* l)
{
	if (l->name) {
		litmus_remove_proc_lock(l);

		kfree(l->name);
		l->name = NULL;
	}
}

static struct litmus_lock_proc_ops fifo_proc_ops =
{
	.add = fifo_proc_add,
	.remove = fifo_proc_remove
};
#endif

struct litmus_lock* fifo_mutex_new(struct litmus_lock_ops* ops)
{
	struct fifo_mutex* mutex;

	mutex = kmalloc(sizeof(*mutex), GFP_KERNEL);
	if (!mutex)
		return NULL;
	memset(mutex, 0, sizeof(*mutex));

	mutex->litmus_lock.ops = ops;
	mutex->owner = NULL;
	mutex->hp_waiter = NULL;
	init_waitqueue_head(&mutex->wait);

	raw_spin_lock_init(&mutex->lock);
	LOCKDEP_DYNAMIC_ALLOC(mutex, &mutex->lock);

	((struct litmus_lock*)mutex)->nest.hp_waiter_ptr = &mutex->hp_waiter;

//	((struct litmus_lock*)mutex)->proc = &fifo_proc_ops;

	return &mutex->litmus_lock;
}

