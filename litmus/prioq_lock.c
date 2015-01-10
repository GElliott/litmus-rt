#include <linux/slab.h>
#include <linux/uaccess.h>

#include <litmus/trace.h>
#include <litmus/sched_plugin.h>
#include <litmus/prioq_lock.h>

#include <litmus/litmus_proc.h>


#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#endif

//#define PRIOQ_VERBOSE

#ifdef PRIOQ_VERBOSE
void __attribute__((unused))
__dump_prioq_lock_info(struct prioq_mutex *mutex)
{
	TRACE_CUR("%s (mutex: %p):\n", mutex->litmus_lock.name, mutex);
	TRACE_CUR("owner: %s/%d (inh: %s/%d)\n",
			  (mutex->owner) ?
			  mutex->owner->comm : "null",
			  (mutex->owner) ?
			  mutex->owner->pid : 0,
			  (mutex->owner && tsk_rt(mutex->owner)->inh_task) ?
			  tsk_rt(mutex->owner)->inh_task->comm : "null",
			  (mutex->owner && tsk_rt(mutex->owner)->inh_task) ?
			  tsk_rt(mutex->owner)->inh_task->pid : 0);
	TRACE_CUR("hp waiter: %s/%d (inh: %s/%d)\n",
			  (mutex->hp_waiter) ?
			  mutex->hp_waiter->comm : "null",
			  (mutex->hp_waiter) ?
			  mutex->hp_waiter->pid : 0,
			  (mutex->hp_waiter && tsk_rt(mutex->hp_waiter)->inh_task) ?
			  tsk_rt(mutex->hp_waiter)->inh_task->comm : "null",
			  (mutex->hp_waiter && tsk_rt(mutex->hp_waiter)->inh_task) ?
			  tsk_rt(mutex->hp_waiter)->inh_task->pid : 0);
	TRACE_CUR("blocked tasks, front to back:\n");
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
			TRACE_CUR("\t%s/%d (inh: %s/%d)"
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
		}
	}
	else {
		TRACE_CUR("\t<NONE>\n");
	}
}
#else
#define __dump_prioq_lock_info(x)
#endif

static void __add_wait_queue_sorted(wait_queue_head_t *q, wait_queue_t *add_node)
{
	struct list_head *pq = &(q->task_list);
	wait_queue_t *q_node;
	struct task_struct *queued_task;
	struct task_struct *add_task;
	struct list_head *pos;

	if (list_empty(pq)) {
		list_add_tail(&add_node->task_list, pq);
		return;
	}

	add_task = get_queued_task(add_node);

	/* less priority than tail?  if so, go to tail */
	q_node = list_entry(pq->prev, wait_queue_t, task_list);
	queued_task = get_queued_task(q_node);
	if (litmus->compare(queued_task, add_task)) {
		list_add_tail(&add_node->task_list, pq);
		return;
	}

	/* belongs at head or between nodes */
	list_for_each(pos, pq) {
		q_node = list_entry(pos, wait_queue_t, task_list);
		queued_task = get_queued_task(q_node);
		if(litmus->compare(add_task, queued_task)) {
			list_add(&add_node->task_list, pos->prev);
			return;
		}
	}

	WARN_ON(1);
	list_add_tail(&add_node->task_list, pq);
}

static inline void __add_wait_queue_sorted_exclusive(wait_queue_head_t *q, wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_sorted(q, wait);
}


static void __prioq_increase_pos(struct prioq_mutex *mutex, struct task_struct *t)
{
	wait_queue_t		*q;
	struct list_head	*pos;
	struct task_struct  *queued;

	/* TODO: Make this efficient instead of remove/add */
	list_for_each(pos, &mutex->wait.task_list) {
		q = list_entry(pos, wait_queue_t, task_list);
		queued = get_queued_task(q);
		if (queued == t) {
			__remove_wait_queue(&mutex->wait, q);
			__add_wait_queue_sorted(&mutex->wait, q);
			return;
		}
	}

	BUG();
}

#ifndef CONFIG_LITMUS_DGL_SUPPORT
static void __prioq_decrease_pos(struct prioq_mutex *mutex, struct task_struct *t)
{
	/* TODO: Make this efficient instead of remove/add */
	__prioq_increase_pos(mutex, t);
}
#endif


/* caller is responsible for locking */
static struct task_struct* __prioq_mutex_find_hp_waiter(struct prioq_mutex *mutex,
														struct task_struct* skip)
{
	wait_queue_t		*q;
	struct list_head	*pos;
	struct task_struct  *queued = NULL, *found = NULL;

	/* list in sorted order.  higher-prio tasks likely at the front. */
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

static int ___prioq_dgl_acquire_via_inheritance(struct prioq_mutex *mutex, struct task_struct *t, dgl_wait_state_t *dgl_wait)
{
	/* Any task that acquires a PRIOQ mutex via inheritance does not inheritance
	 * does not inherit priority from the hp_waiter, by defintion of the
	 * priority queue. */

	struct litmus_lock *l;
	BUG_ON(mutex->owner != NULL);
	BUG_ON(list_empty(&mutex->wait.task_list));

	l = &mutex->litmus_lock;

	if (dgl_wait) {
		BUG_ON(t != dgl_wait->task);

		/* we're a part of a DGL */
		if(__attempt_atomic_dgl_acquire(NULL, dgl_wait)) {
			TRACE_CUR("%s/%d cannot take entire DGL via inheritance.\n",
					  t->comm, t->pid);
			/* it can't take the lock. nullify 't'. */
			t = NULL;
		}
		else {
			TRACE_CUR("%s/%d can take its entire DGL atomically via inheritance!\n",
					  t->comm, t->pid);
			/* __attempt_atomic_dgl_acquire() already cleaned up the state of acquired locks */
		}
	}
	else {
		/* we're a regular singular request. we can always take the lock if
		 * there is no mutex owner. */
		wait_queue_t *first;

		TRACE_CUR("%s/%d can take it's singular lock via inheritance!\n",
				  t->comm, t->pid);

		first = list_entry(mutex->wait.task_list.next, wait_queue_t, task_list);

		BUG_ON(get_queued_task(first) != t);

		__remove_wait_queue(&mutex->wait, first); /* remove the blocked task */

		/* update/cleanup the state of the lock */

		mutex->owner = t; /* take ownership!!! */

		mutex->hp_waiter = __prioq_mutex_find_hp_waiter(mutex, t);
		l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
			effective_priority(mutex->hp_waiter) : NULL;

		if (mutex->hp_waiter)
			TRACE_CUR("%s/%d is new highest-prio waiter\n",
					  mutex->hp_waiter->comm, mutex->hp_waiter->pid);
		else
			TRACE_CUR("no further waiters\n");

		raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);

		binheap_add(&l->nest.hp_binheap_node,
					&tsk_rt(t)->hp_blocked_tasks,
					struct nested_info, hp_binheap_node);

		raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);
	}

	if (t) {
		BUG_ON(mutex->owner != t);

		TRACE_CUR("%s/%d waking up since it is no longer blocked.\n", t->comm, t->pid);

		tsk_rt(t)->blocked_lock = NULL;
		mb();

		wake_up_for_lock(t);
	}

	return (t != NULL);
}

static inline struct task_struct* get_head_task(struct prioq_mutex *mutex)
{
	wait_queue_t *q_node = list_entry(mutex->wait.task_list.next, wait_queue_t, task_list);
	return get_queued_task(q_node);
}

static int __prioq_dgl_increase_pos(struct prioq_mutex *mutex, struct task_struct *t)
{
//	(1) Increase position for 't' for all locks it is waiting.
//  (2) Check to see if 't' can take the lock, DGL or singular lock.
//  (3) If it can, do so and wake up 't'.

	struct list_head *pos;
	struct task_struct *new_head;
	struct task_struct *cur_head = NULL;
	dgl_wait_state_t *dgl_wait = NULL;
	int woke_up = 0;
	int found = 0;


	BUG_ON(list_empty(&mutex->wait.task_list));

	/* note the task at the head of the queue */
	if(mutex->owner == NULL) {
		cur_head = get_head_task(mutex);
	}

	list_for_each(pos, &mutex->wait.task_list) {
		dgl_wait_state_t *temp_dgl_state;
		wait_queue_t *q = list_entry(pos, wait_queue_t, task_list);
		struct task_struct *queued = get_queued_task_and_dgl_wait(q, &temp_dgl_state);

		if (queued == t) {

			TRACE_CUR("found %s/%d in prioq of lock %d\n",
					  t->comm, t->pid,
					  mutex->litmus_lock.ident);

			if(temp_dgl_state) { /* it's a DGL request */
				int i;
				dgl_wait = temp_dgl_state;

				TRACE_CUR("found request for %s/%d is a DGL request of size %d.\n",
						  t->comm, t->pid, dgl_wait->size);

				// reposition on the other mutexes
				for(i = 0; i < dgl_wait->size; ++i) {
					// assume they're all PRIOQ_MUTEX
					struct prioq_mutex *pm = (struct prioq_mutex *) dgl_wait->locks[i];
					if (pm != mutex)
						__prioq_increase_pos(pm, t);
				}
			}

			// reposition on this mutex
			__remove_wait_queue(&mutex->wait, q);
			__add_wait_queue_sorted(&mutex->wait, q);
			found = 1;
			break;
		}
	}

	BUG_ON(!found);

	if (mutex->owner == NULL) {
		/* who is the new head? */
		new_head = get_head_task(mutex);

		/* is the prioq mutex idle? */
		if(cur_head != new_head) {
			/* the new head might be able to take the lock */

			BUG_ON(new_head != t); /* the new head must be this task since our prio increased */

			TRACE_CUR("Change in prioq head on idle prioq mutex %d: old = %s/%d new = %s/%d\n",
					  mutex->litmus_lock.ident,
					  cur_head->comm, cur_head->pid,
					  new_head->comm, new_head->pid);

			woke_up = ___prioq_dgl_acquire_via_inheritance(mutex, t, dgl_wait);
		}
	}

	return woke_up;
}

static int ___prioq_dgl_decrease_pos_and_check_acquire(struct prioq_mutex *mutex, struct task_struct *t, wait_queue_t *q)
{
	struct list_head *pos;
	struct task_struct *new_head;
	struct task_struct *cur_head = NULL;
	int woke_up = 0;
	int found = 1;

	BUG_ON(list_empty(&mutex->wait.task_list));

	/* find the position of t in mutex's wait q if it's not provided */
	if (q == NULL) {
		found = 0;
		list_for_each(pos, &mutex->wait.task_list) {
			q = list_entry(pos, wait_queue_t, task_list);
			if (t == get_queued_task(q)) {
				found = 1;
				break;
			}
		}
	}

	BUG_ON(!q);
	BUG_ON(!found);

	if(mutex->owner == NULL) {
		cur_head = get_head_task(mutex);
	}

	// update the position
	__remove_wait_queue(&mutex->wait, q);
	__add_wait_queue_sorted(&mutex->wait, q);

	if(mutex->owner == NULL) {
		// get a reference to dgl_wait of the new head is a DGL request
		dgl_wait_state_t *dgl_wait;
		q = list_entry(mutex->wait.task_list.next, wait_queue_t, task_list);
		new_head = get_queued_task_and_dgl_wait(q, &dgl_wait);

		/* is the prioq mutex idle and did the head change? */
		if(cur_head != new_head) {
			/* the new head might be able to take the lock */
			TRACE_CUR("Change in prioq head on idle prioq mutex %d: old = %s/%d new = %s/%d\n",
					  mutex->litmus_lock.ident,
					  cur_head->comm, cur_head->pid,
					  new_head->comm, new_head->pid);

			woke_up = ___prioq_dgl_acquire_via_inheritance(mutex, new_head, dgl_wait);
		}
	}
	return woke_up;
}

static void __prioq_dgl_decrease_pos(struct prioq_mutex *mutex, struct task_struct *t)
{
//	(1) Decrease position for 't' for all locks it is waiting.
//  (2) For every lock upon which 't' was the head AND that lock is idle:
//  (3)    Can the new head take the lock?
//  (4)    If it can, do so and wake up the new head.

	struct list_head	*pos;

	BUG_ON(list_empty(&mutex->wait.task_list));

	list_for_each(pos, &mutex->wait.task_list) {
		dgl_wait_state_t *dgl_wait;
		wait_queue_t *q = list_entry(pos, wait_queue_t, task_list);
		struct task_struct *queued = get_queued_task_and_dgl_wait(q, &dgl_wait);

		if (queued == t) {
			TRACE_CUR("found %s/%d in prioq of lock %d\n",
					  t->comm, t->pid,
					  mutex->litmus_lock.ident);

			if (dgl_wait) {
				// reposition on all mutexes and check for wakeup
				int i;

				TRACE_CUR("found request for %s/%d is a DGL request of size %d.\n",
						  t->comm, t->pid, dgl_wait->size);

				for(i = 0; i < dgl_wait->size; ++i) {
					// assume they're all PRIOQ_MUTEX
					struct prioq_mutex *pm = (struct prioq_mutex *) dgl_wait->locks[i];
					if (pm != mutex)
						___prioq_dgl_decrease_pos_and_check_acquire(pm, t, NULL);
					else
						___prioq_dgl_decrease_pos_and_check_acquire(pm, t, q);
				}
			}
			else {
				___prioq_dgl_decrease_pos_and_check_acquire(mutex, t, q);
			}
			return;
		}
	}

	BUG();
}



int prioq_mutex_is_owner(struct litmus_lock *l, struct task_struct *t)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	return(mutex->owner == t);
}

struct task_struct* prioq_mutex_get_owner(struct litmus_lock *l)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	return(mutex->owner);
}

// return 1 if resource was immediatly acquired.
// Assumes mutex->lock is held.
// Must set task state to TASK_UNINTERRUPTIBLE if task blocks.
int prioq_mutex_dgl_lock(struct litmus_lock *l, dgl_wait_state_t* dgl_wait,
					   wait_queue_t* wq_node)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	struct task_struct *t = dgl_wait->task;

	int acquired_immediatly = 0;

	BUG_ON(t != current);


	init_dgl_waitqueue_entry(wq_node, dgl_wait);

	//set_task_state(t, TASK_UNINTERRUPTIBLE); /* done in do_litmus_dgl_atomic_lock() only if needed */
	__add_wait_queue_sorted_exclusive(&mutex->wait, wq_node);

	return acquired_immediatly;
}


void prioq_mutex_enable_priority(struct litmus_lock *l,
							   dgl_wait_state_t* dgl_wait)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	struct task_struct *t = dgl_wait->task;
	struct task_struct *owner = mutex->owner;
	unsigned long flags;
	local_save_flags(flags);  // needed for coarse-grain DGLs?

	/**************************************
	* This code looks like it supports fine-grain locking, but it does not!
	* TODO: Gaurantee that mutex->lock is held by the caller to support fine-grain locking.
	**************************************/

	BUG_ON(owner == t);

	tsk_rt(t)->blocked_lock = l;
	mb();

	TRACE_TASK(t, "Enabling prio on lock %d. I am %s/%d  :  cur hp_waiter is %s/%d.\n",
			   l->ident,
			   (t) ? t->comm : "null",
			   (t) ? t->pid : 0,
			   (mutex->hp_waiter) ? mutex->hp_waiter->comm : "null",
			   (mutex->hp_waiter) ? mutex->hp_waiter->pid : 0);

	if (litmus->compare(t, mutex->hp_waiter)) {
		struct task_struct *old_max_eff_prio;
		struct task_struct *new_max_eff_prio;
		struct task_struct *new_prio = NULL;

		if(mutex->hp_waiter)
			TRACE_TASK(t, "has higher prio than hp_waiter (%s/%d).\n",
					   mutex->hp_waiter->comm, mutex->hp_waiter->pid);
		else
			TRACE_TASK(t, "has higher prio than hp_waiter (NIL).\n");


		if (!owner) {
			TRACE_TASK(t, "Enabling priority, but this lock %d is idle.\n", l->ident);
			goto out;
		}

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

		return;
	}

	TRACE_TASK(t, "no change in hp_waiter.\n");

out:
	unlock_fine_irqrestore(&mutex->lock, flags);
}

static void select_next_lock_if_primary(struct litmus_lock *l,
										dgl_wait_state_t *dgl_wait)
{
	struct task_struct *t = dgl_wait->task;

	if(tsk_rt(t)->blocked_lock == l) {
		struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

		TRACE_CUR("Lock %d in DGL was primary for %s/%d.\n",
				  l->ident, t->comm, t->pid);

		tsk_rt(t)->blocked_lock = NULL;
		mb();


		/* determine new hp_waiter if necessary */
		if (t == mutex->hp_waiter) {

			TRACE_TASK(t, "Deciding to not be hp waiter on lock %d any more.\n", l->ident);
			/* next has the highest priority --- it doesn't need to
			 * inherit.  However, we need to make sure that the
			 * next-highest priority in the queue is reflected in
			 * hp_waiter. */
			mutex->hp_waiter = __prioq_mutex_find_hp_waiter(mutex, t);
			l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
				effective_priority(mutex->hp_waiter) :
				NULL;


			if (mutex->hp_waiter)
				TRACE_CUR("%s/%d is new highest-prio waiter\n",
						  mutex->hp_waiter->comm, mutex->hp_waiter->pid);
			else
				TRACE_CUR("no further waiters\n");
		}

		select_next_lock(dgl_wait /*, l*/);  // pick the next lock to be blocked on
	}
	else {
		TRACE_CUR("Got lock early! Lock %d in DGL was NOT primary for %s/%d.\n",
				  l->ident, t->comm, t->pid);
	}
}

int prioq_mutex_dgl_can_quick_lock(struct litmus_lock *l, struct task_struct *t)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

	if(!mutex->owner) {
		wait_queue_t *front = list_entry(mutex->wait.task_list.next, wait_queue_t, task_list);
		struct task_struct *at_front = get_queued_task(front);
		if(t == at_front) {
			return 1;
		}
	}
	return 0;
}

void prioq_mutex_dgl_quick_lock(struct litmus_lock *l, struct litmus_lock *cur_lock,
								struct task_struct* t, wait_queue_t *q)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

	BUG_ON(mutex->owner);
	BUG_ON(t != get_queued_task(list_entry(mutex->wait.task_list.next, wait_queue_t, task_list)));


	mutex->owner = t;

	if (l != cur_lock) {
		/* we have to update the state of the other lock for it */
		__remove_wait_queue(&mutex->wait, q);

		mutex->hp_waiter = __prioq_mutex_find_hp_waiter(mutex, t);
		l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
			effective_priority(mutex->hp_waiter) :
			NULL;

		if (mutex->hp_waiter)
			TRACE_TASK(mutex->hp_waiter, "is new highest-prio waiter\n");
		else
			TRACE("no further waiters\n");

		raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);

		binheap_add(&l->nest.hp_binheap_node,
					&tsk_rt(t)->hp_blocked_tasks,
					struct nested_info, hp_binheap_node);

		raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);
	}
	else {
		/* the unlock call that triggered the quick_lock call will handle
		 * the acquire of cur_lock.
		 */
	}
}
#endif




int prioq_mutex_lock(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct task_struct *owner;
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
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

	/* block if there is an owner, or if hp_waiter is blocked for DGL and
	 * prio(t) < prio(hp_waiter) */
	if (mutex->owner ||
		(waitqueue_active(&mutex->wait) && litmus->compare(mutex->hp_waiter, t))) {
		TRACE_TASK(t, "Blocking on lock %d (held by %s/%d).\n",
					l->ident,
				   (mutex->owner) ? mutex->owner->comm : "null",
				   (mutex->owner) ? mutex->owner->pid : 0);

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

		__add_wait_queue_sorted_exclusive(&mutex->wait, &wait);

		/* check if we need to activate priority inheritance */
		/* We can't be the hp waiter if there is no owner - task waiting for
		 * the full DGL must be the hp_waiter. */
		if (owner && litmus->compare(t, mutex->hp_waiter)) {

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

			TRACE_TASK(t, "prioq_mutex %d state after enqeue in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);

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

			TRACE_TASK(t, "prioq_mutex %d state after enqeue in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);

			unlock_fine_irqrestore(&mutex->lock, flags);
		}

		flush_pending_wakes();
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


int prioq_mutex_unlock(struct litmus_lock* l)
{
	int err = 0;
	struct task_struct *t = current, *next = NULL;
	struct task_struct *old_max_eff_prio;
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	unsigned long flags;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock;
	dgl_wait_state_t *dgl_wait = NULL;
#endif

	if (mutex->owner != t) {
		err = -EINVAL;
		return err;
	}

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	dgl_lock = litmus->get_dgl_spinlock(current);
#endif

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


	mutex->owner = NULL;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	if(waitqueue_active(&mutex->wait)) {
		/* Priority queue-based locks must be _acquired_ atomically under DGLs
		 * in order to avoid deadlock.  We leave this lock idle momentarily the
		 * DGL waiter can't acquire all locks at once.
		 */
		wait_queue_t *q = list_entry(mutex->wait.task_list.next, wait_queue_t, task_list);
		get_queued_task_and_dgl_wait(q, &dgl_wait);

		if (dgl_wait) {
			TRACE_CUR("Checking to see if DGL waiter %s/%d can take its locks\n",
					  dgl_wait->task->comm, dgl_wait->task->pid);

			if(__attempt_atomic_dgl_acquire(l, dgl_wait)) {
				/* failed. can't take this lock yet. we remain at head of prioq
				 * allow hp requests in the future to go ahead of us. */
				select_next_lock_if_primary(l, dgl_wait);
				goto out;
			}
			else {
				TRACE_CUR("%s/%d can take its entire DGL atomically.\n",
						  dgl_wait->task->comm, dgl_wait->task->pid);
			}
		}

		/* remove the first */
		next = __waitqueue_dgl_remove_first(&mutex->wait, &dgl_wait);

		BUG_ON(dgl_wait && (next != dgl_wait->task));
	}
#else
	/* check if there are jobs waiting for this resource */
	next = __waitqueue_remove_first(&mutex->wait);
#endif
	if (next) {
		/* next becomes the resouce holder */
		mutex->owner = next;
		TRACE_CUR("lock %d ownership passed to %s/%d\n", l->ident, next->comm, next->pid);

		/* determine new hp_waiter if necessary */
		if (next == mutex->hp_waiter) {

			TRACE_CUR("%s/%d was highest-prio waiter\n", next->comm, next->pid);

			/* next has the highest priority --- it doesn't need to
			 * inherit.  However, we need to make sure that the
			 * next-highest priority in the queue is reflected in
			 * hp_waiter. */
			mutex->hp_waiter = __prioq_mutex_find_hp_waiter(mutex, next);
			l->nest.hp_waiter_eff_prio = (mutex->hp_waiter) ?
				effective_priority(mutex->hp_waiter) :
				NULL;


			if (mutex->hp_waiter)
				TRACE_CUR("%s/%d is new highest-prio waiter\n",
						  mutex->hp_waiter->comm, mutex->hp_waiter->pid);
			else
				TRACE_CUR("no further waiters\n");


			raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);

			binheap_add(&l->nest.hp_binheap_node,
						&tsk_rt(next)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);

			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
		}
		else {
			/* Well, if 'next' is not the highest-priority waiter,
			 * then it (probably) ought to inherit the highest-priority
			 * waiter's priority. */
			TRACE_CUR("%s/%d is not hp_waiter of lock %d.\n", next->comm, next->pid, l->ident);

			raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);

			binheap_add(&l->nest.hp_binheap_node,
						&tsk_rt(next)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);

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
			   (top_priority(&tsk_rt(next)->hp_blocked_tasks) == l->nest.hp_waiter_eff_prio))
			{
				if(dgl_wait && tsk_rt(next)->blocked_lock) {
					if(litmus->__compare(l->nest.hp_waiter_eff_prio, BASE, next, EFFECTIVE)) {
						litmus->nested_increase_prio(next, l->nest.hp_waiter_eff_prio, &mutex->lock, flags);  // unlocks lock && hp_blocked_tasks_lock.
						goto out;  // all spinlocks are released.  bail out now.
					}
				}
				else {
					litmus->increase_prio(next, l->nest.hp_waiter_eff_prio);
				}
			}

			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
#else
			if(likely(top_priority(&tsk_rt(next)->hp_blocked_tasks) == l->nest.hp_waiter_eff_prio))
			{
				litmus->increase_prio(next, l->nest.hp_waiter_eff_prio);
			}
			raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
#endif
		}

		TRACE_CUR("%s/%d waking up since it is no longer blocked.\n", next->comm, next->pid);

		tsk_rt(next)->blocked_lock = NULL;
		mb();

		wake_up_for_lock(next);
	}

	unlock_fine_irqrestore(&mutex->lock, flags);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
out:
#endif

	unlock_global_irqrestore(dgl_lock, flags);

	return err;
}

int prioq_mutex_should_yield_lock(struct litmus_lock* l)
{
	int should_yield;
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	struct task_struct *t = current;
	unsigned long flags;

	if (unlikely(mutex->owner != t))
		return -EINVAL;

	local_irq_save(flags);

	/* if hp_waiter can preempt 't', then 't' should be inheriting from hp_waiter */
	should_yield = (NULL != mutex->hp_waiter) &&
		(effective_priority(t) == effective_priority(mutex->hp_waiter));

	local_irq_restore(flags);

	return should_yield;
}

void prioq_mutex_propagate_increase_inheritance(struct litmus_lock* l,
											struct task_struct* t,
											raw_spinlock_t* to_unlock,
											unsigned long irqflags)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

	// relay-style locking
	lock_fine(&mutex->lock);
	unlock_fine(to_unlock);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	{
		int woke_up = __prioq_dgl_increase_pos(mutex, t);
		if (woke_up) {
			/* t got the DGL. it is not blocked anywhere. just return. */
			unlock_fine_irqrestore(&mutex->lock, irqflags);
			return;
		}
	}
#else
	__prioq_increase_pos(mutex, t);
#endif

	if(tsk_rt(t)->blocked_lock == l) {  // prevent race on tsk_rt(t)->blocked
		struct task_struct *owner = mutex->owner;

		struct task_struct *old_max_eff_prio;
		struct task_struct *new_max_eff_prio;

		if (!owner) {
			TRACE_TASK(t, "Owner on PRIOQ lock %d is null. Don't propagate.\n", l->ident);
			if(t == mutex->hp_waiter) {
				// reflect the changed prio.
				l->nest.hp_waiter_eff_prio = effective_priority(mutex->hp_waiter);
			}
			return;
		}

		raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

		old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

		if((t != mutex->hp_waiter) && litmus->compare(t, mutex->hp_waiter)) {
			TRACE_TASK(t, "is new highest-prio waiter by propagation.\n");
			mutex->hp_waiter = t;

			TRACE_TASK(t, "prioq_mutex %d state after prio increase in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);
		}
		else {
			TRACE_TASK(t, "prioq_mutex %d state after prio increase in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);
		}

		if(t == mutex->hp_waiter) {
			// reflect the increased priority in the heap node.
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
		struct litmus_lock *still_blocked;

		TRACE_TASK(t, "prioq_mutex %d state after prio increase in priority queue\n", l->ident);
		__dump_prioq_lock_info(mutex);

		still_blocked = tsk_rt(t)->blocked_lock;

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





inline static void __prioq_mutex_propagate_decrease_inheritance(
						struct litmus_lock* l,
						struct task_struct* t,
						unsigned long irqflags,
						int budget_triggered)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	__prioq_dgl_decrease_pos(mutex, t);
#else
	__prioq_decrease_pos(mutex, t);
#endif

	if(tsk_rt(t)->blocked_lock == l) {  // prevent race on tsk_rt(t)->blocked
		if(t == mutex->hp_waiter) {
			struct task_struct *owner = mutex->owner;

			struct task_struct *old_max_eff_prio;
			struct task_struct *new_max_eff_prio;

			if (!owner) {
				TRACE_TASK(t, "Owner on PRIOQ lock %d is null. Don't propagate.\n", l->ident);
				// reflect the changed prio.
				l->nest.hp_waiter_eff_prio = effective_priority(mutex->hp_waiter);
				return;
			}

			raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

			old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			binheap_delete(&l->nest.hp_binheap_node, &tsk_rt(owner)->hp_blocked_tasks);
			mutex->hp_waiter = __prioq_mutex_find_hp_waiter(mutex, NULL); /* update HP waiter */

			TRACE_TASK(t, "prioq_mutex %d state after prio decrease in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);

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

				TRACE_CUR("Propagating decreased inheritance to holder of lock %d.\n",
						  l->ident);

				if(litmus->__compare(new_max_eff_prio, BASE, owner, BASE)) {
					TRACE_CUR("%s/%d has greater base priority than base priority of owner (%s/%d) of lock %d.\n",
							  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
							  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
							  owner->comm,
							  owner->pid,
							  l->ident);

					decreased_prio = new_max_eff_prio;
				}
				else {
					TRACE_CUR("%s/%d has lesser base priority than base priority of owner (%s/%d) of lock %d.\n",
							  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
							  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
							  owner->comm,
							  owner->pid,
							  l->ident);

					decreased_prio = NULL;
				}

				// beware: recursion
				litmus->nested_decrease_prio(owner, decreased_prio, &mutex->lock, irqflags,
					budget_triggered); // will unlock mutex->lock
			}
			else {
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				unlock_fine_irqrestore(&mutex->lock, irqflags);
			}
		}
		else {
			TRACE_TASK(t, "prioq_mutex %d state after prio decrease in priority queue\n", l->ident);
			__dump_prioq_lock_info(mutex);

			TRACE_TASK(t, "is not hp_waiter.  No propagation.\n");
			unlock_fine_irqrestore(&mutex->lock, irqflags);
		}
	}
	else {
		struct litmus_lock *still_blocked;

		TRACE_TASK(t, "prioq_mutex %d state after prio decrease in priority queue\n", l->ident);
		__dump_prioq_lock_info(mutex);

		if (budget_triggered)
			WARN_ON(1);

		still_blocked = tsk_rt(t)->blocked_lock;

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
																   budget_triggered);
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

void prioq_mutex_propagate_decrease_inheritance(struct litmus_lock* l,
												struct task_struct* t,
												raw_spinlock_t* to_unlock,
												unsigned long irqflags,
												int budget_triggered)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);

	// relay-style locking
	lock_fine(&mutex->lock);
	unlock_fine(to_unlock);

	__prioq_mutex_propagate_decrease_inheritance(&mutex->litmus_lock, t,
												 irqflags, budget_triggered);
}

void prioq_mutex_budget_exhausted(struct litmus_lock* l, struct task_struct* t)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	unsigned long flags = 0;

	/* DGL lock must already be held on this code path if DGLs are enabled. */
	lock_fine_irqsave(&mutex->lock, flags);

	__prioq_mutex_propagate_decrease_inheritance(&mutex->litmus_lock, t, flags, 1);
}

int prioq_mutex_close(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct prioq_mutex *mutex = prioq_mutex_from_lock(l);
	unsigned long flags;

	int is_owner;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	lock_global_irqsave(dgl_lock, flags);
	lock_fine_irqsave(&mutex->lock, flags);

	is_owner = (mutex->owner == t);

	unlock_fine_irqrestore(&mutex->lock, flags);
	unlock_global_irqrestore(dgl_lock, flags);

	/*
	 TODO: Currently panic.  FIX THIS!
	if (is_owner)
		prioq_mutex_unlock(l);
	*/

	return 0;
}

void prioq_mutex_free(struct litmus_lock* lock)
{
	kfree(prioq_mutex_from_lock(lock));
}

#if 0
/* The following may race if DGLs are enabled.  Only examine /proc if things
   appear to be locked up.  TODO: FIX THIS! Must find an elegant way to transmit
   DGL lock to function. */
static int prioq_proc_print(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct prioq_mutex *mutex = prioq_mutex_from_lock((struct litmus_lock*)data);

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

				blocked_task = get_queued_task(q);
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

static void prioq_proc_add(struct litmus_lock* l)
{
	if (!l->name)
		l->name = kmalloc(LOCK_NAME_LEN*sizeof(char), GFP_KERNEL);
	snprintf(l->name, LOCK_NAME_LEN, "prioq-%d", l->ident);
	litmus_add_proc_lock(l, prioq_proc_print);
}

static void prioq_proc_remove(struct litmus_lock* l)
{
	if (l->name) {
		litmus_remove_proc_lock(l);

		kfree(l->name);
		l->name = NULL;
	}
}

static struct litmus_lock_proc_ops prioq_proc_ops =
{
	.add = prioq_proc_add,
	.remove = prioq_proc_remove
};
#endif

struct litmus_lock* prioq_mutex_new(struct litmus_lock_ops* ops)
{
	struct prioq_mutex* mutex;

	mutex = kmalloc(sizeof(*mutex), GFP_KERNEL);
	if (!mutex)
		return NULL;
	memset(mutex, 0, sizeof(*mutex));

	mutex->litmus_lock.ops = ops;
	mutex->owner   = NULL;
	mutex->hp_waiter = NULL;
	init_waitqueue_head(&mutex->wait);

	raw_spin_lock_init(&mutex->lock);
	LOCKDEP_DYNAMIC_ALLOC(mutex, &mutex->lock);

	((struct litmus_lock*)mutex)->nest.hp_waiter_ptr = &mutex->hp_waiter;
//	((struct litmus_lock*)mutex)->proc = &prioq_proc_ops;

	TRACE_CUR("Created new fifo mutex at %p\n", mutex);

	return &mutex->litmus_lock;
}

