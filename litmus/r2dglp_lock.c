#include <linux/slab.h>
#include <linux/uaccess.h>

#include <litmus/trace.h>
#include <litmus/sched_plugin.h>
#include <litmus/fdso.h>

#include <litmus/litmus_proc.h>

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#include <litmus/nvidia_info.h>
#endif

#include <litmus/r2dglp_lock.h>

#define R2DGLP_INVAL_DISTANCE 0x7FFFFFFF

int r2dglp_max_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	const r2dglp_heap_node_t *d_a = binheap_entry(a, r2dglp_heap_node_t, node);
	const r2dglp_heap_node_t *d_b = binheap_entry(b, r2dglp_heap_node_t, node);

	BUG_ON(!d_a);
	BUG_ON(!d_b);

	return litmus->__compare(d_a->task, BASE, d_b->task, BASE);
}

int r2dglp_min_heap_base_priority_order(const struct sbinheap_node *a,
				const struct sbinheap_node *b)
{
	const r2dglp_heap_node_t *d_a = binheap_entry(a, r2dglp_heap_node_t, node);
	const r2dglp_heap_node_t *d_b = binheap_entry(b, r2dglp_heap_node_t, node);

	return litmus->__compare(d_b->task, BASE, d_a->task, BASE);
}

int r2dglp_donor_max_heap_base_priority_order(const struct sbinheap_node *a,
				const struct sbinheap_node *b)
{
	const r2dglp_wait_state_t *d_a = binheap_entry(a, r2dglp_wait_state_t, node);
	const r2dglp_wait_state_t *d_b = binheap_entry(b, r2dglp_wait_state_t, node);

	return litmus->__compare(d_a->task, BASE, d_b->task, BASE);
}


int r2dglp_min_heap_donee_order(const struct sbinheap_node *a,
				const struct sbinheap_node *b)
{
	const struct task_struct *prio_a;
	const struct task_struct *prio_b;

	const r2dglp_donee_heap_node_t *d_a =
		binheap_entry(a, r2dglp_donee_heap_node_t, node);
	const r2dglp_donee_heap_node_t *d_b =
		binheap_entry(b, r2dglp_donee_heap_node_t, node);

	if(!d_a->donor_info) {
		prio_a = d_a->task;
	}
	else {
		prio_a = d_a->donor_info->task;
		BUG_ON(d_a->task != d_a->donor_info->donee_info->task);
	}

	if(!d_b->donor_info) {
		prio_b = d_b->task;
	}
	else {
		prio_b = d_b->donor_info->task;
		BUG_ON(d_b->task != d_b->donor_info->donee_info->task);
	}

	/* note reversed order of "b < a" and not "a < b" */
	return litmus->__compare(prio_b, BASE, prio_a, BASE);
}


static inline unsigned int nominal_fq_len(struct fifo_queue *fq)
{
	return (fq->count - fq->is_vunlocked);
}

static inline int r2dglp_get_idx(struct r2dglp_semaphore *sem,
				struct fifo_queue *queue)
{
	return (queue - &sem->fifo_queues[0]);
}

static inline struct fifo_queue* r2dglp_get_queue(struct r2dglp_semaphore *sem,
				struct task_struct *holder)
{
	struct fifo_queue *fq = NULL;
	int i;
	for(i = 0; i < sem->nr_replicas; ++i) {
		if(sem->fifo_queues[i].owner == holder) {
			fq = &sem->fifo_queues[i];
			break;
		}
	}

	return(fq);
}

static struct task_struct* r2dglp_find_hp_waiter(struct fifo_queue *kqueue,
				struct task_struct *skip)
{
	struct list_head *pos;
	struct task_struct *queued, *found = NULL;

	list_for_each(pos, &kqueue->wait.task_list) {
		queued  = (struct task_struct*) list_entry(pos, wait_queue_t, task_list)->private;

		/* Compare task prios, find high prio task. */
		if(queued != skip && litmus->compare(queued, found))
			found = queued;
	}
	return found;
}

static struct fifo_queue* r2dglp_find_shortest(struct r2dglp_semaphore *sem,
				struct fifo_queue *search_start)
{
	/* we start our search at search_start instead of at the beginning of the
	   queue list to load-balance across all resources. */
	struct fifo_queue* step = search_start;
	struct fifo_queue* shortest = sem->shortest_fifo_queue;

	do {
		step = (step+1 != &sem->fifo_queues[sem->nr_replicas]) ?
			step+1 : &sem->fifo_queues[0];

		/* consider actual lengths, not nominal lengths */
		if(step->count < shortest->count) {
			shortest = step;
			if(step->count == 0)
				break; /* can't get any shorter */
		}
	}while(step != search_start);

	return(shortest);
}

static inline struct task_struct* r2dglp_mth_highest(struct r2dglp_semaphore *sem)
{
	return sbinheap_top_entry(&sem->top_m, r2dglp_heap_node_t, node)->task;
}

static void r2dglp_add_global_list(struct r2dglp_semaphore *sem,
				struct task_struct *t,
				r2dglp_heap_node_t *node)
{
	node->task = t;
	INIT_SBINHEAP_NODE(&node->snode);
	INIT_BINHEAP_NODE(&node->dnode);

	if(sem->top_m.size < sem->top_m.max_size) {
		TRACE_CUR("Trivially adding %s/%d to top-m global list.\n",
				  t->comm, t->pid);
		sbinheap_add(&node->snode, &sem->top_m, r2dglp_heap_node_t, snode);
	}
	else if(litmus->__compare(t, BASE, r2dglp_mth_highest(sem), BASE)) {
		r2dglp_heap_node_t *evicted =
			sbinheap_top_entry(&sem->top_m, r2dglp_heap_node_t, snode);

		TRACE_CUR("Adding %s/%d to top-m and evicting %s/%d.\n",
				  t->comm, t->pid,
				  evicted->task->comm, evicted->task->pid);

		sbinheap_delete_root(&sem->top_m, r2dglp_heap_node_t, snode);
		INIT_SBINHEAP_NODE(&evicted->snode);

		binheap_add(&evicted->dnode, &sem->not_top_m, r2dglp_heap_node_t, dnode);
		sbinheap_add(&node->snode, &sem->top_m, r2dglp_heap_node_t, snode);
	}
	else {
		TRACE_CUR("Adding %s/%d to not-top-m global list.\n",
				  t->comm, t->pid);

		binheap_add(&node->dnode, &sem->not_top_m, r2dglp_heap_node_t, dnode);
	}
}


static void r2dglp_del_global_list(struct r2dglp_semaphore *sem,
				struct task_struct *t,
				r2dglp_heap_node_t *node)
{
	BUG_ON(!(sbinheap_is_in_heap(&node->snode) || binheap_is_in_heap(&node->dnode)));

	TRACE_CUR("Removing %s/%d from global list.\n", t->comm, t->pid);

	if(sbinheap_is_in_this_heap(&node->snode, &sem->top_m)) {
		TRACE_CUR("%s/%d is in top-m\n", t->comm, t->pid);

		sbinheap_delete(&node->snode, &sem->top_m);
		INIT_SBINHEAP_NODE(&node->snode);

		if(!binheap_empty(&sem->not_top_m)) {
			r2dglp_heap_node_t *promoted =
				binheap_top_entry(&sem->not_top_m, r2dglp_heap_node_t, dnode);
			TRACE_CUR("Promoting %s/%d to top-m\n",
					  promoted->task->comm, promoted->task->pid);

			binheap_delete_root(&sem->not_top_m, r2dglp_heap_node_t, dnode);
			INIT_BINHEAP_NODE(&promoted->dnode);

			sbinheap_add(&promoted->snode, &sem->top_m, r2dglp_heap_node_t, snode);
		}
		else {
			TRACE_CUR("No one to promote to top-m.\n");
		}
	}
	else {
		TRACE_CUR("%s/%d is in not-top-m\n", t->comm, t->pid);

		binheap_delete(&node->dnode, &sem->not_top_m);
		INIT_BINHEAP_NODE(&node->dnode);
	}
}

static int r2dglp_is_among_mth_highest(struct r2dglp_semaphore *sem,
				r2dglp_heap_node_t *node)
{
	BUG_ON(!(sbinheap_is_in_heap(&node->snode) || binheap_is_in_heap(&node->dnode)));
	if(sbinheap_is_in_this_heap(&node->snode, &sem->top_m)) {
		return 1;
	}
	return 0;
}

static void r2dglp_add_donees(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				struct task_struct *t,
				r2dglp_donee_heap_node_t* node)
{
	node->task = t;
	node->donor_info = NULL;
	node->fq = fq;
	INIT_SBINHEAP_NODE(&node->snode);

	sbinheap_add(&node->snode, &sem->donees, r2dglp_donee_heap_node_t, snode);
}


static void r2dglp_refresh_owners_prio_increase(struct task_struct *t,
				struct fifo_queue *fq,
				struct r2dglp_semaphore *sem,
				unsigned long flags)
{
	/* priority of 't' has increased (note: 't' might already be hp_waiter). */
	if ((t == fq->hp_waiter) || litmus->compare(t, fq->hp_waiter)) {
		struct task_struct *old_max_eff_prio;
		struct task_struct *new_max_eff_prio;
		struct task_struct *new_prio = NULL;
		struct task_struct *owner = fq->owner;

		if(fq->hp_waiter)
			TRACE_TASK(t, "has higher prio than hp_waiter (%s/%d).\n",
					   fq->hp_waiter->comm, fq->hp_waiter->pid);
		else
			TRACE_TASK(t, "has higher prio than hp_waiter (NIL).\n");

		if(owner)
		{
			raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

			if (unlikely(binheap_empty(&tsk_rt(owner)->hp_blocked_tasks))) {
				TRACE_TASK(owner, "not drawing inheritance from fq %d.\n",
								r2dglp_get_idx(sem, fq));
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				WARN_ON(1);
				return;
			}

			old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			fq->hp_waiter = t;
			fq->nest.hp_waiter_eff_prio = effective_priority(fq->hp_waiter);

			binheap_decrease(&fq->nest.hp_binheap_node,
				&tsk_rt(owner)->hp_blocked_tasks);
			new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

			if(new_max_eff_prio != old_max_eff_prio) {
				TRACE_TASK(t, "is new hp_waiter.\n");

				if ((effective_priority(owner) == old_max_eff_prio) ||
					(litmus->__compare(new_max_eff_prio, BASE,
									   owner, EFFECTIVE))){
					new_prio = new_max_eff_prio;
				}
			}
			else {
				TRACE_TASK(t, "no change in max_eff_prio of heap.\n");
			}

			if(new_prio) {
				/* set new inheritance and propagate */
				TRACE_TASK(t, "Effective priority changed for owner "
						   "%s/%d to %s/%d\n",
						   owner->comm, owner->pid,
						   new_prio->comm, new_prio->pid);
				litmus->nested_increase_prio(owner, new_prio, &sem->lock,
											 flags);  /* unlocks lock. */
			}
			else {
				TRACE_TASK(t, "No change in effective priority (is %s/%d).  "
                           "Propagation halted.\n",
						   new_max_eff_prio->comm, new_max_eff_prio->pid);
				raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
				unlock_fine_irqrestore(&sem->lock, flags);
			}
		}
		else {
			fq->hp_waiter = t;
			fq->nest.hp_waiter_eff_prio = effective_priority(fq->hp_waiter);

			TRACE_TASK(t, "no owner.\n");
			unlock_fine_irqrestore(&sem->lock, flags);
		}
	}
	else {
		TRACE_TASK(t, "hp_waiter is unaffected.\n");
		unlock_fine_irqrestore(&sem->lock, flags);
	}
}

/* hp_waiter has decreased */
static void r2dglp_refresh_owners_prio_decrease(struct fifo_queue *fq,
				struct r2dglp_semaphore *sem,
				unsigned long flags,
				int budget_triggered)
{
	struct task_struct *owner = fq->owner;

	struct task_struct *old_max_eff_prio;
	struct task_struct *new_max_eff_prio;

	if(!owner) {
		TRACE_CUR("No owner. Returning.\n");
		unlock_fine_irqrestore(&sem->lock, flags);
		return;
	}

	raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

	if (unlikely(binheap_empty(&tsk_rt(owner)->hp_blocked_tasks))) {
		TRACE_TASK(owner, "not drawing inheritance from fq %d.\n",
						r2dglp_get_idx(sem, fq));
		raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
		unlock_fine_irqrestore(&sem->lock, flags);
		WARN_ON(1);
		return;
	}

	old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

	binheap_delete(&fq->nest.hp_binheap_node, &tsk_rt(owner)->hp_blocked_tasks);
	fq->nest.hp_waiter_eff_prio =
			(fq->hp_waiter) ? effective_priority(fq->hp_waiter) : NULL;
	binheap_add(&fq->nest.hp_binheap_node, &tsk_rt(owner)->hp_blocked_tasks,
				struct nested_info, hp_binheap_node);

	new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

	if((old_max_eff_prio != new_max_eff_prio) &&
	   (effective_priority(owner) == old_max_eff_prio))
	{
		/* Need to set new effective_priority for owner */
		struct task_struct *decreased_prio;

		TRACE_CUR("Propagating decreased inheritance to holder of fq %d.\n",
				  r2dglp_get_idx(sem, fq));

		if(litmus->__compare(new_max_eff_prio, BASE, owner, BASE)) {
			TRACE_CUR("%s/%d has greater base priority than base priority "
					  "of owner (%s/%d) of fq %d.\n",
					  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
					  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
					  owner->comm,
					  owner->pid,
					  r2dglp_get_idx(sem, fq));

			decreased_prio = new_max_eff_prio;
		}
		else {
			TRACE_CUR("%s/%d has lesser base priority than base priority "
					  "of owner (%s/%d) of fq %d.\n",
					  (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
					  (new_max_eff_prio) ? new_max_eff_prio->pid : 0,
					  owner->comm,
					  owner->pid,
					  r2dglp_get_idx(sem, fq));

			decreased_prio = NULL;
		}

		/* beware: recursion */
		/* also, call will unlock mutex->lock */
		litmus->nested_decrease_prio(owner, decreased_prio, &sem->lock,
						flags, budget_triggered);
	}
	else {
		TRACE_TASK(owner, "No need to propagate priority decrease forward.\n");
		raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
		unlock_fine_irqrestore(&sem->lock, flags);
	}
}


static void r2dglp_remove_donation_from_owner(struct binheap_node *n,
				struct fifo_queue *fq,
				struct r2dglp_semaphore *sem,
				unsigned long flags)
{
	struct task_struct *owner = fq->owner;

	struct task_struct *old_max_eff_prio;
	struct task_struct *new_max_eff_prio;

	BUG_ON(!owner);
	BUG_ON(!binheap_is_in_heap(n));

	raw_spin_lock(&tsk_rt(owner)->hp_blocked_tasks_lock);

	old_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

	TRACE_CUR("Old effective priority: %s/%d\n",
		(old_max_eff_prio) ?
			old_max_eff_prio->comm : "null",
		(old_max_eff_prio) ?
			old_max_eff_prio->pid : 0);

	binheap_delete(n, &tsk_rt(owner)->hp_blocked_tasks);

	new_max_eff_prio = top_priority(&tsk_rt(owner)->hp_blocked_tasks);

	TRACE_CUR("New effective priority: %s/%d\n",
		(new_max_eff_prio) ?
			new_max_eff_prio->comm : "null",
		(new_max_eff_prio) ?
			new_max_eff_prio->pid : 0);

	if((old_max_eff_prio != new_max_eff_prio) &&
	   (effective_priority(owner) == old_max_eff_prio))
	{
		/* Need to set new effective_priority for owner */
		struct task_struct *decreased_prio;

		TRACE_CUR("Propagating decreased inheritance to holder of fq %d.\n",
				  r2dglp_get_idx(sem, fq));

		if(litmus->__compare(new_max_eff_prio, BASE, owner, BASE)) {
			TRACE_CUR("has greater base priority than base priority of owner "
					  "of fq %d.\n",
					  r2dglp_get_idx(sem, fq));
			decreased_prio = new_max_eff_prio;
		}
		else {
			TRACE_CUR("has lesser base priority than base priority of owner of "
					  "fq %d.\n",
					  r2dglp_get_idx(sem, fq));
			decreased_prio = NULL;
		}

		/* beware: recursion */
		/* also, call will unlock mutex->lock */
		litmus->nested_decrease_prio(owner, decreased_prio, &sem->lock,
						flags, 0);
	}
	else {
		TRACE_TASK(owner, "No need to propagate priority decrease forward.\n");
		raw_spin_unlock(&tsk_rt(owner)->hp_blocked_tasks_lock);
		unlock_fine_irqrestore(&sem->lock, flags);
	}
}

static void r2dglp_remove_donation_from_fq_waiter(struct task_struct *t,
				struct binheap_node *n)
{
	struct task_struct *old_max_eff_prio;
	struct task_struct *new_max_eff_prio;

	raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);

	TRACE_CUR("Removing donation from fq waiter %s/%d\n", t->comm, t->pid);

	old_max_eff_prio = top_priority(&tsk_rt(t)->hp_blocked_tasks);

	binheap_delete(n, &tsk_rt(t)->hp_blocked_tasks);

	new_max_eff_prio = top_priority(&tsk_rt(t)->hp_blocked_tasks);

	if((old_max_eff_prio != new_max_eff_prio) &&
	   (effective_priority(t) == old_max_eff_prio))
	{
		/* Need to set new effective_priority for owner */
		struct task_struct *decreased_prio;

		if(litmus->__compare(new_max_eff_prio, BASE, t, BASE)) {
			decreased_prio = new_max_eff_prio;
		}
		else {
			decreased_prio = NULL;
		}

        /* no need to propagate decreased inheritance to AUX
           or klmirqd tasks since they cannot (should not) inherit
           a priority directly from us while we suspend on a litmus
		   lock. */
		tsk_rt(t)->inh_task = decreased_prio;
	}

	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);
}

static void r2dglp_get_immediate(struct task_struct* t,
				struct fifo_queue *fq,
				struct r2dglp_semaphore *sem,
				unsigned long flags)
{
	/* resource available now */
	TRACE_CUR("queue %d: acquired immediately\n", r2dglp_get_idx(sem, fq));

	fq->owner = t;

	raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);
	binheap_add(&fq->nest.hp_binheap_node, &tsk_rt(t)->hp_blocked_tasks,
				struct nested_info, hp_binheap_node);
	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);

	++(fq->count);

	/* even though we got the replica, we're still considered in the fifo */
	++(sem->nr_in_fifos);

	r2dglp_add_global_list(sem, t, &fq->global_heap_node);
	r2dglp_add_donees(sem, fq, t, &fq->donee_heap_node);

	sem->shortest_fifo_queue =
			r2dglp_find_shortest(sem, sem->shortest_fifo_queue);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs) {
		sem->aff_obs->ops->notify_enqueue(sem->aff_obs, fq, t);
		sem->aff_obs->ops->notify_acquired(sem->aff_obs, fq, t);
	}
#endif

	unlock_fine_irqrestore(&sem->lock, flags);
}


static void __r2dglp_enqueue_on_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *wait,
				r2dglp_heap_node_t *global_heap_node,
				r2dglp_donee_heap_node_t *donee_heap_node)
{
	struct task_struct *t = wait->task;

	/* resource is not free => must suspend and wait */
	TRACE_TASK(t, "Enqueuing on fq %d.\n",
			   r2dglp_get_idx(sem, fq));

	init_waitqueue_entry(&wait->fq_node, t);

	__add_wait_queue_tail_exclusive(&fq->wait, &wait->fq_node);

	++(fq->count);
	++(sem->nr_in_fifos);

	/* update global list. */
	if(likely(global_heap_node)) {
		if(sbinheap_is_in_heap(&global_heap_node->snode) ||
		   binheap_is_in_heap(&global_heap_node->dnode)) {
			WARN_ON(1);
			r2dglp_del_global_list(sem, t, global_heap_node);
		}
		r2dglp_add_global_list(sem, t, global_heap_node);
	}
	// update donor eligiblity list.
	if(likely(donee_heap_node))
		r2dglp_add_donees(sem, fq, t, donee_heap_node);

	if(sem->shortest_fifo_queue == fq)
		sem->shortest_fifo_queue = r2dglp_find_shortest(sem, fq);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		sem->aff_obs->ops->notify_enqueue(sem->aff_obs, fq, t);
#endif

	wait->cur_q = R2DGLP_FQ;
	wait->fq = fq;
	mb();

	TRACE_TASK(t, "shortest queue is now %d\n", r2dglp_get_idx(sem, fq));
}


static void r2dglp_enqueue_on_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *wait,
				unsigned long flags)
{
	/* resource is not free => must suspend and wait */
	TRACE_TASK(wait->task, "queue %d: Resource is not free => must suspend "
			   "and wait.\n",
			   r2dglp_get_idx(sem, fq));

	INIT_SBINHEAP_NODE(&wait->global_heap_node.snode);
	INIT_BINHEAP_NODE(&wait->global_heap_node.dnode);
	INIT_SBINHEAP_NODE(&wait->donee_heap_node.snode);

	__r2dglp_enqueue_on_fq(sem, fq, wait,
					&wait->global_heap_node, &wait->donee_heap_node);

	/* call unlocks sem->lock */
	r2dglp_refresh_owners_prio_increase(wait->task, fq, sem, flags);
}


static void __r2dglp_enqueue_on_pq(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t *wait)
{
	TRACE_TASK(wait->task, "goes to PQ.\n");

	wait->pq_node.task = wait->task; /* copy over task (little redundant...) */

	r2dglp_add_global_list(sem, wait->task, &wait->global_heap_node);

	binheap_add(&wait->pq_node.dnode, &sem->priority_queue,
				r2dglp_heap_node_t, dnode);

	wait->cur_q = R2DGLP_PQ;
}

static void r2dglp_enqueue_on_pq(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t *wait)
{
	INIT_SBINHEAP_NODE(&wait->global_heap_node.snode);
	INIT_BINHEAP_NODE(&wait->global_heap_node.dnode);
	INIT_SBINHEAP_NODE(&wait->donee_heap_node.snode);
	INIT_BINHEAP_NODE(&wait->pq_node.dnode);

	__r2dglp_enqueue_on_pq(sem, wait);
}

static void r2dglp_enqueue_on_donor(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t* wait,
				unsigned long flags)
{
	struct task_struct *t = wait->task;
	r2dglp_donee_heap_node_t *donee_node = NULL;
	struct task_struct *donee;

	struct task_struct *old_max_eff_prio;
	struct task_struct *new_max_eff_prio;
	struct task_struct *new_prio = NULL;

	INIT_SBINHEAP_NODE(&wait->global_heap_node.snode);
	INIT_BINHEAP_NODE(&wait->global_heap_node.dnode);
	INIT_SBINHEAP_NODE(&wait->donee_heap_node.snode);
	INIT_BINHEAP_NODE(&wait->pq_node.dnode);
	INIT_SBINHEAP_NODE(&wait->snode);

	/* Add donor to the global list. */
	r2dglp_add_global_list(sem, t, &wait->global_heap_node);

	/* Select a donee */
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	donee_node = (sem->aff_obs) ?
		sem->aff_obs->ops->advise_donee_selection(sem->aff_obs, t) :
		sbinheap_top_entry(&sem->donees, r2dglp_donee_heap_node_t, snode);
#else
	donee_node = sbinheap_top_entry(&sem->donees, r2dglp_donee_heap_node_t, snode);
#endif

	donee = donee_node->task;

	TRACE_TASK(t, "Donee selected: %s/%d\n", donee->comm, donee->pid);

	TRACE_CUR("Temporarily removing %s/%d from donee list.\n",
			  donee->comm, donee->pid);

    /* Remove from donee list */
	sbinheap_delete(&donee_node->snode, &sem->donees);

	wait->donee_info = donee_node;

	/* Add t to donor heap. */
	sbinheap_add(&wait->snode, &sem->donors, r2dglp_wait_state_t, snode);

	/* Now adjust the donee's priority. */

	/* Lock the donee's inheritance heap. */
	raw_spin_lock(&tsk_rt(donee)->hp_blocked_tasks_lock);

	old_max_eff_prio = top_priority(&tsk_rt(donee)->hp_blocked_tasks);

	if(donee_node->donor_info) {
		/* Steal donation relation.  Evict old donor to PQ. */

		/* Remove old donor from donor heap */
		r2dglp_wait_state_t *old_wait = donee_node->donor_info;
		struct task_struct *old_donor = old_wait->task;

		TRACE_TASK(t, "Donee (%s/%d) had donor %s/%d. "
				   "Moving old donor to PQ.\n",
				   donee->comm, donee->pid, old_donor->comm, old_donor->pid);

		sbinheap_delete(&old_wait->snode, &sem->donors);

		/* Remove donation from donee's inheritance heap. */
		binheap_delete(&old_wait->prio_donation.hp_binheap_node,
					   &tsk_rt(donee)->hp_blocked_tasks);
		/* WARNING: have not updated inh_prio! */

		/* Remove old donor from the global heap. */
		r2dglp_del_global_list(sem, old_donor, &old_wait->global_heap_node);

		/* Add old donor to PQ. */
		__r2dglp_enqueue_on_pq(sem, old_wait);
	}

	/* Add back donee's node to the donees heap with increased prio */
    TRACE_CUR("Adding %s/%d back to donee list.\n", donee->comm, donee->pid);

	donee_node->donor_info = wait;
	INIT_SBINHEAP_NODE(&donee_node->snode);
	sbinheap_add(&donee_node->snode, &sem->donees, r2dglp_donee_heap_node_t, snode);

	/* Add an inheritance/donation to the donee's inheritance heap. */
	wait->prio_donation.lock = (struct litmus_lock*)sem;
	wait->prio_donation.hp_waiter_eff_prio = t;
	wait->prio_donation.hp_waiter_ptr = NULL;
	INIT_BINHEAP_NODE(&wait->prio_donation.hp_binheap_node);

	binheap_add(&wait->prio_donation.hp_binheap_node,
				&tsk_rt(donee)->hp_blocked_tasks,
				struct nested_info, hp_binheap_node);

	new_max_eff_prio = top_priority(&tsk_rt(donee)->hp_blocked_tasks);

	if(new_max_eff_prio != old_max_eff_prio) {
		if ((effective_priority(donee) == old_max_eff_prio) ||
			(litmus->__compare(new_max_eff_prio, BASE, donee, EFFECTIVE))){
			TRACE_TASK(t, "Donation increases %s/%d's effective priority\n",
					   donee->comm, donee->pid);
			new_prio = new_max_eff_prio;
		}
	}

	if(new_prio) {
		struct fifo_queue *donee_fq = donee_node->fq;

		if(donee != donee_fq->owner) {
			TRACE_TASK(t, "%s/%d is not the owner. "
                       "Propagating priority to owner %s/%d.\n",
					   donee->comm, donee->pid,
					   donee_fq->owner->comm, donee_fq->owner->pid);

			raw_spin_unlock(&tsk_rt(donee)->hp_blocked_tasks_lock);

            /* call unlocks sem->lock */
			r2dglp_refresh_owners_prio_increase(donee, donee_fq, sem, flags);
		}
		else {
			TRACE_TASK(t, "%s/%d is the owner. "
                       "Propagating priority immediatly.\n",
					   donee->comm, donee->pid);

            /* call unlocks sem->lock and donee's heap lock */
			litmus->nested_increase_prio(donee, new_prio, &sem->lock, flags);
		}
	}
	else {
		TRACE_TASK(t, "No change in effective priority (it is %s/%d).\n",
				   (new_max_eff_prio) ? new_max_eff_prio->comm : "null",
				   (new_max_eff_prio) ? new_max_eff_prio->pid : 0);
		raw_spin_unlock(&tsk_rt(donee)->hp_blocked_tasks_lock);
		unlock_fine_irqrestore(&sem->lock, flags);
	}

	wait->cur_q = R2DGLP_DONOR;
}


int r2dglp_lock(struct litmus_lock* l)
{
	struct task_struct* t = current;
	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);
	unsigned long flags = 0, more_flags;
	struct fifo_queue *fq = NULL;
	int replica = -EINVAL;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock;
#endif

	r2dglp_wait_state_t wait;

	if (!is_realtime(t))
		return -EPERM;

	memset(&wait, 0, sizeof(wait));

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	lock_global_irqsave(dgl_lock, flags);
	raw_spin_lock_irqsave(&sem->real_lock, more_flags);
	lock_fine_irqsave(&sem->lock, flags);

	TRACE_CUR("Requesting a replica from lock %d.\n", l->ident);

	if(sem->nr_in_fifos < sem->max_in_fifos) {
		/* enqueue somwhere */
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		fq = (sem->aff_obs) ?
			sem->aff_obs->ops->advise_enqueue(sem->aff_obs, t) :
			sem->shortest_fifo_queue;
#else
		fq = sem->shortest_fifo_queue;
#endif
		if(fq->count == 0) {
			/* take available resource */
			replica = r2dglp_get_idx(sem, fq);

			TRACE_CUR("Getting replica %d\n", replica);

			r2dglp_get_immediate(t, fq, sem, flags);  /* unlocks sem->lock */

			raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
			unlock_global_irqrestore(dgl_lock, flags);
			goto acquired;
		}
		else {
			TRACE_CUR("Will go on FQ somewhere.\n");

			wait.task = t;   /* THIS IS CRITICALLY IMPORTANT!!! */

            /* record where we are blocked */
			tsk_rt(t)->blocked_lock = (struct litmus_lock*)sem;
			mb();

			set_task_state(t, TASK_UNINTERRUPTIBLE);

			r2dglp_enqueue_on_fq(sem, fq, &wait, flags);  /* unlocks sem->lock */
		}
	}
	else {
		TRACE_CUR("Going on a heap.\n");

		wait.task = t;   /* THIS IS CRITICALLY IMPORTANT!!! */

        /* record where we are blocked */
		tsk_rt(t)->blocked_lock = (struct litmus_lock*)sem;
		mb();

		/* FIXME: interruptible would be nice some day */
		set_task_state(t, TASK_UNINTERRUPTIBLE);

		if(litmus->__compare(r2dglp_mth_highest(sem), BASE, t, BASE)) {
			TRACE_CUR("Going on PQ heap.\n");
			/* enqueue on PQ */
			r2dglp_enqueue_on_pq(sem, &wait);
			unlock_fine_irqrestore(&sem->lock, flags);
		}
		else {
			/* enqueue as donor */
			TRACE_CUR("Going on donor heap.\n");
			r2dglp_enqueue_on_donor(sem, &wait, flags);	 /* unlocks sem->lock */
		}
	}

	tsk_rt(t)->blocked_lock_data = (unsigned long)&wait;

	flush_pending_wakes();

	raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
	unlock_global_irqrestore(dgl_lock, flags);

	TRACE_CUR("Suspending for replica.\n");

	TS_LOCK_SUSPEND;

	suspend_for_lock();

	TS_LOCK_RESUME;

	fq = wait.fq;

	tsk_rt(t)->blocked_lock_data = 0;

	replica = r2dglp_get_idx(sem, fq);

acquired:
	TRACE_CUR("Acquired lock %d, queue %d\n", l->ident, replica);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		return sem->aff_obs->ops->replica_to_resource(sem->aff_obs, fq);
#endif

	return replica;
}

static void __drop_from_donor(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t *wait)
{
	BUG_ON(wait->cur_q != R2DGLP_DONOR);

	TRACE_TASK(wait->task, "is being dropped from donor heap.\n");

	sbinheap_delete(&wait->snode, &sem->donors);
	wait->cur_q = R2DGLP_INVL;
}

static void r2dglp_move_donor_to_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *donor_info)
{
#ifdef CONFIG_SCHED_DEBUG_TRACE
	struct task_struct *t = donor_info->task;
	TRACE_CUR("Donor %s/%d being moved to fq %d\n",
			  t->comm,
			  t->pid,
			  r2dglp_get_idx(sem, fq));
#endif

	__drop_from_donor(sem, donor_info);

    /* Already in global_list, so pass null to prevent adding 2nd time. */
	__r2dglp_enqueue_on_fq(sem, fq, donor_info,
						  NULL, /* pass NULL */
						  &donor_info->donee_heap_node);

    /* Note: r2dglp_update_owners_prio() still needs to be called. */
}

static void __drop_from_pq(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t *wait)
{
	BUG_ON(wait->cur_q != R2DGLP_PQ);

	TRACE_TASK(wait->task, "is being dropped from the PQ.\n");

	binheap_delete(&wait->pq_node.dnode, &sem->priority_queue);
	wait->cur_q = R2DGLP_INVL;
}

static void r2dglp_move_pq_to_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *wait)
{
#ifdef CONFIG_SCHED_DEBUG_TRACE
	struct task_struct *t = wait->task;
	TRACE_CUR("PQ request %s/%d being moved to fq %d\n",
			  t->comm,
			  t->pid,
			  r2dglp_get_idx(sem, fq));
#endif

	r2dglp_del_global_list(sem, t, &wait->global_heap_node);
	__drop_from_pq(sem, wait);
	__r2dglp_enqueue_on_fq(sem, fq, wait,
						  &wait->global_heap_node,
						  &wait->donee_heap_node);

    /* Note: r2dglp_update_owners_prio() still needs to be called. */
}

static r2dglp_wait_state_t* r2dglp_find_hp_waiter_to_steal(
	struct r2dglp_semaphore* sem,
	struct fifo_queue* skip)
{
	/* must hold sem->lock */

	struct fifo_queue *fq = NULL;
	struct list_head	*pos;
	struct task_struct 	*queued;
	int i;

	for(i = 0; i < sem->nr_replicas; ++i) {
		if( (sem->fifo_queues[i].count > 1) && (&sem->fifo_queues[i] != skip) &&
		   (!fq || litmus->compare(sem->fifo_queues[i].hp_waiter, fq->hp_waiter)) ) {

			TRACE_CUR("hp_waiter on fq %d (%s/%d) has higher prio than "
                      "hp_waiter on fq %d (%s/%d)\n",
					  r2dglp_get_idx(sem, &sem->fifo_queues[i]),
					  sem->fifo_queues[i].hp_waiter->comm,
					  sem->fifo_queues[i].hp_waiter->pid,
					  (fq) ? r2dglp_get_idx(sem, fq) : 0,
					  (fq) ? ((fq->hp_waiter) ? fq->hp_waiter->comm : "null") : "nullXX",
					  (fq) ? ((fq->hp_waiter) ? fq->hp_waiter->pid : 0) : -2);

			fq = &sem->fifo_queues[i];

			WARN_ON(!(fq->hp_waiter));
		}
	}

	if(fq) {
		struct task_struct *max_hp = fq->hp_waiter;
		r2dglp_wait_state_t* ret = NULL;

		TRACE_CUR("Searching for %s/%d on fq %d\n",
				  max_hp->comm,
				  max_hp->pid,
				  r2dglp_get_idx(sem, fq));

		BUG_ON(!max_hp);

		list_for_each(pos, &fq->wait.task_list) {
			wait_queue_t *wait = list_entry(pos, wait_queue_t, task_list);

			queued  = (struct task_struct*) wait->private;

			TRACE_CUR("fq %d entry: %s/%d\n",
					  r2dglp_get_idx(sem, fq),
					  queued->comm,
					  queued->pid);

			/* Compare task prios, find high prio task. */
			if (queued == max_hp) {
				TRACE_CUR("Found it!\n");
				ret = container_of(wait, r2dglp_wait_state_t, fq_node);
			}
		}

		WARN_ON(!ret);
		return ret;
	}

	return(NULL);
}

static void __drop_from_fq(struct r2dglp_semaphore *sem,
				r2dglp_wait_state_t *wait)
{
	struct task_struct *t = wait->task;
	struct fifo_queue *fq = wait->fq;

	BUG_ON(wait->cur_q != R2DGLP_FQ);
	BUG_ON(!fq);

	TRACE_TASK(t, "is being dropped from fq.\n");

	__remove_wait_queue(&fq->wait, &wait->fq_node);
	--(fq->count);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		sem->aff_obs->ops->notify_dequeue(sem->aff_obs, fq, t);
#endif

	if(t == fq->hp_waiter) {
		fq->hp_waiter = r2dglp_find_hp_waiter(fq, NULL);
		TRACE_TASK(t, "New hp_waiter for fq %d is %s/%d!\n",
				   r2dglp_get_idx(sem, fq),
				   (fq->hp_waiter) ? fq->hp_waiter->comm : "null",
				   (fq->hp_waiter) ? fq->hp_waiter->pid : 0);
	}

	/* Update shortest. */
	if(fq->count < sem->shortest_fifo_queue->count)
		sem->shortest_fifo_queue = fq;
	--(sem->nr_in_fifos);

	wait->cur_q = R2DGLP_INVL;
}

static void r2dglp_steal_to_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *fq_wait)
{
	WARN_ON(fq_wait->fq != fq_wait->donee_heap_node.fq);
	__drop_from_fq(sem, fq_wait);

	fq_wait->donee_heap_node.fq = fq;  // just to be safe
	__r2dglp_enqueue_on_fq(sem, fq, fq_wait, NULL, NULL);

	/* Note: We have not checked the priority inheritance of fq's owner yet. */
}


static void r2dglp_migrate_fq_to_owner_heap_nodes(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				r2dglp_wait_state_t *old_wait)
{
	struct task_struct *t = old_wait->task;

	BUG_ON(old_wait->donee_heap_node.fq != fq);

	TRACE_TASK(t, "Migrating wait_state to memory of queue %d.\n",
			   r2dglp_get_idx(sem, fq));

    /* Need to migrate global_heap_node and donee_heap_node off of the stack
	   to the nodes allocated for the owner of this fq. */

	/* TODO: Enhance binheap() to perform this operation in place. */

	r2dglp_del_global_list(sem, t, &old_wait->global_heap_node); /* remove */
	fq->global_heap_node = old_wait->global_heap_node;			/* copy */
	r2dglp_add_global_list(sem, t, &fq->global_heap_node);		/* re-add */

	sbinheap_delete(&old_wait->donee_heap_node.snode, &sem->donees);  /* remove */
	fq->donee_heap_node = old_wait->donee_heap_node;  /* copy */

	if(fq->donee_heap_node.donor_info) {
		/* let donor know that our location has changed */

        /* validate cross-link */
		BUG_ON(fq->donee_heap_node.donor_info->donee_info->task != t);

		fq->donee_heap_node.donor_info->donee_info = &fq->donee_heap_node;
	}
	INIT_SBINHEAP_NODE(&fq->donee_heap_node.snode);
	sbinheap_add(&fq->donee_heap_node.snode, &sem->donees,
				r2dglp_donee_heap_node_t, snode);  /* re-add */
}



void r2dglp_grant_replica_to_next(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq)
{
	wait_queue_t *wait;
	r2dglp_wait_state_t *fq_wait;
	struct task_struct *next;

	BUG_ON(!waitqueue_active(&fq->wait));

	wait = list_entry(fq->wait.task_list.next, wait_queue_t, task_list);
	fq_wait = container_of(wait, r2dglp_wait_state_t, fq_node);
	next = (struct task_struct*) wait->private;

	__remove_wait_queue(&fq->wait, wait);

	TRACE_CUR("queue %d: ASSIGNING %s/%d as owner - next\n",
			  r2dglp_get_idx(sem, fq),
			  next->comm, next->pid);

	/* migrate wait-state to fifo-memory. */
	r2dglp_migrate_fq_to_owner_heap_nodes(sem, fq, fq_wait);

	/* next becomes the resouce holder */
	fq->owner = next;
	tsk_rt(next)->blocked_lock = NULL;

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		sem->aff_obs->ops->notify_acquired(sem->aff_obs, fq, next);
#endif

	/* determine new hp_waiter if necessary */
	if (next == fq->hp_waiter) {
		TRACE_TASK(next, "was highest-prio waiter\n");
		/* next has the highest priority --- it doesn't need to
		 * inherit.  However, we need to make sure that the
		 * next-highest priority in the queue is reflected in
		 * hp_waiter. */
		fq->hp_waiter = r2dglp_find_hp_waiter(fq, NULL);
		TRACE_TASK(next, "New hp_waiter for fq %d is %s/%d!\n",
				   r2dglp_get_idx(sem, fq),
				   (fq->hp_waiter) ? fq->hp_waiter->comm : "null",
				   (fq->hp_waiter) ? fq->hp_waiter->pid : 0);

		fq->nest.hp_waiter_eff_prio = (fq->hp_waiter) ?
		effective_priority(fq->hp_waiter) : NULL;

		if (fq->hp_waiter)
			TRACE_TASK(fq->hp_waiter, "is new highest-prio waiter\n");
		else
			TRACE("no further waiters\n");

		raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);
		binheap_add(&fq->nest.hp_binheap_node,
					&tsk_rt(next)->hp_blocked_tasks,
					struct nested_info,
					hp_binheap_node);
		raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
	}
	else {
		/* Well, if 'next' is not the highest-priority waiter,
		 * then it (probably) ought to inherit the highest-priority
		 * waiter's priority. */
		TRACE_TASK(next, "is not hp_waiter of replica %d. hp_waiter is %s/%d\n",
				   r2dglp_get_idx(sem, fq),
				   (fq->hp_waiter) ? fq->hp_waiter->comm : "null",
				   (fq->hp_waiter) ? fq->hp_waiter->pid : 0);

		raw_spin_lock(&tsk_rt(next)->hp_blocked_tasks_lock);

		binheap_add(&fq->nest.hp_binheap_node,
					&tsk_rt(next)->hp_blocked_tasks,
					struct nested_info,
					hp_binheap_node);

		/* It is possible that 'next' *should* be the hp_waiter, but isn't
		 * because that update hasn't yet executed (update operation is
		 * probably blocked on mutex->lock). So only inherit if the top of
		 * 'next's top heap node is indeed the effective prio. of hp_waiter.
		 * (We use fq->hp_waiter_eff_prio instead of
		 * effective_priority(hp_waiter) since the effective priority of
		 * hp_waiter can change (and the update has not made it to this lock).)
		 */
		if(likely(top_priority(&tsk_rt(next)->hp_blocked_tasks) ==
				  fq->nest.hp_waiter_eff_prio))
		{
			if(fq->nest.hp_waiter_eff_prio)
				litmus->increase_prio(next, fq->nest.hp_waiter_eff_prio);
			else
				WARN_ON(1);
		}

		raw_spin_unlock(&tsk_rt(next)->hp_blocked_tasks_lock);
	}

	/* wake up the new resource holder! */
	wake_up_for_lock(next);
}


/* some compile-time configuration options for testing */
#define ALLOW_STEALING				1
#define ALWAYS_TERMINATE_DONATION	1

void r2dglp_move_next_to_fq(struct r2dglp_semaphore *sem,
				struct fifo_queue *fq,
				struct task_struct *t,
				r2dglp_donee_heap_node_t *donee_node,
				unsigned long *flags,
				int allow_stealing,
				int always_terminate_donation)
{
	struct task_struct *donee = NULL;
	struct task_struct *new_on_fq = NULL;
	struct fifo_queue *fq_of_new_on_fq = NULL;

	r2dglp_wait_state_t *other_donor_info = NULL;
	struct fifo_queue *to_steal = NULL;
	int need_steal_prio_reeval = 0;

	if (donee_node->donor_info) {
		r2dglp_wait_state_t *donor_info = donee_node->donor_info;

		new_on_fq = donor_info->task;

		/* donor moved to FQ */
		donee = t;

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs) {
			fq_of_new_on_fq =
					sem->aff_obs->ops->advise_enqueue(sem->aff_obs, new_on_fq);
			if((nominal_fq_len(fq_of_new_on_fq) >= sem->max_fifo_len) &&
               !sem->aff_obs->relax_max_fifo_len) {
				WARN_ON(1);
				fq_of_new_on_fq = fq;
			}
		}
		else {
			fq_of_new_on_fq = fq;
        }
#else
		fq_of_new_on_fq = fq;
#endif

		TRACE_TASK(t, "Moving MY donor (%s/%d) to fq %d "
				   "(non-aff wanted fq %d).\n",
				   new_on_fq->comm, new_on_fq->pid,
				   r2dglp_get_idx(sem, fq_of_new_on_fq),
				   r2dglp_get_idx(sem, fq));

		r2dglp_move_donor_to_fq(sem, fq_of_new_on_fq, donor_info);

		/* treat donor as if it had donated to a task other than 't'.
		 * this triggers the termination of the donation relationship. */
		if (always_terminate_donation) {
			other_donor_info = donor_info;
		}
	}
	/* We can move someone else's donor to FQ.
	   2015 Thinking:
	     We can only do this if there isn't a waiting task in
	     PQ that is among the top-m requests. (If there is such
	     a task in PQ, then there is only one, and it is
	     at the head).
	   2012/2013 Thinking:
	     We don't have to worry about PQ. The priority of such a job
		 ensures that it is never among the top-m.
		 ** We have forgotten the proof behind this reasoning! However,
		    experimentation hasn't disproven this case yet. **
	   Let's go with 2015 reasoning---it's the more conservative choice.
	 */
	else if(!sbinheap_empty(&sem->donors) &&
	        (binheap_empty(&sem->priority_queue) ||
	         !r2dglp_is_among_mth_highest(sem,
			      binheap_top_entry(&sem->priority_queue,
				      r2dglp_heap_node_t, node))))
	{
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		other_donor_info = (sem->aff_obs) ?
			sem->aff_obs->ops->advise_donor_to_fq(sem->aff_obs, fq) :
			sbinheap_top_entry(&sem->donors, r2dglp_wait_state_t, snode);
#else
		other_donor_info =
			sbinheap_top_entry(&sem->donors, r2dglp_wait_state_t, snode);
#endif

		new_on_fq = other_donor_info->task;
		donee = other_donor_info->donee_info->task;

		/* update the donee's heap position. */
		other_donor_info->donee_info->donor_info = NULL; /* clear cross-link */
		sbinheap_decrease(&other_donor_info->donee_info->snode, &sem->donees);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs) {
			fq_of_new_on_fq =
					sem->aff_obs->ops->advise_enqueue(sem->aff_obs, new_on_fq);
			if((nominal_fq_len(fq_of_new_on_fq) >= sem->max_fifo_len) &&
               !sem->aff_obs->relax_max_fifo_len) {
				WARN_ON(1);
				fq_of_new_on_fq = fq;
			}
		}
		else {
			fq_of_new_on_fq = fq;
        }
#else
		fq_of_new_on_fq = fq;
#endif

		TRACE_TASK(t, "Moving a donor (%s/%d) to fq %d "
				   "(non-aff wanted fq %d).\n",
				   new_on_fq->comm, new_on_fq->pid,
				   r2dglp_get_idx(sem, fq_of_new_on_fq),
				   r2dglp_get_idx(sem, fq));

		r2dglp_move_donor_to_fq(sem, fq_of_new_on_fq, other_donor_info);
	}
	/* No eligible donors, so move PQ */
	else if(!binheap_empty(&sem->priority_queue)) {
		r2dglp_heap_node_t *pq_node = binheap_top_entry(&sem->priority_queue,
						r2dglp_heap_node_t, node);
		r2dglp_wait_state_t *pq_wait = container_of(pq_node, r2dglp_wait_state_t,
						pq_node);

		new_on_fq = pq_wait->task;

#ifdef CONFIG_SCHED_DEBUG_TRACE
		if(!sbinheap_empty(&sem->donors)) {
			/* This never seems to fire. In 2012/2013, we thought that it
			   would be impossible for this to fire. However, we've forgotten
			   that reasoning... perhaps we were right. */
			TRACE_TASK(t, "Moving a pq waiter over a donor.");
		}
#endif

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs) {
			fq_of_new_on_fq =
					sem->aff_obs->ops->advise_enqueue(sem->aff_obs, new_on_fq);
			if((nominal_fq_len(fq_of_new_on_fq) >= sem->max_fifo_len) &&
							!sem->aff_obs->relax_max_fifo_len) {
				WARN_ON(1);
				fq_of_new_on_fq = fq;
			}
		}
		else {
			fq_of_new_on_fq = fq;
        }
#else
		fq_of_new_on_fq = fq;
#endif

		TRACE_TASK(t, "Moving a pq waiter (%s/%d) to fq %d "
				   "(non-aff wanted fq %d).\n",
				   new_on_fq->comm, new_on_fq->pid,
				   r2dglp_get_idx(sem, fq_of_new_on_fq),
				   r2dglp_get_idx(sem, fq));

		r2dglp_move_pq_to_fq(sem, fq_of_new_on_fq, pq_wait);
	}
	/* No PQ and this queue is empty, so steal. */
	else if(allow_stealing && fq->count == 0) {
		r2dglp_wait_state_t *fq_wait;

		TRACE_TASK(t, "Looking to steal a request for fq %d...\n",
				   r2dglp_get_idx(sem, fq));

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		fq_wait = (sem->aff_obs) ?
			sem->aff_obs->ops->advise_steal(sem->aff_obs, fq) :
			r2dglp_find_hp_waiter_to_steal(sem, fq);
#else
		fq_wait = r2dglp_find_hp_waiter_to_steal(sem, fq);
#endif

		if(fq_wait) {
			to_steal = fq_wait->donee_heap_node.fq;

			new_on_fq = fq_wait->task;
			fq_of_new_on_fq = fq;
			need_steal_prio_reeval = (new_on_fq == to_steal->hp_waiter);

			TRACE_TASK(t, "Found %s/%d of fq %d to steal for fq %d...\n",
					   new_on_fq->comm, new_on_fq->pid,
					   r2dglp_get_idx(sem, to_steal),
					   r2dglp_get_idx(sem, fq));

			r2dglp_steal_to_fq(sem, fq, fq_wait);
		}
		else {
			TRACE_TASK(t, "Found nothing to steal for fq %d.\n",
					   r2dglp_get_idx(sem, fq));
		}
	}
	else {
		/* move no one */
	}


    /* Now patch up other priorities.

       At most one of the following:
          if(donee && donee != t), decrease prio, propagate to owner, or onward
          if(to_steal), update owner's prio (hp_waiter has already been set) */

	BUG_ON(other_donor_info && to_steal);

	if(other_donor_info) {
		struct fifo_queue *other_fq = other_donor_info->donee_info->fq;

		BUG_ON(!donee);
		BUG_ON(!always_terminate_donation && donee == t);

		TRACE_TASK(t, "Terminating donation relation of "
				   "donor %s/%d to donee %s/%d!\n",
				   other_donor_info->task->comm, other_donor_info->task->pid,
				   donee->comm, donee->pid);

		/* need to terminate donation relation. */
		if(donee == other_fq->owner) {
			TRACE_TASK(t, "Donee %s/%d is an owner of fq %d.\n",
					   donee->comm, donee->pid,
					   r2dglp_get_idx(sem, other_fq));

			r2dglp_remove_donation_from_owner(
				&other_donor_info->prio_donation.hp_binheap_node,
				other_fq, sem, *flags);

            /* there should be no contention!!!! */
			lock_fine_irqsave(&sem->lock, *flags);
		}
		else {
			TRACE_TASK(t, "Donee %s/%d is blocked in of fq %d.\n",
					   donee->comm, donee->pid,
					   r2dglp_get_idx(sem, other_fq));

			r2dglp_remove_donation_from_fq_waiter(donee,
				&other_donor_info->prio_donation.hp_binheap_node);
			if(donee == other_fq->hp_waiter) {
				TRACE_TASK(t, "Donee %s/%d was an hp_waiter of fq %d. "
                           "Rechecking hp_waiter.\n",
						   donee->comm, donee->pid,
						   r2dglp_get_idx(sem, other_fq));

				other_fq->hp_waiter = r2dglp_find_hp_waiter(other_fq, NULL);
				TRACE_TASK(t, "New hp_waiter for fq %d is %s/%d!\n",
						   r2dglp_get_idx(sem, other_fq),
						   (other_fq->hp_waiter) ? other_fq->hp_waiter->comm : "null",
						   (other_fq->hp_waiter) ? other_fq->hp_waiter->pid : 0);

                /* unlocks sem->lock. reacquire it. */
				r2dglp_refresh_owners_prio_decrease(other_fq, sem, *flags, 0);
                /* there should be no contention!!!! */
				lock_fine_irqsave(&sem->lock, *flags);
			}
		}
	}
	else if(to_steal) {
		TRACE_TASK(t, "Rechecking priority inheritance of fq %d, "
                   "triggered by stealing.\n",
				   r2dglp_get_idx(sem, to_steal));

		if(need_steal_prio_reeval) {
            /* unlocks sem->lock. reacquire it. */
			r2dglp_refresh_owners_prio_decrease(to_steal, sem, *flags, 0);
            /* there should be no contention!!!! */
			lock_fine_irqsave(&sem->lock, *flags);
		}
	}

	/* check for new HP waiter. */
	if(new_on_fq) {
        /* unlocks sem->lock. reacquire it. */
		r2dglp_refresh_owners_prio_increase(new_on_fq, fq_of_new_on_fq,
						sem, *flags);
        /* there should be no contention!!!! */
		lock_fine_irqsave(&sem->lock, *flags);
	}

	/* we moved a request to an empty FQ. wake it up */
	if(unlikely(fq_of_new_on_fq &&
				fq_of_new_on_fq != fq &&
				fq_of_new_on_fq->count == 1)) {
		r2dglp_grant_replica_to_next(sem, fq_of_new_on_fq);
	}
}

int r2dglp_unlock(struct litmus_lock* l)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);
	struct task_struct *t = current;
	struct fifo_queue *fq;

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock;
#endif

	unsigned long flags = 0, more_flags;

	int err = 0;

	fq = r2dglp_get_queue(sem, t);  /* returns NULL if 't' is not owner. */

	if (!fq) {
		TRACE_TASK(t, "does not hold a replica of lock %d\n", l->ident);
		err = -EINVAL;
		goto out;
	}

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	dgl_lock = litmus->get_dgl_spinlock(t);
#endif
	lock_global_irqsave(dgl_lock, flags);
	raw_spin_lock_irqsave(&sem->real_lock, more_flags);
	lock_fine_irqsave(&sem->lock, flags);

	TRACE_TASK(t, "Freeing replica %d.\n", r2dglp_get_idx(sem, fq));

	/* Remove 't' from the heaps, but data in nodes will still be good. */
	if(likely(!fq->is_vunlocked)) {
		r2dglp_del_global_list(sem, t, &fq->global_heap_node);
		sbinheap_delete(&fq->donee_heap_node.snode, &sem->donees);
	}

	fq->owner = NULL;  /* no longer owned!! */
	--(fq->count);
	if(fq->count < sem->shortest_fifo_queue->count) {
		sem->shortest_fifo_queue = fq;
	}

	if (likely(!fq->is_vunlocked))
		--(sem->nr_in_fifos);
	else
		TRACE_TASK(t, "virtually unlocked. handing off replica only.\n");

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs) {
		sem->aff_obs->ops->notify_dequeue(sem->aff_obs, fq, t);
		sem->aff_obs->ops->notify_freed(sem->aff_obs, fq, t);
	}
#endif

	/* 't' must drop all priority and clean up data structures before hand-off.

	   DROP ALL INHERITANCE.  R2DGLP MUST BE OUTER-MOST
	   This kills any inheritance from a donor.
     */
	raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);
	{
		int count = 0;
		TRACE_TASK(t, "discarding inheritance because R2DGLP is outermost\n");
		while (!binheap_empty(&tsk_rt(t)->hp_blocked_tasks)) {
			binheap_delete_root(&tsk_rt(t)->hp_blocked_tasks,
				struct nested_info, hp_binheap_node);
			++count;
		}

		if (count)
			litmus->decrease_prio(t, NULL, 0);
	}
	raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);

	if (likely(!fq->is_vunlocked)) {
		/* Move the next request into the FQ and update heaps as needed.
		   Skip this step we if already did this during the virtual unlock. */
		r2dglp_move_next_to_fq(sem, fq, t, &fq->donee_heap_node, &flags,
						ALLOW_STEALING, !ALWAYS_TERMINATE_DONATION);
	}
	else {
        /* reset vunlock flag */
		fq->is_vunlocked = 0;
    }

	if (waitqueue_active(&fq->wait))
		r2dglp_grant_replica_to_next(sem, fq);

	unlock_fine_irqrestore(&sem->lock, flags);
	raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
	unlock_global_irqrestore(dgl_lock, flags);

	TRACE_CUR("done with freeing replica.\n");

out:
	return err;
}



void r2dglp_abort_request(struct r2dglp_semaphore *sem, struct task_struct *t,
				unsigned long flags)
{
	r2dglp_wait_state_t *wait =
			(r2dglp_wait_state_t*)tsk_rt(t)->blocked_lock_data;
	r2dglp_donee_heap_node_t	*donee_info;
	struct task_struct	*donee;
	struct fifo_queue	*donee_fq;
	struct fifo_queue	*fq = wait->fq;

	BUG_ON(!wait);

	/* drop the request from the proper R2DGLP data structure and re-eval
	 * priority relations */
	switch(wait->cur_q)
	{
		case R2DGLP_PQ:
			TRACE_TASK(t, "Aborting request while on PQ.\n");
			r2dglp_del_global_list(sem, t, &wait->global_heap_node);
			/* No one inherits from waiters in PQ. Just drop the request. */
			__drop_from_pq(sem, wait);
			break;


		case R2DGLP_FQ:
			TRACE_TASK(t, "Aborting request while on FQ.\n");
			r2dglp_del_global_list(sem, t, &wait->global_heap_node);
			sbinheap_delete(&wait->donee_heap_node.snode, &sem->donees);

			/* remove the task from the FQ */
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
			if(sem->aff_obs)
				sem->aff_obs->ops->notify_dequeue(sem->aff_obs, fq, t);
#endif
			__drop_from_fq(sem, wait);

			/* Drop any and all inheritance t receives. */
			raw_spin_lock(&tsk_rt(t)->hp_blocked_tasks_lock);
			{
				int count = 0;
				TRACE_TASK(t, "discarding inheritance because R2DGLP "
							  "is outermost\n");
				while (!binheap_empty(&tsk_rt(t)->hp_blocked_tasks)) {
					binheap_delete_root(&tsk_rt(t)->hp_blocked_tasks,
						struct nested_info, hp_binheap_node);
					++count;
				}

				if (count)
					litmus->decrease_prio(t, NULL, 0);
			}
			raw_spin_unlock(&tsk_rt(t)->hp_blocked_tasks_lock);

            /* unlocks sem->lock. reacquire it. */
			r2dglp_refresh_owners_prio_decrease(wait->donee_heap_node.fq,
							sem, flags, 1);
            /* there should be no contention!!!! */
			lock_fine_irqsave(&sem->lock, flags);
			r2dglp_move_next_to_fq(sem, fq, t, &wait->donee_heap_node, &flags,
							ALLOW_STEALING, !ALWAYS_TERMINATE_DONATION);
			break;


		case R2DGLP_DONOR:
			TRACE_TASK(t, "Aborting request while donor.\n");
			r2dglp_del_global_list(sem, t, &wait->global_heap_node);
			__drop_from_donor(sem, wait);

			/* update donee */
			donee_info = wait->donee_info;
			donee_info->donor_info = NULL;  // clear the cross-link
			sbinheap_decrease(&donee_info->snode, &sem->donees);

			donee = donee_info->task;
			donee_fq = donee_info->fq;
			if (donee == donee_fq->owner) {
				TRACE_TASK(t, "Donee %s/%d is an owner of fq %d.\n",
						   donee->comm, donee->pid,
						   r2dglp_get_idx(sem, donee_fq));
                /* unlocks sem->lock. reacquire it. */
				r2dglp_remove_donation_from_owner(
					&wait->prio_donation.hp_binheap_node,
					donee_fq, sem, flags);
                /* there should be no contention!!!! */
				lock_fine_irqsave(&sem->lock, flags);
			}
			else {
				TRACE_TASK(t, "Donee %s/%d is blocked in of fq %d.\n",
						   donee->comm, donee->pid,
						   r2dglp_get_idx(sem, donee_fq));

				r2dglp_remove_donation_from_fq_waiter(donee,
					&wait->prio_donation.hp_binheap_node);

				if(donee == donee_fq->hp_waiter) {
					TRACE_TASK(t, "Donee %s/%d was an hp_waiter of fq %d. "
							   "Rechecking hp_waiter.\n",
							   donee->comm, donee->pid,
							   r2dglp_get_idx(sem, donee_fq));

					donee_fq->hp_waiter = r2dglp_find_hp_waiter(donee_fq, NULL);
					TRACE_TASK(t, "New hp_waiter for fq %d is %s/%d!\n",
							   r2dglp_get_idx(sem, donee_fq),
							   (donee_fq->hp_waiter) ? donee_fq->hp_waiter->comm : "null",
							   (donee_fq->hp_waiter) ? donee_fq->hp_waiter->pid : 0);

                    /* unlocks sem->lock. reacquire it. */
					r2dglp_refresh_owners_prio_decrease(donee_fq, sem, flags, 1);
                    /* there should be no contention!!!! */
					lock_fine_irqsave(&sem->lock, flags);
				}
			}

			break;
		default:
			BUG();
	}

	BUG_ON(wait->cur_q != R2DGLP_INVL); /* state should now be invalid */
}

void r2dglp_budget_exhausted(struct litmus_lock* l, struct task_struct* t)
{
	/*
	 * PRE: (1) Our deadline has already been postponed.
	 *      (2) DLG lock is already held of DGLs are supported.
	 *
	 * Exhaustion Response: Remove request from locks and re-issue it.
	 *
	 * step 1: first check that we are actually blocked.
	 * step 2: remove our request from ANY data structure:
	 * step 3: reissue the request
	 */

	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);
	struct litmus_lock* blocked_lock;
	unsigned long flags = 0, more_flags;

	raw_spin_lock_irqsave(&sem->real_lock, more_flags);
	lock_fine_irqsave(&sem->lock, flags);

	blocked_lock = tsk_rt(t)->blocked_lock;
	if (blocked_lock == l) {
		r2dglp_wait_state_t *wait;
		r2dglp_abort_request(sem, t, flags);

		/* now re-issue the request */

		TRACE_TASK(t, "Reissuing a request for replica from lock %d.\n",
						l->ident);

		wait = (r2dglp_wait_state_t*)tsk_rt(t)->blocked_lock_data;

		/* re-init the wait state just to be safe */
		memset(wait, 0, sizeof(*wait));
		wait->task = t;

		if(sem->nr_in_fifos < sem->max_in_fifos) {

			struct fifo_queue *fq;

			/* enqueue somwhere */
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
			fq = (sem->aff_obs) ?
				sem->aff_obs->ops->advise_enqueue(sem->aff_obs, t) :
				sem->shortest_fifo_queue;
#else
			fq = sem->shortest_fifo_queue;
#endif
			TRACE_TASK(t, "is going to an FQ.\n");
			/* if this were true, then we should have been blocked */
			BUG_ON(fq->count == 0);
			r2dglp_enqueue_on_fq(sem, fq, wait, flags);  /* unlocks sem->lock */
		}
		else if(litmus->__compare(r2dglp_mth_highest(sem), BASE, t, BASE)) {
			TRACE_TASK(t, "is going to PQ.\n");
			/* enqueue on PQ */
			r2dglp_enqueue_on_pq(sem, wait);
			unlock_fine_irqrestore(&sem->lock, flags);
		}
		else {
			/* enqueue as donor */
			TRACE_TASK(t, "is going to donor heap.\n");
			r2dglp_enqueue_on_donor(sem, wait, flags);	 /* unlocks sem->lock */
		}

		raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
	}
	else if (blocked_lock) {
		unlock_fine_irqrestore(&sem->lock, flags);
		raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);

		TRACE_TASK(t, "is blocked, but not on R2DGLP. Redirecting...\n");
		if(blocked_lock->ops->supports_budget_exhaustion) {
			TRACE_TASK(t, "Lock %d supports budget exhaustion.\n",
					   blocked_lock->ident);
			blocked_lock->ops->budget_exhausted(blocked_lock, t);
		}
	}
	else {
		TRACE_TASK(t, "appears to be no longer blocked.\n");
		unlock_fine_irqrestore(&sem->lock, flags);
		raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
	}

	return;
}

void r2dglp_virtual_unlock(struct litmus_lock* l, struct task_struct* t)
{
	/* PRE: DGL lock already held if DGLs are supported */

	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);
	struct fifo_queue *fq = r2dglp_get_queue(sem, t);
	unsigned long flags = 0, more_flags;

	TRACE_TASK(t, "performing virtual unlock\n");

	if (!fq)
		return;

	if (fq->is_vunlocked) {
		TRACE_TASK(t, "Lock %d already virtually unlocked.\n", l->ident);
		return;
	}

	raw_spin_lock_irqsave(&sem->real_lock, more_flags);
	lock_fine_irqsave(&sem->lock, flags);

	if (unlikely(fq->owner != t)) {
		TRACE_TASK(t, "no longer holds lock %d.\n", l->ident);
		goto out;
	}

	/* 't' exits priority-tracking data structures, making it
	   "invisible" to all priority inheritance mechanisms except
	   for FQ-based inheritance. 't' can still transitively
	   inherit priority from a donor. */
	r2dglp_del_global_list(sem, t, &fq->global_heap_node);

#ifdef CONFIG_SCHED_DEBUG_TRACE
	if(fq->donee_heap_node.donor_info &&
	   fq->donee_heap_node.donor_info->task) {
		TRACE_TASK(t, "has a donor while vunlock: %s/%d\n",
			fq->donee_heap_node.donor_info->task->comm,
			fq->donee_heap_node.donor_info->task->pid);
	}
#endif

	sbinheap_delete(&fq->donee_heap_node.snode, &sem->donees);

	/* Move a request from donor heap or PQ to fq. don't steal from
	 * other FQs.  Also, terminate donation relationship if we move
	 * a donor to 't' to the FQ (we'll pick inheritance back up via
	 * the FQ, if needed). */
	r2dglp_move_next_to_fq(sem, fq, t, &fq->donee_heap_node, &flags,
					!ALLOW_STEALING, ALWAYS_TERMINATE_DONATION);

	/* decrement fifo count to simulate unlock. individual fifo
	 * length counts remain unchanged. */
	--(sem->nr_in_fifos);
	fq->is_vunlocked = 1;

	TRACE_TASK(t, "virtual unlock completed\n");

out:
	unlock_fine_irqrestore(&sem->lock, flags);
	raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
}



int r2dglp_close(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);
	unsigned long flags;

	int owner = 0;
	int i;

	raw_spin_lock_irqsave(&sem->real_lock, flags);

	for(i = 0; i < sem->nr_replicas; ++i) {
		if(sem->fifo_queues[i].owner == t) {
			owner = 1;
			break;
		}
	}

	raw_spin_unlock_irqrestore(&sem->real_lock, flags);

	if (owner)
		r2dglp_unlock(l);

	return 0;
}

void r2dglp_free(struct litmus_lock* l)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(l);

	kfree(sem->donors.buf);
	kfree(sem->donees.buf);
	kfree(sem->top_m.buf);
	kfree(sem->fifo_queues);
	kfree(sem);
}

struct litmus_lock* r2dglp_new(unsigned int m,
				struct litmus_lock_ops* ops,
				void* __user uarg)
{
	struct r2dglp_semaphore* sem;
	struct r2dglp_args args;
	unsigned int i;

	BUG_ON(m <= 0);

	if(!access_ok(VERIFY_READ, uarg, sizeof(args)))
		return(NULL);
	if(__copy_from_user(&args, uarg, sizeof(args)))
		return(NULL);

	/* validation */

	/* there must be at least one resource */
	if (args.nr_replicas < 1) {
		printk("Invalid number of replicas.\n");
		return(NULL);
	}
	/* R2DGLP_OPTIMAL_FIFO_LEN can only be determined if nr_max_holders
	   is R2DGLP_M_HOLDERS (number of CPUs) */
	if (args.max_fifo_len == R2DGLP_OPTIMAL_FIFO_LEN &&
		args.max_in_fifos != R2DGLP_M_IN_FIFOS) {
		printk("Cannot compute optimal FIFO length if "
			   "max_in_fifos != R2DGLP_M_IN_FIFOS\n");
		return(NULL);
	}
	if ((args.max_in_fifos != R2DGLP_UNLIMITED_IN_FIFOS) &&
		(args.max_fifo_len != R2DGLP_UNLIMITED_FIFO_LEN) &&
		(args.max_in_fifos > args.nr_replicas*args.max_fifo_len)) {
		printk("Not enough total FIFO space for specified max requests "
			   "in FIFOs.\n");
		return(NULL);
	}

	sem = kmalloc(sizeof(*sem), GFP_KERNEL);
	if(!sem)
		return NULL;
	memset(sem, 0, sizeof(*sem));

	sem->fifo_queues = kmalloc(sizeof(struct fifo_queue)*args.nr_replicas,
					GFP_KERNEL);
	if(!sem->fifo_queues)
	{
		kfree(sem);
		return NULL;
	}

	sem->litmus_lock.ops = ops;
//	sem->litmus_lock.proc = &r2dglp_proc_ops;

	raw_spin_lock_init(&sem->lock);
	LOCKDEP_DYNAMIC_ALLOC(sem, &sem->lock);

	raw_spin_lock_init(&sem->real_lock);

	sem->nr_replicas = args.nr_replicas;
	sem->max_in_fifos = (args.max_in_fifos == R2DGLP_M_IN_FIFOS) ?
		m :
		args.max_in_fifos;
	sem->max_fifo_len = (args.max_fifo_len == R2DGLP_OPTIMAL_FIFO_LEN) ?
		(sem->max_in_fifos/args.nr_replicas) +
			((sem->max_in_fifos%args.nr_replicas) != 0) :
		args.max_fifo_len;
	sem->nr_in_fifos = 0;

	TRACE_CUR("New R2DGLP Sem: m = %u, k = %u, max fifo_len = %u\n",
		  sem->max_in_fifos,
		  sem->nr_replicas,
		  sem->max_fifo_len);

	for(i = 0; i < args.nr_replicas; ++i) {
		struct fifo_queue* q = &(sem->fifo_queues[i]);

		q->owner = NULL;
		q->hp_waiter = NULL;
		init_waitqueue_head(&q->wait);
		q->count = 0;
		q->is_vunlocked = 0;

		q->global_heap_node.task = NULL;
		INIT_BINHEAP_NODE(&q->global_heap_node.dnode);

		q->donee_heap_node.task = NULL;
		q->donee_heap_node.donor_info = NULL;
		q->donee_heap_node.fq = NULL;
		INIT_SBINHEAP_NODE(&q->donee_heap_node.snode);

		q->nest.lock = (struct litmus_lock*)sem;
		q->nest.hp_waiter_eff_prio = NULL;
		q->nest.hp_waiter_ptr = &q->hp_waiter;
		INIT_BINHEAP_NODE(&q->nest.hp_binheap_node);
	}

	sem->shortest_fifo_queue = &sem->fifo_queues[0];

	// init heaps

	/* heaps of bounded sizes */

	/* bounded by cluster size */
	sem->top_m.compare = r2dglp_min_heap_base_priority_order;
	sem->top_m.max_size = m;
	sem->top_m.buf = kmalloc(m * sizeof(struct sbinheap_node),
		GFP_KERNEL);
	if(!sem->top_m.buf)
	{
		kfree(sem->fifo_queues);
		kfree(sem);
		return NULL;
	}
	INIT_SBINHEAP(&sem->top_m);

	/* bounded by num FQ slots  */
	sem->donees.compare = r2dglp_min_heap_donee_order;
	sem->donees.max_size = sem->max_in_fifos;
	sem->donees.buf = kmalloc(
		sem->max_in_fifos * sizeof(struct sbinheap_node),
		GFP_KERNEL);
	if(!sem->donees.buf)
	{
		kfree(sem->top_m.buf);
		kfree(sem->fifo_queues);
		kfree(sem);
		return NULL;
	}
	INIT_SBINHEAP(&sem->donees);

	/* bounded by cluster size */
	sem->donors.compare = r2dglp_donor_max_heap_base_priority_order;
	sem->donors.max_size = m; /* bounded by cluster size */
	sem->donors.buf = kmalloc(m * sizeof(struct sbinheap_node),
		GFP_KERNEL);
	if(!sem->donors.buf)
	{
		kfree(sem->donees.buf);
		kfree(sem->top_m.buf);
		kfree(sem->fifo_queues);
		kfree(sem);
		return NULL;
	}
	INIT_SBINHEAP(&sem->donors);

	/* heaps of unbounded size */
	INIT_BINHEAP_HANDLE(&sem->not_top_m, r2dglp_max_heap_base_priority_order);
	INIT_BINHEAP_HANDLE(&sem->priority_queue,
					r2dglp_max_heap_base_priority_order);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	sem->aff_obs = NULL;
#endif

	return &sem->litmus_lock;
}




#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)

/****************************************************************************/
/*                            AFFINITY HEURISTICS                           */
/****************************************************************************/


static inline int __replica_to_gpu(struct r2dglp_affinity* aff, int replica)
{
	int gpu = replica % aff->nr_rsrc;
	return gpu;
}

static inline int replica_to_gpu(struct r2dglp_affinity* aff, int replica)
{
	int gpu = __replica_to_gpu(aff, replica) + aff->offset;
	return gpu;
}

static inline int gpu_to_base_replica(struct r2dglp_affinity* aff, int gpu)
{
	int replica = gpu - aff->offset;
	return replica;
}

static inline int same_gpu(struct r2dglp_affinity* aff,
				int replica_a, int replica_b)
{
	return(replica_to_gpu(aff, replica_a) == replica_to_gpu(aff, replica_b));
}

static inline int has_affinity(struct r2dglp_affinity* aff,
				struct task_struct* t, int replica)
{
	if(tsk_rt(t)->last_gpu >= 0)
		return (tsk_rt(t)->last_gpu == replica_to_gpu(aff, replica));
	return 0;
}

int r2dglp_aff_obs_close(struct affinity_observer* obs)
{
	return 0;
}

void r2dglp_aff_obs_free(struct affinity_observer* obs)
{
	struct r2dglp_affinity *r2dglp_aff = r2dglp_aff_obs_from_aff_obs(obs);

	/* make sure the thread destroying this semaphore will not
	   call the exit callback on a destroyed lock. */
	struct task_struct *t = current;
	if (is_realtime(t) && tsk_rt(t)->rsrc_exit_cb_args == r2dglp_aff)
	{
		tsk_rt(t)->rsrc_exit_cb = NULL;
		tsk_rt(t)->rsrc_exit_cb_args = NULL;
	}

	kfree(r2dglp_aff->nr_cur_users_on_rsrc);
	kfree(r2dglp_aff->nr_aff_on_rsrc);
	kfree(r2dglp_aff->q_info);
	kfree(r2dglp_aff);
}

static struct affinity_observer* r2dglp_aff_obs_new(
                struct affinity_observer_ops* ops,
				struct r2dglp_affinity_ops* r2dglp_ops,
				void* __user args)
{
	struct r2dglp_affinity* r2dglp_aff;
	struct gpu_affinity_observer_args aff_args;
	struct r2dglp_semaphore* sem;
	unsigned int i;
	unsigned long flags;

	if(!access_ok(VERIFY_READ, args, sizeof(aff_args))) {
		return(NULL);
	}
	if(__copy_from_user(&aff_args, args, sizeof(aff_args))) {
		return(NULL);
	}

	sem = (struct r2dglp_semaphore*) get_lock_from_od(aff_args.obs.lock_od);

	if(sem->litmus_lock.type != R2DGLP_SEM) {
		TRACE_CUR("Lock type not supported.  Type = %d\n",
						sem->litmus_lock.type);
		return(NULL);
	}

	if((aff_args.rho <= 0) ||
	   (sem->nr_replicas%aff_args.rho != 0)) {
		TRACE_CUR("Lock %d does not support #replicas (%u) for #simult_users "
				  "(%u) per replica.  #replicas should be evenly divisible "
				  "by #simult_users.\n",
				  sem->litmus_lock.ident,
				  sem->nr_replicas,
				  aff_args.rho);
		return(NULL);
	}

	r2dglp_aff = kmalloc(sizeof(*r2dglp_aff), GFP_KERNEL);
	if(!r2dglp_aff)
		return(NULL);

	r2dglp_aff->q_info = kmalloc(
					sizeof(struct r2dglp_queue_info)*sem->nr_replicas,
					GFP_KERNEL);
	if(!r2dglp_aff->q_info) {
		kfree(r2dglp_aff);
		return(NULL);
	}

	r2dglp_aff->nr_cur_users_on_rsrc = kmalloc(
					sizeof(unsigned int)*(sem->nr_replicas / aff_args.rho),
					GFP_KERNEL);
	if(!r2dglp_aff->nr_cur_users_on_rsrc) {
		kfree(r2dglp_aff->q_info);
		kfree(r2dglp_aff);
		return(NULL);
	}

	r2dglp_aff->nr_aff_on_rsrc = kmalloc(
					sizeof(unsigned int)*(sem->nr_replicas / aff_args.rho),
					GFP_KERNEL);
	if(!r2dglp_aff->nr_aff_on_rsrc) {
		kfree(r2dglp_aff->nr_cur_users_on_rsrc);
		kfree(r2dglp_aff->q_info);
		kfree(r2dglp_aff);
		return(NULL);
	}

	affinity_observer_new(&r2dglp_aff->obs, ops, &aff_args.obs);

	r2dglp_aff->ops = r2dglp_ops;
	r2dglp_aff->offset = aff_args.replica_to_gpu_offset;
	r2dglp_aff->nr_simult = aff_args.rho;
	r2dglp_aff->nr_rsrc = sem->nr_replicas / r2dglp_aff->nr_simult;
	r2dglp_aff->relax_max_fifo_len = (aff_args.relaxed_rules) ? 1 : 0;

	TRACE_CUR("GPU affinity_observer: offset = %d, nr_simult = %d, "
			  "nr_rsrc = %d, relaxed_fifo_len = %d\n",
			  r2dglp_aff->offset, r2dglp_aff->nr_simult, r2dglp_aff->nr_rsrc,
			  r2dglp_aff->relax_max_fifo_len);

	memset(r2dglp_aff->nr_cur_users_on_rsrc, 0,
					sizeof(int)*(r2dglp_aff->nr_rsrc));
	memset(r2dglp_aff->nr_aff_on_rsrc, 0,
					sizeof(unsigned int)*(r2dglp_aff->nr_rsrc));

	for(i = 0; i < sem->nr_replicas; ++i) {
		r2dglp_aff->q_info[i].q = &sem->fifo_queues[i];
		r2dglp_aff->q_info[i].estimated_len = 0;

		/* multiple q_info's will point to the same resource (aka GPU) if
		   aff_args.nr_simult_users > 1 */
		r2dglp_aff->q_info[i].nr_cur_users =
				&r2dglp_aff->nr_cur_users_on_rsrc[__replica_to_gpu(r2dglp_aff,i)];
		r2dglp_aff->q_info[i].nr_aff_users =
				&r2dglp_aff->nr_aff_on_rsrc[__replica_to_gpu(r2dglp_aff,i)];
	}

	/* attach observer to the lock */
	raw_spin_lock_irqsave(&sem->real_lock, flags);
	sem->aff_obs = r2dglp_aff;
	raw_spin_unlock_irqrestore(&sem->real_lock, flags);

	return &r2dglp_aff->obs;
}

static int gpu_replica_to_resource(struct r2dglp_affinity* aff,
				struct fifo_queue* fq)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	return(replica_to_gpu(aff, r2dglp_get_idx(sem, fq)));
}



/*--------------------------------------------------------------------------*/
/*                      ADVANCED AFFINITY HEURISITICS                       */
/*                                                                          */
/* These heuristics estimate FIFO length wait times and try to enqueue      */
/* tasks into the shortest queues. When two queues are equivlenet, the GPU  */
/* that maintains affinity is selected. When a task has no affinity, the    */
/* heuristic tries to get the GPU with the fewest number of other tasks     */
/* with affinity on that GPU.                                               */
/*                                                                          */
/* Heuristics to explore in the future:                                     */
/*   - Utilization                                                          */
/*   - Longest non-preemptive section                                       */
/*   - Criticality                                                          */
/*   - Task period                                                          */
/*--------------------------------------------------------------------------*/

struct fifo_queue* gpu_r2dglp_advise_enqueue(struct r2dglp_affinity* aff,
				struct task_struct* t)
{
	// advise_enqueue must be smart as not not break R2DGLP rules:
	//  * No queue can be greater than ceil(m/k) in length, unless
	//    'relax_max_fifo_len' is asserted
	//  * Cannot let a queue idle if there exist waiting PQ/donors
	//      -- needed to guarantee parallel progress of waiters.
	//
	// We may be able to relax some of these constraints, but this will have to
	// be carefully evaluated.
	//
	// Huristic strategy: Find the shortest queue that is not full.

	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	lt_t min_len;
	unsigned int min_nr_users, min_nr_aff_users;
	struct r2dglp_queue_info *shortest, *aff_queue;
	struct fifo_queue *to_enqueue;
	unsigned int i;
	int affinity_gpu;

	unsigned int max_fifo_len = (aff->relax_max_fifo_len) ?
		sem->max_in_fifos : /* allow poss. of all requests on same queue */
		sem->max_fifo_len;  /* constraint FIFO len */

	/* if we have no affinity, find the GPU with the least number of users
	   with active affinity */
	if(unlikely(tsk_rt(t)->last_gpu < 0)) {
		int temp_min = aff->nr_aff_on_rsrc[0];
		affinity_gpu = aff->offset;

		for(i = 1; i < aff->nr_rsrc; ++i) {
			if(aff->nr_aff_on_rsrc[i] < temp_min) {
				affinity_gpu = aff->offset + i;
			}
		}

		TRACE_CUR("no affinity. defaulting to %d with %d aff users.\n",
						affinity_gpu, temp_min);
	}
	else {
		affinity_gpu = tsk_rt(t)->last_gpu;
	}

	// all things being equal, let's start with the queue with which we have
	// affinity.  this helps us maintain affinity even when we don't have
	// an estiamte for local-affinity execution time (i.e., 2nd time on GPU)
	aff_queue = &aff->q_info[gpu_to_base_replica(aff, affinity_gpu)];
	shortest = aff_queue;

	min_len = shortest->estimated_len + get_gpu_estimate(t, MIG_LOCAL);
	min_nr_users = *(shortest->nr_cur_users);
	min_nr_aff_users = *(shortest->nr_aff_users);


	TRACE_CUR("cs is %llu on queue %d (count = %u): est len = %llu\n",
			  get_gpu_estimate(t, MIG_LOCAL),
			  r2dglp_get_idx(sem, shortest->q),
			  shortest->q->count,
			  min_len);

	for(i = 0; i < sem->nr_replicas; ++i) {
		if(&aff->q_info[i] != shortest) {
			/* is there room on this q? */
			if(nominal_fq_len(aff->q_info[i].q) < max_fifo_len) {
				int want = 0;

				lt_t migration =
					get_gpu_estimate(t,
								gpu_migration_distance(tsk_rt(t)->last_gpu,
													replica_to_gpu(aff, i)));
				lt_t est_len = aff->q_info[i].estimated_len + migration;

				// queue is smaller, or they're equal and the other has a
				// smaller number of total users.
				//
				// tie-break on the shortest number of simult users.  this
				// only kicks in when there are more than 1 empty queues.

				// TODO: Make "est_len < min_len" a fuzzy function that allows
				// queues "close enough" in length to be considered equal.

				/* NOTE: 'shortest' starts out with affinity GPU */
				if(unlikely(nominal_fq_len(shortest->q) >= max_fifo_len)) {
					/* 'shortest' is full and i-th queue is not */
					want = 1;
				}
				else if(est_len < min_len) {
					/* i-th queue has shortest length */
					want = 1;
				}
				else if(unlikely(est_len == min_len)) {
					/* equal lengths */
					if(!has_affinity(aff, t, r2dglp_get_idx(sem, shortest->q))) {
						/* don't sacrifice affinity on tie */
						if(has_affinity(aff, t, i)) {
							/* switch to maintain affinity */
							want = 1;
						}
						else if(*(aff->q_info[i].nr_aff_users) <
										min_nr_aff_users) {
							/* favor one with less affinity load */
							want = 1;
						}
						else if((*(aff->q_info[i].nr_aff_users) == min_nr_aff_users) && /* equal number of affinity */
								(*(aff->q_info[i].nr_cur_users) < min_nr_users)) {		/* favor one with current fewer users */
							want = 1;
						}
					}
				}

				if(want) {
					shortest = &aff->q_info[i];
					min_len = est_len;
					min_nr_users = *(aff->q_info[i].nr_cur_users);
					min_nr_aff_users = *(aff->q_info[i].nr_aff_users);
				}

				TRACE_CUR("cs is %llu on queue %d (count = %u): "
						  "est len = %llu\n",
						  get_gpu_estimate(t,
								gpu_migration_distance(tsk_rt(t)->last_gpu,
										replica_to_gpu(aff, i))),
						  r2dglp_get_idx(sem, aff->q_info[i].q),
						  aff->q_info[i].q->count,
						  est_len);
			}
			else {
				TRACE_CUR("queue %d is too long.  ineligible for enqueue.\n",
						  r2dglp_get_idx(sem, aff->q_info[i].q));
			}
		}
	}

	if(nominal_fq_len(shortest->q) >= max_fifo_len) {
		TRACE_CUR("selected fq %d is too long, but returning it anyway.\n",
				  r2dglp_get_idx(sem, shortest->q));
	}

	to_enqueue = shortest->q;
	TRACE_CUR("enqueue on fq %d (count = %u) (non-aff wanted fq %d)\n",
			  r2dglp_get_idx(sem, to_enqueue),
			  to_enqueue->count,
			  r2dglp_get_idx(sem, sem->shortest_fifo_queue));

	return to_enqueue;
}


static r2dglp_wait_state_t* pick_steal(struct r2dglp_affinity* aff,
				int dest_gpu,
				struct fifo_queue* fq)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	r2dglp_wait_state_t *wait = NULL;
	int max_improvement = -(MIG_NONE+1);
	int replica = r2dglp_get_idx(sem, fq);

	if(waitqueue_active(&fq->wait)) {
		int this_gpu = replica_to_gpu(aff, replica);
		struct list_head *pos;

		list_for_each(pos, &fq->wait.task_list) {
			wait_queue_t *fq_wait = list_entry(pos, wait_queue_t, task_list);
			r2dglp_wait_state_t *tmp_wait =
					container_of(fq_wait, r2dglp_wait_state_t, fq_node);

			int tmp_improvement =
				gpu_migration_distance(this_gpu,
								tsk_rt(tmp_wait->task)->last_gpu) -
				gpu_migration_distance(dest_gpu,
								tsk_rt(tmp_wait->task)->last_gpu);

			if(tmp_improvement > max_improvement) {
				wait = tmp_wait;
				max_improvement = tmp_improvement;

				if(max_improvement >= (MIG_NONE-1)) {
					goto out;
				}
			}
		}

		BUG_ON(!wait);
	}
	else {
		TRACE_CUR("fq %d is empty!\n", replica);
	}

out:

	TRACE_CUR("Candidate victim from fq %d is %s/%d.  aff improvement = %d.\n",
			  replica,
			  (wait) ? wait->task->comm : "null",
			  (wait) ? wait->task->pid  : 0,
			  max_improvement);

	return wait;
}


r2dglp_wait_state_t* gpu_r2dglp_advise_steal(struct r2dglp_affinity* aff,
				struct fifo_queue* dst)
{
	/* Huristic strategy: Find task with greatest improvement in affinity. */

	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	r2dglp_wait_state_t *to_steal_state = NULL;
	int max_improvement = -(MIG_NONE+1);
	int replica, i;
	int dest_gpu;

	replica = r2dglp_get_idx(sem, dst);
	dest_gpu = replica_to_gpu(aff, replica);

	for(i = 0; i < sem->nr_replicas; ++i) {
		r2dglp_wait_state_t *tmp_to_steal_state =
			pick_steal(aff, dest_gpu, &sem->fifo_queues[i]);

		if(tmp_to_steal_state) {
			int tmp_improvement =
				gpu_migration_distance(replica_to_gpu(aff, i),
								tsk_rt(tmp_to_steal_state->task)->last_gpu) -
				gpu_migration_distance(dest_gpu,
								tsk_rt(tmp_to_steal_state->task)->last_gpu);

			if(tmp_improvement > max_improvement) {
				to_steal_state = tmp_to_steal_state;
				max_improvement = tmp_improvement;

				if(max_improvement >= (MIG_NONE-1)) {
					goto out;
				}
			}
		}
	}

out:
	if(!to_steal_state) {
		TRACE_CUR("Could not find anyone to steal.\n");
	}
	else {
		TRACE_CUR("Selected victim %s/%d on fq %d (GPU %d) for fq %d "
				  "(GPU %d): improvement = %d\n",
				  to_steal_state->task->comm, to_steal_state->task->pid,
				  r2dglp_get_idx(sem, to_steal_state->donee_heap_node.fq),
				  replica_to_gpu(aff,
				      r2dglp_get_idx(sem, to_steal_state->donee_heap_node.fq)),
				  r2dglp_get_idx(sem, dst),
				  dest_gpu,
				  max_improvement);
	}

	return(to_steal_state);
}


static inline int has_donor(wait_queue_t* fq_wait)
{
	r2dglp_wait_state_t *wait =
			container_of(fq_wait, r2dglp_wait_state_t, fq_node);
	return(wait->donee_heap_node.donor_info != NULL);
}

static r2dglp_donee_heap_node_t* pick_donee(struct r2dglp_affinity* aff,
				struct fifo_queue* fq,
				int* dist_from_head)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	struct task_struct *donee;
	r2dglp_donee_heap_node_t *donee_node;
	struct task_struct *mth_highest = r2dglp_mth_highest(sem);

	if(fq->owner &&
	   fq->donee_heap_node.donor_info == NULL &&
	   mth_highest != fq->owner &&
	   litmus->__compare(mth_highest, BASE, fq->owner, BASE)) {
		donee = fq->owner;
		donee_node = &(fq->donee_heap_node);
		*dist_from_head = 0;

		BUG_ON(donee != donee_node->task);

		TRACE_CUR("picked owner of fq %d as donee\n",
				  r2dglp_get_idx(sem, fq));

		goto out;
	}
	else if(waitqueue_active(&fq->wait)) {
		struct list_head	*pos;

		TRACE_CUR("searching fq %d for donee\n", r2dglp_get_idx(sem, fq));

		*dist_from_head = 1;

		/* iterating from the start of the queue is nice since this means
		   the donee will be closer to obtaining a resource. */
		list_for_each(pos, &fq->wait.task_list) {
			wait_queue_t *fq_wait = list_entry(pos, wait_queue_t, task_list);
			r2dglp_wait_state_t *wait =
					container_of(fq_wait, r2dglp_wait_state_t, fq_node);

			if(!has_donor(fq_wait) &&
			   mth_highest != wait->task &&
			   litmus->__compare(mth_highest, BASE, wait->task, BASE)) {
				donee = (struct task_struct*) fq_wait->private;
				donee_node = &wait->donee_heap_node;

				BUG_ON(donee != donee_node->task);

				TRACE_CUR("picked waiter in fq %d as donee\n",
						  r2dglp_get_idx(sem, fq));

				goto out;
			}
			++(*dist_from_head);
		}
	}

	donee = NULL;
	donee_node = NULL;
	*dist_from_head = R2DGLP_INVAL_DISTANCE;

	TRACE_CUR("Found no one to be donee in fq %d!\n", r2dglp_get_idx(sem, fq));

out:

	TRACE_CUR("Candidate donee for fq %d is %s/%d (dist_from_head = %d)\n",
			  r2dglp_get_idx(sem, fq),
			  (donee) ? (donee)->comm : "null",
			  (donee) ? (donee)->pid  : 0,
			  *dist_from_head);

	return donee_node;
}

r2dglp_donee_heap_node_t* gpu_r2dglp_advise_donee_selection(
				struct r2dglp_affinity* aff,
				struct task_struct* donor)
{
	// Huristic strategy: Find the highest-priority donee that is waiting on
	// a queue closest to our affinity.  (1) The donee CANNOT already have a
	// donor (exception: donee is the lowest-prio task in the donee heap).
	// (2) Requests in 'top_m' heap are ineligible.
	//
	// Further strategy: amongst elible donees waiting for the same GPU, pick
	// the one closest to the head of the FIFO queue (including owners).

	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	r2dglp_donee_heap_node_t *donee_node;
	gpu_migration_dist_t distance;
	int start, i, j;

	r2dglp_donee_heap_node_t *default_donee;
	r2dglp_wait_state_t *default_donee_donor_info;

	if(tsk_rt(donor)->last_gpu < 0) {
		/* no affinity.  just return the min prio, like standard R2DGLP */
		/* TODO: Find something closer to the head of the queue?? */
		donee_node = sbinheap_top_entry(&sem->donees,
			r2dglp_donee_heap_node_t,
			snode);
		goto out;
	}


	// Temporarily break any donation relation the default donee (the lowest
	// prio task in the FIFO queues) to make it eligible for selection below.
	//
	// NOTE: The original donor relation *must* be restored, even if we select
	// the default donee through affinity-aware selection, before returning
	// from this function so we don't screw up our heap ordering.
	// The standard R2DGLP algorithm will steal the donor relationship if needed.
	default_donee =
		sbinheap_top_entry(&sem->donees, r2dglp_donee_heap_node_t, snode);

	default_donee_donor_info = default_donee->donor_info;  // back-up donor relation
	default_donee->donor_info = NULL;  // temporarily break any donor relation.

	// initialize our search
	donee_node = NULL;
	distance = MIG_NONE;

	// TODO: The below search logic may work well for locating nodes to steal
	// when an FQ goes idle.  Validate this code and apply it to stealing.

	// begin search with affinity GPU.
	start = gpu_to_base_replica(aff, tsk_rt(donor)->last_gpu);
	i = start;
	do {  // "for each gpu" / "for each aff->nr_rsrc"
		gpu_migration_dist_t temp_distance = gpu_migration_distance(start, i);

		// only interested in queues that will improve our distance
		if(temp_distance < distance || donee_node == NULL) {
			int dist_from_head = R2DGLP_INVAL_DISTANCE;

			TRACE_CUR("searching for donor on GPU %d\n", i);

			// visit each queue and pick a donee.  bail as soon as we find
			// one for this class.

			for(j = 0; j < aff->nr_simult; ++j) {
				int temp_dist_from_head;
				r2dglp_donee_heap_node_t *temp_donee_node;
				struct fifo_queue *fq;

				fq = &(sem->fifo_queues[i + j*aff->nr_rsrc]);
				temp_donee_node = pick_donee(aff, fq, &temp_dist_from_head);

				if(temp_dist_from_head < dist_from_head)
				{
					// we check all the FQs for this GPU to spread priorities
					// out across the queues.  does this decrease jitter?
					donee_node = temp_donee_node;
					dist_from_head = temp_dist_from_head;
				}
			}

			if(dist_from_head != R2DGLP_INVAL_DISTANCE) {
				TRACE_CUR("found donee %s/%d and is the %d-th waiter.\n",
						  donee_node->task->comm, donee_node->task->pid,
						  dist_from_head);
			}
			else {
				TRACE_CUR("found no eligible donors from GPU %d\n", i);
			}
		}
		else {
			TRACE_CUR("skipping GPU %d (distance = %d, best donor "
					  "distance = %d)\n", i, temp_distance, distance);
		}

		i = (i+1 < aff->nr_rsrc) ? i+1 : 0;  // increment with wrap-around
	} while (i != start);


	/* restore old donor info state. */
	default_donee->donor_info = default_donee_donor_info;

	if(!donee_node) {
		donee_node = default_donee;

		TRACE_CUR("Could not find a donee. We have to steal one.\n");
		// TODO: vv Is the below a bug when raised?
		//WARN_ON(default_donee->donor_info == NULL);
	}

out:

	TRACE_CUR("Selected donee %s/%d on fq %d "
			  "(GPU %d) for %s/%d with affinity for GPU %d\n",
			  donee_node->task->comm, donee_node->task->pid,
			  r2dglp_get_idx(sem, donee_node->fq),
			  replica_to_gpu(aff, r2dglp_get_idx(sem, donee_node->fq)),
			  donor->comm, donor->pid, tsk_rt(donor)->last_gpu);

	return(donee_node);
}


typedef struct
{
	int gpu;
	r2dglp_wait_state_t* closest;
	int dist;
} find_closest_donor_args_t;

static void __find_closest_donor(sbinheap_node_t donor_node, void *_args)
{
	find_closest_donor_args_t* args = (find_closest_donor_args_t*)_args;

	r2dglp_wait_state_t *this_donor =
		sbinheap_entry(donor_node, r2dglp_wait_state_t, snode);

	int this_dist =
		gpu_migration_distance(args->gpu,
			tsk_rt(this_donor->task)->last_gpu);

	if(this_dist < args->dist) {
		// take this donor
		args->dist = this_dist;
		args->closest = this_donor;
	}
	else if(this_dist == args->dist) {
		// priority tie-break.  Even though this is a pre-order traversal,
		// this is a heap, not a binary tree, so we still need to do a priority
		// comparision.
		if(!(args->closest) ||
		   litmus->compare(this_donor->task, (args->closest)->task)) {
			args->dist = this_dist;
			args->closest = this_donor;
		}
	}
}

r2dglp_wait_state_t* gpu_r2dglp_advise_donor_to_fq(struct r2dglp_affinity* aff,
				struct fifo_queue* fq)
{
	// Huristic strategy: Find donor with the closest affinity to fq.
	// Tie-break on priority.
	// We need to iterate over all the donors to do this.

	r2dglp_wait_state_t *donor;
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	find_closest_donor_args_t args =
	{
		.gpu = replica_to_gpu(aff, r2dglp_get_idx(sem, fq)),
		.closest = NULL,
		.dist = MIG_NONE,
	};

#ifdef CONFIG_SCHED_DEBUG_TRACE
	r2dglp_wait_state_t* default_donor =
		sbinheap_top_entry(&sem->donors, r2dglp_wait_state_t, snode);
#endif

	sbinheap_for_each(&sem->donors, __find_closest_donor, &args);
	donor = args.closest;

	BUG_ON(!donor);

	TRACE_CUR("Selected donor %s/%d (distance = %d) to move to fq %d "
			  "(non-aff wanted %s/%d). differs = %d\n",
			  donor->task->comm, donor->task->pid,
			  args.dist,
			  r2dglp_get_idx(sem, fq),
			  default_donor->task->comm, default_donor->task->pid,
			  (donor->task != default_donor->task)
			  );

	return(donor);
}



void gpu_r2dglp_notify_enqueue(struct r2dglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	struct r2dglp_queue_info *info = &aff->q_info[replica];
	lt_t est_time;
	lt_t est_len_before;

	if(current == t)
		tsk_rt(t)->suspend_gpu_tracker_on_block = 1;

	est_len_before = info->estimated_len;
	est_time = get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu, gpu));
	info->estimated_len += est_time;

	TRACE_CUR("fq %d: q_len (%llu) + est_cs (%llu) = %llu\n",
			  r2dglp_get_idx(sem, info->q),
			  est_len_before, est_time,
			  info->estimated_len);
}

void gpu_r2dglp_notify_dequeue(struct r2dglp_affinity* aff, struct fifo_queue* fq,
				struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	struct r2dglp_queue_info *info = &aff->q_info[replica];
	lt_t est_time = get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu, gpu));

	if(est_time > info->estimated_len) {
		WARN_ON(1);
		info->estimated_len = 0;
	}
	else {
		info->estimated_len -= est_time;
	}

	TRACE_CUR("fq %d est len is now %llu\n",
			  r2dglp_get_idx(sem, info->q),
			  info->estimated_len);
}

int gpu_r2dglp_notify_exit(struct r2dglp_affinity* aff, struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	unsigned long flags = 0, more_flags;
	int aff_rsrc;
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t *dgl_lock = litmus->get_dgl_spinlock(t);
#endif

	if (tsk_rt(t)->last_gpu < 0)
		return 0;

	lock_global_irqsave(dgl_lock, flags);
	raw_spin_lock_irqsave(&sem->real_lock, more_flags);
	lock_fine_irqsave(&sem->lock, flags);

	/* decrement affinity count on old GPU */
	aff_rsrc = tsk_rt(t)->last_gpu - aff->offset;
	--(aff->nr_aff_on_rsrc[aff_rsrc]);

	if(unlikely(aff->nr_aff_on_rsrc[aff_rsrc] < 0)) {
		WARN_ON(aff->nr_aff_on_rsrc[aff_rsrc] < 0);
		aff->nr_aff_on_rsrc[aff_rsrc] = 0;
	}

	unlock_fine_irqrestore(&sem->lock, flags);
	raw_spin_unlock_irqrestore(&sem->real_lock, more_flags);
	unlock_global_irqrestore(dgl_lock, flags);

	return 0;
}

int gpu_r2dglp_notify_exit_trampoline(struct task_struct* t)
{
	struct r2dglp_affinity* aff =
			(struct r2dglp_affinity*)tsk_rt(t)->rsrc_exit_cb_args;
	if(likely(aff))
		return gpu_r2dglp_notify_exit(aff, t);
	else
		return -1;
}

void gpu_r2dglp_notify_acquired(struct r2dglp_affinity* aff,
				struct fifo_queue* fq,
				struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	int last_gpu = tsk_rt(t)->last_gpu;

	/* record the type of migration */
	tsk_rt(t)->gpu_migration = gpu_migration_distance(last_gpu, gpu);

	TRACE_CUR("%s/%d acquired gpu %d (prev = %d).  migration type = %d\n",
			  t->comm, t->pid, gpu, last_gpu, tsk_rt(t)->gpu_migration);

	/* count the number or resource holders */
	++(*(aff->q_info[replica].nr_cur_users));

	if(gpu != last_gpu) {
		if(last_gpu >= 0) {
			int old_rsrc = last_gpu - aff->offset;
			--(aff->nr_aff_on_rsrc[old_rsrc]);
		}

		/* increment affinity count on new GPU */
		++(aff->nr_aff_on_rsrc[gpu - aff->offset]);
		tsk_rt(t)->rsrc_exit_cb_args = aff;
		tsk_rt(t)->rsrc_exit_cb = gpu_r2dglp_notify_exit_trampoline;
	}

	reg_nv_device(gpu, 1, t);  /* register */

	tsk_rt(t)->suspend_gpu_tracker_on_block = 0;
	reset_gpu_tracker(t);
	start_gpu_tracker(t);
}

void gpu_r2dglp_notify_freed(struct r2dglp_affinity* aff,
				struct fifo_queue* fq,
				struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	lt_t est_time;

	stop_gpu_tracker(t);  /* stop the tracker before we do anything else. */

	est_time = get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu, gpu));

	/* count the number or resource holders */
	--(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 0, t);	/* unregister */

	/* update estimates */
	update_gpu_estimate(t, get_gpu_time(t));

	TRACE_CUR("%s/%d freed gpu %d (prev = %d).  mig type = %d.  "
			  "actual time was %llu.  "
			  "estimated was %llu.  "
			  "diff is %d\n",
			  t->comm, t->pid, gpu, tsk_rt(t)->last_gpu,
			  tsk_rt(t)->gpu_migration,
			  get_gpu_time(t),
			  est_time,
			  (long long)get_gpu_time(t) - (long long)est_time);

	tsk_rt(t)->last_gpu = gpu;
}

struct r2dglp_affinity_ops gpu_r2dglp_affinity =
{
	.advise_enqueue = gpu_r2dglp_advise_enqueue,
	.advise_steal = gpu_r2dglp_advise_steal,
	.advise_donee_selection = gpu_r2dglp_advise_donee_selection,
	.advise_donor_to_fq = gpu_r2dglp_advise_donor_to_fq,

	.notify_enqueue = gpu_r2dglp_notify_enqueue,
	.notify_dequeue = gpu_r2dglp_notify_dequeue,
	.notify_acquired = gpu_r2dglp_notify_acquired,
	.notify_freed = gpu_r2dglp_notify_freed,

	.notify_exit = gpu_r2dglp_notify_exit,

	.replica_to_resource = gpu_replica_to_resource,
};

struct affinity_observer* r2dglp_gpu_aff_obs_new(
				struct affinity_observer_ops* ops,
				void* __user args)
{
	return r2dglp_aff_obs_new(ops, &gpu_r2dglp_affinity, args);
}




/*--------------------------------------------------------------------------*/
/*                 SIMPLE LOAD-BALANCING AFFINITY HEURISTIC                 */
/*--------------------------------------------------------------------------*/

struct fifo_queue* simple_gpu_r2dglp_advise_enqueue(struct r2dglp_affinity* aff,
				struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	unsigned int min_count;
	unsigned int min_nr_users;
	struct r2dglp_queue_info *shortest;
	struct fifo_queue *to_enqueue;
	unsigned int i;

	shortest = &aff->q_info[0];
	min_count = shortest->q->count;
	min_nr_users = *(shortest->nr_cur_users);

	TRACE_CUR("queue %d: waiters = %u, total holders = %u\n",
			  r2dglp_get_idx(sem, shortest->q),
			  shortest->q->count,
			  min_nr_users);

	for(i = 1; i < sem->nr_replicas; ++i) {
		unsigned int len = aff->q_info[i].q->count;

		// queue is smaller, or they're equal and the other has a smaller number
		// of total users.
		//
		// tie-break on the shortest number of simult users.  this only kicks in
		// when there are more than 1 empty queues.
		if((len < min_count) ||
		   ((len == min_count) && (*(aff->q_info[i].nr_cur_users) < min_nr_users))) {
			shortest = &aff->q_info[i];
			min_count = shortest->q->count;
			min_nr_users = *(aff->q_info[i].nr_cur_users);
		}

		TRACE_CUR("queue %d: waiters = %d, total holders = %d\n",
				  r2dglp_get_idx(sem, aff->q_info[i].q),
				  aff->q_info[i].q->count,
				  *(aff->q_info[i].nr_cur_users));
	}

	to_enqueue = shortest->q;
	TRACE_CUR("enqueue on fq %d (non-aff wanted fq %d)\n",
			  r2dglp_get_idx(sem, to_enqueue),
			  r2dglp_get_idx(sem, sem->shortest_fifo_queue));

	return to_enqueue;
}

r2dglp_wait_state_t* simple_gpu_r2dglp_advise_steal(struct r2dglp_affinity* aff,
				struct fifo_queue* dst)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	return r2dglp_find_hp_waiter_to_steal(sem, NULL);
}

r2dglp_donee_heap_node_t* simple_gpu_r2dglp_advise_donee_selection(
				struct r2dglp_affinity* aff, struct task_struct* donor)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	r2dglp_donee_heap_node_t *donee =
		sbinheap_top_entry(&sem->donees, r2dglp_donee_heap_node_t, snode);
	return(donee);
}

r2dglp_wait_state_t* simple_gpu_r2dglp_advise_donor_to_fq(
				struct r2dglp_affinity* aff, struct fifo_queue* fq)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	r2dglp_wait_state_t* donor =
		sbinheap_top_entry(&sem->donors, r2dglp_wait_state_t, snode);
	return(donor);
}

void simple_gpu_r2dglp_notify_enqueue(struct r2dglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t)
{
}

void simple_gpu_r2dglp_notify_dequeue(struct r2dglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t)
{
}

void simple_gpu_r2dglp_notify_acquired(struct r2dglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);

	/* count the number or resource holders */
	++(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 1, t);  /* register */
}

void simple_gpu_r2dglp_notify_freed(struct r2dglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock(aff->obs.lock);
	int replica = r2dglp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);

	/* count the number or resource holders */
	--(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 0, t);	/* unregister */
}

struct r2dglp_affinity_ops simple_gpu_r2dglp_affinity =
{
	.advise_enqueue = simple_gpu_r2dglp_advise_enqueue,
	.advise_steal = simple_gpu_r2dglp_advise_steal,
	.advise_donee_selection = simple_gpu_r2dglp_advise_donee_selection,
	.advise_donor_to_fq = simple_gpu_r2dglp_advise_donor_to_fq,

	.notify_enqueue = simple_gpu_r2dglp_notify_enqueue,
	.notify_dequeue = simple_gpu_r2dglp_notify_dequeue,
	.notify_acquired = simple_gpu_r2dglp_notify_acquired,
	.notify_freed = simple_gpu_r2dglp_notify_freed,

	.notify_exit = NULL,

	.replica_to_resource = gpu_replica_to_resource,
};

struct affinity_observer* r2dglp_simple_gpu_aff_obs_new(
                struct affinity_observer_ops* ops,
				void* __user args)
{
	return r2dglp_aff_obs_new(ops, &simple_gpu_r2dglp_affinity, args);
}
#endif /* end LITMUS_AFFINITY_LOCKING && LITMUS_NVIDIA */

#if 0
/* debugging routines */

static void __r2dglp_dump_pq(struct binheap_node *n, int depth)
{
	r2dglp_heap_node_t *request;
	char padding[81] = "                                                                                ";

	if(n == NULL) {
		TRACE("+-> %p\n", NULL);
		return;
	}

	request = binheap_entry(n, r2dglp_heap_node_t, node);

	if(depth*2 <= 80)
		padding[depth*2] = '\0';


	TRACE("%s+-> %s/%d\n",
		  padding,
		  request->task->comm,
		  request->task->pid);

    if(n->left) __r2dglp_dump_pq(n->left, depth+1);
    if(n->right) __r2dglp_dump_pq(n->right, depth+1);
}

static void __r2dglp_dump_donors(struct binheap_node *n, int depth)
{
	r2dglp_wait_state_t *donor_node;
	char padding[81] = "                                                                                ";

	if(n == NULL) {
		TRACE("+-> %p\n", NULL);
		return;
	}

	donor_node = binheap_entry(n, r2dglp_wait_state_t, node);

	if(depth*2 <= 80)
		padding[depth*2] = '\0';


	TRACE("%s+-> %s/%d (donee: %s/%d)\n",
          padding,
          donor_node->task->comm,
          donor_node->task->pid,
          donor_node->donee_info->task->comm,
          donor_node->donee_info->task->pid);

    if(n->left) __r2dglp_dump_donors(n->left, depth+1);
    if(n->right) __r2dglp_dump_donors(n->right, depth+1);
}

static void __r2dglp_dump_fifoq(int i, struct fifo_queue* fq)
{
	TRACE("    FIFO %d: Owner = %s/%d (Virtually Unlocked = %u),  HP Waiter = %s/%d,  Length = %u\n",
		  i,
		  (fq->owner) ? fq->owner->comm : "null",
		  (fq->owner) ? fq->owner->pid : 0,
		  fq->is_vunlocked,
		  (fq->hp_waiter) ? fq->hp_waiter->comm : "null",
		  (fq->hp_waiter) ? fq->hp_waiter->pid : 0,
		  fq->count);
	if (waitqueue_active(&fq->wait)) {
		struct list_head *pos;
		list_for_each(pos, &fq->wait.task_list) {
			wait_queue_t *q = list_entry(pos, wait_queue_t, task_list);
			struct task_struct *t = (struct task_struct*) q->private;
			TRACE("        %s/%d (effective priority: %s/%d)\n",
				  t->comm, t->pid,
				  (tsk_rt(t)->inh_task) ? tsk_rt(t)->inh_task->comm : "null",
				  (tsk_rt(t)->inh_task) ? tsk_rt(t)->inh_task->pid : 0);
		}
	}
}

__attribute__ ((unused))
static void __r2dglp_dump_state(struct r2dglp_semaphore *sem)
{
	int i;
	TRACE("R2DGLP Lock %d\n", sem->litmus_lock.ident);
	TRACE("# Replicas: %u    Max FIFO Len: %u    Max in FIFOs: %u    Cur # in FIFOs: %u\n",
		  sem->nr_replicas, sem->max_fifo_len, sem->max_in_fifos, sem->nr_in_fifos);
	TRACE("# requests in top-m: %u\n", sem->top_m_size);

	for (i = 0; i < sem->nr_replicas; ++i)
		__r2dglp_dump_fifoq(i, &sem->fifo_queues[i]);

	TRACE("    PQ:\n");
	__r2dglp_dump_pq(sem->priority_queue.root, 1);

	TRACE("    Donors:\n");
	__r2dglp_dump_donors(sem->donors.root, 1);
}

static void print_global_list(struct binheap_node* n, int depth)
{
	r2dglp_heap_node_t *global_heap_node;
	char padding[81] = "                                                                                ";

	if(n == NULL) {
		TRACE_CUR("+-> %p\n", NULL);
		return;
	}

	global_heap_node = binheap_entry(n, r2dglp_heap_node_t, node);

	if(depth*2 <= 80)
		padding[depth*2] = '\0';

	TRACE_CUR("%s+-> %s/%d\n",
			  padding,
			  global_heap_node->task->comm,
			  global_heap_node->task->pid);

    if(n->left) print_global_list(n->left, depth+1);
    if(n->right) print_global_list(n->right, depth+1);
}

static void print_donees(struct r2dglp_semaphore *sem, struct binheap_node *n, int depth)
{
	r2dglp_donee_heap_node_t *donee_node;
	char padding[81] = "                                                                                ";
	struct task_struct* donor = NULL;

	if(n == NULL) {
		TRACE_CUR("+-> %p\n", NULL);
		return;
	}

	donee_node = binheap_entry(n, r2dglp_donee_heap_node_t, node);

	if(depth*2 <= 80)
		padding[depth*2] = '\0';

	if(donee_node->donor_info) {
		donor = donee_node->donor_info->task;
	}

	TRACE_CUR("%s+-> %s/%d (d: %s/%d) (fq: %d)\n",
			  padding,
			  donee_node->task->comm,
			  donee_node->task->pid,
			  (donor) ? donor->comm : "null",
			  (donor) ? donor->pid : 0,
			  r2dglp_get_idx(sem, donee_node->fq));

    if(n->left) print_donees(sem, n->left, depth+1);
    if(n->right) print_donees(sem, n->right, depth+1);
}

static void print_donors(struct binheap_node *n, int depth)
{
	r2dglp_wait_state_t *donor_node;
	char padding[81] = "                                                                                ";

	if(n == NULL) {
		TRACE_CUR("+-> %p\n", NULL);
		return;
	}

	donor_node = binheap_entry(n, r2dglp_wait_state_t, node);

	if(depth*2 <= 80)
		padding[depth*2] = '\0';


	TRACE_CUR("%s+-> %s/%d (donee: %s/%d)\n",
			  padding,
			  donor_node->task->comm,
			  donor_node->task->pid,
			  donor_node->donee_info->task->comm,
			  donor_node->donee_info->task->pid);

    if(n->left) print_donors(n->left, depth+1);
    if(n->right) print_donors(n->right, depth+1);
}
#endif

#if 0
struct r2dglp_proc_print_heap_args
{
	struct r2dglp_semaphore *sem;
	int *size;
	char **next;
};

static void __r2dglp_pq_to_proc(struct binheap_node *n, void *args)
{
	struct r2dglp_proc_print_heap_args *hargs;
	r2dglp_heap_node_t *request;
	int w;

	if (!n)
		return;

	hargs = (struct r2dglp_proc_print_heap_args*) args;
	request = binheap_entry(n, r2dglp_heap_node_t, node);

	w = scnprintf(*(hargs->next), *(hargs->size), "\t%s/%d\n",
				  request->task->comm, request->task->pid);
	*(hargs->size) -= w;
	*(hargs->next) += w;
}

static void __r2dglp_donor_to_proc(struct binheap_node *n, void *args)
{
	struct r2dglp_proc_print_heap_args *hargs;
	r2dglp_wait_state_t *donor_node;
	int w;

	if (!n)
		return;

	hargs = (struct r2dglp_proc_print_heap_args*) args;
	donor_node = binheap_entry(n, r2dglp_wait_state_t, node);

	w = scnprintf(*(hargs->next), *(hargs->size), "\t%s/%d (donee: %s/%d)\n",
				  donor_node->task->comm,
				  donor_node->task->pid,
				  donor_node->donee_info->task->comm,
				  donor_node->donee_info->task->pid);
	*(hargs->size) -= w;
	*(hargs->next) += w;
}


static int r2dglp_proc_print(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct r2dglp_semaphore *sem = r2dglp_from_lock((struct litmus_lock*)data);

	int attempts = 0;
	const int max_attempts = 10;
	int locked = 0;
	unsigned long flags;

	int size = count;
	char *next = page;

	struct r2dglp_proc_print_heap_args heap_args = {sem, &size, &next};

	int w;
	int i;

	while(attempts < max_attempts)
	{
		locked = raw_spin_trylock_irqsave(&sem->real_lock, flags);

		if (unlikely(!locked)) {
			++attempts;
			cpu_relax();
		}
		else {
			break;
		}
	}

	if (!locked) {
		w = scnprintf(next, size, "%s is busy.\n", sem->litmus_lock.name);
		size -= w;
		next += w;
		return count - size;
	}

	w = scnprintf(next, size, "nr_replicas: %u\n", sem->nr_replicas); size -= w; next += w;
	w = scnprintf(next, size, "max_fifo_len: %u\n", sem->max_fifo_len); size -= w; next += w;
	w = scnprintf(next, size, "max_in_fifos: %u\n", sem->max_in_fifos); size -= w; next += w;
	w = scnprintf(next, size, "current nr_in_fifos: %u\n", sem->nr_in_fifos); size -= w; next += w;
	w = scnprintf(next, size, "nr in top-m: %u\n\n", sem->top_m_size); size -= w; next += w;

	for (i = 0; i < sem->nr_replicas; ++i)
	{
		struct fifo_queue *fq = &sem->fifo_queues[i];
		w = scnprintf(next, size, "replica %d: owner = %s/%d (Virtually Unlocked = %u), hp waiter = %s/%d, length = %u\n",
					  i,
					  (fq->owner) ? fq->owner->comm : "null",
					  (fq->owner) ? fq->owner->pid : 0,
					  fq->is_vunlocked,
					  (fq->hp_waiter) ? fq->hp_waiter->comm : "null",
					  (fq->hp_waiter) ? fq->hp_waiter->pid : 0,
					  fq->count);
		size -= w; next += w;


		if (waitqueue_active(&fq->wait)) {
			struct list_head *pos;
			list_for_each(pos, &fq->wait.task_list) {
				wait_queue_t *q = list_entry(pos, wait_queue_t, task_list);
				struct task_struct *blocked_task = (struct task_struct*) q->private;
				w = scnprintf(next, size,
							  "\t%s/%d (inh: %s/%d)\n",
							  blocked_task->comm, blocked_task->pid,
							  (tsk_rt(blocked_task)->inh_task) ?
                              tsk_rt(blocked_task)->inh_task->comm : "null",
							  (tsk_rt(blocked_task)->inh_task) ?
                              tsk_rt(blocked_task)->inh_task->pid : 0);
				size -= w;
				next += w;
			}
		}
		else {
			w = scnprintf(next, size, "\t<NONE>\n");
			size -= w;
			next += w;
		}
	}

	if (binheap_empty(&sem->priority_queue)) {
		w = scnprintf(next, size, "pq:\n\t<NONE>\n");
		size -= w;
		next += w;
	}
	else {
		w = scnprintf(next, size, "donors:\n"); size -= w; next += w;
		binheap_for_each(&sem->priority_queue, __r2dglp_pq_to_proc, &heap_args);
	}

	if (binheap_empty(&sem->donors)) {
		w = scnprintf(next, size, "donors:\n\t<NONE>\n");
		size -= w;
		next += w;
	}
	else {
		w = scnprintf(next, size, "donors:\n"); size -= w; next += w;
		sbinheap_for_each(&sem->donors, __r2dglp_donor_to_proc, &heap_args);
	}

	raw_spin_unlock_irqrestore(&sem->real_lock, flags);

	return count - size;
}

static void r2dglp_proc_add(struct litmus_lock *l)
{
	if (!l->name)
		l->name = kmalloc(LOCK_NAME_LEN*sizeof(char), GFP_KERNEL);
	snprintf(l->name, LOCK_NAME_LEN, "r2dglp-%d", l->ident);
	litmus_add_proc_lock(l, r2dglp_proc_print);
}

static void r2dglp_proc_remove(struct litmus_lock *l)
{
	if (l->name) {
		litmus_remove_proc_lock(l);

		kfree(l->name);
		l->name = NULL;
	}
}

static struct litmus_lock_proc_ops r2dglp_proc_ops =
{
	.add = r2dglp_proc_add,
	.remove = r2dglp_proc_remove
};
#endif
