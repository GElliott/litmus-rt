#include <linux/sched.h>
#include <litmus/litmus.h>
#include <litmus/fdso.h>

#ifdef CONFIG_LITMUS_LOCKING

#include <linux/sched.h>
#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/trace.h>
#include <litmus/litmus.h>
#include <litmus/wait.h>
#include <litmus/sched_trace.h>

#ifdef CONFIG_LITMUS_DGL_SUPPORT
#include <linux/uaccess.h>
#endif

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#endif

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/jobs.h>
#endif

static int create_generic_lock(void** obj_ref, obj_type_t type,
				void* __user arg);
static int open_generic_lock(struct od_table_entry* entry,
				void* __user arg);
static int close_generic_lock(struct od_table_entry* entry);
static void destroy_generic_lock(obj_type_t type, void* sem);

struct fdso_ops generic_lock_ops = {
	.create  = create_generic_lock,
	.open    = open_generic_lock,
	.close   = close_generic_lock,
	.destroy = destroy_generic_lock
};

static atomic_t lock_id_gen = ATOMIC_INIT(0);


static inline bool is_lock(struct od_table_entry* entry)
{
	return entry->class == &generic_lock_ops;
}

static inline struct litmus_lock* get_lock(struct od_table_entry* entry)
{
	BUG_ON(!is_lock(entry));
	return (struct litmus_lock*) entry->obj->obj;
}

static int create_generic_lock(void** obj_ref, obj_type_t type,
				void* __user arg)
{
	struct litmus_lock* lock;
	int err;

	err = litmus->allocate_lock(&lock, type, arg);
	if (err == 0) {
#ifdef CONFIG_LITMUS_NESTED_LOCKING
		lock->nest.lock = lock;
		lock->nest.hp_waiter_eff_prio = NULL;

		INIT_BINHEAP_NODE(&lock->nest.hp_binheap_node);
		if(!lock->nest.hp_waiter_ptr) {
			TRACE_CUR("BEWARE: hp_waiter_ptr should probably not be NULL in "
					  "most cases. (exception: R2DGLP donors)\n");
		}
#endif
		lock->type = type;
		lock->ident = atomic_inc_return(&lock_id_gen);
		*obj_ref = lock;

		TRACE_CUR("Lock %d (%p) created. Type = %d\n.",
						lock->ident, lock, type);

		if (lock->proc && lock->proc->add)
			lock->proc->add(lock);
    }
	return err;
}

static int open_generic_lock(struct od_table_entry* entry, void* __user arg)
{
	struct litmus_lock* lock = get_lock(entry);
	if (lock->ops->open)
		return lock->ops->open(lock, arg);
	else
		return 0; /* default: any task can open it */
}

static int close_generic_lock(struct od_table_entry* entry)
{
	struct litmus_lock* lock = get_lock(entry);
	if (lock->ops->close)
		return lock->ops->close(lock);
	else
		return 0; /* default: closing succeeds */
}

static void destroy_generic_lock(obj_type_t type, void* obj)
{
	struct litmus_lock* lock = (struct litmus_lock*) obj;
	lock->ops->deallocate(lock);
}

asmlinkage long sys_litmus_lock(int lock_od)
{
	long err = -EINVAL;
	struct od_table_entry* entry;
	struct litmus_lock* l;
	unsigned long flags;

	TS_SYSCALL_IN_START;

	TS_SYSCALL_IN_END;

	TS_LOCK_START;

	entry = get_entry_for_od(lock_od);
	if (entry && is_lock(entry)) {
		l = get_lock(entry);
		TRACE_CUR("Attempts to lock %d\n", l->ident);

		local_irq_save(flags);
		err = l->ops->lock(l);
		if (!err) {
			sched_trace_lock(current, l->ident, 1);

			TRACE_CUR("Got lock %d\n", l->ident);

			if (tsk_rt(current)->outermost_lock == NULL) {
				TRACE_CUR("Lock %d is outermost lock.\n", l->ident);
				tsk_rt(current)->outermost_lock = l;
			}
		}
		flush_pending_wakes();
		local_irq_restore(flags);
	}

	/* Note: task my have been suspended or preempted in between! Take this
	 * into account when computing overheads. */
	TS_LOCK_END;

	TS_SYSCALL_OUT_START;

	return err;
}

asmlinkage long sys_litmus_unlock(int lock_od)
{
	long err = -EINVAL;
	struct od_table_entry* entry;
	struct litmus_lock* l;
	unsigned long flags;

	TS_SYSCALL_IN_START;

	TS_SYSCALL_IN_END;

	TS_UNLOCK_START;

	entry = get_entry_for_od(lock_od);
	if (entry && is_lock(entry)) {
		l = get_lock(entry);

		if (l == tsk_rt(current)->outermost_lock) {
			TRACE_CUR("Lock %d assumed to be outermost lock.\n", l->ident);
			tsk_rt(current)->outermost_lock = NULL;
		}

		TRACE_CUR("Attempts to unlock %d\n", l->ident);
		local_irq_save(flags);
		err = l->ops->unlock(l);
		if (!err) {
			sched_trace_lock(current, l->ident, 0);
			TRACE_CUR("Unlocked %d\n", l->ident);
		}
		flush_pending_wakes();
		local_irq_restore(flags);
	}

	/* Note: task my have been preempted in between!  Take this into
	 * account when computing overheads. */
	TS_UNLOCK_END;

	TS_SYSCALL_OUT_START;

	return err;
}

asmlinkage long sys_litmus_should_yield_lock(int lock_od)
{
	long err = -EINVAL;
	struct od_table_entry* entry;
	struct litmus_lock* l;

	entry = get_entry_for_od(lock_od);
	if (entry && is_lock(entry)) {
		l = get_lock(entry);

		if (l->ops->should_yield_lock) {
			TRACE_CUR("Checking to see if should yield lock %d\n", l->ident);
			err = l->ops->should_yield_lock(l);
		}
		else {
			TRACE_CUR("Lock %d does not support yielding.\n", l->ident);
			err = 0; /* report back "no, don't unlock" */
		}
	}

	return err;
}


struct task_struct* __waitqueue_remove_first(wait_queue_head_t *wq)
{
	wait_queue_t* q;
	struct task_struct* t = NULL;

	if (waitqueue_active(wq)) {
		q = list_entry(wq->task_list.next,
			       wait_queue_t, task_list);
		t = (struct task_struct*) q->private;
		__remove_wait_queue(wq, q);
	}
	return(t);
}

#ifdef CONFIG_LITMUS_NESTED_LOCKING

void print_hp_waiters(struct binheap_node* n, int depth)
{
	struct litmus_lock *l;
	struct nested_info *nest;
	char padding[81] = "                                                                                ";
	struct task_struct *hp = NULL;
	struct task_struct *hp_eff = NULL;
	struct task_struct *node_prio = NULL;


	if(n == NULL) {
		TRACE("+-> %p\n", NULL);
		return;
	}

	nest = binheap_entry(n, struct nested_info, hp_binheap_node);
	l = nest->lock;

	if(depth*2 <= 80)
		padding[depth*2] = '\0';

	if(nest->hp_waiter_ptr && *(nest->hp_waiter_ptr)) {
		hp = *(nest->hp_waiter_ptr);

		if(tsk_rt(hp)->inh_task) {
			hp_eff = tsk_rt(hp)->inh_task;
		}
	}

	node_prio = nest->hp_waiter_eff_prio;

	TRACE("%s+-> %s/%d [waiter = %s/%d] [waiter's inh = %s/%d] (lock = %d)\n",
		  padding,
		  (node_prio) ? node_prio->comm : "null",
		  (node_prio) ? node_prio->pid : 0,
		  (hp) ? hp->comm : "null",
		  (hp) ? hp->pid : 0,
		  (hp_eff) ? hp_eff->comm : "null",
		  (hp_eff) ? hp_eff->pid : 0,
		  l->ident);

    if(n->left) print_hp_waiters(n->left, depth+1);
    if(n->right) print_hp_waiters(n->right, depth+1);
}
#endif


#ifdef CONFIG_LITMUS_DGL_SUPPORT

struct litmus_lock* select_next_lock(dgl_wait_state_t* dgl_wait)
{
	int num_locks = dgl_wait->size;
	int last = dgl_wait->last_primary;
	int start;
	int idx;

	/*
	 We pick the next lock in reverse order. This causes inheritance propagation
	 from locks received earlier to flow in the same direction as regular nested
	 locking. This might make fine-grain DGL easier in the future.
	 */

	BUG_ON(tsk_rt(dgl_wait->task)->blocked_lock);

	/* Try to enable priority on a lock that has an owner.
	   Note reverse loop iteration order */
	idx = start = (last != 0) ? last - 1 : num_locks - 1;
	do {
		struct litmus_lock *l = dgl_wait->locks[idx];

		if(!l->ops->is_owner(l, dgl_wait->task) && l->ops->get_owner(l)) {
			dgl_wait->last_primary = idx;
			tsk_rt(dgl_wait->task)->blocked_lock = l;
			mb();
			TRACE_TASK(dgl_wait->task, "New blocked lock is %d\n", l->ident);
			l->ops->enable_priority(l, dgl_wait);
			return(l);
		}
		idx = (idx != 0) ? idx - 1 : num_locks - 1;
	} while(idx != start);

	/* There was no one to push on.  This can happen if the blocked task is
	   behind a task that is idling a prioq-mutex.
	   Note reverse order. */
	idx = (last != 0) ? last - 1 : num_locks - 1;
	do {
		struct litmus_lock *l = dgl_wait->locks[idx];

		if(!l->ops->is_owner(l, dgl_wait->task)) {
			dgl_wait->last_primary = idx;
			tsk_rt(dgl_wait->task)->blocked_lock = l;
			mb();
			TRACE_TASK(dgl_wait->task, "New blocked lock is %d\n", l->ident);
			l->ops->enable_priority(l, dgl_wait);
			return(l);
		}
		idx = (idx != 0) ? idx - 1 : num_locks - 1;
	} while(idx != start);

	return(NULL);
}

int dgl_wake_up(wait_queue_t *wq_node, unsigned mode, int sync, void *key)
{
	BUG();
	return 1;
}

struct task_struct* __waitqueue_dgl_remove_first(wait_queue_head_t *wq,
								  dgl_wait_state_t** dgl_wait)
{
	wait_queue_t *q;
	struct task_struct *task = NULL;

	*dgl_wait = NULL;

	if (waitqueue_active(wq)) {
		q = list_entry(wq->task_list.next,
					   wait_queue_t, task_list);

		if(q->func == dgl_wake_up) {
			*dgl_wait = (dgl_wait_state_t*) q->private;
			task = (*dgl_wait)->task;
		}
		else {
			task = (struct task_struct*) q->private;
		}

		__remove_wait_queue(wq, q);
	}
	return task;
}

void init_dgl_wait_state(dgl_wait_state_t *dgl_wait)
{
	memset(dgl_wait, 0, sizeof(dgl_wait_state_t));
}

void init_dgl_waitqueue_entry(wait_queue_t *wq_node, dgl_wait_state_t *dgl_wait)
{
	init_waitqueue_entry(wq_node, dgl_wait->task);
	wq_node->private = dgl_wait;
	wq_node->func = dgl_wake_up;
}

#ifdef CONFIG_SCHED_DEBUG_TRACE
static void snprintf_dgl(char* buf, size_t bsz, struct litmus_lock* dgl_locks[],
				int sz)
{
	int i;
	char* ptr;

	ptr = buf;
	for(i = 0; i < sz && ptr < buf+bsz; ++i) {
		struct litmus_lock *l = dgl_locks[i];
		int remaining = bsz - (ptr-buf);
		int written;

		if(i == 0)
			written = snprintf(ptr, remaining, "%d ", l->ident);
		else if(i == sz - 1)
			written = snprintf(ptr, remaining, " %d", l->ident);
		else
			written = snprintf(ptr, remaining, " %d ", l->ident);
		ptr += written;
	}
}
#endif


/* only valid when locks are prioq locks!!!
 * THE BIG DGL LOCK MUST BE HELD! */
int __attempt_atomic_dgl_acquire(struct litmus_lock *cur_lock,
				dgl_wait_state_t *dgl_wait)
{
	int i;

	/* check to see if we can take all the locks */
	for(i = 0; i < dgl_wait->size; ++i) {
		struct litmus_lock *l = dgl_wait->locks[i];
		if(!l->ops->dgl_can_quick_lock(l, dgl_wait->task)) {
			return -1;
		}
	}

	/* take the locks */
	for(i = 0; i < dgl_wait->size; ++i) {
		struct litmus_lock *l = dgl_wait->locks[i];
		l->ops->dgl_quick_lock(l, cur_lock, dgl_wait->task,
						&dgl_wait->wq_nodes[i]);

		sched_trace_lock(dgl_wait->task, l->ident, 1);

		BUG_ON(!(l->ops->is_owner(l, dgl_wait->task)));
	}

	return 0; /* success */
}


static long do_litmus_dgl_lock(dgl_wait_state_t *dgl_wait)
{
	int i;
	unsigned long irqflags;
	unsigned long kludge_flags;
	raw_spinlock_t *dgl_lock;

#ifdef CONFIG_SCHED_DEBUG_TRACE
	{
		char dglstr[MAX_DGL_SIZE*5];
		snprintf_dgl(dglstr, dgl_wait->size*5, dgl_wait->locks, dgl_wait->size);
		TRACE_CUR("Locking DGL with size %d: %s\n", dgl_wait->size, dglstr);
	}
#endif

	BUG_ON(dgl_wait->task != current);

	dgl_wait->nr_remaining = dgl_wait->size;

	dgl_lock = litmus->get_dgl_spinlock(dgl_wait->task);

	local_irq_save(kludge_flags);
	raw_spin_lock_irqsave(dgl_lock, irqflags);

	/* Try to acquire each lock. Enqueue (non-blocking) if it is unavailable. */
	for(i = 0; i < dgl_wait->size; ++i) {
		struct litmus_lock *tmp = dgl_wait->locks[i];

		/* dgl_lock() must set task state to TASK_UNINTERRUPTIBLE
		   if task blocks. */

		if(tmp->ops->dgl_lock(tmp, dgl_wait, &dgl_wait->wq_nodes[i])) {
			sched_trace_lock(dgl_wait->task, tmp->ident, 1);
			--(dgl_wait->nr_remaining);
			TRACE_CUR("Acquired lock %d immediatly.\n", tmp->ident);
		}
	}

	if(dgl_wait->nr_remaining == 0) {
		/* acquired entire group immediatly */
		TRACE_CUR("Acquired all locks in DGL immediatly!\n");
		raw_spin_unlock_irqrestore(dgl_lock, irqflags);
		local_irq_restore(kludge_flags);
	}
	else {
		struct litmus_lock *first_primary;

		TRACE_CUR("As many as %d locks in DGL are pending. Suspending.\n",
				  dgl_wait->nr_remaining);

		first_primary = select_next_lock(dgl_wait);

		BUG_ON(!first_primary);

		TRACE_CUR("Suspending for lock %d\n", first_primary->ident);

		TS_DGL_LOCK_SUSPEND;

		/* free dgl_lock before suspending */
		raw_spin_unlock_irqrestore(dgl_lock, irqflags);
		flush_pending_wakes();
		local_irq_restore(kludge_flags);
		suspend_for_lock();

		TS_DGL_LOCK_RESUME;

		TRACE_CUR("Woken up from DGL suspension.\n");
	}

	TRACE_CUR("Acquired entire DGL\n");

	return 0;
}



static long do_litmus_dgl_atomic_lock(dgl_wait_state_t *dgl_wait)
{
	int i;
	unsigned long irqflags;
	unsigned long kludge_flags;
	raw_spinlock_t *dgl_lock;
	struct task_struct *t = current;

#ifdef CONFIG_SCHED_DEBUG_TRACE
	{
		char dglstr[MAX_DGL_SIZE*5];
		snprintf_dgl(dglstr, dgl_wait->size*5, dgl_wait->locks, dgl_wait->size);
		TRACE_CUR("Atomic locking DGL with size %d: %s\n", dgl_wait->size, dglstr);
	}
#endif

	dgl_lock = litmus->get_dgl_spinlock(dgl_wait->task);

	BUG_ON(dgl_wait->task != t);

	local_irq_save(kludge_flags);
	raw_spin_lock_irqsave(dgl_lock, irqflags);


	dgl_wait->nr_remaining = dgl_wait->size;

	/* enqueue for all locks */
	for(i = 0; i < dgl_wait->size; ++i) {
		/* dgl_lock must only enqueue.  cannot set TASK_UNINTERRUPTIBLE!!
		 * Note the difference in requirements with do_litmus_dgl_lock().
		 */
		struct litmus_lock *tmp = dgl_wait->locks[i];
		tmp->ops->dgl_lock(tmp, dgl_wait, &dgl_wait->wq_nodes[i]);
	}

	/* now try to take all locks */
	if(__attempt_atomic_dgl_acquire(NULL, dgl_wait)) {
		struct litmus_lock *l;

		/* Failed to acquire all locks at once.
		 * Pick a lock to push on and suspend. */
		TRACE_CUR("Could not atomically acquire all locks.\n");

		/* we set the uninterruptible state here since
		 * __attempt_atomic_dgl_acquire() may actually succeed. */
		set_task_state(t, TASK_UNINTERRUPTIBLE);

		l = select_next_lock(dgl_wait);

		TRACE_CUR("Suspending for lock %d\n", l->ident);

		TS_DGL_LOCK_SUSPEND;

		/* free dgl_lock before suspending */
		raw_spin_unlock_irqrestore(dgl_lock, irqflags);
		flush_pending_wakes();
		local_irq_restore(kludge_flags);
		suspend_for_lock();

		TS_DGL_LOCK_RESUME;

		TRACE_CUR("Woken up from DGL suspension.\n");

		goto all_acquired;  /* we should hold all locks when we wake up. */
	}
	raw_spin_unlock_irqrestore(dgl_lock, irqflags);
	flush_pending_wakes();
	local_irq_restore(kludge_flags);

all_acquired:

	dgl_wait->nr_remaining = 0;

	TRACE_CUR("Acquired entire DGL\n");

	return 0;
}


asmlinkage long sys_litmus_dgl_lock(void* __user usr_dgl_ods, int dgl_size)
{
	struct task_struct *t = current;
	long err = -EINVAL;
	int dgl_ods[MAX_DGL_SIZE];

	if(dgl_size > MAX_DGL_SIZE || dgl_size < 1)
		goto out;

	if(!access_ok(VERIFY_READ, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;

	if(__copy_from_user(&dgl_ods, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;

	if (!is_realtime(t)) {
		err = -EPERM;
		goto out;
	}

	if (dgl_size == 1) {
		/* DGL size of 1. Just call regular singular lock. */
		TRACE_CUR("DGL lock with size = 1. Treating as regular lock.\n");
		err = sys_litmus_lock(dgl_ods[0]);
	}
	else {
		int i;
		int num_need_atomic = 0;

		/* lives on the stack until all resources in DGL are held. */
		dgl_wait_state_t dgl_wait_state;

		init_dgl_wait_state(&dgl_wait_state);

		for(i = 0; i < dgl_size; ++i) {
			struct od_table_entry *entry = get_entry_for_od(dgl_ods[i]);
			if(entry && is_lock(entry)) {
				dgl_wait_state.locks[i] = get_lock(entry);
				if(!dgl_wait_state.locks[i]->ops->supports_dgl) {
					TRACE_CUR("Lock %d does not support all required "
							"DGL operations.\n",
							 dgl_wait_state.locks[i]->ident);
					goto out;
				}

				if(dgl_wait_state.locks[i]->ops->requires_atomic_dgl) {
					++num_need_atomic;
				}
			}
			else {
				TRACE_CUR("Invalid lock identifier\n");
				goto out;
			}
		}

		if (num_need_atomic && num_need_atomic != dgl_size) {
			TRACE_CUR("All locks in DGL must support atomic "
					"acquire if any one does.\n");
			goto out;
		}

		dgl_wait_state.task = t;
		dgl_wait_state.size = dgl_size;

		TS_DGL_LOCK_START;
		if (!num_need_atomic)
			err = do_litmus_dgl_lock(&dgl_wait_state);
		else
			err = do_litmus_dgl_atomic_lock(&dgl_wait_state);

		/* Note: task my have been suspended or preempted in between!  Take
		 * this into account when computing overheads. */
		TS_DGL_LOCK_END;
	}

out:
	return err;
}

static long do_litmus_dgl_unlock(struct litmus_lock* dgl_locks[], int dgl_size)
{
	int i;
	long err = 0;
	unsigned long flags;

#ifdef CONFIG_SCHED_DEBUG_TRACE
	{
		char dglstr[MAX_DGL_SIZE*5];
		snprintf_dgl(dglstr, dgl_size*5, dgl_locks, dgl_size);
		TRACE_CUR("Unlocking a DGL with size %d: %s\n", dgl_size, dglstr);
	}
#endif

	local_irq_save(flags);
	for(i = dgl_size - 1; i >= 0; --i) {  /* unlock in reverse order */

		struct litmus_lock *l = dgl_locks[i];
		long tmp_err;

		TRACE_CUR("Unlocking lock %d of DGL.\n", l->ident);

		tmp_err = l->ops->unlock(l);
		sched_trace_lock(current, l->ident, 0);

		if(tmp_err) {
			TRACE_CUR("There was an error unlocking %d: %d.\n",
							l->ident, tmp_err);
			err = tmp_err;
		}
	}
	flush_pending_wakes();
	local_irq_restore(flags);

	TRACE_CUR("DGL unlocked. err = %d\n", err);

	return err;
}

asmlinkage long sys_litmus_dgl_unlock(void* __user usr_dgl_ods, int dgl_size)
{
	long err = -EINVAL;
	int dgl_ods[MAX_DGL_SIZE];

	if(dgl_size > MAX_DGL_SIZE || dgl_size < 1)
		goto out;

	if(!access_ok(VERIFY_READ, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;

	if(__copy_from_user(&dgl_ods, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;


	if (dgl_size == 1) {
		/* DGL size of 1. Just call regular singular lock. */
		TRACE_CUR("DGL unlock with size = 1. Treating as regular unlock.\n");
		err = sys_litmus_unlock(dgl_ods[0]);
	}
	else {
		struct litmus_lock *dgl_locks[MAX_DGL_SIZE];
		int i;
		for(i = 0; i < dgl_size; ++i) {
			struct od_table_entry *entry = get_entry_for_od(dgl_ods[i]);
			if(entry && is_lock(entry)) {
				dgl_locks[i] = get_lock(entry);
				if(!dgl_locks[i]->ops->supports_dgl) {
					TRACE_CUR("Lock %d does not support all required "
							"DGL operations.\n",
							dgl_locks[i]->ident);
					goto out;
				}
			}
			else {
				TRACE_CUR("Invalid lock identifier\n");
				goto out;
			}
		}

		TS_DGL_UNLOCK_START;
		err = do_litmus_dgl_unlock(dgl_locks, dgl_size);

		/* Note: task my have been suspended or preempted in between!  Take
		 * this into account when computing overheads. */
		TS_DGL_UNLOCK_END;
	}

out:
	return err;
}

asmlinkage long sys_litmus_dgl_should_yield_lock(void* __user usr_dgl_ods,
				int dgl_size)
{
	long err = -EINVAL;
	int dgl_ods[MAX_DGL_SIZE];

	if(dgl_size > MAX_DGL_SIZE || dgl_size < 1)
		goto out;

	if(!access_ok(VERIFY_READ, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;

	if(__copy_from_user(&dgl_ods, usr_dgl_ods, dgl_size*(sizeof(*dgl_ods))))
		goto out;


	if (dgl_size == 1) {
		/* DGL size of 1. Just call regular singular lock. */
		TRACE_CUR("Treating as regular lock.\n");
		err = sys_litmus_should_yield_lock(dgl_ods[0]);
	}
	else {
		unsigned long flags;
		int i;
		err = 0;

		local_irq_save(flags);

		for(i = 0; (i < dgl_size) && (0 == err); ++i) {
			struct od_table_entry *entry = get_entry_for_od(dgl_ods[i]);
			if (entry && is_lock(entry)) {
				struct litmus_lock *l = get_lock(entry);
				if (l->ops->should_yield_lock) {
					TRACE_CUR("Checking to see if should yield lock %d\n",
									l->ident);
					err = l->ops->should_yield_lock(l);
				}
				else {
					TRACE_CUR("Lock %d does not support yielding.\n", l->ident);
				}
			}
			else {
				TRACE_CUR("Invalid lock identifier\n");
				err = -EINVAL;
			}
		}

		local_irq_restore(flags);
	}

out:
	return err;
}


#else  /* CONFIG_LITMUS_DGL_SUPPORT */

asmlinkage long sys_litmus_dgl_lock(void* __user usr_dgl_ods, int dgl_size)
{
	return -ENOSYS;
}

asmlinkage long sys_litmus_dgl_unlock(void* __user usr_dgl_ods, int dgl_size)
{
	return -ENOSYS;
}

asmlinkage long sys_litmus_dgl_should_yield_lock(void* __user usr_dgl_ods,
				int dgl_size)
{
	return -ENOSYS;
}

#endif

unsigned int __add_wait_queue_prio_exclusive(
	wait_queue_head_t* head,
	prio_wait_queue_t *new)
{
	struct list_head *pos;
	unsigned int passed = 0;

	new->wq.flags |= WQ_FLAG_EXCLUSIVE;

	/* find a spot where the new entry is less than the next */
	list_for_each(pos, &head->task_list) {
		prio_wait_queue_t* queued = list_entry(pos, prio_wait_queue_t,
						       wq.task_list);

		if (unlikely(lt_before(new->priority, queued->priority) ||
			     (new->priority == queued->priority &&
			      new->tie_breaker < queued->tie_breaker))) {
			/* pos is not less than new, thus insert here */
			__list_add(&new->wq.task_list, pos->prev, pos);
			goto out;
		}
		passed++;
	}

	/* if we get to this point either the list is empty or every entry
	 * queued element is less than new.
	 * Let's add new to the end. */
	list_add_tail(&new->wq.task_list, &head->task_list);
out:
	return passed;
}


void suspend_for_lock(void)
{
#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
	struct task_struct *t = current;
#endif

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
	DECLARE_WORKER_VIS_FLAGS(vis_flags);
	hide_from_workers(t, &vis_flags);
#endif

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
	/* disable tracking */
	if(tsk_rt(t)->held_gpus) {
		/* tracking is actually stopped in schedule(), where it
		   is also stopped upon preemption */
		tsk_rt(t)->suspend_gpu_tracker_on_block = 1;
	}
#endif

	schedule();

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
	/* re-enable tracking */
	if(tsk_rt(t)->held_gpus)
		tsk_rt(t)->suspend_gpu_tracker_on_block = 0;
#endif

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
	show_to_workers(t, &vis_flags);
#endif
}

#define WAKE_Q_SZ	32

typedef struct wake_queue
{
	struct task_struct *to_wake[WAKE_Q_SZ];
	int count;
} wake_queue_t;

DEFINE_PER_CPU(wake_queue_t, wqueues);

void init_wake_queues()
{
	int cpu = 0;
	for_each_online_cpu(cpu) {
		wake_queue_t *q = &per_cpu(wqueues, cpu);
		memset(q, 0, sizeof(*q));
	}
}

int wake_up_for_lock(struct task_struct* t)
{
	/* queues up wakes for waking on unlock exit */

	int ret = 1; /* mimic success of wake_up_process() */
	wake_queue_t *q;

	TRACE_TASK(t, "is queued for wakeup\n");
	q = &per_cpu(wqueues, smp_processor_id());
	q->to_wake[q->count] = t;
	++(q->count);

	BUG_ON(q->count >= WAKE_Q_SZ);

	return ret;
}

int flush_pending_wakes()
{
	int count = 0, i;
	wake_queue_t *q;

	q = &per_cpu(wqueues, smp_processor_id());
	for(i = 0; i < q->count; ++i) {
		if (q->to_wake[i]) {
			struct task_struct *t = q->to_wake[i];
			q->to_wake[i] = NULL;

			TRACE_TASK(t, "is being woken up\n");
			wake_up_process(t);
			++count;
		}
	}
	WARN_ON(count != q->count);
	q->count = 0;

	return count;
}

void set_inh_task_linkback(struct task_struct* t, struct task_struct* linkto)
{
    const int MAX_IDX = BITS_PER_LONG - 1;

    int success = 0;
    int old_idx = tsk_rt(t)->inh_task_linkback_idx;

    /* is the linkback already set? */
    if (old_idx >= 0 && old_idx <= MAX_IDX) {
        if ((BIT_MASK(old_idx) & tsk_rt(linkto)->used_linkback_slots) &&
            (tsk_rt(linkto)->inh_task_linkbacks[old_idx] == t)) {
            TRACE_TASK(t, "linkback is current.\n");
            return;
        }
        BUG();
    }

    /* kludge: upper limit on num linkbacks */
    BUG_ON(tsk_rt(linkto)->used_linkback_slots == ~0ul);

    while(!success) {
        int b = find_first_zero_bit(&tsk_rt(linkto)->used_linkback_slots,
                    BITS_PER_BYTE*sizeof(tsk_rt(linkto)->used_linkback_slots));

        BUG_ON(b > MAX_IDX);

        /* set bit... */
        if (!test_and_set_bit(b, &tsk_rt(linkto)->used_linkback_slots)) {
            TRACE_TASK(t, "linking back to %s/%d in slot %d\n",
							linkto->comm, linkto->pid, b);
            if (tsk_rt(linkto)->inh_task_linkbacks[b])
                TRACE_TASK(t, "%s/%d already has %s/%d in slot %d\n",
                           linkto->comm, linkto->pid,
                           tsk_rt(linkto)->inh_task_linkbacks[b]->comm,
                           tsk_rt(linkto)->inh_task_linkbacks[b]->pid,
                           b);

            /* TODO: allow dirty data to remain in [b] after code is tested */
            BUG_ON(tsk_rt(linkto)->inh_task_linkbacks[b] != NULL);
            /* ...before setting slot */
            tsk_rt(linkto)->inh_task_linkbacks[b] = t;
            tsk_rt(t)->inh_task_linkback_idx = b;
            success = 1;
        }
    }
}

void clear_inh_task_linkback(struct task_struct* t,
				struct task_struct* linkedto)
{
    const int MAX_IDX = BITS_PER_LONG - 1;

    int success = 0;
    int slot = tsk_rt(t)->inh_task_linkback_idx;

    if (slot < 0) {
        TRACE_TASK(t, "assuming linkback already cleared.\n");
        return;
    }

    BUG_ON(slot > MAX_IDX);
    BUG_ON(tsk_rt(linkedto)->inh_task_linkbacks[slot] != t);

    /* be safe - clear slot before clearing the bit */
    tsk_rt(t)->inh_task_linkback_idx = -1;
    tsk_rt(linkedto)->inh_task_linkbacks[slot] = NULL;

    success = test_and_clear_bit(slot, &tsk_rt(linkedto)->used_linkback_slots);

    BUG_ON(!success);
}

#else  /* CONFIG_LITMUS_LOCKING */

struct fdso_ops generic_lock_ops = {};

asmlinkage long sys_litmus_lock(int sem_od)
{
	return -ENOSYS;
}

asmlinkage long sys_litmus_unlock(int sem_od)
{
	return -ENOSYS;
}

#endif /* end CONFIG_LITMUS_LOCKING */
