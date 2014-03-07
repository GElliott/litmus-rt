#ifndef LITMUS_LOCKING_H
#define LITMUS_LOCKING_H

#include <linux/list.h>

#if defined(CONFIG_DEBUG_SPINLOCK) && defined(CONFIG_LITMUS_NESTED_LOCKING)
#include <linux/lockdep.h>
#endif

#include <litmus/binheap.h>

struct litmus_lock;
struct litmus_lock_ops;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
struct nested_info
{
	struct litmus_lock *lock;
	struct task_struct *hp_waiter_eff_prio;
	struct task_struct **hp_waiter_ptr;
    struct binheap_node hp_binheap_node;
};

static inline struct task_struct* top_priority(struct binheap* handle) {
	if(!binheap_empty(handle)) {
		return (struct task_struct*)(binheap_top_entry(handle,
			struct nested_info, hp_binheap_node)->hp_waiter_eff_prio);
	}
	return NULL;
}

void print_hp_waiters(struct binheap_node* n, int depth);
#endif

#define LOCK_NAME_LEN 32
struct litmus_lock_proc_ops {
	void (*add)(struct litmus_lock *l);
	void (*remove)(struct litmus_lock *l);
};



/* Generic base struct for LITMUS^RT userspace semaphores.
 * This structure should be embedded in protocol-specific semaphores.
 */
struct litmus_lock {
	struct litmus_lock_ops *ops;
	int type;

	int ident;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	struct nested_info nest;
#endif

	struct litmus_lock_proc_ops *proc;
	char *name;

#if defined(CONFIG_DEBUG_SPINLOCK) && defined(CONFIG_LITMUS_NESTED_LOCKING)
	/* We need to allow spinlocks to be acquired in a nested fashion without
	   triggering complaints from lockdep. These fields are used to assign a
	   unique lockdep class to each lock instance (the locks would all be of
	   the same lockdep class, otherwise).

	   Notes:
	   - A small change to lockdep is also require to enable non-static-memory
	     names/keys.
	   - Locks must still be acquired in a total order to avoid deadlock.
	 */
	struct lock_class_key lockdep_key;
#endif
};

#if defined(CONFIG_LITMUS_NESTED_LOCKING) && defined(CONFIG_DEBUG_SPINLOCK)
#define LOCKDEP_DYNAMIC_ALLOC(litlock, lock) \
	do { \
		lockdep_set_class_and_name((lock), \
			&((struct litmus_lock*)litlock)->lockdep_key, #litlock); \
	} while(0)
#else
#define LOCKDEP_DYNAMIC_ALLOC(litlock, lock) \
	do { (void)litlock; (void)lock; } while(0)
#endif

#ifdef CONFIG_LITMUS_DGL_SUPPORT

#define MAX_DGL_SIZE CONFIG_LITMUS_MAX_DGL_SIZE

typedef struct dgl_wait_state {
	struct task_struct *task;	/* task waiting on DGL */
	struct litmus_lock *locks[MAX_DGL_SIZE];	/* requested locks in DGL */
	int size;			/* size of the DGL */
	int nr_remaining;	/* nr locks remainging before DGL is complete */
	int last_primary;	/* index lock in locks[] that has active priority */
	wait_queue_t wq_nodes[MAX_DGL_SIZE];
} dgl_wait_state_t;

void wake_or_wait_on_next_lock(dgl_wait_state_t *dgl_wait);
struct litmus_lock* select_next_lock(dgl_wait_state_t* dgl_wait);

void init_dgl_wait_state(dgl_wait_state_t* dgl_wait);
void init_dgl_waitqueue_entry(wait_queue_t *wq_node,
				dgl_wait_state_t* dgl_wait);
int dgl_wake_up(wait_queue_t *wq_node, unsigned mode, int sync, void *key);
struct task_struct* __waitqueue_dgl_remove_first(wait_queue_head_t *wq,
				dgl_wait_state_t** dgl_wait);

int __attempt_atomic_dgl_acquire(struct litmus_lock *cur_lock,
				dgl_wait_state_t *dgl_wait);


static inline struct task_struct* get_queued_task_and_dgl_wait(wait_queue_t* q,
				dgl_wait_state_t** dgl_wait_ptr)
{
	struct task_struct *queued;

	if(q->func == dgl_wake_up) {
		*dgl_wait_ptr = (dgl_wait_state_t*) q->private;
		queued = (*dgl_wait_ptr)->task;
	}
	else {
		*dgl_wait_ptr = NULL;
		queued = (struct task_struct*) q->private;
	}

	return queued;
}
#endif


static inline struct task_struct* get_queued_task(wait_queue_t* q)
{
	struct task_struct *queued;
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	if(q->func == dgl_wake_up) {
		dgl_wait_state_t *dgl_wait = (dgl_wait_state_t*) q->private;
		queued = dgl_wait->task;
	}
	else {
		queued = (struct task_struct*) q->private;
	}
#else
	queued = (struct task_struct*) q->private;
#endif
	return queued;
}



typedef int (*lock_op_t)(struct litmus_lock *l);
typedef lock_op_t lock_close_t;
typedef lock_op_t lock_lock_t;
typedef lock_op_t lock_unlock_t;
typedef lock_op_t lock_should_yield_lock_t;

typedef int (*lock_open_t)(struct litmus_lock *l, void* __user arg);
typedef void (*lock_free_t)(struct litmus_lock *l);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
/* Assumes task's base-priority already updated to reflect new priority. */
typedef void (*lock_budget_exhausted_t)(struct litmus_lock* l,
				struct task_struct* t);
typedef void (*lock_omlp_virtual_unlock_t)(struct litmus_lock* l,
				struct task_struct* t);
#endif

struct litmus_lock_ops {
	/* Current task tries to obtain / drop a reference to a lock.
	 * Optional methods, allowed by default. */
	lock_open_t open;
	lock_close_t close;

	/* Current tries to lock/unlock this lock (mandatory methods). */
	lock_lock_t lock;
	lock_unlock_t unlock;
	lock_should_yield_lock_t should_yield_lock;

	/* The lock is no longer being referenced (mandatory method). */
	lock_free_t deallocate;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	lock_budget_exhausted_t	budget_exhausted;
	lock_omlp_virtual_unlock_t omlp_virtual_unlock;

	void (*propagate_increase_inheritance)(struct litmus_lock* l,
					struct task_struct* t,
					raw_spinlock_t* to_unlock, unsigned long irqflags);
	void (*propagate_decrease_inheritance)(struct litmus_lock* l,
					struct task_struct* t,
					raw_spinlock_t* to_unlock, unsigned long irqflags,
					int budget_triggered);
#endif
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	raw_spinlock_t* (*get_dgl_spin_lock)(struct litmus_lock *l);
	int (*dgl_lock)(struct litmus_lock *l, dgl_wait_state_t* dgl_wait,
					wait_queue_t* wq_node);
	int (*is_owner)(struct litmus_lock *l, struct task_struct *t);
	struct task_struct* (*get_owner)(struct litmus_lock *l);
	void (*enable_priority)(struct litmus_lock *l, dgl_wait_state_t* dgl_wait);

	int (*dgl_can_quick_lock)(struct litmus_lock *l, struct task_struct *t);
	void (*dgl_quick_lock)(struct litmus_lock *l, struct litmus_lock *cur_lock,
		  struct task_struct* t, wait_queue_t *q);
#endif

	/* all flags at the end */
	unsigned int supports_budget_exhaustion:1;
	unsigned int is_omlp_family:1;

#ifdef CONFIG_LITMUS_NESTED_LOCKING
	unsigned int supports_nesting:1;
#endif
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	unsigned int supports_dgl:1;
	unsigned int requires_atomic_dgl:1;
#endif
};


/*
 Nested inheritance can be achieved with fine-grain locking when there is
 no need for DGL support, presuming locks are acquired in a partial order
 (no cycles!).  However, DGLs allow locks to be acquired in any order.  This
 makes nested inheritance very difficult (we don't yet know a solution) to
 realize with fine-grain locks, so we use a big lock instead.

 Code contains both fine-grain and coarse-grain methods together, side-by-side.
 Each lock operation *IS NOT* surrounded by ifdef/endif to help make code more
 readable.  However, this leads to the odd situation where both code paths
 appear together in code as if they were both active together.

 THIS IS NOT REALLY THE CASE!  ONLY ONE CODE PATH IS ACTUALLY ACTIVE!

 Example:
	lock_global_irqsave(coarseLock, flags);
	lock_fine_irqsave(fineLock, flags);

 Reality (coarse):
	lock_global_irqsave(coarseLock, flags);
	//lock_fine_irqsave(fineLock, flags);

 Reality (fine):
	//lock_global_irqsave(coarseLock, flags);
	lock_fine_irqsave(fineLock, flags);

 Be careful when you read code involving nested inheritance.
 */
#if defined(CONFIG_LITMUS_DGL_SUPPORT)
/* DGL requires a big lock to implement nested inheritance */
#define lock_global_irqsave(lock, flags) \
		raw_spin_lock_irqsave((lock), (flags))
#define lock_global(lock) \
		raw_spin_lock((lock))
#define trylock_global_irqsave(lock, flags) \
		raw_spin_trylock_irqsave((lock), (flags))
#define trylock_global(lock) \
		raw_spin_trylock((lock))
#define unlock_global_irqrestore(lock, flags) \
		raw_spin_unlock_irqrestore((lock), (flags))
#define unlock_global(lock) \
		raw_spin_unlock((lock))

/* fine-grain locking are no-ops with DGL support */
#define lock_fine_irqsave(lock, flags)
#define lock_fine(lock)
#define trylock_fine_irqsave(lock, flags)
#define trylock_fine(lock)
#define unlock_fine_irqrestore(lock, flags)
#define unlock_fine(lock)

#elif defined(CONFIG_LITMUS_NESTED_LOCKING)
/* Use fine-grain locking when DGLs are disabled. */
/* global locking are no-ops without DGL support */
#define lock_global_irqsave(lock, flags)
#define lock_global(lock)
#define trylock_global_irqsave(lock, flags)
#define trylock_global(lock)
#define unlock_global_irqrestore(lock, flags)
#define unlock_global(lock)

#define lock_fine_irqsave(lock, flags) \
		raw_spin_lock_irqsave((lock), (flags))
#define lock_fine(lock) \
		raw_spin_lock((lock))
#define trylock_fine_irqsave(lock, flags) \
		raw_spin_trylock_irqsave((lock), (flags))
#define trylock_fine(lock) \
		raw_spin_trylock((lock))
#define unlock_fine_irqrestore(lock, flags) \
		raw_spin_unlock_irqrestore((lock), (flags))
#define unlock_fine(lock) \
		raw_spin_unlock((lock))
#endif


void suspend_for_lock(void);
int wake_up_for_lock(struct task_struct* t);
void flush_pending_wakes(void);
void init_wake_queues(void);

/* thread safe?? */
#ifndef CONFIG_LITMUS_NESTED_LOCKING
#define holds_locks(t) \
	(tsk_rt(t)->num_locks_held || tsk_rt(t)->num_local_locks_held)
#else
#define holds_locks(t) \
	(tsk_rt(t)->num_locks_held || \
	 tsk_rt(t)->num_local_locks_held || \
	 !binheap_empty(&tsk_rt(t)->hp_blocked_tasks))
#endif

void set_inh_task_linkback(struct task_struct* t, struct task_struct* linkto);
void clear_inh_task_linkback(struct task_struct* t,
				struct task_struct* linkedto);

#endif
