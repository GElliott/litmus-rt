#ifndef LITMUS_PRIOQ_H
#define LITMUS_PRIOQ_H

#include <litmus/litmus.h>
#include <litmus/binheap.h>
#include <litmus/locking.h>

/* struct for semaphore with priority inheritance */
struct prioq_mutex {
	struct litmus_lock litmus_lock;

	/* current resource holder */
	struct task_struct *owner;

	/* highest-priority waiter */
	struct task_struct *hp_waiter;

	/* priority-ordered queue of waiting tasks.
	 * Ironically, we don't use a binheap because that would make DGL
	 * implementation a LOT harder. */
	wait_queue_head_t	wait;

	/* we do some nesting within spinlocks, so we can't use the normal
	 sleeplocks found in wait_queue_head_t. */
	raw_spinlock_t		lock;
};

static inline struct prioq_mutex* prioq_mutex_from_lock(struct litmus_lock* lock)
{
	return container_of(lock, struct prioq_mutex, litmus_lock);
}

#ifdef CONFIG_LITMUS_DGL_SUPPORT
int prioq_mutex_is_owner(struct litmus_lock *l, struct task_struct *t);
struct task_struct* prioq_mutex_get_owner(struct litmus_lock *l);
int prioq_mutex_dgl_lock(struct litmus_lock *l, dgl_wait_state_t* dgl_wait, wait_queue_t* wq_node);
int prioq_mutex_dgl_unlock(struct litmus_lock *l);
void prioq_mutex_enable_priority(struct litmus_lock *l, dgl_wait_state_t* dgl_wait);
void prioq_mutex_dgl_quick_lock(struct litmus_lock *l, struct litmus_lock *cur_lock,
								struct task_struct* t, wait_queue_t *q);
int prioq_mutex_dgl_can_quick_lock(struct litmus_lock *l, struct task_struct *t);
#endif

void prioq_mutex_budget_exhausted(struct litmus_lock* l, struct task_struct* t);

void prioq_mutex_propagate_increase_inheritance(struct litmus_lock* l,
				struct task_struct* t,
				raw_spinlock_t* to_unlock,
				unsigned long irqflags);

void prioq_mutex_propagate_decrease_inheritance(struct litmus_lock* l,
				struct task_struct* t,
				raw_spinlock_t* to_unlock,
				unsigned long irqflags,
				int budget_triggered);


int prioq_mutex_lock(struct litmus_lock* l);
int prioq_mutex_unlock(struct litmus_lock* l);
int prioq_mutex_should_yield_lock(struct litmus_lock* l);
int prioq_mutex_close(struct litmus_lock* l);
void prioq_mutex_free(struct litmus_lock* l);
struct litmus_lock* prioq_mutex_new(struct litmus_lock_ops*);

#endif
