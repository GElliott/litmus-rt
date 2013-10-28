#ifndef LITMUS_FIFO_H
#define LITMUS_FIFO_H

#include <litmus/litmus.h>
#include <litmus/binheap.h>
#include <litmus/locking.h>

/* struct for semaphore with priority inheritance */
struct fifo_mutex {
	struct litmus_lock litmus_lock;

	/* current resource holder */
	struct task_struct *owner;

	/* highest-priority waiter */
	struct task_struct *hp_waiter;

	/* FIFO queue of waiting tasks -- for now.  time stamp in the future. */
	wait_queue_head_t	wait;

	/* we do some nesting within spinlocks, so we can't use the normal
	 sleeplocks found in wait_queue_head_t. */
	raw_spinlock_t		lock;
};

static inline struct fifo_mutex* fifo_mutex_from_lock(struct litmus_lock* lock)
{
	return container_of(lock, struct fifo_mutex, litmus_lock);
}

#ifdef CONFIG_LITMUS_DGL_SUPPORT
int fifo_mutex_is_owner(struct litmus_lock *l, struct task_struct *t);
struct task_struct* fifo_mutex_get_owner(struct litmus_lock *l);
int fifo_mutex_dgl_lock(struct litmus_lock *l, dgl_wait_state_t* dgl_wait, wait_queue_t* wq_node);
void fifo_mutex_enable_priority(struct litmus_lock *l, dgl_wait_state_t* dgl_wait);
#endif

/* Assumes task's base-priority already updated to reflect new priority. */
void fifo_mutex_budget_exhausted(struct litmus_lock *l, struct task_struct *t);

void fifo_mutex_propagate_increase_inheritance(struct litmus_lock* l,
				struct task_struct* t,
				raw_spinlock_t* to_unlock,
				unsigned long irqflags);

void fifo_mutex_propagate_decrease_inheritance(struct litmus_lock* l,
				struct task_struct* t,
				raw_spinlock_t* to_unlock,
				unsigned long irqflags,
				int budget_triggered);

int fifo_mutex_lock(struct litmus_lock* l);
int fifo_mutex_unlock(struct litmus_lock* l);
int fifo_mutex_should_yield_lock(struct litmus_lock* l);
int fifo_mutex_close(struct litmus_lock* l);
void fifo_mutex_free(struct litmus_lock* l);
struct litmus_lock* fifo_mutex_new(struct litmus_lock_ops*);

#endif
