#ifndef LITMUS_KFMLP_H
#define LITMUS_KFMLP_H

#include <litmus/litmus.h>
#include <litmus/locking.h>

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
#include <litmus/kexclu_affinity.h>

struct kfmlp_affinity;
#endif

/* struct for semaphore with priority inheritance */
struct kfmlp_queue
{
	wait_queue_head_t wait;
	struct task_struct* owner;
	struct task_struct* hp_waiter;
	unsigned int count; /* number of waiters + holder */
};

struct kfmlp_semaphore
{
	struct litmus_lock litmus_lock;

	spinlock_t	lock;

	unsigned int num_resources; /* aka k */

	struct kfmlp_queue *queues; /* array */
	struct kfmlp_queue *shortest_queue; /* pointer to shortest queue */

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	struct kfmlp_affinity *aff_obs;
#endif
};

static inline struct kfmlp_semaphore* kfmlp_from_lock(struct litmus_lock* lock)
{
	return container_of(lock, struct kfmlp_semaphore, litmus_lock);
}

int kfmlp_lock(struct litmus_lock* l);
int kfmlp_unlock(struct litmus_lock* l);
int kfmlp_close(struct litmus_lock* l);
void kfmlp_free(struct litmus_lock* l);
struct litmus_lock* kfmlp_new(struct litmus_lock_ops*, void* __user arg);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
struct kfmlp_queue_info
{
	struct kfmlp_queue* q;
	lt_t estimated_len;
	unsigned int *nr_cur_users;
};

struct kfmlp_affinity_ops
{
	struct kfmlp_queue* (*advise_enqueue)(struct kfmlp_affinity* aff,
					struct task_struct* t);
	struct task_struct* (*advise_steal)(struct kfmlp_affinity* aff,
					wait_queue_t** to_steal,
					struct kfmlp_queue** to_steal_from);
	void (*notify_enqueue)(struct kfmlp_affinity* aff,
					struct kfmlp_queue* fq,
					struct task_struct* t);
	void (*notify_dequeue)(struct kfmlp_affinity* aff,
					struct kfmlp_queue* fq,
					struct task_struct* t);
	void (*notify_acquired)(struct kfmlp_affinity* aff,
					struct kfmlp_queue* fq,
					struct task_struct* t);
	void (*notify_freed)(struct kfmlp_affinity* aff,
					struct kfmlp_queue* fq,
					struct task_struct* t);
	int (*replica_to_resource)(struct kfmlp_affinity* aff,
					struct kfmlp_queue* fq);
};

struct kfmlp_affinity
{
	struct affinity_observer obs;
	struct kfmlp_affinity_ops *ops;
	struct kfmlp_queue_info *q_info;
	unsigned int *nr_cur_users_on_rsrc;
	unsigned int offset;
	unsigned int nr_simult;
	unsigned int nr_rsrc;
};

static inline struct kfmlp_affinity* kfmlp_aff_obs_from_aff_obs(
				struct affinity_observer* aff_obs)
{
	return container_of(aff_obs, struct kfmlp_affinity, obs);
}

int kfmlp_aff_obs_close(struct affinity_observer* aff_obs);
void kfmlp_aff_obs_free(struct affinity_observer* aff_obs);

#ifdef CONFIG_LITMUS_NVIDIA
struct affinity_observer* kfmlp_gpu_aff_obs_new(
	struct affinity_observer_ops*, void* __user arg);

struct affinity_observer* kfmlp_simple_gpu_aff_obs_new(
	struct affinity_observer_ops*, void* __user arg);
#endif

#endif  /* end LITMUS_AFFINITY_LOCKING */

#endif
