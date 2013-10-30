#ifndef LITMUS_IKGLP_H
#define LITMUS_IKGLP_H

#include <litmus/litmus.h>
#include <litmus/binheap.h>
#include <litmus/locking.h>

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
#include <litmus/kexclu_affinity.h>
struct ikglp_affinity;
#endif

typedef struct ikglp_heap_node
{
	struct task_struct *task;
	struct binheap_node node;
} ikglp_heap_node_t;

struct fifo_queue;
struct ikglp_wait_state;
struct fifo_queue;

typedef struct ikglp_donee_heap_node
{
	struct task_struct *task;
	struct fifo_queue *fq;

    /* cross-linked with ikglp_wait_state_t of donor */
	struct ikglp_wait_state *donor_info;

	struct binheap_node node;
} ikglp_donee_heap_node_t;

typedef enum ikglp_states
{
	IKGLP_INVL = 0,
	IKGLP_FQ,
	IKGLP_PQ,
	IKGLP_DONOR
} ikglp_states_t;

/*
   Maintains the state of a request as it goes through the IKGLP.
   There are three exclusive wait states:
    (1) as a donor
    (2) in the PQ
    (3) in the FQ
*/
typedef struct ikglp_wait_state {
	struct task_struct	*task;  /* pointer back to the requesting task */

	ikglp_states_t		cur_q;
	/* data for x-highest-prio tasks */
	ikglp_heap_node_t	global_heap_node;

    /* TODO: put these fields in an appropriate union since wait
       states are exclusive. */

	/** Data for whilst in FIFO Queue **/
	wait_queue_t		fq_node;
	struct fifo_queue	*fq;
	ikglp_donee_heap_node_t	donee_heap_node;

	/** Data for whilst in PQ **/
	ikglp_heap_node_t	pq_node;

	/** Data for whilst a donor **/
    /* cross-linked with donee's ikglp_donee_heap_node_t */
	ikglp_donee_heap_node_t	*donee_info;
	struct nested_info	prio_donation;
	struct binheap_node	node;
} ikglp_wait_state_t;

/* struct for FIFO mutex with priority inheritance */
struct fifo_queue
{
	wait_queue_head_t wait;
	struct task_struct* owner;

	/* used for bookkeepping */
	ikglp_heap_node_t global_heap_node;
	ikglp_donee_heap_node_t donee_heap_node;

	struct task_struct* hp_waiter;
	unsigned int count; /* number of waiters + holder */

	struct nested_info nest;

	/* Asserted if owner has 'virtually' unlocked the FIFO's replica.
	 * See rule B2 in Brandenburg's "Virtually Exclusive Resources"
	 * tech report MPI_SWS-2012-005.
	 *
	 * In this implementation, allows the FIFO queue to temporarily
	 * grow by one past it's maximum size.
	 */
	unsigned int is_vunlocked:1;
};

/* Main IKGLP data structure. */
struct ikglp_semaphore
{
	struct litmus_lock litmus_lock;

	raw_spinlock_t	lock;
	raw_spinlock_t	real_lock;

	unsigned int nr_replicas;  /* AKA k */
	unsigned int max_fifo_len; /* max len of a fifo queue */

	unsigned int max_in_fifos;
	unsigned int nr_in_fifos;

	struct binheap top_m;     /* min heap, base prio */
	unsigned int top_m_size;  /* number of nodes in top_m */

	struct binheap not_top_m; /* max heap, ordered by base priority */

	struct binheap donees;	  /* min-heap, ordered by base priority */

    /* cached value - pointer to shortest fifo queue */
	struct fifo_queue *shortest_fifo_queue;

	/* data structures for holding requests */
	struct fifo_queue *fifo_queues; /* array nr_replicas in length */
	struct binheap priority_queue;  /* max-heap, ordered by base priority */
	struct binheap donors;          /* max-heap, ordered by base priority */

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	struct ikglp_affinity *aff_obs; /* pointer to affinity observer */
#endif
};

static inline struct ikglp_semaphore* ikglp_from_lock(struct litmus_lock* lock)
{
	return container_of(lock, struct ikglp_semaphore, litmus_lock);
}

int ikglp_lock(struct litmus_lock* l);
int ikglp_unlock(struct litmus_lock* l);
void ikglp_virtual_unlock(struct litmus_lock* l, struct task_struct* t);
void ikglp_budget_exhausted(struct litmus_lock* l, struct task_struct* t);

int ikglp_close(struct litmus_lock* l);
void ikglp_free(struct litmus_lock* l);
struct litmus_lock* ikglp_new(unsigned int m, struct litmus_lock_ops*,
				void* __user arg);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
struct ikglp_queue_info
{
	struct fifo_queue* q;
	lt_t estimated_len;
	unsigned int *nr_cur_users;
	unsigned int *nr_aff_users;
};

/* routines for IKGLP to call to get advice on queueing operations */
typedef struct fifo_queue* (*advise_enqueue_t)(struct ikglp_affinity* aff,
				struct task_struct* t);
typedef ikglp_wait_state_t* (*advise_steal_t)(struct ikglp_affinity* aff,
				struct fifo_queue* dst);
typedef ikglp_donee_heap_node_t* (*advise_donee_t)(struct ikglp_affinity* aff,
				struct task_struct* t);
typedef ikglp_wait_state_t* (*advise_donor_t)(struct ikglp_affinity* aff,
				struct fifo_queue* dst);

/* routines for IKGLP to notify the affinity observer about changes in mutex state */
typedef void (*notify_enqueue_t)(struct ikglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t);
typedef void (*notify_dequeue_t)(struct ikglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t);
typedef void (*notify_acquire_t)(struct ikglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t);
typedef void (*notify_free_t)(struct ikglp_affinity* aff,
				struct fifo_queue* fq, struct task_struct* t);
typedef int (*notify_exit_t)(struct ikglp_affinity* aff,
				struct task_struct* t);

/* convert a replica # to a GPU (includes offsets & simult user folding) */
typedef int (*replica_to_resource_t)(struct ikglp_affinity* aff,
				struct fifo_queue* fq);

struct ikglp_affinity_ops
{
	advise_enqueue_t advise_enqueue;
	advise_steal_t advise_steal;
	advise_donee_t advise_donee_selection;
	advise_donor_t advise_donor_to_fq;

	notify_enqueue_t notify_enqueue;
	notify_dequeue_t notify_dequeue;
	notify_acquire_t notify_acquired;
	notify_free_t notify_freed;
	notify_exit_t notify_exit;

	replica_to_resource_t replica_to_resource;
};

struct ikglp_affinity
{
	struct affinity_observer obs;
	struct ikglp_affinity_ops *ops;
	struct ikglp_queue_info *q_info;
	unsigned int *nr_cur_users_on_rsrc;
	unsigned int *nr_aff_on_rsrc;
	unsigned int offset;
	unsigned int nr_simult;
	unsigned int nr_rsrc;

	unsigned int relax_max_fifo_len:1;
};

static inline struct ikglp_affinity* ikglp_aff_obs_from_aff_obs(
				struct affinity_observer* aff_obs)
{
	return container_of(aff_obs, struct ikglp_affinity, obs);
}

int ikglp_aff_obs_close(struct affinity_observer*);
void ikglp_aff_obs_free(struct affinity_observer*);

#ifdef CONFIG_LITMUS_NVIDIA
struct affinity_observer* ikglp_gpu_aff_obs_new(
				struct affinity_observer_ops* aff,
				void* __user arg);
struct affinity_observer* ikglp_simple_gpu_aff_obs_new(
				struct affinity_observer_ops* aff,
				void* __user arg);
#endif /* end LITMUS_NVIDIA */

#endif /* end LITMUS_AFFINITY_LOCKING */

#endif
