#include <linux/slab.h>
#include <linux/uaccess.h>

#include <litmus/trace.h>
#include <litmus/sched_plugin.h>
#include <litmus/fdso.h>

#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)
#include <litmus/gpu_affinity.h>
#include <litmus/nvidia_info.h>
#endif

#include <litmus/kfmlp_lock.h>

static inline int kfmlp_get_idx(struct kfmlp_semaphore* sem,
				struct kfmlp_queue* queue)
{
	return (queue - &sem->queues[0]);
}

static inline struct kfmlp_queue* kfmlp_get_queue(
				struct kfmlp_semaphore* sem,
				struct task_struct* holder)
{
	unsigned int i;
	for(i = 0; i < sem->num_resources; ++i)
		if(sem->queues[i].owner == holder)
			return(&sem->queues[i]);
	return(NULL);
}

/* caller is responsible for locking */
static struct task_struct* kfmlp_find_hp_waiter(struct kfmlp_queue *kqueue,
				struct task_struct *skip)
{
	struct list_head	*pos;
	struct task_struct 	*queued, *found = NULL;

	list_for_each(pos, &kqueue->wait.task_list) {
		queued =
			(struct task_struct*) list_entry(pos, wait_queue_t,
							task_list)->private;

		/* Compare task prios, find high prio task. */
		if (queued != skip && litmus->compare(queued, found))
			found = queued;
	}
	return found;
}

static inline struct kfmlp_queue* kfmlp_find_shortest(
				struct kfmlp_semaphore* sem,
				struct kfmlp_queue* search_start)
{
	/* we start our search at search_start instead of at the beginning of the
	   queue list to load-balance across all resources. */
	struct kfmlp_queue* step = search_start;
	struct kfmlp_queue* shortest = sem->shortest_queue;

	do {
		step = (step+1 != &sem->queues[sem->num_resources]) ?
		step+1 : &sem->queues[0];

		if(step->count < shortest->count) {
			shortest = step;
			if(step->count == 0)
				break; /* can't get any shorter */
		}
	}while(step != search_start);

	return(shortest);
}


static struct task_struct* kfmlp_select_hp_steal(struct kfmlp_semaphore* sem,
				wait_queue_t** to_steal,
				struct kfmlp_queue** to_steal_from)
{
	/* must hold sem->lock */

	unsigned int i;

	*to_steal = NULL;
	*to_steal_from = NULL;

	for(i = 0; i < sem->num_resources; ++i) {
		if( (sem->queues[i].count > 1) &&
		   ((*to_steal_from == NULL) ||
			(litmus->compare(sem->queues[i].hp_waiter,
							 (*to_steal_from)->hp_waiter))) ) {
			*to_steal_from = &sem->queues[i];
		}
	}

	if(*to_steal_from) {
		struct list_head *pos;
		struct task_struct *target = (*to_steal_from)->hp_waiter;

		TRACE_CUR("want to steal hp_waiter (%s/%d) from queue %d\n",
				  target->comm,
				  target->pid,
				  kfmlp_get_idx(sem, *to_steal_from));

		list_for_each(pos, &(*to_steal_from)->wait.task_list) {
			wait_queue_t *node = list_entry(pos, wait_queue_t, task_list);
			struct task_struct *queued = (struct task_struct*) node->private;
			/* Compare task prios, find high prio task. */
			if (queued == target) {
				*to_steal = node;

				TRACE_CUR("steal: selected %s/%d from queue %d\n",
						  queued->comm, queued->pid,
						  kfmlp_get_idx(sem, *to_steal_from));

				return queued;
			}
		}

		TRACE_CUR("Could not find %s/%d in queue %d!!!  THIS IS A BUG!\n",
				  target->comm,
				  target->pid,
				  kfmlp_get_idx(sem, *to_steal_from));
		BUG();
	}

	return NULL;
}

static void kfmlp_steal_node(struct kfmlp_semaphore *sem,
							 struct kfmlp_queue *dst,
							 wait_queue_t *wait,
							 struct kfmlp_queue *src)
{
	struct task_struct* t = (struct task_struct*) wait->private;

	__remove_wait_queue(&src->wait, wait);
	--(src->count);

	if(t == src->hp_waiter) {
		src->hp_waiter = kfmlp_find_hp_waiter(src, NULL);

		TRACE_CUR("queue %d: %s/%d is new hp_waiter\n",
				  kfmlp_get_idx(sem, src),
				  (src->hp_waiter) ? src->hp_waiter->comm : "nil",
				  (src->hp_waiter) ? src->hp_waiter->pid : -1);

		if(src->owner && tsk_rt(src->owner)->inh_task == t) {
			litmus->decrease_prio(src->owner, src->hp_waiter, 0);
		}
	}

	if(sem->shortest_queue->count > src->count) {
		sem->shortest_queue = src;
		TRACE_CUR("queue %d is the shortest\n",
				kfmlp_get_idx(sem, sem->shortest_queue));
	}

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		sem->aff_obs->ops->notify_dequeue(sem->aff_obs, src, t);
#endif

	init_waitqueue_entry(wait, t);
	__add_wait_queue_tail_exclusive(&dst->wait, wait);
	++(dst->count);

	if(litmus->compare(t, dst->hp_waiter)) {
		dst->hp_waiter = t;

		TRACE_CUR("queue %d: %s/%d is new hp_waiter\n",
				  kfmlp_get_idx(sem, dst),
				  t->comm, t->pid);

		if(dst->owner && litmus->compare(t, dst->owner)) {
			litmus->increase_prio(dst->owner, t);
		}
	}

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		sem->aff_obs->ops->notify_enqueue(sem->aff_obs, dst, t);
#endif
}


int kfmlp_lock(struct litmus_lock* l)
{
	struct task_struct* t = current;
	struct kfmlp_semaphore *sem = kfmlp_from_lock(l);
	struct kfmlp_queue* my_queue = NULL;
	wait_queue_t wait;
	unsigned long flags;

	if (!is_realtime(t))
		return -EPERM;

	spin_lock_irqsave(&sem->lock, flags);

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		my_queue = sem->aff_obs->ops->advise_enqueue(sem->aff_obs, t);
	if(!my_queue)
		my_queue = sem->shortest_queue;
#else
	my_queue = sem->shortest_queue;
#endif

	if (my_queue->owner) {
		/* resource is not free => must suspend and wait */
		TRACE_CUR("queue %d: Resource is not free => must suspend and wait. "
				  "(queue size = %d)\n",
				  kfmlp_get_idx(sem, my_queue),
				  my_queue->count);

		init_waitqueue_entry(&wait, t);

		/* FIXME: interruptible would be nice some day */
		set_task_state(t, TASK_UNINTERRUPTIBLE);

		__add_wait_queue_tail_exclusive(&my_queue->wait, &wait);

		TRACE_CUR("queue %d: hp_waiter is currently %s/%d\n",
				  kfmlp_get_idx(sem, my_queue),
				  (my_queue->hp_waiter) ? my_queue->hp_waiter->comm : "nil",
				  (my_queue->hp_waiter) ? my_queue->hp_waiter->pid : -1);

		/* check if we need to activate priority inheritance */
		if (litmus->compare(t, my_queue->hp_waiter)) {
			my_queue->hp_waiter = t;
			TRACE_CUR("queue %d: %s/%d is new hp_waiter\n",
					  kfmlp_get_idx(sem, my_queue),
					  t->comm, t->pid);

			if (litmus->compare(t, my_queue->owner))
				litmus->increase_prio(my_queue->owner, my_queue->hp_waiter);
		}

		++(my_queue->count);

		if(my_queue == sem->shortest_queue) {
			sem->shortest_queue = kfmlp_find_shortest(sem, my_queue);
			TRACE_CUR("queue %d is the shortest\n",
					  kfmlp_get_idx(sem, sem->shortest_queue));
		}

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs)
			sem->aff_obs->ops->notify_enqueue(sem->aff_obs, my_queue, t);
#endif

		flush_pending_wakes();

		/* release lock before sleeping */
		spin_unlock_irqrestore(&sem->lock, flags);

		/* We depend on the FIFO order.  Thus, we don't need to recheck
		 * when we wake up; we are guaranteed to have the lock since
		 * there is only one wake up per release (or steal).
		 */
		suspend_for_lock();


		if(my_queue->owner == t) {
			TRACE_CUR("queue %d: acquired through waiting\n",
					  kfmlp_get_idx(sem, my_queue));
		}
		else {
			/* this case may happen if our wait entry was stolen
			 between queues. record where we went. */
			my_queue = kfmlp_get_queue(sem, t);

			BUG_ON(!my_queue);
			TRACE_CUR("queue %d: acquired through stealing\n",
					  kfmlp_get_idx(sem, my_queue));
		}
	}
	else {
		TRACE_CUR("queue %d: acquired immediately\n",
				  kfmlp_get_idx(sem, my_queue));

		my_queue->owner = t;

		++(my_queue->count);

		if(my_queue == sem->shortest_queue) {
			sem->shortest_queue = kfmlp_find_shortest(sem, my_queue);
			TRACE_CUR("queue %d is the shortest\n",
					  kfmlp_get_idx(sem, sem->shortest_queue));
		}

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs) {
			sem->aff_obs->ops->notify_enqueue(sem->aff_obs, my_queue, t);
			sem->aff_obs->ops->notify_acquired(sem->aff_obs, my_queue, t);
		}
#endif
		spin_unlock_irqrestore(&sem->lock, flags);
	}


#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs)
		return sem->aff_obs->ops->replica_to_resource(sem->aff_obs, my_queue);
#endif
	return kfmlp_get_idx(sem, my_queue);
}


int kfmlp_unlock(struct litmus_lock* l)
{
	struct task_struct *t = current, *next;
	struct kfmlp_semaphore *sem = kfmlp_from_lock(l);
	struct kfmlp_queue *my_queue, *to_steal_from;
	unsigned long flags;
	int err = 0;

	my_queue = kfmlp_get_queue(sem, t);

	if (!my_queue) {
		err = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&sem->lock, flags);

	TRACE_CUR("queue %d: unlocking\n", kfmlp_get_idx(sem, my_queue));

	my_queue->owner = NULL;  // clear ownership
	--(my_queue->count);

	if(my_queue->count < sem->shortest_queue->count) {
		sem->shortest_queue = my_queue;
		TRACE_CUR("queue %d is the shortest\n",
				  kfmlp_get_idx(sem, sem->shortest_queue));
	}

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	if(sem->aff_obs) {
		sem->aff_obs->ops->notify_dequeue(sem->aff_obs, my_queue, t);
		sem->aff_obs->ops->notify_freed(sem->aff_obs, my_queue, t);
	}
#endif

	/* we lose the benefit of priority inheritance (if any) */
	if (tsk_rt(t)->inh_task)
		litmus->decrease_prio(t, NULL, 0);

	/* check if there are jobs waiting for this resource */
RETRY:
	next = __waitqueue_remove_first(&my_queue->wait);
	if (next) {
		/* next becomes the resouce holder */
		my_queue->owner = next;

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		if(sem->aff_obs)
			sem->aff_obs->ops->notify_acquired(sem->aff_obs, my_queue, next);
#endif

		TRACE_CUR("queue %d: lock ownership passed to %s/%d\n",
				  kfmlp_get_idx(sem, my_queue), next->comm, next->pid);

		/* determine new hp_waiter if necessary */
		if (next == my_queue->hp_waiter) {
			TRACE_TASK(next, "was highest-prio waiter\n");
			my_queue->hp_waiter = kfmlp_find_hp_waiter(my_queue, next);
			if (my_queue->hp_waiter)
				TRACE_TASK(my_queue->hp_waiter,
						"queue %d: is new highest-prio waiter\n",
						kfmlp_get_idx(sem, my_queue));
			else
				TRACE("queue %d: no further waiters\n",
						kfmlp_get_idx(sem, my_queue));
		} else {
			/* Well, if next is not the highest-priority waiter,
			 * then it ought to inherit the highest-priority
			 * waiter's priority. */
			litmus->increase_prio(next, my_queue->hp_waiter);
		}

		/* wake up next */
		wake_up_for_lock(next);
	}
	else {
		/* TODO: put this stealing logic before we attempt to release
		   our resource.  (simplifies code and gets rid of ugly goto RETRY. */
		wait_queue_t *wait;

		TRACE_CUR("queue %d: looking to steal someone...\n",
				  kfmlp_get_idx(sem, my_queue));

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
		next = (sem->aff_obs) ?
		  sem->aff_obs->ops->advise_steal(sem->aff_obs, &wait, &to_steal_from) :
		  kfmlp_select_hp_steal(sem, &wait, &to_steal_from);
#else
		next = kfmlp_select_hp_steal(sem, &wait, &to_steal_from);
#endif

		if(next) {
			TRACE_CUR("queue %d: stealing %s/%d from queue %d\n",
					  kfmlp_get_idx(sem, my_queue),
					  next->comm, next->pid,
					  kfmlp_get_idx(sem, to_steal_from));

			kfmlp_steal_node(sem, my_queue, wait, to_steal_from);

			goto RETRY;  /* will succeed this time. */
		}
		else {
			TRACE_CUR("queue %d: no one to steal.\n",
					  kfmlp_get_idx(sem, my_queue));
		}
	}

	spin_unlock_irqrestore(&sem->lock, flags);

out:
	return err;
}

int kfmlp_close(struct litmus_lock* l)
{
	struct task_struct *t = current;
	struct kfmlp_semaphore *sem = kfmlp_from_lock(l);
	struct kfmlp_queue *my_queue;
	unsigned long flags;

	unsigned int owner;

	spin_lock_irqsave(&sem->lock, flags);

	my_queue = kfmlp_get_queue(sem, t);
	owner = (my_queue) ? (my_queue->owner == t) : 0;

	spin_unlock_irqrestore(&sem->lock, flags);

	if (owner)
		kfmlp_unlock(l);

	return 0;
}

void kfmlp_free(struct litmus_lock* l)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(l);
	kfree(sem->queues);
	kfree(sem);
}

struct litmus_lock* kfmlp_new(struct litmus_lock_ops* ops, void* __user args)
{
	struct kfmlp_semaphore* sem;
	unsigned int num_resources = 0;
	unsigned int i;

	if(!access_ok(VERIFY_READ, args, sizeof(num_resources)))
		return(NULL);
	if(__copy_from_user(&num_resources, args, sizeof(num_resources)))
		return(NULL);
	if(num_resources < 1)
		return(NULL);

	sem = kmalloc(sizeof(*sem), GFP_KERNEL);
	if(!sem)
		return(NULL);
	memset(sem, 0, sizeof(*sem));

	sem->queues = kmalloc(sizeof(struct kfmlp_queue)*num_resources, GFP_KERNEL);
	if(!sem->queues) {
		kfree(sem);
		return(NULL);
	}

	sem->litmus_lock.ops = ops;
	spin_lock_init(&sem->lock);
	sem->num_resources = num_resources;

	for(i = 0; i < num_resources; ++i) {
		sem->queues[i].owner = NULL;
		sem->queues[i].hp_waiter = NULL;
		init_waitqueue_head(&sem->queues[i].wait);
		sem->queues[i].count = 0;
	}

	sem->shortest_queue = &sem->queues[0];

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	sem->aff_obs = NULL;
#endif

	return &sem->litmus_lock;
}


#if defined(CONFIG_LITMUS_AFFINITY_LOCKING) && defined(CONFIG_LITMUS_NVIDIA)

static inline int __replica_to_gpu(struct kfmlp_affinity* aff, int replica)
{
	int gpu = replica % aff->nr_rsrc;
	return gpu;
}

static inline int replica_to_gpu(struct kfmlp_affinity* aff, int replica)
{
	int gpu = __replica_to_gpu(aff, replica) + aff->offset;
	return gpu;
}

static inline int gpu_to_base_replica(struct kfmlp_affinity* aff, int gpu)
{
	int replica = gpu - aff->offset;
	return replica;
}

int kfmlp_aff_obs_close(struct affinity_observer* obs)
{
	return 0;
}

void kfmlp_aff_obs_free(struct affinity_observer* obs)
{
	struct kfmlp_affinity *kfmlp_aff = kfmlp_aff_obs_from_aff_obs(obs);
	kfree(kfmlp_aff->nr_cur_users_on_rsrc);
	kfree(kfmlp_aff->q_info);
	kfree(kfmlp_aff);
}

static struct affinity_observer* kfmlp_aff_obs_new(
				struct affinity_observer_ops* ops,
				struct kfmlp_affinity_ops* kfmlp_ops,
				void* __user args)
{
	struct kfmlp_affinity* kfmlp_aff;
	struct gpu_affinity_observer_args aff_args;
	struct kfmlp_semaphore* sem;
	unsigned int i;
	unsigned long flags;

	if(!access_ok(VERIFY_READ, args, sizeof(aff_args)))
		return(NULL);
	if(__copy_from_user(&aff_args, args, sizeof(aff_args)))
		return(NULL);

	sem = (struct kfmlp_semaphore*) get_lock_from_od(aff_args.obs.lock_od);

	if(sem->litmus_lock.type != KFMLP_SEM) {
		TRACE_CUR("Lock type not supported.  Type = %d\n",
				sem->litmus_lock.type);
		return(NULL);
	}

	if((aff_args.rho <= 0) ||
	   (sem->num_resources%aff_args.rho != 0)) {
		TRACE_CUR("Lock %d does not support #replicas (%d) for #simult_users "
				  "(%d) per replica.  #replicas should be evenly divisible "
				  "by #simult_users.\n",
				  sem->litmus_lock.ident,
				  sem->num_resources,
				  aff_args.rho);
		return(NULL);
	}

	kfmlp_aff = kmalloc(sizeof(*kfmlp_aff), GFP_KERNEL);
	if(!kfmlp_aff)
		return(NULL);

	kfmlp_aff->q_info = kmalloc(sizeof(struct kfmlp_queue_info) *
					sem->num_resources, GFP_KERNEL);
	if(!kfmlp_aff->q_info) {
		kfree(kfmlp_aff);
		return(NULL);
	}

	kfmlp_aff->nr_cur_users_on_rsrc = kmalloc(sizeof(unsigned int) *
					(sem->num_resources / aff_args.rho), GFP_KERNEL);
	if(!kfmlp_aff->nr_cur_users_on_rsrc) {
		kfree(kfmlp_aff->q_info);
		kfree(kfmlp_aff);
		return(NULL);
	}

	affinity_observer_new(&kfmlp_aff->obs, ops, &aff_args.obs);

	kfmlp_aff->ops = kfmlp_ops;
	kfmlp_aff->offset = aff_args.replica_to_gpu_offset;
	kfmlp_aff->nr_simult = aff_args.rho;
	kfmlp_aff->nr_rsrc = sem->num_resources / kfmlp_aff->nr_simult;

	memset(kfmlp_aff->nr_cur_users_on_rsrc, 0,
		sizeof(unsigned int)*(sem->num_resources / kfmlp_aff->nr_rsrc));

	for(i = 0; i < sem->num_resources; ++i) {
		kfmlp_aff->q_info[i].q = &sem->queues[i];
		kfmlp_aff->q_info[i].estimated_len = 0;

		/* multiple q_info's will point to the same resource (aka GPU) if
		   aff_args.nr_simult_users > 1 */
		kfmlp_aff->q_info[i].nr_cur_users =
				&kfmlp_aff->nr_cur_users_on_rsrc[__replica_to_gpu(kfmlp_aff,i)];
	}

	/* attach observer to the lock */
	spin_lock_irqsave(&sem->lock, flags);
	sem->aff_obs = kfmlp_aff;
	spin_unlock_irqrestore(&sem->lock, flags);

	return &kfmlp_aff->obs;
}

static int gpu_replica_to_resource(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq) {
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	return(replica_to_gpu(aff, kfmlp_get_idx(sem, fq)));
}


/*** Smart KFMLP Affinity ***/

struct kfmlp_queue* gpu_kfmlp_advise_enqueue(
				struct kfmlp_affinity* aff, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	lt_t min_len;
	unsigned int min_nr_users;
	struct kfmlp_queue_info *shortest;
	struct kfmlp_queue *to_enqueue;
	unsigned int i;
	int affinity_gpu;

	/* simply pick the shortest queue if, we have no affinity, or we have
	   affinity with the shortest */
	if(unlikely(tsk_rt(t)->last_gpu < 0))
		affinity_gpu = aff->offset;  /* first gpu */
	else
		affinity_gpu = tsk_rt(t)->last_gpu;

	/* all things being equal, let's start with the queue with which we have
	   affinity. this helps us maintain affinity even when we don't have
	   an estiamte for local-affinity execution time (i.e., 2nd time on GPU) */
	shortest = &aff->q_info[gpu_to_base_replica(aff, affinity_gpu)];

	min_len = shortest->estimated_len + get_gpu_estimate(t, MIG_LOCAL);
	min_nr_users = *(shortest->nr_cur_users);

	TRACE_CUR("cs is %llu on queue %d: est len = %llu\n",
			  get_gpu_estimate(t, MIG_LOCAL),
			  kfmlp_get_idx(sem, shortest->q),
			  min_len);

	for(i = 0; i < sem->num_resources; ++i) {
		if(&aff->q_info[i] != shortest) {

			lt_t est_len =
				aff->q_info[i].estimated_len +
				get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu,
							replica_to_gpu(aff, i)));

			/* queue is smaller, or they're equal and the other has a smaller
			   number of total users.

			   tie-break on the shortest number of simult users.
			   this only kicks in when there are more than 1 empty queues. */
			if((est_len < min_len) ||
			   ((est_len == min_len) &&
					(*(aff->q_info[i].nr_cur_users) < min_nr_users))) {
				shortest = &aff->q_info[i];
				min_len = est_len;
				min_nr_users = *(aff->q_info[i].nr_cur_users);
			}

			TRACE_CUR("cs is %llu on queue %d: est len = %llu\n",
				get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu,
							replica_to_gpu(aff, i))),
				kfmlp_get_idx(sem, aff->q_info[i].q),
				est_len);
		}
	}

	to_enqueue = shortest->q;
	TRACE_CUR("enqueue on fq %d (non-aff wanted fq %d)\n",
			  kfmlp_get_idx(sem, to_enqueue),
			  kfmlp_get_idx(sem, sem->shortest_queue));

	return to_enqueue;
}

struct task_struct* gpu_kfmlp_advise_steal(struct kfmlp_affinity* aff,
				wait_queue_t** to_steal, struct kfmlp_queue** to_steal_from)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	/* TODO: Implement affinity-aware stealing. */
	return kfmlp_select_hp_steal(sem, to_steal, to_steal_from);
}


void gpu_kfmlp_notify_enqueue(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	struct kfmlp_queue_info *info = &aff->q_info[replica];
	lt_t est_time;
	lt_t est_len_before;

	if(current == t)
		tsk_rt(t)->suspend_gpu_tracker_on_block = 1;

	est_len_before = info->estimated_len;
	est_time = get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu, gpu));
	info->estimated_len += est_time;

	TRACE_CUR("fq %d: q_len (%llu) + est_cs (%llu) = %llu\n",
			  kfmlp_get_idx(sem, info->q),
			  est_len_before, est_time,
			  info->estimated_len);
}

void gpu_kfmlp_notify_dequeue(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	struct kfmlp_queue_info *info = &aff->q_info[replica];
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
			  kfmlp_get_idx(sem, info->q),
			  info->estimated_len);
}

void gpu_kfmlp_notify_acquired(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);

	/* record the type of migration */
	tsk_rt(t)->gpu_migration =
			gpu_migration_distance(tsk_rt(t)->last_gpu, gpu);

	TRACE_CUR("%s/%d acquired gpu %d.  migration type = %d\n",
			  t->comm, t->pid, gpu, tsk_rt(t)->gpu_migration);

	/* count the number or resource holders */
	++(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 1, t);  /* register */

	tsk_rt(t)->suspend_gpu_tracker_on_block = 0;
	reset_gpu_tracker(t);
	start_gpu_tracker(t);
}

void gpu_kfmlp_notify_freed(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);
	lt_t est_time;

	stop_gpu_tracker(t);  /* stop the tracker before we do anything else. */

	est_time = get_gpu_estimate(t,
					gpu_migration_distance(tsk_rt(t)->last_gpu, gpu));

	tsk_rt(t)->last_gpu = gpu;

	/* count the number or resource holders */
	--(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 0, t);	/* unregister */

	update_gpu_estimate(t, get_gpu_time(t));

	TRACE_CUR("%s/%d freed gpu %d.  "
			  "actual time was %llu.  "
			  "estimated was %llu.  "
			  "diff is %d\n",
			  t->comm, t->pid, gpu,
			  get_gpu_time(t),
			  est_time,
			  (long long)get_gpu_time(t) - (long long)est_time);
}

struct kfmlp_affinity_ops gpu_kfmlp_affinity =
{
	.advise_enqueue = gpu_kfmlp_advise_enqueue,
	.advise_steal = gpu_kfmlp_advise_steal,
	.notify_enqueue = gpu_kfmlp_notify_enqueue,
	.notify_dequeue = gpu_kfmlp_notify_dequeue,
	.notify_acquired = gpu_kfmlp_notify_acquired,
	.notify_freed = gpu_kfmlp_notify_freed,
	.replica_to_resource = gpu_replica_to_resource,
};

struct affinity_observer* kfmlp_gpu_aff_obs_new(
				struct affinity_observer_ops* ops,
				void* __user args)
{
	return kfmlp_aff_obs_new(ops, &gpu_kfmlp_affinity, args);
}


/** Simple KFMLP Affinity (standard KFMLP with auto-gpu registration) **/

struct kfmlp_queue* simple_gpu_kfmlp_advise_enqueue(struct kfmlp_affinity* aff,
				struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	unsigned int min_count;
	unsigned int min_nr_users;
	struct kfmlp_queue_info *shortest;
	struct kfmlp_queue *to_enqueue;
	unsigned int i;

	shortest = &aff->q_info[0];
	min_count = shortest->q->count;
	min_nr_users = *(shortest->nr_cur_users);

	TRACE_CUR("queue %d: waiters = %d, total holders = %d\n",
			  kfmlp_get_idx(sem, shortest->q),
			  shortest->q->count,
			  min_nr_users);

	for(i = 1; i < sem->num_resources; ++i) {
		unsigned int len = aff->q_info[i].q->count;

		/* queue is smaller, or they're equal and the other has a smaller number
		   of total users.

		   tie-break on the shortest number of simult users.  this only kicks in
		   when there are more than 1 empty queues. */
		if((len < min_count) ||
		   ((len == min_count) &&
				(*(aff->q_info[i].nr_cur_users) < min_nr_users))) {
			shortest = &aff->q_info[i];
			min_count = shortest->q->count;
			min_nr_users = *(aff->q_info[i].nr_cur_users);
		}

		TRACE_CUR("queue %d: waiters = %d, total holders = %d\n",
				  kfmlp_get_idx(sem, aff->q_info[i].q),
				  aff->q_info[i].q->count,
				  *(aff->q_info[i].nr_cur_users));
	}

	to_enqueue = shortest->q;
	TRACE_CUR("enqueue on fq %d (non-aff wanted fq %d)\n",
			  kfmlp_get_idx(sem, to_enqueue),
			  kfmlp_get_idx(sem, sem->shortest_queue));

	return to_enqueue;
}

struct task_struct* simple_gpu_kfmlp_advise_steal(struct kfmlp_affinity* aff,
				wait_queue_t** to_steal, struct kfmlp_queue** to_steal_from)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	return kfmlp_select_hp_steal(sem, to_steal, to_steal_from);
}

void simple_gpu_kfmlp_notify_enqueue(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
}

void simple_gpu_kfmlp_notify_dequeue(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
}

void simple_gpu_kfmlp_notify_acquired(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);

	/* count the number or resource holders */
	++(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 1, t);  /* register */
}

void simple_gpu_kfmlp_notify_freed(struct kfmlp_affinity* aff,
				struct kfmlp_queue* fq, struct task_struct* t)
{
	struct kfmlp_semaphore *sem = kfmlp_from_lock(aff->obs.lock);
	int replica = kfmlp_get_idx(sem, fq);
	int gpu = replica_to_gpu(aff, replica);

	/* count the number or resource holders */
	--(*(aff->q_info[replica].nr_cur_users));

	reg_nv_device(gpu, 0, t);	/* unregister */
}

struct kfmlp_affinity_ops simple_gpu_kfmlp_affinity =
{
	.advise_enqueue = simple_gpu_kfmlp_advise_enqueue,
	.advise_steal = simple_gpu_kfmlp_advise_steal,
	.notify_enqueue = simple_gpu_kfmlp_notify_enqueue,
	.notify_dequeue = simple_gpu_kfmlp_notify_dequeue,
	.notify_acquired = simple_gpu_kfmlp_notify_acquired,
	.notify_freed = simple_gpu_kfmlp_notify_freed,
	.replica_to_resource = gpu_replica_to_resource,
};

struct affinity_observer* kfmlp_simple_gpu_aff_obs_new(
				struct affinity_observer_ops* ops,
				void* __user args)
{
	return kfmlp_aff_obs_new(ops, &simple_gpu_kfmlp_affinity, args);
}

#endif /* end LITMUS_AFFINITY_LOCKING && LITMUS_NVIDIA */
