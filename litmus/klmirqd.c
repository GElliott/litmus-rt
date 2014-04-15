#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/completion.h>

#include <linux/sched.h>
#include <linux/cpuset.h>

#include <litmus/litmus.h>
#include <litmus/sched_trace.h>
#include <litmus/jobs.h>
#include <litmus/sched_plugin.h>
#include <litmus/klmirqd.h>

/* TODO: Remove unneeded mb() and other barriers. */

enum pending_flags
{
	LIT_TASKLET_LOW = 0x1,
	LIT_TASKLET_HI  = LIT_TASKLET_LOW<<1,
	LIT_WORK = LIT_TASKLET_HI<<1
};

struct klmirqd_registration
{
	raw_spinlock_t lock;
	u32 nr_threads;
	struct list_head threads;

	unsigned int initialized:1;
	unsigned int shuttingdown:1;
};

static struct klmirqd_registration klmirqd_state =
{
	.lock = __RAW_SPIN_LOCK_INITIALIZER(klmirqd_state.lock),
	.nr_threads = 0,
	.threads = {&klmirqd_state.threads, &klmirqd_state.threads},
	.initialized = 1,
	.shuttingdown = 0,
};

static atomic_t klmirqd_id_gen = ATOMIC_INIT(-1);

void init_klmirqd(void)
{
}

static int __klmirqd_is_ready(void)
{
	return (klmirqd_state.initialized == 1 && klmirqd_state.shuttingdown == 0);
}

int klmirqd_is_ready(void)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&klmirqd_state.lock, flags);
	ret = __klmirqd_is_ready();
	raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);

	return ret;
}

int klmirqd_is_dead(void)
{
	return(!klmirqd_is_ready());
}


void kill_klmirqd(void)
{
	if(!klmirqd_is_dead())
	{
		unsigned long flags;
		struct list_head *pos;
		struct list_head *q;

		raw_spin_lock_irqsave(&klmirqd_state.lock, flags);

		TRACE("Killing all klmirqd threads! (%d of them)\n",
			klmirqd_state.nr_threads);

		klmirqd_state.shuttingdown = 1;
		mb();

		list_for_each_safe(pos, q, &klmirqd_state.threads) {
			struct klmirqd_info* info =
					list_entry(pos, struct klmirqd_info, klmirqd_reg);

			if(info->terminating != 1) {
				struct completion exit;
				init_completion(&exit);

				info->terminating = 1;
				info->exited = &exit;
				mb(); /* just to be sure? */
				flush_pending(info->klmirqd);

				/* signal termination */
				raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);
				kthread_stop(info->klmirqd);
				/* completion signaled when task exits rt-mode */
				wait_for_completion(&exit);
				raw_spin_lock_irqsave(&klmirqd_state.lock, flags);
			}
		}
		klmirqd_state.shuttingdown = 0;
		raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);
	}
}



void kill_klmirqd_thread(struct task_struct* klmirqd_thread)
{
	unsigned long flags;
	struct klmirqd_info* info;

	if (!tsk_rt(klmirqd_thread)->is_interrupt_task) {
		TRACE("%s/%d is not a klmirqd thread\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
		return;
	}

	TRACE("Killing klmirqd thread %s/%d\n",
		klmirqd_thread->comm, klmirqd_thread->pid);

	raw_spin_lock_irqsave(&klmirqd_state.lock, flags);

	info = tsk_rt(klmirqd_thread)->klmirqd_info;

	if(info->terminating != 1) {
		struct completion exit;
		init_completion(&exit);
		info->terminating = 1;
		info->exited = &exit;
		mb();

		flush_pending(klmirqd_thread);
		raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);

		kthread_stop(klmirqd_thread);
		/* completion signaled when task exits rt-mode */
		wait_for_completion(&exit);
	}
	else {
		raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);
	}
}

struct klmirqd_launch_data
{
	int cpu_affinity;
	klmirqd_callback_t* cb;
	char name[MAX_KLMIRQD_NAME_LEN+1];
	struct work_struct work;
};

static int run_klmirqd(void* callback);


/* executed by a kworker from workqueues */
static void __launch_klmirqd_thread(struct work_struct *work)
{
	int id;
	struct task_struct* thread = NULL;
	struct klmirqd_launch_data* launch_data =
		container_of(work, struct klmirqd_launch_data, work);

	TRACE("Creating klmirqd thread\n");

	if (launch_data->cpu_affinity != -1) {
		if (launch_data->name[0] == '\0') {
			id = atomic_inc_return(&klmirqd_id_gen);
			TRACE("Launching klmirqd_th%d/%d\n",
				id, launch_data->cpu_affinity);

			thread = kthread_create(
						run_klmirqd,
						/* treat the affinity as a pointer,
						   we'll cast it back later */
						(void*)launch_data->cb,
						"klmirqd_th%d/%d",
						id,
						launch_data->cpu_affinity);
		}
		else {
			TRACE("Launching %s/%d\n",
				launch_data->name, launch_data->cpu_affinity);

			thread = kthread_create(
						run_klmirqd,
						/* treat the affinity as a pointer,
						   we'll cast it back later */
						(void*)launch_data->cb,
						"%s/%d",
						launch_data->name,
						launch_data->cpu_affinity);
		}

		/* litmus will put is in the right cluster. */
		kthread_bind(thread, launch_data->cpu_affinity);
	}
	else {
		if (launch_data->name[0] == '\0') {
			id = atomic_inc_return(&klmirqd_id_gen);
			TRACE("Launching klmirqd_th%d\n", id);

			thread = kthread_create(
						run_klmirqd,
						/* treat the affinity as a pointer,
						   we'll cast it back later */
						(void*)launch_data->cb,
						"klmirqd_th%d",
						id);

		}
		else {
			TRACE("Launching %s\n", launch_data->name);

			thread = kthread_create(
						run_klmirqd,
						/* treat the affinity as a pointer,
						   we'll cast it back later */
						(void*)launch_data->cb,
						launch_data->name);
		}
	}

	if (thread)
		wake_up_process(thread);
	else
		TRACE("Could not create thread!\n");

	kfree(launch_data);
}


int launch_klmirqd_thread(char* name, int cpu, klmirqd_callback_t* cb)
{
	struct klmirqd_launch_data* delayed_launch;

	if (!klmirqd_is_ready()) {
		TRACE("klmirqd is not ready.  Check that it was initialized!\n");
		return -1;
	}

	/* tell a work queue to launch the threads.  we can't make scheduling
	 calls since we're in an atomic state. */
	delayed_launch = kmalloc(sizeof(struct klmirqd_launch_data), GFP_ATOMIC);
	delayed_launch->cpu_affinity = cpu;
	delayed_launch->cb = cb;
	INIT_WORK(&delayed_launch->work, __launch_klmirqd_thread);

	if(name)
		snprintf(delayed_launch->name, MAX_KLMIRQD_NAME_LEN+1, "%s", name);
	else
		delayed_launch->name[0] = '\0';

	schedule_work(&delayed_launch->work);

	return 0;
}


#define KLMIRQD_SLICE_NR_JIFFIES 4
#define KLMIRQD_SLICE_NS ((NSEC_PER_SEC / HZ) * KLMIRQD_SLICE_NR_JIFFIES)

static int become_litmus_daemon(struct task_struct* tsk)
{
	int ret = 0;

	struct rt_task tp = {
		.exec_cost = KLMIRQD_SLICE_NS,
		.period = KLMIRQD_SLICE_NS,
		.relative_deadline = KLMIRQD_SLICE_NS,
		.phase = 0,
		.cpu = task_cpu(current),
		.priority = LITMUS_LOWEST_PRIORITY,
		.cls = RT_CLASS_BEST_EFFORT,
		/* klmirdq monitors its budget, so no enforcement needed */
		.budget_policy = NO_ENFORCEMENT,
		.drain_policy = DRAIN_SIMPLE,
		.budget_signal_policy = NO_SIGNALS,
		.release_policy = TASK_DAEMON,
	};

	struct sched_param param = { .sched_priority = 0};

	TRACE_CUR("Setting %s/%d as daemon thread.\n", tsk->comm, tsk->pid);

	/* set task params */
	tsk_rt(tsk)->task_params = tp;
	tsk_rt(tsk)->is_interrupt_task = 1;

	/* inform the OS we're SCHED_LITMUS --
	 sched_setscheduler_nocheck() calls litmus_admit_task(). */
	sched_setscheduler_nocheck(tsk, SCHED_LITMUS, &param);

	return ret;
}

static int become_normal_daemon(struct task_struct* tsk)
{
	int ret = 0;
	struct sched_param param = { .sched_priority = 0};

	TRACE_TASK(tsk, "exiting real-time mode\n");
	sched_setscheduler_nocheck(tsk, SCHED_NORMAL, &param);

	return ret;
}

static int register_klmirqd(struct task_struct* tsk)
{
	int retval = 0;
	unsigned long flags;
	struct klmirqd_info *info = NULL;

	if (!tsk_rt(tsk)->is_interrupt_task) {
		TRACE("Only proxy threads already running in Litmus "
			  "may become klmirqd threads!\n");
		WARN_ON(1);
		retval = -1;
		goto out;
	}

	/* allocate and initialize klmirqd data for the thread */
	info = kmalloc(sizeof(struct klmirqd_info), GFP_KERNEL);
	if (!info) {
		TRACE("Failed to allocate klmirqd_info struct!\n");
		retval = -1; /* todo: pick better code */
		goto out;
	}

	raw_spin_lock_irqsave(&klmirqd_state.lock, flags);

	if (!__klmirqd_is_ready()) {
		TRACE("klmirqd is not ready! Did you forget to initialize it?\n");
		kfree(info);
		WARN_ON(1);
		retval = -1;
		goto out_unlock;
	}

	/* allocate and initialize klmirqd data for the thread */
	memset(info, 0, sizeof(struct klmirqd_info));
	info->klmirqd = tsk;
	info->pending_tasklets_hi.tail = &info->pending_tasklets_hi.head;
	info->pending_tasklets.tail = &info->pending_tasklets.head;
	INIT_LIST_HEAD(&info->worklist);
	INIT_LIST_HEAD(&info->klmirqd_reg);
	raw_spin_lock_init(&info->lock);
	info->exited = NULL;

	/* now register with klmirqd */
	list_add_tail(&info->klmirqd_reg, &klmirqd_state.threads);
	++klmirqd_state.nr_threads;

	/* update the task struct to point to klmirqd info */
	tsk_rt(tsk)->klmirqd_info = info;

out_unlock:
	raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);

out:
	return retval;
}

static int unregister_klmirqd(struct task_struct* tsk)
{
	int retval = 0;
	unsigned long flags;
	struct klmirqd_info *info = tsk_rt(tsk)->klmirqd_info;

	TRACE_CUR("unregistering.\n");

	if (!tsk_rt(tsk)->is_interrupt_task || !info) {
		WARN_ON(1);
		retval = -1;
		goto out;
	}

	raw_spin_lock_irqsave(&klmirqd_state.lock, flags);

	/* remove the entry in the klmirqd thread list */
	list_del(&info->klmirqd_reg);
	mb();
	--klmirqd_state.nr_threads;

	/* remove link to klmirqd info from thread */
	tsk_rt(tsk)->klmirqd_info = NULL;

	/* clean up memory */
	kfree(info);

	raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);

out:
	return retval;
}

int proc_read_klmirqd_stats(char *page, char **start,
							 off_t off, int count,
							 int *eof, void *data)
{
	unsigned long flags;
	int len;

	raw_spin_lock_irqsave(&klmirqd_state.lock, flags);

	if (klmirqd_state.initialized) {
		if (!klmirqd_state.shuttingdown) {
			struct list_head *pos;

			len = snprintf(page, PAGE_SIZE,
						   "num ready klmirqds: %d\n\n",
						   klmirqd_state.nr_threads);

			list_for_each(pos, &klmirqd_state.threads) {
				struct klmirqd_info* info = list_entry(pos,
								struct klmirqd_info, klmirqd_reg);

				len +=
					snprintf(page + len - 1, PAGE_SIZE, /*-1 to strip off \0*/
							 "klmirqd_thread: %s/%d\n"
							 "\tpending: %x\n"
							 "\tnum hi: %d\n"
							 "\tnum low: %d\n"
							 "\tnum work: %d\n\n",
							 info->klmirqd->comm, info->klmirqd->pid,
							 info->pending,
							 atomic_read(&info->num_hi_pending),
							 atomic_read(&info->num_low_pending),
							 atomic_read(&info->num_work_pending));
			}
		}
		else {
			len = snprintf(page, PAGE_SIZE, "klmirqd is shutting down\n");
		}
	}
	else {
		len = snprintf(page, PAGE_SIZE, "klmirqd is not initialized!\n");
	}

	raw_spin_unlock_irqrestore(&klmirqd_state.lock, flags);

	return(len);
}

/* forward declarations */
static void ___litmus_tasklet_schedule(struct tasklet_struct *t,
									   struct klmirqd_info *which,
									   int wakeup);
static void ___litmus_tasklet_hi_schedule(struct tasklet_struct *t,
										  struct klmirqd_info *which,
										  int wakeup);
static void ___litmus_schedule_work(struct work_struct *w,
									struct klmirqd_info *which,
									int wakeup);


inline static u32 litirq_pending_hi_irqoff(struct klmirqd_info* which)
{
	return (which->pending & LIT_TASKLET_HI);
}

inline static u32 litirq_pending_low_irqoff(struct klmirqd_info* which)
{
	return (which->pending & LIT_TASKLET_LOW);
}

inline static u32 litirq_pending_work_irqoff(struct klmirqd_info* which)
{
	return (which->pending & LIT_WORK);
}

inline static u32 litirq_pending_irqoff(struct klmirqd_info* which)
{
	return(which->pending);
}


inline static u32 litirq_pending(struct klmirqd_info* which)
{
	unsigned long flags;
	u32 pending;

	raw_spin_lock_irqsave(&which->lock, flags);
	pending = litirq_pending_irqoff(which);
	raw_spin_unlock_irqrestore(&which->lock, flags);

	return pending;
};

static void wakeup_litirqd_locked(struct klmirqd_info* which)
{
	/* Interrupts are disabled: no need to stop preemption */
	if (which && which->klmirqd) {
		if(which->klmirqd->state != TASK_RUNNING) {
			TRACE("Waking up klmirqd: %s/%d\n",
				which->klmirqd->comm, which->klmirqd->pid);

			wake_up_process(which->klmirqd);
		}
	}
}


static void do_lit_tasklet(struct klmirqd_info* which,
				struct tasklet_head* pending_tasklets)
{
	unsigned long flags;
	struct tasklet_struct *list;
	atomic_t* count;

	raw_spin_lock_irqsave(&which->lock, flags);

	/* copy out the tasklets for our private use. */
	list = pending_tasklets->head;
	pending_tasklets->head = NULL;
	pending_tasklets->tail = &pending_tasklets->head;

	/* remove pending flag */
	which->pending &= (pending_tasklets == &which->pending_tasklets) ?
		~LIT_TASKLET_LOW :
		~LIT_TASKLET_HI;

	count = (pending_tasklets == &which->pending_tasklets) ?
		&which->num_low_pending:
		&which->num_hi_pending;

	raw_spin_unlock_irqrestore(&which->lock, flags);

	while(list) {
		struct tasklet_struct *t = list;

		/* advance, lest we forget */
		list = list->next;

		/* execute tasklet if it has my priority and is free */
		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if(!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				TRACE_CUR("Invoking tasklet.\n");

				sched_trace_tasklet_begin(effective_priority(current));
				t->func(t->data);
				tasklet_unlock(t);
				sched_trace_tasklet_end(effective_priority(current), 0ul);

				atomic_dec(count);

				continue;  /* process more tasklets */
			}
			tasklet_unlock(t);
		}

		TRACE_CUR("Could not invoke tasklet. Requeuing.\n");

		/* couldn't process tasklet.  put it back at the end of the queue. */
		if(pending_tasklets == &which->pending_tasklets)
			___litmus_tasklet_schedule(t, which, 0);
		else
			___litmus_tasklet_hi_schedule(t, which, 0);
	}
}


/* returns 1 if priorities need to be changed to continue processing
   pending tasklets. */
static void do_litirq(struct klmirqd_info* which)
{
	u32 pending;

	if(in_interrupt()) {
		TRACE("exiting early: in interrupt context!\n");
		return;
	}

	if(which->klmirqd != current) {
		TRACE_CUR("exiting early: thread/info mismatch! "
				"Running %s/%d but given %s/%d.\n",
				current->comm, current->pid,
				which->klmirqd->comm, which->klmirqd->pid);
		return;
	}

	if(!is_realtime(current)) {
		TRACE_CUR("exiting early: klmirqd is not real-time. "
				"Sched Policy = %d\n",
				current->policy);
		return;
	}

	/* We only handle tasklets & work objects, no need for RCU triggers? */

	pending = litirq_pending(which);
	if(pending) {
		/* extract the work to do and do it! */
		if(pending & LIT_TASKLET_HI) {
			TRACE_CUR("Invoking HI tasklets.\n");
			do_lit_tasklet(which, &which->pending_tasklets_hi);
		}

		if(pending & LIT_TASKLET_LOW) {
			TRACE_CUR("Invoking LOW tasklets.\n");
			do_lit_tasklet(which, &which->pending_tasklets);
		}
	}
}


static void do_work(struct klmirqd_info* which)
{
	unsigned long flags;
	struct work_struct* work;
	work_func_t f;

	/* only execute one work-queue item to yield to tasklets.
	   ...is this a good idea, or should we just batch them? */
	raw_spin_lock_irqsave(&which->lock, flags);

	if(!litirq_pending_work_irqoff(which)) {
		raw_spin_unlock_irqrestore(&which->lock, flags);
		goto no_work;
	}

	work = list_first_entry(&which->worklist, struct work_struct, entry);
	list_del_init(&work->entry);

	if(list_empty(&which->worklist))
		which->pending &= ~LIT_WORK;

	raw_spin_unlock_irqrestore(&which->lock, flags);


	TRACE_CUR("Invoking work object.\n");

	/* do the work! */
	work_clear_pending(work);
	f = work->func;

	sched_trace_work_begin(effective_priority(current), current);
	f(work);  /* can't touch 'work' after this point,
			   the user may have freed it. */
	sched_trace_work_end(effective_priority(current), current, 0ul);

	atomic_dec(&which->num_work_pending);

no_work:
	return;
}

/* main loop for klitsoftirqd */
static int run_klmirqd(void* callback)
{
	int retval = 0;
	struct klmirqd_info* info = NULL;
	struct completion* exit = NULL;
	klmirqd_callback_t* cb = (klmirqd_callback_t*)(callback);

	retval = become_litmus_daemon(current);
	if (retval != 0) {
		TRACE_CUR("Failed to transition to rt-task.\n");
		goto failed;
	}

	retval = register_klmirqd(current);
	if (retval != 0) {
		TRACE_CUR("Failed to become a klmirqd thread.\n");
		goto failed_sched_normal;
	}

	if (cb && cb->func) {
		retval = cb->func(cb->arg);
		if (retval != 0) {
			TRACE_CUR("klmirqd callback reported failure. retval = %d\n",
				retval);
			goto failed_unregister;
		}
	}

	/* enter the interrupt handling workloop */

	info = tsk_rt(current)->klmirqd_info;

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		preempt_disable();
		if (!litirq_pending(info)) {
			/* sleep for work */
			TRACE_CUR("No more tasklets or work objects. Going to sleep.\n");

			set_new_job_on_wake(current);
			{
				preempt_enable_no_resched();
				schedule();
			}
			clear_new_job_on_wake(current);

			if(kthread_should_stop()) { /* bail out */
				TRACE_CUR("Signaled to terminate.\n");
				continue;
			}

			preempt_disable();
		}

		__set_current_state(TASK_RUNNING);

		while (litirq_pending(info)) {
			preempt_enable_no_resched();

			if(kthread_should_stop()) {
				TRACE_CUR("Signaled to terminate.\n");
				break;
			}

			preempt_disable();

			/* Double check that there's still pending work and the owner hasn't
			 * changed. Pending items may have been flushed while we were sleeping.
			 */
			if(litirq_pending(info)) {
				TRACE_CUR("Executing tasklets and/or work objects.\n");

				do_litirq(info);

				preempt_enable_no_resched();

				/* work objects are preemptible. */
				do_work(info);
			}
			else {
				TRACE_CUR("Pending work was flushed!\n");

				preempt_enable_no_resched();
			}

			if(unlikely(budget_exhausted(current))) {
				/* will resched */
				TRACE_CUR("Exhausted budget. Completing job.\n");
				litmus->complete_job();
			}
			else {
				cond_resched();
			}
			preempt_disable();
		}
		preempt_enable();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

failed_unregister:
	/* remove our registration from klmirqd */
	exit = info->exited;
	mb();
	unregister_klmirqd(current);

failed_sched_normal:
	become_normal_daemon(current);

	if (exit) {
		TRACE_CUR("signalling exit\n");
		complete(exit);
	}

failed:
	return retval;
}


void flush_pending(struct task_struct* tsk)
{
	unsigned long flags;
	struct tasklet_struct *list;
	u32 work_flushed = 0;

	struct klmirqd_info *which;

	if (!tsk_rt(tsk)->is_interrupt_task) {
		TRACE("%s/%d is not a proxy thread\n", tsk->comm, tsk->pid);
		WARN_ON(1);
		return;
	}

	which = tsk_rt(tsk)->klmirqd_info;
	if (!which) {
		TRACE("%s/%d is not a klmirqd thread!\n", tsk->comm, tsk->pid);
		WARN_ON(1);
		return;
	}

	raw_spin_lock_irqsave(&which->lock, flags);

	/* flush hi tasklets. */
	if(litirq_pending_hi_irqoff(which))
	{
		which->pending &= ~LIT_TASKLET_HI;

		list = which->pending_tasklets_hi.head;
		which->pending_tasklets_hi.head = NULL;
		which->pending_tasklets_hi.tail = &which->pending_tasklets_hi.head;

		TRACE("Handing HI tasklets back to Linux.\n");

		while(list) {
			struct tasklet_struct *t = list;
			list = list->next;

			BUG_ON(!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state));

			work_flushed |= LIT_TASKLET_HI;

			if(!test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
				atomic_dec(&which->num_hi_pending);
				___tasklet_hi_schedule(t);
			}
			else {
				TRACE("dropped hi tasklet??\n");
				BUG();
			}
		}
	}

	/* flush low tasklets. */
	if(litirq_pending_low_irqoff(which))
	{
		which->pending &= ~LIT_TASKLET_LOW;

		list = which->pending_tasklets.head;
		which->pending_tasklets.head = NULL;
		which->pending_tasklets.tail = &which->pending_tasklets.head;

		TRACE("Handing LOW tasklets back to Linux.\n");

		while(list) {
			struct tasklet_struct *t = list;
			list = list->next;

			BUG_ON(!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state));

			work_flushed |= LIT_TASKLET_LOW;

			if(!test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
				atomic_dec(&which->num_low_pending);
				___tasklet_schedule(t);
			}
			else {
				TRACE("dropped tasklet??\n");
				BUG();
			}
		}
	}

	/* flush work objects */
	if(litirq_pending_work_irqoff(which)) {
		TRACE("Handing work objects back to Linux.\n");

		which->pending &= ~LIT_WORK;
		while(!list_empty(&which->worklist)) {
			struct work_struct* work =
				list_first_entry(&which->worklist, struct work_struct, entry);
			list_del_init(&work->entry);

			work_flushed |= LIT_WORK;
			atomic_dec(&which->num_work_pending);

			queue_work(system_wq, work);
		}
	}

	mb(); /* commit changes to pending flags */

	raw_spin_unlock_irqrestore(&which->lock, flags);
}




static void ___litmus_tasklet_schedule(struct tasklet_struct *t,
				struct klmirqd_info *which,
				int wakeup)
{
	unsigned long flags;
	u32 old_pending;

	t->next = NULL;

	raw_spin_lock_irqsave(&which->lock, flags);

	*(which->pending_tasklets.tail) = t;
	which->pending_tasklets.tail = &t->next;

	old_pending = which->pending;
	which->pending |= LIT_TASKLET_LOW;

	atomic_inc(&which->num_low_pending);

	mb();

	if(!old_pending && wakeup)
		wakeup_litirqd_locked(which); /* wake up the klmirqd */

	raw_spin_unlock_irqrestore(&which->lock, flags);
}


int __litmus_tasklet_schedule(struct tasklet_struct *t,
				struct task_struct* klmirqd_thread)
{
	int ret = 0; /* assume failure */
	struct klmirqd_info* info;

	if (unlikely(!is_realtime(klmirqd_thread) ||
		!tsk_rt(klmirqd_thread)->is_interrupt_task ||
		!tsk_rt(klmirqd_thread)->klmirqd_info)) {
		TRACE("can't handle tasklets\n");
		return ret;
	}

	info = tsk_rt(klmirqd_thread)->klmirqd_info;

	if (likely(!info->terminating)) {
		ret = 1;
		___litmus_tasklet_schedule(t, info, 1);
	}
	else {
		TRACE("Tasklet rejected because %s/%d is terminating\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
	}
	return(ret);
}

EXPORT_SYMBOL(__litmus_tasklet_schedule);


static void ___litmus_tasklet_hi_schedule(struct tasklet_struct *t,
				struct klmirqd_info *which,
				int wakeup)
{
	unsigned long flags;
	u32 old_pending;

	t->next = NULL;

	raw_spin_lock_irqsave(&which->lock, flags);

	*(which->pending_tasklets_hi.tail) = t;
	which->pending_tasklets_hi.tail = &t->next;

	old_pending = which->pending;
	which->pending |= LIT_TASKLET_HI;

	atomic_inc(&which->num_hi_pending);

	mb();

	if(!old_pending && wakeup)
		wakeup_litirqd_locked(which); /* wake up the klmirqd */

	raw_spin_unlock_irqrestore(&which->lock, flags);
}

int __litmus_tasklet_hi_schedule(struct tasklet_struct *t,
				struct task_struct* klmirqd_thread)
{
	int ret = 0; /* assume failure */
	struct klmirqd_info* info;

	if (unlikely(!is_realtime(klmirqd_thread) ||
		!tsk_rt(klmirqd_thread)->is_interrupt_task ||
		!tsk_rt(klmirqd_thread)->klmirqd_info)) {
		TRACE("%s/%d can't handle tasklets\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
		return ret;
	}

	info = tsk_rt(klmirqd_thread)->klmirqd_info;

	if (likely(!info->terminating)) {
		ret = 1;
		___litmus_tasklet_hi_schedule(t, info, 1);
	}
	else {
		TRACE("Tasklet rejected because %s/%d is terminating\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
	}

	return(ret);
}

EXPORT_SYMBOL(__litmus_tasklet_hi_schedule);


int __litmus_tasklet_hi_schedule_first(struct tasklet_struct *t,
				struct task_struct* klmirqd_thread)
{
	int ret = 0; /* assume failure */
	u32 old_pending;
	struct klmirqd_info* info;

	BUG_ON(!irqs_disabled());

	if (unlikely(!is_realtime(klmirqd_thread) ||
				 !tsk_rt(klmirqd_thread)->is_interrupt_task ||
				 !tsk_rt(klmirqd_thread)->klmirqd_info)) {
		TRACE("%s/%d can't handle tasklets\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
		return ret;
	}

	info = tsk_rt(klmirqd_thread)->klmirqd_info;

	if (likely(!info->terminating)) {

		raw_spin_lock(&info->lock);

		ret = 1;  /* success! */

		t->next = info->pending_tasklets_hi.head;
		info->pending_tasklets_hi.head = t;

		old_pending = info->pending;
		info->pending |= LIT_TASKLET_HI;

		atomic_inc(&info->num_hi_pending);

		mb();

		if(!old_pending)
			wakeup_litirqd_locked(info); /* wake up the klmirqd */

		raw_spin_unlock(&info->lock);
	}
	else {
		TRACE("Tasklet rejected because %s/%d is terminating\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
	}

	return(ret);
}

EXPORT_SYMBOL(__litmus_tasklet_hi_schedule_first);



static void ___litmus_schedule_work(struct work_struct *w,
				struct klmirqd_info *which,
				int wakeup)
{
	unsigned long flags;
	u32 old_pending;

	raw_spin_lock_irqsave(&which->lock, flags);

	work_pending(w);
	list_add_tail(&w->entry, &which->worklist);

	old_pending = which->pending;
	which->pending |= LIT_WORK;

	atomic_inc(&which->num_work_pending);

	mb();

	if(!old_pending && wakeup)
		wakeup_litirqd_locked(which); /* wakeup the klmirqd */

	raw_spin_unlock_irqrestore(&which->lock, flags);
}

int __litmus_schedule_work(struct work_struct *w, struct task_struct* klmirqd_thread)
{
	int ret = 1; /* assume success */
	struct klmirqd_info* info;

	if (unlikely(!is_realtime(klmirqd_thread) ||
				 !tsk_rt(klmirqd_thread)->is_interrupt_task ||
				 !tsk_rt(klmirqd_thread)->klmirqd_info)) {
		TRACE("%s/%d can't handle work items\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
		return ret;
	}

	info = tsk_rt(klmirqd_thread)->klmirqd_info;


	if (likely(!info->terminating)) {
		___litmus_schedule_work(w, info, 1);
	}
	else {
		TRACE("Work rejected because %s/%d is terminating\n",
			klmirqd_thread->comm, klmirqd_thread->pid);
		ret = 0;
	}

	return(ret);
}
EXPORT_SYMBOL(__litmus_schedule_work);
