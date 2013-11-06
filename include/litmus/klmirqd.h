#ifndef __LITMUS_SOFTIRQ_H
#define __LITMUS_SOFTIRQ_H

#include <linux/workqueue.h>
#include <linux/interrupt.h>

/*
   Threaded tasklet/workqueue handling for Litmus.
   Items are scheduled in the following order: hi-tasklet,
   lo-tasklet, workqueue.  Items are scheduled in FIFO order
   within each of these classes.

   klmirqd assumes the priority of the owner of the
   tasklet when the tasklet is next to execute.

   The base-priority of a klimirqd thread is below all regular
   real-time tasks, but above all other Linux scheduling
   classes (klmirqd threads are within the SHCED_LITMUS class).
   Regular real-time tasks may increase the priority of
   a klmirqd thread, but klmirqd is unaware of this
   (this was not the case in prior incarnations of klmirqd).
 */


/* Initialize klmirqd */
void init_klmirqd(void);

/* Raises a flag to tell klmirqds to terminate.
 Termination is async, so some threads may be running
 after function return. */
void kill_klmirqd(void);

void kill_klmirqd_thread(struct task_struct* klmirqd_thread);

/* Returns 1 if all NR_LITMUS_SOFTIRQD klitirqs are ready
 to handle tasklets. 0, otherwise.*/
int klmirqd_is_ready(void);

/* Returns 1 if no NR_LITMUS_SOFTIRQD klitirqs are ready
 to handle tasklets. 0, otherwise.*/
int klmirqd_is_dead(void);


typedef int (*klmirqd_cb_t) (void *arg);

typedef struct
{
	klmirqd_cb_t func;
	void* arg;
} klmirqd_callback_t;

/* Launches a klmirqd thread with the provided affinity.

   Actual launch of threads is deffered to kworker's
   workqueue, so daemons will likely not be immediately
   running when this function returns, though the required
   data will be initialized.

   cpu == -1 for no affinity

   provide a name at most 31 (32, + null terminator) characters long.
   name == NULL for a default name.  (all names are appended with
   base-CPU affinity)
 */
#define MAX_KLMIRQD_NAME_LEN 31
int launch_klmirqd_thread(char* name, int cpu, klmirqd_callback_t* cb);

/* Flushes all pending work out to the OS for regular
 * tasklet/work processing.
 */
void flush_pending(struct task_struct* klmirqd_thread);


/*** tasklet scheduling ***/

extern int __litmus_tasklet_schedule(
		struct tasklet_struct *t,
		struct task_struct *klmirqd_thread);

/* schedule a tasklet on klmirqd #k_id */
static inline int litmus_tasklet_schedule(
	struct tasklet_struct *t,
	struct task_struct *klmirqd_thread)
{
	int ret = 0;
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		ret = __litmus_tasklet_schedule(t, klmirqd_thread);
	}
	return(ret);
}

/* for use by __tasklet_schedule() */
static inline int _litmus_tasklet_schedule(
	struct tasklet_struct *t,
	struct task_struct *klmirqd_thread)
{
	return(__litmus_tasklet_schedule(t, klmirqd_thread));
}


/*** tasklet_hi scheduling ***/

extern int __litmus_tasklet_hi_schedule(struct tasklet_struct *t,
				struct task_struct *klmirqd_thread);

/* schedule a hi tasklet on klmirqd #k_id */
static inline int litmus_tasklet_hi_schedule(struct tasklet_struct *t,
				struct task_struct *klmirqd_thread)
{
	int ret = 0;
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		ret = __litmus_tasklet_hi_schedule(t, klmirqd_thread);
	}
	return(ret);
}

/* for use by __tasklet_hi_schedule() */
static inline int _litmus_tasklet_hi_schedule(struct tasklet_struct *t,
				struct task_struct *klmirqd_thread)
{
	return(__litmus_tasklet_hi_schedule(t, klmirqd_thread));
}


extern int __litmus_tasklet_hi_schedule_first(
	struct tasklet_struct *t,
	struct task_struct *klmirqd_thread);

/* schedule a hi tasklet on klmirqd #k_id on next go-around */
/* PRECONDITION: Interrupts must be disabled. */
static inline int litmus_tasklet_hi_schedule_first(
	struct tasklet_struct *t,
	struct task_struct *klmirqd_thread)
{
	int ret = 0;
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
		ret = __litmus_tasklet_hi_schedule_first(t, klmirqd_thread);
	return(ret);
}

/* for use by __tasklet_hi_schedule_first() */
static inline int _litmus_tasklet_hi_schedule_first(
	struct tasklet_struct *t,
	struct task_struct *klmirqd_thread)
{
	return(__litmus_tasklet_hi_schedule_first(t, klmirqd_thread));
}


/*** work_struct scheduling ***/

extern int __litmus_schedule_work(
	struct work_struct *w,
	struct task_struct *klmirqd_thread);

static inline int litmus_schedule_work(
	struct work_struct *w,
	struct task_struct *klmirqd_thread)
{
	int ret = 0;
	if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(w)))
		ret = __litmus_schedule_work(w, klmirqd_thread);
	return(ret);
}

static inline int _litmus_schedule_work(
	struct work_struct *w,
	struct task_struct *klmirqd_thread)
{
	return(__litmus_schedule_work(w, klmirqd_thread));
}

#endif
