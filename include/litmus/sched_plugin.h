/*
 * Definition of the scheduler plugin interface.
 *
 */
#ifndef _LINUX_SCHED_PLUGIN_H_
#define _LINUX_SCHED_PLUGIN_H_

#include <linux/sched.h>

#ifdef CONFIG_LITMUS_LOCKING
#include <litmus/locking.h>
#endif

/************************ setup/tear down ********************/

typedef long (*activate_plugin_t) (void);
typedef long (*deactivate_plugin_t) (void);

struct domain_proc_info;
typedef long (*get_domain_proc_info_t) (struct domain_proc_info **info);

/********************* scheduler invocation ******************/

/*  Plugin-specific realtime tick handler */
typedef void (*scheduler_tick_t) (struct task_struct *cur);
/* Novell make sched decision function */
typedef struct task_struct* (*schedule_t)(struct task_struct * prev);
/* Clean up after the task switch has occured.
 * This function is called after every (even non-rt) task switch.
 */
typedef void (*finish_switch_t)(struct task_struct *prev);


/********************* task state changes ********************/

/* Called to setup a new real-time task.
 * Release the first job, enqueue, etc.
 * Task may already be running.
 */
typedef void (*task_new_t) (struct task_struct *task,
			    int on_rq,
			    int running);

/* Called to re-introduce a task after blocking.
 * Can potentially be called multiple times.
 */
typedef void (*task_wake_up_t) (struct task_struct *task);
/* called to notify the plugin of a blocking real-time task
 * it will only be called for real-time tasks and before schedule is called */
typedef void (*task_block_t)  (struct task_struct *task);
/* Called when a real-time task exits or changes to a different scheduling
 * class.
 * Free any allocated resources
 */
typedef void (*task_exit_t)    (struct task_struct *);

/* task_exit() is called with interrupts disabled and runqueue locks held, and
 * thus and cannot block or spin.  task_cleanup() is called sometime later
 * without any locks being held.
 */
typedef void (*task_cleanup_t)	(struct task_struct *);

/**************************** misc ***************************/

/* Called to compare the scheduling priorities between two tasks */
typedef int (*higher_prio_t)(struct task_struct* a, struct task_struct* b);

/************** locking and inheritance routines *************/
#ifdef CONFIG_LITMUS_LOCKING
/* Called when the current task attempts to create a new lock of a given
 * protocol type. */
typedef long (*allocate_lock_t) (struct litmus_lock **lock, int type,
				void* __user config);

typedef void (*increase_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh);
typedef void (*decrease_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh, int budget_triggered);
typedef int (*__increase_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh);
typedef int (*__decrease_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh, int budget_triggered);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
typedef enum
{
	BASE,
	EFFECTIVE
} comparison_mode_t;

typedef void (*nested_increase_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh, raw_spinlock_t *to_unlock,
				unsigned long irqflags);
typedef void (*nested_decrease_prio_t)(struct task_struct* t,
				struct task_struct* prio_inh, raw_spinlock_t *to_unlock,
				unsigned long irqflags, int budget_triggered);
typedef int (*__higher_prio_t)(struct task_struct* a, comparison_mode_t a_mod,
				struct task_struct* b, comparison_mode_t b_mod);
#endif /* end LITMUS_NESTED_LOCKING */

#ifdef CONFIG_LITMUS_DGL_SUPPORT
typedef raw_spinlock_t* (*get_dgl_spinlock_t) (struct task_struct *t);
#endif /* end LITMUS_DGL_SUPPORT */

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
struct affinity_observer;
typedef long (*allocate_affinity_observer_t) (
				struct affinity_observer **aff_obs, int type,
				void* __user config);
#endif /* end LITMUS_AFFINITY_LOCKING */
#endif /* end LITMUS_LOCKING */

#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
typedef int (*default_cpu_for_gpu_t)(int gpu);
#endif

/********************* sys call backends  ********************/
/* This function causes the caller to sleep until the next release */
typedef long (*complete_job_t) (void);

typedef long (*admit_task_t)(struct task_struct* tsk);

typedef long (*wait_for_release_at_t)(lt_t release_time);

/************************ misc routines ***********************/


struct sched_plugin {
	struct list_head	list;
	/* 	basic info 		*/
	char 			*plugin_name;

	/*	setup			*/
	activate_plugin_t	activate_plugin;
	deactivate_plugin_t	deactivate_plugin;
	get_domain_proc_info_t	get_domain_proc_info;

	/* 	scheduler invocation 	*/
	scheduler_tick_t	tick;
	schedule_t		schedule;
	finish_switch_t 	finish_switch;

	/*	syscall backend 	*/
	complete_job_t 		complete_job;
	wait_for_release_at_t	wait_for_release_at;

	/*	task state changes 	*/
	admit_task_t		admit_task;

	task_new_t		task_new;
	task_wake_up_t		task_wake_up;
	task_block_t		task_block;

	task_exit_t 		task_exit;
	task_cleanup_t		task_cleanup;

	/*  misc */
	higher_prio_t		compare;

#ifdef CONFIG_LITMUS_LOCKING
	/*	locking protocols	*/
	allocate_lock_t		allocate_lock;
	increase_prio_t		increase_prio;
	decrease_prio_t		decrease_prio;
	/*  varients that don't take scheduler locks */
	__increase_prio_t	__increase_prio;
	__decrease_prio_t	__decrease_prio;
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	/* nested locking */
	nested_increase_prio_t	nested_increase_prio;
	nested_decrease_prio_t	nested_decrease_prio;
	__higher_prio_t		__compare;
#endif /* end NESTED_LOCKING */

#ifdef CONFIG_LITMUS_DGL_SUPPORT
	get_dgl_spinlock_t	get_dgl_spinlock;
#endif /* end LITMUS_DGL_SUPPORT */

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	allocate_affinity_observer_t allocate_aff_obs;
#endif /* end LITMUS_AFFINITY_LOCKING */
#endif /* end LITMUS_LOCKING */

#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
	default_cpu_for_gpu_t	map_gpu_to_cpu;
#endif
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));


extern struct sched_plugin *litmus;

int register_sched_plugin(struct sched_plugin* plugin);
struct sched_plugin* find_sched_plugin(const char* name);
void print_sched_plugins(struct seq_file *m);

extern struct sched_plugin linux_sched_plugin;

#endif
