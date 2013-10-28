/* sched_plugin.c -- core infrastructure for the scheduler plugin system
 *
 * This file includes the initialization of the plugin system, the no-op Linux
 * scheduler plugin, some dummy functions, and some helper functions.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/preempt.h>
#include <litmus/jobs.h>

/*
 * Generic function to trigger preemption on either local or remote cpu
 * from scheduler plugins. The key feature is that this function is
 * non-preemptive section aware and does not invoke the scheduler / send
 * IPIs if the to-be-preempted task is actually non-preemptive.
 */
void preempt_if_preemptable(struct task_struct* t, int cpu)
{
	/* t is the real-time task executing on CPU on_cpu If t is NULL, then
	 * on_cpu is currently scheduling background work.
	 */

	int reschedule = 0;

	if (!t)
		/* move non-real-time task out of the way */
		reschedule = 1;
	else {
		if (smp_processor_id() == cpu) {
			/* local CPU case */
			/* check if we need to poke userspace */
			if (is_user_np(t))
				/* Yes, poke it. This doesn't have to be atomic since
				 * the task is definitely not executing. */
				request_exit_np(t);
			else if (!is_kernel_np(t))
				/* only if we are allowed to preempt the
				 * currently-executing task */
				reschedule = 1;
		} else {
			/* Remote CPU case.  Only notify if it's not a kernel
			 * NP section and if we didn't set the userspace
			 * flag. */
			reschedule = !(is_kernel_np(t) || request_exit_np_atomic(t));
		}
	}
	if (likely(reschedule))
		litmus_reschedule(cpu);
}


/*************************************************************
 *                   Dummy plugin functions                  *
 *************************************************************/

static void litmus_dummy_finish_switch(struct task_struct * prev)
{
}

static struct task_struct* litmus_dummy_schedule(struct task_struct * prev)
{
	sched_state_task_picked();
	return NULL;
}

static void litmus_dummy_tick(struct task_struct* tsk)
{
}

static long litmus_dummy_admit_task(struct task_struct* tsk)
{
	printk(KERN_CRIT "LITMUS^RT: Linux plugin rejects %s/%d.\n",
		tsk->comm, tsk->pid);
	return -EINVAL;
}

static void litmus_dummy_task_new(struct task_struct *t, int on_rq, int running)
{
}

static void litmus_dummy_task_wake_up(struct task_struct *task)
{
}

static void litmus_dummy_task_block(struct task_struct *task)
{
}

static void litmus_dummy_task_exit(struct task_struct *task)
{
}

static void litmus_dummy_task_cleanup(struct task_struct *task)
{
}

static long litmus_dummy_complete_job(void)
{
	return -ENOSYS;
}

static long litmus_dummy_activate_plugin(void)
{
	return 0;
}

static long litmus_dummy_deactivate_plugin(void)
{
	return 0;
}

static long litmus_dummy_get_domain_proc_info(struct domain_proc_info **d)
{
	*d = NULL;
	return 0;
}

#ifdef CONFIG_LITMUS_LOCKING
static int litmus_dummy_compare(struct task_struct* a, struct task_struct* b)
{
	TRACE_CUR("WARNING: Dummy compare function called!\n");
	return 0;
}

static long litmus_dummy_allocate_lock(struct litmus_lock **lock, int type,
				void* __user config)
{
	return -ENXIO;
}

static void litmus_dummy_increase_prio(struct task_struct* t,
				struct task_struct* prio_inh)
{
}

static void litmus_dummy_decrease_prio(struct task_struct* t,
				struct task_struct* prio_inh, int budget_triggered)
{
}

static int litmus_dummy___increase_prio(struct task_struct* t,
				struct task_struct* prio_inh)
{
	TRACE_CUR("WARNING: Dummy litmus_dummy___increase_prio called!\n");
	return 0;
}

static int litmus_dummy___decrease_prio(struct task_struct* t,
				struct task_struct* prio_inh, int budget_triggered)
{
	TRACE_CUR("WARNING: Dummy litmus_dummy___decrease_prio called!\n");
	return 0;
}
#endif

#ifdef CONFIG_LITMUS_NESTED_LOCKING
static void litmus_dummy_nested_increase_prio(struct task_struct* t,
				struct task_struct* prio_inh,
				raw_spinlock_t *to_unlock, unsigned long irqflags)
{
}

static void litmus_dummy_nested_decrease_prio(struct task_struct* t,
				struct task_struct* prio_inh,
				raw_spinlock_t *to_unlock, unsigned long irqflags,
				int budget_triggered)
{
}

static int litmus_dummy___compare(
				struct task_struct* a, comparison_mode_t a_mod,
				struct task_struct* b, comparison_mode_t b_mode)
{
	TRACE_CUR("WARNING: Dummy compare function called!\n");
	return 0;
}
#endif

#ifdef CONFIG_LITMUS_DGL_SUPPORT
static raw_spinlock_t* litmus_dummy_get_dgl_spinlock(struct task_struct *t)
{
	return NULL;
}
#endif

#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
static long litmus_dummy_allocate_aff_obs(struct affinity_observer **aff_obs,
				int type,
				void* __user config)
{
	return -ENXIO;
}
#endif

#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
static int litmus_dummy_map_gpu_to_cpu(int gpu)
{
	return 0;
}
#endif

/* The default scheduler plugin. It doesn't do anything and lets Linux do its
 * job.
 */
struct sched_plugin linux_sched_plugin = {
	.plugin_name = "Linux",
	.tick = litmus_dummy_tick,
	.task_new   = litmus_dummy_task_new,
	.task_exit = litmus_dummy_task_exit,
	.task_wake_up = litmus_dummy_task_wake_up,
	.task_block = litmus_dummy_task_block,
	.complete_job = litmus_dummy_complete_job,
	.schedule = litmus_dummy_schedule,
	.finish_switch = litmus_dummy_finish_switch,
	.activate_plugin = litmus_dummy_activate_plugin,
	.deactivate_plugin = litmus_dummy_deactivate_plugin,
	.get_domain_proc_info = litmus_dummy_get_domain_proc_info,
#ifdef CONFIG_LITMUS_LOCKING
	.compare = litmus_dummy_compare,
	.allocate_lock = litmus_dummy_allocate_lock,
	.increase_prio = litmus_dummy_increase_prio,
	.decrease_prio = litmus_dummy_decrease_prio,
	.__increase_prio = litmus_dummy___increase_prio,
	.__decrease_prio = litmus_dummy___decrease_prio,
#endif
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	.nested_increase_prio = litmus_dummy_nested_increase_prio,
	.nested_decrease_prio = litmus_dummy_nested_decrease_prio,
	.__compare = litmus_dummy___compare,
#endif
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	.get_dgl_spinlock = litmus_dummy_get_dgl_spinlock,
#endif
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	.allocate_aff_obs = litmus_dummy_allocate_aff_obs,
#endif
#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
	.map_gpu_to_cpu = litmus_dummy_map_gpu_to_cpu,
#endif
	.admit_task = litmus_dummy_admit_task
};

/*
 *	The reference to current plugin that is used to schedule tasks within
 *	the system. It stores references to actual function implementations
 *	Should be initialized by calling "init_***_plugin()"
 */
struct sched_plugin *litmus = &linux_sched_plugin;

/* the list of registered scheduling plugins */
static LIST_HEAD(sched_plugins);
static DEFINE_RAW_SPINLOCK(sched_plugins_lock);

#define CHECK(func) {\
	if (!plugin->func) \
		plugin->func = litmus_dummy_ ## func;}

/* FIXME: get reference to module  */
int register_sched_plugin(struct sched_plugin* plugin)
{
	printk(KERN_INFO "Registering LITMUS^RT plugin %s.\n",
	       plugin->plugin_name);

	/* make sure we don't trip over null pointers later */
	CHECK(finish_switch);
	CHECK(schedule);
	CHECK(tick);
	CHECK(task_wake_up);
	CHECK(task_exit);
	CHECK(task_cleanup);
	CHECK(task_block);
	CHECK(task_new);
	CHECK(complete_job);
	CHECK(activate_plugin);
	CHECK(deactivate_plugin);
	CHECK(get_domain_proc_info);
#ifdef CONFIG_LITMUS_LOCKING
	CHECK(compare);
	CHECK(allocate_lock);
	CHECK(increase_prio);
	CHECK(decrease_prio);
	CHECK(__increase_prio);
	CHECK(__decrease_prio);
#endif
#ifdef CONFIG_LITMUS_NESTED_LOCKING
	CHECK(nested_increase_prio);
	CHECK(nested_decrease_prio);
	CHECK(__compare);
#endif
#ifdef CONFIG_LITMUS_DGL_SUPPORT
	CHECK(get_dgl_spinlock);
#endif
#ifdef CONFIG_LITMUS_AFFINITY_LOCKING
	CHECK(allocate_aff_obs);
#endif
#if defined(CONFIG_LITMUS_NVIDIA) && defined(CONFIG_LITMUS_SOFTIRQD)
	CHECK(map_gpu_to_cpu);
#endif
	CHECK(admit_task);

	if (!plugin->wait_for_release_at)
		plugin->wait_for_release_at = default_wait_for_release_at;

	raw_spin_lock(&sched_plugins_lock);
	list_add(&plugin->list, &sched_plugins);
	raw_spin_unlock(&sched_plugins_lock);

	return 0;
}


/* FIXME: reference counting, etc. */
struct sched_plugin* find_sched_plugin(const char* name)
{
	struct list_head *pos;
	struct sched_plugin *plugin;

	raw_spin_lock(&sched_plugins_lock);
	list_for_each(pos, &sched_plugins) {
		plugin = list_entry(pos, struct sched_plugin, list);
		if (!strcmp(plugin->plugin_name, name))
		    goto out_unlock;
	}
	plugin = NULL;

out_unlock:
	raw_spin_unlock(&sched_plugins_lock);
	return plugin;
}

void print_sched_plugins(struct seq_file *m)
{
	struct list_head *pos;
	struct sched_plugin *plugin;

	raw_spin_lock(&sched_plugins_lock);
	list_for_each(pos, &sched_plugins) {
		plugin = list_entry(pos, struct sched_plugin, list);
		seq_printf(m, "%s\n", plugin->plugin_name);
	}
	raw_spin_unlock(&sched_plugins_lock);
}
