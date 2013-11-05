#ifndef _LITMUS_BUDGET_H_
#define _LITMUS_BUDGET_H_

#include <linux/hrtimer.h>
#include <linux/semaphore.h>

#include <litmus/binheap.h>

struct enforcement_timer
{
	raw_spinlock_t lock;
	struct hrtimer timer;
	unsigned int job_when_armed;
	unsigned int armed:1;
};

int cancel_enforcement_timer(struct task_struct* t);

typedef void (*scheduled_t)(struct task_struct* t);
typedef void (*blocked_t)(struct task_struct* t);
typedef void (*preempt_t)(struct task_struct* t);
typedef void (*sleep_t)(struct task_struct* t);
typedef void (*wakeup_t)(struct task_struct* t);

#define IN_SCHEDULE 1

typedef enum hrtimer_restart (*exhausted_t)(struct task_struct* t,
				int in_schedule);
typedef void (*exit_t)(struct task_struct* t);
typedef void (*inherit_t)(struct task_struct* t, struct task_struct* prio_inh);
typedef void (*disinherit_t)(struct task_struct* t,
				struct task_struct* prio_inh);

typedef void (*enter_top_m_t)(struct task_struct* t);
typedef void (*exit_top_m_t)(struct task_struct* t);

struct budget_tracker_ops
{
	scheduled_t			on_scheduled;	/* called from litmus_schedule(). */
	blocked_t			on_blocked;		/* called from plugin::schedule() */
	preempt_t			on_preempt;		/* called from plugin::schedule() */
	sleep_t				on_sleep;		/* called from plugin::schedule() */
	wakeup_t			on_wakeup;

	exit_t				on_exit;		/* task exiting rt mode */

	/* called by plugin::tick() or timer interrupt */
	exhausted_t			on_exhausted;

	/* inheritance callbacks for bandwidth inheritance-related
	   budget tracking/enforcement methods */
	inherit_t			on_inherit;
	disinherit_t		on_disinherit;

	enter_top_m_t		on_enter_top_m;	/* task enters top-m priority tasks */
	exit_top_m_t		on_exit_top_m;	/* task exits top-m priority tasks */
};

struct budget_tracker
{
	struct enforcement_timer timer;
	const struct budget_tracker_ops* ops;
	unsigned long flags;

	struct binheap_node top_m_node;
	lt_t suspend_timestamp;
};

/* budget tracker flags */
enum BT_FLAGS
{
	BTF_BUDGET_EXHAUSTED	= 0,
	BTF_SIG_BUDGET_SENT		= 1,
	BTF_IS_TOP_M			= 2,
	BTF_WAITING_FOR_RELEASE = 3,
};

/* Functions for simple DRAIN_SIMPLE policy common
 * to every scheduler. Scheduler must provide
 * implementation for simple_on_exhausted().
 */
void simple_on_scheduled(struct task_struct* t);
void simple_on_blocked(struct task_struct* t);
void simple_on_preempt(struct task_struct* t);
void simple_on_sleep(struct task_struct* t);
void simple_on_exit(struct task_struct* t);


/* Functions for DRAIN_SIMPLE_IO policy common
 * to every scheduler. Scheduler must provide
 * implementation for simple_io_on_exhausted().
 */
#define simple_io_on_scheduled	simple_on_scheduled
void simple_io_on_blocked(struct task_struct* t);
void simple_io_on_wakeup(struct task_struct* t);
#define simple_io_on_preempt	simple_on_preempt
#define simple_io_on_sleep	simple_on_sleep
#define simple_io_on_exit	simple_on_exit


/* Functions for DRAIN_SOBLIV policy common
 * to every scheduler. Scheduler must provide
 * implementation for sobliv_on_exhausted().
 *
 * Limitation: Quantum budget tracking is unsupported.
 */
void sobliv_on_blocked(struct task_struct* t);
void sobliv_on_wakeup(struct task_struct* t);
#define sobliv_on_exit	simple_on_exit
void sobliv_on_inherit(struct task_struct* t, struct task_struct* prio_inh);
void sobliv_on_disinherit(struct task_struct* t, struct task_struct* prio_inh);
void sobliv_on_enter_top_m(struct task_struct* t);
void sobliv_on_exit_top_m(struct task_struct* t);

void reevaluate_inheritance(struct task_struct* t);

#define budget_state_machine(t, evt) \
	do { \
		if (get_budget_timer(t).ops && \
			get_budget_timer(t).ops->evt != NULL) { \
			get_budget_timer(t).ops->evt(t); \
		} \
	}while(0)

#define budget_state_machine2(t, evt, param) \
	do { \
		if (get_budget_timer(t).ops && \
			get_budget_timer(t).ops->evt != NULL) { \
			get_budget_timer(t).ops->evt(t, param); \
		} \
	}while(0)

#define budget_state_machine_chgprio(a, b, evt) \
	do { \
		if (get_budget_timer(a).ops && \
			get_budget_timer(b).ops && \
			get_budget_timer(a).ops->evt != NULL && \
			get_budget_timer(b).ops->evt != NULL) {\
			get_budget_timer(a).ops->evt(a, b); \
		} \
	}while(0)


void init_budget_tracker(struct budget_tracker* bt,
				const struct budget_tracker_ops* ops);


/* Send SIG_BUDGET to a real-time task. */
void send_sigbudget(struct task_struct* t);

#endif
