#ifndef LITMUS_SIGNAL_H
#define LITMUS_SIGNAL_H

#ifdef __KERNEL__
#include <linux/signal.h>
#else
#include <signal.h>
#endif

/* Signals used by Litmus to asynchronously communicate events
 * to real-time tasks.
 *
 * Signal values overlap with [SIGRTMIN, SIGRTMAX], so beware of
 * application-level conflicts when dealing with COTS user-level
 * code.
 */

/* Sent to a Litmus task when all of the following conditions are true:
 * (1) The task has exhausted its budget.
 * (2) budget_signal_policy is QUANTUM_SIGNALS or PRECISE_SIGNALS.
 *
 * Note: If a task does not have a registered handler for SIG_BUDGET,
 * the signal will cause the task to terminate (default action).
 */

/* Assigned values start at SIGRTMAX and decrease, hopefully reducing
 * likelihood of user-level conflicts.
 */
#define SIG_BUDGET					(SIGRTMAX - 0)

/*
Future signals could include:

#define SIG_DEADLINE_MISS			(SIGRTMAX - 1)
#define SIG_CRIT_LEVEL_CHANGE		(SIGRTMAX - 2)
*/

#define SIGLITMUSMIN				SIG_BUDGET

#ifdef __KERNEL__
#if (SIGLITMUSMIN < SIGRTMIN)
/* no compile-time check in user-space since SIGRTMIN may be a variable. */
#error "Too many LITMUS^RT signals!"
#endif
#endif

#endif
