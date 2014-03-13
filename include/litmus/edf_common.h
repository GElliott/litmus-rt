/*
 * EDF common data structures and utility functions shared by all EDF
 * based scheduler plugins
 */

/* CLEANUP: Add comments and make it less messy.
 *
 */

#ifndef __UNC_EDF_COMMON_H__
#define __UNC_EDF_COMMON_H__

#include <litmus/rt_domain.h>

void edf_domain_init(rt_domain_t* rt, check_resched_needed_t resched,
				release_jobs_t release);

int edf_higher_prio(const struct task_struct* first, const struct task_struct* second);

int edf_ready_order(const struct bheap_node* a, const struct bheap_node* b);

/* binheap_nodes must be embedded within 'struct litmus_lock' */
int edf_max_heap_order(const struct binheap_node *a, const struct binheap_node *b);
int edf_min_heap_order(const struct binheap_node *a, const struct binheap_node *b);
int edf_max_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b);
int edf_min_heap_base_priority_order(const struct binheap_node *a,
				const struct binheap_node *b);
int edf_preemption_needed(rt_domain_t* rt, struct task_struct *t);
#ifdef CONFIG_LITMUS_NESTED_LOCKING
int __edf_higher_prio(const struct task_struct* first, comparison_mode_t first_mode,
				const struct task_struct* second, comparison_mode_t second_mode);
#endif

#endif
