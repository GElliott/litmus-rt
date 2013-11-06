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

int edf_higher_prio(struct task_struct* first, struct task_struct* second);

int edf_ready_order(struct bheap_node* a, struct bheap_node* b);

#ifdef CONFIG_LITMUS_NESTED_LOCKING
/* binheap_nodes must be embedded within 'struct litmus_lock' */
int edf_max_heap_order(struct binheap_node *a, struct binheap_node *b);
int edf_min_heap_order(struct binheap_node *a, struct binheap_node *b);
int edf_max_heap_base_priority_order(struct binheap_node *a,
				struct binheap_node *b);
int edf_min_heap_base_priority_order(struct binheap_node *a,
				struct binheap_node *b);

int __edf_higher_prio(struct task_struct* first, comparison_mode_t first_mode,
				struct task_struct* second, comparison_mode_t second_mode);
#endif

int edf_preemption_needed(rt_domain_t* rt, struct task_struct *t);

#endif
