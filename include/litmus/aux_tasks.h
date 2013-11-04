#ifndef LITMUS_AUX_taskS
#define LITMUS_AUX_taskS

struct task_struct;

int make_aux_task_if_required(struct task_struct *t);

/* call on an aux task when it exits real-time */
int exit_aux_task(struct task_struct *t);

/* call when an aux_owner becomes real-time */
long enable_aux_task_owner(struct task_struct *t);

/* call when an aux_owner exits real-time */
long disable_aux_task_owner(struct task_struct *t);

/* call when an aux_owner increases its priority */
int aux_task_owner_increase_priority(struct task_struct *t);

/* call when an aux_owner decreases its priority */
int aux_task_owner_decrease_priority(struct task_struct *t);

#endif
