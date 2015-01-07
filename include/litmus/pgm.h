#ifndef _LITMUS_PGM_H_
#define _LITMUS_PGM_H_

#include <litmus/litmus.h>

#define is_pgm_waiting(t) (tsk_rt(t)->ctrl_page && tsk_rt(t)->ctrl_page->pgm_waiting)
#define is_pgm_waiting_with_deadline_shift(t) (is_pgm_waiting(t) && tsk_rt(t)->ctrl_page->pgm_check_deadline)
#define is_pgm_sending(t) (tsk_rt(t)->ctrl_page && tsk_rt(t)->ctrl_page->pgm_sending)
#define is_pgm_satisfied(t) (tsk_rt(t)->ctrl_page && tsk_rt(t)->ctrl_page->pgm_satisfied)

int setup_pgm_release(struct task_struct* t);

#endif
