#ifndef __LITMUS_JOBS_H__
#define __LITMUS_JOBS_H__

void prepare_for_next_period(struct task_struct *t);
void release_at(struct task_struct *t, lt_t start);
long default_wait_for_release_at(lt_t release_time);
void setup_release(struct task_struct *t, lt_t start);
long complete_job(void);

#if defined(CONFIG_REALTIME_AUX_TASKS) || defined(CONFIG_LITMUS_NVIDIA)
typedef struct
{
#ifdef CONFIG_REALTIME_AUX_TASKS
	unsigned int aux_hide:1;
	unsigned int do_aux_restore:1;
#endif
#ifdef CONFIG_LITMUS_NVIDIA
	unsigned int gpu_hide:1;
	unsigned int do_gpu_restore:1;
#endif
} worker_visibility_t;

#if defined(CONFIG_REALTIME_AUX_TASKS) && defined(CONFIG_LITMUS_NVIDIA)
#define DECLARE_WORKER_VIS_FLAGS(symb) \
	worker_visibility_t symb = {0, 0, 0, 0}
#else
#define DECLARE_WORKER_VIS_FLAGS(symb) \
	worker_visibility_t symb = {0, 0}
#endif

void hide_from_workers(struct task_struct *t, worker_visibility_t *wv);
void show_to_workers(struct task_struct *t, worker_visibility_t *wv);
#endif /* end REALTIME_AUX_TASKS || LITMUS_NVIDIA */

#endif
