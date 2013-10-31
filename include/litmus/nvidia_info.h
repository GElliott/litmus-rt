#ifndef __LITMUS_NVIDIA_H
#define __LITMUS_NVIDIA_H

#include <linux/interrupt.h>

#ifdef CONFIG_LITMUS_SOFTIRQD
#include <litmus/klmirqd.h>
#endif

#define NV_DEVICE_NUM CONFIG_NV_DEVICE_NUM

/* TODO: Make this a function that checks the PCIe bus
   or maybe proc settings */
#define num_online_gpus() (NV_DEVICE_NUM)


/* Functions used for decoding NVIDIA blobs. */

int init_nvidia_info(void);
void shutdown_nvidia_info(void);

int is_nvidia_func(void* func_addr);

struct work_struct;
int nv_schedule_work(struct work_struct *work);

struct tasklet_struct;
void nv_tasklet_schedule(struct tasklet_struct *t);
void nv_tasklet_hi_schedule(struct tasklet_struct *t);
void nv_tasklet_hi_schedule_first(struct tasklet_struct *t);

/* Returns the NVIDIA device # associated with provided tasklet
   and work_struct. */
u32 get_tasklet_nv_device_num(const struct tasklet_struct *t);
u32 get_work_nv_device_num(const struct work_struct *t);

/* Functions for figuring out the priority of GPU-using tasks */

struct task_struct* get_nv_max_device_owner(u32 target_device_id);

#ifdef CONFIG_LITMUS_SOFTIRQD
struct task_struct* get_and_lock_nvklmirqd_thread(u32 target_device_id,
				unsigned long* flags);
void unlock_nvklmirqd_thread(u32 target_device_id, unsigned long* flags);
struct task_struct* get_nvklmirqd_thread(u32 target_device_id);

typedef int (*klmirqd_tasklet_sched_t)(struct tasklet_struct *t,
				struct task_struct* klmirqd_th);
int nv_tasklet_schedule_klmirqd(struct tasklet_struct *t,
				klmirqd_tasklet_sched_t klmirqd_func);

#if defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON) || \
	defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED)
struct task_struct* get_and_lock_nvklmworkqd_thread(u32 target_device_id,
				unsigned long* flags);
void unlock_nvklmworkqd_thread(u32 target_device_id, unsigned long* flags);
struct task_struct* get_nvklmworkqd_thread(u32 target_device_id);

struct work_struct;
int nv_schedule_work_klmirqd(struct work_struct *work);
#endif /* end LITMUS_NVIDIA_WORKQ_ON || LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
#endif /* end LITMUS_SOFTIRQD */

#ifdef CONFIG_LITMUS_NVIDIA_NONSPLIT_INTERRUPTS
void nv_tasklet_schedule_now(struct tasklet_struct *t);
#endif

/* call when the GPU-holding task, t, blocks */
long enable_gpu_owner(struct task_struct *t);

/* call when the GPU-holding task, t, resumes */
long disable_gpu_owner(struct task_struct *t);

/* call when the GPU-holding task, t, had a priority change due to budget
   exhaustion */
long recheck_gpu_owner(struct task_struct* t);

/* call when the GPU-holding task, t, increases its priority */
int gpu_owner_increase_priority(struct task_struct *t);

/* call when the GPU-holding task, t, decreases its priority */
int gpu_owner_decrease_priority(struct task_struct *t);

/* Register a thread as owning a given GPU. Used to properly prioritize
   the scheduling of GPU tasklets and workqueue work. */
int reg_nv_device(int reg_device_id, int reg_action, struct task_struct *t);

#endif
