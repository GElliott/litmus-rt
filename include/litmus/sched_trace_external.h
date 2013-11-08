/*
 * sched_trace_external.h -- exposes select litmus feather-trace events
 * to modules (e.g., Litmus-aware GPL-layer of GPU device driver).
 */
#ifndef _LINUX_SCHED_TRACE_EXTERNAL_H_
#define _LINUX_SCHED_TRACE_EXTERNAL_H_

#ifdef CONFIG_SCHED_TASK_TRACE
extern void __sched_trace_tasklet_begin_external(struct task_struct* t);
static inline void sched_trace_tasklet_begin_external(struct task_struct* t)
{
	__sched_trace_tasklet_begin_external(t);
}

extern void __sched_trace_tasklet_end_external(struct task_struct* t,
				unsigned long flushed);
static inline void sched_trace_tasklet_end_external(struct task_struct* t,
				unsigned long flushed)
{
	__sched_trace_tasklet_end_external(t, flushed);
}

extern void __sched_trace_work_begin_external(struct task_struct* t,
				struct task_struct* e);
static inline void sched_trace_work_begin_external(struct task_struct* t,
				struct task_struct* e)
{
	__sched_trace_work_begin_external(t, e);
}

extern void __sched_trace_work_end_external(struct task_struct* t,
				struct task_struct* e, unsigned long f);
static inline void sched_trace_work_end_external(struct task_struct* t,
				struct task_struct* e, unsigned long f)
{
	__sched_trace_work_end_external(t, e, f);
}

#ifdef CONFIG_LITMUS_NVIDIA
extern void __sched_trace_nv_interrupt_begin_external(u32 device);
static inline void sched_trace_nv_interrupt_begin_external(u32 device)
{
	__sched_trace_nv_interrupt_begin_external(device);
}

extern void __sched_trace_nv_interrupt_end_external(u32 device);
static inline void sched_trace_nv_interrupt_end_external(u32 device)
{
	__sched_trace_nv_interrupt_end_external(device);
}
#endif /* end LITMUS_NVIDIA */
#else  /* end SCHED_TASK_TRACE def'ed */
/* no tracing. */
static inline void sched_trace_tasklet_begin_external(struct task_struct* t){}
static inline void sched_trace_tasklet_end_external(struct task_struct* t,
				unsigned long flushed){}
static inline void sched_trace_work_begin_external(struct task_struct* t,
				struct task_struct* e){}
static inline void sched_trace_work_end_external(struct task_struct* t,
				struct task_struct* e, unsigned long f){}
#ifdef CONFIG_LITMUS_NVIDIA
static inline void sched_trace_nv_interrupt_begin_external(u32 device){}
static inline void sched_trace_nv_interrupt_end_external(u32 device){}
#endif /* end LITMUS_NVIDIA */
#endif /* end SCHED_TASK_TRACE !def'ed */

#ifdef CONFIG_LITMUS_NVIDIA
#define EX_TS(evt) \
extern void __##evt(void); \
static inline void EX_##evt(void) { __##evt(); }

EX_TS(TS_NV_TOPISR_START)
EX_TS(TS_NV_TOPISR_END)
EX_TS(TS_NV_BOTISR_START)
EX_TS(TS_NV_BOTISR_END)
EX_TS(TS_NV_RELEASE_BOTISR_START)
EX_TS(TS_NV_RELEASE_BOTISR_END)

#endif /* end LITMUS_NVIDIA */

#endif /* end _LINUX_SCHED_TRACE_EXTERNAL_H_ */
