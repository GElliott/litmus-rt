#include <linux/module.h>

#include <litmus/trace.h>
#include <litmus/sched_trace.h>
#include <litmus/litmus.h>

void __sched_trace_tasklet_begin_external(struct task_struct* t)
{
	sched_trace_tasklet_begin(t);
}
EXPORT_SYMBOL(__sched_trace_tasklet_begin_external);

void __sched_trace_tasklet_end_external(struct task_struct* t,
				unsigned long flushed)
{
	sched_trace_tasklet_end(t, flushed);
}
EXPORT_SYMBOL(__sched_trace_tasklet_end_external);

void __sched_trace_work_begin_external(struct task_struct* t,
				struct task_struct* e)
{
	sched_trace_work_begin(t, e);
}
EXPORT_SYMBOL(__sched_trace_work_begin_external);

void __sched_trace_work_end_external(struct task_struct* t,
				struct task_struct* e, unsigned long f)
{
	sched_trace_work_end(t, e, f);
}
EXPORT_SYMBOL(__sched_trace_work_end_external);

#ifdef CONFIG_LITMUS_NVIDIA
void __sched_trace_nv_interrupt_begin_external(u32 device)
{
	sched_trace_nv_interrupt_begin((unsigned long)device);
}
EXPORT_SYMBOL(__sched_trace_nv_interrupt_begin_external);

void __sched_trace_nv_interrupt_end_external(u32 device)
{
	sched_trace_nv_interrupt_end((unsigned long)device);
}
EXPORT_SYMBOL(__sched_trace_nv_interrupt_end_external);
#endif /* end LITMUS_NVIDIA */
