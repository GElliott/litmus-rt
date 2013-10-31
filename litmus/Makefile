#
# Makefile for LITMUS^RT
#

obj-y     = sched_plugin.o litmus.o \
	    preempt.o \
	    litmus_proc.o \
	    budget.o \
	    clustered.o \
	    jobs.o \
	    sync.o \
	    rt_domain.o \
	    edf_common.o \
	    fp_common.o \
	    fdso.o \
	    locking.o \
	    srp.o \
	    bheap.o \
	    binheap.o \
	    ctrldev.o \
	    uncachedev.o \
	    sched_gsn_edf.o \
	    sched_psn_edf.o \
	    sched_pfp.o

obj-$(CONFIG_PLUGIN_CEDF) += sched_cedf.o
obj-$(CONFIG_PLUGIN_PFAIR) += sched_pfair.o
obj-$(CONFIG_SCHED_CPU_AFFINITY) += affinity.o

obj-$(CONFIG_LITMUS_LOCKING) += kfmlp_lock.o
obj-$(CONFIG_LITMUS_NESTED_LOCKING) += fifo_lock.o prioq_lock.o ikglp_lock.o
obj-$(CONFIG_LITMUS_AFFINITY_LOCKING) += kexclu_affinity.o

obj-$(CONFIG_LITMUS_SOFTIRQD) += klmirqd.o

obj-$(CONFIG_LITMUS_NVIDIA) += nvidia_info.o
ifeq ($(CONFIG_LITMUS_AFFINITY_LOCKING),y)
	obj-$(CONFIG_LITMUS_NVIDIA) += gpu_affinity.o
endif

obj-$(CONFIG_FEATHER_TRACE) += ft_event.o ftdev.o
obj-$(CONFIG_SCHED_TASK_TRACE) += sched_task_trace.o
obj-$(CONFIG_SCHED_DEBUG_TRACE) += sched_trace.o
obj-$(CONFIG_SCHED_OVERHEAD_TRACE) += trace.o
