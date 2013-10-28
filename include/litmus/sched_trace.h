/*
 * sched_trace.h -- record scheduler events to a byte stream for offline analysis.
 */
#ifndef _LINUX_SCHED_TRACE_H_
#define _LINUX_SCHED_TRACE_H_

/* all times in nanoseconds */

struct st_trace_header {
	u8	type;		/* Of what type is this record?  */
	u8	cpu;		/* On which CPU was it recorded? */
	u16	pid;		/* PID of the task.              */
	u32	job:24;		/* The job sequence number.      */
	u8	extra;
} __attribute__((packed));

#define ST_NAME_LEN 16
struct st_name_data {
	char	cmd[ST_NAME_LEN];/* The name of the executable of this process. */
} __attribute__((packed));

struct st_param_data {		/* regular params */
	u32	wcet;
	u32	period;
	u32	phase;
	u8	partition;
	u8	class;
	u8	__unused[2];
} __attribute__((packed));

struct st_release_data {	/* A job is was/is going to be released. */
	u64	release;	/* What's the release time?              */
	u64	deadline;	/* By when must it finish?		 */
} __attribute__((packed));

struct st_assigned_data {	/* A job was asigned to a CPU. 		 */
	u64	when;
	u8	target;		/* Where should it execute?	         */
	u8	__unused[7];
} __attribute__((packed));

struct st_switch_to_data {	/* A process was switched to on a given CPU.   */
	u64	when;		/* When did this occur?                        */
	u32	exec_time;	/* Time the current job has executed.          */
	u8	__unused[4];
} __attribute__((packed));

struct st_switch_away_data {	/* A process was switched away from on a given CPU. */
	u64	when;
	u64	exec_time;
} __attribute__((packed));

struct st_completion_data {	/* A job completed. */
	u64	when;
	u64	backlog_remaining:62;
	u8	was_backlog_job:1;
	u8	forced:1; 	/* Set to 1 if job overran and kernel advanced to the
		           * next task automatically; set to 0 otherwise. */
} __attribute__((packed));

struct st_block_data {		/* A task blocks. */
	u64	when;
	u8	for_io;
	u8	__unused[7];
} __attribute__((packed));

struct st_resume_data {		/* A task resumes. */
	u64	when;
	u64	__unused;
} __attribute__((packed));

struct st_action_data {
	u64	when;
	u32	action;
	u8	__unused[4];
} __attribute__((packed));

struct st_sys_release_data {
	u64	when;
	u64	release;
} __attribute__((packed));


struct st_tasklet_release_data {
	u64 when;
	u32 device;
	u32 __unused;
} __attribute__((packed));

struct st_tasklet_begin_data {
	u64 when;
	u16 exe_pid;
	u8  __unused[6];
} __attribute__((packed));

struct st_tasklet_end_data {
	u64 when;
	u16 exe_pid;
	u8	flushed;
	u8	__unused[5];
} __attribute__((packed));


struct st_work_release_data {
	u64 when;
	u32 device;
	u32 __unused;
} __attribute__((packed));

struct st_work_begin_data {
	u64 when;
	u16 exe_pid;
	u8	__unused[6];
} __attribute__((packed));

struct st_work_end_data {
	u64 when;
	u16 exe_pid;
	u8	flushed;
	u8	__unused[5];
} __attribute__((packed));

struct st_effective_priority_change_data {
	u64 when;
	u32 inh_pid;
	u32 prev_inh_pid;
} __attribute__((packed));

struct st_nv_interrupt_begin_data {
	u64 when;
	u32 device;
	u32 serialNumber;
} __attribute__((packed));

struct st_nv_interrupt_end_data {
	u64 when;
	u32 device;
	u32 serialNumber;
} __attribute__((packed));

struct st_migration_data {
	u64 observed;
	u64 estimated;
} __attribute__((packed));


/* passed as an argument to tracing for st_migration_data */
struct migration_info {
	u64 observed;
	u64 estimated;
	u8 distance;
};

struct st_lock_data{
	u64 when;
	u32 lock_id;
	u8	acquired;
	u8	__unused[3];
} __attribute__((packed));

#define DATA(x) struct st_ ## x ## _data x;

typedef enum {
        ST_NAME = 1,		/* Start at one, so that we can spot
				 * uninitialized records. */
	ST_PARAM,
	ST_RELEASE,
	ST_ASSIGNED,
	ST_SWITCH_TO,
	ST_SWITCH_AWAY,
	ST_COMPLETION,
	ST_BLOCK,
	ST_RESUME,
	ST_ACTION,
	ST_SYS_RELEASE,
	ST_TASKLET_RELEASE,
	ST_TASKLET_BEGIN,
	ST_TASKLET_END,
	ST_WORK_RELEASE,
	ST_WORK_BEGIN,
	ST_WORK_END,
	ST_EFF_PRIO_CHANGE,
	ST_NV_INTERRUPT_BEGIN,
	ST_NV_INTERRUPT_END,

	ST_MIGRATION,
	ST_LOCK
} st_event_record_type_t;

struct st_event_record {
	struct st_trace_header hdr;
	union {
		u64 raw[2];

		DATA(name);
		DATA(param);
		DATA(release);
		DATA(assigned);
		DATA(switch_to);
		DATA(switch_away);
		DATA(completion);
		DATA(block);
		DATA(resume);
		DATA(action);
		DATA(sys_release);
		DATA(tasklet_release);
		DATA(tasklet_begin);
		DATA(tasklet_end);
		DATA(work_release);
		DATA(work_begin);
		DATA(work_end);
		DATA(effective_priority_change);
		DATA(nv_interrupt_begin);
		DATA(nv_interrupt_end);

		DATA(migration);
		DATA(lock);
	} data;
} __attribute__((packed));

#undef DATA

#ifdef __KERNEL__

#include <linux/sched.h>
#include <litmus/feather_trace.h>

#ifdef CONFIG_SCHED_TASK_TRACE

#define SCHED_TRACE(id, callback, task) \
	ft_event1(id, callback, task)
#define SCHED_TRACE2(id, callback, task, xtra) \
	ft_event2(id, callback, task, xtra)
#define SCHED_TRACE3(id, callback, task, xtra1, xtra2) \
	ft_event3(id, callback, task, xtra1, xtra2)

/* provide prototypes; needed on sparc64 */
#ifndef NO_TASK_TRACE_DECLS
feather_callback void do_sched_trace_task_name(unsigned long id,
					       struct task_struct* task);
feather_callback void do_sched_trace_task_param(unsigned long id,
						struct task_struct* task);
feather_callback void do_sched_trace_task_release(unsigned long id,
						  struct task_struct* task);
feather_callback void do_sched_trace_task_switch_to(unsigned long id,
						    struct task_struct* task);
feather_callback void do_sched_trace_task_switch_away(unsigned long id,
						      struct task_struct* task);
feather_callback void do_sched_trace_task_completion(unsigned long id,
						     struct task_struct* task,
						     unsigned long forced);
feather_callback void do_sched_trace_task_block(unsigned long id,
						struct task_struct* task);
feather_callback void do_sched_trace_task_resume(unsigned long id,
						 struct task_struct* task);
feather_callback void do_sched_trace_action(unsigned long id,
					    struct task_struct* task,
					    unsigned long action);
feather_callback void do_sched_trace_sys_release(unsigned long id,
						 lt_t* start);


feather_callback void do_sched_trace_tasklet_release(unsigned long id,
												   struct task_struct* owner,
												   u32 device);
feather_callback void do_sched_trace_tasklet_begin(unsigned long id,
												  struct task_struct* owner);
feather_callback void do_sched_trace_tasklet_end(unsigned long id,
												 struct task_struct* owner,
												 unsigned long flushed);

feather_callback void do_sched_trace_work_release(unsigned long id,
													 struct task_struct* owner,
													 u32 device);
feather_callback void do_sched_trace_work_begin(unsigned long id,
												struct task_struct* owner,
												struct task_struct* exe);
feather_callback void do_sched_trace_work_end(unsigned long id,
											  struct task_struct* owner,
											  struct task_struct* exe,
											  unsigned long flushed);

feather_callback void do_sched_trace_eff_prio_change(unsigned long id,
											  struct task_struct* task,
											  struct task_struct* inh);

feather_callback void do_sched_trace_nv_interrupt_begin(unsigned long id,
												u32 device);
feather_callback void do_sched_trace_nv_interrupt_end(unsigned long id,
												unsigned long unused);

feather_callback void do_sched_trace_migration(unsigned long id,
											  struct task_struct* task,
											  struct migration_info* mig_info);

feather_callback void do_sched_trace_lock(unsigned long id,
										  struct task_struct* task,
										  unsigned long lock_id,
										  unsigned long acquired);

/* returns true if we're tracing an interrupt on current CPU */
/* int is_interrupt_tracing_active(void); */

#endif

#else

#define SCHED_TRACE(id, callback, task)        /* no tracing */
#define SCHED_TRACE2(id, callback, task, xtra) /* no tracing */
#define SCHED_TRACE3(id, callback, task, xtra1, xtra2)

#endif

#ifdef CONFIG_SCHED_LITMUS_TRACEPOINT

#include <trace/events/litmus.h>

#else

/* Override trace macros to actually do nothing */
#define trace_litmus_task_param(t)
#define trace_litmus_task_release(t)
#define trace_litmus_switch_to(t)
#define trace_litmus_switch_away(prev)
#define trace_litmus_task_completion(t, forced)
#define trace_litmus_task_block(t)
#define trace_litmus_task_resume(t)
#define trace_litmus_sys_release(start)
#define trace_litmus_eff_prio_change(t, p)

#endif


#define SCHED_TRACE_BASE_ID 500


#define sched_trace_task_name(t)					\
	SCHED_TRACE(SCHED_TRACE_BASE_ID + 1,				\
			do_sched_trace_task_name, t)

#define sched_trace_task_param(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 2,			\
				do_sched_trace_task_param, t);		\
		trace_litmus_task_param(t);				\
	} while (0)

#define sched_trace_task_release(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 3,			\
				do_sched_trace_task_release, t);	\
		trace_litmus_task_release(t);				\
	} while (0)

#define sched_trace_task_switch_to(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 4,			\
			do_sched_trace_task_switch_to, t);		\
		trace_litmus_switch_to(t);				\
	} while (0)

#define sched_trace_task_switch_away(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 5,			\
			do_sched_trace_task_switch_away, t);		\
		trace_litmus_switch_away(t);				\
	} while (0)

#define sched_trace_task_completion(t, forced)				\
	do {								\
		SCHED_TRACE2(SCHED_TRACE_BASE_ID + 6,			\
				do_sched_trace_task_completion, t,	\
				(unsigned long) forced);		\
		trace_litmus_task_completion(t, forced);		\
	} while (0)

#define sched_trace_task_block(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 7,			\
			do_sched_trace_task_block, t);			\
		trace_litmus_task_block(t);				\
	} while (0)

#define sched_trace_task_resume(t)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 8,			\
				do_sched_trace_task_resume, t);		\
		trace_litmus_task_resume(t);				\
	} while (0)

#define sched_trace_action(t, action)					\
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 9,				\
		do_sched_trace_action, t, (unsigned long) action);

/* when is a pointer, it does not need an explicit cast to unsigned long */
#define sched_trace_sys_release(when)					\
	do {								\
		SCHED_TRACE(SCHED_TRACE_BASE_ID + 10,			\
			do_sched_trace_sys_release, when);		\
		trace_litmus_sys_release(when);				\
	} while (0)

#define sched_trace_tasklet_release(t, d) \
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 11, do_sched_trace_tasklet_release, t, d)

#define sched_trace_tasklet_begin(t) \
	SCHED_TRACE(SCHED_TRACE_BASE_ID + 12, do_sched_trace_tasklet_begin, t)

#define sched_trace_tasklet_end(t, flushed) \
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 13, do_sched_trace_tasklet_end, t, flushed)


#define sched_trace_work_release(t, d) \
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 14, do_sched_trace_work_release, t, d)

#define sched_trace_work_begin(t, e) \
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 15, do_sched_trace_work_begin, t, e)

#define sched_trace_work_end(t, e, flushed) \
	SCHED_TRACE3(SCHED_TRACE_BASE_ID + 16, do_sched_trace_work_end, t, e, flushed)

#define sched_trace_eff_prio_change(t, p)				\
	do {												\
		SCHED_TRACE2(SCHED_TRACE_BASE_ID + 17,			\
			do_sched_trace_eff_prio_change, t, p);		\
		trace_litmus_eff_prio_change(t, p);				\
	} while (0)

#define sched_trace_nv_interrupt_begin(d) \
	SCHED_TRACE(SCHED_TRACE_BASE_ID + 18, do_sched_trace_nv_interrupt_begin, d)
#define sched_trace_nv_interrupt_end(d) \
	SCHED_TRACE(SCHED_TRACE_BASE_ID + 19, do_sched_trace_nv_interrupt_end, d)

#define sched_trace_migration(t, mig_info) \
	SCHED_TRACE2(SCHED_TRACE_BASE_ID + 20, do_sched_trace_migration, t, mig_info)


#define sched_trace_lock(t, lock_id, acquired) \
	SCHED_TRACE3(SCHED_TRACE_BASE_ID + 21, do_sched_trace_lock, t, lock_id, acquired)

#define sched_trace_quantum_boundary() /* NOT IMPLEMENTED */

#endif /* __KERNEL__ */

#endif
