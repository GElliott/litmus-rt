#ifndef LITMUS_GPU_AFFINITY_H
#define LITMUS_GPU_AFFINITY_H

#include <litmus/rt_param.h>
#include <litmus/sched_plugin.h>
#include <litmus/litmus.h>

void update_gpu_estimate(struct task_struct* t, lt_t observed);
gpu_migration_dist_t gpu_migration_distance(int a, int b);

static inline void reset_gpu_tracker(struct task_struct* t)
{
	t->rt_param.accum_gpu_time = 0;
	t->rt_param.gpu_time_stamp = 0;
}

static inline void start_gpu_tracker(struct task_struct* t)
{
	lt_t now = litmus_clock();
	if (likely(!t->rt_param.gpu_time_stamp))
		t->rt_param.gpu_time_stamp = now;
}

static inline void stop_gpu_tracker(struct task_struct* t)
{
	lt_t now = litmus_clock();
	if (likely(t->rt_param.gpu_time_stamp)) {
		t->rt_param.accum_gpu_time += (now - t->rt_param.gpu_time_stamp);
		t->rt_param.gpu_time_stamp = 0;
	}
}

static inline lt_t get_gpu_time(struct task_struct* t)
{
	lt_t accum = t->rt_param.accum_gpu_time;
	if (t->rt_param.gpu_time_stamp != 0)
		accum += (litmus_clock() - t->rt_param.gpu_time_stamp);
	return accum;
}

static inline lt_t get_gpu_estimate(struct task_struct* t,
				gpu_migration_dist_t dist)
{
	int i;
	lt_t val;

	if(dist == MIG_NONE)
		dist = MIG_LOCAL;

	val = t->rt_param.gpu_migration_est[dist].avg;
	for(i = dist-1; i >= 0; --i)
		if(t->rt_param.gpu_migration_est[i].avg > val)
			val = t->rt_param.gpu_migration_est[i].avg;

	return ((val > 0) ? val : dist+1);
}

#endif
