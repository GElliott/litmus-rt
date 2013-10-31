#include <linux/sched.h>
#include <litmus/litmus.h>
#include <litmus/gpu_affinity.h>

#include <litmus/sched_trace.h>
#include <litmus/trace.h>

/* two second cap on crazy observations */
#define OBSERVATION_CAP ((lt_t)(2e9))

#define NUM_STDEV_NUM	2
#define NUM_STDEV_DENOM	1

#define MIN(a, b) ((a < b) ? a : b)

#if 0
/* PID feedback controller */
static fp_t update_estimate(feedback_est_t* fb, fp_t a, fp_t b, lt_t observed)
{
	fp_t relative_err;
	fp_t err, new;
	fp_t actual = _integer_to_fp(observed);

	err = _sub(actual, fb->est);
	new = _add(_mul(a, err), _mul(b, fb->accum_err));

	relative_err = _div(err, actual);

	fb->est = new;
	fb->accum_err = _add(fb->accum_err, err);

	return relative_err;
}
#endif

static lt_t varience(lt_t nums[], const lt_t avg, const uint32_t count)
{
	/* brute force: takes about as much time as incremental running methods
	 * when count < 50 (on Bonham). Brute force also less prone to overflow.
	 */
	lt_t sqdeviations = 0;
	uint32_t i;
	for(i = 0; i < count; ++i) {
		lt_t temp = (int64_t)nums[i] - (int64_t)avg;
		sqdeviations += temp * temp;
	}
	return sqdeviations/count;
}

static lt_t isqrt(lt_t n)
{
	/* integer square root using babylonian method
	 * (algo taken from wikipedia */
	lt_t res = 0;
	lt_t bit = ((lt_t)1) << (sizeof(n)*8-2);
	while (bit > n)
		bit >>= 2;

	while (bit != 0) {
		if (n >= res + bit) {
			n -= res + bit;
			res = (res >> 1) + bit;
		}
		else {
			res >>= 1;
		}
		bit >>= 2;
	}
	return res;
}

void update_gpu_estimate(struct task_struct *t, lt_t observed)
{
	avg_est_t *est;
	struct migration_info mig_info;

	BUG_ON(tsk_rt(t)->gpu_migration > MIG_LAST);

	est = &(tsk_rt(t)->gpu_migration_est[tsk_rt(t)->gpu_migration]);

	/* log the migration event */
	mig_info.observed = observed;
	mig_info.estimated = est->avg;
	mig_info.distance = tsk_rt(t)->gpu_migration;
	sched_trace_migration(t, &mig_info);

	if (unlikely(observed > OBSERVATION_CAP)) {
		TRACE_TASK(t,
			"Crazy observation greater than was dropped: %llu > %llu\n",
			observed,
			OBSERVATION_CAP);
		return;
	}

	/* filter values outside NUM_STDEVx the standard deviation,
	   but only filter if enough samples have been taken. */
	if (likely((est->count > MIN(10, AVG_EST_WINDOW_SIZE/2)))) {
		lt_t lower, upper;

		lt_t range = (est->std*NUM_STDEV_NUM)/NUM_STDEV_DENOM;
		lower = est->avg - MIN(range, est->avg); // no underflow.

		if (unlikely(observed < lower)) {
			TRACE_TASK(t,
				"Observation is too small: %llu < %llu (avg: %llu)\n",
				observed, lower, est->avg);
			return;
		}

		upper = est->avg + range;
		if (unlikely(observed > upper)) {
			TRACE_TASK(t,
				"Observation is too large: %llu > %llu (avg: %llu)\n",
				observed, upper, est->avg);
			return;
		}
	}

	if (unlikely(est->count < AVG_EST_WINDOW_SIZE))
		++est->count;
	else
		est->sum -= est->history[est->idx];

	TS_UPDATE_GPU_EST_START;
	est->history[est->idx] = observed;
	est->sum += observed;
	est->avg = est->sum/est->count;
	est->std = isqrt(varience(est->history, est->avg, est->count));
	est->idx = (est->idx + 1) % AVG_EST_WINDOW_SIZE;
	TS_UPDATE_GPU_EST_END;

	TRACE_TASK(t,
		"GPU est update after (dist = %d, obs = %llu): %llu\n",
		tsk_rt(t)->gpu_migration,
		observed,
		est->avg);
}

gpu_migration_dist_t gpu_migration_distance(int a, int b)
{
	/* GPUs organized in a binary hierarchy, no more than 2^MIG_FAR GPUs */
	int i;
	int dist;

	if(likely(a >= 0 && b >= 0)) {
		for(i = 0; i <= MIG_FAR; ++i) {
			if(a>>i == b>>i) {
				dist = i;
				goto out;
			}
		}
		dist = MIG_NONE; /* hopefully never reached. */
		TRACE_CUR("WARNING: GPU distance too far! %d -> %d\n", a, b);
	}
	else {
		dist = MIG_NONE;
	}

out:
	TRACE_CUR("Distance %d -> %d is %d\n", a, b, dist);

	return dist;
}
