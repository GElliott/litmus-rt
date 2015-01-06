/* litmus/pgm.c - common pgm control code
 */

#include <linux/sched.h>
#include <litmus/litmus.h>
#include <litmus/pgm.h>
#include <litmus/sched_trace.h>

/* Only readjust release/deadline if difference is over a given threshold.
   It's a weak method for accounting overheads. Ideally, we'd know the last
   time 't' was woken up by its last predecessor, rather than having to look
   at 'now'. Adjustment threshold currently set to 200us. */
#define ADJUSTMENT_THRESH_NS (200*1000LL)

int setup_pgm_release(struct task_struct* t)
{
	int shifted_release = 0;

	/* approximate time last predecessor gave us tokens */
	lt_t now = litmus_clock();

	TRACE_TASK(t, "is starting a new PGM job: waiting:%d\n",
		tsk_rt(t)->ctrl_page->pgm_waiting);

	BUG_ON(!tsk_rt(t)->ctrl_page->pgm_waiting);

	/* Adjust release time if we got the last tokens after release of this job.
	   This is possible since PGM jobs are early-released. Don't shift our
	   deadline if we got the tokens earlier than expected. */
	if (now > tsk_rt(t)->job_params.release) {
		long long diff_ns = now - tsk_rt(t)->job_params.release;
		if (diff_ns > ADJUSTMENT_THRESH_NS) {
			lt_t adj_deadline = now + get_rt_relative_deadline(t);

			TRACE_TASK(t, "adjusting PGM release time from (r = %llu, d = %llu) "
				"to (r = %llu, d = %llu)\n",
				tsk_rt(t)->job_params.release, tsk_rt(t)->job_params.deadline,
				now, adj_deadline);

			tsk_rt(t)->job_params.release = now;
			tsk_rt(t)->job_params.deadline = adj_deadline;
			shifted_release = 1;
		}
		else {
			TRACE_TASK(t, "adjustment falls below threshold. %lld < %lld\n",
				diff_ns, ADJUSTMENT_THRESH_NS);
		}
	}
	else {
		TRACE_TASK(t, "got tokens early--no need to adjust release. "
			"cur time = %llu, release time = %llu\n",
			now, tsk_rt(t)->job_params.release);
	}

	/* possible that there can be multiple instances of pgm_release logged.
	   analysis tools should filter out all but the last pgm_release for
	   a given job release */
	sched_trace_pgm_release(t);

	return shifted_release;
}
