#ifndef LITMUS_AFF_OBS_H
#define LITMUS_AFF_OBS_H

#include <litmus/locking.h>

struct affinity_observer_ops;
struct affinity_observer_args;

struct affinity_observer
{
	struct affinity_observer_ops* ops;
	int type;
	int ident;

	struct litmus_lock* lock;  // the lock under observation
};

typedef int (*aff_obs_open_t)(struct affinity_observer* aff_obs,
				void* __user arg);
typedef int (*aff_obs_close_t)(struct affinity_observer* aff_obs);
typedef void (*aff_obs_free_t)(struct affinity_observer* aff_obs);

struct affinity_observer_ops
{
	aff_obs_open_t open;
	aff_obs_close_t close;
	aff_obs_free_t deallocate;
};

struct litmus_lock* get_lock_from_od(int od);

void affinity_observer_new(struct affinity_observer* aff,
				struct affinity_observer_ops* ops,
				struct affinity_observer_args* args);

#endif
