#include <litmus/fdso.h>
#include <litmus/sched_plugin.h>
#include <litmus/trace.h>
#include <litmus/litmus.h>
#include <litmus/locking.h>

#include <litmus/kexclu_affinity.h>

static int create_generic_aff_obs(void** obj_ref, obj_type_t type,
				void* __user arg);
static int open_generic_aff_obs(struct od_table_entry* entry, void* __user arg);
static int close_generic_aff_obs(struct od_table_entry* entry);
static void destroy_generic_aff_obs(obj_type_t type, void* sem);

struct fdso_ops generic_affinity_ops = {
	.create  = create_generic_aff_obs,
	.open    = open_generic_aff_obs,
	.close   = close_generic_aff_obs,
	.destroy = destroy_generic_aff_obs
};

static atomic_t aff_obs_id_gen = ATOMIC_INIT(0);

static inline bool is_affinity_observer(struct od_table_entry *entry)
{
	return (entry->class == &generic_affinity_ops);
}

static inline struct affinity_observer* get_affinity_observer(
				struct od_table_entry* entry)
{
	BUG_ON(!is_affinity_observer(entry));
	return (struct affinity_observer*) entry->obj->obj;
}

static int create_generic_aff_obs(void** obj_ref, obj_type_t type,
				void* __user arg)
{
	struct affinity_observer* aff_obs;
	int err;

	err = litmus->allocate_aff_obs(&aff_obs, type, arg);
	if (err == 0) {
		BUG_ON(!aff_obs->lock);
		aff_obs->type = type;
		*obj_ref = aff_obs;
    }
	return err;
}

static int open_generic_aff_obs(struct od_table_entry* entry, void* __user arg)
{
	struct affinity_observer* aff_obs = get_affinity_observer(entry);
	if (aff_obs->ops->open)
		return aff_obs->ops->open(aff_obs, arg);
	else
		return 0; /* default: any task can open it */
}

static int close_generic_aff_obs(struct od_table_entry* entry)
{
	struct affinity_observer* aff_obs = get_affinity_observer(entry);
	if (aff_obs->ops->close)
		return aff_obs->ops->close(aff_obs);
	else
		return 0; /* default: closing succeeds */
}

static void destroy_generic_aff_obs(obj_type_t type, void* obj)
{
	struct affinity_observer* aff_obs = (struct affinity_observer*) obj;
	aff_obs->ops->deallocate(aff_obs);
}

struct litmus_lock* get_lock_from_od(int od)
{
	extern struct fdso_ops generic_lock_ops;

	struct od_table_entry *entry = get_entry_for_od(od);

	if(entry && entry->class == &generic_lock_ops) {
		return (struct litmus_lock*) entry->obj->obj;
	}
	return NULL;
}

void affinity_observer_new(struct affinity_observer* aff,
				struct affinity_observer_ops* ops,
				struct affinity_observer_args* args)
{
	aff->ops = ops;
	aff->lock = get_lock_from_od(args->lock_od);
	aff->ident = atomic_inc_return(&aff_obs_id_gen);
}
