/* litmus/nvidia_info.c - routines for:
	1) Determining GPU device ID given NVIDIA GPL-layer tasklet data.
	2) Tracking GPU ownership by task_structs
	3) Managing klmirqd scheduling priority
	4) Handling nvidia tasklets and work_structs

	TODO: Refactor 1&2 and 3&4 into seperate files.
*/

#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#include <litmus/sched_trace.h>
#include <litmus/nvidia_info.h>
#include <litmus/litmus.h>

#include <litmus/sched_plugin.h>

#include <litmus/binheap.h>

#if defined(CONFIG_NV_DRV_331_44)
#define NV_MAJOR_V 331
#define NV_MINOR_V 44
#elif defined(CONFIG_NV_DRV_331_13)
#define NV_MAJOR_V 331
#define NV_MINOR_V 13
#elif defined(CONFIG_NV_DRV_325_15)
#define NV_MAJOR_V 325
#define NV_MINOR_V 15
#elif defined(CONFIG_NV_DRV_319_37)
#define NV_MAJOR_V 319
#define NV_MINOR_V 37
#elif defined(CONFIG_NV_DRV_304_54)
#define NV_MAJOR_V 304
#define NV_MINOR_V 54
#elif defined(CONFIG_NV_DRV_295_40)
#define NV_MAJOR_V 295
#define NV_MINOR_V 40
#elif defined(CONFIG_NV_DRV_270_41)
#define NV_MAJOR_V 279
#define NV_MINOR_V 41
#else
#error "Unsupported NV Driver"
#endif

#if NV_MAJOR_V >= 319
#include <drm/drmP.h>
#endif

/* The following structures map to structers found in the GPL layer
   of the NVIDIA-disributed binary blob driver. Much of the code
   is cobbled together from various versions of the NV driver. We
   can factor this out into a separate tool that gives memory offsets
   to determine the device ID if distributing this code ever becomes
   a problem. */

typedef unsigned char	NvV8;	/* "void": enumerated or multiple fields*/
typedef unsigned short	NvV16;	/* "void": enumerated or multiple fields*/
typedef unsigned char	NvU8;	/* 0 to 255								*/
typedef unsigned short	NvU16;	/* 0 to 65535							*/
typedef signed char		NvS8; 	/* -128 to 127							*/
typedef signed short	NvS16;	/* -32768 to 32767						*/
typedef float			NvF32;	/* IEEE Single Precision (S1E8M23)		*/
typedef double			NvF64;	/* IEEE Double Precision (S1E11M52)		*/
typedef unsigned int	NvV32;	/* "void": enumerated or multiple fields*/
typedef unsigned int	NvU32;	/* 0 to 4294967295						*/
typedef unsigned long long NvU64; /* 0 to 18446744073709551615			*/
typedef NvU8			NvBool;
typedef union
{
	volatile NvV8 Reg008[1];
	volatile NvV16 Reg016[1];
	volatile NvV32 Reg032[1];
} litmus_nv_hwreg_t, * litmus_nv_phwreg_t;

typedef struct
{
	NvU64 address;
#if NV_MAJOR_V >= 295
	NvU64 strapped_size;
#endif
	NvU64 size;
	NvU32 offset;
	NvU32 *map;
	litmus_nv_phwreg_t map_u;
} litmus_nv_aperture_t;

#if NV_MAJOR_V >= 331
typedef struct
{
	NvU32	domain;
	NvU8	bus;
	NvU8	slot;
#if NV_MINOR_V == 44
	NvU8	function;
#endif
	NvU16	vendor_id;
	NvU16	device_id;
	NvBool	valid;
} litmus_pci_info_t;
#endif

typedef struct
{
	void  *priv;				/* private data */
	void  *os_state;			/* os-specific device state */

#if NV_MAJOR_V == 270
	int	   rmInitialized;
#endif
	int	flags;

#if NV_MAJOR_V < 331
	/* PCI config info */
	NvU32 domain;
	NvU16 bus;
	NvU16 slot;
	NvU16 vendor_id;
	NvU16 device_id;
#else
	litmus_pci_info_t pci_info;
#endif

	NvU16 subsystem_id;
	NvU32 gpu_id;
	void *handle;

#if NV_MAJOR_V < 325
	NvU32 pci_cfg_space[16];
#else
	NvU32 pci_cfg_space[64];
#endif

	/* physical characteristics */
	litmus_nv_aperture_t bars[3];
	litmus_nv_aperture_t *regs;
	litmus_nv_aperture_t *fb, ud;

#if NV_MAJOR_V < 325
	litmus_nv_aperture_t agp;
#endif

	NvU32  interrupt_line;

#if NV_MAJOR_V < 325
	NvU32 agp_config;
	NvU32 agp_status;
#endif

	NvU32 primary_vga;

	NvU32 sim_env;

	NvU32 rc_timer_enabled;

	/* list of events allocated for this device */
	void *event_list;

	void *kern_mappings;

} litmus_nv_state_t;

typedef struct work_struct litmus_nv_task_t;

typedef struct litmus_nv_work_s
{
	litmus_nv_task_t task;
	void *data;
} litmus_nv_work_t;

typedef struct litmus_nv_linux_state_s
{
	litmus_nv_state_t nv_state;
	atomic_t usage_count;

	struct pci_dev *dev;

#if NV_MAJOR_V < 325
	void *agp_bridge;
#endif

	void *alloc_queue;

	void *timer_sp;
	void *isr_sp;
	void *pci_cfgchk_sp;
	void *isr_bh_sp;
	char registry_keys[512];

	/* keep track of any pending bottom halfes */
	struct tasklet_struct tasklet;
	litmus_nv_work_t work;

	/* get a timer callback every second */
	struct timer_list rc_timer;

	/* lock for linux-specific data, not used by core rm */
#if !defined(CONFIG_NV_DRV_USES_MUTEX)
	struct semaphore ldata_lock;
#else
	struct mutex ldata_lock;
#endif

#if NV_MAJOR_V >= 331 && NV_MINOR_V >= 44
	struct proc_dir_entry *proc_dir;
#endif

	/* lock for linux-specific alloc queue */
#if !defined(CONFIG_NV_DRV_USES_MUTEX)
	struct semaphore at_lock;
#else
	struct mutex at_lock;
#endif

	/* !!! This field is all that we're after to determine
	   !!! the device number of the GPU that spawned a given
	   vvv tasklet or workqueue item. */
	NvU32 device_num;
	struct litmus_nv_linux_state_s *next;

#if NV_MAJOR_V >= 319
	struct drm_device *drm;
#endif
} litmus_nv_linux_state_t;


#ifdef CONFIG_SCHED_DEBUG_TRACE
static void __attribute__((unused))
dump_nvidia_info(const struct tasklet_struct *t)
{
	litmus_nv_state_t* nvstate = NULL;
	litmus_nv_linux_state_t* linuxstate =  NULL;
	struct pci_dev* pci = NULL;

	nvstate = (litmus_nv_state_t*)(t->data);

	if(nvstate) {
		TRACE("NV State:\n"
			  "\ttasklet ptr = %p\n"
			  "\tstate ptr = %p\n"
			  "\tprivate data ptr = %p\n"
			  "\tos state ptr = %p\n"
			  "\tdomain = %u\n"
			  "\tbus = %u\n"
			  "\tslot = %u\n"
			  "\tvender_id = %u\n"
			  "\tdevice_id = %u\n"
			  "\tsubsystem_id = %u\n"
			  "\tgpu_id = %u\n"
			  "\tinterrupt_line = %u\n",
			  t,
			  nvstate,
			  nvstate->priv,
			  nvstate->os_state,
#if NV_MAJOR_V < 331
			  nvstate->domain,
			  nvstate->bus,
			  nvstate->slot,
			  nvstate->vendor_id,
			  nvstate->device_id,
#else
			  nvstate->pci_info.domain,
			  nvstate->pci_info.bus,
			  nvstate->pci_info.slot,
			  nvstate->pci_info.vendor_id,
			  nvstate->pci_info.device_id,
#endif
			  nvstate->subsystem_id,
			  nvstate->gpu_id,
			  nvstate->interrupt_line);

		linuxstate = container_of(nvstate, litmus_nv_linux_state_t, nv_state);
	}
	else {
		TRACE("INVALID NVSTATE????\n");
	}

	if(linuxstate) {
		int ls_offset =
				(void*)(&(linuxstate->device_num)) -
				(void*)(linuxstate);
		int ns_offset_raw =
				(void*)(&(linuxstate->device_num)) -
				(void*)(&(linuxstate->nv_state));
		int ns_offset_desired =
				(void*)(&(linuxstate->device_num)) -
				(void*)(nvstate);

		TRACE("LINUX NV State:\n"
			  "\tlinux nv state ptr: %p\n"
			  "\taddress of tasklet: %p\n"
			  "\taddress of work: %p\n"
			  "\tusage_count: %d\n"
			  "\tdevice_num: %u\n"
			  "\ttasklet addr == this tasklet: %d\n"
			  "\tpci: %p\n",
			  linuxstate,
			  &(linuxstate->tasklet),
			  &(linuxstate->work),
			  atomic_read(&(linuxstate->usage_count)),
			  linuxstate->device_num,
			  (t == &(linuxstate->tasklet)),
			  linuxstate->dev);

		pci = linuxstate->dev;

		TRACE("Offsets:\n"
			  "\tOffset from LinuxState: %d, %x\n"
			  "\tOffset from NVState: %d, %x\n"
			  "\tOffset from parameter: %d, %x\n"
			  "\tdevice_num: %u\n",
			  ls_offset, ls_offset,
			  ns_offset_raw, ns_offset_raw,
			  ns_offset_desired, ns_offset_desired,
			  *((u32*)((void*)nvstate + ns_offset_desired)));
	}
	else {
		TRACE("INVALID LINUXNVSTATE?????\n");
	}
}
#endif


static struct module* nvidia_mod = NULL;

static int init_nv_device_reg(void);
static int shutdown_nv_device_reg(void);
void shutdown_nvidia_info(void);

static int nvidia_going_module_notify(struct notifier_block *self,
				unsigned long val, void *data)
{
	struct module *mod = data;

	if (nvidia_mod && (mod == nvidia_mod)) {
		switch (val) {
		case MODULE_STATE_GOING:
			/* just set our mod reference to null to avoid crash */
			nvidia_mod = NULL;
			mb();
			break;
		default:
			break;
		}
	}

	return 0;
}

static struct notifier_block nvidia_going =
{
	.notifier_call = nvidia_going_module_notify,
	.priority = 1,
};


struct init_nvinfo_wq_data
{
	struct work_struct work;
};

static void __init_nvidia_info(struct work_struct *w)
{
	struct init_nvinfo_wq_data *work =
			container_of(w, struct init_nvinfo_wq_data, work);
	struct module* mod;

	mutex_lock(&module_mutex);
	mod = find_module("nvidia");
	mutex_unlock(&module_mutex);

	if(mod != NULL) {
		TRACE("%s : Found NVIDIA module. Core Code: %p to %p\n", __FUNCTION__,
			  (void*)(mod->module_core),
			  (void*)(mod->module_core) + mod->core_size);

		init_nv_device_reg();
		nvidia_mod = mod; /* make module visible to others */
		register_module_notifier(&nvidia_going);
	}
	else {
		TRACE("%s : Could not find NVIDIA module!  Loaded?\n", __FUNCTION__);
		init_nv_device_reg();
	}

	kfree(work);
}

int init_nvidia_info(void)
{
	struct init_nvinfo_wq_data *wq_job =
		kmalloc(sizeof(struct init_nvinfo_wq_data), GFP_ATOMIC);
	INIT_WORK(&wq_job->work, __init_nvidia_info);
	schedule_work(&wq_job->work);
	return 0;
}

void shutdown_nvidia_info(void)
{
	if (nvidia_mod) {
		nvidia_mod = NULL;
		mb();

		unregister_module_notifier(&nvidia_going);
		shutdown_nv_device_reg();
	}
}

/* works with pointers to static data inside the module too. */
int is_nvidia_func(void* func_addr)
{
	int ret = 0;
	struct module* mod = nvidia_mod;

	if(mod)
		ret = within_module_core((long unsigned int)func_addr, mod);

	return(ret);
}
EXPORT_SYMBOL(is_nvidia_func);

int nv_schedule_work(struct work_struct *work)
{
#if defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON) || \
	defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED)
	if(nv_schedule_work_klmirqd(work))
		return 1;
#endif
	/* default to linux handler */
	sched_trace_work_release(NULL, get_work_nv_device_num(work));
	return queue_work(system_wq, work);
}
EXPORT_SYMBOL(nv_schedule_work);

void nv_tasklet_schedule(struct tasklet_struct *t)
{
	/* assume t has already been identified as an nvidia tasklet */
#if defined(CONFIG_LITMUS_NVIDIA_NONSPLIT_INTERRUPTS)
	if (nv_tasklet_schedule_now(t))
		return;
#elif defined(CONFIG_LITMUS_SOFTIRQD)
	if (nv_tasklet_schedule_klmirqd(t, _litmus_tasklet_schedule))
		return;
#else
	sched_trace_tasklet_release(NULL, get_tasklet_nv_device_num(t));
#endif
	/* default to linux handler */
	___tasklet_schedule(t);
}
EXPORT_SYMBOL(nv_tasklet_schedule);

void nv_tasklet_hi_schedule(struct tasklet_struct *t)
{
	/* assume t has already been identified as an nvidia tasklet */
#if defined(CONFIG_LITMUS_NVIDIA_NONSPLIT_INTERRUPTS)
	if (nv_tasklet_schedule_now(t))
		return;
#elif defined(CONFIG_LITMUS_SOFTIRQD)
	if (nv_tasklet_schedule_klmirqd(t, _litmus_tasklet_hi_schedule))
		return;
#else
	sched_trace_tasklet_release(NULL, get_tasklet_nv_device_num(t));
#endif
	/* default to linux handler */
	___tasklet_hi_schedule(t);
}
EXPORT_SYMBOL(nv_tasklet_hi_schedule);

void nv_tasklet_hi_schedule_first(struct tasklet_struct *t)
{
	BUG_ON(!irqs_disabled());

	/* assume t has already been identified as an nvidia tasklet */
#if defined(CONFIG_LITMUS_NVIDIA_NONSPLIT_INTERRUPTS)
	if (nv_tasklet_schedule_now(t))
		return;
#elif defined(CONFIG_LITMUS_SOFTIRQD)
	if (nv_tasklet_schedule_klmirqd(t, _litmus_tasklet_hi_schedule_first))
		return;
#else
	sched_trace_tasklet_release(NULL, get_tasklet_nv_device_num(t));
#endif
	/* default to linux handler */
	___tasklet_hi_schedule_first(t);
}
EXPORT_SYMBOL(nv_tasklet_hi_schedule_first);

inline u32 remap_nv_device_num(u32 device)
{
#ifdef CONFIG_NV_DRV_331_44
	/* Userspace and kernel enumerate GPUs in reversed orders on
	   each NUMA node. GPUSync currently has the 'userspace' view
	   of the world, so we need to remap.
	   Example:
		   User 0 -> OS 3
		   User 1 -> OS 2
		   User 2 -> OS 1
		   User 3 -> OS 0

	   TODO: DO THIS REMAPPING AT THE USER LEVEL!
	 */
	/* remap hack for specific bonham platform. */
		        /* 0, 1, 2, 3, 4, 5, 6, 7 */
	u32 remap[] = {3, 2, 1, 0, 7, 6, 5, 4};
	BUG_ON(device > sizeof(remap)/sizeof(remap[0]));
	device = remap[device];
#endif
	return device;
}


u32 get_tasklet_nv_device_num(const struct tasklet_struct *t)
{
	/* TODO: use hard-coded offsets instead of including structures
	   derived from NVIDIA's GPL layer data structures */
	u32 device;
	litmus_nv_state_t* nvstate = (litmus_nv_state_t*)(t->data);
	litmus_nv_linux_state_t* linuxstate =
			container_of(nvstate, litmus_nv_linux_state_t, nv_state);

	device = linuxstate->device_num;

	BUG_ON(device >= NV_DEVICE_NUM);

	device = remap_nv_device_num(device);

	return device;
}

u32 get_work_nv_device_num(const struct work_struct *t)
{
	const int DEVICE_NUM_OFFSET = sizeof(struct work_struct);
	void* state = (void*)(t);
	void** device_num_ptr = state + DEVICE_NUM_OFFSET;

	/* pray NVIDIA will aways set "data" to device ID pointer */
	u32 device = *((u32*)(*device_num_ptr));

	BUG_ON(device >= NV_DEVICE_NUM);

	device = remap_nv_device_num(device);

	return(device);
}


typedef struct {
	/* TODO: Check if this rwlock can be safely removed.
	   Depends on how klmirqd syncs. */
	rwlock_t rwlock;

	/* GPU owners are organized in a priority-ordered heap */
	struct binheap	owners;

#ifdef CONFIG_LITMUS_SOFTIRQD
	klmirqd_callback_t interrupt_callback;
	struct task_struct* interrupt_thread;

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
	klmirqd_callback_t workq_callback;
	struct task_struct* workq_thread;
#endif
#endif

#ifdef CONFIG_LITMUS_NV_KLMIRQD_DEBUG
	struct tasklet_struct nv_klmirqd_dbg_tasklet;
#endif
}nv_device_registry_t;


/* global registry table for GPU device ownership */
static nv_device_registry_t NV_DEVICE_REG[NV_DEVICE_NUM];



#ifdef CONFIG_LITMUS_SOFTIRQD
/* launches a klmirqd thread for a given device */
static int nvidia_launch_interrupt_cb(void *arg)
{
	unsigned long flags;
	int reg_device_id = (int)(long long)(arg);
	nv_device_registry_t *reg = &NV_DEVICE_REG[reg_device_id];

	TRACE("nvklmirqd callback for GPU %d\n", reg_device_id);

	write_lock_irqsave(&reg->rwlock, flags);
	reg->interrupt_thread = current;
	write_unlock_irqrestore(&reg->rwlock, flags);

	return 0;
}

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
/* launches a klmirqd thread for a given device
   (exclusively handles deferred workqueue work) */
static int nvidia_launch_workq_cb(void *arg)
{
	unsigned long flags;
	int reg_device_id = (int)(long long)(arg);
	nv_device_registry_t *reg = &NV_DEVICE_REG[reg_device_id];

	TRACE("nvklmworkerd callback for GPU %d\n", reg_device_id);

	write_lock_irqsave(&reg->rwlock, flags);
	reg->workq_thread = current;
	write_unlock_irqrestore(&reg->rwlock, flags);

	return 0;
}
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
#endif /* end LITMUS_SOFTIRQD */

#ifdef CONFIG_LITMUS_NV_KLMIRQD_DEBUG
struct nv_klmirqd_dbg_timer_struct
{
	struct hrtimer timer;
};

static struct nv_klmirqd_dbg_timer_struct nv_klmirqd_dbg_timer;

static void nv_klmirqd_arm_dbg_timer(lt_t relative_time)
{
	lt_t when_to_fire = litmus_clock() + relative_time;

	TRACE("next nv tasklet in %lld ns\n", relative_time);

	__hrtimer_start_range_ns(&nv_klmirqd_dbg_timer.timer,
					ns_to_ktime(when_to_fire),
					0,
					HRTIMER_MODE_ABS_PINNED,
					0);
}

static void nv_klmirqd_dbg_tasklet_func(unsigned long arg)
{
	lt_t now = litmus_clock();
	nv_device_registry_t *reg = (nv_device_registry_t*)arg;

	TRACE("nv klmirqd routine invoked for GPU %d!\n", reg - &NV_DEVICE_REG[0]);

	/* set up the next timer -- within next 10ms */
	nv_klmirqd_arm_dbg_timer(now % (NSEC_PER_MSEC * 10));
}


static enum hrtimer_restart nvklmirqd_timer_func(struct hrtimer *timer)
{
	unsigned long flags;
	lt_t now = litmus_clock();
	int gpu = (int)(now % num_online_gpus());
	nv_device_registry_t *reg = &NV_DEVICE_REG[gpu];
	struct task_struct* klmirqd_th;

	TRACE("nvklmirqd_timer invoked!\n");

	klmirqd_th = get_and_lock_nvklmirqd_thread(gpu, &flags);

	if (klmirqd_th) {
		TRACE("Adding a tasklet for GPU %d\n", gpu);
		litmus_tasklet_schedule(&reg->nv_klmirqd_dbg_tasklet, klmirqd_th);
		unlock_nvklmirqd_thread(gpu, &flags);
	}
	else {
		TRACE("nv klmirqd is not ready!\n");
		printk("nv klmirqd is not ready!\n");
		/* set up the next timer -- within next 10ms */
		nv_klmirqd_arm_dbg_timer(now % (NSEC_PER_MSEC * 10));
	}

	return HRTIMER_NORESTART;
}
#endif


static int gpu_owner_max_priority_order(const struct binheap_node *a,
				const struct binheap_node *b)
{
	struct task_struct *d_a =
			container_of(
				binheap_entry(a, struct rt_param, gpu_owner_node),
				struct task_struct, rt_param);
	struct task_struct *d_b =
			container_of(
				binheap_entry(b, struct rt_param, gpu_owner_node),
				struct task_struct, rt_param);

	BUG_ON(!d_a);
	BUG_ON(!d_b);

	return litmus->compare(d_a, d_b);
}

#ifdef CONFIG_LITMUS_SOFTIRQD
static int create_threads(nv_device_registry_t* reg, int device)
{
	int ret = 0;
	char name[MAX_KLMIRQD_NAME_LEN+1];
	int default_cpu = litmus->map_gpu_to_cpu(device);
	int status;

	/* spawn the interrupt thread */
	snprintf(name, MAX_KLMIRQD_NAME_LEN, "nvklmirqd%d", device);
	reg->interrupt_callback.func = nvidia_launch_interrupt_cb;
	reg->interrupt_callback.arg = (void*)(long long)(device);
	mb();
	status = launch_klmirqd_thread(name, default_cpu,
								   &reg->interrupt_callback);
	if(status != 0) {
		TRACE("Failed to create nvklmirqd thread for GPU %d\n", device);
		--ret;
	}

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
	/* spawn the workqueue thread */
	snprintf(name, MAX_KLMIRQD_NAME_LEN, "nvklmworker%d", device);
	reg->workq_callback.func = nvidia_launch_workq_cb;
	reg->workq_callback.arg = (void*)(long long)(device);
	mb();
	status = launch_klmirqd_thread(name, default_cpu,
								   &reg->workq_callback);
	if(status != 0) {
		TRACE("Failed to create nvklmworkqd thread for GPU %d\n", device);
		--ret;
	}
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */

	return ret;
}

static int destroy_threads(nv_device_registry_t* reg, int device)
{
	int ret = 0;
	unsigned long flags;

	if (reg->interrupt_thread
#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
		|| reg->workq_thread
#endif
		) {
		write_lock_irqsave(&reg->rwlock, flags);
		if (reg->interrupt_thread) {
			struct task_struct* th = reg->interrupt_thread;
			reg->interrupt_thread = NULL;
			write_unlock_irqrestore(&reg->rwlock, flags);
			kill_klmirqd_thread(th);
		}
		else
			write_unlock_irqrestore(&reg->rwlock, flags);

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
		write_lock_irqsave(&reg->rwlock, flags);
		if (reg->workq_thread) {
			struct task_struct* th = reg->workq_thread;
			reg->workq_thread = NULL;
			write_unlock_irqrestore(&reg->rwlock, flags);
			kill_klmirqd_thread(th);
		}
		else
			write_unlock_irqrestore(&reg->rwlock, flags);
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
	}

	return ret;
}

#if defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON) || \
	defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED)
/* called by Linux's schedule_work() to hand GPU work_structs to klmirqd */
int nv_schedule_work_klmirqd(struct work_struct *work)
{
	int ret = 0; /* fail */

	unsigned long flags;
	u32 nvidia_device;
	struct task_struct* klmirqd_th;

	nvidia_device = get_work_nv_device_num(work);
	klmirqd_th = get_and_lock_nvklmworkqd_thread(nvidia_device, &flags);

	if (likely(klmirqd_th)) {
		TRACE("Handling NVIDIA workq for device %u "
			"(klmirqd: %s/%d) at %llu\n",
			nvidia_device,
			klmirqd_th->comm,
			klmirqd_th->pid,
			litmus_clock());

		sched_trace_work_release(effective_priority(klmirqd_th),
			nvidia_device);

		ret = litmus_schedule_work(work, klmirqd_th);

		unlock_nvklmirqd_thread(nvidia_device, &flags);
	}
	else {
		TRACE("Could not find klmirqd thread for GPU %u\n", nvidia_device);
	}

	return ret;
}
#endif /* end LITMUS_NVIDIA_WORKQ_ON || WORKQ_ON_DEDICATED */



#endif /* end LITMUS_SOFTIRQD */

static int init_nv_device_reg(void)
{
	int i;

#ifdef CONFIG_LITMUS_SOFTIRQD
	if (!klmirqd_is_ready()) {
		TRACE("klmirqd is not ready!\n");
		printk("klmirqd is not ready!\n");
		return 0;
	}
#endif

	memset(NV_DEVICE_REG, 0, sizeof(NV_DEVICE_REG));
	mb();

	for(i = 0; i < num_online_gpus(); ++i) {
		rwlock_init(&NV_DEVICE_REG[i].rwlock);
		INIT_BINHEAP_HANDLE(&NV_DEVICE_REG[i].owners,
			gpu_owner_max_priority_order);

#ifdef CONFIG_LITMUS_SOFTIRQD
		(void)create_threads(&NV_DEVICE_REG[i], i);
#endif
	}

#ifdef CONFIG_LITMUS_NV_KLMIRQD_DEBUG
	for(i = 0; i < num_online_gpus(); ++i) {
		tasklet_init(&NV_DEVICE_REG[i].nv_klmirqd_dbg_tasklet,
					 nv_klmirqd_dbg_tasklet_func,
					 (unsigned long)&NV_DEVICE_REG[i]);
	}
	hrtimer_init(&nv_klmirqd_dbg_timer.timer, CLOCK_MONOTONIC,
					HRTIMER_MODE_ABS);
	nv_klmirqd_dbg_timer.timer.function = nvklmirqd_timer_func;
	nv_klmirqd_arm_dbg_timer(NSEC_PER_MSEC * 1000);
#endif

	return 1;
}


/* The following code is full of nasty race conditions... */
/* spawning of klimirqd threads can race with init_nv_device_reg()!!!! */
static int shutdown_nv_device_reg(void)
{
	int i;

	TRACE("Shutting down nv device registration.\n");

	for (i = 0; i < num_online_gpus(); ++i) {

		TRACE("Shutting down GPU %d.\n", i);

#ifdef CONFIG_LITMUS_SOFTIRQD
		(void)destroy_threads(&NV_DEVICE_REG[i], i);
#endif
		while (!binheap_empty(&NV_DEVICE_REG[i].owners)) {
			binheap_delete_root(&NV_DEVICE_REG[i].owners,
							struct rt_param, gpu_owner_node);
		}
	}

	return(1);
}


/* use to get the owner of nv_device_id. */
struct task_struct* get_nv_max_device_owner(u32 target_device_id)
{
	struct task_struct *owner = NULL;
	nv_device_registry_t *reg;

	BUG_ON(target_device_id >= NV_DEVICE_NUM);

	reg = &NV_DEVICE_REG[target_device_id];

	if (!binheap_empty(&reg->owners)) {
		struct task_struct *hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);

		TRACE_CUR("hp: %s/%d\n", hp->comm, hp->pid);

		owner = hp;
	}

	return(owner);
}

#ifdef CONFIG_LITMUS_SOFTIRQD
typedef enum
{
	INTERRUPT_TH,
	WORKQ_TH
} nvklmtype_t;

static struct task_struct* __get_klm_thread(nv_device_registry_t* reg,
				nvklmtype_t type)
{
	struct task_struct *klmirqd = NULL;

	switch(type) {
	case INTERRUPT_TH:
#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON
	case WORKQ_TH:
#endif
		klmirqd = reg->interrupt_thread;
		break;
#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
	case WORKQ_TH:
		klmirqd = reg->workq_thread;
		break;
#endif
	default:
		break;
	}

	return klmirqd;
}

static struct task_struct* __get_and_lock_klm_thread(nv_device_registry_t* reg,
				unsigned long* flags, nvklmtype_t type)
{
	struct task_struct *klmirqd;

	read_lock_irqsave(&reg->rwlock, *flags);

	klmirqd = __get_klm_thread(reg, type);

	if(!klmirqd)
		read_unlock_irqrestore(&reg->rwlock, *flags);

	return klmirqd;
}

static void __unlock_klm_thread(nv_device_registry_t* reg,
				unsigned long* flags, nvklmtype_t type)
{
	/* workq and interrupts share a lock per GPU */
	read_unlock_irqrestore(&reg->rwlock, *flags);
}

struct task_struct* get_and_lock_nvklmirqd_thread(u32 target_device_id,
				unsigned long* flags)
{
	nv_device_registry_t *reg;
	struct task_struct *th;

	BUG_ON(target_device_id >= NV_DEVICE_NUM);

	reg = &NV_DEVICE_REG[target_device_id];
	th = __get_and_lock_klm_thread(reg, flags, INTERRUPT_TH);

#ifndef CONFIG_LITMUS_NV_KLMIRQD_DEBUG
	/* mask out thread if nvidia mod not ready (unless we're in dbg mode) */
	if (th && unlikely(nvidia_mod == NULL)) {
		th = NULL;
		__unlock_klm_thread(reg, flags, INTERRUPT_TH);
	}
#endif

	return th;
}

void unlock_nvklmirqd_thread(u32 target_device_id, unsigned long* flags)
{
	nv_device_registry_t *reg;
	BUG_ON(target_device_id >= NV_DEVICE_NUM);
	reg = &NV_DEVICE_REG[target_device_id];
	__unlock_klm_thread(reg, flags, INTERRUPT_TH);
}

#if defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON) || \
	defined(CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED)
struct task_struct* get_and_lock_nvklmworkqd_thread(u32 target_device_id,
				unsigned long* flags)
{
	nv_device_registry_t *reg;
	struct task_struct *th;

	BUG_ON(target_device_id >= NV_DEVICE_NUM);

	reg = &NV_DEVICE_REG[target_device_id];
	th = __get_and_lock_klm_thread(reg, flags, WORKQ_TH);

#ifndef CONFIG_LITMUS_NV_KLMIRQD_DEBUG
	/* mask out thread if nvidia mod not ready (unless we're in dbg mode) */
	if (th && unlikely(nvidia_mod == NULL)) {
		th = NULL;
		__unlock_klm_thread(reg, flags, WORKQ_TH);
	}
#endif

	return th;
}

void unlock_nvklmworkqd_thread(u32 target_device_id, unsigned long* flags)
{
	nv_device_registry_t *reg;
	BUG_ON(target_device_id >= NV_DEVICE_NUM);
	reg = &NV_DEVICE_REG[target_device_id];
	__unlock_klm_thread(reg, flags, WORKQ_TH);
}
#endif /* end LITMUS_NVIDIA_WORKQ_ON && LITMUS_NVIDIA_WORKQ_ON_DEDICATED */


static int gpu_klmirqd_increase_priority(struct task_struct *klmirqd,
				struct task_struct *hp)
{
	int retval = 0;
	/* the klmirqd thread should never attempt to hold a litmus-level real-time
	   so nested support is not required */
	retval = litmus->__increase_prio(klmirqd, hp);
	return retval;
}

static int gpu_klmirqd_decrease_priority(struct task_struct *klmirqd,
				struct task_struct *hp, int budget_triggered)
{
	int retval = 0;
	/* the klmirqd thread should never attempt to hold a litmus-level real-time
	   so nested support is not required */
	retval = litmus->__decrease_prio(klmirqd, hp, budget_triggered);
	return retval;
}

int nv_tasklet_schedule_klmirqd(struct tasklet_struct *t,
				klmirqd_tasklet_sched_t klmirqd_func)
{
	int ret = 0; /* fail */

	unsigned long flags;
	u32 nvidia_device;
	struct task_struct* klmirqd_th;

	nvidia_device = get_tasklet_nv_device_num(t);
	klmirqd_th = get_and_lock_nvklmirqd_thread(nvidia_device, &flags);

	if (likely(klmirqd_th)) {
		TRACE("Handling NVIDIA tasklet for device %u "
			"(klmirqd: %s/%d) at %llu\n",
			nvidia_device,
			klmirqd_th->comm,
			klmirqd_th->pid,
			litmus_clock());

		sched_trace_tasklet_release(effective_priority(klmirqd_th),
						nvidia_device);

		ret = klmirqd_func(t, klmirqd_th);

		unlock_nvklmirqd_thread(nvidia_device, &flags);
	}
	else {
		TRACE("Could not find klmirqd thread for GPU %u\n", nvidia_device);
	}

	return ret;
}
#endif  /* end LITMUS_SOFTIRQD */

#ifdef CONFIG_LITMUS_NVIDIA_NONSPLIT_INTERRUPTS
int nv_tasklet_schedule_now(struct tasklet_struct *t)
{
	int success = 1;

	sched_trace_tasklet_release(NULL, get_tasklet_nv_device_num(t));

	TRACE("Handling NVIDIA tasklet.\n");

	if(likely(tasklet_trylock(t))) {
		if(likely(!atomic_read(&t->count))) {
			if(!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
				BUG();
			sched_trace_tasklet_begin(NULL);
			t->func(t->data);
			tasklet_unlock(t);
			sched_trace_tasklet_end(NULL, 0ul);
		}
		else {
			success = 0;
		}

		tasklet_unlock(t);
	}
	else {
		success = 0;
	}

	return success;
}
#endif


/* call when an gpu owner becomes real-time */
long enable_gpu_owner(struct task_struct *t)
{
	long retval = 0;
	int gpu;
	nv_device_registry_t *reg;

#ifdef CONFIG_LITMUS_SOFTIRQD
	struct task_struct *hp;
#endif

	if (!tsk_rt(t)->held_gpus)
		return -1;

	BUG_ON(!is_realtime(t));

	gpu = find_first_bit(&tsk_rt(t)->held_gpus,
					BITS_PER_BYTE*sizeof(tsk_rt(t)->held_gpus));

	if (binheap_is_in_heap(&tsk_rt(t)->gpu_owner_node)) {
		TRACE_CUR("task %s/%d is already active on GPU %d\n",
						t->comm, t->pid, gpu);
		goto out;
	}

	/* update the registration (and maybe klmirqd) */
	reg = &NV_DEVICE_REG[gpu];

	binheap_add(&tsk_rt(t)->gpu_owner_node, &reg->owners,
				struct rt_param, gpu_owner_node);


#ifdef CONFIG_LITMUS_SOFTIRQD
	hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);

	if (hp == t) {
		int success;

		/* we're the new hp */
		success = gpu_klmirqd_increase_priority(
						reg->interrupt_thread, effective_priority(t));
		retval = success;

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
		success = gpu_klmirqd_increase_priority(
						reg->workq_thread, effective_priority(t));
		if (success != 1)
			retval = success;
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
	}
#endif /* end LITMUS_SOFTIRQD */

out:
	return retval;
}

/* call when an gpu owner exits real-time */
long disable_gpu_owner(struct task_struct *t)
{
	long retval = 0;
	int gpu;
	nv_device_registry_t *reg;

#ifdef CONFIG_LITMUS_SOFTIRQD
	struct task_struct *hp;
	struct task_struct *new_hp = NULL;
#endif

	if (!tsk_rt(t)->held_gpus) {
		TRACE_CUR("task %s/%d does not hold any GPUs\n", t->comm, t->pid);
		return -1;
	}

	BUG_ON(!is_realtime(t));

	gpu = find_first_bit(&tsk_rt(t)->held_gpus,
					BITS_PER_BYTE*sizeof(tsk_rt(t)->held_gpus));

	if (!binheap_is_in_heap(&tsk_rt(t)->gpu_owner_node))
		goto out;

	reg = &NV_DEVICE_REG[gpu];

#ifdef CONFIG_LITMUS_SOFTIRQD
	hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);

	binheap_delete(&tsk_rt(t)->gpu_owner_node, &reg->owners);

	if (!binheap_empty(&reg->owners)) {
		new_hp = container_of(
				binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
				struct task_struct, rt_param);
	}

	if (hp == t && new_hp != t) {
		int success;
		struct task_struct *to_inh = (new_hp) ?
			effective_priority(new_hp) : NULL;
		success = gpu_klmirqd_decrease_priority(reg->interrupt_thread,
												to_inh, 0);
		retval = success;

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
		success = gpu_klmirqd_decrease_priority(reg->workq_thread,
						to_inh, 0);
		if(success != 1)
			retval = success;
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
	}
#else
	binheap_delete(&tsk_rt(t)->gpu_owner_node, &reg->owners);
#endif /* end !LITMUS_SOFTIRQD */

out:
	return retval;
}


long recheck_gpu_owner(struct task_struct* t)
{
	/* TODO: blend implementation of disable/enable */
	int retval = disable_gpu_owner(t);
	if (!retval)
		retval = enable_gpu_owner(t);
	return retval;
}

/* call to notify the GPU mgmt framework that the priority
   has increased for the given owner (causes re-evaluation
   of GPU tasklet/workqueue scheduling priority) */
int gpu_owner_increase_priority(struct task_struct *t)
{
	int retval = 0;
	int gpu;
	nv_device_registry_t *reg;

	struct task_struct *hp = NULL;
	struct task_struct *hp_eff = NULL;

#ifdef CONFIG_LITMUS_SOFTIRQD
	int increase_klmirqd = 0;
#endif

	BUG_ON(!is_realtime(t));
	BUG_ON(!tsk_rt(t)->held_gpus);

	gpu = find_first_bit(&tsk_rt(t)->held_gpus,
					BITS_PER_BYTE*sizeof(tsk_rt(t)->held_gpus));

	if (!binheap_is_in_heap(&tsk_rt(t)->gpu_owner_node)) {
		TRACE_CUR("nv klmirqd may not inherit from %s/%d on GPU %d\n",
				  t->comm, t->pid, gpu);
		goto out;
	}

	TRACE_CUR("task %s/%d on GPU %d increasing priority.\n",
					t->comm, t->pid, gpu);

	reg = &NV_DEVICE_REG[gpu];

	hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);
	hp_eff = effective_priority(hp);

	if (hp != t) {
		/* our position in the heap may have changed.
		   hp is already at the root. */
		binheap_decrease(&tsk_rt(t)->gpu_owner_node, &reg->owners);
	}
#ifdef CONFIG_LITMUS_SOFTIRQD
	else {
		/* unconditionally propagate - t already has the updated eff and is
		   at the root, so we can't detect a change in inheritance, but we
		   know that priority has indeed increased/changed. */
		increase_klmirqd = 1;
	}

	hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);

	/* check if the eff. prio. of hp has changed */
	if (increase_klmirqd || (effective_priority(hp) != hp_eff)) {
		int success;

		hp_eff = effective_priority(hp);
		TRACE_CUR("%s/%d (eff_prio = %s/%d) is new hp on GPU %d.\n",
						t->comm, t->pid,
						hp_eff->comm, hp_eff->pid,
						gpu);

		success = gpu_klmirqd_increase_priority(reg->interrupt_thread, hp_eff);
		retval = success;

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED
		success = gpu_klmirqd_increase_priority(reg->workq_thread, hp_eff);
		if (success != 1)
			retval = success;
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
	}
#endif /* end LITMUS_SOFTIRQD */

out:
	return retval;
}

/* call to notify the GPU mgmt framework that the priority
   has decreased for the given owner (causes re-evaluation
   of GPU tasklet/workqueue scheduling priority) */
int gpu_owner_decrease_priority(struct task_struct *t)
{
	int retval = 0;
	int gpu;
	nv_device_registry_t *reg;

	struct task_struct *hp = NULL;
	struct task_struct *hp_eff = NULL;

	BUG_ON(!is_realtime(t));
	BUG_ON(!tsk_rt(t)->held_gpus);

	gpu = find_first_bit(&tsk_rt(t)->held_gpus,
					BITS_PER_BYTE*sizeof(tsk_rt(t)->held_gpus));

	if (!binheap_is_in_heap(&tsk_rt(t)->gpu_owner_node)) {
		TRACE_CUR("nv klmirqd may not inherit from %s/%d on GPU %d\n",
				  t->comm, t->pid, gpu);
		goto out;
	}

	TRACE_CUR("task %s/%d on GPU %d decresing priority.\n",
					t->comm, t->pid, gpu);
	reg = &NV_DEVICE_REG[gpu];

	hp = container_of(
			binheap_top_entry(&reg->owners, struct rt_param, gpu_owner_node),
			struct task_struct, rt_param);
	hp_eff = effective_priority(hp);
	binheap_delete(&tsk_rt(t)->gpu_owner_node, &reg->owners);
	binheap_add(&tsk_rt(t)->gpu_owner_node, &reg->owners,
				struct rt_param, gpu_owner_node);

#ifdef CONFIG_LITMUS_SOFTIRQD
	if (hp == t) { /* t was originally the hp */
		struct task_struct *new_hp =
			container_of(binheap_top_entry(&reg->owners,
									struct rt_param, gpu_owner_node),
					 struct task_struct, rt_param);
		/* if the new_hp is still t, or if the effective priority has
		   changed */
		if ((new_hp == t) || (effective_priority(new_hp) != hp_eff)) {
			int success;
			hp_eff = effective_priority(new_hp);
			TRACE_CUR("%s/%d is no longer hp on GPU %d.\n",
							t->comm, t->pid, gpu);
			success = gpu_klmirqd_decrease_priority(reg->interrupt_thread,
							hp_eff, 1);
			retval = success;

#ifdef CONFIG_LITMUS_NVIDIA_WORKQ_ON_DEDICATED

			success = gpu_klmirqd_decrease_priority(reg->workq_thread,
							hp_eff, 1);
			if(success != 1)
				retval = success;
#endif /* end LITMUS_NVIDIA_WORKQ_ON_DEDICATED */
		}
	}
#endif /* end LITMUS_SOFTIRQD */

out:
	return retval;
}

static int __reg_nv_device(int reg_device_id, struct task_struct *t)
{
	__set_bit(reg_device_id, &tsk_rt(t)->held_gpus);
	return 0;
}

static int __clear_reg_nv_device(int de_reg_device_id, struct task_struct *t)
{
	__clear_bit(de_reg_device_id, &tsk_rt(t)->held_gpus);
	return 0;
}

int reg_nv_device(int reg_device_id, int reg_action, struct task_struct *t)
{
	int ret;

	if((reg_device_id < num_online_gpus()) && (reg_device_id >= 0))
	{
		if(reg_action)
			ret = __reg_nv_device(reg_device_id, t);
		else
			ret = __clear_reg_nv_device(reg_device_id, t);
	}
	else
	{
		ret = -ENODEV;
	}

	return ret;
}
