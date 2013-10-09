#ifndef LITMUS_RSPINLOCK_H
#define LITMUS_RSPINLOCK_H

#include <linux/spinlock.h>

/* recurisve raw spinlock implementation */

typedef struct raw_rspinlock {
	raw_spinlock_t	baselock;
	/* number of times lock held recursively */
	int				rcount;
	/* cpu that holds lock */
	atomic_t		owner;
} raw_rspinlock_t;

/* initializers */

#define raw_rspin_lock_init(lock) \
do{\
	raw_spin_lock_init(&(lock)->baselock); \
	(lock)->rcount = 0; \
	atomic_set(&(lock)->owner, NO_CPU); \
}while(0)


#define __RAW_RSPIN_LOCK_INITIALIZER(lockname) \
{\
	.baselock = __RAW_SPIN_LOCK_INITIALIZER(lockname), \
	.rcount = 0, \
	.owner = ATOMIC_INIT(NO_CPU), \
}

#define __RAW_RSPIN_LOCK_UNLOCKED(lockname) \
	(raw_rspinlock_t ) __RAW_RSPIN_LOCK_INITIALIZER(lockname)

/* for static initialization */
#define DEFINE_RAW_RSPINLOCK(x)	raw_rspinlock_t x = __RAW_RSPIN_LOCK_UNLOCKED(x)


/* lock calls */

#define raw_rspin_lock_irqsave(lock, flags) \
do {\
	if (unlikely(irqs_disabled() && \
			atomic_read(&(lock)->owner) == smp_processor_id())) { \
		local_irq_save(flags); /* useless. makes compiler happy though */ \
		++(lock)->rcount; \
	} else { \
		raw_spin_lock_irqsave(&(lock)->baselock, flags); \
		atomic_set(&(lock)->owner, smp_processor_id()); \
	} \
}while(0)

#define raw_rspin_lock(lock) \
do {\
	if (unlikely(atomic_read(&(lock)->owner) == smp_processor_id())) { \
		++(lock)->rcount; \
	} else { \
		raw_spin_lock(&(lock)->baselock); \
		atomic_set(&(lock)->owner, smp_processor_id()); \
	} \
}while(0)


/* unlock calls */

#define raw_rspin_unlock_irqrestore(lock, flags) \
do {\
	if (unlikely((lock)->rcount > 0)) { \
		--(lock)->rcount; \
		local_irq_restore(flags); /* useless. makes compiler happy though */ \
	} else {\
		atomic_set(&(lock)->owner, NO_CPU); \
		raw_spin_unlock_irqrestore(&(lock)->baselock, flags); \
	}\
}while(0)

#define raw_rspin_unlock(lock) \
do {\
	if (unlikely((lock)->rcount > 0)) { \
		--(lock)->rcount; \
	} else {\
		atomic_set(&(lock)->owner, NO_CPU); \
		raw_spin_unlock(&(lock)->baselock); \
	}\
}while(0)




/* recurisve spinlock implementation */

typedef struct rspinlock {
	spinlock_t		baselock;
	/* number of times lock held recursively */
	int				rcount;
	/* cpu that holds lock */
	atomic_t		owner;
} rspinlock_t;

/* initializers */

#define rspin_lock_init(lock) \
do{\
	spin_lock_init(&(lock)->baselock); \
	(lock)->rcount = 0; \
	atomic_set(&(lock)->owner, NO_CPU); \
}while(0)


#define __RSPIN_LOCK_INITIALIZER(lockname) \
{\
	.baselock = __SPIN_LOCK_INITIALIZER(lockname), \
	.rcount = 0, \
	.owner = ATOMIC_INIT(NO_CPU), \
}

#define __RSPIN_LOCK_UNLOCKED(lockname) \
	(rspinlock_t ) __RSPIN_LOCK_INITIALIZER(lockname)

/* for static initialization */
#define DEFINE_RSPINLOCK(x)	rspinlock_t x = __RSPIN_LOCK_UNLOCKED(x)


/* lock calls */

#define rspin_lock_irqsave(lock, flags) \
do {\
	if (unlikely(irqs_disabled() && \
			atomic_read(&(lock)->owner) == smp_processor_id())) { \
		local_irq_save(flags); /* useless. makes compiler happy though */ \
		++(lock)->rcount; \
	} else { \
		spin_lock_irqsave(&(lock)->baselock, flags); \
		atomic_set(&(lock)->owner, smp_processor_id()); \
	} \
}while(0)

#define rspin_lock(lock) \
do {\
	if (unlikely(atomic_read(&(lock)->owner) == smp_processor_id())) { \
		++(lock)->rcount; \
	} else { \
		spin_lock(&(lock)->baselock); \
		atomic_set(&(lock)->owner, smp_processor_id()); \
	} \
}while(0)


/* unlock calls */

#define rspin_unlock_irqrestore(lock, flags) \
do {\
	if (unlikely((lock)->rcount > 0)) { \
		--(lock)->rcount; \
		local_irq_restore(flags); /* useless. makes compiler happy though */ \
	} else {\
		atomic_set(&(lock)->owner, NO_CPU); \
		spin_unlock_irqrestore(&(lock)->baselock, flags); \
	}\
}while(0)

#define rspin_unlock(lock) \
do {\
	if (unlikely((lock)->rcount > 0)) { \
		--(lock)->rcount; \
	} else {\
		atomic_set(&(lock)->owner, NO_CPU); \
		spin_unlock(&(lock)->baselock); \
	}\
}while(0)

#endif