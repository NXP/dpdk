/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef HEADER_COMPAT_H
#define HEADER_COMPAT_H

#include <sched.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>
#include <assert.h>
#include <dirent.h>
#include <inttypes.h>
#include <error.h>

/* The following definitions are primarily to allow the single-source driver
 * interfaces to be included by arbitrary program code. Ie. for interfaces that
 * are also available in kernel-space, these definitions provide compatibility
 * with certain attributes and types used in those interfaces. */

/* Required compiler attributes */
#define __maybe_unused	__attribute__((unused))
#define __always_unused	__attribute__((unused))
#define __packed	__attribute__((__packed__))
#define __user
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define ____cacheline_aligned __attribute__((aligned(L1_CACHE_BYTES)))
#define container_of(p, t, f) (t *)((void *)p - offsetof(t, f))
#define __stringify_1(x) #x
#define __stringify(x)	__stringify_1(x)
#define panic(x) \
do { \
	printf("panic: %s", x); \
	abort(); \
} while (0)

#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Required types */
typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;
typedef uint64_t	dma_addr_t;
typedef cpu_set_t	cpumask_t;
#define spinlock_t	pthread_mutex_t
typedef	u32		compat_uptr_t;
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

/* I/O operations */
static inline u32 in_be32(volatile void *__p)
{
	volatile u32 *p = __p;
	return *p;
}
static inline void out_be32(volatile void *__p, u32 val)
{
	volatile u32 *p = __p;
	*p = val;
}

/* Debugging */
#define prflush(fmt, args...) \
	do { \
		printf(fmt, ##args); \
		fflush(stdout); \
	} while (0)
#define pr_crit(fmt, args...)	 prflush("CRIT:" fmt, ##args)
#define pr_err(fmt, args...)	 prflush("ERR:" fmt, ##args)
#define pr_warning(fmt, args...) prflush("WARN:" fmt, ##args)
#define pr_info(fmt, args...)	 prflush(fmt, ##args)

#define BUG()	abort()
#ifdef CONFIG_BUGON
#ifdef pr_debug
#undef pr_debug
#endif
#define pr_debug(fmt, args...)	printf(fmt, ##args)
#define BUG_ON(c) \
do { \
	if (c) { \
		pr_crit("BUG: %s:%d\n", __FILE__, __LINE__); \
		abort(); \
	} \
} while(0)
#define might_sleep_if(c)	BUG_ON(c)
#define msleep(x) \
do { \
	pr_crit("BUG: illegal call %s:%d\n", __FILE__, __LINE__); \
	exit(EXIT_FAILURE); \
} while(0)
#else
#ifdef pr_debug
#undef pr_debug
#endif
#define pr_debug(fmt, args...)	do { ; } while(0)
#define BUG_ON(c)		do { ; } while(0)
#define might_sleep_if(c)	do { ; } while(0)
#define msleep(x)		do { ; } while(0)
#endif
#define WARN_ON(c, str) \
do { \
	static int warned_##__LINE__; \
	if ((c) && !warned_##__LINE__) { \
		pr_warning("%s\n", str); \
		pr_warning("(%s:%d)\n", __FILE__, __LINE__); \
		warned_##__LINE__ = 1; \
	} \
} while (0)

#define ALIGN(x, a) (((x) + ((typeof(x))(a) - 1)) & ~((typeof(x))(a) - 1))

/****************/
/* Linked-lists */
/****************/

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

#define LIST_HEAD(n) \
struct list_head n = { \
	.prev = &n, \
	.next = &n \
}
#define INIT_LIST_HEAD(p) \
do { \
	struct list_head *__p298 = (p); \
	__p298->prev = __p298->next =__p298; \
} while(0)
#define list_entry(node, type, member) \
	(type *)((void *)node - offsetof(type, member))
#define list_empty(p) \
({ \
	const struct list_head *__p298 = (p); \
	((__p298->next == __p298) && (__p298->prev == __p298)); \
})
#define list_add(p,l) \
do { \
	struct list_head *__p298 = (p); \
	struct list_head *__l298 = (l); \
	__p298->next = __l298->next; \
	__p298->prev = __l298; \
	__l298->next->prev = __p298; \
	__l298->next = __p298; \
} while(0)
#define list_add_tail(p,l) \
do { \
	struct list_head *__p298 = (p); \
	struct list_head *__l298 = (l); \
	__p298->prev = __l298->prev; \
	__p298->next = __l298; \
	__l298->prev->next = __p298; \
	__l298->prev = __p298; \
} while(0)
#define list_for_each(i, l)				\
	for (i = (l)->next; i != (l); i = i->next)
#define list_for_each_safe(i, j, l)			\
	for (i = (l)->next, j = i->next; i != (l);	\
	     i = j, j = i->next)
#define list_for_each_entry(i, l, name) \
	for (i = list_entry((l)->next, typeof(*i), name); &i->name != (l); \
		i = list_entry(i->name.next, typeof(*i), name))
#define list_for_each_entry_safe(i, j, l, name) \
	for (i = list_entry((l)->next, typeof(*i), name), \
		j = list_entry(i->name.next, typeof(*j), name); \
		&i->name != (l); \
		i = j, j = list_entry(j->name.next, typeof(*j), name))
#define list_del(i) \
do { \
	(i)->next->prev = (i)->prev; \
	(i)->prev->next = (i)->next; \
} while(0)

/* Other miscellaneous interfaces our APIs depend on; */

#define lower_32_bits(x) ((u32)(x))
#define upper_32_bits(x) ((u32)(((x) >> 16) >> 16))

/* Compiler/type stuff */
typedef unsigned int	gfp_t;
typedef uint32_t	phandle;

#define noinline	__attribute__((noinline))
#define __iomem
#define EINTR		4
#define ENODEV		19
#define MODULE_AUTHOR(s)
#define MODULE_LICENSE(s)
#define MODULE_DESCRIPTION(s)
#define MODULE_PARM_DESC(x, y)
#define EXPORT_SYMBOL(x)
#define module_init(fn) int m_##fn(void) { return fn(); }
#define module_exit(fn) void m_##fn(void) { fn(); }
#define module_param(x, y, z)
#define module_param_string(w, x, y, z)
#define GFP_KERNEL	0
#define __KERNEL__
#define __init
#define __raw_readb(p)	*(const volatile unsigned char *)(p)
#define __raw_readl(p)	*(const volatile unsigned int *)(p)
#define __raw_writel(v, p) \
do { \
	*(volatile unsigned int *)(p) = (v); \
} while (0)

/* printk() stuff */
#define printk(fmt, args...)	do_not_use_printk
#define nada(fmt, args...)	do { ; } while(0)

/* Interrupt stuff */
typedef uint32_t	irqreturn_t;
#define IRQ_HANDLED	0

/* memcpy() stuff - when you know alignments in advance */
#ifdef CONFIG_TRY_BETTER_MEMCPY
static inline void copy_words(void *dest, const void *src, size_t sz)
{
	u32 *__dest = dest;
	const u32 *__src = src;
	size_t __sz = sz >> 2;
	BUG_ON((unsigned long)dest & 0x3);
	BUG_ON((unsigned long)src & 0x3);
	BUG_ON(sz & 0x3);
	while (__sz--)
		*(__dest++) = *(__src++);
}
static inline void copy_shorts(void *dest, const void *src, size_t sz)
{
	u16 *__dest = dest;
	const u16 *__src = src;
	size_t __sz = sz >> 1;
	BUG_ON((unsigned long)dest & 0x1);
	BUG_ON((unsigned long)src & 0x1);
	BUG_ON(sz & 0x1);
	while (__sz--)
		*(__dest++) = *(__src++);
}
static inline void copy_bytes(void *dest, const void *src, size_t sz)
{
	u8 *__dest = dest;
	const u8 *__src = src;
	while (sz--)
		*(__dest++) = *(__src++);
}
#else
#define copy_words memcpy
#define copy_shorts memcpy
#define copy_bytes memcpy
#endif

/* Spinlock stuff */
#define spinlock_t		pthread_mutex_t
#define __SPIN_LOCK_UNLOCKED(x)	PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
#define spin_lock_init(x) \
	do { \
		__maybe_unused int __foo;	\
		pthread_mutexattr_t __foo_attr;	\
		__foo = pthread_mutexattr_init(&__foo_attr);	\
		BUG_ON(__foo);	\
		__foo = pthread_mutexattr_settype(&__foo_attr,	\
						  PTHREAD_MUTEX_ADAPTIVE_NP); \
		BUG_ON(__foo);	\
		__foo = pthread_mutex_init(x, &__foo_attr); \
		BUG_ON(__foo); \
	} while (0)
#define spin_lock(x) \
	do { \
		__maybe_unused int __foo = pthread_mutex_lock(x); \
		BUG_ON(__foo); \
	} while (0)
#define spin_unlock(x) \
	do { \
		__maybe_unused int __foo = pthread_mutex_unlock(x); \
		BUG_ON(__foo); \
	} while (0)
#define spin_lock_irq(x)	do {				\
					local_irq_disable();	\
					spin_lock(x);		\
				} while (0)
#define spin_unlock_irq(x)	do {				\
					spin_unlock(x);		\
					local_irq_enable();	\
				} while (0)
#define spin_lock_irqsave(x, f)	do { spin_lock_irq(x); } while (0)
#define spin_unlock_irqrestore(x, f) do { spin_unlock_irq(x); } while (0)

#define raw_spinlock_t				spinlock_t
#define raw_spin_lock_init(x)			spin_lock_init(x)
#define raw_spin_lock_irqsave(x, f)		spin_lock(x)
#define raw_spin_unlock_irqrestore(x, f)	spin_unlock(x)

/* Completion stuff */
#define DECLARE_COMPLETION(n) int n = 0;
#define complete(n) \
do { \
	*n = 1; \
} while(0)
#define wait_for_completion(n) \
do { \
	while (!*n) { \
		bman_poll(); \
		qman_poll(); \
	} \
	*n = 0; \
} while(0)

/* Platform device stuff */
struct platform_device { void *dev; };
static inline struct
platform_device *platform_device_alloc(const char *name __always_unused,
					int id __always_unused)
{
	struct platform_device *ret = malloc(sizeof(*ret));
	if (ret)
		ret->dev = NULL;
	return ret;
}
#define platform_device_add(pdev)	0
#define platform_device_del(pdev)	do { ; } while(0)
static inline void platform_device_put(struct platform_device *pdev)
{
	free(pdev);
}
struct resource {
	int unused;
};

/* Allocator stuff */
#define kmalloc(sz, t)	malloc(sz)
#define vmalloc(sz)	malloc(sz)
#define kfree(p)	do { if (p) free(p); } while (0)
static inline void *kzalloc(size_t sz, gfp_t __foo __always_unused)
{
	void *ptr = malloc(sz);
	if (ptr)
		memset(ptr, 0, sz);
	return ptr;
}
static inline unsigned long get_zeroed_page(gfp_t __foo __always_unused)
{
	void *p;
	if (posix_memalign(&p, 4096, 4096))
		return 0;
	memset(p, 0, 4096);
	return (unsigned long)p;
}
static inline void free_page(unsigned long p)
{
	free((void *)p);
}
struct kmem_cache {
	size_t sz;
	size_t align;
};
#define SLAB_HWCACHE_ALIGN	0
static inline struct kmem_cache *kmem_cache_create(const char *n __always_unused,
		 size_t sz, size_t align, unsigned long flags __always_unused,
			void (*c)(void *) __always_unused)
{
	struct kmem_cache *ret = malloc(sizeof(*ret));
	if (ret) {
		ret->sz = sz;
		ret->align = align;
	}
	return ret;
}
static inline void kmem_cache_destroy(struct kmem_cache *c)
{
	free(c);
}
static inline void *kmem_cache_alloc(struct kmem_cache *c, gfp_t f __always_unused)
{
	void *p;
	if (posix_memalign(&p, c->align, c->sz))
		return NULL;
	return p;
}
static inline void kmem_cache_free(struct kmem_cache *c __always_unused, void *p)
{
	free(p);
}
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t f)
{
	void *ret = kmem_cache_alloc(c, f);
	if (ret)
		memset(ret, 0, c->sz);
	return ret;
}

/* Bitfield stuff. */
#define BITS_PER_ULONG	(sizeof(unsigned long) << 3)
#define SHIFT_PER_ULONG	(((1 << 5) == BITS_PER_ULONG) ? 5 : 6)
#define BITS_MASK(idx)	((unsigned long)1 << ((idx) & (BITS_PER_ULONG - 1)))
#define BITS_IDX(idx)	((idx) >> SHIFT_PER_ULONG)
static inline unsigned long test_bits(unsigned long mask,
				volatile unsigned long *p)
{
	return *p & mask;
}
static inline int test_bit(int idx, volatile unsigned long *bits)
{
	return test_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline void set_bits(unsigned long mask, volatile unsigned long *p)
{
	*p |= mask;
}
static inline void set_bit(int idx, volatile unsigned long *bits)
{
	set_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline void clear_bits(unsigned long mask, volatile unsigned long *p)
{
	*p &= ~mask;
}
static inline void clear_bit(int idx, volatile unsigned long *bits)
{
	clear_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline unsigned long test_and_set_bits(unsigned long mask,
					volatile unsigned long *p)
{
	unsigned long ret = test_bits(mask, p);
	set_bits(mask, p);
	return ret;
}
static inline int test_and_set_bit(int idx, volatile unsigned long *bits)
{
	int ret = test_bit(idx, bits);
	set_bit(idx, bits);
	return ret;
}
static inline int test_and_clear_bit(int idx, volatile unsigned long *bits)
{
	int ret = test_bit(idx, bits);
	clear_bit(idx, bits);
	return ret;
}
static inline int find_next_zero_bit(unsigned long *bits, int limit, int idx)
{
	while ((++idx < limit) && test_bit(idx, bits))
		;
	return idx;
}
static inline int find_first_zero_bit(unsigned long *bits, int limit)
{
	int idx = 0;
	while (test_bit(idx, bits) && (++idx < limit))
		;
	return idx;
}

static inline u64 div64_u64(u64 n, u64 d)
{
	return n / d;
}

#define dmb(opt) { asm volatile("dmb " #opt : : : "memory"); }
#define smp_mb() dmb(ish)

/* Atomic stuff */
typedef struct {
	int counter;
} atomic_t;

#define atomic_read(v)  (*(volatile int *)&(v)->counter)
#define atomic_set(v, i) (((v)->counter) = (i))
static inline void atomic_add(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_add\n"
	"1:	ldxr    %w0, %2\n"
	"	add     %w0, %w0, %w3\n"
	"	stxr    %w1, %w0, %2\n"
	"	cbnz    %w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i));
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_add_return\n"
	"1:	ldxr    %w0, %2\n"
	"	add     %w0, %w0, %w3\n"
	"	stlxr   %w1, %w0, %2\n"
	"	cbnz    %w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "memory");

	smp_mb();
	return result;
}

static inline void atomic_sub(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_sub\n"
	"1:	ldxr    %w0, %2\n"
	"	sub     %w0, %w0, %w3\n"
	"	stxr    %w1, %w0, %2\n"
	"	cbnz    %w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i));
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_sub_return\n"
	"1:	ldxr    %w0, %2\n"
	"	sub     %w0, %w0, %w3\n"
	"	stlxr   %w1, %w0, %2\n"
	"	cbnz    %w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "memory");

	smp_mb();
	return result;
}

#define atomic_inc(v)           atomic_add(1, v)
#define atomic_dec(v)           atomic_sub(1, v)

#define atomic_inc_and_test(v)  (atomic_add_return(1, v) == 0)
#define atomic_dec_and_test(v)  (atomic_sub_return(1, v) == 0)
#define atomic_inc_return(v)    (atomic_add_return(1, v))
#define atomic_dec_return(v)    (atomic_sub_return(1, v))
#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)

#endif /* HEADER_COMPAT_H */
