/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
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

#ifndef HEADER_USDPAA_COMPAT_H
#define HEADER_USDPAA_COMPAT_H

/* All <xxx.h> headers include this header, directly or otherwise. This
 * should provide the minimal set of system includes and base-definitions
 * required by these headers, such that C code can include USDPAA headers
 * without pre-requisites. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <linux/types.h>

/* This defines any configuration symbols that are required by <xxx.h>
 * headers. */
#include <conf.h>

/* The following definitions are primarily to allow the single-source driver
 * interfaces to be included by arbitrary program code. Ie. for interfaces that
 * are also available in kernel-space, these definitions provide compatibility
 * with certain attributes and types used in those interfaces. */

/* Required compiler attributes */
#define __maybe_unused	__attribute__((unused))
#define __always_unused	__attribute__((unused))
#define __packed	__attribute__((__packed__))
#define __user
#define ____cacheline_aligned __attribute__((aligned(L1_CACHE_BYTES)))
#undef container_of
#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })
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
struct rb_node {
	struct rb_node *prev, *next;
};

typedef	u32		compat_uptr_t;
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

/* SMP stuff */
static inline int cpumask_test_cpu(int cpu, cpumask_t *mask)
{
	return CPU_ISSET(cpu, mask);
}

static inline void cpumask_set_cpu(int cpu, cpumask_t *mask)
{
	CPU_SET(cpu, mask);
}

static inline void cpumask_clear_cpu(int cpu, cpumask_t *mask)
{
	CPU_CLR(cpu, mask);
}

#define DEFINE_PER_CPU(t, x)	__thread t per_cpu__##x
#define per_cpu(x, c)		per_cpu__##x
#define get_cpu_var(x)		per_cpu__##x
#define __get_cpu_var(x)	per_cpu__##x
#define put_cpu_var(x)		do {; } while (0)
#define __PERCPU		__thread
/* to be used as an upper-limit only */
#define NR_CPUS			64

/* Atomic stuff */
typedef struct {
	long v;
} atomic_t;
/* NB: __atomic_*() functions copied and twiddled from lwe_atomic.h */
static inline int atomic_read(const atomic_t *v)
{
	return v->v;
}

static inline void atomic_set(atomic_t *v, int i)
{
	v->v = i;
}

#if defined(__aarch64__)
static inline long __atomic_add(long *i, long v)
{
	unsigned long tmp;
	unsigned long result;

	asm volatile("// atomic_add\n"
		"1:     ldxr    %w0, %2\n"
		"	add     %w0, %w0, %w3\n"
		"	stxr    %w1, %w0, %2\n"
		"	cbnz    %w1, 1b"
		: "=&r" (result), "=&r" (tmp), "+Q" (v)
		: "Ir" (*i));

	return result;
}
#elif defined(__powerpc__) || defined(__powerpc64__)
static inline long
__atomic_add(long *ptr, long val)
{
	long ret;

	/* FIXME 64-bit */
	asm volatile("1: lwarx %0, %y1;"
		     "add %0, %0, %2;"
		     "stwcx. %0, %y1;"
		     "bne 1b;" :
		     "=&r" (ret), "+Z" (*ptr) :
		     "r" (val) :
		     "memory", "cc");

	return ret;
}
#else
#error ARCH not Supported
#endif
static inline void atomic_inc(atomic_t *v)
{
	__atomic_add((long *)&v->v, 1);
}

static inline int atomic_dec_and_test(atomic_t *v)
{
	return __atomic_add((long *)&v->v, -1) == 0;
}

static inline void atomic_dec(atomic_t *v)
{
	__atomic_add((long *)&v->v, -1);
}

/* new variants not present in LWE */
static inline int atomic_inc_and_test(atomic_t *v)
{
	return __atomic_add((long *)&v->v, 1) == 0;
}

static inline int atomic_inc_return(atomic_t *v)
{
	return	__atomic_add((long *)&v->v, 1);
}

/* Waitqueue stuff */
typedef struct { }		wait_queue_head_t;
#define DECLARE_WAIT_QUEUE_HEAD(x) int dummy_##x __always_unused
#define might_sleep()		do {; } while (0)
#define init_waitqueue_head(x)	do {; } while (0)
#define wake_up(x)		do {; } while (0)
#define wait_event(x, c) \
do { \
	while (!(c)) { \
		bman_poll(); \
		qman_poll(); \
	} \
} while (0)
#define wait_event_interruptible(x, c) \
({ \
	wait_event(x, c); \
	0; \
})

/* I/O operations */
static inline u32 in_be32(volatile void *__p)
{
	volatile u32 *p = __p;

	return be32toh(*p);
}

static inline void out_be32(volatile void *__p, u32 val)
{
	volatile u32 *p = __p;
	*p = htobe32(val);
}

#define hwsync __sync_synchronize
#define dcbt_ro(p) __builtin_prefetch(p, 0)
#define dcbt_rw(p) __builtin_prefetch(p, 1)

#if defined(__aarch64__)
#define lwsync() \
	do { \
		asm volatile ("dmb st" : : : "memory");	\
	} while (0)

#define dcbf(p) \
	do { \
		asm volatile("dc cvac, %0" : : "r"(p) : "memory");	\
	} while (0)
#define dcbf_64(p) dcbf(p)

#define dcbi(p) \
	do { \
		asm volatile("dc civac, %0" : : "r"(p) : "memory");	\
	} while (0)

#define dcbz(p) \
	do { \
		asm volatile("dc zva, %0" : : "r" (p) : "memory");	\
	} while (0)
#define dcbz_64(p) dcbz(p)

#define dcbit_ro(p) \
	do { \
		dcbi(p);						\
		asm volatile("prfm pldl1keep, [%0, #64]" : : "r" (p));	\
	} while (0)

#elif defined(__powerpc__) || defined(__powerpc64__)
#ifdef CONFIG_PPC_E500MC

#define lwsync() \
	do { \
		asm volatile ("lwsync" : : : "memory"); \
	} while (0)

#define dcbf(p) \
	do { \
	       asm volatile ("dcbf 0,%0" : : "r" (p)); \
       } while (0)

#define dcbi(p) dcbf(p)

#define dcbzl(p) \
	do { \
		__asm__ __volatile__ ("dcbzl 0,%0" : : "r" (p));	\
	} while (0)
#define dcbz_64(p) \
	do { \
		dcbzl(p); \
	} while (0)
#define dcbf_64(p) \
	do { \
		dcbf(p); \
	} while (0)
/* Commonly used combo */
#define dcbit_ro(p) \
	do { \
		dcbi(p); \
		dcbt_ro(p); \
	} while (0)
#else
#define dcbz(p) \
	do { \
		__asm__ __volatile__ ("dcbz 0,%0" : : "r" (p));	\
	} while (0)
#define dcbz_64(p) \
	do { \
		dcbz((u32)p + 32);	\
		dcbz(p);	\
	} while (0)
#define dcbf_64(p) \
	do { \
		dcbf((u32)p + 32); \
		dcbf(p); \
	} while (0)
/* Commonly used combo */
#define dcbit_ro(p) \
	do { \
		dcbi(p); \
		dcbi((u32)p + 32); \
		dcbt_ro(p); \
		dcbt_ro((u32)p + 32); \
	} while (0)
#endif /* CONFIG_PPC_E500MC */

#endif /* __ppc__ */

#define barrier() \
	do { \
		asm volatile ("" : : : "memory"); \
	} while (0)
#define cpu_relax barrier

/* Debugging */
#define prflush(fmt, args...) \
	do { \
		printf(fmt, ##args); \
		fflush(stdout); \
	} while (0)

#define pr_crit(fmt, args...)	 prflush("CRIT:" fmt, ##args)

#ifdef pr_err
#undef pr_err
#endif
#define pr_err(fmt, args...)	 prflush("ERR:" fmt, ##args)

#ifdef pr_warning
#undef pr_warning
#endif
#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warning(fmt, args...) prflush("WARN:" fmt, ##args)
#define pr_warn	pr_warning

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
} while (0)
#define might_sleep_if(c)	BUG_ON(c)
#define msleep(x) \
do { \
	pr_crit("BUG: illegal call %s:%d\n", __FILE__, __LINE__); \
	exit(EXIT_FAILURE); \
} while (0)
#else
#ifdef pr_debug
#undef pr_debug
#endif
#define pr_debug(fmt, args...)	do { ; } while (0)
#define BUG_ON(c)		do { ; } while (0)
#define might_sleep_if(c)	do { ; } while (0)
#define msleep(x)		do { ; } while (0)
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

#define ALIGN(x, a) (((x) + ((__typeof__(x))(a) - 1)) \
			& ~((__typeof__(x))(a) - 1))

/* "struct list_head" is needed by fsl_qman.h and fman.h, and the latter is not
 * much use to users unless related logic is available too
 * ("list_for_each_entry()", etc), so we put all of it in here; */
#include <dpaa_list.h>

/* Other miscellaneous interfaces our APIs depend on; */

/* Qman/Bman API inlines and macros; */

#ifdef lower_32_bits
#undef lower_32_bits
#endif
#define lower_32_bits(x) ((u32)(x))

#ifdef upper_32_bits
#undef upper_32_bits
#endif
#define upper_32_bits(x) ((u32)(((x) >> 16) >> 16))

#if defined(__aarch64__)
static inline uint64_t mfatb(void)
{
	uint64_t ret, ret_new, timeout = 200;

	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	BUG_ON(!timeout && (ret != ret_new));
	return ret * 64;
}
#elif defined(__powerpc__) || defined(__powerpc64__)

/* PPAC inlines require cpu_spin(); */
/* Alternate Time Base */
#define SPR_ATBL	526
#define SPR_ATBU	527
#define SPR_TBL		268
#define SPR_TBU		269
#define mfspr(reg) \
({ \
	register_t ret; \
	asm volatile("mfspr %0, %1" : "=r" (ret) : "i" (reg) : "memory"); \
	ret; \
})
static inline uint64_t mfatb(void)
{
	uint32_t hi, lo, chk;

	do {
		hi = mfspr(SPR_ATBU);
		lo = mfspr(SPR_ATBL);
		chk = mfspr(SPR_ATBU);
	} while (unlikely(hi != chk));
	return (uint64_t)hi << 32 | (uint64_t) lo;
}

static inline uint64_t mftb(void)
{
	uint32_t hi, lo, chk;

	do {
		hi = mfspr(SPR_TBU);
		lo = mfspr(SPR_TBL);
		chk = mfspr(SPR_TBU);
	} while (unlikely(hi != chk));
	return (uint64_t)hi << 32 | (uint64_t) lo;
}

#endif

/* Spin for a few cycles without bothering the bus */
static inline void cpu_spin(int cycles)
{
	uint64_t now = mfatb();

	while (mfatb() < (now + cycles))
		;
}

static inline void __hexdump(unsigned long start, unsigned long end,
			     unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;

		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if (!(start & 1))
					buf[pos++] = ' ';
				if (!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}

static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~(unsigned long)15;
	unsigned long end = (p + sz + 15) & ~(unsigned long)15;
	const unsigned char *c = ptr;

	__hexdump(start, end, p, sz, c);
}

#define cpu_to_be64(d) htobe64(d)
#define cpu_to_be32(d) htobe32(d)
#define cpu_to_be16(d) htobe16(d)

#define be64_to_cpu(d) be64toh(d)
#define be32_to_cpu(d) be32toh(d)
#define be16_to_cpu(d) be16toh(d)

#endif /* HEADER_USDPAA_COMPAT_H */
