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

#ifndef HEADER_COMPAT_H
#define HEADER_COMPAT_H

#include <sched.h>

#include <usdpaa/compat.h>

/* <usdpaa/compat.h> already includes system headers and definitions required
 * via the APIs, so these includes and definitions should only supply whatever
 * additions are required to compile the implementations. */
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

/* Strange though it may seem, all qman/bman-dependent apps include this header,
 * so this is a good place to force the inclusion of conf.h. There are
 * unfortunate side-effects to requiring that apps include it directly - eg. if
 * an app does not include it, it may compile ok but assume all configuration
 * choices are deselected (which may mean the driver and the app may be
 * behaviourally incompatible). */
#include <internal/conf.h>

/* NB: these compatibility shims are in this exported header because they're
 * required by interfaces shared with linux drivers (ie. for "single-source"
 * purposes).
 */

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

#if defined(__powerpc64__)
#define CONFIG_PPC64
#endif

/* printk() stuff */
#define printk(fmt, args...)	do_not_use_printk
#define nada(fmt, args...)	do { ; } while(0)

/* Debug stuff */
#ifdef CONFIG_FSL_BMAN_CHECKING
#define BM_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)
#else
#define BM_ASSERT(x)		do { ; } while(0)
#endif
#ifdef CONFIG_FSL_QMAN_CHECKING
#define QM_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)
#else
#define QM_ASSERT(x)		do { ; } while(0)
#endif

/* Interrupt stuff */
typedef uint32_t	irqreturn_t;
#define IRQ_HANDLED	0
#ifdef CONFIG_FSL_DPA_IRQ_SAFETY
#error "Won't work"
#endif
#define local_irq_disable()	do { ; } while(0)
#define local_irq_enable()	do { ; } while(0)
#define local_irq_save(v)	do { ; } while(0)
#define local_irq_restore(v)	do { ; } while(0)
#define request_irq(irq, isr, args, devname, portal) \
	qbman_request_irq(irq, isr, args, devname, portal)
#define free_irq(irq, portal) \
	qbman_free_irq(irq, portal)
#define irq_can_set_affinity(x)	0
#define irq_set_affinity(x,y)	0

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
		__foo = pthread_mutexattr_destroy(&__foo_attr);	\
		BUG_ON(__foo); \
	} while (0)
#define spin_lock_destroy(x) \
	do { \
		__maybe_unused int __foo; \
		__foo = pthread_mutex_destroy(x); \
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
#define raw_spin_lock_destroy(x)        spin_lock_destroy(x)
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

/************/
/* RB-trees */
/************/

/* Linux has a good RB-tree implementation, that we can't use (GPL). It also has
 * a flat/hooked-in interface that virtually requires license-contamination in
 * order to write a caller-compatible implementation. Instead, I've created an
 * RB-tree encapsulation on top of linux's primitives (it does some of the work
 * the client logic would normally do), and this gives us something we can
 * reimplement on LWE. Unfortunately there's no good+free RB-tree
 * implementations out there that are license-compatible and "flat" (ie. no
 * dynamic allocation). I did find a malloc-based one that I could convert, but
 * that will be a task for later on. For now, LWE's RB-tree is implemented using
 * an ordered linked-list.
 *
 * Note, the only linux-esque type is "struct rb_node", because it's used
 * statically in the exported header, so it can't be opaque. Our version doesn't
 * include a "rb_parent_color" field because we're doing linked-list instead of
 * a true rb-tree.
 */

#if 0 /* declared in <usdpaa/compat.h>, required by <usdpaa/fsl_qman.h> */
struct rb_node {
	struct rb_node *prev, *next;
};
#endif

struct dpa_rbtree {
	struct rb_node *head, *tail;
};

#define DPA_RBTREE { NULL, NULL }
static inline void dpa_rbtree_init(struct dpa_rbtree *tree)
{
	tree->head = tree->tail = NULL;
}

#define QMAN_NODE2OBJ(ptr, type, node_field) \
	(type *)((char *)ptr - offsetof(type, node_field))

#define IMPLEMENT_DPA_RBTREE(name, type, node_field, val_field) \
static inline int name##_push(struct dpa_rbtree *tree, type *obj) \
{ \
	struct rb_node *node = tree->head; \
	if (!node) { \
		tree->head = tree->tail = &obj->node_field; \
		obj->node_field.prev = obj->node_field.next = NULL; \
		return 0; \
	} \
	while (node) { \
		type *item = QMAN_NODE2OBJ(node, type, node_field); \
		if (obj->val_field == item->val_field) \
			return -EBUSY; \
		if (obj->val_field < item->val_field) { \
			if (tree->head == node) \
				tree->head = &obj->node_field; \
			else \
				node->prev->next = &obj->node_field; \
			obj->node_field.prev = node->prev; \
			obj->node_field.next = node; \
			node->prev = &obj->node_field; \
			return 0; \
		} \
		node = node->next; \
	} \
	obj->node_field.prev = tree->tail; \
	obj->node_field.next = NULL; \
	tree->tail->next = &obj->node_field; \
	tree->tail = &obj->node_field; \
	return 0; \
} \
static inline void name##_del(struct dpa_rbtree *tree, type *obj) \
{ \
	if (tree->head == &obj->node_field) { \
		if (tree->tail == &obj->node_field) \
			/* Only item in the list */ \
			tree->head = tree->tail = NULL; \
		else { \
			/* Is the head, next != NULL */ \
			tree->head = tree->head->next; \
			tree->head->prev = NULL; \
		} \
	} else { \
		if (tree->tail == &obj->node_field) { \
			/* Is the tail, prev != NULL */ \
			tree->tail = tree->tail->prev; \
			tree->tail->next = NULL; \
		} else { \
			/* Is neither the head nor the tail */ \
			obj->node_field.prev->next = obj->node_field.next; \
			obj->node_field.next->prev = obj->node_field.prev; \
		} \
	} \
} \
static inline type *name##_find(struct dpa_rbtree *tree, u32 val) \
{ \
	struct rb_node *node = tree->head; \
	while (node) { \
		type *item = QMAN_NODE2OBJ(node, type, node_field); \
		if (val == item->val_field) \
			return item; \
		if (val < item->val_field) \
			return NULL; \
		node = node->next; \
	} \
	return NULL; \
}

static inline u64 div64_u64(u64 n, u64 d)
{
	return n / d;
}

#endif /* HEADER_COMPAT_H */
