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

#ifndef HEADER_DPA_SYS_H
#define HEADER_DPA_SYS_H

#include <usdpaa/dma_mem.h>
#include <internal/of.h>

/* For now, USDPAA FQID/BPID allocation uses the common logic in dpa_alloc.c via the
 * following interface. This is to match the kernel's implementation, but it
 * will be replaced by an interface that calls into the kernel for allocations,
 * once the dynamic portal->cpu affinity stuff is complete. */
struct dpa_alloc {
	struct list_head list;
	spinlock_t lock;
};
#define DECLARE_DPA_ALLOC(name) \
	struct dpa_alloc name = { \
		.list = { \
			.prev = &name.list, \
			.next = &name.list \
		}, \
		.lock = __SPIN_LOCK_UNLOCKED(name.lock) \
	}
int dpa_alloc_new(struct dpa_alloc *alloc, u32 *result, u32 count, u32 align,
		  int partial);
void dpa_alloc_free(struct dpa_alloc *alloc, u32 fqid, u32 count);

/* For 2-element tables related to cache-inhibited and cache-enabled mappings */
#define DPA_PORTAL_CE 0
#define DPA_PORTAL_CI 1

#ifdef CONFIG_FSL_DPA_CHECKING
#define DPA_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)
#else
#define DPA_ASSERT(x)		do { ; } while(0)
#endif

/* This is the interface from the platform-agnostic driver code to (de)register
 * interrupt handlers. We simply create/destroy corresponding structs. */
int qbman_request_irq(int irq, irqreturn_t (*isr)(int irq, void *arg),
			unsigned long flags, const char *name, void *arg);
int qbman_free_irq(int irq, void *arg);

void qbman_invoke_irq(int irq);

#endif /* HEADER_DPA_SYS_H */
