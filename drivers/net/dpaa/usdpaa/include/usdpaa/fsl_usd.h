/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#ifndef FSL_USD_H
#define FSL_USD_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>

#ifdef __cplusplus
extern "C" {
#endif

/***********************************/
/* USDPAA-specific initialisation: */

/* Thread-entry/exit hooks; */
int qman_thread_init(void);
int qman_thread_init_idx(uint32_t idx);
int bman_thread_init(void);
int bman_thread_init_idx(uint32_t idx);
int qman_thread_finish(void);
int bman_thread_finish(void);

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE

int qman_thread_init_slave(const struct qman_portal_config *cfg);
int qman_thread_init_shared(void);
int qman_thread_init_shared_idx(uint32_t idx);
int qman_thread_finish_slave(void);


int bman_thread_init_slave(const struct bman_portal_config *cfg);
int bman_thread_init_shared(void);
int bman_thread_init_shared_idx(uint32_t idx);
int bman_thread_finish_slave(void);


#endif

#define QBMAN_ANY_PORTAL_IDX 0xffffffff

/* Obtain and free raw (unitialized) portals */

struct usdpaa_raw_portal {
	/* inputs */

	/* set to non zero to turn on stashing */
	uint8_t enable_stash;
	/* Stashing attributes for the portal */
	uint32_t cpu;
	uint32_t cache;
	uint32_t window;

	/* Specifies the stash request queue this portal should use */
	uint8_t sdest;

	/* Specifes a specific portal index to map or QBMAN_ANY_PORTAL_IDX
	 * for don't care.  The portal index will be populated by the
	 * driver when the ioctl() successfully completes */
	uint32_t index;

	/* outputs */
	uint64_t cinh;
	uint64_t cena;
};

int qman_allocate_raw_portal(struct usdpaa_raw_portal *portal);
int qman_free_raw_portal(struct usdpaa_raw_portal *portal);

int bman_allocate_raw_portal(struct usdpaa_raw_portal *portal);
int bman_free_raw_portal(struct usdpaa_raw_portal *portal);


/* Obtain thread-local UIO file-descriptors */
int qman_thread_fd(void);
int bman_thread_fd(void);

/* Post-process interrupts. NB, the kernel IRQ handler disables the interrupt
 * line before notifying us, and this post-processing re-enables it once
 * processing is complete. As such, it is essential to call this before going
 * into another blocking read/select/poll. */
void qman_thread_irq(void);
void bman_thread_irq(void);

/* Global setup */
int qman_global_init(void);
int bman_global_init(void);

#ifdef __cplusplus
}
#endif

#endif /* FSL_USD_H */

