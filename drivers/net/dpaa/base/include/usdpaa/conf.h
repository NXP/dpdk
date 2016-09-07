/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef HEADER_USDPAA_CONF_H
#define HEADER_USDPAA_CONF_H

/*
 * This header is included by <usdpaa/compat.h>, and thus by all other
 * <usdpaa/xxx.h> headers. It should provide the minimal set of configuration
 * primitives required by these headers, and thus by any code (internal,
 * application, or 3rd party) that includes them.
 *
 * To determine which CONFIG_* symbols should be covered by this header (and
 * which should not), grep for CONFIG_ within include/usdpaa/.
 */

/* e500mc SoCs have 64-byte cachelines. #undef this for 32-byte cachelines */
#define CONFIG_PPC_E500MC

#ifdef CONFIG_PPC_E500MC
#define L1_CACHE_BYTES 64
#else
#define L1_CACHE_BYTES 32
#endif

/* support for BUG_ON()s, might_sleep()s, etc */
#undef CONFIG_BUGON

/* don't support blocking (so, WAIT flags won't be #define'd) */
#undef CONFIG_FSL_DPA_CAN_WAIT

#ifdef CONFIG_FSL_DPA_CAN_WAIT
/* if we can "WAIT" - can we "WAIT_SYNC" too? */
#undef CONFIG_FSL_DPA_CAN_WAIT_SYNC
#endif

/* don't compile support for FQ lookups (turn this on for 64bit user-space) */
#undef CONFIG_FSL_QMAN_FQ_LOOKUP
#if (__WORDSIZE == 64)
#define CONFIG_FSL_QMAN_FQ_LOOKUP
#endif

#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
/* if FQ lookups are supported, this controls the number of initialised,
 * s/w-consumed FQs that can be supported at any one time. */
#define CONFIG_FSL_QMAN_FQ_LOOKUP_MAX (32 * 1024)
#endif

#define CONFIG_FSL_DPA_PORTAL_SHARE

#define CONFIG_FSL_BMAN_CONFIG

#endif /* HEADER_USDPAA_CONF_H */
