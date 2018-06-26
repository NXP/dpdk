/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2017-2018 NXP
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of NXP nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DPAA_SEC_LOG_H_
#define _DPAA_SEC_LOG_H_

extern int dpaa_logtype_sec;

#define DPAA_SEC_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, dpaa_logtype_sec, "dpaa_sec: " \
		fmt "\n", ##args)

#define DPAA_SEC_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, dpaa_logtype_sec, "dpaa_sec: %s(): " \
		fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() DPAA_SEC_DEBUG(" >>")

#define DPAA_SEC_INFO(fmt, args...) \
	DPAA_SEC_LOG(INFO, fmt, ## args)
#define DPAA_SEC_ERR(fmt, args...) \
	DPAA_SEC_LOG(ERR, fmt, ## args)
#define DPAA_SEC_WARN(fmt, args...) \
	DPAA_SEC_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define DPAA_SEC_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#define DPAA_SEC_DP_DEBUG(fmt, args...) \
	DPAA_SEC_DP_LOG(DEBUG, fmt, ## args)
#define DPAA_SEC_DP_INFO(fmt, args...) \
	DPAA_SEC_DP_LOG(INFO, fmt, ## args)
#define DPAA_SEC_DP_WARN(fmt, args...) \
	DPAA_SEC_DP_LOG(WARNING, fmt, ## args)
#define DPAA_SEC_DP_ERR(fmt, args...) \
	DPAA_SEC_DP_LOG(ERR, fmt, ## args)

#endif /* _DPAA_SEC_LOG_H_ */
