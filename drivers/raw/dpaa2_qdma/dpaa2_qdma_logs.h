/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#ifndef __DPAA2_QDMA_LOGS_H__
#define __DPAA2_QDMA_LOGS_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int dpaa2_qdma_logtype;

#define DPAA2_QDMA_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, dpaa2_qdma_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

#define DPAA2_QDMA_FUNC_TRACE() DPAA2_QDMA_LOG(DEBUG, ">>")

#define DPAA2_QDMA_DEBUG(fmt, args...) \
	DPAA2_QDMA_LOG(DEBUG, fmt, ## args)
#define DPAA2_QDMA_INFO(fmt, args...) \
	DPAA2_QDMA_LOG(INFO, fmt, ## args)
#define DPAA2_QDMA_ERR(fmt, args...) \
	DPAA2_QDMA_LOG(ERR, fmt, ## args)
#define DPAA2_QDMA_WARN(fmt, args...) \
	DPAA2_QDMA_LOG(WARNING, fmt, ## args)

#ifdef __cplusplus
}
#endif

#endif /* __DPAA2_QDMA_LOGS_H__ */
