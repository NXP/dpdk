/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2026 NXP
 */

#ifndef _ENETQOS_LOGS_H_
#define _ENETQOS_LOGS_H_

#include <rte_log.h>

extern int enetqos_logtype_pmd;
#define RTE_LOGTYPE_ENETQOS enetqos_logtype_pmd

/* PMD related logs */
#define ENETQOS_PMD_LOG(level, ...) \
	RTE_LOG_LINE(level, ENETQOS, __VA_ARGS__)

#define ENETQOS_PMD_DEBUG(...) \
	RTE_LOG_LINE_PREFIX(DEBUG, ENETQOS, "%s()", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() ENETQOS_PMD_DEBUG(">>")

#define ENETQOS_PMD_INFO(fmt, ...) \
	ENETQOS_PMD_LOG(INFO, fmt, ## __VA_ARGS__)
#define ENETQOS_PMD_ERR(fmt, ...) \
	ENETQOS_PMD_LOG(ERR, fmt, ## __VA_ARGS__)
#define ENETQOS_PMD_WARN(fmt, ...) \
	ENETQOS_PMD_LOG(WARNING, fmt, ## __VA_ARGS__)

/* DP Logs, toggled out at compile time if level lower than current level */
#define ENETQOS_DP_LOG(level, ...) \
	RTE_LOG_DP_LINE(level, ENETQOS, __VA_ARGS__)

#endif /* _ENETQOS_LOGS_H_ */
