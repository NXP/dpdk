/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
 */

#ifndef _LSXINIC_COMMON_LOGS_H_
#define _LSXINIC_COMMON_LOGS_H_

extern int lsxinic_logtype_pmd;
#define RTE_LOGTYPE_LSXINIC_NET lsxinic_logtype_pmd

#define LSXINIC_PMD_LOG(level, ...) \
        RTE_LOG_LINE(level, LSXINIC_NET, __VA_ARGS__)

#define LSXINIC_PMD_DBG(...) \
        RTE_LOG_LINE_PREFIX(DEBUG, LSXINIC_NET, "%s(): ", __func__, __VA_ARGS__)

#define LSXINIC_PMD_CRIT(fmt, ...) \
        LSXINIC_PMD_LOG(CRIT, fmt, ## __VA_ARGS__)
#define LSXINIC_PMD_INFO(fmt, ...) \
        LSXINIC_PMD_LOG(INFO, fmt, ## __VA_ARGS__)
#define LSXINIC_PMD_ERR(fmt, ...) \
        LSXINIC_PMD_LOG(ERR, fmt, ## __VA_ARGS__)
#define LSXINIC_PMD_WARN(fmt, ...) \
        LSXINIC_PMD_LOG(WARNING, fmt, ## __VA_ARGS__)
#endif /* _LSXINIC_COMMON_LOGS_H_ */
