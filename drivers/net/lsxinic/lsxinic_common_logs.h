/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_COMMON_LOGS_H_
#define _LSXINIC_COMMON_LOGS_H_
#define LSXINIC_PMD_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "lsxinic:" fmt "\n", ##args)

#undef LSXINIC_PMD_DBG_ENABLE

#ifdef LSXINIC_PMD_DBG_ENABLE
#define LSXINIC_PMD_DBG(fmt, args...) \
	LSXINIC_PMD_LOG(DEBUG, fmt, ## args)
#else
#define LSXINIC_PMD_DBG(fmt, args...) \
	do { } while (0)
#endif
#define LSXINIC_PMD_INFO(fmt, args...) \
	LSXINIC_PMD_LOG(INFO, fmt, ## args)
#define LSXINIC_PMD_ERR(fmt, args...) \
	LSXINIC_PMD_LOG(ERR, fmt, ## args)
#define LSXINIC_PMD_WARN(fmt, args...) \
	LSXINIC_PMD_LOG(WARNING, fmt, ## args)

#endif /* _LSXINIC_COMMON_LOGS_H_ */
