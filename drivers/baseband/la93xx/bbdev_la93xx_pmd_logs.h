/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2026 NXP
 */

#ifndef _BBDEV_LA93XX_PMD_LOGS_H_
#define _BBDEV_LA93XX_PMD_LOGS_H_

extern int bbdev_la93xx_logtype;
#define RTE_LOGTYPE_LA93XX_BBDEV bbdev_la93xx_logtype

#define LA93XX_PMD_LOG(level, ...) \
	RTE_LOG_LINE(level, LA93XX_BBDEV, __VA_ARGS__)

#define BBDEV_LA93XX_PMD_DEBUG(...) \
	RTE_LOG_LINE_PREFIX(DEBUG, LA93XX_BBDEV, "%s(): ", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() BBDEV_LA93XX_PMD_DEBUG(">>")

#define BBDEV_LA93XX_PMD_CRIT(fmt, ...) \
	LA93XX_PMD_LOG(CRIT, fmt, ## __VA_ARGS__)
#define BBDEV_LA93XX_PMD_INFO(fmt, ...) \
	LA93XX_PMD_LOG(INFO, fmt, ## __VA_ARGS__)
#define BBDEV_LA93XX_PMD_ERR(fmt, ...) \
	LA93XX_PMD_LOG(ERR, fmt, ## __VA_ARGS__)
#define BBDEV_LA93XX_PMD_WARN(fmt, ...) \
	LA93XX_PMD_LOG(WARNING, fmt, ## __VA_ARGS__)

/* DP Logs, toggled out at compile time if level lower than current level */
#define LA93XX_PMD_DP_LOG(level, ...) \
	RTE_LOG_DP_LINE(level, LA93XX_BBDEV, __VA_ARGS__)

#define BBDEV_LA93XX_PMD_DP_DEBUG(fmt, ...) \
	LA93XX_PMD_DP_LOG(DEBUG, fmt, ## __VA_ARGS__)
#define BBDEV_LA93XX_PMD_DP_INFO(fmt, ...) \
	LA93XX_PMD_DP_LOG(INFO, fmt, ## __VA_ARGS__)
#define BBDEV_LA93XX_PMD_DP_WARN(fmt, ...) \
	LA93XX_PMD_DP_LOG(WARNING, fmt, ## __VA_ARGS__)

#endif /* _BBDEV_LA93XX_PMD_LOGS_H_ */
