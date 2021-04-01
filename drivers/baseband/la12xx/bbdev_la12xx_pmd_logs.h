/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _BBDEV_LA12XX_PMD_LOGS_H_
#define _BBDEV_LA12XX_PMD_LOGS_H_

extern int bbdev_la12xx_logtype;

/* TODO: As DEBUG is defined in some commpn header, we need to undef it
 * here. This needs to be removed from here once fixed.
 */
#undef DEBUG

#define BBDEV_LA12XX_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, bbdev_la12xx_logtype, "bbdev_la12xx: " \
		fmt "\n", ##args)

#define BBDEV_LA12XX_PMD_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, bbdev_la12xx_logtype, "bbdev_la12xx: %s(): "\
		fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() BBDEV_LA12XX_PMD_DEBUG(">>")

#define BBDEV_LA12XX_PMD_CRIT(fmt, args...) \
	BBDEV_LA12XX_PMD_LOG(CRIT, fmt, ## args)
#define BBDEV_LA12XX_PMD_INFO(fmt, args...) \
	BBDEV_LA12XX_PMD_LOG(INFO, fmt, ## args)
#define BBDEV_LA12XX_PMD_ERR(fmt, args...) \
	BBDEV_LA12XX_PMD_LOG(ERR, fmt, ## args)
#define BBDEV_LA12XX_PMD_WARN(fmt, args...) \
	BBDEV_LA12XX_PMD_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define BBDEV_LA12XX_PMD_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#define BBDEV_LA12XX_PMD_DP_DEBUG(fmt, args...) \
	BBDEV_LA12XX_PMD_DP_LOG(DEBUG, fmt, ## args)
#define BBDEV_LA12XX_PMD_DP_INFO(fmt, args...) \
	BBDEV_LA12XX_PMD_DP_LOG(INFO, fmt, ## args)
#define BBDEV_LA12XX_PMD_DP_WARN(fmt, args...) \
	BBDEV_LA12XX_PMD_DP_LOG(WARNING, fmt, ## args)

#endif /* _BBDEV_LA12XX_PMD_LOGS_H_ */
