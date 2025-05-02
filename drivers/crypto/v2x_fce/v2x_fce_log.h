/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef _V2X_FCE_LOG_H_
#define _V2X_FCE_LOG_H_

#include <rte_log.h>

extern int fce_logtype;

#define FCE_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, fce_logtype, "FCE %s() line %u: " \
		fmt "\n", __func__, __LINE__, ##args)

#define FCE_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, fce_logtype, "FCE: " \
		fmt "\n", ##args)

#define FCE_INFO(fmt, args...) \
	FCE_LOG(INFO, fmt, ## args)
#define FCE_ERR(fmt, args...) \
	FCE_LOG(ERR, fmt, ## args)
#define FCE_WARN(fmt, args...) \
	FCE_LOG(WARNING, fmt, ## args)

#endif /* _V2X_FCE_LOG_H_ */
