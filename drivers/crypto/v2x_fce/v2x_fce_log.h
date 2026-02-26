/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#ifndef _V2X_FCE_LOG_H_
#define _V2X_FCE_LOG_H_

#include <rte_log.h>

extern int fce_logtype;
#define RTE_LOGTYPE_FCE fce_logtype

#define FCE_LOG(level, ...) \
        RTE_LOG_LINE(level, FCE, __VA_ARGS__)

#define FCE_DEBUG(...) \
        RTE_LOG_LINE_PREFIX(DEBUG, FCE, "%s(): ", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() FCE_DEBUG(" >>")

#define FCE_INFO(fmt, ...) \
        FCE_LOG(INFO, fmt, ## __VA_ARGS__)
#define FCE_ERR(fmt, ...) \
        FCE_LOG(ERR, fmt, ## __VA_ARGS__)
#define FCE_WARN(fmt, ...) \
        FCE_LOG(WARNING, fmt, ## __VA_ARGS__)

#endif /* _V2X_FCE_LOG_H_ */
