/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __CMDIF_H__
#define __CMDIF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include <rte_log.h>

#include <rte_byteorder.h>
#include <fsl_cmdif_flib_fd.h>

#define RTE_LOGTYPE_CMDIF RTE_LOGTYPE_USER8

#define CPU_TO_SRV16(val) rte_cpu_to_be_16(val)
#define CPU_TO_SRV32(val) rte_cpu_to_be_32(val)
#define CPU_TO_BE64(val)  rte_cpu_to_be_64(val)
#define CPU_TO_BE16(val)  rte_cpu_to_be_16(val)
#define CPU_TO_LE64(val)  rte_cpu_to_le_64(val)
#define CPU_TO_LE32(val)  rte_cpu_to_le_32(val)

/** EPID to be used for setting by client */
#define CMDIF_EPID	0

#ifdef DPAA2_CMDIF_FLIB_DEBUG
#ifndef DEBUG
#define DEBUG
#endif
#endif /* DPAA2_CMDIF_FLIB_DEBUG */

#define SHBP_BUF_TO_PTR(BUF) ((uint64_t *)(BUF))
#define SHBP_PTR_TO_BUF(BUF) ((uint64_t)(BUF))

#ifdef __cplusplus
}
#endif

#endif /* __CMDIF_H__ */
