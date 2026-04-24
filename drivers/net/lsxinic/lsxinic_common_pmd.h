/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2026 NXP
 */

#ifndef _LSINIC_COMMON_PMD_H_
#define _LSINIC_COMMON_PMD_H_

#include <rte_io.h>
#include "rte_tm.h"
#include <rte_pci.h>

#include "lsxinic_common_logs.h"

#define LSINIC_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define LSINIC_ETH_OVERHEAD_SIZE RTE_TM_ETH_FRAMING_OVERHEAD_FCS

#endif /*  _LSINIC_COMMON_PMD_H_ */
