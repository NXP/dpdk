/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_EP_RAWDEV_DMA_H_
#define _LSXINIC_EP_RAWDEV_DMA_H_

#include <rte_pmd_dpaa2_qdma.h>

/* Flagged in dma job*/
#define LSINIC_QDMA_JOB_USING_FLAG (1ULL << 31)

int lsinic_dma_init(void);
int lsinic_dma_uninit(void);

#endif /* _LSXINIC_EP_RAWDEV_DMA_H_ */
