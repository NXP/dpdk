/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_EP_RAWDEV_DMA_H_
#define _LSXINIC_EP_RAWDEV_DMA_H_

#include <rte_pmd_dpaa2_qdma.h>

int lsinic_dma_init(void);
int lsinic_dma_uninit(void);
int lsinic_dma_mp_sync_setup(void);

#endif /* _LSXINIC_EP_RAWDEV_DMA_H_ */
