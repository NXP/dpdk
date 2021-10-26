/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_EP_DMA_H_
#define _LSXINIC_EP_DMA_H_

#include <rte_pmd_dpaa2_qdma.h>

#define QDMA_MAP_SIZE (4096)
#define QDMA_REG_BASE			(0x8380000)

#define REG_DMR				(QDMA_REG_BASE + 0x00)
#define REG_DSRP			(QDMA_REG_BASE + 0x04)
#define REG_DEWQAR0		(QDMA_REG_BASE + 0x60)
#define REG_DWQBWCR0		(QDMA_REG_BASE + 0x70)
#define REG_DWQBWCR1		(QDMA_REG_BASE + 0x74)
#define REG_DPWQAR		(QDMA_REG_BASE + 0x78)
#define REG_DSRM			(QDMA_REG_BASE + 0x10004)
#define REG_DGBTR			(QDMA_REG_BASE + 0x10040)

int lsinic_dma_write_reg(uint64_t addr, uint32_t val);
uint32_t lsinic_dma_read_reg(uint64_t addr);
int lsinic_dma_reg_init(void);
int lsinic_dma_init(void);
int lsinic_dma_uninit(void);

#endif /* _LSXINIC_EP_DMA_H_ */
