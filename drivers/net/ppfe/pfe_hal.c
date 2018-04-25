/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#include <rte_cycles.h>
#include <arpa/inet.h>

#include "pfe_logs.h"
#include "pfe_mod.h"

void *cbus_base_addr;
void *ddr_base_addr;
unsigned long ddr_phys_base_addr;
unsigned int ddr_size;
static struct pe_info pe[MAX_PE];

/* Initializes the PFE library.
 * Must be called before using any of the library functions.
 *
 * @param[in] cbus_base		CBUS virtual base address (as mapped in
 * the host CPU address space)
 * @param[in] ddr_base		PFE DDR range virtual base address (as
 * mapped in the host CPU address space)
 * @param[in] ddr_phys_base	PFE DDR range physical base address (as
 * mapped in platform)
 * @param[in] size		PFE DDR range size (as defined by the host
 * software)
 */
void pfe_lib_init(void *cbus_base, void *ddr_base, unsigned long ddr_phys_base,
		  unsigned int size)
{
	cbus_base_addr = cbus_base;
	ddr_base_addr = ddr_base;
	ddr_phys_base_addr = ddr_phys_base;
	ddr_size = size;

	pe[CLASS0_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(0);
	pe[CLASS0_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(0);
	pe[CLASS0_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS0_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS0_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS0_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[CLASS1_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(1);
	pe[CLASS1_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(1);
	pe[CLASS1_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS1_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS1_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS1_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[CLASS2_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(2);
	pe[CLASS2_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(2);
	pe[CLASS2_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS2_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS2_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS2_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[CLASS3_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(3);
	pe[CLASS3_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(3);
	pe[CLASS3_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS3_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS3_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS3_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[CLASS4_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(4);
	pe[CLASS4_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(4);
	pe[CLASS4_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS4_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS4_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS4_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[CLASS5_ID].dmem_base_addr = CLASS_DMEM_BASE_ADDR(5);
	pe[CLASS5_ID].pmem_base_addr = CLASS_IMEM_BASE_ADDR(5);
	pe[CLASS5_ID].pmem_size = CLASS_IMEM_SIZE;
	pe[CLASS5_ID].mem_access_wdata = CLASS_MEM_ACCESS_WDATA;
	pe[CLASS5_ID].mem_access_addr = CLASS_MEM_ACCESS_ADDR;
	pe[CLASS5_ID].mem_access_rdata = CLASS_MEM_ACCESS_RDATA;

	pe[TMU0_ID].dmem_base_addr = TMU_DMEM_BASE_ADDR(0);
	pe[TMU0_ID].pmem_base_addr = TMU_IMEM_BASE_ADDR(0);
	pe[TMU0_ID].pmem_size = TMU_IMEM_SIZE;
	pe[TMU0_ID].mem_access_wdata = TMU_MEM_ACCESS_WDATA;
	pe[TMU0_ID].mem_access_addr = TMU_MEM_ACCESS_ADDR;
	pe[TMU0_ID].mem_access_rdata = TMU_MEM_ACCESS_RDATA;

	pe[TMU1_ID].dmem_base_addr = TMU_DMEM_BASE_ADDR(1);
	pe[TMU1_ID].pmem_base_addr = TMU_IMEM_BASE_ADDR(1);
	pe[TMU1_ID].pmem_size = TMU_IMEM_SIZE;
	pe[TMU1_ID].mem_access_wdata = TMU_MEM_ACCESS_WDATA;
	pe[TMU1_ID].mem_access_addr = TMU_MEM_ACCESS_ADDR;
	pe[TMU1_ID].mem_access_rdata = TMU_MEM_ACCESS_RDATA;

	pe[TMU3_ID].dmem_base_addr = TMU_DMEM_BASE_ADDR(3);
	pe[TMU3_ID].pmem_base_addr = TMU_IMEM_BASE_ADDR(3);
	pe[TMU3_ID].pmem_size = TMU_IMEM_SIZE;
	pe[TMU3_ID].mem_access_wdata = TMU_MEM_ACCESS_WDATA;
	pe[TMU3_ID].mem_access_addr = TMU_MEM_ACCESS_ADDR;
	pe[TMU3_ID].mem_access_rdata = TMU_MEM_ACCESS_RDATA;

#if !defined(CONFIG_FSL_PPFE_UTIL_DISABLED)
	pe[UTIL_ID].dmem_base_addr = UTIL_DMEM_BASE_ADDR;
	pe[UTIL_ID].mem_access_wdata = UTIL_MEM_ACCESS_WDATA;
	pe[UTIL_ID].mem_access_addr = UTIL_MEM_ACCESS_ADDR;
	pe[UTIL_ID].mem_access_rdata = UTIL_MEM_ACCESS_RDATA;
#endif
}

void gemac_set_laddrN(void *base, struct pfe_mac_addr *address,
		      unsigned int entry_index)
{
	if (entry_index < 1 || entry_index > EMAC_SPEC_ADDR_MAX)
		return;

	entry_index = entry_index - 1;
	if (entry_index < 1) {
		writel(htonl(address->bottom),  base + EMAC_PHY_ADDR_LOW);
		writel((htonl(address->top) | 0x8808), base +
			EMAC_PHY_ADDR_HIGH);
	} else {
		writel(htonl(address->bottom),  base + ((entry_index - 1) * 8)
			+ EMAC_SMAC_0_0);
		writel((htonl(address->top) | 0x8808), base + ((entry_index -
			1) * 8) + EMAC_SMAC_0_1);
	}
}

/**************************** GPI ***************************/

/* Initializes a GPI block.
 * @param[in] base	GPI base address
 * @param[in] cfg	GPI configuration
 */
void gpi_init(void *base, struct gpi_cfg *cfg)
{
	gpi_reset(base);

	gpi_disable(base);

	gpi_set_config(base, cfg);
}

/* Resets a GPI block.
 * @param[in] base	GPI base address
 */
void gpi_reset(void *base)
{
	writel(CORE_SW_RESET, base + GPI_CTRL);
}

/* Enables a GPI block.
 * @param[in] base	GPI base address
 */
void gpi_enable(void *base)
{
	writel(CORE_ENABLE, base + GPI_CTRL);
}

/* Disables a GPI block.
 * @param[in] base	GPI base address
 */
void gpi_disable(void *base)
{
	writel(CORE_DISABLE, base + GPI_CTRL);
}

/* Sets the configuration of a GPI block.
 * @param[in] base	GPI base address
 * @param[in] cfg	GPI configuration
 */
void gpi_set_config(void *base, struct gpi_cfg *cfg)
{
	writel(CBUS_VIRT_TO_PFE(BMU1_BASE_ADDR + BMU_ALLOC_CTRL),	base
		+ GPI_LMEM_ALLOC_ADDR);
	writel(CBUS_VIRT_TO_PFE(BMU1_BASE_ADDR + BMU_FREE_CTRL),	base
		+ GPI_LMEM_FREE_ADDR);
	writel(CBUS_VIRT_TO_PFE(BMU2_BASE_ADDR + BMU_ALLOC_CTRL),	base
		+ GPI_DDR_ALLOC_ADDR);
	writel(CBUS_VIRT_TO_PFE(BMU2_BASE_ADDR + BMU_FREE_CTRL),	base
		+ GPI_DDR_FREE_ADDR);
	writel(CBUS_VIRT_TO_PFE(CLASS_INQ_PKTPTR), base + GPI_CLASS_ADDR);
	writel(DDR_HDR_SIZE, base + GPI_DDR_DATA_OFFSET);
	writel(LMEM_HDR_SIZE, base + GPI_LMEM_DATA_OFFSET);
	writel(0, base + GPI_LMEM_SEC_BUF_DATA_OFFSET);
	writel(0, base + GPI_DDR_SEC_BUF_DATA_OFFSET);
	writel((DDR_HDR_SIZE << 16) |	LMEM_HDR_SIZE,	base + GPI_HDR_SIZE);
	writel((DDR_BUF_SIZE << 16) |	LMEM_BUF_SIZE,	base + GPI_BUF_SIZE);

	writel(((cfg->lmem_rtry_cnt << 16) | (GPI_DDR_BUF_EN << 1) |
		GPI_LMEM_BUF_EN), base + GPI_RX_CONFIG);
	writel(cfg->tmlf_txthres, base + GPI_TMLF_TX);
	writel(cfg->aseq_len,	base + GPI_DTX_ASEQ);
	writel(1, base + GPI_TOE_CHKSUM_EN);

	if (cfg->mtip_pause_reg) {
		writel(cfg->mtip_pause_reg, base + GPI_CSR_MTIP_PAUSE_REG);
		writel(EGPI_PAUSE_TIME, base + GPI_TX_PAUSE_TIME);
	}
}

/**************************** HIF ***************************/
/* Initializes HIF copy block.
 *
 */
void hif_init(void)
{
	/*Initialize HIF registers*/
	writel((HIF_RX_POLL_CTRL_CYCLE << 16) | HIF_TX_POLL_CTRL_CYCLE,
	       HIF_POLL_CTRL);
}

/* Enable hif tx DMA and interrupt
 *
 */
void hif_tx_enable(void)
{
	writel(HIF_CTRL_DMA_EN, HIF_TX_CTRL);
	writel((readl(HIF_INT_ENABLE) | HIF_INT_EN | HIF_TXPKT_INT_EN),
	       HIF_INT_ENABLE);
}

/* Disable hif tx DMA and interrupt
 *
 */
void hif_tx_disable(void)
{
	u32	hif_int;

	writel(0, HIF_TX_CTRL);

	hif_int = readl(HIF_INT_ENABLE);
	hif_int &= HIF_TXPKT_INT_EN;
	writel(hif_int, HIF_INT_ENABLE);
}

/* Enable hif rx DMA and interrupt
 *
 */
void hif_rx_enable(void)
{
	hif_rx_dma_start();
	writel((readl(HIF_INT_ENABLE) | HIF_INT_EN | HIF_RXPKT_INT_EN),
	       HIF_INT_ENABLE);
}

/* Disable hif rx DMA and interrupt
 *
 */
void hif_rx_disable(void)
{
	u32	hif_int;

	writel(0, HIF_RX_CTRL);

	hif_int = readl(HIF_INT_ENABLE);
	hif_int &= HIF_RXPKT_INT_EN;
	writel(hif_int, HIF_INT_ENABLE);
}
