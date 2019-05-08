/*
 * Copyright 2019 NXP
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree or part of the
 * FreeRTOS distribution.
 *
 * FreeRTOS is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License (version 2) as published by
 * the Free Software Foundation >>!AND MODIFIED BY!<< the FreeRTOS exception.
 * >>! NOTE: The modification to the GPL is included to allow you to
 * >>! distribute a combined work that includes FreeRTOS without being obliged to
 * >>! provide the source code for proprietary components outside of the FreeRTOS
 * >>! kernel.
 *
 * FreeRTOS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  Full license text is available from the
 * following link: http://www.freertos.org/a00114.htmlor the BSD-3-Clause
 *
 */
#ifndef __GUL_HOST_IF_H__
#define __GUL_HOST_IF_H__
#include "gul_ipc_if.h"

/*Common Addresses and offsets*/
#ifdef ABERDEEN
#define GUL_PCI1_ADDR_BASE	(0x2000000000ULL)
#define GUL_PCI1_ADDR_SIZE	(32 * 1024 * 1024 * 1024) /*32 GB*/
#define SPLIT_VA32_H(A) ((uint32_t)((uint64_t)(A)>>32))
#define SPLIT_VA32_L(A) ((uint32_t)((uint64_t)(A)))
#else
#define GUL_PCI1_ADDR_BASE	(0x00000000)
#define GUL_PCI1_ADDR_SIZE	(2 * 1024 * 1024 * 1024) /*2 GB*/
#define GUL_PCI2_ADDR_BASE	(0x80000000)
#define GUL_PCI2_ADDR_SIZE	(1 * 1024 * 1024 * 1024) /*1 GB*/
#endif

/* Host Physical addresses exposed to Modem. Addresses defined below are view
 * of host physical addresses in Modem address space (PCIe). Following are
 * the exposed Physical addresses:
 * 1. DMA buf - May be deleted, not used currently.
 * 2. MSI - MSI addresses of host.
 * 3. SCRATCH buf - used for L1Trace, Modem logging.
 * 4. Huge Page  - User space Huge page for IPC.
 * 5. FECA AXI Slave & FECA APB Slave - used only for Aberdeen.
 **/

/*
 * For Aberdeen DMA buff is used for FreeRTOS image load, thus 512KB max size.
 * This buffer is not required for Aberdeen, as Linux ITB is loaded using
 * scratch buf.
 * XXX:TBD:Revisit this size after FreeRTOS implementation is available
 */
#ifndef ABERDEEN

#define GUL_USER_HUGE_PAGE_SIZE (1 * 1024 * 1024 * 1024) /*1GB*/
#define GUL_SCRATCH_DMA_BUF_MAX_SIZE	(512 * 1024 * 1024) /*512 MB*/
#define GUL_FECA_AXI_SLAVE_SIZE		(64 * 1024 * 1024) /*64 MB*/
#define GUL_FECA_APB_SLAVE_SIZE		(64 * 1024) /*64 KB*/
#define GUL_EP_DMA_BUF_PHYS_SIZE	(64 * 1024) /*64 KB*/
#define GUL_EP_TO_HOST_MSI_SIZE		(4 * 1024) /*4 KB*/
#else
#define GUL_USER_HUGE_PAGE_SIZE (1 * 1024 * 1024 * 1024) /*1GB*/
#define GUL_SCRATCH_DMA_BUF_MAX_SIZE	(512 * 1024 * 1024) /*512 MB*/
#define GUL_FECA_AXI_SLAVE_SIZE		(64 * 1024 * 1024) /*64 MB*/
#define GUL_FECA_APB_SLAVE_SIZE		(64 * 1024) /*64 KB*/
#define GUL_EP_DMA_BUF_PHYS_SIZE	(0) /*0 KB*/
#define GUL_EP_TO_HOST_MSI_SIZE		(4 * 1024) /*4 KB*/
#endif


/*User space Huge page*/
#define GUL_USER_HUGE_PAGE_OFFSET	(0)

#define GUL_USER_HUGE_PAGE_ADDR	(GUL_PCI1_ADDR_BASE + GUL_USER_HUGE_PAGE_OFFSET)

/*SCRATCH BUF*/
#define GUL_SCRATCH_DMA_BUF_OFFSET	(GUL_USER_HUGE_PAGE_OFFSET +\
			GUL_USER_HUGE_PAGE_SIZE)
#define GUL_SCRATCH_DMA_BUF_PHYS_ADDR	(GUL_PCI1_ADDR_BASE + \
			GUL_SCRATCH_DMA_BUF_OFFSET)

/*FECA PCIe BARs - AXI Slave & APB Slave */
#define GUL_FECA_AXI_SLAVE_OFFSET	(GUL_SCRATCH_DMA_BUF_OFFSET + \
					GUL_SCRATCH_DMA_BUF_MAX_SIZE)
#define GUL_FECA_AXI_SLAVE_ADDR		(GUL_PCI1_ADDR_BASE + \
					GUL_FECA_AXI_SLAVE_OFFSET)
#define GUL_FECA_APB_SLAVE_OFFSET	(GUL_FECA_AXI_SLAVE_OFFSET + \
			GUL_FECA_AXI_SLAVE_SIZE)
#define GUL_FECA_APB_SLAVE_ADDR		(GUL_PCI1_ADDR_BASE + \
					GUL_FECA_APB_SLAVE_OFFSET)

/*DMA buf*/
#define GUL_EP_DMA_BUF_OFFSET		(GUL_FECA_APB_SLAVE_OFFSET +\
				GUL_FECA_APB_SLAVE_SIZE)
#define GUL_EP_DMA_BUF_PHYS_ADDR	(GUL_PCI1_ADDR_BASE +	\
					GUL_EP_DMA_BUF_OFFSET)

/*MSI */
#define GUL_EP_TOHOST_MSI_OFFSET	(GUL_EP_DMA_BUF_OFFSET + \
					GUL_EP_DMA_BUF_PHYS_SIZE)
#define GUL_EP_TOHOST_MSI_PHY_ADDR	(GUL_PCI1_ADDR_BASE + GUL_EP_TOHOST_MSI_OFFSET)


#define GUL_EP_FREERTOS_LOAD_ADDR	0x1f800000
#define GUL_EP_BOOT_HDR_OFFSET		0x00000000
#define GUL_EP_DMA_PHYS_OFFSET(addr) (addr - GUL_EP_DMA_BUF_PHYS_ADDR)
#define GUL_EP_HIF_OFFSET		0x1C000
#define GUL_EP_HIF_SIZE			(4 * 1024)

#define GUL_MAX_SCRATCH_BUF_SIZE	(2 * 1024 * 1024 * 1024)
#define GUL_RFIC_SCRATCH_BUF_SIZE	(1024 * 1024)
#define GUL_MSI_MAX_CNT		8
#define GUL_QDMA_CHANNELS	14

enum gul_msi_id {
	MSI_IRQ_MUX = 0,
	MSI_IRQ_UNUSED_1,
	MSI_IRQ_UNUSED_2,
	MSI_IRQ_UNUSED_3,
	MSI_IRQ_UNUSED_4,
	MSI_IRQ_UNUSED_5,
	MSI_IRQ_UNUSED_6,
	MSI_IRQ_UNUSED_7,
};

enum scratch_buf_request_id {
	GUL_SCRATCH_L1_TRACE = 0,
	GUL_SCRATCH_DBG_LOGGER,
	GUL_SCRATCH_END,
};

enum gul_msg_unit_id {
	GUL_MSG_UNIT_1 = 0,
	GUL_MSG_UNIT_2,
	GUL_MSG_UNIT3,
	GUL_MSG_UNIT_CNT,
};

#define GUL_DMA_OUTBOUND_WIN    OUTBOUND_0
#define GUL_MSI_OUTBOUND_WIN    OUTBOUND_1
#define GUL_V2H_OUTBOUND_WIN    OUTBOUND_2


#define GUL_IRQ_MUX_MSG_UNIT		GUL_MSG_UNIT_1
#define GUL_RFIC_SWCMD_MSG_UNIT		GUL_MSG_UNIT_1
#define BITMASK(n)			(1 << n)
#define GUL_IRQ_MUX_MSG_UNIT_BIT	(0)
#define GUL_RFIC_SWCMD_MSG_UNIT_BIT	(1)

#define GUL_IPC_MSG_UNIT		GUL_MSG_UNIT_2
#define GUL_IPC_CH_MSG_UNIT_BIT(n)	(1 << n)
#define GUL_IPC_CH0_MSG_UNIT_BIT	(0)
#define GUL_IPC_CH1_MSG_UNIT_BIT	(1)
#define GUL_IPC_CH2_MSG_UNIT_BIT	(2)
#define GUL_IPC_CH3_MSG_UNIT_BIT	(3)

/*TBD: This structure needs to be changed for MPIC message registers*/
struct gul_msg_unit {
	uint32_t msiir;
	uint32_t msir;
} __attribute__ ((packed));

/*Scratch register for Host <> GUL Boot hand shake*/
#define GUL_BOOT_HSHAKE_HIF_REG		10
#define GUL_BOOT_HSHAKE_HIF_SIZ_REG	11

enum gul_boot_fsm {
	NONE = 0,
	GUL_HOST_START_CLOCK_CONFIG,
	GUL_HOST_COMPLETE_CLOCK_CONFIG,
	GUL_HOST_START_DRIVER_INIT,
};

#define		PCIE_QDMA_DIS_MASK	0x00000001

struct sgtable {
	uint32_t len;
	uint32_t resv;
	uint32_t src;
	uint32_t dest;
};

struct cfword {
	uint32_t addr;
	uint32_t data;
};

struct gul_boot_header {
	uint32_t			preamble;
	uint32_t			sgentries;
	struct sgtable			sgtbl[8];
	uint32_t			bl_entry;
	uint32_t			flags;
	uint32_t			cfword_count;
	struct  cfword			cfwrd[128];
	uint32_t			target_boot_done;       // for testing
} __packed;
/*
struct gul_boot_header {
	uint32_t preamble;
	uint32_t plugin_size;
	uint32_t plugin_offset;
	uint32_t bl_size;
	uint32_t bl_src_offset;
	uint32_t bl_dest;
	uint32_t bl_entry;
	uint32_t reserved;
} __attribute__ ((packed));
*/
#define GUL_BOOT_HDR_BYPASS_BOOT_PLUGIN	(1 << 16)
#define GUL_BOOT_HDR_BYPASS_BOOT_EDMA	(1 << 0)

struct irq_evt_regs {
	uint32_t irq_evt_cfg;
	uint32_t irq_evt_en;
	uint32_t irq_evt_status;
	uint32_t irq_evt_clr;
	uint32_t vspa_evt_mask;
	uint32_t ipc_evt_mask;
	uint32_t test_evt_mask;
} __attribute__ ((packed));

#define GUL_EVT_UPDATE_EVT_CFG(pIrqEvtRegs, nIrqEvts) do {	\
	pIrqEvtRegs->irq_evt_cfg &= ~(0xff00);			\
	pIrqEvtRegs->irq_evt_cfg |= (nIrqEvts << 8);		\
} while (0)

#define GUL_EVT_SET_EVT_CFG(pIrqEvtRegs, nIrqWrds, nIrqEvts) do {	\
	pIrqEvtRegs->irq_evt_cfg = ((nIrqEvts << 8) | nIrqWrds);	\
} while (0)

#define GUL_DBG_LOG_MAX_STRLEN	(100)

struct debug_log_regs {
	uint64_t buf;
	uint64_t len;
	uint32_t log_level;
} __attribute__ ((packed));

#define GUL_LOG_LEVEL_ERR	1
#define GUL_LOG_LEVEL_INFO	2
#define GUL_LOG_LEVEL_DBG	3
#define GUL_LOG_LEVEL_ISR	4
#define GUL_LOG_LEVEL_ALL	5

struct gul_QDMA {
	uint32_t status;
	uint32_t xfer_req;
	uint32_t success_interrupt;
	uint32_t error_interrupt;
	uint32_t no_callback_reg;
} __attribute__((packed));

struct gul_ipc_stats {
	uint32_t num_of_msg_recved;  /**< Total number of messages received */
	uint32_t num_of_msg_sent;    /**< Total number of messages/ptr sent */
	uint32_t total_msg_length;   /**< Total message length */
	uint32_t error_count;        /**<  Error count */
	uint32_t err_input_invalid;
	uint32_t err_channel_invalid;
	uint32_t err_instance_invalid;
	uint32_t err_mem_invalid;
	uint32_t err_channel_full;
	uint32_t err_channel_empty;
	uint32_t err_buf_list_full;
	uint32_t err_buf_list_empty;
} __attribute__((packed));

struct gul_stats {
	uint32_t disabled_evt_try_cnt;
	uint32_t irq_evt_raised;
	uint32_t irq_evt_cleared;
	uint32_t irq_mux_tx_msi_cnt;
	uint32_t irq_mux_rx_msi_cnt;
	uint32_t avi_cm4_mbox0_tx_cnt;
	uint32_t avi_cm4_mbox1_tx_cnt;
	uint32_t avi_cm4_mbox0_rx_cnt;
	uint32_t avi_cm4_mbox1_rx_cnt;
	uint32_t avi_err_queue_full;
	uint32_t avi_intr_raised;
	uint32_t avi_mbox_intr_raised;
	uint32_t eDMA_ch_allocated;
	struct gul_QDMA gul_QDMA_ch[GUL_QDMA_CHANNELS];
	uint32_t WDOG_interrupt;
	struct gul_ipc_stats gul_ipc_ch[NUM_IPC_CHANNELS];
} __attribute__((packed));

struct hif_ipc_regs {
	uint32_t ipc_mdata_offset;
	uint32_t ipc_mdata_size;
} __attribute__((packed));

struct hif_rfic_regs {
	uint32_t mdata_offset_reg;
	uint32_t mdata_size;
	uint32_t spi_access_disabled;
} __attribute__((packed));

struct hif_feca_regs {
	uint64_t axi_slave;
	uint64_t axi_slave_size;
	uint64_t apb_slave;
	uint64_t apb_slave_size;
} __attribute__((packed));

enum host_mem_region_id {
	HOST_MEM_HUGE_PAGE_BUF = 0,
	HOST_MEM_SCRATCH_BUF,
	HOST_MEM_FECA_AXI_SLAVE,
	HOST_MEM_FECA_APB_SLAVE,
	HOST_MEM_END
};

struct host_mem_region {
	uint32_t mod_phys_l;
	uint32_t mod_phys_h;
	uint32_t size_l;
	uint32_t size_h;
} __attribute__((packed));

/* XXX:NOTE: Always increment HIF version when you add anything in
 * struct gul_hif. Following are rules for MAJOR/MINOR increment
 * MAJOR version: If a new register/register group is added.
 * MINOR version: If a new bit/flag of a register is added.
 */

#define GUL_HIF_MAJOR_VERSION		(0)
#define GUL_HIF_MINOR_VERSION		(1)

struct gul_hif {
	uint32_t ver;
	uint32_t hif_ver;
	uint32_t status;
	uint32_t host_ready;
	uint32_t mod_ready;
	struct host_mem_region host_regions[HOST_MEM_END];
	struct irq_evt_regs irq_evt_regs;
	struct debug_log_regs dbg_log_regs;
	struct gul_stats stats;
	struct hif_ipc_regs ipc_regs;
	struct hif_rfic_regs rfic_regs;
	struct hif_feca_regs feca_regs;
} __attribute__((packed));


#define GUL_VER_MAJOR(ver) ((ver >> 16) & 0xffff)
#define GUL_VER_MINOR(ver) (ver & 0xffff)
#define GUL_VER_MAKE(major, minor) (((major & 0xffff) << 16) \
				| (minor & 0xffff))

/* Host Ready bits */
#define HIF_HOST_READY_HOST_REGIONS	(1 << 0)
#define HIF_HOST_READY_VSPA1		(1 << 3)
#define HIF_HOST_READY_VSPA2		(1 << 4)
#define HIF_HOST_READY_VSPA3		(1 << 5)
#define HIF_HOST_READY_VSPA4		(1 << 6)
#define HIF_HOST_READY_VSPA5		(1 << 7)
#define HIF_HOST_READY_VSPA6		(1 << 8)
#define HIF_HOST_READY_VSPA7		(1 << 9)
#define HIF_HOST_READY_VSPA8		(1 << 10)
#define HIF_HOST_READY_RFIC		(1 << 11)
#define HIF_HOST_READY_IPC_LIB		(1 << 12)
#define HIF_HOST_READY_IPC_APP		(1 << 13)

/*For Modem Define these macros using endianness conversion to LE*/

#define SET_HIF_HOST_RDY(hif, RDY_MASK) (hif->host_ready |= RDY_MASK)
#define CHK_HIF_MOD_RDY(hif, RDY_MASK) (hif->mod_ready & RDY_MASK)

/* Modem Ready bits */
#define HIF_MOD_READY_AIOP_ATUS		(1 << 0)
#define HIF_MOD_READY_IPC_LIB		(1 << 5)
#define HIF_MOD_READY_IPC_APP		(1 << 6)

/* Set IRQ_REAL_MSI_BIT to enable dedicated MSI interrupt line ,
 * and virtual irq line can be used by setting the TEST or LAST
 * EVT bits */

typedef enum {
	IRQ_EVT_IPC_CH1_BIT = 0,
	IRQ_EVT_IPC_CH2_BIT,
	IRQ_EVT_IPC_CH3_BIT,
	IRQ_EVT_IPC_CH4_BIT,
	IRQ_EVT_VSPA_BIT,
	IRQ_EVT_TEST_BIT,
	IRQ_EVT_LAST_BIT,
	IRQ_REAL_MSI_BIT
} gul_irq_evt_bits_t;

/* This enum will specify the dedicated MSI lines shared between
 * the host and EP (**MSI_IRQ_MAX_CNT cant be used as a MSI line)
 */

#define GUL_IRQ_EVT(bit) (1 << bit)
#define GUL_EVT_BTS_PER_WRD	32

/* XXX:NOTE: If you add an EVT in gul_irq_evt_bits_t, add the bit
 * in relevant mask below as well. If you add new Event group in additional to
 * the groups (VSPA, IPC, TEST) below. Define a new mask and add handling
 * in gul_get_subdrv_virqmap() function
 */
#define IRQ_EVT_VSPA_EVT_MASK	(GUL_IRQ_EVT(IRQ_EVT_VSPA_BIT))
#define IRQ_EVT_IPC_EVT_MASK	(GUL_IRQ_EVT(IRQ_EVT_IPC_CH1_BIT) |	\
				 GUL_IRQ_EVT(IRQ_EVT_IPC_CH2_BIT) |	\
				 GUL_IRQ_EVT(IRQ_EVT_IPC_CH3_BIT) |	\
				 GUL_IRQ_EVT(IRQ_EVT_IPC_CH4_BIT))
#define IRQ_EVT_TEST_EVT_MASK	(GUL_IRQ_EVT(IRQ_EVT_TEST_BIT))
#define IRQ_EVT_MSI_MASK	(GUL_IRQ_EVT(IRQ_REAL_MSI_BIT))

#endif
