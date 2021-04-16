/*
 * Copyright 2017-2021 NXP
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
#ifndef __LA9310_HOST_IF_H__
#define __LA9310_HOST_IF_H__

/* No of buffer descriptor  in ring */
#define V2H_MAX_BD			16
#define MAX_SENT_RESUME			5

/*Common Addresses and offsets*/
#define LA9310_EP_DMA_BUF_PHYS_ADDR	0xA0000000
#define LA9310_EP_TOHOST_MSI_PHY_ADDR	0xA0400000
#define LA9310_SCRATCH_DMA_BUF_PHYS_ADDR	0xA0600000
#define LA9310_USER_HUGE_PAGE_PHYS_ADDR	0xC0000000
#define LA9310_EP_FREERTOS_LOAD_ADDR	0x1f800000
#define LA9310_EP_BOOT_HDR_OFFSET		0x00000000
#define LA9310_EP_DMA_PHYS_OFFSET(addr) (addr - LA9310_EP_DMA_BUF_PHYS_ADDR)
#define LA9310_EP_HIF_OFFSET		0x1C000
#define LA9310_EP_IPC_OFFSET		0x1D000
#define LA9310_EP_HIF_SIZE			(4 * 1024)
#define LA9310_EP_IPC_SIZE			(16 * 1024)

#define LA9310_MAX_SCRATCH_BUF_SIZE	(128 * 1024 * 1024)
#define LA9310_MSI_MAX_CNT		8
#define LA9310_eDMA_CHANNELS	14

#define LA9310_DMA_OUTBOUND_WIN    OUTBOUND_0
#define LA9310_MSI_OUTBOUND_WIN    OUTBOUND_1
#define LA9310_V2H_OUTBOUND_WIN    OUTBOUND_2


#define LA9310_IRQ_MUX_MSG_UNIT		LA9310_MSG_UNIT_1
#define BITMASK(n)			(1 << n)
#define LA9310_IRQ_MUX_MSG_UNIT_BIT	(0)

#define LA9310_IPC_MSG_UNIT		LA9310_MSG_UNIT_2
#define LA9310_IPC_CH_MSG_UNIT_BIT(n)	(1 << n)
#define LA9310_IPC_CH0_MSG_UNIT_BIT	(0)
#define LA9310_IPC_CH1_MSG_UNIT_BIT	(1)
#define LA9310_IPC_CH2_MSG_UNIT_BIT	(2)
#define LA9310_IPC_CH3_MSG_UNIT_BIT	(3)

struct la9310_msg_unit {
	uint32_t msiir;
	uint32_t msir;
} __attribute__ ((packed));

/*Scratch register for Host <> LA9310 Boot hand shake*/
#define LA9310_BOOT_HSHAKE_SCRATCH_REG	1

#define LA9310_BOOT_HDR_BYPASS_BOOT_PLUGIN	(1 << 16)
#define LA9310_BOOT_HDR_BYPASS_BOOT_EDMA	(1 << 0)

struct la9310_irq_evt_regs {
	uint32_t irq_evt_cfg;
	uint32_t irq_evt_en;
	uint32_t irq_evt_status;
	uint32_t irq_evt_clr;
	uint32_t vspa_evt_mask;
	uint32_t ipc_evt_mask;
	uint32_t test_evt_mask;
} __attribute__ ((packed));

#define LA9310_EVT_UPDATE_EVT_CFG(pIrqEvtRegs, nIrqEvts) do {	\
	pIrqEvtRegs->irq_evt_cfg &= ~(0xff00);			\
	pIrqEvtRegs->irq_evt_cfg |= (nIrqEvts << 8);		\
} while (0)

#define LA9310_EVT_SET_EVT_CFG(pIrqEvtRegs, nIrqWrds, nIrqEvts) do {	\
	pIrqEvtRegs->irq_evt_cfg = ((nIrqEvts << 8) | nIrqWrds);	\
} while (0)

#define LA9310_DBG_LOG_MAX_STRLEN	(100)

struct la9310_debug_log_regs {
	uint32_t buf;
	uint32_t len;
	uint32_t log_level;
} __attribute__ ((packed));

#define LA9310_LOG_LEVEL_ERR	1
#define LA9310_LOG_LEVEL_INFO	2
#define LA9310_LOG_LEVEL_DBG	3
#define LA9310_LOG_LEVEL_ISR	4
#define LA9310_LOG_LEVEL_ALL	5

struct la9310_eDMA {
	uint8_t  status;
	uint32_t xfer_req;
	uint32_t success_interrupt;
	uint32_t error_interrupt;
	uint32_t no_callback_reg;
};

struct la9310_stats {
	uint32_t disabled_evt_try_cnt;
	uint32_t irq_evt_raised;
	uint32_t irq_evt_cleared;
	uint32_t irq_mux_tx_msi_cnt;
	uint32_t irq_mux_rx_msi_cnt;
	uint32_t v2h_sent_pkt;
	uint32_t v2h_dropped_pkt;
	uint32_t v2h_resumed;
	uint32_t v2h_last_sent_pkt;
	uint32_t v2h_last_dropped_pkt;
	uint32_t v2h_last_sent_pkt_resumed[MAX_SENT_RESUME];
	uint32_t v2h_last_dropped_pkt_resumed[MAX_SENT_RESUME];
	uint32_t v2h_final_ring_owner[V2H_MAX_BD];
	uint32_t v2h_backout_count;
	uint32_t avi_cm4_mbox0_tx_cnt;
	uint32_t avi_cm4_mbox1_tx_cnt;
	uint32_t avi_cm4_mbox0_rx_cnt;
	uint32_t avi_cm4_mbox1_rx_cnt;
	uint32_t avi_err_queue_full;
	uint32_t avi_intr_raised;
	uint32_t avi_mbox_intr_raised;
	uint32_t eDMA_ch_allocated;
	struct la9310_eDMA la9310_eDMA_ch[LA9310_eDMA_CHANNELS];
	uint32_t WDOG_interrupt;
	uint32_t rf_host_swcmds_rxed;
	uint32_t rf_host_swcmds_busy;
	uint32_t rf_host_swcmd_dropped_qfull;
	uint32_t rf_venom_cmd_recv;
	uint32_t rf_venom_cmd_resp_dropped_qfull;
	uint32_t rf_venom_cmd_failed;
	uint32_t v2h_intr_enabled;
};

struct la9310_hif_ipc_regs {
	uint32_t ipc_mdata_offset;
	uint32_t ipc_mdata_size;
};

/* Host ready bits */
#define LA9310_HIF_HOST_READY_IPC_LIB	(1 << 0)
#define LA9310_HIF_STATUS_VSPA_READY  (1 << 1)
#define LA9310_HIF_HOST_READY_IPC_APP	(1 << 2)
#define LA9310_HIF_STATUS_V2H_READY   (1 << 3)
#define LA9310_HIF_STATUS_WDOG_READY  (1 << 4)

/* Modem Ready bits */
#define LA9310_HIF_MOD_READY_IPC_LIB	(1 << 0)
#define LA9310_HIF_MOD_READY_IPC_APP	(1 << 1)

#define CHK_HIF_MOD_RDY(hif, RDY_MASK) (hif->mod_ready & RDY_MASK)
#define SET_HIF_HOST_RDY(hif, RDY_MASK) (hif->host_ready |= RDY_MASK)

/* XXX:NOTE: Always increment HIF version when you add anything in
 * struct la9310_hif. Following are rules for MAJOR/MINOR increment
 * MAJOR version: If a new register/register group is added.
 * MINOR version: If a new bit/flag of a register is added.
 */

#define LA9310_HIF_MAJOR_VERSION		(5)
#define LA9310_HIF_MINOR_VERSION		(1)

struct la9310_hif {
	uint32_t ver;
	uint32_t hif_ver;
	uint32_t status;
	uint32_t host_ready;
	uint32_t mod_ready;
	uint32_t scratch_buf_size[2];
	uint32_t scratch_buf_phys_addr[2];
	struct la9310_irq_evt_regs irq_evt_regs;
	struct la9310_debug_log_regs dbg_log_regs;
	struct la9310_stats stats;
	struct la9310_hif_ipc_regs ipc_regs;
} __attribute__((packed));

#endif
