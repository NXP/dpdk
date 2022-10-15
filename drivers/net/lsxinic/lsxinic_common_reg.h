/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022 NXP
 */

#ifndef _LSINIC_REG_H_
#define _LSINIC_REG_H_

#ifndef __packed
#define __packed	__rte_packed
#endif

#include "lsxinic_common.h"

/* INIC device information */
#define LSINIC_INIT_FLAG	0xfee5ca1e

enum LSINIC_QEUE_TYPE {
	LSINIC_QUEUE_RX,
	LSINIC_QUEUE_TX
};

#define LSINIC_DONT_INT		(0)
#define LSINIC_MSIX_INT		(1)
#define LSINIC_MMSI_INT		(2)

#define LSX_PCIEP_REG_BAR_IDX (0)
#define LSX_PCIEP_RING_BAR_IDX (2)
#define LSX_PCIEP_XFER_MEM_BAR_IDX (4)

#define LSINIC_RC_TX_DATA_ROOM_OVERHEAD 128

/* lsinic_bd_desc descriptor for iNIC */
/* len_cmd field bit definitions */
/* For CB buffer, length excludes CB header.*/
#define LSINIC_BD_LEN_MASK	0x0000ffff /* Data length mask */
#define LSINIC_BD_CMD_EOP	0x80000000 /* End of Packet */

enum lsinic_dev_status {
	LSINIC_DEV_INITING,
	LSINIC_DEV_INITED,
	LSINIC_DEV_UP,
	LSINIC_DEV_DOWN,
	LSINIC_DEV_REMOVED
};

enum LSINIC_QEUE_STATUS {
	LSINIC_QUEUE_UNAVAILABLE,
	LSINIC_QUEUE_START,
	LSINIC_QUEUE_RUNNING,
#ifdef RTE_LSINIC_PCIE_RAW_TEST_ENABLE
	LSINIC_QUEUE_RAW_TEST_RUNNING,
#endif
	LSINIC_QUEUE_STOP,
};

enum LSINIC_QEUE_MSIX_STATUS {
	LSINIC_QUEUE_MSIX_UNMASK,
	LSINIC_QUEUE_MSIX_MASK,
};

enum inic_command {
	INIC_COMMAND_VF_MAC_ADDR = 0x01,
	INIC_COMMAND_VF_VLAN = 0x10,
	INIC_COMMAND_PF_MAC_ADDR = 0x1000
};

#define PCIDEV_DRIVER_MAX_NUM	64
#define PCIDEV_TYPE_UNKNOWN	0
#define PCIDEV_TYPE_NETWORK_0	0x01
#define PCIDEV_TYPE_NETWORK_MAX	0x1f
#define PCIDEV_TYPE_SEC_0	0x20
#define PCIDEV_TYPE_SEC_MAX	0x3f
#define PCIDEV_TYPE_PME		0x40
#define PCIDEV_TYPE_MEM		0x50

enum PCIDEV_COMMAND {
	PCIDEV_COMMAND_IDLE,
	PCIDEV_COMMAND_INIT,
	PCIDEV_COMMAND_START,
	PCIDEV_COMMAND_STOP,
	PCIDEV_COMMAND_REMOVE,
	PCIDEV_COMMAND_SET_MAC,
	PCIDEV_COMMAND_SET_MTU,
	PCIDEV_COMMAND_SET_VLAN,
	PCIDEV_COMMAND_SET_VF_MAC,
	PCIDEV_COMMAND_SET_VF_VLAN,
	PCIDEV_COMMAND_NUM,
};

enum PCIDEV_RESULT {
	PCIDEV_RESULT_SUCCEED,
	PCIDEV_RESULT_FAILED,
	PCIDEV_RESULT_NUM,
};

enum PCIDEV_STATUS {
	PCIDEV_STATUS_IDLE,
	PCIDEV_STATUS_INIT,
	PCIDEV_STATUS_START,
	PCIDEV_STATUS_STOP,
	PCIDEV_STATUS_REMOVE,
	PCIDEV_STATUS_TODEV,
	PCIDEV_STATUS_NUM,
};

#define LSINIC_RING_REG_OFFSET (0)

/* Transmit Config masks */
#define LSINIC_CR_DISABLE	0x00000000 /* Disable specific Queue */
#define LSINIC_CR_ENABLE	0x80000000 /* Enable specific Queue */
#define LSINIC_CR_BUSY		0x40000000 /* Specific Queue busy */

#define LSINIC_INT_VECTOR_SHIFT 16
#define LSINIC_INT_THRESHOLD_MASK \
	((((uint32_t)1) << LSINIC_INT_VECTOR_SHIFT) - 1)

/* Size is 0x40 */
enum EP_MEM_BD_TYPE {
	EP_MEM_LONG_BD,
	/* For RC to set dest addr in RC memory, EP->RC*/
	EP_MEM_DST_ADDR_BD,
	EP_MEM_DST_ADDRL_BD,
	EP_MEM_DST_ADDRX_BD,
	/* For RC to set source addr in RC memory, RC->EP*/
	EP_MEM_SRC_ADDRL_BD,
	EP_MEM_SRC_ADDRX_BD
};

enum RC_MEM_BD_TYPE {
	RC_MEM_LONG_BD,
	/* For EP to notify RC with len and cmd, EP->RC*/
	RC_MEM_LEN_CMD,
	/* For EP to confirm RC, RC->EP*/
	RC_MEM_BD_CNF,
	RC_MEM_IDX_CNF
};

struct lsinic_ring_reg {
	uint32_t cr;
	uint32_t sr;
	uint32_t barl;
	uint32_t pir;	/* rc produce data, then modify the register */
	uint32_t cir;	/* ep consume data, then modify the register */
	uint32_t ar;
	uint32_t icrl;
	uint32_t icrh;
	/**
	 * Interrupt Coalescing Register
	 * Interrupt vector bits 31:16
	 * Indicates interrupt verctor which will be used to generate
	 * MSIX interrupt to remote.
	 * 0: MSIX vector 0
	 * ...
	 * 7: MSIX vector 7
	 *
	 * Interrupt event threshold bits 15:0
	 * Indicates the number of interrupt events that need to occur
	 * in order to generate a remote interrupt ...
	 * 0: 0 interrupt events (coalescing mode disabled)
	 * ...
	 * 0xFF: 255 interrupt events
	 */
	uint32_t icr;
	/**
	 * Interrupt interval Register
	 * Indicates the interval of time that must elapse for a remote
	 * interrupt to be generated when the icr is greater than 0, but
	 * less than the coalescing threshold
	 * 0 0ns
	 * 1 1ns
	 */
	uint32_t iir;
	uint32_t isr;
	uint32_t r_descl;	/* desc PCI low address On RC side */
	uint32_t r_desch;	/* desc PCI high address On RC side */
	uint32_t r_ep_mem_bd_type;
	uint32_t r_rc_mem_bd_type;
#ifdef RTE_LSINIC_PCIE_RAW_TEST_ENABLE
	uint32_t r_raw_test;	/* EP PCIe RAW test */
#endif
} __packed;

struct lsinic_bdr_reg {
	struct lsinic_ring_reg tx_ring[LSINIC_RING_MAX_COUNT];
	struct lsinic_ring_reg rx_ring[LSINIC_RING_MAX_COUNT];
} __packed;

#define LSINIC_RING_BD_OFFSET (0x2000)

enum lsinic_ring_bd_status {
	RING_BD_READY = 1,
	RING_BD_AVAILABLE = 2,
	RING_BD_HW_PROCESSING = 3,
	RING_BD_HW_COMPLETE = 4
};

#define RING_BD_STATUS_MASK 0xff

#define RING_BD_ADDR_CHECK (RING_BD_STATUS_MASK + 1)

#define LSINIC_BD_CTX_IDX_INVALID 0xfff
#define LSINIC_BD_CTX_IDX_SHIFT 16
#define LSINIC_BD_CTX_IDX_MASK \
	(~(uint32_t)((((uint32_t)1) << LSINIC_BD_CTX_IDX_SHIFT) - 1))
#define lsinic_bd_ctx_idx(bd_status) \
	((((uint32_t)(bd_status)) & LSINIC_BD_CTX_IDX_MASK) >> \
	LSINIC_BD_CTX_IDX_SHIFT)

struct lsinic_bd_desc {
	uint64_t pkt_addr;	/* Packet buffer address */
	union {
		uint64_t desc;
		struct {
			/* For CB buffer, length excludes CB header.*/
			uint32_t len_cmd;	/* length and command */
			uint32_t bd_status;
		};
	};
} __packed;

#define LSINIC_BD_ENTRY_SIZE sizeof(struct lsinic_bd_desc)
#define LSINIC_BD_ENTRY_COUNT_SHIFT 9
#define LSINIC_BD_ENTRY_COUNT (1 << LSINIC_BD_ENTRY_COUNT_SHIFT)

struct lsinic_rc_rx_len_idx {
	union {
		uint32_t len_idx;
		struct {
			/* For CB buffer, length excludes CB header.*/
			uint16_t total_len;
			uint16_t idx;
		};
	};
} __packed;

struct lsinic_rc_tx_bd_cnf {
	uint8_t bd_complete;
} __packed;

struct lsinic_rc_tx_idx_cnf {
	uint32_t idx_complete;
} __packed;

struct lsinic_ep_tx_dst_addr {
	uint64_t pkt_addr;
} __packed;

struct lsinic_ep_tx_dst_addrl {
	uint32_t pkt_addr_low;
} __packed;

struct lsinic_ep_tx_dst_addrx {
	uint16_t pkt_addr_idx;
} __packed;

struct lsinic_ep_rx_src_addrl {
	union {
		uint64_t addr_cmd_len;
		struct {
			uint32_t pkt_addr_low;
			uint32_t len_cmd;
		};
	};
} __packed;

struct lsinic_ep_rx_src_addrx {
	union {
		uint32_t idx_cmd_len;
		struct {
			uint16_t pkt_idx;
			uint16_t len;
		};
	};
} __packed;

#define LSINIC_MAX_BD_ENTRY_SIZE LSINIC_BD_ENTRY_SIZE

#define LSINIC_BD_RING_SIZE	\
	(LSINIC_BD_ENTRY_SIZE * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_LEN_IDX_RING_SIZE \
	(sizeof(struct lsinic_rc_rx_len_idx) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_BD_CNF_RING_SIZE \
	(sizeof(struct lsinic_rc_tx_bd_cnf) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_IDX_CNF_SIZE sizeof(struct lsinic_rc_tx_idx_cnf)

#define LSINIC_DST_ADDR_RING_SIZE \
	(sizeof(struct lsinic_ep_tx_dst_addr) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_DST_ADDRL_RING_SIZE \
	(sizeof(struct lsinic_ep_tx_dst_addrl) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_DST_ADDRX_RING_SIZE \
	(sizeof(struct lsinic_ep_tx_dst_addrx) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_SRC_ADDRL_RING_SIZE \
	(sizeof(struct lsinic_ep_rx_src_addrl) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_SRC_ADDRX_RING_SIZE \
	(sizeof(struct lsinic_ep_rx_src_addrx) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_RING_SIZE \
	(LSINIC_MAX_BD_ENTRY_SIZE * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_TX_RING_BD_MAX_SIZE \
	(LSINIC_RING_SIZE * LSINIC_RING_MAX_COUNT)

#define LSINIC_RX_RING_BD_MAX_SIZE \
	(LSINIC_RING_SIZE * LSINIC_RING_MAX_COUNT)

#define LSINIC_RING_BD_MAX_SIZE \
	(LSINIC_TX_RING_BD_MAX_SIZE + LSINIC_RX_RING_BD_MAX_SIZE)

#define LSINIC_TX_BD_OFFSET 0
#define LSINIC_RX_BD_OFFSET LSINIC_TX_RING_BD_MAX_SIZE

#define LSINIC_RING_BAR_MAX_SIZE \
	(LSINIC_RX_BD_OFFSET + LSINIC_RX_RING_BD_MAX_SIZE)

#define LSINIC_REG_OFFSET(p, o) ((void *)((uint8_t *)(p) + (o)))

static inline uint32_t
lxsnic_test_staterr(struct lsinic_bd_desc *bd_desc,
	const uint32_t stat_err_bits)
{
	return (bd_desc->len_cmd) & stat_err_bits;
}

#define LSINIC_DEV_REG_OFFSET (0x0000)

struct lsinic_command_reg {
	uint32_t cmd_type;
	uint32_t cmd_vf_idx;
	uint32_t cmd_vf_vlan;
	uint32_t cmd_vf_macaddrh;
	uint32_t cmd_vf_macaddrl;
} __packed;

struct lsinic_dev_reg {  /* offset 0x000-0x1FF */
	/* RC send command and get result from status reg */
	uint32_t command;		/* 0x000 */
	uint32_t result;		/* 0x004 */

	/* EP information */
	uint32_t rev;			/* 0x008 */
	uint32_t ep_state;		/* 0x00c */
	uint32_t pf_idx;		/* 0x010 */
	uint32_t vf_idx;		/* 0x014 */
	uint32_t init_flag;		/* 0x018 */
	uint32_t cap[63];		/* 0x01c - 0x114 */
	uint32_t rx_ring_max_num;	/* 0x118 */
	uint32_t rx_entry_max_num;	/* 0x11c */
	uint32_t tx_ring_max_num;	/* 0x120 */
	uint32_t tx_entry_max_num;	/* 0x124 */
	uint32_t msix_max_num;		/* 0x128 */
	uint32_t dev_reg_offset;	/* 0x12c */
	uint32_t obwin_size;		/* 0x130 xG */
	uint32_t vf_num;		/* 0x134 MAX VF number */
} __packed;

#define LSINIC_RCS_REG_OFFSET (0x0200)

#define LSINIC_DEV_MSIX_MAX_NB LSINIC_RING_MAX_COUNT

struct lsinic_rcs_reg {  /* offset 0x200-0x2FF */
	/* RC sets the following reg */
	uint32_t rc_state;
	struct lsinic_command_reg cmd;
	uint32_t r_regl;	/* shadow reg low address On RC side */
	uint32_t r_regh;	/* shadow reg high address On RC side */
	uint64_t r_dma_base;
	uint32_t r_dma_elt_size;
	uint32_t msi_flag;
	uint32_t msix_mask[LSINIC_DEV_MSIX_MAX_NB];
} __packed;

#define LSINIC_ETH_REG_OFFSET (0x0300)

static inline int val_bit_len(uint64_t mask)
{
	int len = 0;

	if (mask)
		len = 1;
	else
		return 0;

	while (mask >> 1) {
		mask = mask >> 1;
		len++;
	}

	return len;
}

#define LSINIC_CAP_XFER_COMPLETE_POS 0
#define LSINIC_CAP_XFER_COMPLETE \
	(1 << LSINIC_CAP_XFER_COMPLETE_POS)

#define LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM_POS 1
#define LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM \
	(1 << LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM_POS)

#define LSINIC_CAP_XFER_ORDER_PRSV_POS 2
#define LSINIC_CAP_XFER_ORDER_PRSV \
	(1 << LSINIC_CAP_XFER_ORDER_PRSV_POS)

enum rc_set_addr_type {
	RC_SET_ADDRF_TYPE = 0,
	RC_SET_ADDRL_TYPE = 1,
	RC_SET_ADDRX_TYPE = 2,
	RC_SET_ADDR_TYPE_MASK = 3
};

#define LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_POS 3
#define LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_GET(cap) \
	(((cap) >> LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_POS) & \
	RC_SET_ADDR_TYPE_MASK)
#define LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_SET(cap, type) \
	do { \
		(cap) &= ~(RC_SET_ADDR_TYPE_MASK << \
			LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_POS); \
		(cap) |= ((type) << LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_POS); \
	} while (0)

#define LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_POS \
	(LSINIC_CAP_XFER_RC_XMIT_ADDR_TYPE_POS + \
	val_bit_len(RC_SET_ADDR_TYPE_MASK))

enum rc_xmit_cnf_type {
	RC_XMIT_BD_CNF = 0,
	RC_XMIT_RING_CNF = 1,
	RC_XMIT_INDEX_CNF = 2,
	RC_XMIT_CNF_MASK = 3
};

#define LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap) \
	(((cap) >> LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_POS) & RC_XMIT_CNF_MASK)
#define LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(cap, type) \
	do { \
		(cap) &= ~(RC_XMIT_CNF_MASK << \
			LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_POS); \
		(cap) |= ((type) << LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_POS); \
	} while (0)

#define LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_POS \
	(LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_POS + val_bit_len(RC_XMIT_CNF_MASK))

enum ep_xmit_bd_type {
	EP_XMIT_LBD_TYPE = 0,
	EP_XMIT_SBD_TYPE = 1,
	EP_XMIT_BD_TYPE_MASK = 3
};

#define LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_GET(cap) \
	(((cap) >> LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_POS) & EP_XMIT_BD_TYPE_MASK)

#define LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(cap, type) \
	do { \
		(cap) &= ~(EP_XMIT_BD_TYPE_MASK << \
			LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_POS); \
		(cap) |= ((type) << LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_POS); \
	} while (0)

#define LSXINIC_VF_AVAILABLE (((uint32_t)1) << 15)

struct lsinic_eth_reg {  /* offset 0x300-0x3FF */
	uint32_t rev;
	uint32_t cap;
	uint32_t eth_stat;
	uint32_t fmidx;
	uint32_t macidx;
	uint32_t macaddrh;
	uint32_t macaddrl;
	uint32_t tx_ring_num;
	uint32_t tx_entry_num;
	uint32_t rx_ring_num;
	uint32_t rx_entry_num;
	uint32_t vlan;
	uint32_t vf_idx;
	uint32_t vf_macaddrh;
	uint32_t vf_macaddrl;
	uint32_t vf_vlan;
	uint32_t max_data_room;
} __packed;

#define LSINIC_REG_BAR_MAX_SIZE \
	(LSINIC_ETH_REG_OFFSET + sizeof(struct lsinic_eth_reg))

#define LSINIC_RC_BD_DESC(R, i)	(&(R)->rc_bd_desc[i])
#define LSINIC_EP_BD_DESC(R, i)	(&(R)->ep_bd_desc[i])

#endif /* _LSINIC_REG_H_ */
