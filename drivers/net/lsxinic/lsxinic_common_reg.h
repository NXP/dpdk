/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSINIC_REG_H_
#define _LSINIC_REG_H_

#ifndef __packed
#define __packed	__rte_packed
#endif

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

/* Combination number shift/mask */
#define LSINIC_BD_MG_NUM_SHIFT 16
#define LSINIC_BD_MG_NUM_MASK \
		(((uint32_t)0x1f) << LSINIC_BD_MG_NUM_SHIFT)

#define LSINIC_BD_CMD_EOP	0x80000000 /* End of Packet */
#define LSINIC_BD_CMD_SG	0x40000000 /* Segment Packet */
#define LSINIC_BD_CMD_MG	0x20000000 /* Merged Packet */
#define LSINIC_BD_CMD_VLE	0x10000000 /* Add VLAN tag */
#define LSINIC_BD_CMD_IXSM	0x08000000 /* Insert IP checksum */
#define LSINIC_BD_CMD_TXSM	0x04000000 /* Insert TCP/UDP checksum */
#define LSINIC_BD_CMD_IFCS	0x02000000 /* Insert FCS (Ethernet CRC) */
#define LSINIC_BD_CMD_IC	0x01000000 /* Insert Checksum */
#define LSINIC_BD_CMD_DEXT	0x00800000 /* Descriptor extension */
/* extended cmd field bit definitions */
#define LSINIC_BD_SG_LEN_MASK	0x0000ffff /* SG length mask */

#define LSINIC_MG_ALIGN_SIZE           8 /* bytes */

/* Within one cache line*/
#define LSINIC_MG_PKT_LEN_MASK 0x0fff
#define LSINIC_MG_ALIGN_OFFSET_SHIFT 12
#define LSINIC_MG_ALIGN_OFFSET_MASK \
	(((uint16_t)0xf) << LSINIC_MG_ALIGN_OFFSET_SHIFT)

#define LSINIC_MERGE_MAX_NUM		32

struct lsinic_mg_header {
	uint16_t len_cmd[LSINIC_MERGE_MAX_NUM];
} __packed;

#define lsinic_mg_entry_len(len_cmd) \
		((len_cmd) & LSINIC_MG_PKT_LEN_MASK)

#define lsinic_mg_entry_align_offset(len_cmd) \
		(((len_cmd) & LSINIC_MG_ALIGN_OFFSET_MASK) >> \
			LSINIC_MG_ALIGN_OFFSET_SHIFT)

#define lsinic_mg_entry_set(pkt_len, align_offset) \
		((((uint16_t)(align_offset) & 0xf) << \
		LSINIC_MG_ALIGN_OFFSET_SHIFT) | \
		(((uint16_t)(pkt_len)) & LSINIC_MG_PKT_LEN_MASK))

enum lsinic_xfer_complete_flag {
	LSINIC_XFER_COMPLETE_INIT_FLAG = 0,
	LSINIC_XFER_COMPLETE_DONE_FLAG = 1
};

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

#define LSINIC_RING_MAX_COUNT	32

#define LSINIC_RING_REG_OFFSET (0)

/* Transmit Config masks */
#define LSINIC_CR_DISABLE	0x00000000 /* Disable specific Queue */
#define LSINIC_CR_ENABLE	0x80000000 /* Enable specific Queue */
#define LSINIC_CR_BUSY		0x40000000 /* Specific Queue busy */

#define LSINIC_INT_VECTOR_SHIFT 16
#define LSINIC_INT_THRESHOLD_MASK \
	((((uint32_t)1) << LSINIC_INT_VECTOR_SHIFT) - 1)

/* Size is 0x40 */
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
	uint32_t r_ep2rcl;	/* ep2rc PCI low address On RC side */
	uint32_t r_ep2rch;	/* ep2rc PCI high address On RC side */
	uint32_t  resr[1];
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

#define LSINIC_BD_CTX_IDX_USED

#ifdef LSINIC_BD_CTX_IDX_USED
#define LSINIC_BD_CTX_IDX_INVALID 0xfff
#define LSINIC_BD_CTX_IDX_SHIFT 16
#define LSINIC_BD_CTX_IDX_MASK \
	(~(uint32_t)((((uint32_t)1) << LSINIC_BD_CTX_IDX_SHIFT) - 1))
#define lsinic_bd_ctx_idx(bd_status) \
	((((uint32_t)(bd_status)) & LSINIC_BD_CTX_IDX_MASK) >> \
	LSINIC_BD_CTX_IDX_SHIFT)
#endif

struct lsinic_bd_desc {
	uint64_t pkt_addr;	/* Packet buffer address */
#ifndef LSINIC_BD_CTX_IDX_USED
	uint64_t sw_ctx;
#endif
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

#ifdef LSINIC_BD_CTX_IDX_USED
#define EP2RC_TX_CTX_IDX(cnt_idx) \
	((cnt_idx) & (LSINIC_BD_ENTRY_COUNT - 1))
#define EP2RC_TX_CTX_CNT(cnt_idx) \
	((cnt_idx) >> (LSINIC_BD_ENTRY_COUNT_SHIFT + 1))

#define EP2RC_TX_IDX_CNT_SET(cnt_idx, idx, cnt) \
	(cnt_idx = (idx) | (cnt) << (LSINIC_BD_ENTRY_COUNT_SHIFT + 1))

struct ep2rc_notify {
	uint16_t total_len;
	uint16_t cnt_idx;
} __packed;
#endif

#define LSINIC_BD_RING_SIZE	(LSINIC_BD_ENTRY_SIZE * LSINIC_BD_ENTRY_COUNT)
#ifdef LSINIC_BD_CTX_IDX_USED
#define LSINIC_EP2RC_RING_MAX_SIZE \
	(sizeof(struct ep2rc_notify) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_EP2RC_NOTIFY_RING_SIZE LSINIC_EP2RC_RING_MAX_SIZE

#else
#define LSINIC_EP2RC_RING_MAX_SIZE \
	(sizeof(uint8_t) * LSINIC_BD_ENTRY_COUNT)
#endif

#define LSINIC_EP2RC_COMPLETE_RING_SIZE \
	(sizeof(uint8_t) * LSINIC_BD_ENTRY_COUNT)

#define LSINIC_RING_SIZE (LSINIC_BD_RING_SIZE + LSINIC_EP2RC_RING_MAX_SIZE)

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
	uint32_t rbp_enable;		/* 0x01c */
	uint32_t cap[62];		/* 0x020 - 0x114 */
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

struct lsinic_rcs_reg {  /* offset 0x200-0x2FF */
	/* RC sets the following reg */
	uint32_t bind_dev_id;
	uint32_t rc_state;
	struct lsinic_command_reg cmd;
	uint32_t r_regl;	/* shadow reg low address On RC side */
	uint32_t r_regh;	/* shadow reg high address On RC side */
	uint32_t rxdma_regl;	/* pci dma test rx low address On RC side */
	uint32_t rxdma_regh;	/* pci dma test rx high address On RC side */
	uint32_t txdma_regl;	/* pci dma test tx low address On RC side */
	uint32_t txdma_regh;	/* pci dma test tx high address On RC side */
	uint32_t msi_flag;
	uint32_t msix_mask[32];
} __packed;

#define LSINIC_ETH_REG_OFFSET (0x0300)

static inline int mask_bit_len(uint64_t mask)
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

enum egress_cnf_type {
	EGRESS_BD_CNF = 0,
	EGRESS_RING_CNF = 1,
	EGRESS_INDEX_CNF = 2,
	EGRESS_CNF_MASK = 3
};

#define LSINIC_CAP_XFER_EGRESS_CNF_POS 6

#define LSINIC_CAP_XFER_EGRESS_CNF_GET(cap) \
	(((cap) >> LSINIC_CAP_XFER_EGRESS_CNF_POS) & EGRESS_CNF_MASK)

#define LSINIC_CAP_XFER_EGRESS_CNF_SET(cap, type) \
	do { \
		(cap) &= ~(EGRESS_CNF_MASK << LSINIC_CAP_XFER_EGRESS_CNF_POS); \
		(cap) |= ((type) << LSINIC_CAP_XFER_EGRESS_CNF_POS); \
	} while (0)

enum ingress_notify_type {
	INGRESS_BD_NOTIFY = 0,
	INGRESS_RING_NOTIFY = 1,
	INGRESS_INDEX_NOTIFY = 2,
	INGRESS_NOTIFY_MASK = 3
};

#define LSINIC_CAP_XFER_INGRESS_NOTIFY_POS \
	(LSINIC_CAP_XFER_EGRESS_CNF_POS + mask_bit_len(EGRESS_CNF_MASK))

#define LSINIC_CAP_XFER_INGRESS_NOTIFY_GET(cap) \
	(((cap) >> LSINIC_CAP_XFER_INGRESS_NOTIFY_POS) & INGRESS_NOTIFY_MASK)

#define LSINIC_CAP_XFER_INGRESS_NOTIFY_SET(cap, type) \
	do { \
		(cap) &= ~(INGRESS_NOTIFY_MASK << \
			LSINIC_CAP_XFER_INGRESS_NOTIFY_POS); \
		(cap) |= ((type) << LSINIC_CAP_XFER_INGRESS_NOTIFY_POS); \
	} while (0)

#define LSINIC_CAP_XFER_COMPLETE 0x00000001
#define LSINIC_CAP_XFER_PKT_MERGE 0x00000002
#define LSINIC_CAP_XFER_TX_BD_UPDATE 0x00000004
#define LSINIC_CAP_XFER_RX_BD_UPDATE 0x00000008
#define LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM 0x00000010

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
	uint32_t merge_threshold;
} __packed;

#define LSINIC_REG_BAR_MAX_SIZE \
	(LSINIC_ETH_REG_OFFSET + sizeof(struct lsinic_eth_reg))

#define LSINIC_RC_BD_DESC(R, i)	    (&(R)->rc_bd_desc[i])
#define LSINIC_EP_BD_DESC(R, i)	    (&(R)->ep_bd_desc[i])

#endif /* _LSINIC_REG_H_ */
