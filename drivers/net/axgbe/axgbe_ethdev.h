/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.
 *   Copyright(c) 2018 Synopsys, Inc. All rights reserved.
 */

#ifndef RTE_ETH_AXGBE_H_
#define RTE_ETH_AXGBE_H_

#include <rte_mempool.h>
#include <rte_lcore.h>
#include "axgbe_common.h"

#define AXGBE_MAX_DMA_CHANNELS		16
#define AXGBE_MAX_QUEUES		16
#define AXGBE_PRIORITY_QUEUES		8
#define AXGBE_DMA_STOP_TIMEOUT		1

/* DMA cache settings - Outer sharable, write-back, write-allocate */
#define AXGBE_DMA_OS_AXDOMAIN		0x2
#define AXGBE_DMA_OS_ARCACHE		0xb
#define AXGBE_DMA_OS_AWCACHE		0xf

/* DMA cache settings - System, no caches used */
#define AXGBE_DMA_SYS_AXDOMAIN		0x3
#define AXGBE_DMA_SYS_ARCACHE		0x0
#define AXGBE_DMA_SYS_AWCACHE		0x0

/* PCI BAR mapping */
#define AXGBE_AXGMAC_BAR		0
#define AXGBE_XPCS_BAR			1
#define AXGBE_MAC_PROP_OFFSET		0x1d000
#define AXGBE_I2C_CTRL_OFFSET		0x1e000

/* PCI clock frequencies */
#define AXGBE_V2_DMA_CLOCK_FREQ		500000000
#define AXGBE_V2_PTP_CLOCK_FREQ		125000000

#define AXGMAC_FIFO_MIN_ALLOC		2048
#define AXGMAC_FIFO_UNIT		256
#define AXGMAC_FIFO_ALIGN(_x)                            \
	(((_x) + AXGMAC_FIFO_UNIT - 1) & ~(XGMAC_FIFO_UNIT - 1))
#define AXGMAC_FIFO_FC_OFF		2048
#define AXGMAC_FIFO_FC_MIN		4096

#define AXGBE_TC_MIN_QUANTUM		10

/* Flow control queue count */
#define AXGMAC_MAX_FLOW_CONTROL_QUEUES	8

/* Flow control threshold units */
#define AXGMAC_FLOW_CONTROL_UNIT	512
#define AXGMAC_FLOW_CONTROL_ALIGN(_x)				\
	(((_x) + AXGMAC_FLOW_CONTROL_UNIT - 1) &		\
	~(AXGMAC_FLOW_CONTROL_UNIT - 1))
#define AXGMAC_FLOW_CONTROL_VALUE(_x)				\
	(((_x) < 1024) ? 0 : ((_x) / AXGMAC_FLOW_CONTROL_UNIT) - 2)
#define AXGMAC_FLOW_CONTROL_MAX		33280

/* Maximum MAC address hash table size (256 bits = 8 bytes) */
#define AXGBE_MAC_HASH_TABLE_SIZE	8

/* Receive Side Scaling */
#define AXGBE_RSS_OFFLOAD  ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP)

#define AXGBE_RSS_HASH_KEY_SIZE		40
#define AXGBE_RSS_MAX_TABLE_SIZE	256
#define AXGBE_RSS_LOOKUP_TABLE_TYPE	0
#define AXGBE_RSS_HASH_KEY_TYPE		1

/* Auto-negotiation */
#define AXGBE_AN_MS_TIMEOUT		500
#define AXGBE_LINK_TIMEOUT		5

#define AXGBE_SGMII_AN_LINK_STATUS	BIT(1)
#define AXGBE_SGMII_AN_LINK_SPEED	(BIT(2) | BIT(3))
#define AXGBE_SGMII_AN_LINK_SPEED_100	0x04
#define AXGBE_SGMII_AN_LINK_SPEED_1000	0x08
#define AXGBE_SGMII_AN_LINK_DUPLEX	BIT(4)

/* ECC correctable error notification window (seconds) */
#define AXGBE_ECC_LIMIT			60

/* MDIO port types */
#define AXGMAC_MAX_C22_PORT		3

/* Helper macro for descriptor handling
 *  Always use AXGBE_GET_DESC_DATA to access the descriptor data
 *  since the index is free-running and needs to be and-ed
 *  with the descriptor count value of the ring to index to
 *  the proper descriptor data.
 */
#define AXGBE_GET_DESC_DATA(_ring, _idx)			\
	((_ring)->rdata +					\
	 ((_idx) & ((_ring)->rdesc_count - 1)))

struct axgbe_port;

enum axgbe_state {
	AXGBE_DOWN,
	AXGBE_LINK_INIT,
	AXGBE_LINK_ERR,
	AXGBE_STOPPED,
};

enum axgbe_int {
	AXGMAC_INT_DMA_CH_SR_TI,
	AXGMAC_INT_DMA_CH_SR_TPS,
	AXGMAC_INT_DMA_CH_SR_TBU,
	AXGMAC_INT_DMA_CH_SR_RI,
	AXGMAC_INT_DMA_CH_SR_RBU,
	AXGMAC_INT_DMA_CH_SR_RPS,
	AXGMAC_INT_DMA_CH_SR_TI_RI,
	AXGMAC_INT_DMA_CH_SR_FBE,
	AXGMAC_INT_DMA_ALL,
};

enum axgbe_int_state {
	AXGMAC_INT_STATE_SAVE,
	AXGMAC_INT_STATE_RESTORE,
};

enum axgbe_ecc_sec {
	AXGBE_ECC_SEC_TX,
	AXGBE_ECC_SEC_RX,
	AXGBE_ECC_SEC_DESC,
};

enum axgbe_speed {
	AXGBE_SPEED_1000 = 0,
	AXGBE_SPEED_2500,
	AXGBE_SPEED_10000,
	AXGBE_SPEEDS,
};

enum axgbe_xpcs_access {
	AXGBE_XPCS_ACCESS_V1 = 0,
	AXGBE_XPCS_ACCESS_V2,
};

enum axgbe_an_mode {
	AXGBE_AN_MODE_CL73 = 0,
	AXGBE_AN_MODE_CL73_REDRV,
	AXGBE_AN_MODE_CL37,
	AXGBE_AN_MODE_CL37_SGMII,
	AXGBE_AN_MODE_NONE,
};

enum axgbe_an {
	AXGBE_AN_READY = 0,
	AXGBE_AN_PAGE_RECEIVED,
	AXGBE_AN_INCOMPAT_LINK,
	AXGBE_AN_COMPLETE,
	AXGBE_AN_NO_LINK,
	AXGBE_AN_ERROR,
};

enum axgbe_rx {
	AXGBE_RX_BPA = 0,
	AXGBE_RX_XNP,
	AXGBE_RX_COMPLETE,
	AXGBE_RX_ERROR,
};

enum axgbe_mode {
	AXGBE_MODE_KX_1000 = 0,
	AXGBE_MODE_KX_2500,
	AXGBE_MODE_KR,
	AXGBE_MODE_X,
	AXGBE_MODE_SGMII_100,
	AXGBE_MODE_SGMII_1000,
	AXGBE_MODE_SFI,
	AXGBE_MODE_UNKNOWN,
};

enum axgbe_speedset {
	AXGBE_SPEEDSET_1000_10000 = 0,
	AXGBE_SPEEDSET_2500_10000,
};

enum axgbe_mdio_mode {
	AXGBE_MDIO_MODE_NONE = 0,
	AXGBE_MDIO_MODE_CL22,
	AXGBE_MDIO_MODE_CL45,
};

struct axgbe_hw_if {
	void (*config_flow_control)(struct axgbe_port *);
	int (*config_rx_mode)(struct axgbe_port *);

	int (*init)(struct axgbe_port *);

	int (*read_mmd_regs)(struct axgbe_port *, int, int);
	void (*write_mmd_regs)(struct axgbe_port *, int, int, int);
	int (*set_speed)(struct axgbe_port *, int);

	int (*set_ext_mii_mode)(struct axgbe_port *, unsigned int,
				enum axgbe_mdio_mode);
	int (*read_ext_mii_regs)(struct axgbe_port *, int, int);
	int (*write_ext_mii_regs)(struct axgbe_port *, int, int, uint16_t);

	/* For FLOW ctrl */
	int (*config_tx_flow_control)(struct axgbe_port *);
	int (*config_rx_flow_control)(struct axgbe_port *);

	int (*exit)(struct axgbe_port *);
};

/* This structure contains flags that indicate what hardware features
 * or configurations are present in the device.
 */
struct axgbe_hw_features {
	/* HW Version */
	unsigned int version;

	/* HW Feature Register0 */
	unsigned int gmii;		/* 1000 Mbps support */
	unsigned int vlhash;		/* VLAN Hash Filter */
	unsigned int sma;		/* SMA(MDIO) Interface */
	unsigned int rwk;		/* PMT remote wake-up packet */
	unsigned int mgk;		/* PMT magic packet */
	unsigned int mmc;		/* RMON module */
	unsigned int aoe;		/* ARP Offload */
	unsigned int ts;		/* IEEE 1588-2008 Advanced Timestamp */
	unsigned int eee;		/* Energy Efficient Ethernet */
	unsigned int tx_coe;		/* Tx Checksum Offload */
	unsigned int rx_coe;		/* Rx Checksum Offload */
	unsigned int addn_mac;		/* Additional MAC Addresses */
	unsigned int ts_src;		/* Timestamp Source */
	unsigned int sa_vlan_ins;	/* Source Address or VLAN Insertion */

	/* HW Feature Register1 */
	unsigned int rx_fifo_size;	/* MTL Receive FIFO Size */
	unsigned int tx_fifo_size;	/* MTL Transmit FIFO Size */
	unsigned int adv_ts_hi;		/* Advance Timestamping High Word */
	unsigned int dma_width;		/* DMA width */
	unsigned int dcb;		/* DCB Feature */
	unsigned int sph;		/* Split Header Feature */
	unsigned int tso;		/* TCP Segmentation Offload */
	unsigned int dma_debug;		/* DMA Debug Registers */
	unsigned int rss;		/* Receive Side Scaling */
	unsigned int tc_cnt;		/* Number of Traffic Classes */
	unsigned int hash_table_size;	/* Hash Table Size */
	unsigned int l3l4_filter_num;	/* Number of L3-L4 Filters */

	/* HW Feature Register2 */
	unsigned int rx_q_cnt;		/* Number of MTL Receive Queues */
	unsigned int tx_q_cnt;		/* Number of MTL Transmit Queues */
	unsigned int rx_ch_cnt;		/* Number of DMA Receive Channels */
	unsigned int tx_ch_cnt;		/* Number of DMA Transmit Channels */
	unsigned int pps_out_num;	/* Number of PPS outputs */
	unsigned int aux_snap_num;	/* Number of Aux snapshot inputs */
};

struct axgbe_version_data {
	enum axgbe_xpcs_access xpcs_access;
	unsigned int mmc_64bit;
	unsigned int tx_max_fifo_size;
	unsigned int rx_max_fifo_size;
	unsigned int tx_tstamp_workaround;
	unsigned int ecc_support;
	unsigned int i2c_support;
};

/*
 * Structure to store private data for each port.
 */
struct axgbe_port {
	/*  Ethdev where port belongs*/
	struct rte_eth_dev *eth_dev;
	/* Pci dev info */
	const struct rte_pci_device *pci_dev;
	/* Version related data */
	struct axgbe_version_data *vdata;

	/* AXGMAC/XPCS related mmio registers */
	uint64_t xgmac_regs;	/* AXGMAC CSRs */
	uint64_t xpcs_regs;	/* XPCS MMD registers */
	uint64_t xprop_regs;	/* AXGBE property registers */
	uint64_t xi2c_regs;	/* AXGBE I2C CSRs */

	/* XPCS indirect addressing lock */
	unsigned int xpcs_window_def_reg;
	unsigned int xpcs_window_sel_reg;
	unsigned int xpcs_window;
	unsigned int xpcs_window_size;
	unsigned int xpcs_window_mask;

	/* Flags representing axgbe_state */
	unsigned long dev_state;

	struct axgbe_hw_if hw_if;

	/* AXI DMA settings */
	unsigned int coherent;
	unsigned int axdomain;
	unsigned int arcache;
	unsigned int awcache;

	unsigned int tx_max_channel_count;
	unsigned int rx_max_channel_count;
	unsigned int channel_count;
	unsigned int tx_ring_count;
	unsigned int tx_desc_count;
	unsigned int rx_ring_count;
	unsigned int rx_desc_count;

	unsigned int tx_max_q_count;
	unsigned int rx_max_q_count;
	unsigned int tx_q_count;
	unsigned int rx_q_count;

	/* Tx/Rx common settings */
	unsigned int pblx8;

	/* Tx settings */
	unsigned int tx_sf_mode;
	unsigned int tx_threshold;
	unsigned int tx_pbl;
	unsigned int tx_osp_mode;
	unsigned int tx_max_fifo_size;

	/* Rx settings */
	unsigned int rx_sf_mode;
	unsigned int rx_threshold;
	unsigned int rx_pbl;
	unsigned int rx_max_fifo_size;
	unsigned int rx_buf_size;

	/* Device clocks */
	unsigned long sysclk_rate;
	unsigned long ptpclk_rate;

	/* Keeps track of power mode */
	unsigned int power_down;

	/* Current PHY settings */
	int phy_link;
	int phy_speed;

	pthread_mutex_t xpcs_mutex;
	pthread_mutex_t i2c_mutex;
	pthread_mutex_t an_mutex;
	pthread_mutex_t phy_mutex;

	/* Flow control settings */
	unsigned int pause_autoneg;
	unsigned int tx_pause;
	unsigned int rx_pause;
	unsigned int rx_rfa[AXGBE_MAX_QUEUES];
	unsigned int rx_rfd[AXGBE_MAX_QUEUES];
	unsigned int fifo;

	/* Receive Side Scaling settings */
	u8 rss_key[AXGBE_RSS_HASH_KEY_SIZE];
	uint32_t rss_table[AXGBE_RSS_MAX_TABLE_SIZE];
	uint32_t rss_options;
	int rss_enable;

	/* Hardware features of the device */
	struct axgbe_hw_features hw_feat;

	struct ether_addr mac_addr;
};

void axgbe_init_function_ptrs_dev(struct axgbe_hw_if *hw_if);
#endif /* RTE_ETH_AXGBE_H_ */
