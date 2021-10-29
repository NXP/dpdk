/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _LS_INIC_H_
#define _LS_INIC_H_

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netdevice.h>

#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"

extern const char *lsinic_driver_name;
extern const char lsinic_driver_version[];

#undef INIC_RC_EP_DEBUG_ENABLE

#undef Q_VECTOR_TXRX_SEPARATE /* Tx Rx ring in separate q_vector */
#undef VF_VLAN_ENABLE
#define RC_RING_REG_SHADOW_ENABLE
#define LSINIC_NO_SKB_FRAG /* will not support SG and jumbo frame */

#define LSINIC_CMD_LOOP_NUM 10

/* Supported Rx Buffer Sizes */
#define LSINIC_RXBUFFER_256    256  /* Used for skb receive header */
#define LSINIC_RXBUFFER_2K    2048
#define LSINIC_RXBUFFER_3K    3072
#define LSINIC_RXBUFFER_4K    4096
#define LSINIC_MAX_RXBUFFER  16384  /* largest size for a single descriptor */

/*
 * NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN means we
 * reserve 64 more, and skb_shared_info adds an additional 320 bytes more,
 * this adds up to 448 bytes of extra data.
 *
 * Since netdev_alloc_skb now allocates a page fragment we can use a value
 * of 256 and the resultant skb will have a truesize of 960 or less.
 */
#define LSINIC_RX_HDR_SIZE LSINIC_RXBUFFER_256

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define LSINIC_RX_BUFFER_WRITE	16

#define LSINIC_MAX_VF_FUNCTIONS          64

/* TX/RX descriptor defines */
#define LSINIC_DEFAULT_TXD	LSINIC_BD_ENTRY_COUNT
#define LSINIC_DEFAULT_TX_WORK	LSINIC_BD_ENTRY_COUNT
#define LSINIC_MAX_TXD		LSINIC_BD_ENTRY_COUNT
#define LSINIC_MIN_TXD		64

#define LSINIC_DEFAULT_RXD	LSINIC_BD_ENTRY_COUNT
#define LSINIC_MAX_RXD		LSINIC_BD_ENTRY_COUNT
#define LSINIC_MIN_RXD		64

#define MAX_MSIX_VECTORS			8
#define MAX_MULTI_MSI_VECTORS			32
#define NON_Q_VECTORS				0

#define LSINIC_INTERRUPT_THRESHOLD 32
#define LSINIC_INTERRUPT_INTERVAL 100 /* 100ns */

#define LSINIC_WRITE_REG(reg, value) iowrite32((value), (reg))
#define LSINIC_READ_REG(reg) ioread32((reg))

/* Link speed */
typedef u32 lsinic_link_speed;
#define LSINIC_LINK_SPEED_UNKNOWN   0
#define LSINIC_LINK_SPEED_100_FULL  0x0008
#define LSINIC_LINK_SPEED_1GB_FULL  0x0020
#define LSINIC_LINK_SPEED_10GB_FULL 0x0080

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S) DIV_ROUND_UP((S), LSINIC_RC_XMIT_MAX_SIZE)
#define DESC_NEEDED ((MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE)) + 4)

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer
 */
struct lsinic_tx_buffer {
	struct lsinic_bd_desc *next_to_watch;
	struct sk_buff *skb;
	unsigned int bytecount;
	unsigned short gso_segs;
	__be16 protocol;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

struct lsinic_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	unsigned int len;
};

struct lsinic_queue_stats {
	u64 packets;
	u64 bytes;
};

struct lsinic_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
};

struct lsinic_rx_queue_stats {
	u64 rsc_count;
	u64 rsc_flush;
	u64 non_eop_descs;
	u64 alloc_rx_page_failed;
	u64 alloc_rx_buff_failed;
	u64 alloc_rx_dma_failed;
	u64 csum_err;
};

enum lsinic_ring_state_t {
	__LSINIC_TX_FDIR_INIT_DONE,
	__LSINIC_TX_DETECT_HANG,
	__LSINIC_HANG_CHECK_ARMED,
	__LSINIC_RX_RSC_ENABLED,
	__LSINIC_RX_CSUM_UDP_ZERO_ERR,
	__LSINIC_RX_FCOE,
};

#define check_for_tx_hang(ring) \
	test_bit(__LSINIC_TX_DETECT_HANG, &(ring)->state)
#define set_check_for_tx_hang(ring) \
	set_bit(__LSINIC_TX_DETECT_HANG, &(ring)->state)
#define clear_check_for_tx_hang(ring) \
	clear_bit(__LSINIC_TX_DETECT_HANG, &(ring)->state)
#define ring_is_rsc_enabled(ring) \
	test_bit(__LSINIC_RX_RSC_ENABLED, &(ring)->state)
#define set_ring_rsc_enabled(ring) \
	set_bit(__LSINIC_RX_RSC_ENABLED, &(ring)->state)
#define clear_ring_rsc_enabled(ring) \
	clear_bit(__LSINIC_RX_RSC_ENABLED, &(ring)->state)
struct lsinic_ring {
	struct lsinic_ring *next;	/* pointer to next ring in q_vector */
	struct lsinic_q_vector *q_vector; /* backpointer to host q_vector */
	struct net_device *netdev;	/* netdev ring belongs to */
	struct device *dev;		/* device for DMA mapping */
	union {
		struct lsinic_tx_buffer *tx_buffer_info;
		struct lsinic_rx_buffer *rx_buffer_info;
	};

	u16 count; /* amount of bd descriptors. MUST be a power of 2! */
	unsigned int size; /* bd desc length in bytes */
	unsigned int data_room; /* Max payload size in bytes */

	struct lsinic_bd_desc *ep_bd_desc; /* bd desc point to EP memory */
	struct lsinic_bd_desc *rc_bd_desc; /* bd desc point to RC(local) memory */
	dma_addr_t rc_bd_desc_dma; /* phys. address of rc_bd_desc */

	struct lsinic_ring_reg *ep_reg;	/* ring reg point to EP memory */
	struct lsinic_ring_reg *rc_reg;	/* ring reg point to RC memory */
	dma_addr_t rc_reg_dma;		/* phys. address of rc_reg */

	unsigned long state;
	u32 ep_sr;

	u8 queue_index; /* needed for multiqueue queue management */
	u8 reg_idx;			/* holds the special value that gets
					 * the hardware register offset
					 * associated with this ring, which is
					 * different for DCB and RSS modes
					 */
	u16 free_tail;
	union {
		u16 tx_avail_idx;
		u16 rx_used_idx;
	};

	struct lsinic_queue_stats stats;
	struct u64_stats_sync syncp;
	union {
		struct lsinic_tx_queue_stats tx_stats;
		struct lsinic_rx_queue_stats rx_stats;
	};
	struct lsinic_adapter *adapter;
	struct sk_buff **self_test_skb;
	u16 self_test_skb_total;
	u16 self_test_skb_count;
} ____cacheline_internodealigned_in_smp;

static inline unsigned int lsinic_rx_bufsz(struct lsinic_ring *ring)
{
	return ring->data_room;
}

static inline unsigned int lsinic_rx_pg_order(struct lsinic_ring *ring)
{
	return 0;
}
#define lsinic_rx_pg_size(_ring) (PAGE_SIZE << lsinic_rx_pg_order(_ring))

/* lsinic_test_staterr - tests bits in Rx descriptor status and error fields */
static inline u32 lsinic_test_staterr(struct lsinic_bd_desc *rc_bd_desc,
					  const u32 stat_err_bits)
{
	return (rc_bd_desc->len_cmd) & stat_err_bits;
}

static inline u32 lsinic_desc_len(struct lsinic_bd_desc *rc_bd_desc)
{
	return LSINIC_READ_REG(&rc_bd_desc->len_cmd) & LSINIC_BD_LEN_MASK;
}

struct lsinic_ring_container {
	struct lsinic_ring *ring;	/* pointer to linked list of rings */
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 work_limit;			/* total work allowed per interrupt */
	u8 count;			/* total number of rings in vector */
};

/* iterator for handling rings in ring container */
#define lsinic_for_each_ring(pos, head) \
	for (pos = (head).ring; pos != NULL; pos = pos->next)

#define MAX_RX_PACKET_BUFFERS ((adapter->flags & LSINIC_FLAG_DCB_ENABLED) \
				? 8 : 1)
#define MAX_TX_PACKET_BUFFERS MAX_RX_PACKET_BUFFERS

/* MAX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct lsinic_q_vector {
	struct lsinic_adapter *adapter;
#ifdef CONFIG_LSINIC_DCA
	int cpu;	    /* CPU for DCA */
#endif
	u16 v_idx; /* index of q_vector within array */
	struct lsinic_ring_container rx, tx;

	struct napi_struct napi;
	cpumask_t affinity_mask;
	int numa_node;
	struct rcu_head rcu;	/* to avoid race with update stats on free */
	char name[IFNAMSIZ + 9];

	struct task_struct *clean_thread; /* registering with packet driver */

	/* for dynamic allocation of rings associated with this q_vector */
	struct lsinic_ring ring[0] ____cacheline_internodealigned_in_smp;
};

#define MAX_Q_VECTORS 64

struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	/* u16 vf_mc_hashes[LSINIC_MAX_VF_MC_ENTRIES];
	 * u16 num_vf_mc_hashes;
	 * u16 default_vf_vlan_id;
	 * u16 vlans_enabled;
	 */
	bool clear_to_send;
	bool pf_set_mac;
	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
	u16 pf_qos;
	u16 tx_rate;
	u16 vlan_count;
	u8 spoofchk_enabled;
	unsigned int vf_api;
};

struct vi_vectors_info {
	u16 vec;
};

struct lsinic_adapter {
	/* OS defined structs */
	struct net_device *netdev;
	union {
		struct pci_dev *pdev;
		struct platform_device *platdev;
	};
	struct resource res[DEVICE_COUNT_RESOURCE];

	unsigned long state;

	u32 flags;
#define LSINIC_FLAG_MSI_CAPABLE                  (u32)(1 << 0)
#define LSINIC_FLAG_MSI_ENABLED                  (u32)(1 << 1)
#define LSINIC_FLAG_MSIX_CAPABLE                 (u32)(1 << 2)
#define LSINIC_FLAG_MSIX_ENABLED                 (u32)(1 << 3)
#define LSINIC_FLAG_RX_1BUF_CAPABLE              (u32)(1 << 4)
#define LSINIC_FLAG_RX_PS_CAPABLE                (u32)(1 << 5)
#define LSINIC_FLAG_RX_PS_ENABLED                (u32)(1 << 6)
#define LSINIC_FLAG_IN_NETPOLL                   (u32)(1 << 7)
#define LSINIC_FLAG_DCA_ENABLED                  (u32)(1 << 8)
#define LSINIC_FLAG_DCA_CAPABLE                  (u32)(1 << 9)
#define LSINIC_FLAG_IMIR_ENABLED                 (u32)(1 << 10)
#define LSINIC_FLAG_MQ_CAPABLE                   (u32)(1 << 11)
#define LSINIC_FLAG_DCB_ENABLED                  (u32)(1 << 12)
#define LSINIC_FLAG_VMDQ_CAPABLE                 (u32)(1 << 13)
#define LSINIC_FLAG_VMDQ_ENABLED                 (u32)(1 << 14)
#define LSINIC_FLAG_FAN_FAIL_CAPABLE             (u32)(1 << 15)
#define LSINIC_FLAG_NEED_LINK_UPDATE             (u32)(1 << 16)
#define LSINIC_FLAG_NEED_LINK_CONFIG             (u32)(1 << 17)
#define LSINIC_FLAG_FDIR_HASH_CAPABLE            (u32)(1 << 18)
#define LSINIC_FLAG_FDIR_PERFECT_CAPABLE         (u32)(1 << 19)
#define LSINIC_FLAG_FCOE_CAPABLE                 (u32)(1 << 20)
#define LSINIC_FLAG_FCOE_ENABLED                 (u32)(1 << 21)
#define LSINIC_FLAG_SRIOV_CAPABLE                (u32)(1 << 22)
#define LSINIC_FLAG_SRIOV_ENABLED                (u32)(1 << 23)
#define LSINIC_FLAG_THREAD_ENABLED		  (u32)(1 << 24)
#define LSINIC_FLAG_MUTIMSI_CAPABLE		  (u32)(1 << 25)
#define LSINIC_FLAG_MUTIMSI_ENABLED		  (u32)(1 << 26)

	u32 flags2;
#define LSINIC_FLAG2_RSC_CAPABLE                 (u32)(1 << 0)
#define LSINIC_FLAG2_RSC_ENABLED                 (u32)(1 << 1)
#define LSINIC_FLAG2_TEMP_SENSOR_CAPABLE         (u32)(1 << 2)
#define LSINIC_FLAG2_TEMP_SENSOR_EVENT           (u32)(1 << 3)
#define LSINIC_FLAG2_SEARCH_FOR_SFP              (u32)(1 << 4)
#define LSINIC_FLAG2_SFP_NEEDS_RESET             (u32)(1 << 5)
#define LSINIC_FLAG2_RESET_REQUESTED             (u32)(1 << 6)
#define LSINIC_FLAG2_FDIR_REQUIRES_REINIT        (u32)(1 << 7)
#define LSINIC_FLAG2_RSS_FIELD_IPV4_UDP		(u32)(1 << 8)
#define LSINIC_FLAG2_RSS_FIELD_IPV6_UDP		(u32)(1 << 9)
#define LSINIC_FLAG2_PTP_ENABLED			(u32)(1 << 10)
#define LSINIC_FLAG2_PTP_PPS_ENABLED		(u32)(1 << 11)
#define LSINIC_FLAG2_BRIDGE_MODE_VEB		(u32)(1 << 12)

	/* Tx fast path data */
	int num_tx_queues;
	u16 tx_itr_setting;
	u16 tx_work_limit;

	/* Rx fast path data */
	int num_rx_queues;
	u16 rx_itr_setting;

	/* TX */
	struct lsinic_ring *tx_ring[LSINIC_RING_MAX_COUNT]
						____cacheline_aligned_in_smp;

	u64 restart_queue;
	u64 lsc_int;
	u32 tx_timeout_count;

	/* RX */
	struct lsinic_ring *rx_ring[LSINIC_RING_MAX_COUNT];
	int num_rx_pools;		/* == num_rx_queues in 82598 */
	int num_rx_queues_per_pool;	/* 1 if 82598, can be many if 82599 */
	u64 hw_csum_rx_error;
	u64 hw_rx_no_dma_resources;
	u64 rsc_total_count;
	u64 rsc_total_flush;
	u64 non_eop_descs;
	u32 alloc_rx_page_failed;
	u32 alloc_rx_buff_failed;

	struct lsinic_q_vector *q_vector[MAX_Q_VECTORS];

	int num_q_vectors;	/* current number of q_vectors for device */
	int max_q_vectors;	/* true count of q_vectors for device */
	struct msix_entry *msix_entries;
	struct vi_vectors_info vectors_info[MAX_Q_VECTORS];

	void __iomem *hw_addr;
	void *bd_desc_base;
	u16 msg_enable;

	void *ep_ring_virt_base;  /* EP ring base */
	dma_addr_t ep_ring_phy_base;
	u64 ep_ring_win_size;

	void *rc_ring_virt_base;  /* RC ring shadow base */
	dma_addr_t rc_ring_phy_base;
	u64 rc_ring_win_size;

	void *rc_bd_desc_base;
	dma_addr_t rc_bd_desc_phy;

	u64 tx_busy;
	unsigned int tx_ring_bd_count;	/* MUST be a power of 2! */
	unsigned int rx_ring_bd_count;	/* MUST be a power of 2! */

	u32 link_speed;
	bool link_up;
	unsigned long link_check_timeout;

	struct timer_list service_timer;
	struct work_struct service_task;

	u16 bd_number;

	u32 interrupt_event;

	/* SR-IOV */
	DECLARE_BITMAP(active_vfs, LSINIC_MAX_VF_FUNCTIONS);
	unsigned int num_vfs;
	struct vf_data_storage *vfinfo;
	int vf_rate_link_speed;

	u32 timer_event_accumulator;
	u32 vferr_refcount;
	struct kobject *info_kobj;

	u8 default_up;
};


enum lsinic_state_t {
	__LSINIC_TESTING,
	__LSINIC_RESETTING,
	__LSINIC_DOWN,
	__LSINIC_SERVICE_SCHED,
	__LSINIC_IN_SFP_INIT,
};

struct lsinic_cb {
	union {				/* Union defining head/tail partner */
		struct sk_buff *head;
		struct sk_buff *tail;
	};
	dma_addr_t dma;
	u16 append_cnt;
	bool page_released;
};
#define LSINIC_CB(skb) ((struct lsinic_cb *)(skb)->cb)

static inline struct netdev_queue *
txring_txq(const struct lsinic_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}

#define e_dev_info(format, arg...) \
	dev_info(&adapter->pdev->dev, format, ## arg)
#define e_dev_warn(format, arg...) \
	dev_warn(&adapter->pdev->dev, format, ## arg)
#define e_dev_err(format, arg...) \
	dev_err(&adapter->pdev->dev, format, ## arg)
#define e_dev_notice(format, arg...) \
	dev_notice(&adapter->pdev->dev, format, ## arg)
#define e_info(msglvl, format, arg...) \
	netif_info(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_err(msglvl, format, arg...) \
	netif_err(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_warn(msglvl, format, arg...) \
	netif_warn(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_crit(msglvl, format, arg...) \
	netif_crit(adapter, msglvl, adapter->netdev, format, ## arg)

/*************************************/
/* Driver State Bits */
#define NET_STATE_STOPPED	 0
#define NET_STATE_RUNNING	 1
#define NET_STATE_INITED	 2

#define PH_MAX_MTU		4000
#define PH_MTU			2000
#define RX_NAPI_WEIGHT	    64

#define INIC_HOST_BUF_SIZE (0x100000)
#define DPAA2_ETH_TX_QUEUES 8
#define PCI_DEVID_LSINIC_LS20XXDEV 0x0953
#define PCI_VENDOR_ID_FREESCALE 0x1957
#define PCI_CLASS_ETHERNET_CONTROLLER 0x020000
#define MAX_MSIX_NUM (2)
#define INIC_NETDEV_NUM (1)

#define VRING_REG_OFFSET (32)

#endif /* _LS_INIC_H_ */
