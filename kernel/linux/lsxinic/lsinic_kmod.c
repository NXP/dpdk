/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */
#pragma GCC diagnostic ignored "-Winline"

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/cpumask.h>

#include <linux/string.h>
#include <linux/mdio.h>
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/checksum.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/u64_stats_sync.h>

#include <linux/platform_device.h>

#include "lsinic_kmod.h"
#include "print_buffer.h"
#include "lsinic_kcompat.h"
#include "lsinic_ethtool.h"

#include "lsxinic_self_test_data.h"

const char lsinic_driver_version[] = "1.0";

const char *lsinic_driver_name = "lsinic_driver";
static unsigned int max_vfs;
module_param(max_vfs, uint, S_IRUGO);
MODULE_PARM_DESC(max_vfs,
		" Maximum number of virtual functions to\n"
		"\t\t\t allocate per physical function - default is\n"
		"\t\t\t zero and maximum value is 64.");

static unsigned int pcie_perf_tx;
module_param(pcie_perf_tx, uint, S_IRUGO);
static unsigned int pcie_perf_rx;
module_param(pcie_perf_rx, uint, S_IRUGO);

static unsigned int lsinic_thread_mode;
module_param(lsinic_thread_mode, uint, S_IRUGO);
static unsigned int lsinic_loopback;
module_param(lsinic_loopback, uint, S_IRUGO);
static unsigned int lsinic_sim;
module_param(lsinic_sim, uint, S_IRUGO);
static unsigned int lsinic_self_test;
module_param(lsinic_self_test, uint, S_IRUGO);
static unsigned int lsinic_self_test_len = 1024;
module_param(lsinic_self_test_len, uint, S_IRUGO);
static unsigned int lsinic_sim_multi_pci;
module_param(lsinic_sim_multi_pci, uint, S_IRUGO);

#define SIM_MAX_DEV_NB 16
static struct platform_device *sim_dev[SIM_MAX_DEV_NB];

static bool mmsi_flag;
module_param(mmsi_flag, bool, S_IRUGO);
MODULE_PARM_DESC(mmsi_flag, "Enable muti-msi interrupt");

static char lsinic_default_device_descr[] =
			      "Layerscape (R) 10 Gigabit Network Connection";

#undef PRINT_TX
#ifdef PRINT_TX
#define printk_tx(format, ...) pr_info(format, ## __VA_ARGS__)
#else
#define printk_tx(format, ...) do {} while (0)
#endif

#undef PRINT_RX
#ifdef PRINT_RX
#define printk_rx(format, ...) pr_info(format, ## __VA_ARGS__)
#else
#define printk_rx(format, ...) do {} while (0)
#endif

#undef PRINT_DEV
#ifdef PRINT_DEV
#define printk_dev(format, ...) pr_info(format, ## __VA_ARGS__)
#else
#define printk_dev(format, ...) do {} while (0)
#endif

#undef PRINT_INIT
#ifdef PRINT_INIT
#define printk_init(format, ...) pr_info(format, ## __VA_ARGS__)
#else
#define printk_init(format, ...) do {} while (0)
#endif

#define lsinic_assert(p) do {	\
	if (!(p)) {	\
		printk(KERN_CRIT "BUG at %s:%d assert(%s)\n",	\
			__FILE__, __LINE__, #p);			\
		BUG();	\
	}		\
} while (0)

#define TEST_COUNT	1000

#ifndef ioread64
static inline u64 inic_read_reg64(u64 *reg)
{
	u64 __v = *reg;

	rmb();
	return __v;
}
#define ioread64(c) inic_read_reg64(c)
#endif

#ifndef iowrite64
static inline void inic_write_reg64(u64 *reg, u64 data)
{
	wmb();
	*reg = data;
}
#define iowrite64(c, d) inic_write_reg64(c, d)
#endif

static void lsinic_get_macaddr(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	int i;
	u8 mac_addr[6];
	u32 mac_high = LSINIC_READ_REG(&eth_reg->macaddrh);
	u32 mac_low = LSINIC_READ_REG(&eth_reg->macaddrl);

	for (i = 0; i < 4; i++)
		mac_addr[5 - i] = (u8)(mac_low >> (i * 8));

	for (i = 0; i < 2; i++)
		mac_addr[1 - i] = (u8)(mac_high >> (i * 8));

	memcpy(netdev->dev_addr, (char *)&mac_addr, netdev->addr_len);
	memcpy(netdev->perm_addr, (char *)&mac_addr, netdev->addr_len);
}

static int
lsinic_set_netdev(struct lsinic_adapter *adapter,
	enum PCIDEV_COMMAND cmd)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	int wait_loop = LSINIC_CMD_LOOP_NUM;
	u32 cmd_status;

	switch (cmd) {
	case PCIDEV_COMMAND_START:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_UP);
		break;
	case PCIDEV_COMMAND_STOP:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_DOWN);
		break;
	case PCIDEV_COMMAND_REMOVE:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_REMOVED);
		break;
	case PCIDEV_COMMAND_INIT:
		{
			if (pcie_perf_tx) {
				u32 size =
					adapter->num_tx_queues *
					LSINIC_QDMA_TEST_PKT_MAX_LEN *
					adapter->tx_ring_bd_count;

				if (size <= KMALLOC_MAX_SIZE) {
					void *va_tx = kmalloc(size, GFP_KERNEL);
					dma_addr_t pa_tx = __pa(va_tx);

					printk(KERN_WARNING
						"PCIe Tx perf enable host addr: 0x%lx, size: %d\n",
						(unsigned long)pa_tx, size);
					LSINIC_WRITE_REG(&rcs_reg->txdma_regl,
						pa_tx & DMA_BIT_MASK(32));
					LSINIC_WRITE_REG(&rcs_reg->txdma_regh,
						pa_tx >> 32);
				}
			}

			if (pcie_perf_rx) {
				u32 size = adapter->num_rx_queues *
						LSINIC_QDMA_TEST_PKT_MAX_LEN *
						adapter->rx_ring_bd_count;

				if (size <= KMALLOC_MAX_SIZE) {
					void *va_rx = kmalloc(size, GFP_KERNEL);
					dma_addr_t pa_rx = __pa(va_rx);

					printk(KERN_WARNING
						"PCIe RX perf enable host addr: 0x%lx, size: %d\n",
						(unsigned long)pa_rx, size);
					LSINIC_WRITE_REG(&rcs_reg->rxdma_regl,
						pa_rx & DMA_BIT_MASK(32));
					LSINIC_WRITE_REG(&rcs_reg->rxdma_regh,
						pa_rx >> 32);
				}
			}
		}
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_INITED);
		break;
	default:
		break;
	}

	LSINIC_WRITE_REG(&reg->command, cmd);
	do {
		msleep(500);
		cmd_status = LSINIC_READ_REG(&reg->command);
	} while (--wait_loop && (cmd_status != PCIDEV_COMMAND_IDLE));

	if (!wait_loop) {
		e_err(drv, "Command-%d: failed to get right status!\n", cmd);
		return PCIDEV_RESULT_FAILED;
	}

	return LSINIC_READ_REG(&reg->result);
}

static void
lsinic_disable_rx_queue(struct lsinic_adapter *adapter,
	struct lsinic_ring *ring)
{
	u32 rxdctl;
	struct lsinic_ring_reg *ring_reg = ring->ep_reg;

	if (ring->rc_reg)
		rxdctl = ring->rc_reg->cr;
	else
		rxdctl = LSINIC_READ_REG(&ring_reg->cr);

	rxdctl &= ~LSINIC_CR_ENABLE;
	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, rxdctl);
	if (ring->rc_reg)
		LSINIC_WRITE_REG(&ring->rc_reg->cr, rxdctl);
}

static void
lsinic_msix_disable(struct lsinic_adapter *adapter, u16 idx)
{
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	if (idx >= 32) {
		pr_info("lsinic_msix_disable hw:%p idx:%d ERROR\n",
			adapter->hw_addr, idx);
		return;
	}

	LSINIC_WRITE_REG(&rcs_reg->msix_mask[idx], 1);
}

static void
lsinic_msix_enable(struct lsinic_adapter *adapter, u16 idx)
{
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	if (idx >= 32) {
		pr_info("%s hw:%p idx:%d ERROR\n",
			__func__, adapter->hw_addr, idx);
		return;
	}

	LSINIC_WRITE_REG(&rcs_reg->msix_mask[idx], 0);
}

static void
lsinic_synchronize_irq(struct lsinic_adapter *adapter,
	unsigned int irq,
	int vector)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	synchronize_irq(pci_irq_vector(adapter->pdev, vector));
#else
	synchronize_irq(irq);
#endif
}

static void
lsinic_unmap_and_free_tx_resource(struct lsinic_ring *ring,
	struct lsinic_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len),
			       DMA_TO_DEVICE);
	}
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
}

/* lsinic_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static inline void lsinic_irq_disable(struct lsinic_adapter *adapter)
{
	int i;

	if (adapter->flags & LSINIC_FLAG_THREAD_ENABLED)
		return;

	/* disable the EP MSIX interrupt */
	for (i = 0; i < adapter->num_q_vectors; i++)
		lsinic_msix_disable(adapter, i);

	if (adapter->flags & LSINIC_FLAG_MUTIMSI_ENABLED) {
		int vector;

		for (vector = 0; vector < adapter->num_q_vectors; vector++)
			lsinic_synchronize_irq(adapter,
				adapter->vectors_info[vector].vec,
				vector);

		if (NON_Q_VECTORS)
			lsinic_synchronize_irq(adapter,
				adapter->vectors_info[vector].vec,
				vector);
	} else if (adapter->flags & LSINIC_FLAG_MSIX_ENABLED) {
		int vector;

		for (vector = 0; vector < adapter->num_q_vectors; vector++)
			lsinic_synchronize_irq(adapter,
				adapter->msix_entries[vector].vector,
				vector);

		if (NON_Q_VECTORS)
			lsinic_synchronize_irq(adapter,
				adapter->msix_entries[vector].vector,
				vector);
	} else {
		lsinic_synchronize_irq(adapter, adapter->pdev->irq, 0);
	}
}

static void lsinic_clean_thread_stop(struct lsinic_q_vector *q_vector)
{
	if (q_vector->clean_thread) {
		kthread_stop(q_vector->clean_thread);
		q_vector->clean_thread = NULL;
	}
}

static void lsinic_clean_thread_stop_all(struct lsinic_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++)
		lsinic_clean_thread_stop(adapter->q_vector[q_idx]);
}

static void lsinic_napi_disable_all(struct lsinic_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++)
		napi_disable(&adapter->q_vector[q_idx]->napi);
}

static void
lsinic_disable_tx_queue(struct lsinic_adapter *adapter,
	struct lsinic_ring *ring)
{
	u32 txdctl;

	if (ring->rc_reg)
		txdctl = LSINIC_READ_REG(&ring->rc_reg->cr);
	else
		txdctl = LSINIC_READ_REG(&ring->ep_reg->cr);

	txdctl &= ~LSINIC_CR_ENABLE;
	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring->ep_reg->cr, txdctl);
	if (ring->rc_reg)
		LSINIC_WRITE_REG(&ring->rc_reg->cr, txdctl);
}

/* lsinic_clean_rx_ring - Free Rx Buffers per Queue
 * @rx_ring: ring to free buffers from
 **/
static void lsinic_clean_rx_ring(struct lsinic_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	unsigned long size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_buffer_info)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct lsinic_rx_buffer *rx_buffer;

		rx_buffer = &rx_ring->rx_buffer_info[i];
		if (rx_buffer->skb) {
			struct sk_buff *skb = rx_buffer->skb;

			if (LSINIC_CB(skb)->page_released) {
				dma_unmap_page(dev,
					       LSINIC_CB(skb)->dma,
					       lsinic_rx_bufsz(rx_ring),
					       DMA_FROM_DEVICE);
				LSINIC_CB(skb)->page_released = false;
			}
			dev_kfree_skb(skb);
		}
		rx_buffer->skb = NULL;
		if (rx_buffer->dma)
			dma_unmap_single(dev, rx_buffer->dma,
					rx_buffer->len,
					DMA_FROM_DEVICE);
		rx_buffer->dma = 0;
		if (rx_buffer->page)
			__free_pages(rx_buffer->page,
				     lsinic_rx_pg_order(rx_ring));
		rx_buffer->page = NULL;
	}

	size = sizeof(struct lsinic_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	if (rx_ring->rc_bd_desc)
		memset(rx_ring->rc_bd_desc, 0, rx_ring->size);

	if (rx_ring->rc_reg)
		memset(rx_ring->rc_reg, 0, sizeof(*rx_ring->rc_reg));
}

/* lsinic_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void lsinic_clean_all_rx_rings(struct lsinic_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		lsinic_clean_rx_ring(adapter->rx_ring[i]);
}

/* lsinic_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
static void lsinic_clean_tx_ring(struct lsinic_ring *tx_ring)
{
	struct lsinic_tx_buffer *tx_buffer_info;
	unsigned long size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_buffer_info)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		lsinic_unmap_and_free_tx_resource(tx_ring, tx_buffer_info);
	}

	netdev_tx_reset_queue(txring_txq(tx_ring));

	size = sizeof(struct lsinic_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	if (tx_ring->rc_bd_desc)
		memset(tx_ring->rc_bd_desc, 0, tx_ring->size);

	if (tx_ring->rc_reg)
		memset(tx_ring->rc_reg, 0, sizeof(*tx_ring->rc_reg));
}

/* lsinic_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void lsinic_clean_all_tx_rings(struct lsinic_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		lsinic_clean_tx_ring(adapter->tx_ring[i]);
}

static void lsinic_down(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int i;

	/* signal that we are down to the interrupt handler */
	set_bit(__LSINIC_DOWN, &adapter->state);

	/* disable the netdev receive */
	lsinic_set_netdev(adapter, PCIDEV_COMMAND_STOP);

	/* disable all enabled rx queues */
	for (i = 0; i < adapter->num_rx_queues; i++)
		/* this call also flushes the previous write */
		lsinic_disable_rx_queue(adapter, adapter->rx_ring[i]);

	usleep_range(10000, 20000);

	netif_tx_stop_all_queues(netdev);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	lsinic_irq_disable(adapter);

	if (lsinic_thread_mode)
		lsinic_clean_thread_stop_all(adapter);
	else
		lsinic_napi_disable_all(adapter);

	adapter->flags2 &= ~(LSINIC_FLAG2_FDIR_REQUIRES_REINIT |
			     LSINIC_FLAG2_RESET_REQUESTED);
	adapter->flags &= ~LSINIC_FLAG_NEED_LINK_UPDATE;

	del_timer_sync(&adapter->service_timer);

	/* disable all tx queues */
	for (i = 0; i < adapter->num_tx_queues; i++)
		lsinic_disable_tx_queue(adapter, adapter->tx_ring[i]);

	lsinic_clean_all_tx_rings(adapter);
	lsinic_clean_all_rx_rings(adapter);

}

static void lsinic_reset_queue(struct lsinic_ring *ring)
{
	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring->ep_reg->cr, LSINIC_CR_DISABLE);
	LSINIC_WRITE_REG(&ring->ep_reg->pir, 0);
	LSINIC_WRITE_REG(&ring->ep_reg->cir, 0);

	/* MSIX setting*/
	LSINIC_WRITE_REG(&ring->ep_reg->icr,
		ring->q_vector->v_idx << LSINIC_INT_VECTOR_SHIFT |
		LSINIC_INTERRUPT_THRESHOLD);

	LSINIC_WRITE_REG(&ring->ep_reg->iir, LSINIC_INTERRUPT_INTERVAL);

	if (ring->rc_reg) {
		ring->rc_reg->pir = 0;
		ring->rc_reg->cir = 0;
	}

	if (ring->rc_bd_desc) {
		LSINIC_WRITE_REG(&ring->ep_reg->r_descl,
			ring->rc_bd_desc_dma & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&ring->ep_reg->r_desch,
			ring->rc_bd_desc_dma >> 32);
	}
}

/* lsinic_configure_tx_ring - Configure 8259x Tx ring after Reset
 * @adapter: board private structure
 * @ring: structure containing ring specific data
 *
 * Configure the Tx descriptor ring after a reset.
 **/
static void
lsinic_configure_tx_ring(struct lsinic_adapter *adapter,
	struct lsinic_ring *ring)
{
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	u8 reg_idx = ring->reg_idx;
	u32 txdctl = LSINIC_CR_ENABLE | LSINIC_CR_BUSY;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->tx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->tx_ring[reg_idx];

	ring->ep_reg = ring_reg;

	if (adapter->rc_ring_virt_base)
		ring->rc_reg = rc_ring_reg;
	else
		ring->rc_reg = NULL;

	lsinic_reset_queue(ring);

	/* enable queue */
	LSINIC_WRITE_REG(&ring_reg->cr, txdctl);
}

/* lsinic_configure_tx - Configure 8259x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void lsinic_configure_tx(struct lsinic_adapter *adapter)
{
	u32 i;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++)
		lsinic_configure_tx_ring(adapter, adapter->tx_ring[i]);
}

static int lxsnic_rx_bd_init_skb(struct lsinic_ring *rx_queue,
	u16 idx)
{
	struct lsinic_bd_desc *ep_rx_desc, *rc_rx_desc;
	struct sk_buff *skb;
	struct lsinic_rx_buffer *rx_buffer;

	rc_rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
	ep_rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);
	skb = netdev_alloc_skb_ip_align(rx_queue->netdev,
			rx_queue->data_room);
	if (unlikely(!skb)) {
		rx_queue->rx_stats.alloc_rx_buff_failed++;
		return -ENOMEM;
	}
	rx_buffer = &rx_queue->rx_buffer_info[idx];
	rx_buffer->skb = skb;
	rx_buffer->len = rx_queue->data_room;
	rx_buffer->page_offset = 0;
	rx_buffer->dma = dma_map_single(rx_queue->dev, skb->data,
					rx_buffer->len, DMA_FROM_DEVICE);
	if (dma_mapping_error(rx_queue->dev, rx_buffer->dma)) {
		dev_err(rx_queue->dev, "init Rx DMA map failed, %d\n", idx);
		rx_queue->rx_stats.alloc_rx_dma_failed++;
		msleep(1000);
		return -ENOMEM;
	}

	rc_rx_desc->pkt_addr = rx_buffer->dma;
#ifndef LSINIC_BD_CTX_IDX_USED
	rc_rx_desc->sw_ctx = (uint64_t)rx_buffer;
	rc_rx_desc->bd_status = RING_BD_READY;

	memcpy(ep_rx_desc, rc_rx_desc, offsetof(struct lsinic_bd_desc, desc));
	wmb();
	rc_rx_desc->sw_ctx = ioread64(&ep_rx_desc->sw_ctx);
	ep_rx_desc->desc = rc_rx_desc->desc;
#else
	rc_rx_desc->bd_status = ((uint32_t)idx) << LSINIC_BD_CTX_IDX_SHIFT |
							RING_BD_READY;
	mem_cp128b_atomic((uint8_t *)ep_rx_desc, (uint8_t *)rc_rx_desc);
#endif

#ifdef INIC_RC_EP_DEBUG_ENABLE
	LSINIC_WRITE_REG(&rx_queue->ep_reg->pir,
		(idx + 1) & (rx_queue->count - 1));
#endif

	return 0;
}

static void
lsinic_configure_rx_ring(struct lsinic_adapter *adapter,
	struct lsinic_ring *ring)
{
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	u8 reg_idx = ring->reg_idx;
	u32 rxdctl, i;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->rx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->rx_ring[reg_idx];

	ring->ep_reg = ring_reg;

	if (adapter->rc_ring_virt_base)
		ring->rc_reg = rc_ring_reg;
	else
		ring->rc_reg = NULL;

	lsinic_reset_queue(ring);

	/* enable receive descriptor ring */
	rxdctl = LSINIC_CR_ENABLE | LSINIC_CR_BUSY;
	LSINIC_WRITE_REG(&ring_reg->cr, rxdctl);
	for (i = 0; i < ring->count; i++)
		lxsnic_rx_bd_init_skb(ring, i);
}

/* lsinic_configure_rx - Configure 8259x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void lsinic_configure_rx(struct lsinic_adapter *adapter)
{
	int i;

	/*
	 * Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++)
		lsinic_configure_rx_ring(adapter, adapter->rx_ring[i]);
}

static int lsinic_configure(struct lsinic_adapter *adapter)
{
	lsinic_configure_tx(adapter);
	lsinic_configure_rx(adapter);

	return 0;
}

static int lsinic_clean_rings_thread(void *data);

static int
lsinic_clean_thread_creat(struct lsinic_q_vector *q_vector)
{
	int cpu_idx = 1;

	q_vector->clean_thread = kthread_create(lsinic_clean_rings_thread,
						q_vector, "%s",
						q_vector->name);

	if (IS_ERR(q_vector->clean_thread)) {
		pr_info("Failed to start %s clean thread.\n", q_vector->name);
		q_vector->clean_thread = NULL;
		return -EINVAL;
	}

	/* Bind the thread to CPU. */
	cpu_idx = q_vector->v_idx + 1;
	if ((cpu_idx % num_possible_cpus()) == 0)
		cpu_idx = 1;
	kthread_bind(q_vector->clean_thread, cpu_idx);

	return 0;
}

static void lsinic_clean_thread_creat_all(struct lsinic_adapter *adapter)
{
	int q_idx, ti = 0, ri = 0;
	struct lsinic_q_vector *q_vector;
	struct net_device *netdev = adapter->netdev;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];

		lsinic_msix_disable(adapter, q_vector->v_idx);

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "TxRx", ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "rx", ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "tx", ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}

		lsinic_clean_thread_creat(q_vector);
	}
}

static int lsinic_init_tx_bd(struct lsinic_adapter *adapter)
{
	u32 i, j, bd_status, count;
	struct lsinic_ring *tx_ring;
	struct lsinic_bd_desc *rc_tx_desc;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		tx_ring = adapter->tx_ring[i];
		for (j = 0; j < tx_ring->count; j++) {
			rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, j);
			bd_status = rc_tx_desc->bd_status;
			count = 0;
			while ((bd_status & RING_BD_STATUS_MASK) !=
				RING_BD_READY) {
				msleep(1);
				bd_status = rc_tx_desc->bd_status;
				rmb();
				count++;
				if (count > 1000) {
					e_dev_err("TXQ%d:BD%d invalid status 0x%08x\n",
						tx_ring->queue_index,
						j, bd_status);
					return -1;
				}
			}
			lsinic_assert((bd_status & RING_BD_STATUS_MASK) ==
				RING_BD_READY);
#ifdef LSINIC_BD_CTX_IDX_USED
			rc_tx_desc->bd_status &=
				(~LSINIC_BD_CTX_IDX_MASK);
			rc_tx_desc->bd_status |=
				(((u32)j) << LSINIC_BD_CTX_IDX_SHIFT);
#else
			rc_tx_desc->sw_ctx =
				(uint64_t)&tx_ring->tx_buffer_info[j];
#endif
		}
	}

	return 0;
}

static void lsinic_napi_enable_all(struct lsinic_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		napi_enable(&adapter->q_vector[q_idx]->napi);
		lsinic_msix_enable(adapter, adapter->q_vector[q_idx]->v_idx);

		/* If all buffers were filled by other side
		 * before we napi_enabled,
		 * we won't get another interrupt,
		 * so process any outstanding packets now.
		 * We synchronize against interrupts via
		 * NAPI_STATE_SCHED.
		 */
		if (napi_schedule_prep(&adapter->q_vector[q_idx]->napi))
			__napi_schedule(&adapter->q_vector[q_idx]->napi);
	}
}

static void lsinic_clean_thread_run_all(struct lsinic_adapter *adapter)
{
	int q_idx;
	struct lsinic_q_vector *q_vector;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];

		wake_up_process(q_vector->clean_thread);
	}
}

static int lsinic_up_complete(struct lsinic_adapter *adapter)
{
	int ret;

	/* Need to clear the DOWN status */
	clear_bit(__LSINIC_DOWN, &adapter->state);

	if (lsinic_thread_mode)
		lsinic_clean_thread_creat_all(adapter);
	else
		lsinic_napi_enable_all(adapter);

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_START);

	lsinic_get_macaddr(adapter);

	ret = lsinic_init_tx_bd(adapter);
	if (ret)
		return ret;

	/* enable transmits */
	netif_tx_start_all_queues(adapter->netdev);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem
	 */
	adapter->flags |= LSINIC_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	mod_timer(&adapter->service_timer, jiffies);
	if (lsinic_thread_mode)
		lsinic_clean_thread_run_all(adapter);

	return 0;
}

static void lsinic_up(struct lsinic_adapter *adapter)
{
	/* hardware has been reset, we need to reload some things */
	lsinic_configure(adapter);

	lsinic_up_complete(adapter);
}

static void lsinic_reinit_locked(struct lsinic_adapter *adapter)
{
	WARN_ON(in_interrupt());
	/* put off any impending NetWatchDogTimeout */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	adapter->netdev->trans_start = jiffies;
#endif
	lsinic_down(adapter);
	/*
	 * If SR-IOV enabled then wait a bit before bringing the adapter
	 * back up to give the VFs time to respond to the reset.  The
	 * two second wait is based upon the watchdog timer cycle in
	 * the VF driver.
	 */
	if (adapter->flags & LSINIC_FLAG_SRIOV_ENABLED)
		msleep(2000);
	lsinic_up(adapter);
	clear_bit(__LSINIC_RESETTING, &adapter->state);
}

static inline u32 lsinic_get_pending(u32 head, u32 tail, u32 count)
{
	if (head != tail)
		return (head < tail) ?
			tail - head : (tail + count - head);
	return 0;
}

/**
 * lsinic_watchdog_update_link - update the link status
 * @adapter: pointer to the device adapter structure
 * @link_speed: pointer to a u32 to store the link_speed
 **/
static void lsinic_watchdog_update_link(struct lsinic_adapter *adapter)
{
	u32 ep_state = 0;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	struct lsinic_dev_reg *dev_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	int i;

	if (!(adapter->flags & LSINIC_FLAG_NEED_LINK_UPDATE))
		return;

	ep_state = LSINIC_READ_REG(&dev_reg->ep_state);
	if (ep_state != LSINIC_DEV_UP) {
		link_up = false;
		link_speed = 0;
	} else {
		link_up = true;
		link_speed = LSINIC_LINK_SPEED_10GB_FULL;
	}

	if (adapter->link_up != link_up) {
		if (link_up) {
			printk(KERN_WARNING "inic: ep link up\n");
		} else {
			lsinic_reinit_locked(adapter);
			printk(KERN_WARNING "inic: ep link down\n");
		}
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;
	adapter->vf_rate_link_speed = link_speed;
	for (i = 0; i < adapter->num_vfs; i++)
		adapter->vfinfo[i].tx_rate = link_speed;
}

/**
 * lsinic_watchdog_link_is_up - update netif_carrier status and
 *                             print link up message
 * @adapter: pointer to the device adapter structure
 **/
static void lsinic_watchdog_link_is_up(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u32 link_speed = adapter->link_speed;
	bool flow_rx, flow_tx;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;
	flow_tx = false;
	flow_rx = false;

	e_info(drv, "LSINIC Link is Up %s, Flow Control: %s\n",
	       (link_speed == LSINIC_LINK_SPEED_10GB_FULL ?
	       "10 Gbps" :
	       (link_speed == LSINIC_LINK_SPEED_1GB_FULL ?
	       "1 Gbps" :
	       (link_speed == LSINIC_LINK_SPEED_100_FULL ?
	       "100 Mbps" :
	       "unknown speed"))),
	       ((flow_rx && flow_tx) ? "RX/TX" :
	       (flow_rx ? "RX" :
	       (flow_tx ? "TX" : "None"))));

	netif_carrier_on(netdev);
}

/**
 * lsinic_watchdog_link_is_down - update netif_carrier status and
 *                               print link down message
 * @adapter: pointer to the adapter structure
 **/
static void lsinic_watchdog_link_is_down(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->link_up = false;
	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	netif_carrier_off(netdev);
}

/**
 * lsinic_watchdog_subtask - check and bring link up
 * @adapter: pointer to the device adapter structure
 **/
static void lsinic_watchdog_subtask(struct lsinic_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__LSINIC_DOWN, &adapter->state) ||
	    test_bit(__LSINIC_RESETTING, &adapter->state))
		return;

	lsinic_watchdog_update_link(adapter);

	if (adapter->link_up)
		lsinic_watchdog_link_is_up(adapter);
	else
		lsinic_watchdog_link_is_down(adapter);
}

static void lsinic_service_event_schedule(struct lsinic_adapter *adapter)
{
	if (!test_bit(__LSINIC_DOWN, &adapter->state) &&
	    !test_and_set_bit(__LSINIC_SERVICE_SCHED, &adapter->state))
		schedule_work(&adapter->service_task);
}

/**
 * lsinic_service_timer - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
#ifdef HAVE_TIMER_SETUP
static void lsinic_service_timer(struct timer_list *t)
{
	struct lsinic_adapter *adapter = from_timer(adapter, t, service_timer);
	unsigned long next_event_offset;
	bool ready = true;

	/* poll faster when waiting for link */
	if (adapter->flags & LSINIC_FLAG_NEED_LINK_UPDATE)
		next_event_offset = HZ / 10;
	else
		next_event_offset = HZ * 2;

	/* Reset the timer */
	mod_timer(&adapter->service_timer, next_event_offset + jiffies);

	if (ready)
		lsinic_service_event_schedule(adapter);
}
#else
static void lsinic_service_timer(unsigned long data)
{
	struct lsinic_adapter *adapter = (struct lsinic_adapter *)data;
	unsigned long next_event_offset;
	bool ready = true;

	/* poll faster when waiting for link */
	if (adapter->flags & LSINIC_FLAG_NEED_LINK_UPDATE)
		next_event_offset = HZ / 10;
	else
		next_event_offset = HZ * 2;

	/* Reset the timer */
	mod_timer(&adapter->service_timer, next_event_offset + jiffies);

	if (ready)
		lsinic_service_event_schedule(adapter);
}
#endif

static void lsinic_service_event_complete(struct lsinic_adapter *adapter)
{
	WARN_ON(!test_bit(__LSINIC_SERVICE_SCHED, &adapter->state));

	clear_bit(__LSINIC_SERVICE_SCHED, &adapter->state);
}

/**
 * lsinic_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
static void lsinic_service_task(struct work_struct *work)
{
	struct lsinic_adapter *adapter = container_of(work,
						     struct lsinic_adapter,
						     service_task);

	lsinic_watchdog_subtask(adapter);

	lsinic_service_event_complete(adapter);
}

/* lsinic_sw_init - Initialize (struct lsinic_adapter)
 * @adapter: board private structure to initialize
 *
 * lsinic_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int lsinic_sw_init(struct lsinic_adapter *adapter)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	u32 max_data_room = LSINIC_READ_REG(&eth_reg->max_data_room);

	if (max_data_room > PAGE_SIZE) {
		printk_init("max_data_room(%d) > PAGE_SIZE(%d)\n",
			max_data_room, (u32)PAGE_SIZE);
		return -EINVAL;
	}

	adapter->max_q_vectors = MAX_Q_VECTORS;

	/* set default work limits */
	adapter->tx_work_limit = LSINIC_DEFAULT_TX_WORK;

	/* get ring setting */
	adapter->tx_ring_bd_count = LSINIC_READ_REG(&eth_reg->tx_entry_num);
	adapter->rx_ring_bd_count = LSINIC_READ_REG(&eth_reg->rx_entry_num);
	adapter->num_tx_queues = LSINIC_READ_REG(&eth_reg->tx_ring_num);
	adapter->num_rx_queues = LSINIC_READ_REG(&eth_reg->rx_ring_num);

	set_bit(__LSINIC_DOWN, &adapter->state);

	return 0;
}

/**
 * lsinic_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void lsinic_free_tx_resources(struct lsinic_ring *tx_ring)
{

	lsinic_clean_tx_ring(tx_ring);

	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

	tx_ring->rc_bd_desc = NULL;
	tx_ring->rc_reg = NULL;
}

/**
 * lsinic_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
static void lsinic_free_all_tx_resources(struct lsinic_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		lsinic_free_tx_resources(adapter->tx_ring[i]);
}

/**
 * lsinic_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void lsinic_free_rx_resources(struct lsinic_ring *rx_ring)
{
	lsinic_clean_rx_ring(rx_ring);

	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

	rx_ring->rc_bd_desc = NULL;
	rx_ring->rc_reg = NULL;
}

/**
 * lsinic_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
static void lsinic_free_all_rx_resources(struct lsinic_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		lsinic_free_rx_resources(adapter->rx_ring[i]);
}

/**
 * lsinic_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int lsinic_setup_tx_resources(struct lsinic_adapter *adapter, int i)
{
	struct lsinic_ring *tx_ring = adapter->tx_ring[i];
	struct device *dev = tx_ring->dev;
	int size;

	size = sizeof(struct lsinic_tx_buffer) * tx_ring->count;

	tx_ring->tx_buffer_info = vzalloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;

	tx_ring->adapter = adapter;
	tx_ring->data_room = PAGE_SIZE;
	tx_ring->data_room -= LSINIC_RC_TX_DATA_ROOM_OVERHEAD;
	tx_ring->ep_bd_desc = (struct lsinic_bd_desc *)
		((u8 *)adapter->bd_desc_base + LSINIC_TX_BD_OFFSET +
		i * LSINIC_RING_SIZE);

	tx_ring->tx_avail_idx = 0;

#ifdef RC_RING_REG_SHADOW_ENABLE
	tx_ring->size = tx_ring->count * sizeof(struct lsinic_bd_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);
	tx_ring->rc_bd_desc = (struct lsinic_bd_desc *)
		((char *)adapter->rc_bd_desc_base +
		LSINIC_TX_BD_OFFSET +
		i * LSINIC_RING_SIZE);
	tx_ring->rc_bd_desc_dma = ((u64)adapter->rc_bd_desc_phy) +
	(u64)((u64)tx_ring->rc_bd_desc - (u64)adapter->rc_bd_desc_base);

	printk_init("RC tx phy_base:%lX, queue:%d bd_virt:%p bd_phy:%lX\n",
			adapter->ep_ring_phy_base, i, tx_ring->rc_bd_desc,
			tx_ring->rc_bd_desc_dma);

	tx_ring->rc_reg = NULL;
#else
	tx_ring->rc_bd_desc = NULL;
	tx_ring->rc_reg = NULL;
#endif

	return 0;

err:
	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	tx_ring->rc_bd_desc = NULL;
	tx_ring->rc_bd_desc_dma = 0;
	dev_err(dev, "Unable to allocate memory for the Tx descriptor ring\n");

	return -ENOMEM;
}

/**
 * lsinic_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int lsinic_setup_all_tx_resources(struct lsinic_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = lsinic_setup_tx_resources(adapter, i);
		if (!err)
			continue;

		e_err(probe, "Allocation for Tx Queue %u failed\n", i);
		goto err_setup_tx;
	}

	return 0;
err_setup_tx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		lsinic_free_tx_resources(adapter->tx_ring[i]);
	return err;
}

/**
 * lsinic_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int lsinic_setup_rx_resources(struct lsinic_adapter *adapter, int i)
{
	struct lsinic_ring *rx_ring = adapter->rx_ring[i];
	struct device *dev = rx_ring->dev;
	int size;

	size = sizeof(struct lsinic_rx_buffer) * rx_ring->count;

	rx_ring->rx_buffer_info = vzalloc(size);
	if (!rx_ring->rx_buffer_info)
		goto err;

	rx_ring->adapter = adapter;
	rx_ring->data_room = PAGE_SIZE;
	rx_ring->data_room -= LSINIC_RC_TX_DATA_ROOM_OVERHEAD;
	rx_ring->ep_bd_desc = (struct lsinic_bd_desc *)
		((u8 *)adapter->bd_desc_base +
		LSINIC_RX_BD_OFFSET +
		i * LSINIC_RING_SIZE);
	rx_ring->rx_used_idx = 0;

#ifdef RC_RING_REG_SHADOW_ENABLE
	rx_ring->size = rx_ring->count * sizeof(struct lsinic_bd_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);
	rx_ring->rc_bd_desc = (struct lsinic_bd_desc *)((char *)
			adapter->rc_bd_desc_base + LSINIC_RX_BD_OFFSET +
			i * LSINIC_RING_SIZE);
	rx_ring->rc_bd_desc_dma = ((u64)adapter->rc_bd_desc_phy) +
	(u64)((u64)rx_ring->rc_bd_desc - (u64)adapter->rc_bd_desc_base);

	printk_init("RC rx phy_base:%lX, queue:%d bd_virt:%p bd_phy:%lX\n",
			adapter->ep_ring_phy_base, i, rx_ring->rc_bd_desc,
			rx_ring->rc_bd_desc_dma);
#else
	rx_ring->rc_bd_desc = NULL;
#endif

	printk_dev("%s %d: desc: %p 0x%llx [0x%x]. ep_bd_addr = 0x%p\n",
		   __func__, __LINE__,
		   rx_ring->rc_bd_desc, rx_ring->rc_bd_desc_dma,
		   rx_ring->size, rx_ring->ep_bd_desc);

	return 0;

err:
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;
	rx_ring->rc_bd_desc = NULL;
	rx_ring->rc_bd_desc_dma = 0;
	dev_err(dev, "Unable to allocate memory for the Rx descriptor ring\n");
	return -ENOMEM;
}

/**
 * lsinic_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int lsinic_setup_all_rx_resources(struct lsinic_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = lsinic_setup_rx_resources(adapter, i);
		if (!err)
			continue;

		e_err(probe, "Allocation for Rx Queue %u failed\n", i);
		goto err_setup_rx;
	}

		return 0;
err_setup_rx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		lsinic_free_rx_resources(adapter->rx_ring[i]);
	return err;
}

#ifndef LSINIC_NO_SKB_FRAG
static bool lsinic_alloc_mapped_page(struct lsinic_ring *rx_ring,
				    struct lsinic_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page))
		return true;

	/* alloc new page for storage */
	page = __skb_alloc_pages(GFP_ATOMIC | __GFP_COLD | __GFP_COMP,
				 bi->skb, lsinic_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page(rx_ring->dev, page, 0,
			   lsinic_rx_pg_size(rx_ring), DMA_FROM_DEVICE);

	/*
	 * if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, lsinic_rx_pg_order(rx_ring));
		bi->page = NULL;

		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = 0;

	return true;
}
#endif

static irqreturn_t lsinic_msix_other(int irq, void *data)
{
	pr_info("%s: irq = %d, data = 0x%p\n", __func__, irq, data);

	return IRQ_HANDLED;
}

static struct sk_buff *
lsinic_fetch_rx_buffer(struct lsinic_ring *rx_ring,
			struct lsinic_bd_desc *rx_desc)
{
	struct sk_buff *skb;
	unsigned int size;
	struct lsinic_rx_buffer *rx_buffer;
#ifdef LSINIC_BD_CTX_IDX_USED
	u16 used_idx;

	used_idx = lsinic_bd_ctx_idx(rx_desc->bd_status);

	rx_buffer = &rx_ring->rx_buffer_info[used_idx];
#else
	rx_buffer = (struct lsinic_rx_buffer *)rx_desc->sw_ctx;
#endif
	size = lsinic_desc_len(rx_desc);
	skb = rx_buffer->skb;
	if (rx_desc->bd_status & RING_BD_ADDR_CHECK)
		lsinic_assert(rx_buffer->dma == rx_desc->pkt_addr);

	/* we are not reusing the buffer so unmap it */
	dma_unmap_single(rx_ring->dev, rx_buffer->dma,
			rx_buffer->len,
			DMA_FROM_DEVICE);
	/* clear contents of buffer_info */
	rx_buffer->skb = NULL;
	rx_buffer->dma = 0;
	rx_buffer->page = NULL;

	/* end copybreak code */
	skb_put(skb, size);

	return skb;
}

static int
lsinic_fetch_merge_rx_buffers(struct lsinic_ring *rx_ring,
			       struct lsinic_bd_desc *rx_desc,
			       struct sk_buff **skb_arry)
{
	struct sk_buff *skb;
	struct lsinic_mg_header *mgd;
	void *data;
	int total_size, count = 0, i, len, offset = 0;
	int align_off = 0, mg_header_size = 0;
	struct lsinic_rx_buffer *rx_buffer;
#ifdef LSINIC_BD_CTX_IDX_USED
	u16 used_idx;

	used_idx = lsinic_bd_ctx_idx(rx_desc->bd_status);

	rx_buffer = &rx_ring->rx_buffer_info[used_idx];
#else
	rx_buffer = (struct lsinic_rx_buffer *)rx_desc->sw_ctx;
#endif
	skb = rx_buffer->skb;
	if (rx_desc->bd_status & RING_BD_ADDR_CHECK)
		lsinic_assert(rx_buffer->dma == rx_desc->pkt_addr);

	/* we are not reusing the buffer so unmap it */
	dma_unmap_single(rx_ring->dev, rx_buffer->dma,
			rx_buffer->len,
			DMA_FROM_DEVICE);
	/* clear contents of buffer_info */
	rx_buffer->skb = NULL;
	rx_buffer->dma = 0;
	rx_buffer->page = NULL;

	prefetch(skb->data);

	total_size = lsinic_desc_len(rx_desc);
	if (total_size > rx_ring->data_room) {
		pr_info("total_size(%d) > max size(%d)\n",
			total_size, rx_ring->data_room);
		return 0;
	}

	count = ((rx_desc->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
			LSINIC_BD_MG_NUM_SHIFT) + 1;

	data = skb->data;
	printk_rx("get merge packets size=%d count=%d data=%p\n",
		  total_size, count, data);

	mgd = data;
	len = lsinic_mg_entry_len(mgd->len_cmd[0]);

	/* Check the value correctness */
	if ((offset + len) > total_size)
		return 0;

	mg_header_size = sizeof(struct lsinic_mg_header);
	align_off = lsinic_mg_entry_align_offset(mgd->len_cmd[0]);
	offset = mg_header_size + len + align_off;

	skb_reserve(skb, mg_header_size);
	skb_put(skb, len);
	skb_arry[0] = skb;
	printk_rx("MGD0: len=%d va:%p next mgd offset=%d\n",
		   len, (void *)((char *)data + mg_header_size), offset);

	for (i = 1; i < count; i++) {
		len = lsinic_mg_entry_len(mgd->len_cmd[i]);
		align_off = lsinic_mg_entry_align_offset(mgd->len_cmd[i]);

		/* Check the value correctness */
		if ((offset + len - mg_header_size) > total_size)
			break;

		/* allocate a skb to store the frags */
		skb = netdev_alloc_skb_ip_align(rx_ring->netdev,
						ALIGN(len, sizeof(long)));
		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			break;
		}

		/*
		 * we will be copying header into skb->data in
		 * pskb_may_pull so it is in our interest to prefetch
		 * it now to avoid a possible cache miss
		 */
		prefetchw(skb->data);
		memcpy(__skb_put(skb, len),
			(void *)((char *)data + offset), len);
		skb_arry[i] = skb;

		offset += len + align_off;
		printk_rx("MGD%d: len=%d va:%p next mgd offset=%d\n",
			i, len,
			(void *)((char *)data + offset - len - align_off),
			offset);
	}

	return i;
}

/**
 * lsinic_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool lsinic_is_non_eop(struct lsinic_ring *rx_ring,
			       struct lsinic_bd_desc *rx_desc,
			       struct sk_buff *skb)
{
	u16 i;

	i = rx_ring->rx_used_idx & (rx_ring->count - 1);
	/*
	 *rx_desc = LSINIC_RC_BD_DESC(rx_ring, i);
	 */
	rx_ring->rx_used_idx++;

	/*
	 * TODO need to check the logic here
	 * seem the original EOP can't work
	 * when using packed ring.
	 */
	/*
	 *i = rx_ring->rx_used_idx & (rx_ring->count - 1);
	 *rx_desc = LSINIC_RC_BD_DESC(rx_ring, i);
	 *ntc = rx_desc->index;
	 *printk_rx("%s rx_desc%d: len_cmd=0x%x\n",
		  __func__, ntc, rx_desc->len_cmd);

	 */

/*
 *#ifdef RC_RING_REG_SHADOW_ENABLE
 *        prefetch(LSINIC_RC_BD_DESC(rx_ring, ntc));
 *#endif
 */

	/* if we are the last buffer then there is nothing else to do */
	if (likely(lsinic_test_staterr(rx_desc, LSINIC_BD_CMD_EOP)))
		return false;

	/* place skb in next buffer to be received */
	/*
	 *rx_ring->rx_buffer_info[ntc].skb = skb;
	 *rx_ring->rx_stats.non_eop_descs++;
	 */

	return true;
}

static void lsinic_set_rsc_gso_size(struct lsinic_ring *ring,
				   struct sk_buff *skb)
{
	u16 hdr_len = skb_headlen(skb);

	/* set gso_size to avoid messing up TCP MSS */
	skb_shinfo(skb)->gso_size = DIV_ROUND_UP((skb->len - hdr_len),
						 LSINIC_CB(skb)->append_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
}

static void lsinic_update_rsc_stats(struct lsinic_ring *rx_ring,
				   struct sk_buff *skb)
{
	/* if append_cnt is 0 then frame is not RSC */
	if (!LSINIC_CB(skb)->append_cnt)
		return;

	rx_ring->rx_stats.rsc_count += LSINIC_CB(skb)->append_cnt;
	rx_ring->rx_stats.rsc_flush++;

	lsinic_set_rsc_gso_size(rx_ring, skb);

	/* gso_size is computed using append_cnt so always clear it last */
	LSINIC_CB(skb)->append_cnt = 0;
}

static void lsinic_update_vlan(struct lsinic_ring *rx_ring,
				struct sk_buff *skb)
{
#ifdef VF_VLAN_ENABLE
	u32 ret;
	u16 vlan, vlan_remote;
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(rx_ring->adapter->hw_addr,
			LSINIC_ETH_REG_OFFSET);

	ret = vlan_get_tag(skb, &vlan);
	vlan_remote = LSINIC_READ_REG(&eth_reg->vlan);

	printk_rx("%s: ret=%d, vlan=%d, vlan_remote=%d\n",
		  __func__, ret, vlan, vlan_remote);

	if (vlan != vlan_remote && vlan_remote)
		skb_put(skb, 0);
	else if (!ret && (vlan == vlan_remote)) {
		size = size - VLAN_HLEN;
		header = ETH_ALEN * 2;
		while (header) {
			header--;
			memcpy(skb->data + header + VLAN_HLEN,
			       skb->data + header, 1);
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan);
		}
		skb->data += VLAN_HLEN;
	}
#endif
}

/**
 * lsinic_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, timestamp, protocol, and
 * other fields within the skb.
 **/
static void lsinic_process_skb_fields(struct lsinic_ring *rx_ring,
				       struct sk_buff *skb)
{
	struct net_device *dev = rx_ring->netdev;

	lsinic_update_rsc_stats(rx_ring, skb);

	lsinic_update_vlan(rx_ring, skb);

	skb_record_rx_queue(skb, rx_ring->queue_index);

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = eth_type_trans(skb, dev);
}

static void lsinic_rx_skb(struct lsinic_q_vector *q_vector,
			 struct sk_buff *skb)
{
	struct lsinic_adapter *adapter = q_vector->adapter;

	if (adapter->flags & LSINIC_FLAG_THREAD_ENABLED)
		netif_receive_skb(skb);
	else if (!(adapter->flags & LSINIC_FLAG_IN_NETPOLL))
		napi_gro_receive(&q_vector->napi, skb);
	else
		netif_rx(skb);
}

netdev_tx_t lsinic_xmit_frame_ring(struct sk_buff *skb,
			  struct lsinic_adapter *adapter,
			  struct lsinic_ring *tx_ring);

static void lsinic_loopback_rx_tx(struct sk_buff *skb,
				  struct lsinic_q_vector *q_vector,
				  struct lsinic_ring *rx_ring)
{
	struct iphdr *iph;
	int tmpip, tx_idx;
	netdev_tx_t ret;
	struct lsinic_adapter *adapter;

	iph = (struct iphdr *)(skb->data + 14);
	tmpip = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmpip;

	adapter = q_vector->adapter;
	tx_idx = rx_ring->reg_idx % adapter->num_tx_queues;

	ret = lsinic_xmit_frame_ring(skb, adapter,
				    adapter->tx_ring[tx_idx]);
	if (ret == NETDEV_TX_BUSY)
		dev_kfree_skb_any(skb);
}

static inline int lsinic_rx_bd_skb_set(struct lsinic_ring *rx_queue,
		uint16_t idx, struct sk_buff *skb, dma_addr_t dma)
{
	struct lsinic_bd_desc *ep_rx_desc, *rc_rx_desc;
	struct lsinic_rx_buffer *rx_buffer;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t rxbuf_idx;
#endif

	rc_rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
	ep_rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);

#ifdef LSINIC_BD_CTX_IDX_USED
	rxbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
	rx_buffer = &rx_queue->rx_buffer_info[rxbuf_idx];
#else
	rx_buffer = (struct lsinic_rx_buffer *)rc_rx_desc->sw_ctx;
#endif

	if (rx_buffer->dma)
		dma_unmap_single(rx_queue->dev, rx_buffer->dma,
			rx_queue->data_room,
			DMA_FROM_DEVICE);
	rx_buffer->dma = dma;

	rc_rx_desc->pkt_addr = rx_buffer->dma;
	rx_buffer->skb = skb;
#ifdef LSINIC_BD_CTX_IDX_USED
	rc_rx_desc->bd_status = RING_BD_READY |
					(rxbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	mem_cp128b_atomic((uint8_t *)ep_rx_desc, (uint8_t *)rc_rx_desc);
#else
	rc_rx_desc->sw_ctx = (uint64_t)rx_buffer;
	rc_rx_desc->bd_status = RING_BD_READY;

	memcpy(ep_rx_desc, rc_rx_desc, offsetof(struct lsinic_bd_desc, desc));
	wmb();
	rc_rx_desc->sw_ctx = ioread64(&ep_rx_desc->sw_ctx);
	ep_rx_desc->desc = rc_rx_desc->desc;
#endif
	return 0;
}

static void lsinic_tx_self_gen_pkt(u8 *payload)
{
	struct ethhdr *eth_header;
	struct iphdr *ipv4_header;
	u64 rand;

	get_random_bytes(&rand, sizeof(u64));
	memcpy(payload, s_self_test_xmit_data_base,
			sizeof(s_self_test_xmit_data_base));
	eth_header = (struct ethhdr *)payload;
	ipv4_header = (struct iphdr *)(eth_header + 1);
	ipv4_header->saddr = (__be32)(rand & 0xffffffff);
	ipv4_header->daddr = (__be32)((rand >> 32) & 0xffffffff);
	ipv4_header->check = 0;
	ipv4_header->check = ip_fast_csum(ipv4_header, sizeof(struct iphdr));
}

static int lsinic_tx_self_test_skb_alloc(struct lsinic_ring *tx_ring)
{
	int alloc_count = 64;
	int i;
	dma_addr_t new_dma;
	struct sk_buff *new_skb;

	tx_ring->self_test_skb = vmalloc(sizeof(void *) * alloc_count);
	for (i = 0; i < alloc_count; i++) {
		new_skb = netdev_alloc_skb_ip_align(tx_ring->netdev,
					tx_ring->data_room);
		if (unlikely(new_skb == NULL))
			break;

		new_dma = dma_map_single(tx_ring->dev, new_skb->data,
					tx_ring->data_room,
					DMA_FROM_DEVICE);
		if (dma_mapping_error(tx_ring->dev, new_dma)) {
			dev_err(tx_ring->dev, "Self test TX DMA map failed\n");
			dev_kfree_skb_any(new_skb);
			break;
		}
		lsinic_tx_self_gen_pkt(new_skb->data);
		skb_put(new_skb, lsinic_self_test_len);
		tx_ring->self_test_skb[i] = new_skb;
		tx_ring->self_test_skb_count++;
		tx_ring->self_test_skb_total++;
	}

	return tx_ring->self_test_skb_total;
}

static struct sk_buff *lsinic_tx_self_test_skb_get(struct lsinic_ring *tx_ring)
{
	struct sk_buff *skb = NULL;

	if (tx_ring->self_test_skb_count) {
		skb = tx_ring->self_test_skb[tx_ring->self_test_skb_count - 1];
		tx_ring->self_test_skb_count--;
	}

	return skb;
}

static int lsinic_tx_self_test_skb_put(
		struct lsinic_ring *tx_ring, struct sk_buff *skb)
{
	lsinic_assert(tx_ring->self_test_skb_count <
		tx_ring->self_test_skb_total);

	tx_ring->self_test_skb[tx_ring->self_test_skb_count] = skb;
	tx_ring->self_test_skb_count++;
	return 0;
}

static bool lsinic_clean_tx(struct lsinic_ring *tx_ring)
{
	struct lsinic_q_vector *q_vector = tx_ring->q_vector;
	struct lsinic_bd_desc *rc_tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = q_vector->tx.work_limit;
	u16 i = tx_ring->free_tail & (tx_ring->count - 1);
#ifdef LSINIC_BD_CTX_IDX_USED
	u16 txe_idx;
#endif
	u32 status;
	struct lsinic_tx_buffer *first = NULL;
	struct sk_buff *last_skb;
	bool complete = false;

	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, i);

	status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

	rmb();

	do {
		if (status != RING_BD_HW_COMPLETE) {
			complete = true;
			break;
		}

#ifdef LSINIC_BD_CTX_IDX_USED
		txe_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		first = &tx_ring->tx_buffer_info[txe_idx];
#else
		first = (struct lsinic_tx_buffer *)rc_tx_desc->sw_ctx;
#endif
		lsinic_assert(first && first->skb);
		if (rc_tx_desc->bd_status & RING_BD_ADDR_CHECK)
			lsinic_assert(first->dma == rc_tx_desc->pkt_addr);
		last_skb = first->skb;
		if (lsinic_self_test)
			lsinic_tx_self_test_skb_put(tx_ring, last_skb);
		else
			dev_kfree_skb_any(last_skb);

		dma_unmap_single(tx_ring->dev,
					dma_unmap_addr(first, dma),
					dma_unmap_len(first, len),
					DMA_TO_DEVICE);

		first->skb = NULL;
		dma_unmap_len_set(first, len, 0);
		total_bytes += first->bytecount;
		total_packets++;

#ifdef LSINIC_BD_CTX_IDX_USED
		rc_tx_desc->bd_status &= (~RING_BD_STATUS_MASK);
		rc_tx_desc->bd_status |= RING_BD_READY;
#else
		rc_tx_desc->bd_status = RING_BD_READY;
#endif

		tx_ring->free_tail++;
		i = tx_ring->free_tail & (tx_ring->count - 1);

		budget--;
		rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, i);

		status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

		rmb();
	} while (likely(budget));

	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	q_vector->tx.total_bytes += total_bytes;
	q_vector->tx.total_packets += total_packets;

#ifdef INIC_RC_EP_DEBUG_ENABLE
	LSINIC_WRITE_REG(&tx_ring->ep_reg->cir, tx_ring->last_used_idx);
#endif

	return complete;
}

static bool lsinic_clean_tx_irq(
		struct lsinic_q_vector *q_vector,
		struct lsinic_ring *tx_ring)
{
	struct lsinic_adapter *adapter = q_vector->adapter;

	if (test_bit(__LSINIC_DOWN, &adapter->state))
		return true;

	return lsinic_clean_tx(tx_ring);
}

/**
 * lsinic_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @q_vector: structure containing interrupt and ring information
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 **/
static int lsinic_clean_rx_irq(struct lsinic_q_vector *q_vector,
			struct lsinic_ring *rx_ring,
			const int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 bd_idx;
	u32 ret_val = 0;

#ifdef RC_RING_REG_SHADOW_ENABLE
	ret_val = rx_ring->rc_reg->sr;
#else
	ret_val = LSINIC_READ_REG(&rx_ring->ep_reg->sr);
#endif
	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != rx_ring->ep_sr)
			pr_warn("inic: ep-tx queue down\n");
		rx_ring->ep_sr = ret_val;
		return 0;
	}
	rx_ring->ep_sr = ret_val;

#ifdef PRINT_RX
	if (lsinic_get_ring_pending(rx_ring)) {
		printk_rx("\n****** %s ******: Rx Ring %d\n",
			  __func__, rx_ring->queue_index);

		printk_rx("RX ring%d - last_avail_idx:%d, rx_count:%d\n",
			  rx_ring->queue_index, rx_ring->last_avail_idx,
			  lsinic_get_ring_pending(rx_ring));
	}
#endif

	while (likely(total_rx_packets < budget)) {
		struct lsinic_bd_desc *rx_desc;
#ifdef LSINIC_BD_CTX_IDX_USED
		struct lsinic_bd_desc local_desc;
#endif
		struct sk_buff *skb;
		struct sk_buff *new_skb;
		dma_addr_t new_dma;

		bd_idx = rx_ring->rx_used_idx & (rx_ring->count - 1);

#ifdef RC_RING_REG_SHADOW_ENABLE
		rx_desc = LSINIC_RC_BD_DESC(rx_ring, bd_idx);
#else
		rx_desc = LSINIC_EP_BD_DESC(rx_ring, bd_idx);
#endif
#ifdef LSINIC_BD_CTX_IDX_USED
		mem_cp128b_atomic((u8 *)&local_desc, (u8 *)rx_desc);
		if ((local_desc.bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;
#else
		if ((rx_desc->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		rmb();
#endif

		new_skb = netdev_alloc_skb_ip_align(rx_ring->netdev,
				rx_ring->data_room);
		if (unlikely(new_skb == NULL))
			break;

		new_dma = dma_map_single(rx_ring->dev, new_skb->data,
					rx_ring->data_room,
					DMA_FROM_DEVICE);
		if (dma_mapping_error(rx_ring->dev, new_dma)) {
			dev_err(rx_ring->dev, "Rx DMA map failed\n");
			rx_ring->rx_stats.alloc_rx_dma_failed++;
			dev_kfree_skb_any(new_skb);
			break;
		}

		if (lsinic_test_staterr(rx_desc, LSINIC_BD_CMD_MG)) {
			struct sk_buff *skb_array[LSINIC_MERGE_MAX_NUM];
			int count, i;

			count = lsinic_fetch_merge_rx_buffers(rx_ring,
						rx_desc,
						skb_array);
			if (!count) {
				rx_desc->len_cmd = LSINIC_BD_CMD_EOP;
				lsinic_is_non_eop(rx_ring, rx_desc, NULL);
				dma_unmap_single(rx_ring->dev, new_dma,
					rx_ring->data_room,
					DMA_FROM_DEVICE);
				dev_kfree_skb_any(new_skb);
				continue;
			}
			count--;
			for (i = 0; i < count; i++) {
				skb = skb_array[i];

#if defined(PRINT_SKB) && defined(PRINT_RX)
				print_skb(skb, RX);
#endif

				total_rx_bytes += skb->len;
				/* update budget accounting */
				total_rx_packets++;

				if (lsinic_loopback) {
					lsinic_loopback_rx_tx(skb,
						q_vector,
						rx_ring);
				} else {
					lsinic_process_skb_fields(rx_ring,
						skb);
					skb_mark_napi_id(skb,
						&q_vector->napi);
					lsinic_rx_skb(q_vector,
						skb);
				}
			}
			skb = skb_array[count]; /* The last packet */
		} else {
			/* retrieve a buffer from the ring */
			skb = lsinic_fetch_rx_buffer(rx_ring, rx_desc);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			dma_unmap_single(rx_ring->dev, new_dma,
					rx_ring->data_room,
					DMA_FROM_DEVICE);
			dev_kfree_skb_any(new_skb);
			break;
		}

		/* place incomplete frames back on ring for completion */
		if (lsinic_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		/* verify the packet layout is correct */
		/*
		 *if (lsinic_cleanup_headers(rx_ring, rx_desc, skb))
		 *        continue;
		 */

		printk_rx("skb->len=%d skb->data_len=%d nr_frags=%d\n",
			  skb->len, skb->data_len, skb_shinfo(skb)->nr_frags);

#if defined(PRINT_SKB) && defined(PRINT_RX)
		print_skb(skb, RX);
#endif

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;
		/* update budget accounting */
		total_rx_packets++;

		if (lsinic_loopback) {
			lsinic_loopback_rx_tx(skb, q_vector, rx_ring);
		} else {
			/* populate checksum, timestamp, VLAN, and protocol */
			lsinic_process_skb_fields(rx_ring, skb);

			skb_mark_napi_id(skb, &q_vector->napi);
			lsinic_rx_skb(q_vector, skb);
		}
		lsinic_rx_bd_skb_set(rx_ring, bd_idx, new_skb, new_dma);

		printk_rx("%s total_rx_packets = %u\n",
			__func__, total_rx_packets);
	}
	/*
	 *spin_unlock_irqrestore(&rx_ring->lock, flags);
	 */

	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;

#ifdef INIC_RC_EP_DEBUG_ENABLE
	LSINIC_WRITE_REG(&rx_ring->ep_reg->cir, rx_ring->rx_used_idx);
#endif

	return total_rx_packets;
}

static irqreturn_t lsinic_napi_intr(int irq, void *data)
{
	struct lsinic_q_vector *q_vector = data;

	lsinic_msix_disable(q_vector->adapter, q_vector->v_idx);

	/* would disable interrupts here but EIAM disabled it */
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

static int lsinic_alloc_q_vectors(struct lsinic_adapter *adapter);
static void lsinic_free_q_vectors(struct lsinic_adapter *adapter);

int lsinic_init_thread(struct lsinic_adapter *adapter)
{
	int v_budget, err;

	v_budget = max(adapter->num_rx_queues, adapter->num_tx_queues);
	v_budget = min_t(int, v_budget, num_online_cpus());

	adapter->num_q_vectors = v_budget;
	adapter->flags |= LSINIC_FLAG_THREAD_ENABLED;

	err = lsinic_alloc_q_vectors(adapter);
	if (err)
		e_dev_err("Unable to allocate memory for queue vectors\n");

	e_dev_info(
		   "Thread mode Multiqueue: Rx Queue count = %u,"
		   " Tx Queue count = %u\n",
		   adapter->num_rx_queues, adapter->num_tx_queues);

	set_bit(__LSINIC_DOWN, &adapter->state);

	return 0;
}

void lsinic_clear_thread(struct lsinic_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	lsinic_free_q_vectors(adapter);
}

static int lsinic_clean_rings_thread(void *data)
{
	struct lsinic_q_vector *q_vector = data;
	struct lsinic_ring *ring;

	pr_info("Start %s CleanThread\n", q_vector->name);
	while (1) {
		if (kthread_should_stop()) {
			pr_info("%s CleanThread is killed\n", q_vector->name);
			break;
		}
		if (lsinic_self_test) {
			lsinic_for_each_ring(ring, q_vector->tx) {
				netdev_tx_t ret;
				struct sk_buff *skb;

				if (!ring->self_test_skb)
					lsinic_tx_self_test_skb_alloc(ring);
				skb = lsinic_tx_self_test_skb_get(ring);
				if (!skb)
					continue;
				ret = lsinic_xmit_frame_ring(skb,
						ring->adapter, ring);
				if (ret == NETDEV_TX_BUSY)
					lsinic_tx_self_test_skb_put(ring, skb);
			}
		}
		lsinic_for_each_ring(ring, q_vector->tx) {
			lsinic_clean_tx(ring);
		}
		lsinic_for_each_ring(ring, q_vector->rx) {
			lsinic_clean_rx_irq(q_vector, ring, 32);
		}
		schedule();
	}
	return 0;
}

/**
 * lsinic_poll - NAPI Rx polling callback
 * @napi: structure for representing this polling device
 * @budget: how many packets driver is allowed to clean
 *
 * This function is used for legacy and MSI, NAPI mode
 **/
int lsinic_poll(struct napi_struct *napi, int budget)
{
	struct lsinic_q_vector *q_vector =
			container_of(napi, struct lsinic_q_vector,
						napi);
	struct lsinic_ring *ring;
	int per_ring_budget, rx_count;
	bool clean_complete = true, tx_complete;

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling
	 */
	if (q_vector->rx.count > 1)
		per_ring_budget = max(budget/q_vector->rx.count, 1);
	else
		per_ring_budget = budget;

	lsinic_for_each_ring(ring, q_vector->tx) {
		tx_complete = lsinic_clean_tx_irq(q_vector, ring);
		if (!tx_complete)
			clean_complete = false;
	}

	lsinic_for_each_ring(ring, q_vector->rx) {
		rx_count = lsinic_clean_rx_irq(q_vector, ring,
				   per_ring_budget);
		if (rx_count >= per_ring_budget)
			clean_complete = false;
	}

	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;

	/* all work done, exit the polling mode */
	napi_complete(napi);
	lsinic_msix_enable(q_vector->adapter, q_vector->v_idx);
	return 0;
}

/**
 * lsinic_request_muti_msi_irqs - Initialize MUTI-MSI interrupts
 * @adapter: board private structure
 *
 * lsinic_request_muti_msi_irqs allocates MUTI-MSI vectors and requests
 * interrupts from the kernel.
 **/
static int lsinic_request_muti_msi_irqs(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct lsinic_q_vector *q_vector = adapter->q_vector[vector];
		struct vi_vectors_info *entry = &adapter->vectors_info[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "TxRx", ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "rx", ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "tx", ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}

#ifdef PRINT_MUTI_MSIX
		pr_debug("%s: q_vector = 0x%p, name = %s\n",
			 __func__, q_vector, q_vector->name);
		pr_debug("%s: muti msi_entry = 0x%p\n", __func__, entry);
		pr_debug("entry->vector = %d\n", entry->vec);
#endif
		err = request_irq(entry->vec, lsinic_napi_intr, 0,
				q_vector->name, q_vector);
		if (err) {
			e_err(probe, "request_irq failed for MSIX Tx interrupt "
					"Error: %d\n", err);
			goto free_queue_irqs;
		}
		/* assign the mask for this irq */
		irq_set_affinity_hint(entry->vec, &q_vector->affinity_mask);
	}

	if (NON_Q_VECTORS) {
		err = request_irq(adapter->vectors_info[vector].vec,
				  lsinic_msix_other, 0, netdev->name, adapter);
		if (err) {
			e_err(probe, "request_irq muti_msi_other failed: %d\n",
				err);
			goto free_queue_irqs;
		}
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		free_irq(adapter->vectors_info[vector].vec,
			 adapter->q_vector[vector]);
	}
	adapter->flags &= ~LSINIC_FLAG_MUTIMSI_ENABLED;
	return err;
}

static void lsinic_irq_set_affinity_hint(struct lsinic_adapter *adapter,
					 unsigned int irq,
					 int vector,
					 void *cpumask)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	irq_set_affinity_hint(pci_irq_vector(adapter->pdev, vector),
			      cpumask);
#else
	irq_set_affinity_hint(irq, cpumask);
#endif
}

static int lsinic_request_muti_interrupt(struct lsinic_adapter *adapter,
					 unsigned int irq,
					 irqreturn_t (*handler)(int, void *),
					 char *name,
					 void *dev_id,
					 int vector)
{
	int err;

#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	err = request_irq(pci_irq_vector(adapter->pdev, vector),
			  handler, 0, name, dev_id);
#else
	err = request_irq(irq, handler, 0, name, dev_id);
#endif

	return err;
}

static int lsinic_request_interrupt(struct lsinic_adapter *adapter,
				    irqreturn_t (*handler)(int, void *),
				    unsigned long irqflags,
				    const char *name,
				    void *dev_id)
{
	int err;

#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	err = request_irq(pci_irq_vector(adapter->pdev, 0),
			  handler, irqflags, name, dev_id);
#else
	err = request_irq(adapter->pdev->irq, handler,
			  irqflags, name, dev_id);
#endif

	return err;
}

static void lsinic_free_interrupt(struct lsinic_adapter *adapter,
				  unsigned int irq,
				  int vector,
				  void *dev_id)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	free_irq(pci_irq_vector(adapter->pdev, vector), dev_id);
#else
	free_irq(irq, dev_id);
#endif
}

static void lsinic_pci_disable_msix(struct lsinic_adapter *adapter)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	pci_free_irq_vectors(adapter->pdev);
#else
	pci_disable_msix(adapter->pdev);
#endif
}

static void lsinic_pci_disable_msi(struct lsinic_adapter *adapter)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	pci_free_irq_vectors(adapter->pdev);
#else
	pci_disable_msi(adapter->pdev);
#endif
}


/**
 * lsinic_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * lsinic_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int lsinic_request_msix_irqs(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct lsinic_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "TxRx", ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "rx", ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "tx", ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}

#ifdef PRINT_MSIX
		pr_debug("%s: q_vector = 0x%p, name = %s\n",
			 __func__, q_vector, q_vector->name);
		pr_debug("%s: msix_entry = 0x%p\n", __func__, entry);
		pr_debug("entry->vector = %d\n", entry->vector);
#endif
		err = lsinic_request_muti_interrupt(adapter, entry->vector,
				lsinic_napi_intr,
				q_vector->name, q_vector, vector);
		if (err) {
			e_err(probe, "request_irq failed for MSIX Tx interrupt "
				"Error: %d\n", err);
			goto free_queue_irqs;
		}

		/* assign the mask for this irq */
		lsinic_irq_set_affinity_hint(adapter, entry->vector,
			vector, &q_vector->affinity_mask);
	}

	if (NON_Q_VECTORS) {
		err = lsinic_request_muti_interrupt(adapter,
				adapter->msix_entries[vector].vector,
				lsinic_msix_other, netdev->name,
				adapter, vector);
		if (err) {
			e_err(probe, "request_irq for msix_other failed: %d\n", err);
			goto free_queue_irqs;
		}
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		lsinic_free_interrupt(adapter,
			adapter->msix_entries[vector].vector,
			vector, adapter->q_vector[vector]);
	}
	adapter->flags &= ~LSINIC_FLAG_MSIX_ENABLED;
	lsinic_pci_disable_msix(adapter);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	return err;
}

/**
 * lsinic_intr - legacy mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t lsinic_intr(int irq, void *data)
{
	return IRQ_HANDLED;
}

/**
 * lsinic_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int lsinic_request_irq(struct lsinic_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err = 0;

	if (adapter->flags & LSINIC_FLAG_THREAD_ENABLED)
		return 0;
	else if (adapter->flags & LSINIC_FLAG_MUTIMSI_ENABLED)
		err = lsinic_request_muti_msi_irqs(adapter);
	else if (adapter->flags & LSINIC_FLAG_MSIX_ENABLED)
		err = lsinic_request_msix_irqs(adapter);
	else if (adapter->flags & LSINIC_FLAG_MSI_ENABLED)
		err = lsinic_request_interrupt(adapter, lsinic_intr, 0,
				netdev->name, adapter);
	else
		err = lsinic_request_interrupt(adapter, lsinic_intr,
				IRQF_SHARED,
				netdev->name, adapter);

	if (err)
		e_err(probe, "request_irq failed, Error %d\n", err);

	return err;
}

void lsinic_reset(struct lsinic_adapter *adapter)
{
}

/**
 * lsinic_set_rx_mode - Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_rx_method entry point is called whenever the unicast/multicast
 * address list or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper unicast, multicast and
 * promiscuous mode.
 **/
void lsinic_set_rx_mode(struct net_device *netdev)
{
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

static void lsinic_free_irq(struct lsinic_adapter *adapter)
{
	int vector;

	if (adapter->flags & LSINIC_FLAG_THREAD_ENABLED)
		return;

	if (adapter->flags & LSINIC_FLAG_MUTIMSI_ENABLED) {
		for (vector = 0; vector < adapter->num_q_vectors; vector++) {
			struct lsinic_q_vector *q_vector =
				adapter->q_vector[vector];
			struct vi_vectors_info *entry =
				&adapter->vectors_info[vector];

			/* free only the irqs that were actually requested */
			if (!q_vector->rx.ring && !q_vector->tx.ring)
				continue;

			/* clear the affinity_mask in the IRQ descriptor */
			lsinic_irq_set_affinity_hint(adapter, entry->vec,
				vector, NULL);
			lsinic_free_interrupt(adapter, entry->vec,
				vector, q_vector);
		}

		if (NON_Q_VECTORS) {
			lsinic_free_interrupt(adapter,
				adapter->vectors_info[vector].vec,
				vector,
				adapter);
			vector++;
		}

		return;
	}

	if (!(adapter->flags & LSINIC_FLAG_MSIX_ENABLED)) {
		lsinic_free_interrupt(adapter, adapter->pdev->irq,
			0, adapter);
		return;
	}

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct lsinic_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

		/* clear the affinity_mask in the IRQ descriptor */
		lsinic_irq_set_affinity_hint(adapter, entry->vector,
			vector, NULL);

		lsinic_free_interrupt(adapter, entry->vector,
			vector, q_vector);
	}

	if (NON_Q_VECTORS) {
		lsinic_free_interrupt(adapter,
			adapter->msix_entries[vector].vector,
			vector,
			adapter);
		vector++;
	}
}

static int lsinic_set_mac(struct net_device *netdev, void *p)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	struct sockaddr *addr = p;
	u32 mac_high = 0;
	u32 mac_low = 0;
	u32 mac_bkh, mac_bkl;
	int i;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	mac_bkh = LSINIC_READ_REG(&eth_reg->macaddrh);
	mac_bkl = LSINIC_READ_REG(&eth_reg->macaddrl);

	for (i = 0; i < 2; i++)
		mac_high |= ((u32)addr->sa_data[1-i] & 0xff) << (i * 8);
	for (i = 0; i < 4; i++)
		mac_low |= ((u32)addr->sa_data[5-i] & 0xff) << (i * 8);

	LSINIC_WRITE_REG(&eth_reg->macaddrh, mac_high);
	LSINIC_WRITE_REG(&eth_reg->macaddrl, mac_low);
	LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_PF_MAC_ADDR);

	err = lsinic_set_netdev(adapter, PCIDEV_COMMAND_SET_MAC);
	if (err) {
		dev_warn(&adapter->pdev->dev,
			"%s: Set MAC failure please check!!!", __func__);
		LSINIC_WRITE_REG(&eth_reg->macaddrh, mac_bkh);
		LSINIC_WRITE_REG(&eth_reg->macaddrl, mac_bkl);

		return -EADDRNOTAVAIL;
	}

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(netdev->perm_addr, addr->sa_data, netdev->addr_len);

	return 0;
}

int lsinic_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	int i;
	u8 mac_addr[6];
	u32 mac_high = 0, mac_low = 0;

	if (!is_valid_ether_addr(mac) || (vf >= adapter->num_vfs))
		return -EINVAL;
	adapter->vfinfo[vf].pf_set_mac = true;
	dev_info(&adapter->pdev->dev,
		"setting MAC %pM on VF %d\n", mac, vf);
	dev_info(&adapter->pdev->dev,
		"Reload the VF driver to make this change effective.");
	if (test_bit(__LSINIC_DOWN, &adapter->state))
		dev_warn(&adapter->pdev->dev, "PF device is not up.\n");

	memcpy(mac_addr, mac, ETH_ALEN);
	for (i = 0; i < 4; i++)
		mac_low |= (u32)(mac_addr[5 - i] << (i * 8));

	for (i = 0; i < 2; i++)
		mac_high |= (u32)(mac_addr[1 - i] << (i * 8));

	memcpy(adapter->vfinfo[vf].vf_mac_addresses, mac, 6);

	LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_VF_MAC_ADDR);
	LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_macaddrh, mac_high);
	LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_macaddrl, mac_low);
	LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_idx, vf);

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_SET_VF_MAC);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 62)
int
lsinic_set_vf_vlan(struct net_device *netdev,
	int vf, u16 vlan, u8 qos, __be16 vlan_proto)
#else
int
lsinic_set_vf_vlan(struct net_device *netdev,
	int vf, u16 vlan, u8 qos)
#endif
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	if ((vf >= adapter->num_vfs) || (vlan > 4095) || (qos > 7))
		return -EINVAL;
	if (vlan || qos) {
		adapter->vfinfo[vf].pf_qos = qos;
		adapter->vfinfo[vf].vlan_count++;
		adapter->vfinfo[vf].pf_vlan = vlan;
		dev_info(&adapter->pdev->dev,
			"Setting VLAN %d, QOS 0x%x on VF %d\n",
			vlan, qos, vf);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_VF_VLAN);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_vlan, vlan);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_idx, vf);
		lsinic_set_netdev(adapter, PCIDEV_COMMAND_SET_VLAN);
	} else {
		adapter->vfinfo[vf].pf_qos = 0;
		if (adapter->vfinfo[vf].vlan_count)
			adapter->vfinfo[vf].vlan_count--;
		adapter->vfinfo[vf].pf_vlan = 0;
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_VF_VLAN);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_vlan, 0);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_idx, vf);
		lsinic_set_netdev(adapter, PCIDEV_COMMAND_SET_VF_VLAN);
	}
	return 0;
}

int lsinic_ndo_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);

	adapter->vfinfo[vf].spoofchk_enabled = setting;

	return 0;
}

int lsinic_get_vf_config(struct net_device *netdev,
			    int vf, struct ifla_vf_info *ivi)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);

	if (vf >= adapter->num_vfs)
		return -EINVAL;
	ivi->vf = vf;
	memcpy(&ivi->mac, adapter->vfinfo[vf].vf_mac_addresses, ETH_ALEN);
	ivi->qos = adapter->vfinfo[vf].pf_qos;
	ivi->vlan = adapter->vfinfo[vf].pf_vlan;
#ifdef HAVE_SPOOFCHK
	ivi->spoofchk = adapter->vfinfo[vf].spoofchk_enabled;
#endif
	return 0;
}

/**
 * lsinic_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/
static int lsinic_open(struct net_device *netdev)
{
	int err = 0;
	u32 reg_val = 0;
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_dev_reg *ep_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	/* disallow open during test */
	if (test_bit(__LSINIC_TESTING, &adapter->state))
		return -EBUSY;

	reg_val = LSINIC_READ_REG(&ep_reg->ep_state);
	if (reg_val == LSINIC_DEV_INITING) {
		printk(KERN_WARNING "inic: ep has NOT been initialized!\n");
		return -EBUSY;
	}

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = lsinic_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = lsinic_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	err = lsinic_configure(adapter);
	if (err)
		goto err_setup_rx;

	err = lsinic_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* Notify the stack of the actual queue counts. */
	netif_set_real_num_tx_queues(netdev,
		adapter->num_rx_pools > 1 ? 1 :
		adapter->num_tx_queues);

	err = netif_set_real_num_rx_queues(netdev,
			adapter->num_rx_pools > 1 ? 1 :
			adapter->num_rx_queues);

	if (err)
		goto err_set_queues;

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_INIT);

	err = lsinic_up_complete(adapter);
	if (!err)
		return 0;

err_set_queues:
	lsinic_free_irq(adapter);
err_req_irq:
	lsinic_free_all_rx_resources(adapter);
err_setup_rx:
	lsinic_free_all_tx_resources(adapter);
err_setup_tx:
	lsinic_reset(adapter);
	return err;
}

static void lsinic_reset_interrupt_capability(struct lsinic_adapter *adapter);
/**
 * lsinic_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static int lsinic_close(struct net_device *netdev)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);

	lsinic_down(adapter);
	lsinic_free_irq(adapter);

	lsinic_free_all_tx_resources(adapter);
	lsinic_free_all_rx_resources(adapter);

	return 0;
}

/**
 * lsinic_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int lsinic_change_mtu(struct net_device *dev, int new_mtu)
{
	struct net_device *netdev = dev;
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	/* MTU < 68 is an error and causes problems on some kernels */
	if ((new_mtu < 68) || (max_frame > LSINIC_READ_REG(&eth_reg->max_data_room)))
		return -EINVAL;

	e_info(probe, "changing MTU from %d to %d\n", netdev->mtu, new_mtu);

	LSINIC_WRITE_REG(&eth_reg->max_data_room, new_mtu);
	if (lsinic_set_netdev(adapter, PCIDEV_COMMAND_SET_MTU))
		return -EAGAIN;

	/* must set new MTU before calling down or up */
	netdev->mtu = new_mtu;

	return 0;
}

#ifdef HAVE_NDO_GET_STATS64
#ifdef HAVE_NEW_INTERFACE
static void
lsinic_get_stats64(struct net_device *netdev,
	struct rtnl_link_stats64 *stats)
#else
static struct rtnl_link_stats64 *
lsinic_get_stats64(struct net_device *netdev,
	struct rtnl_link_stats64 *stats)
#endif
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	int i;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct lsinic_ring *ring = INIC_READ_ONCE(adapter->rx_ring[i]);
		unsigned int start;

		if (ring) {
			do {
				start = INIC_U64_STATS_FETCH_BEGIN(&ring->syncp);
				stats->rx_packets += ring->stats.packets;
				stats->rx_bytes += ring->stats.bytes;
				stats->rx_errors +=
					ring->rx_stats.alloc_rx_page_failed +
					ring->rx_stats.alloc_rx_buff_failed +
					ring->rx_stats.alloc_rx_dma_failed;
				stats->rx_crc_errors +=
					ring->rx_stats.csum_err;

			} while (INIC_U64_STATS_FETCH_RETRY(&ring->syncp, start));
		}
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct lsinic_ring *ring = INIC_READ_ONCE(adapter->tx_ring[i]);
		unsigned int start;

		if (ring) {
			do {
				start = INIC_U64_STATS_FETCH_BEGIN(&ring->syncp);
				stats->tx_packets += ring->stats.packets;
				stats->tx_bytes += ring->stats.bytes;
				stats->tx_dropped += ring->tx_stats.tx_busy;
			} while (INIC_U64_STATS_FETCH_RETRY(&ring->syncp, start));
		}
	}
	rcu_read_unlock();
	/* following stats updated by lsinic_watchdog_task() */
	stats->multicast = netdev->stats.multicast;
	stats->rx_length_errors	= netdev->stats.rx_length_errors;
	stats->rx_missed_errors	= netdev->stats.rx_missed_errors;

#ifdef HAVE_NEW_INTERFACE
	return;
#else
	return stats;
#endif
}
#endif

static int lsinic_ioctl(struct net_device *netdev, struct ifreq *req, int cmd)
{
	struct mii_ioctl_data *mii_data = if_mii(req);
	u16 addr = mii_data->reg_num;

	/* Validate/convert cmd to one of SIOC{G,S}MIIREG */
	switch (cmd) {
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		mii_data->phy_id = 0xa194;
		switch (addr) {
		case MII_BMCR:
			mii_data->val_out = 0x0140;
		break;
		case MII_BMSR:
			mii_data->val_out = 0x0024;
		break;
		case MII_PHYSID1:
		case MII_PHYSID2:
		case MII_ADVERTISE:
		case MII_LPA:
		default:
			return 0;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static u32 lsinic_tx_cmd_type(u32 tx_flags)
{
	return tx_flags;
}

static void
lsinic_tx_map(struct lsinic_ring *tx_ring,
	struct lsinic_tx_buffer *tx_buffer,
	const u8 hdr_len)
{
	dma_addr_t dma;
	struct sk_buff *skb = tx_buffer->skb;
	struct lsinic_bd_desc *ep_tx_desc, *rc_tx_desc;
	unsigned int size = skb_headlen(skb);
	u32 cmd_type;
	u16 i = tx_ring->tx_avail_idx & (tx_ring->count - 1);

	ep_tx_desc = LSINIC_EP_BD_DESC(tx_ring, i);
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, i);


	cmd_type = lsinic_tx_cmd_type(tx_buffer->tx_flags);

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	dma_unmap_len_set(tx_buffer, len, size);
	dma_unmap_addr_set(tx_buffer, dma, dma);

	rc_tx_desc->pkt_addr = dma;
	ep_tx_desc->pkt_addr = dma;

	cmd_type |= LSINIC_BD_CMD_EOP | size;
	rc_tx_desc->len_cmd = cmd_type;

#ifdef LSINIC_BD_CTX_IDX_USED
	rc_tx_desc->bd_status &= (~RING_BD_STATUS_MASK);
	rc_tx_desc->bd_status |= RING_BD_AVAILABLE;
	mem_cp128b_atomic((u8 *)ep_tx_desc, (u8 *)rc_tx_desc);
#else
	rc_tx_desc->sw_ctx = (uint64_t)tx_buffer;
	rc_tx_desc->bd_status = RING_BD_AVAILABLE;

	memcpy(ep_tx_desc, rc_tx_desc,
		offsetof(struct lsinic_bd_desc, desc));
	wmb();
	rc_tx_desc->sw_ctx = ioread64(&ep_tx_desc->sw_ctx);

	ep_tx_desc->desc = rc_tx_desc->desc;
#endif

	tx_ring->tx_avail_idx++;

#ifdef INIC_RC_EP_DEBUG_ENABLE
	LSINIC_WRITE_REG(&tx_ring->ep_reg->pir, tx_ring->tx_avail_idx);
#endif

	/*
	 *ep_tx_desc->len_cmd = rc_tx_desc->len_cmd;
	 *ep_tx_desc->index = rc_tx_desc->index;
	 *ep_tx_desc->flag = rc_tx_desc->flag;
	 */
	printk_tx("tx_ring->avail->idx = %d\n", tx_ring->tx_avail_idx);
}

static int lsinic_gso(struct lsinic_ring *tx_ring,
		       struct lsinic_tx_buffer *first)
{
	struct sk_buff *skb = first->skb;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_header_cloned(skb)) {
		int err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);

		if (err)
			return err;
	}

	first->tx_flags |= LSINIC_BD_CMD_SG;

	return 1;
}

netdev_tx_t
lsinic_xmit_frame_ring(struct sk_buff *skb,
	struct lsinic_adapter *adapter,
	struct lsinic_ring *tx_ring)
{
	struct lsinic_tx_buffer *first = NULL;
	__be16 protocol = skb->protocol;
	u8 hdr_len = 0;
	int gso;
	struct lsinic_bd_desc *rc_tx_desc;
	u16 bd_idx;
#ifdef LSINIC_BD_CTX_IDX_USED
	u16 txe_idx;
#endif
	u32 status;

	if (skb_shinfo(skb)->nr_frags > 1)
		return NETDEV_TX_BUSY;

	bd_idx = tx_ring->tx_avail_idx & (tx_ring->count - 1);
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);

	status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

	rmb();

	if (status != RING_BD_READY)
		return NETDEV_TX_BUSY;

#ifdef LSINIC_BD_CTX_IDX_USED
	txe_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
	first = &tx_ring->tx_buffer_info[txe_idx];
#else
	first = (struct lsinic_tx_buffer *)rc_tx_desc->sw_ctx;
#endif

	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	printk_tx("\n%s:\n", __func__);
	printk_tx("tx_buffer_info 0x%p\n", first);
	printk_tx("skb->len=%d data_len=%d skb_headlen=%d\n",
		  skb->len, skb->data_len, skb_headlen(skb));
	printk_tx("BD count = %d\n", count);

	first->tx_flags = 0;

	first->protocol = protocol;

	gso = lsinic_gso(tx_ring, first);
	if (gso < 0)
		goto out_drop;

	lsinic_tx_map(tx_ring, first, hdr_len);

	return NETDEV_TX_OK;

out_drop:
	if (lsinic_self_test)
		return NETDEV_TX_BUSY;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static netdev_tx_t
lsinic_xmit_frame(struct sk_buff *skb,
	struct net_device *netdev)
{
	u32 ret_val = 0;
	struct lsinic_adapter *adapter = netdev_priv(netdev);
	struct lsinic_ring *tx_ring;
#ifdef VF_VLAN_ENABLE
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	u32 vlan;
#endif

	if (lsinic_loopback || lsinic_self_test) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/*
	 * The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (unlikely(skb->len < 17)) {
		if (skb_pad(skb, 17 - skb->len))
			return NETDEV_TX_OK;
		skb->len = 17;
		skb_set_tail_pointer(skb, 17);
	}

	tx_ring = adapter->tx_ring[skb->queue_mapping];

	#ifdef RC_RING_REG_SHADOW_ENABLE
		ret_val = tx_ring->rc_reg->sr;
	#else
		ret_val = LSINIC_READ_REG(&tx_ring->ep_reg->sr);
	#endif

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != tx_ring->ep_sr)
			pr_warn("inic: ep-rx queue down\n");
		tx_ring->ep_sr = ret_val;
		return 0;
	}
	tx_ring->ep_sr = ret_val;

#ifdef VF_VLAN_ENABLE
	vlan = LSINIC_READ_REG(&eth_reg->vlan);
	if (vlan) {
		skb = vlan_put_tag(skb, htons(ETH_P_8021Q), (u16)vlan);
		if (!skb) {
			pr_err("failed to insert VLAN tag\n");
			return NETDEV_TX_BUSY;
		}
	}
#endif

#if defined(PRINT_SKB) && defined(PRINT_TX)
	print_skb(skb, TX);
#endif

	return lsinic_xmit_frame_ring(skb, adapter, tx_ring);
}

static const struct net_device_ops lsinic_netdev_ops = {
	.ndo_open		= lsinic_open,
	.ndo_stop		= lsinic_close,
	.ndo_start_xmit		= lsinic_xmit_frame,
	.ndo_change_mtu		= lsinic_change_mtu,
	.ndo_set_rx_mode	= lsinic_set_rx_mode,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef HAVE_NDO_GET_STATS64
	.ndo_get_stats64	= lsinic_get_stats64,
#endif
	.ndo_do_ioctl		= lsinic_ioctl,
	.ndo_set_mac_address    = lsinic_set_mac,
	.ndo_set_vf_mac		= lsinic_set_vf_mac,
	.ndo_set_vf_vlan	= lsinic_set_vf_vlan,
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	.ndo_set_vf_spoofchk    = lsinic_ndo_set_vf_spoofchk,
#endif
	.ndo_get_vf_config	= lsinic_get_vf_config,
};

#ifndef HAVE_FREE_RCU
static void kfree_q_vector(struct rcu_head *rcu_head)
{
	struct lsinic_q_vector *q_vector =
			container_of(rcu_head, struct lsinic_q_vector, rcu);

	kfree(q_vector);
}
#endif

static void lsinic_free_rcu(struct lsinic_q_vector *q_vector)
{
#ifdef HAVE_FREE_RCU
	kfree_rcu(q_vector, rcu);
#else
	call_rcu(&q_vector->rcu, kfree_q_vector);
#endif
}

/* lsinic_free_q_vector -
 * Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: Index of vector to be freed
 *
 * This function frees the memory allocated to the q_vector.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void
lsinic_free_q_vector(struct lsinic_adapter *adapter,
	int v_idx)
{
	struct lsinic_q_vector *q_vector = adapter->q_vector[v_idx];
	struct lsinic_ring *ring;

	lsinic_for_each_ring(ring, q_vector->tx)
		adapter->tx_ring[ring->queue_index] = NULL;

	lsinic_for_each_ring(ring, q_vector->rx)
		adapter->rx_ring[ring->queue_index] = NULL;

	adapter->q_vector[v_idx] = NULL;
	netif_napi_del(&q_vector->napi);

	/* lsinic_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	lsinic_free_rcu(q_vector);
}

static void lsinic_add_ring(struct lsinic_ring *ring,
	struct lsinic_ring_container *head)
{
	ring->next = head->ring;
	head->ring = ring;
	head->count++;
}

/**
 * lsinic_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @v_count: q_vectors allocated on adapter, used for ring interleaving
 * @v_idx: index of vector in adapter struct
 * @txr_count: total number of Tx rings to allocate
 * @txr_idx: index of first Tx ring to allocate
 * @rxr_count: total number of Rx rings to allocate
 * @rxr_idx: index of first Rx ring to allocate
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 **/
static int
lsinic_alloc_q_vector(struct lsinic_adapter *adapter,
	int v_count, int v_idx,
	int txr_count, int txr_idx,
	int rxr_count, int rxr_idx)
{
	struct lsinic_q_vector *q_vector;
	struct lsinic_ring *ring;
	int ring_count, size;
	int node = -1;
	int cpu = -1, cpu_idx;

	ring_count = txr_count + rxr_count;
	size = sizeof(struct lsinic_q_vector) +
	       (sizeof(struct lsinic_ring) * ring_count);


	cpu_idx = v_idx + 1;
	if ((cpu_idx % num_possible_cpus()) == 0)
		cpu_idx = 1;
	if (cpu_online(cpu_idx)) {
		cpu = cpu_idx;
		node = cpu_to_node(cpu);
	}

	q_vector = kzalloc_node(size, GFP_KERNEL, node);
	if (!q_vector)
		q_vector = kzalloc(size, GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	/* setup affinity mask and node */
	if (cpu != -1)
		cpumask_set_cpu(cpu, &q_vector->affinity_mask);
	q_vector->numa_node = node;

	/* initialize NAPI */
	netif_napi_add(adapter->netdev, &q_vector->napi,
		lsinic_poll, 64);

	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;
	q_vector->v_idx = v_idx;

	/* initialize work limits */
	q_vector->tx.work_limit = adapter->tx_work_limit;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	printk_dev("\n%s: q_vector = 0x%p, sizeof = %lu\n",
		__func__, q_vector, sizeof(*q_vector));
	printk_dev("%s: ring = 0x%p\n", __func__, ring);
	printk_dev("Setup Tx ring: txr_count = %d\n", txr_count);

	while (txr_count) {
		/* assign generic ring traits */
		if (lsinic_sim)
			ring->dev = &adapter->platdev->dev;
		else
			ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		printk_dev("Tx ring [%d] = 0x%p\n", txr_idx, ring);
		printk_dev("Tx ring->dev = 0x%p\n", ring->dev);

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		lsinic_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_bd_count;
		ring->queue_index = txr_idx;

		/* assign ring to adapter */
		adapter->tx_ring[txr_idx] = ring;

		/* update count and index */
		txr_count--;
		txr_idx += v_count;

		/* push pointer to next ring */
		ring++;
	}

	printk_dev("Setup Rx ring: rxr_count = %d\n", rxr_count);

	while (rxr_count) {
		/* assign generic ring traits */
		if (lsinic_sim)
			ring->dev = &adapter->platdev->dev;
		else
			ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		printk_dev("Rx ring [%d] = 0x%p\n", rxr_idx, ring);
		printk_dev("Rx ring->dev = 0x%p\n", ring->dev);

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		lsinic_add_ring(ring, &q_vector->rx);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_bd_count;
		ring->queue_index = rxr_idx;

		/* assign ring to adapter */
		adapter->rx_ring[rxr_idx] = ring;

		/* update count and index */
		rxr_count--;
		rxr_idx += v_count;

		/* push pointer to next ring */
		ring++;
	}

	return 0;
}

/* lsinic_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int lsinic_alloc_q_vectors(struct lsinic_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int rxr_idx = 0, txr_idx = 0, v_idx = 0;
	int err;
	int i;

	/* only one q_vector if MSI-X is disabled. */
	if ((!(adapter->flags & LSINIC_FLAG_MSIX_ENABLED)) &&
		(!(adapter->flags & LSINIC_FLAG_MUTIMSI_ENABLED)))
		q_vectors = 1;

	if (adapter->flags & LSINIC_FLAG_THREAD_ENABLED)
		q_vectors = adapter->num_q_vectors;

#ifdef Q_VECTOR_TXRX_SEPARATE
	q_vectors = q_vectors / 2;
#endif
	for (; v_idx < q_vectors; v_idx++) {
		int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors - v_idx);
		int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors - v_idx);
#ifdef PRINT_MSIX
		pr_info("%s: Loop: v_idx = %d\n", __func__, v_idx);
		pr_info("%s: tqpv = %d, txr_idx = %d\n",
		       __func__, tqpv, txr_idx);
		pr_info("%s: rqpv = %d, rxr_idx = %d\n",
		       __func__, rqpv, rxr_idx);
#endif
#ifndef Q_VECTOR_TXRX_SEPARATE
		err = lsinic_alloc_q_vector(adapter, q_vectors, v_idx,
				tqpv, txr_idx,
				rqpv, rxr_idx);
#else
		err = lsinic_alloc_q_vector(adapter,
				q_vectors, v_idx,
				tqpv, txr_idx,
				0, 0);
		err = lsinic_alloc_q_vector(adapter,
				q_vectors, v_idx + q_vectors,
				0, 0,
				rqpv, rxr_idx);
#endif

		if (err)
			goto err_out;

		/* update counts and index */
		rxr_remaining -= rqpv;
		txr_remaining -= tqpv;
		rxr_idx++;
		txr_idx++;
	}

	for (i = 0; i < adapter->num_rx_queues; i++)
		adapter->rx_ring[i]->reg_idx = i;
	for (i = 0; i < adapter->num_tx_queues; i++)
		adapter->tx_ring[i]->reg_idx = i;

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		lsinic_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

/**
 * lsinic_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void lsinic_free_q_vectors(struct lsinic_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		lsinic_free_q_vector(adapter, v_idx);
}

static void lsinic_reset_interrupt_capability(struct lsinic_adapter *adapter)
{
	if (adapter->flags & LSINIC_FLAG_MSIX_ENABLED) {
		adapter->flags &= ~LSINIC_FLAG_MSIX_ENABLED;
		lsinic_pci_disable_msix(adapter);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
	} else if (adapter->flags & LSINIC_FLAG_MSI_ENABLED) {
		adapter->flags &= ~LSINIC_FLAG_MSI_ENABLED;
		lsinic_pci_disable_msi(adapter);
	} else if (adapter->flags & LSINIC_FLAG_MUTIMSI_ENABLED) {
		adapter->flags &= ~LSINIC_FLAG_MUTIMSI_ENABLED;
		lsinic_pci_disable_msi(adapter);
	}
}

static int
lsinic_acquire_muti_msi(struct lsinic_adapter *adapter,
	unsigned int min_vecs,
	unsigned int max_vecs)
{
	int vecs;
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	vecs = pci_alloc_irq_vectors(adapter->pdev, min_vecs,
			max_vecs, PCI_IRQ_MSI);
	if (vecs < 0)
		return -1;
#else
	return pci_enable_msi_range(adapter->pdev, min_vecs, max_vecs);
#endif

	return vecs;
}

static int
lsinic_acquire_muti_msi_vectors(struct lsinic_adapter *adapter,
	int vectors)
{
	int i = 0;
	int ret, vector_threshold;

	/* at least larger than msix number on lx2160 */
	vector_threshold = 1;

	ret = lsinic_acquire_muti_msi(adapter, vector_threshold, vectors);
	if (ret < 0) {
		adapter->flags &= ~LSINIC_FLAG_MUTIMSI_ENABLED;
		return ret;
	}

	if (ret < vector_threshold) {
		adapter->flags &= ~LSINIC_FLAG_MUTIMSI_ENABLED;
	} else {
		vectors = ret;
		adapter->flags |= LSINIC_FLAG_MUTIMSI_ENABLED;

		vectors -= NON_Q_VECTORS;
		adapter->num_q_vectors = min(vectors, adapter->max_q_vectors);

		for (i = 0; i < adapter->num_q_vectors; i++)
			adapter->vectors_info[i].vec = adapter->pdev->irq + i;

		ret = 0;
	}
	return ret;
}

static int lsinic_pci_alloc_muti_irq(struct lsinic_adapter *adapter,
				     unsigned int vecs,
				     int vector_threshold)
{
	int err;
	int vectors = vecs;

#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	err = pci_alloc_irq_vectors(adapter->pdev, vecs, vecs, PCI_IRQ_MSIX);
	if (err < 0)
		vectors = 0;
	else
		vectors = err;
#else
	/* The more we get, the more we will assign to Tx/Rx Cleanup
	 * for the separate queues...where Rx Cleanup >= Tx Cleanup.
	 * Right now, we simply care about how many we'll get; we'll
	 * set them up later while requesting irq's.
	 */
	while (vectors >= vector_threshold) {
		err = pci_enable_msix(adapter->pdev,
				adapter->msix_entries, vecs);

		if (!err) /* Success in acquiring all requested vectors. */
			break;
		else if (err < 0)
			vectors = 0; /* Nasty failure, quit now */
		else /* err == number of vectors we should try again with */
			vectors = err;
	}
#endif

	return vectors;
}

static int lsinic_pci_alloc_irq(struct lsinic_adapter *adapter)
{
#ifdef HAVE_PCI_ALLOC_IRQ_VECTORS
	int nvec;

	nvec = pci_alloc_irq_vectors(adapter->pdev, 1, 1,
			PCI_IRQ_MSI);
	if (nvec != 1)
		return 1;
#else
	return pci_enable_msi(adapter->pdev);
#endif

	return 0;
}

static void
lsinic_acquire_msix_vectors(struct lsinic_adapter *adapter,
	int vectors)
{
	int vector_threshold;

	/* We'll want at least 2 (vector_threshold):
	 * 1) TxQ[0] + RxQ[0] handler
	 * 2) Other (Link Status Change, etc.)
	 */
	vector_threshold = 1;

	lsinic_pci_alloc_muti_irq(adapter, vectors,
		vector_threshold);

	if (vectors < vector_threshold) {
		/* Can't allocate enough MSI-X interrupts?  Oh well.
		 * This just means we'll go with either a single MSI
		 * vector or fall back to legacy interrupts.
		 */
		netif_printk(adapter, hw, KERN_DEBUG, adapter->netdev,
			"Unable to allocate MSI-X interrupts\n");
		adapter->flags &= ~LSINIC_FLAG_MSIX_ENABLED;
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
	} else {
		adapter->flags |= LSINIC_FLAG_MSIX_ENABLED; /* Woot! */
		/* Adjust for only the vectors we'll use, which is minimum
		 * of max_msix_q_vectors + NON_Q_VECTORS, or the number of
		 * vectors we were allocated.
		 */
		vectors -= NON_Q_VECTORS;
		adapter->num_q_vectors =
			min(vectors, adapter->max_q_vectors);
	}
}

/* lsinic_set_interrupt_capability - set MSI-X or MSI if supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 **/
static void
lsinic_set_interrupt_capability(struct lsinic_adapter *adapter)
{
	int vector, v_budget, err;
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	/*
	 * It's easy to be greedy for MSI-X vectors, but it really
	 * doesn't do us much good if we have a lot more vectors
	 * than CPU's.  So let's be conservative and only ask for
	 * (roughly) the same number of vectors as there are CPU's.
	 * The default is to use pairs of vectors.
	 */
	v_budget = max(adapter->num_rx_queues, adapter->num_tx_queues);
	v_budget = min_t(int, v_budget, num_online_cpus());
	v_budget += NON_Q_VECTORS;
	if (v_budget > MAX_MSIX_VECTORS) {
		/* enable multi-msi */
		mmsi_flag = 1;
	}

	/* At the same time, hardware can only support a maximum of
	 * hw.mac->max_msix_vectors vectors.  With features
	 * such as RSS and VMDq, we can easily surpass the number of Rx and Tx
	 * descriptor queues supported by our device.  Thus, we cap it off in
	 * those rare cases where the cpu count also exceeds our vector limit.
	 */
	if (mmsi_flag) {
		v_budget = min_t(int, v_budget, MAX_MULTI_MSI_VECTORS);
		err = lsinic_acquire_muti_msi_vectors(adapter, v_budget);
		if (err == 0) {
			LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_MMSI_INT);
			return;
		}
	} else {
		v_budget = min_t(int, v_budget, MAX_MSIX_VECTORS);
	}
	LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_MSIX_INT);

	/* A failure in MSI-X entry allocation isn't fatal, but it does
	 * mean we disable MSI-X capabilities of the adapter.
	 */
	adapter->msix_entries =
		kcalloc(v_budget, sizeof(struct msix_entry), GFP_KERNEL);
	if (adapter->msix_entries) {
		for (vector = 0; vector < v_budget; vector++)
			adapter->msix_entries[vector].entry = vector;

		lsinic_acquire_msix_vectors(adapter, v_budget);

		if (adapter->flags & LSINIC_FLAG_MSIX_ENABLED)
			return;
	}

	adapter->num_q_vectors = 1;

	err = lsinic_pci_alloc_irq(adapter);
	if (err) {
		netif_printk(adapter, hw, KERN_DEBUG, adapter->netdev,
			"Unable to allocate MSI interrupt, "
			"falling back to legacy.  Error: %d\n", err);
		return;
	}
	adapter->flags |= LSINIC_FLAG_MSI_ENABLED;
}

/**
 * lsinic_init_interrupt_scheme - Determine proper interrupt scheme
 * @adapter: board private structure to initialize
 *
 * We determine which interrupt scheme to use based on...
 * - Kernel support (MSI, MSI-X)
 *   - which can be user-defined (via MODULE_PARAM)
 * - Hardware queue count (num_*_queues)
 *   - defined by miscellaneous hardware support/features (RSS, etc.)
 **/
int lsinic_init_interrupt_scheme(struct lsinic_adapter *adapter)
{
	int err;

	/* Set interrupt mode */
	lsinic_set_interrupt_capability(adapter);

	err = lsinic_alloc_q_vectors(adapter);
	if (err) {
		e_dev_err("Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}

	e_dev_info("Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n",
		(adapter->num_rx_queues) ? "Enabled" : "Disabled",
		adapter->num_rx_queues, adapter->num_tx_queues);

	set_bit(__LSINIC_DOWN, &adapter->state);

	return 0;

err_alloc_q_vectors:
	lsinic_reset_interrupt_capability(adapter);
	return err;
}

/**
 * lsinic_clear_interrupt_scheme - Clear the current interrupt scheme settings
 * @adapter: board private structure to clear interrupt scheme on
 *
 * We go through and clear interrupt specific resources and reset the structure
 * to pre-load conditions
 **/
void lsinic_clear_interrupt_scheme(struct lsinic_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	lsinic_free_q_vectors(adapter);
	lsinic_reset_interrupt_capability(adapter);
}

static int lsinic_enable_sriov(struct lsinic_adapter *adapter)
{
	int i;

	adapter->vfinfo =
		kcalloc(adapter->num_vfs,
			sizeof(struct vf_data_storage), GFP_KERNEL);
	if (adapter->vfinfo) {
		/* enable spoof checking for all VFs */
		for (i = 0; i < adapter->num_vfs; i++)
			adapter->vfinfo[i].spoofchk_enabled = true;
		return 0;
	}

	return -ENOMEM;
}

int lsinic_free_sriov(struct lsinic_adapter *adapter)
{
	kfree(adapter->vfinfo);
	adapter->vfinfo = NULL;
	return 0;
}

static int lsinic_vf_init(struct pci_dev *pdev)
{
	struct lsinic_adapter *adapter = pci_get_drvdata(pdev);
	int pos;
	int ret;
	u16 vf_total, vf_availbe;
	u16 pre_existing_vfs = 0;
	u16 offset, stride;

	if (!pci_is_pcie(pdev))
		return -ENODEV;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	adapter->num_vfs = max_vfs;
	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs && pre_existing_vfs != max_vfs)
		pci_disable_sriov(pdev);
	else if (pre_existing_vfs && pre_existing_vfs == max_vfs)
		return 0;

	pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &vf_total);
	if (!vf_total)
		return 0;

	if (max_vfs > vf_total)
		vf_availbe = vf_total;
	else
		vf_availbe = max_vfs;

	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_STRIDE, &stride);

	ret = pci_enable_sriov(pdev, vf_availbe);

	dev_dbg(&pdev->dev,
		"offset is %d  stride is %d %d VFs allocated\n",
		offset, stride, vf_availbe);

	adapter->flags |= LSINIC_FLAG_SRIOV_ENABLED;
	adapter->num_vfs = vf_availbe;

	ret = lsinic_enable_sriov(adapter);
	if (ret) {
		dev_err(&pdev->dev, "Can't' allocate memory for VF Data Storage\n");
		lsinic_free_sriov(adapter);
		return -ENOMEM;
	}

	return 0;
}

static int lsinic_disable_sriov(struct lsinic_adapter *adapter)
{
	/* set num VFs to 0 to prevent access to vfinfo */
	adapter->num_vfs = 0;

	/* if SR-IOV is already disabled then there is nothing to do */
	if (!(adapter->flags & LSINIC_FLAG_SRIOV_ENABLED))
		return 0;

	/*
	 * If our VFs are assigned we cannot shut down SR-IOV
	 * without causing issues, so just leave the hardware
	 * available but disabled
	 */

	if (pci_vfs_assigned(adapter->pdev)) {
		e_dev_warn("Unloading driver while VFs are assigned - VFs will not be deallocated\n");
		return -EPERM;
	}

	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(adapter->pdev);

	/* take a breather then clean up driver data */
	msleep(100);

	adapter->flags &= ~LSINIC_FLAG_SRIOV_ENABLED;
	return 0;
}

static int
lsinic_pci_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	max_vfs = num_vfs;

	lsinic_vf_init(pdev);

	return 0;
}

static int lsinic_pci_sriov_disable(struct pci_dev *pdev)
{
	struct lsinic_adapter *adapter = pci_get_drvdata(pdev);

	lsinic_disable_sriov(adapter);

	return 0;
}

int lsinic_pci_sriov_configure(struct pci_dev *dev, int num_vfs)
{
	if (dev->is_virtfn)
		return 0;

	if (num_vfs == 0)
		return lsinic_pci_sriov_disable(dev);
	else
		return lsinic_pci_sriov_enable(dev, num_vfs);
}

static int lsinic_tune_caps(struct pci_dev *pdev)
{
	struct pci_dev *parent;
	u16 pcaps, ecaps, ctl;
	int rc_sup, ep_sup;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/* Find out supported and configured values for parent (root) */
	parent = pdev->bus->self;
	if (parent->bus->parent) {
		dev_info(&pdev->dev, "Parent not root\n");
		return -EINVAL;
	}

	if (!pci_is_pcie(parent) || !pci_is_pcie(pdev))
		return -EINVAL;

	pcie_capability_read_word(parent, PCI_EXP_DEVCAP, &pcaps);
	pcie_capability_read_word(pdev, PCI_EXP_DEVCAP, &ecaps);

	/* Find max payload supported by root, endpoint */
	rc_sup = pcaps & PCI_EXP_DEVCAP_PAYLOAD;
	ep_sup = ecaps & PCI_EXP_DEVCAP_PAYLOAD;

	if (rc_sup > ep_sup)
		rc_sup = ep_sup;

	pcie_capability_clear_and_set_word(parent, PCI_EXP_DEVCTL,
		PCI_EXP_DEVCTL_PAYLOAD, rc_sup << 5);

	pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
		PCI_EXP_DEVCTL_PAYLOAD, rc_sup << 5);

	pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ctl);

	dev_dbg(&pdev->dev,
		"MAX payload size is %dB, MAX read size is %dB.\n",
		128 << ((ctl & PCI_EXP_DEVCTL_PAYLOAD) >> 5),
		128 << ((ctl & PCI_EXP_DEVCTL_READRQ) >> 12));

	return 0;
}

int lsinic_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct net_device *netdev;
	struct lsinic_dev_reg *ep_reg = NULL;
	struct lsinic_adapter *adapter = NULL;
	unsigned int indices = LSINIC_RING_MAX_COUNT;
	static int cards_found;
	int size_bits;
	int err;
	struct lsinic_rcs_reg *rcs_reg = NULL;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "failed to enable\n");
		return err;
	}

	err = pci_request_regions(pdev, lsinic_driver_name);
	if (err) {
		dev_err(&pdev->dev, "failed to request pci regions\n");
		goto err_pci_region;
	}

	pci_set_master(pdev);

	lsinic_tune_caps(pdev);

	netdev = alloc_etherdev_mq(sizeof(struct lsinic_adapter), indices);
	if (!netdev) {
		dev_err(&pdev->dev, "failed to create netdev\n");
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	pci_set_drvdata(pdev, adapter);

	adapter->netdev = netdev;
	adapter->pdev = pdev;

	adapter->hw_addr = pci_ioremap_bar(pdev, LSX_PCIEP_REG_BAR_IDX);
	if (!adapter->hw_addr) {
		dev_err(&pdev->dev, "failed to map configuration region\n");
		err = -EIO;
		goto err_ioremap_bar2;
	}

	ep_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	if (LSINIC_READ_REG(&ep_reg->init_flag) != LSINIC_INIT_FLAG) {
		dev_err(&pdev->dev, "iNIC EP has been NOT initialized!\n");
		err = -EIO;
		goto err_ioremap_bar4;
	}

	if (LSINIC_READ_REG(&ep_reg->ep_state) == LSINIC_DEV_INITING) {
		dev_err(&pdev->dev, "iNIC EP need to reset!\n");
		err = -EIO;
		goto err_ioremap_bar4;
	}

	printk_dev("adapter->hw_addr = 0x%p\n", adapter->hw_addr);

	size_bits = LSINIC_READ_REG(&ep_reg->obwin_size);
	dev_info(&pdev->dev, "iNIC outbound window size 0x%lx\n",
		(unsigned long)(0x1 << size_bits));
	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(size_bits));
	if (err) {
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Could not set PCI DMA Mask\n");
			goto err_set_mask;
		}
	}

	adapter->ep_ring_win_size =
		pci_resource_len(pdev, LSX_PCIEP_RING_BAR_IDX);
	adapter->ep_ring_phy_base =
		pci_resource_start(pdev, LSX_PCIEP_RING_BAR_IDX);
	adapter->ep_ring_virt_base =
		pci_ioremap_bar(pdev, LSX_PCIEP_RING_BAR_IDX);
	if (!adapter->ep_ring_virt_base) {
		dev_err(&pdev->dev, "failed to map ep_ring_virt_base region\n");
		err = -EIO;
		goto err_ioremap_bar4;
	}
	adapter->bd_desc_base =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_BD_OFFSET);

	adapter->rc_ring_win_size =
		pci_resource_len(pdev, LSX_PCIEP_RING_BAR_IDX);
	adapter->rc_ring_virt_base =
		dma_alloc_coherent(&pdev->dev,
			adapter->rc_ring_win_size,
			&adapter->rc_ring_phy_base,
			GFP_KERNEL);
	if (!adapter->rc_ring_virt_base) {
		printk_init("rc_ring_virt_base is NULL, ERROR!\n");
		goto err_sw_init;
	}

	adapter->rc_bd_desc_base =
		adapter->rc_ring_virt_base + LSINIC_RING_BD_OFFSET;
	adapter->rc_bd_desc_phy =
		((u64)adapter->rc_ring_phy_base) + LSINIC_RING_BD_OFFSET;

	rcs_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	LSINIC_WRITE_REG(&rcs_reg->r_regl,
		adapter->rc_ring_phy_base & DMA_BIT_MASK(32));
	LSINIC_WRITE_REG(&rcs_reg->r_regh,
		adapter->rc_ring_phy_base >> 32);

	netdev->features = NETIF_F_HIGHDMA;
#ifdef HAVE_HW_FEATURES
	netdev->hw_features = netdev->features | NETIF_F_LLTX;
#endif
	netdev->vlan_features = netdev->features;
	/* netdev->needed_headroom = 128; */

	netdev->netdev_ops = &lsinic_netdev_ops;
	lsinic_set_ethtool_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;
	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	adapter->bd_number = cards_found;

	/* setup the private structure */
	err = lsinic_sw_init(adapter);
	if (err) {
		dev_err(&pdev->dev, "lsinic_sw_init failed\n");
		err = -ENODEV;
		goto err_sw_init;
	}

	lsinic_get_macaddr(adapter);

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		e_dev_err("invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}

#ifdef HAVE_TIMER_SETUP
	timer_setup(&adapter->service_timer, &lsinic_service_timer, 0);
#else
	setup_timer(&adapter->service_timer, &lsinic_service_timer,
		(unsigned long) adapter);
#endif

	INIT_WORK(&adapter->service_task, lsinic_service_task);
	clear_bit(__LSINIC_SERVICE_SCHED, &adapter->state);

	if (lsinic_thread_mode) {
		err = lsinic_init_thread(adapter);
		if (err) {
			e_dev_err("failed to initialize thread\n");
			goto err_sw_init;
		}
		LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_DONT_INT);
	} else {
		err = lsinic_init_interrupt_scheme(adapter);
		if (err) {
			e_dev_err("failed to initialize interrupt\n");
			goto err_sw_init;
		}
	}

	if (pdev->is_physfn && !pdev->is_virtfn)
		lsinic_vf_init(pdev);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err) {
		e_dev_err("failed register netdev\n");
		goto err_register;
	}

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);

	e_dev_info("%s\n", lsinic_default_device_descr);
	cards_found++;

	return 0;

err_register:
	if (pdev->is_physfn && !pdev->is_virtfn)
		lsinic_disable_sriov(adapter);
	if (lsinic_thread_mode)
		lsinic_clear_thread(adapter);
	else
		lsinic_clear_interrupt_scheme(adapter);
err_sw_init:
	if (adapter->rc_ring_virt_base) {
		dma_free_coherent(&pdev->dev, adapter->rc_ring_win_size,
			adapter->rc_ring_virt_base,
			adapter->rc_ring_phy_base);
		adapter->rc_ring_virt_base = NULL;
	}
	iounmap(adapter->ep_ring_virt_base);
err_ioremap_bar4:
	iounmap(adapter->hw_addr);
err_ioremap_bar2:
	free_netdev(netdev);
err_alloc_etherdev:
err_set_mask:
	pci_release_regions(pdev);
err_pci_region:
	pci_disable_device(pdev);
	return err;
}

#define PRIMARY_PCI_RES_PF0_FILE "/tmp/0000:01:00.0/resource"
#define PRIMARY_PCI_RES_PF1_FILE "/tmp/0000:01:00.1/resource"
#define SECDONARY_PCI_RES_PF0_FILE "/tmp1/0000:01:00.0/resource"
const char *multi_pci_res_file_name[] = {
	PRIMARY_PCI_RES_PF0_FILE,
	SECDONARY_PCI_RES_PF0_FILE
};

const char *multi_pf_res_file_name[] = {
	PRIMARY_PCI_RES_PF0_FILE,
	PRIMARY_PCI_RES_PF1_FILE
};

#define RES_FILE_DATA_MAX_SIZE (4096 * 2)
static char res_file_data[RES_FILE_DATA_MAX_SIZE];
#define PCI_RESOURCE_FMT_NVAL 3

static int
lsinic_strsplit(char *string, int stringlen,
	char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		return -1;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;
}

static int
lsinic_pci_parse_res(char *line, size_t len, u64 *phys_addr,
	u64 *end_addr, u64 *flags)
{
	int ret;
	union pci_resource_info {
		struct {
			char *phys_addr;
			char *end_addr;
			char *flags;
		};
		char *ptrs[PCI_RESOURCE_FMT_NVAL];
	} res_info;

	if (lsinic_strsplit(line, len, res_info.ptrs, 3, ' ') != 3)
		return -1;

	ret = kstrtoull(res_info.phys_addr, 16, phys_addr);
	if (ret)
		return ret;
	ret = kstrtoull(res_info.end_addr, 16, end_addr);
	if (ret)
		return ret;
	ret = kstrtoull(res_info.flags, 16, flags);
	if (ret)
		return ret;

	return 0;
}

#define PCI_SIM_MAX_RESOURCE 6
#define PCI_BAR_INFO_LEN (19 * 3 + 1)

static char *read_line(char *buf, int buf_len, struct file *fp)
{
	int ret;
	int i = 0;
	loff_t f_pos_old = fp->f_pos;
read_again:
	ret = kernel_read(fp, buf, buf_len, &(fp->f_pos));
	if (ret <= 0)
		return NULL;
	if (buf[0] != '0') {
		f_pos_old++;
		fp->f_pos = f_pos_old;
		goto read_again;
	}
	i = 0;
	while (buf[i] != '\n' && buf[i] != 13 && i < ret)
		i++;
	if (i < ret)
		fp->f_pos += i - ret;
	if (buf[i] == 13)
		fp->f_pos++;
	if (i < buf_len)
		buf[i] = 0;

	return buf;
}

static int lsinic_sim_scan_pci(struct resource *res, int idx)
{
	struct file *res_file;
	int ret = -1;
	int i;
	u64 phys_addr, end_addr, flags;
	const char *file_name;

	if (lsinic_sim_multi_pci)
		file_name = multi_pci_res_file_name[idx];
	else
		file_name = multi_pf_res_file_name[idx];

	res_file = filp_open(file_name, O_RDWR, 0644);
	if (IS_ERR(res_file)) {
		printk(KERN_ERR
			"error occurred while opening file %s, exiting...\n",
			file_name);

		return -1;
	}
	memset(res_file_data, 0, RES_FILE_DATA_MAX_SIZE);

	for (i = 0; i < PCI_SIM_MAX_RESOURCE; i++) {
		read_line(res_file_data, RES_FILE_DATA_MAX_SIZE, res_file);
		ret = lsinic_pci_parse_res(res_file_data,
				RES_FILE_DATA_MAX_SIZE,
				&phys_addr, &end_addr, &flags);
		if (ret)
			break;
		ret = 0;
		res[i].start = phys_addr;
		res[i].end = end_addr;
		res[i].flags = flags;
	}
	filp_close(res_file, NULL);

	return ret;
}

static resource_size_t
pci_sim_resource_len(struct lsinic_adapter *adapter, int bar)
{
	struct resource *res = &adapter->res[bar];

	return res->end - res->start + 1;
}

static resource_size_t
pci_sim_resource_start(struct lsinic_adapter *adapter, int bar)
{
	struct resource *res = &adapter->res[bar];

	return res->start;
}

static void __iomem *
pci_sim_ioremap_bar(struct lsinic_adapter *adapter, int bar)
{
	struct resource *res = &adapter->res[bar];

	return phys_to_virt(res->start);
}

static int lsinic_sim_probe(int idx)
{
	struct net_device *netdev;
	struct lsinic_dev_reg *ep_reg = NULL;
	struct lsinic_adapter *adapter = NULL;
	unsigned int indices = LSINIC_RING_MAX_COUNT;
	int size_bits, err = 0;
	struct lsinic_rcs_reg *rcs_reg = NULL;
	char dev_name[64];
	struct platform_device *pdev;
	struct resource *res;

	res = vzalloc(DEVICE_COUNT_RESOURCE * sizeof(struct resource));
	if (!res)
		return -ENOMEM;

	memset(res, 0, DEVICE_COUNT_RESOURCE * sizeof(struct resource));
	err = lsinic_sim_scan_pci(res, idx);
	if (err) {
		err = -ENOMEM;
		goto err_res_alloc;
	}

	sprintf(dev_name, "INIC_SIM_%d", idx);
	pdev = platform_device_alloc(dev_name, 0);
	if (!pdev) {
		err = -ENOMEM;
		goto err_res_alloc;
	}

	err = platform_device_add(pdev);
	if (err) {
		err = -ENODEV;
		goto err_add_platform_dev;
	}

	netdev = alloc_etherdev_mq(sizeof(struct lsinic_adapter), indices);
	if (!netdev) {
		err = -EIO;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	dev_set_drvdata(&pdev->dev, adapter);

	adapter->netdev = netdev;
	adapter->platdev = pdev;
	memcpy(adapter->res, res,
		DEVICE_COUNT_RESOURCE * sizeof(struct resource));
	adapter->hw_addr =
		pci_sim_ioremap_bar(adapter, LSX_PCIEP_REG_BAR_IDX);
	if (!adapter->hw_addr) {
		err = -EIO;
		goto err_ioremap_bar2;
	}

	ep_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	if (LSINIC_READ_REG(&ep_reg->init_flag) != LSINIC_INIT_FLAG) {
		err = -EIO;
		goto err_ioremap_bar4;
	}

	if (LSINIC_READ_REG(&ep_reg->ep_state) == LSINIC_DEV_INITING) {
		err = -EIO;
		goto err_ioremap_bar4;
	}

	size_bits = LSINIC_READ_REG(&ep_reg->obwin_size);

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = -EIO;
		goto err_set_mask;
	}
	adapter->ep_ring_win_size = pci_sim_resource_len(adapter,
				LSX_PCIEP_RING_BAR_IDX);
	adapter->ep_ring_phy_base = pci_sim_resource_start(adapter,
				LSX_PCIEP_RING_BAR_IDX);
	adapter->ep_ring_virt_base = pci_sim_ioremap_bar(adapter,
				LSX_PCIEP_RING_BAR_IDX);
	if (!adapter->ep_ring_virt_base) {
		err = -EIO;
		goto err_ioremap_bar4;
	}
	adapter->bd_desc_base =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_BD_OFFSET);

	adapter->rc_ring_win_size = pci_sim_resource_len(adapter,
				LSX_PCIEP_RING_BAR_IDX);

	adapter->rc_ring_virt_base = (char *)adapter->ep_ring_virt_base +
			adapter->ep_ring_win_size;
	adapter->rc_ring_phy_base = adapter->ep_ring_phy_base +
			adapter->ep_ring_win_size;
	if (!adapter->rc_ring_virt_base) {
		printk_init("rc_ring_virt_base is NULL, ERROR!\n");
		err = -EIO;
		goto err_sw_init;
	}

	adapter->rc_bd_desc_base =
		(char *)adapter->rc_ring_virt_base + LSINIC_RING_BD_OFFSET;
	adapter->rc_bd_desc_phy =
		((u64)adapter->rc_ring_phy_base) +
		LSINIC_RING_BD_OFFSET;
	rcs_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	LSINIC_WRITE_REG(&rcs_reg->r_regl,
		adapter->rc_ring_phy_base & DMA_BIT_MASK(32));
	LSINIC_WRITE_REG(&rcs_reg->r_regh,
		adapter->rc_ring_phy_base >> 32);

	netdev->features = NETIF_F_HIGHDMA;
#ifdef HAVE_HW_FEATURES
	netdev->hw_features = netdev->features | NETIF_F_LLTX;
#endif
	netdev->vlan_features = netdev->features;
	/* netdev->needed_headroom = 128; */

	netdev->netdev_ops = &lsinic_netdev_ops;
	lsinic_set_ethtool_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;

	adapter->bd_number = idx;

	/* setup the private structure */
	err = lsinic_sw_init(adapter);
	if (err) {
		printk_init("lsinic_sw_init failed\n");
		err = -ENODEV;
		goto err_sw_init;
	}

	lsinic_get_macaddr(adapter);

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		e_dev_err("invalid MAC address\n");
		pr_info("!is_valid_ether_addr\r\n");
		err = -EIO;
		goto err_sw_init;
	}

#ifdef HAVE_TIMER_SETUP
	timer_setup(&adapter->service_timer, &lsinic_service_timer, 0);
#else
	setup_timer(&adapter->service_timer, &lsinic_service_timer,
		    (unsigned long) adapter);
#endif

	INIT_WORK(&adapter->service_task, lsinic_service_task);
	clear_bit(__LSINIC_SERVICE_SCHED, &adapter->state);

	err = lsinic_init_thread(adapter);
	if (err) {
		e_dev_err("failed to initialize thread\n");
		goto err_sw_init;
	}
	LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_DONT_INT);

	sprintf(netdev->name, "inic%d", idx);
	err = register_netdev(netdev);
	if (err) {
		e_dev_err("failed register netdev\n");
		goto err_register;
	}

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);

	e_dev_info("%s\n", lsinic_default_device_descr);
	sim_dev[idx] = pdev;

	vfree(res);

	return 0;

err_register:
	if (lsinic_thread_mode)
		lsinic_clear_thread(adapter);
	else
		lsinic_clear_interrupt_scheme(adapter);
err_sw_init:
err_set_mask:
err_ioremap_bar4:
err_ioremap_bar2:
	free_netdev(netdev);
err_alloc_etherdev:
err_add_platform_dev:
	platform_device_put(pdev);
err_res_alloc:
	vfree(res);

	return err;
}

static void lsinic_remove(struct pci_dev *pdev)
{
	struct lsinic_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev;

	if (!adapter)
		return;

	netdev = adapter->netdev;

	set_bit(__LSINIC_DOWN, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	if (netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(netdev);

	if (max_vfs && pdev->is_physfn && !pdev->is_virtfn)
		lsinic_disable_sriov(adapter);

	if (lsinic_thread_mode)
		lsinic_clear_thread(adapter);
	else
		lsinic_clear_interrupt_scheme(adapter);

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);

	if (adapter->hw_addr)
		iounmap(adapter->hw_addr);

	if (adapter->rc_ring_virt_base) {
		dma_free_coherent(&pdev->dev, adapter->rc_ring_win_size,
				  adapter->rc_ring_virt_base,
				  adapter->rc_ring_phy_base);
		adapter->rc_ring_virt_base = NULL;
	}

	if (adapter->ep_ring_virt_base)
		iounmap(adapter->ep_ring_virt_base);

	e_dev_info("complete\n");

	free_netdev(netdev);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static void lsinic_sim_remove(struct platform_device *simdev)
{
	struct lsinic_adapter *adapter;
	struct net_device *netdev;

	adapter = dev_get_drvdata(&simdev->dev);
	if (!adapter)
		return;

	netdev = adapter->netdev;

	set_bit(__LSINIC_DOWN, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	if (netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(netdev);

	if (lsinic_thread_mode)
		lsinic_clear_thread(adapter);
	else
		lsinic_clear_interrupt_scheme(adapter);

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);

	e_dev_info("complete\n");


	free_netdev(netdev);
	platform_device_unregister(simdev);
}

/* The list of devices that this module will support */
static struct pci_device_id lsinic_ids[] = {
	{PCI_VENDOR_ID_FREESCALE, 0x8240, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 1},
	{PCI_VENDOR_ID_FREESCALE, 0x8d80, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 1},
	{PCI_VENDOR_ID_FREESCALE, 0x8d90, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 1},
	{ 0 },
};
MODULE_DEVICE_TABLE(pci, lsinic_ids);

static struct pci_driver lsinic_driver = {
	.name     = "lsinic",
	.id_table = lsinic_ids,
	.probe    = lsinic_probe,
	.remove   = lsinic_remove,
#if KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE
	.sriov_configure = lsinic_pci_sriov_configure,
#endif
};

/**
 * lsinic_init_module - Driver Registration Routine
 *
 * lsinic_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init lsinic_init_module(void)
{
	int ret = 0;

	pr_info("NXP Layerscape 10 Gigabit PCI Express Network Driver\n");

	if (lsinic_sim) {
		int idx;

		lsinic_thread_mode = 1;
		for (idx = 0; idx < lsinic_sim; idx++) {
			ret = lsinic_sim_probe(idx);
			if (ret)
				return ret;
		}
		return 0;
	}

	ret = pci_register_driver(&lsinic_driver);
	if (ret)
		return ret;

	return 0;
}
module_init(lsinic_init_module);

/**
 * lsinic_exit_module - Driver Exit Cleanup Routine
 *
 * lsinic_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit lsinic_exit_module(void)
{
	pr_info("NXP Layerscape 10 Gigabit PCI Express Network Driver unloaded\n");
	if (lsinic_sim) {
		int idx;

		for (idx = 0; idx < lsinic_sim; idx++) {
			if (sim_dev[idx]) {
				lsinic_sim_remove(sim_dev[idx]);
				sim_dev[idx] = NULL;
			}
		}
		return;
	}

	pci_unregister_driver(&lsinic_driver);
}
module_exit(lsinic_exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NXP Semiconductor");
MODULE_DESCRIPTION("NXP Layerscape 10 Gigabit PCI Express Network Driver");
MODULE_VERSION("Version 1.0.0");
