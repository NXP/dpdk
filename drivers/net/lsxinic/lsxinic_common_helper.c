/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "lsxinic_common.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_common_reg.h"

#include "lsxinic_ep_tool.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_ep_ethtool.h"

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#include <dpaa2_hw_mempool.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_ethdev.h>
#endif

#include "lsxinic_rc_rxtx.h"
#include "lsxinic_rc_ethdev.h"
#include "lsxinic_rc_hw.h"

#include "lsxinic_ep_vio_rxtx.h"

static inline struct rte_ipv4_hdr *
ip_hdr(const struct rte_mbuf *mbuf)
{
	char *pkt_data = rte_pktmbuf_mtod_offset(mbuf, char *, 0);

	return (struct rte_ipv4_hdr *)((uint8_t *)pkt_data +
			sizeof(struct rte_ether_hdr));
}

static void
lsinic_mbuf_print_eth(const struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eth;
	int i;

	eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	if (eth) {
		printf("Ethernet header(0x%p):\n", eth);
		printf("-------------------------------------\n");
		printf("d_addr		= ");
		for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
			printf("%02x:", eth->dst_addr.addr_bytes[i]);

		printf("\n");

		printf("s_addr		= ");
		for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
			printf("%02x:", eth->src_addr.addr_bytes[i]);

		printf("\n");

		printf("ether_type	= 0x%x\n", eth->ether_type);
	}
	printf("\n");
}

static void
lsinic_mbuf_print_ip(const struct rte_mbuf *mbuf)
{
	struct rte_ipv4_hdr *iph;

	iph = ip_hdr(mbuf);
	if (iph) {
		printf("IP header (0x%p):\n", iph);
		printf("-------------------------------------\n");
		printf("version_ihl	= 0x%x\n", iph->version_ihl);
		printf("type_of_service	= 0x%x\n", iph->type_of_service);
		printf("packet_id	= 0x%x\n", iph->packet_id);
		printf("fragment_offset	= 0x%x\n", iph->fragment_offset);
		printf("time_to_live	= 0x%x\n", iph->time_to_live);
		printf("next_proto_id	= 0x%x\n", iph->next_proto_id);
		printf("hdr_checksum	= 0x%x\n", iph->hdr_checksum);
		printf("src_addr	= 0x%x\n", iph->src_addr);
		printf("dst_addr	= 0x%x\n", iph->dst_addr);
	}

	printf("\n");
}

static void
lsinic_mbuf_print(const struct rte_mbuf *mbuf)
{
	char *pkt_data = NULL;

	if (!mbuf)
		return;

	pkt_data = rte_pktmbuf_mtod_offset(mbuf, char *, 0);

	printf("mbuf: %p\n", mbuf);
	printf("=====================================\n");
	printf("pool		= %p\n", mbuf->pool);
	printf("type		= 0x%x\n", mbuf->packet_type);
	printf("buf_addr	= %p\n", mbuf->buf_addr);
	printf("buf_physaddr	= 0x%lx\n", mbuf->buf_iova);
	printf("pkt.data	= %p\n", pkt_data);
	printf("buf_len		= %d\n", mbuf->buf_len);
	printf("pkt.in_port	= %d\n", mbuf->port);
	printf("pkt.nb_segs	= %d\n", mbuf->nb_segs);

	printf("pkt.data_len	= %d\n", mbuf->data_len);
	/* Total pkt len: sum of all segment data_len */
	printf("pkt.pkt_len	= %d\n", mbuf->pkt_len);
	printf("\n");
}

void
lsinic_mbuf_print_all(const struct rte_mbuf *mbuf)
{
	lsinic_mbuf_print(mbuf);
	lsinic_mbuf_print_eth(mbuf);
	lsinic_mbuf_print_ip(mbuf);
}

#define G_SIZE ((double)(1000 * 1000 * 1000))

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static int
lsinic_ep_rx_drop_count(struct rte_eth_dev *eth_dev,
	unsigned long long *dev_imissed)
{
	struct dpaa2_queue *recycle_txq;
	struct rte_eth_dev_data *dpaa2_data;
	struct dpaa2_dev_priv *dpaa2_priv;
	struct rte_eth_dev *dpaa2_dev;
	struct rte_eth_stats igb_stats;
	struct lsinic_queue *rxq;

	rxq = eth_dev->data->rx_queues[0];

	if (rxq->split_type == LSINIC_HW_SPLIT) {
		recycle_txq = rxq->recycle_txq;
		dpaa2_data = recycle_txq->eth_data;
		dpaa2_priv = dpaa2_data->dev_private;
		dpaa2_dev = dpaa2_priv->eth_dev;

		dpaa2_dev->dev_ops->stats_get(dpaa2_dev, &igb_stats);
		*dev_imissed = (unsigned long long)igb_stats.imissed;

		return 0;
	}

	return -1;
}
#endif

static void
print_queue_status(void *queue,
	unsigned long long *packets,
	unsigned long long *errors,
	unsigned long long *drops,
	unsigned long long *fulls,
	unsigned long long *bytes_fcs,
	double *bytes_diff, uint64_t *core_mask,
	enum lsinic_port_type port_type)
{
	struct lsinic_queue *epq = NULL;
	struct lxsnic_ring *rcq = NULL;

	if (!queue)
		return;

	if (port_type == LSINIC_RC_PORT)
		goto print_rc_queue_status;

	epq = queue;

	printf("\t%sq%d: ",
		epq->type == LSINIC_QUEUE_RX ? "rx" : "tx",
		epq->reg_idx);

	printf("\tstatus=%d avail_idx=%d used_idx=%d pir=%d cir=%d\n",
		epq->status,
		epq->next_avail_idx,
		epq->next_used_idx,
		epq->ep_reg->pir,
		epq->ep_reg->cir);

	printf("\t\tpackets=%lld errors=%lld drop_pkts=%lld\n",
		(unsigned long long)epq->packets,
		(unsigned long long)epq->errors,
		(unsigned long long)epq->drop_packet_num);

	printf("\t\tring_full=%lld loop_total=%lld loop_avail=%lld\n",
		(unsigned long long)epq->ring_full,
		(unsigned long long)epq->loop_total,
		(unsigned long long)epq->loop_avail);

	printf("\tEP dmaq=%d next_dma_idx=%d",
		epq->dma_vq, epq->next_dma_idx);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	printf("\t\tnew_desc=%d in_dma=%ld in_dpni=%ld\n",
		epq->new_desc,
		epq->pkts_eq - epq->pkts_dq, (long)epq->recycle_pending);
#else
	printf("\t\tnew_desc=%d in_dma=%ld\n",
		epq->new_desc, epq->pkts_eq - epq->pkts_dq);
#endif

	(*packets) += epq->packets;
	(*errors) += epq->errors;
	(*drops) += epq->drop_packet_num;
	(*fulls) += epq->ring_full;
	(*bytes_fcs) += epq->bytes_fcs;
	(*bytes_diff) += epq->bytes_overhead - epq->bytes_overhead_old;
	epq->bytes_overhead_old = epq->bytes_overhead;

	if (core_mask)
		(*core_mask) |= (((uint64_t)1) << epq->core_id);

	return;
print_rc_queue_status:
	rcq = queue;

	printf("\t%sq%d: ",
		rcq->type == LSINIC_QUEUE_RX ? "rx" : "tx",
		rcq->queue_index);

	printf("\tstatus=%d avail_idx=%d used_idx=%d pir=%d cir=%d\n",
		rcq->status,
		rcq->last_avail_idx,
		rcq->last_used_idx,
		rcq->rc_reg->pir,
		rcq->rc_reg->cir);

	printf("\t\tpackets=%lld errors=%lld drop_pkts=%lld\n",
		(unsigned long long)rcq->packets,
		(unsigned long long)rcq->errors,
		(unsigned long long)rcq->drop_packet_num);

	printf("\t\tring_full=%lld loop_total=%lld loop_avail=%lld\n",
		(unsigned long long)rcq->ring_full,
		(unsigned long long)rcq->loop_total,
		(unsigned long long)rcq->loop_avail);

	(*packets) += rcq->packets;
	(*errors) += rcq->errors;
	(*drops) += rcq->drop_packet_num;
	(*fulls) += rcq->ring_full;
	(*bytes_fcs) += rcq->bytes_fcs;
	(*bytes_diff) += rcq->bytes_overhead -
		rcq->bytes_overhead_old;
	rcq->bytes_overhead_old = rcq->bytes_overhead;

	if (core_mask)
		(*core_mask) |= (((uint64_t)1) << rcq->core_id);
}

static void
print_ep_virtio_queue_status(void *queue,
	unsigned long long *packets,
	unsigned long long *errors,
	unsigned long long *drops,
	unsigned long long *fulls,
	unsigned long long *bytes_fcs,
	double *bytes_diff, uint64_t *core_mask)
{
	struct lsxvio_queue *q = queue;

	if (!q)
		return;

	printf("\t%sq%d: ",
		q->type == LSXVIO_QUEUE_RX ? "rx" : "tx",
		q->reg_idx);

	printf("\t\tpackets=%lld errors=%lld drop_pkts=%lld\n",
		(unsigned long long)q->packets,
		(unsigned long long)q->errors,
		(unsigned long long)q->drop_packet_num);

	printf("\t\tring_full=%lld loop_total=%lld loop_avail=%lld\n",
		(unsigned long long)q->ring_full,
		(unsigned long long)q->loop_total,
		(unsigned long long)q->loop_avail);

	printf("\tEP dmaq=%d next_dma_idx=%d\t\tnew_desc=%d in_dma=%ld\n",
		q->dma_vq, q->next_dma_idx,
		q->new_desc,
		q->pkts_eq - q->pkts_dq);

	(*packets) += q->packets;
	(*errors) += q->errors;
	(*drops) += q->drop_packet_num;
	(*fulls) += q->ring_full;
	(*bytes_fcs) += q->bytes_fcs;
	(*bytes_diff) += q->bytes_overhead - q->bytes_overhead_old;
	q->bytes_overhead_old = q->bytes_overhead;

	if (core_mask)
		(*core_mask) |= (((uint64_t)1) << q->core_id);
}

void print_port_status(struct rte_eth_dev *eth_dev,
	uint64_t *core_mask, uint32_t debug_interval,
	enum lsinic_port_type port_type)
{
	int i;
	void *queue;
	unsigned long long ipackets = 0, opackets = 0;
	unsigned long long ierrors = 0, oerrors = 0;
	unsigned long long idrops = 0, odrops = 0;
	unsigned long long iring_full = 0, oring_full = 0;
	double ibytes_diff = 0;
	double obytes_diff = 0;
	unsigned long long ibytes_fcs = 0, obytes_fcs = 0;
	unsigned long long missed = 0;
	int ret = -1;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (port_type == LSINIC_EP_PORT)
		ret = lsinic_ep_rx_drop_count(eth_dev, &missed);
#endif

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		queue = eth_dev->data->tx_queues[i];
		if (port_type != LSINIC_EP_PORT) {
			print_queue_status(queue, &opackets, &oerrors,
				&odrops, &oring_full, &obytes_fcs, &obytes_diff,
				NULL, port_type);
		} else {
			print_ep_virtio_queue_status(queue, &opackets,
				&oerrors, &odrops, &oring_full, &obytes_fcs,
				&obytes_diff, NULL);
		}
	}

	if (core_mask)
		*core_mask = 0;
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		queue = eth_dev->data->rx_queues[i];
		if (port_type != LSINIC_EP_PORT) {
			print_queue_status(queue, &ipackets, &ierrors,
				&idrops, &iring_full, &ibytes_fcs, &ibytes_diff,
				core_mask, port_type);
		} else {
			print_ep_virtio_queue_status(queue, &ipackets,
				&ierrors, &idrops, &iring_full, &ibytes_fcs,
				&ibytes_diff, core_mask);
		}
	}

	printf("\tTotal txq:\ttotal_pkts=%lld tx_pkts=%lld ",
		opackets + odrops, opackets);
	printf("drop_pkts=%lld ring_full=%lld\n",
		odrops, oring_full);

	printf("TX performance: %fGbps, fcs bits: %lld\r\n",
		obytes_diff * 8 /
		(debug_interval * G_SIZE), obytes_fcs * 8);
	if (!ret)
		idrops = missed;
	printf("\tTotal rxq:\trx=%lld drop=%lld full=%lld\n",
		ipackets, idrops, iring_full);
	printf("RX performance: %fGbps, fcs bits: %lld\r\n",
		ibytes_diff * 8 /
		(debug_interval * G_SIZE), ibytes_fcs * 8);
}
