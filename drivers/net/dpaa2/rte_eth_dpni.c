/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Freescale Semiconductor, Inc nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>

#include <net/if.h>
/* MC header files */
#include <fsl_dpbp.h>
#include <fsl_dpni.h>
#include "rte_eth_dpaa2_pvt.h"
#include "rte_eth_dpni_annot.h"
#include "dpaa2_logs.h"

#include <fsl_qbman_portal.h>
#include <fsl_dpio.h>

/* #define DPAA2_STASHING */

/* tx fd send batching */
#define QBMAN_MULTI_TX
/* #define DPAA2_CGR_SUPPORT */


#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/

#define RTE_ETH_DPAA2_SNAPSHOT_LEN 65535
#define RTE_ETH_DPAA2_SNAPLEN 4096
#define RTE_ETH_DPAA2_PROMISC 1
#define RTE_ETH_DPAA2_TIMEOUT -1
#define ETH_DPAA2_RX_IFACE_ARG "rx_iface"
#define ETH_DPAA2_TX_IFACE_ARG "tx_iface"
#define ETH_DPAA2_IFACE_ARG    "iface"

static const char *drivername = "DPNI PMD";

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		16
#define MAX_TX_QUEUES		16

/*Maximum number of slots available in TX ring*/
#define MAX_TX_RING_SLOTS		8

/*Threshold for a queue to *Enter* Congestion state.
  It is set to 128 frames of size 64 bytes.*/
#define CONG_ENTER_THRESHOLD   (128 * 64)

/*Threshold for a queue to *Exit* Congestion state.
  It is set to 98 frames of size 64 bytes*/
#define CONG_EXIT_THRESHOLD    (98 * 64)

/*! Maximum number of flow distributions per traffic class */
#define MAX_DIST_PER_TC 16

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

#define DPAA2_TX_CKSUM_OFFLOAD_MASK ( \
		PKT_TX_IP_CKSUM | \
		PKT_TX_TCP_CKSUM | \
		PKT_TX_UDP_CKSUM)

struct dpaa2_queue {
	void *dev;
	int32_t eventfd;	/*!< Event Fd of this queue */
	uint32_t fqid;	/*!< Unique ID of this queue */
	uint8_t tc_index;	/*!< traffic class identifier */
	uint16_t flow_id;	/*!< To be used by DPAA2 frmework */
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t err_pkts;
	union {
		struct queue_storage_info_t *q_storage;
		struct qbman_result *cscn;
	};
};

struct dpaa2_dev_priv {
	void *hw;
	int32_t hw_id;
	int32_t qdid;
	uint16_t token;
	uint8_t nb_tx_queues;
	uint8_t nb_rx_queues;
	void *rx_vq[MAX_RX_QUEUES];
	void *tx_vq[MAX_TX_QUEUES];

	struct dpaa2_bp_list *bp_list; /**<Attached buffer pool list */
	uint16_t num_dist_per_tc[MAX_TCS];

	uint8_t max_unicast_filters;
	uint8_t max_multicast_filters;
	uint8_t max_vlan_filters;
	uint8_t num_tc;
	uint32_t options;
};

struct swp_active_dqs {
	struct qbman_result *global_active_dqs;
	uint64_t reserved[7];
};

#define NUM_MAX_SWP 64

struct swp_active_dqs global_active_dqs_list[NUM_MAX_SWP];

static struct rte_pci_id pci_id_dpaa2_map[] = {
	{RTE_PCI_DEVICE(FSL_VENDOR_ID, FSL_MC_DPNI_DEVID)},
};

extern struct bp_info bpid_info[MAX_BPID];

static void dpaa2_print_stats(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint64_t value;

	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_ING_FRAME, &value);
	printf("Rx packets: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_ING_BYTE, &value);
	printf("Rx bytes: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_ING_MCAST_FRAME, &value);
	printf("Rx Multicast: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_ING_FRAME_DROP, &value);
	printf("Rx dropped: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_ING_FRAME_DISCARD, &value);
	printf("Rx discarded: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_EGR_FRAME, &value);
	printf("Tx packets: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_EGR_BYTE, &value);
	printf("Tx bytes: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token, DPNI_CNT_EGR_FRAME_DISCARD, &value);
	printf("Tx dropped: %ld\n", value);
}

/**
 * Atomically reads the link status information from global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */
static inline int
rte_dpni_dev_atomic_read_link_status(struct rte_eth_dev *dev,
				     struct rte_eth_link *link)
{
	struct rte_eth_link *dst = link;
	struct rte_eth_link *src = &dev->data->dev_link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
				*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

/**
 * Atomically writes the link status information into global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */
static inline int
rte_dpni_dev_atomic_write_link_status(struct rte_eth_dev *dev,
				      struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
				*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

static inline uint32_t __attribute__((hot))
dpaa2_rx_parse(uint64_t hw_annot_addr)
{
	uint32_t pkt_type = RTE_PTYPE_UNKNOWN;
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	PMD_DRV_LOG(DEBUG, "\n 1 annotation = 0x%lx   ", annotation->word4);

	if (BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT)) {
		pkt_type = RTE_PTYPE_L2_ETHER_ARP;
		goto parse_done;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT))
		pkt_type = RTE_PTYPE_L2_ETHER;
	else
		goto parse_done;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT |
				L3_IPV4_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV4;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
				L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV4_EXT;

	} else if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT |
				L3_IPV6_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV6;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
				L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV6_EXT;
	} else
		goto parse_done;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_FIRST_FRAGMENT |
				L3_IP_1_MORE_FRAGMENT |
				L3_IP_N_FIRST_FRAGMENT |
				L3_IP_N_MORE_FRAGMENT)) {
		pkt_type |= RTE_PTYPE_L4_FRAG;
		goto parse_done;
	} else
		pkt_type |= RTE_PTYPE_L4_NONFRAG;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_UDP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_TCP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_SCTP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_ICMP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_UNKNOWN_PROTOCOL))
		pkt_type |= RTE_PTYPE_UNKNOWN;

parse_done:
	return pkt_type;
}

static inline void __attribute__((hot))
dpaa2_rx_offload(uint64_t hw_annot_addr, struct rte_mbuf *mbuf)
{
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT | L2_VLAN_N_PRESENT))
		mbuf->ol_flags |= PKT_RX_VLAN_PKT;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= PKT_RX_IP_CKSUM_BAD;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= PKT_RX_L4_CKSUM_BAD;
}

static inline struct rte_mbuf * __attribute__((hot))
eth_fd_to_mbuf(const struct qbman_fd *fd)
{
	struct rte_mbuf *mbuf = DPAA2_INLINE_MBUF_FROM_BUF(
		DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd)),
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);

	/* need to repopulated some of the fields,
	as they may have changed in last transmission*/
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->data_off = DPAA2_GET_FD_OFFSET(fd);
	mbuf->data_len = DPAA2_GET_FD_LEN(fd);
	mbuf->pkt_len = mbuf->data_len;

	/* Parse the packet */
	/* parse results are after the private - sw annotation area */
	mbuf->packet_type = dpaa2_rx_parse(
			(uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd))
			 + DPAA2_FD_PTA_SIZE);

	dpaa2_rx_offload((uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd))
			 + DPAA2_FD_PTA_SIZE, mbuf);

	mbuf->next = NULL;
	rte_mbuf_refcnt_set(mbuf, 1);

	PMD_DRV_LOG(DEBUG, "to mbuf - mbuf =%p, mbuf->buf_addr =%p, off = %d,"
		"fd_off=%d fd =%lx, meta = %d  bpid =%d, len=%d\n",
		mbuf, mbuf->buf_addr, mbuf->data_off,
		DPAA2_GET_FD_OFFSET(fd), DPAA2_GET_FD_ADDR(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_BPID(fd), DPAA2_GET_FD_LEN(fd));

	return mbuf;
}

static inline void __attribute__((hot))
eth_check_offload(struct rte_mbuf *mbuf __rte_unused,
				struct qbman_fd *fd __rte_unused)
{
	/*if (mbuf->ol_flags & DPAA2_TX_CKSUM_OFFLOAD_MASK) {
		todo - enable checksum validation on per packet basis
	}*/
}

static void __attribute__ ((noinline)) __attribute__((hot))
eth_mbuf_to_fd(struct rte_mbuf *mbuf,
	struct qbman_fd *fd, uint16_t bpid)
{
	/*Resetting the buffer pool id and offset field*/
	fd->simple.bpid_offset = 0;

	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(mbuf));
	DPAA2_SET_FD_LEN(fd, mbuf->data_len);
	DPAA2_SET_FD_BPID(fd, bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->data_off);
	DPAA2_SET_FD_ASAL(fd, DPAA2_ASAL_VAL);

	PMD_DRV_LOG(DEBUG, "mbuf =%p, mbuf->buf_addr =%p, off = %d,"
		"fd_off=%d fd =%lx, meta = %d  bpid =%d, len=%d\n",
		mbuf, mbuf->buf_addr, mbuf->data_off,
		DPAA2_GET_FD_OFFSET(fd), DPAA2_GET_FD_ADDR(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_BPID(fd), DPAA2_GET_FD_LEN(fd));

	eth_check_offload (mbuf, fd);

	return;
}

static int
eth_copy_mbuf_to_fd(struct rte_mbuf *mbuf,
	struct qbman_fd *fd, uint16_t bpid)
{
	struct rte_mbuf *m;
	void *mb = NULL;

	if (hw_mbuf_alloc_bulk(bpid_info[bpid].bp_list->buf_pool.mp, &mb, 1)) {
		PMD_DRV_LOG(WARNING, "Unable to allocated DPAA2 buffer");
		rte_pktmbuf_free(mbuf);
		return -1;
	}
	m = (struct rte_mbuf *)mb;
	memcpy((char *)m->buf_addr + mbuf->data_off,
	       (void *)((char *)mbuf->buf_addr + mbuf->data_off),
		mbuf->pkt_len);

	/* Copy required fields */
	m->data_off = mbuf->data_off;
	m->ol_flags = mbuf->ol_flags;
	m->packet_type = mbuf->packet_type;
	m->tx_offload = mbuf->tx_offload;

	/*Resetting the buffer pool id and offset field*/
	fd->simple.bpid_offset = 0;

	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(m));
	DPAA2_SET_FD_LEN(fd, mbuf->data_len);
	DPAA2_SET_FD_BPID(fd, bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->data_off);
	DPAA2_SET_FD_ASAL(fd, DPAA2_ASAL_VAL);

	eth_check_offload(m, fd);

	PMD_DRV_LOG(DEBUG, "\nmbuf %p BMAN buf addr %p",
		    (void *)mbuf, mbuf->buf_addr);

	PMD_DRV_LOG(DEBUG, "\nfdaddr =%lx bpid =%d meta =%d off =%d, len =%d\n",
		    DPAA2_GET_FD_ADDR(fd),
		DPAA2_GET_FD_BPID(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_OFFSET(fd),
		DPAA2_GET_FD_LEN(fd));
	/*free the original packet */
	rte_pktmbuf_free(mbuf);

	return 0;
}

static uint16_t
eth_dpaa2_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0;
	uint8_t is_last = 0, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct rte_eth_dev *dev = dpaa2_q->dev;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;
	dq_storage = dpaa2_q->q_storage->dq_storage[0];

	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	/* todo optimization - we can have dq_storage_phys available*/
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
				    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);

	/*Issue a volatile dequeue command. */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			PMD_DRV_LOG(ERR, "VDQ command is not issued."
				"QBMAN is busy\n");
			/* Portal was busy, try again */
			continue;
		}
		break;
	};

	/* Receive the packets till Last Dequeue entry is found with
	   respect to the above issues PULL command.
	 */
	while (!is_last) {
		/*Check if the previous issued command is completed.
		*Also seems like the SWP is shared between the Ethernet Driver
		*and the SEC driver.*/
		while (!qbman_check_command_complete(swp, dq_storage))
			;
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;
		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				PMD_DRV_LOG(DEBUG, "No frame is delivered\n");
				continue;
			}
		}

		fd = qbman_result_DQ_fd(dq_storage);
		bufs[num_rx] = eth_fd_to_mbuf(fd);
		bufs[num_rx]->port = dev->data->port_id;

		num_rx++;
		dq_storage++;
	} /* End of Packet Rx loop */

	dpaa2_q->rx_pkts += num_rx;

	PMD_DRV_LOG(INFO, "Ethernet Received %d Packets\n", num_rx);
	/*Return the total number of packets received to DPAA2 app*/
	return num_rx;
}

inline int check_swp_active_dqs(uint16_t dpio_dev_index)
{
	if(global_active_dqs_list[dpio_dev_index].global_active_dqs!=NULL)
		return 1;
	return 0;
}

inline void clear_swp_active_dqs(uint16_t dpio_dev_index)
{
	global_active_dqs_list[dpio_dev_index].global_active_dqs = NULL;
}

inline struct qbman_result* get_swp_active_dqs(uint16_t dpio_dev_index)
{
	return global_active_dqs_list[dpio_dev_index].global_active_dqs;
}

inline void set_swp_active_dqs(uint16_t dpio_dev_index, struct qbman_result *dqs)
{
	global_active_dqs_list[dpio_dev_index].global_active_dqs = dqs;
}

static uint16_t
eth_dpaa2_prefetch_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0;
	uint8_t is_last = 0, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd[16];
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage = dpaa2_q->q_storage;
	struct rte_eth_dev *dev = dpaa2_q->dev;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;
	if (!q_storage->active_dqs) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
					    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(thread_io_info.dpio_dev->index)) {
			while (!qbman_check_command_complete(swp, get_swp_active_dqs(thread_io_info.dpio_dev->index)))
				;
			clear_swp_active_dqs(thread_io_info.dpio_dev->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				PMD_DRV_LOG(WARNING, "VDQ command is not issued."
					    "QBMAN is busy\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = thread_io_info.dpio_dev->index;
		set_swp_active_dqs(thread_io_info.dpio_dev->index, dq_storage);
	}
	dq_storage = q_storage->active_dqs;
	while (!qbman_check_command_complete(swp, dq_storage))
		;
	if(dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		struct rte_mbuf *mbuf;

		while (!qbman_result_has_new_result(swp, dq_storage))
			;
		rte_prefetch0((void *)((uint64_t)(dq_storage + 1)));
		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				PMD_DRV_LOG2(DEBUG, "No frame is delivered\n");
				continue;
			}
		}
		fd[num_rx] = qbman_result_DQ_fd(dq_storage);
		mbuf = (struct rte_mbuf *)DPAA2_IOVA_TO_VADDR(
				DPAA2_GET_FD_ADDR(fd[num_rx])
				 - bpid_info[DPAA2_GET_FD_BPID(fd[num_rx])].meta_data_size);
		/* Prefeth mbuf */
		rte_prefetch0(mbuf);
		/* Prefetch Annotation address from where we get parse results */
		rte_prefetch0((void *)((uint64_t)DPAA2_GET_FD_ADDR(fd[num_rx]) + DPAA2_FD_PTA_SIZE + 16));
		/*Prefetch Data buffer*/
		/* rte_prefetch0((void *)((uint64_t)DPAA2_GET_FD_ADDR(fd[num_rx]) + DPAA2_GET_FD_OFFSET(fd[num_rx]))); */

		bufs[num_rx] = eth_fd_to_mbuf(fd[num_rx]);
		bufs[num_rx]->port = dev->data->port_id;

		dq_storage++;
		num_rx++;
		
	} /* End of Packet Rx loop */

	if (check_swp_active_dqs(thread_io_info.dpio_dev->index)) {
		while (!qbman_check_command_complete(swp, get_swp_active_dqs(thread_io_info.dpio_dev->index)))
			;
		clear_swp_active_dqs(thread_io_info.dpio_dev->index);
	}
	q_storage->toggle ^= 1;
	dq_storage = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
				    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
	/*Issue a volatile dequeue command. */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			PMD_DRV_LOG(WARNING, "VDQ command is not issued."
				"QBMAN is busy\n");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage;
	q_storage->active_dpio_id = thread_io_info.dpio_dev->index;
	set_swp_active_dqs(thread_io_info.dpio_dev->index, dq_storage);

	dpaa2_q->rx_pkts += num_rx;

	PMD_DRV_LOG2(INFO, "Ethernet Received %d Packets\n", num_rx);
	/*Return the total number of packets received to DPAA2 app*/
	return num_rx;
}

/*
 * Callback to handle sending packets through a real NIC.
 */
static uint16_t
eth_dpaa2_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function to transmit the frames to given device and VQ*/
	uint32_t loop;
	int32_t ret;
#ifdef QBMAN_MULTI_TX
	struct qbman_fd fd_arr[8];
	uint32_t frames_to_send;
#else
	struct qbman_fd fd;
#endif
	struct rte_mempool *mp;
	struct qbman_eq_desc eqdesc;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_swp *swp;
	uint16_t num_tx = 0;
	uint16_t bpid;
	struct rte_eth_dev *dev = dpaa2_q->dev;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;

	PMD_DRV_LOG(DEBUG, "===> dev =%p, fqid =%d", dev, dpaa2_q->fqid);

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);
	qbman_eq_desc_set_qd(&eqdesc, priv->qdid,
			     dpaa2_q->flow_id, dpaa2_q->tc_index);

	/*Clear the unused FD fields before sending*/
#ifdef QBMAN_MULTI_TX
	while (nb_pkts) {
#ifdef DPAA2_CGR_SUPPORT
		/*Check if the queue is congested*/
		if (qbman_result_is_CSCN(dpaa2_q->cscn))
			goto skip_tx;
#endif
		frames_to_send = (nb_pkts >> 3) ? MAX_TX_RING_SLOTS : nb_pkts;

		for (loop = 0; loop < frames_to_send; loop++) {
			fd_arr[loop].simple.frc = 0;
			DPAA2_RESET_FD_CTRL((&fd_arr[loop]));
			DPAA2_SET_FD_FLC((&fd_arr[loop]), NULL);
			mp = (*bufs)->pool;
			/* Not a hw_pkt pool allocated frame */
			if (mp && !(mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
				printf("\n non hw offload bufffer ");
				/* alloc should be from the default buffer pool
				attached to this interface */
				if (priv->bp_list) {
					bpid = priv->bp_list->buf_pool.bpid;
				} else {
					printf("\n ??? why no bpool attached");
					num_tx = 0;
					goto skip_tx;
				}
				if (eth_copy_mbuf_to_fd(*bufs, &fd_arr[loop], bpid)) {
					bufs++;
					continue;
				}
			} else {
				RTE_ASSERT(mp);
				bpid = mempool_to_bpid(mp);
				eth_mbuf_to_fd(*bufs, &fd_arr[loop], bpid);
			}
			bufs++;
		}
		loop = 0;
		while (loop < frames_to_send) {
			loop += qbman_swp_send_multiple(swp, &eqdesc,
					&fd_arr[loop], frames_to_send - loop);
		}

		num_tx += frames_to_send;
		dpaa2_q->tx_pkts += frames_to_send;
		nb_pkts -= frames_to_send;
	}
#else
#ifdef DPAA2_CGR_SUPPORT
	/*Check if the queue is congested*/
	if(qbman_result_is_CSCN(dpaa2_q->cscn))
		goto skip_tx;
#endif

	fd.simple.frc = 0;
	DPAA2_RESET_FD_CTRL((&fd));
	DPAA2_SET_FD_FLC((&fd), NULL);
	loop = 0;

	while (loop < nb_pkts) {
		/*Prepare each packet which is to be sent*/
		mp = bufs[loop]->pool;
		/* Not a hw_pkt pool allocated frame */
		if (mp && !(mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
			/* alloc should be from the default buffer pool
			attached to this interface */
			if (priv->bp_list) {
				bpid = priv->bp_list->buf_pool.bpid;
			} else {
				/* Buffer not from offloaded area as well as
				* lacks buffer pool identifier. Cannot
				* continue.
				*/
				PMD_DRV_LOG(ERR, "No Buffer pool "
						"attached.\n");
				num_tx = 0;
				goto skip_tx;
			}

			if (eth_copy_mbuf_to_fd(bufs[loop], &fd, bpid)) {
				loop++;
				continue;
			}
		} else {
			RTE_ASSERT(mp);
			bpid = mempool_to_bpid(mp);
			eth_mbuf_to_fd(bufs[loop], &fd, bpid);
		}
		/*Enqueue a single packet to the QBMAN*/
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				PMD_DRV_LOG(DEBUG, "Error in transmiting the frame\n");
			}
		} while (ret != 0);

		/* Free the buffer shell */
		/* rte_pktmbuf_free(bufs[loop]); */
		num_tx++; loop++;
	}
	dpaa2_q->tx_pkts += num_tx;
	dpaa2_q->err_pkts += nb_pkts - num_tx;
#endif
skip_tx:
	return num_tx;
}

static int
dpaa2_vlan_stripping_set(struct rte_eth_dev *dev, int on)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -1;
	}

	ret = dpni_set_vlan_removal(dpni, CMD_PRI_LOW, priv->token, on);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to dpni_set_vlan_removal hwid =%d",
			    priv->hw_id);
	return ret;
}

static int
dpaa2_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -1;
	}

	if (on)
		ret = dpni_add_vlan_id(dpni, CMD_PRI_LOW, priv->token, vlan_id);
	else
		ret = dpni_remove_vlan_id(dpni, CMD_PRI_LOW, priv->token, vlan_id);

	if (ret < 0)
		PMD_DRV_LOG(ERR, "ret = %d Unable to add/rem vlan %d  hwid =%d",
			    ret, vlan_id, priv->hw_id);

	/*todo this should on global basis */
/*	ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, on);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to set vlan filter");
*/	return ret;
}

static void
dpaa2_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;

	if (mask & ETH_VLAN_FILTER_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_filter)
			ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, TRUE);
		else
			ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, FALSE);
		if (ret < 0)
			PMD_DRV_LOG(ERR, "ret = %d Unable to set vlan filter", ret);
	}

	if (mask & ETH_VLAN_STRIP_MASK) {
		/* Enable or disable VLAN stripping */
		if (dev->data->dev_conf.rxmode.hw_vlan_strip)
			dpaa2_vlan_stripping_set(dev, TRUE);
		else
			dpaa2_vlan_stripping_set(dev, FALSE);
	}

	if (mask & ETH_VLAN_EXTEND_MASK) {
		PMD_INIT_FUNC_TRACE();
/*		if (dev->data->dev_conf.rxmode.hw_vlan_extend)
			i40e_vsi_config_double_vlan(vsi, TRUE);
		else
			i40e_vsi_config_double_vlan(vsi, FALSE);
*/	}
}

static void
dpaa2_eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	dev_info->driver_name = drivername;
	dev_info->if_index = priv->hw_id;
	dev_info->max_mac_addrs = priv->max_unicast_filters;
	dev_info->max_rx_pktlen = DPAA2_MAX_RX_PKT_LEN;
	dev_info->max_rx_queues = (uint16_t)priv->nb_rx_queues;
	dev_info->max_tx_queues = (uint16_t)priv->nb_tx_queues;
	dev_info->min_rx_bufsize = DPAA2_MIN_RX_BUF_SIZE;
	dev_info->pci_dev = dev->pci_dev;
	dev_info->rx_offload_capa =
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM;
	dev_info->tx_offload_capa =
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM |
		DEV_TX_OFFLOAD_SCTP_CKSUM;
}

static int
dpaa2_alloc_rx_tx_queues(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint8_t tc_idx;
	uint16_t dist_idx;
	uint32_t vq_id;
	struct dpaa2_queue *mc_q, *mcq;
	uint32_t tot_queues;
	int i;
	struct dpaa2_queue *dpaa2_q;

	tot_queues = priv->nb_rx_queues + priv->nb_tx_queues;
	mc_q = rte_malloc(NULL, sizeof(struct dpaa2_queue) * tot_queues,
			  RTE_CACHE_LINE_SIZE);
	if (!mc_q) {
		PMD_DRV_LOG(ERR, "malloc failed for rx/tx queues\n");
		return -1;
	}

	for (i = 0; i < priv->nb_rx_queues; i++) {
		mc_q->dev = dev;
		priv->rx_vq[i] = mc_q++;
		dpaa2_q = (struct dpaa2_queue *)priv->rx_vq[i];
		dpaa2_q->q_storage = rte_malloc("dq_storage",
			sizeof(struct queue_storage_info_t),
			RTE_CACHE_LINE_SIZE);
		if (!dpaa2_q->q_storage)
			goto fail;

		memset(dpaa2_q->q_storage, 0, sizeof(struct queue_storage_info_t));
	}

	for (i = 0; i < priv->nb_tx_queues; i++) {
		mc_q->dev = dev;
		mc_q->flow_id = DPNI_NEW_FLOW_ID;
		priv->tx_vq[i] = mc_q++;
	}

	vq_id = 0;
	for (tc_idx = 0; tc_idx < priv->num_tc; tc_idx++) {
		for (dist_idx = 0; dist_idx < priv->num_dist_per_tc[tc_idx]; dist_idx++) {
			mcq = (struct dpaa2_queue *)priv->rx_vq[vq_id];
			mcq->tc_index = tc_idx;
			mcq->flow_id = dist_idx;
			vq_id++;
		}
	}

	return 0;
fail:
	 i -= 1;
	while (i >= 0) {
		dpaa2_q = (struct dpaa2_queue *)priv->rx_vq[i];
		rte_free(dpaa2_q->q_storage);
	}
	return -1;
}

static void dpaa2_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg)
{
	uint32_t loop = 0, i = 0, dist_field = 0;
	int l2_configured = 0, l3_configured = 0;
	int l4_configured = 0, sctp_configured = 0;

	memset(kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	while (req_dist_set) {
		if (req_dist_set % 2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case ETH_RSS_L2_PAYLOAD:

				if (l2_configured)
					break;
				l2_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_ETH;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_ETH_TYPE;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
			break;

			case ETH_RSS_IPV4:
			case ETH_RSS_FRAG_IPV4:
			case ETH_RSS_NONFRAG_IPV4_OTHER:
			case ETH_RSS_IPV6:
			case ETH_RSS_FRAG_IPV6:
			case ETH_RSS_NONFRAG_IPV6_OTHER:
			case ETH_RSS_IPV6_EX:

				if (l3_configured)
					break;
				l3_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_DST;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_PROTO;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				kg_cfg->num_extracts++;
				i++;
			break;

			case ETH_RSS_NONFRAG_IPV4_TCP:
			case ETH_RSS_NONFRAG_IPV6_TCP:
			case ETH_RSS_NONFRAG_IPV4_UDP:
			case ETH_RSS_NONFRAG_IPV6_UDP:

				if (l4_configured)
					break;
				l4_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			case ETH_RSS_NONFRAG_IPV4_SCTP:
			case ETH_RSS_NONFRAG_IPV6_SCTP:

				if (sctp_configured)
					break;
				sctp_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_DST;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			default:
				PMD_DRV_LOG(WARNING, "Bad flow distribution option %x\n", dist_field);
			}
		}
		req_dist_set = req_dist_set >> 1;
		loop++;
	}
	kg_cfg->num_extracts = i;
}

static int dpaa2_setup_flow_distribution(struct rte_eth_dev *eth_dev,
					 uint32_t req_dist_set)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret, tc_index = 0;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		PMD_DRV_LOG(ERR, "Memory unavaialble\n");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	dpaa2_distset_to_dpkg_profile_cfg(req_dist_set, &kg_cfg);
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = eth_dev->data->nb_rx_queues;
	tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;

	ret = dpni_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Unable to prepare extract parameters\n");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Setting distribution for Rx failed with"
			"err code: %d\n", ret);
		return ret;
	}

	return 0;
}

static int
dpaa2_remove_flow_distribution(struct rte_eth_dev *eth_dev, uint8_t tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		PMD_DRV_LOG(ERR, "Memory unavaialble\n");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = 0;
	tc_cfg.dist_mode = DPNI_DIST_MODE_NONE;

	ret = dpni_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Unable to prepare extract parameters\n");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Setting distribution for Rx failed with"
			"err code: %d\n", ret);
		return ret;
	}
	return ret;
}

static int
dpaa2_alloc_dq_storage(struct queue_storage_info_t *q_storage)
{
	int i = 0;

	for (i = 0; i < NUM_DQS_PER_QUEUE; i++) {
		q_storage->dq_storage[i] = rte_malloc(NULL,
		NUM_MAX_RECV_FRAMES * sizeof(struct qbman_result),
		RTE_CACHE_LINE_SIZE);
		if (!q_storage->dq_storage[i])
			goto fail;
		/*setting toggle for initial condition*/
		q_storage->toggle = -1;
	}
	return 0;
fail:
	i -= 1;
	while (i >= 0)
		rte_free(q_storage->dq_storage[i]);

	return -1;
}

static int
dpaa2_eth_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct rte_eth_conf *eth_conf = &data->dev_conf;
	struct dpaa2_queue *dpaa2_q;
	int i, ret;

	for (i = 0; i < data->nb_rx_queues; i++) {
		 data->rx_queues[i] = priv->rx_vq[i];
		 dpaa2_q = (struct dpaa2_queue *)data->rx_queues[i];
		 if (dpaa2_alloc_dq_storage(dpaa2_q->q_storage))
			 return -1;
	}

	for (i = 0; i < data->nb_tx_queues; i++) {
		 data->tx_queues[i] = priv->tx_vq[i];
		 dpaa2_q = (struct dpaa2_queue *)data->tx_queues[i];
		 dpaa2_q->cscn = rte_malloc(NULL, sizeof(struct qbman_result), 16);
		 if (!dpaa2_q->cscn)
			 goto fail_tx_queue;
	}

	/* Check for correct configuration */
	if (eth_conf->rxmode.mq_mode != ETH_MQ_RX_RSS &&
	    data->nb_rx_queues > 1) {
		PMD_DRV_LOG(ERR, "Distribution is not enabled, "
			"but Rx queues more than 1\n");
		return -1;
	}

	if (eth_conf->rxmode.mq_mode == ETH_MQ_RX_RSS) {
		/* Return in case number of Rx queues is 1 */
		if (data->nb_rx_queues == 1)
			return 0;
		ret = dpaa2_setup_flow_distribution(dev,
						    eth_conf->rx_adv_conf.rss_conf.rss_hf);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpaa2_setup_flow_distribution failed\n");
			return ret;
		}
	}

	return 0;
 fail_tx_queue:
	i -= 1;
	while (i >= 0) {
		dpaa2_q = (struct dpaa2_queue *)data->tx_queues[i];
		rte_free(dpaa2_q->cscn);
	}
	return -1;
}

static int dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv,
				void *blist)
{
	/* Function to attach a DPNI with a buffer pool list. Buffer pool list
	 * handle is passed in blist.
	 */
	int32_t retcode;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_pools_cfg bpool_cfg;
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)blist;
	struct dpni_buffer_layout layout;
	int tot_size;

	/* ... rx buffer layout .
	Check alignment for buffer layouts first*/

	/* ... rx buffer layout ... */
	tot_size = DPAA2_HW_BUF_RESERVE + RTE_PKTMBUF_HEADROOM;
	tot_size = RTE_ALIGN_CEIL(tot_size,
				       DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM;

	layout.data_head_room = tot_size - DPAA2_FD_PTA_SIZE - DPAA2_MBUF_HW_ANNOTATION;
	retcode = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token,
					    &layout);
	if (retcode) {
		PMD_DRV_LOG(ERR, "Err(%d) in setting rx buffer layout\n", retcode);
		return retcode;
	}

	/*Attach buffer pool to the network interface as described by the user*/
	bpool_cfg.num_dpbp = 1;
	bpool_cfg.pools[0].dpbp_id = bp_list->buf_pool.dpbp_node->dpbp_id;
	bpool_cfg.pools[0].backup_pool = 0;
	bpool_cfg.pools[0].buffer_size =
		RTE_ALIGN_CEIL(bp_list->buf_pool.size,
				    256 /*DPAA2_PACKET_LAYOUT_ALIGN*/);

	retcode = dpni_set_pools(dpni, CMD_PRI_LOW, priv->token, &bpool_cfg);
	if (retcode != 0) {
		PMD_DRV_LOG(ERR, "Error in attaching the buffer pool list"
				"bpid = %d Error code = %d\n",
				bpool_cfg.pools[0].dpbp_id, retcode);
		return retcode;
	}

	priv->bp_list = bp_list;
	return 0;
}

/* Function to setup RX flow information. It contains traffic class ID,
 * flow ID, destination configuration etc.
 */
static int
dpaa2_rx_queue_setup(struct rte_eth_dev *dev,
		     uint16_t rx_queue_id,
			uint16_t nb_rx_desc __rte_unused,
			unsigned int socket_id __rte_unused,
			const struct rte_eth_rxconf *rx_conf __rte_unused,
			struct rte_mempool *mb_pool)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpaa2_queue *dpaa2_q;
	struct dpni_queue_cfg cfg;
	uint8_t tc_id, flow_id;
	uint32_t bpid;
	int ret;

	PMD_DRV_LOG(INFO, "dev =%p, queue =%d, pool = %p, conf =%p",
		    dev, rx_queue_id, mb_pool, rx_conf);

	if (!priv->bp_list || priv->bp_list->mp != mb_pool) {
		RTE_VERIFY(mb_pool->pool_data);
		bpid = mempool_to_bpid(mb_pool);
		ret = dpaa2_attach_bp_list(priv,
				   bpid_info[bpid].bp_list);
		if (ret)
			return ret;
	}
	dpaa2_q = (struct dpaa2_queue *)dev->data->rx_queues[rx_queue_id];

	/*Get the tc id and flow id from given VQ id*/
	tc_id = rx_queue_id / MAX_DIST_PER_TC;
	flow_id = rx_queue_id % MAX_DIST_PER_TC;
	memset(&cfg, 0, sizeof(struct dpni_queue_cfg));

	cfg.options = cfg.options | DPNI_QUEUE_OPT_USER_CTX;

#ifdef DPAA2_STASHING
	cfg.options = cfg.options | DPNI_QUEUE_OPT_FLC;
#endif

	cfg.user_ctx = (uint64_t)(dpaa2_q);
#ifdef DPAA2_STASHING
	cfg.flc_cfg.flc_type = DPNI_FLC_STASH;
	cfg.flc_cfg.frame_data_size = DPNI_STASH_SIZE_64B;
	/* Enabling Annotation stashing */
	cfg.options |= DPNI_FLC_STASH_FRAME_ANNOTATION;
	cfg.flc_cfg.options = DPNI_FLC_STASH_FRAME_ANNOTATION;
#endif
	ret = dpni_set_rx_flow(dpni, CMD_PRI_LOW, priv->token,
			       tc_id, flow_id, &cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting the rx flow: = %d\n", ret);
		return -1;
	}
	return 0;
}

static int
dpaa2_tx_queue_setup(struct rte_eth_dev *dev,
		     uint16_t tx_queue_id,
			uint16_t nb_tx_desc __rte_unused,
			unsigned int socket_id __rte_unused,
			const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)
		dev->data->tx_queues[tx_queue_id];
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_tx_flow_cfg cfg;
	struct dpni_tx_conf_cfg tx_conf_cfg;
#ifdef DPAA2_CGR_SUPPORT
	struct dpni_congestion_notification_cfg cong_notif_cfg;
#endif
	uint32_t tc_idx;
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* Return if queue already configured */
	if (dpaa2_q->flow_id != DPNI_NEW_FLOW_ID)
		return 0;

	memset(&cfg, 0, sizeof(struct dpni_tx_flow_cfg));
	cfg.l3_chksum_gen = 1;
	cfg.options = DPNI_TX_FLOW_OPT_L3_CHKSUM_GEN;
	cfg.l4_chksum_gen = 1;
	cfg.options |= DPNI_TX_FLOW_OPT_L4_CHKSUM_GEN;
	memset(&tx_conf_cfg, 0, sizeof(struct dpni_tx_conf_cfg));
	tx_conf_cfg.errors_only = TRUE;

	/*
	if (action & DPAA2BUF_TX_CONF_REQUIRED) {
		cfg.options = DPNI_TX_FLOW_OPT_TX_CONF_ERROR;
		cfg.use_common_tx_conf_queue =
				((action & DPAA2BUF_TX_CONF_ERR_ON_COMMON_Q) ?
								TRUE : FALSE);
		tx_conf_cfg.errors_only = FALSE;
	}*/

	if (priv->num_tc == 1)
		tc_idx = 0;
	else
		tc_idx = tx_queue_id;

	ret = dpni_set_tx_flow(dpni, CMD_PRI_LOW, priv->token,
			       &(dpaa2_q->flow_id), &cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting the tx flow:"
					"ErrorCode = %x\n", ret);
			return -1;
	}
	/*Set tx-conf and error configuration*/
	ret = dpni_set_tx_conf(dpni, CMD_PRI_LOW, priv->token,
			       dpaa2_q->flow_id, &tx_conf_cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting tx conf settings: "
					"ErrorCode = %x", ret);
		return -1;
	}

	if (tx_queue_id == 0) {
		/*Set tx-conf and error configuration*/
		ret = dpni_set_tx_conf(dpni, CMD_PRI_LOW, priv->token,
				       DPNI_COMMON_TX_CONF, &tx_conf_cfg);
		if (ret) {
			PMD_DRV_LOG(ERR, "Error in setting tx conf settings: "
						"ErrorCode = %x", ret);
			return -1;
		}
	}
	dpaa2_q->tc_index = tc_idx;

#ifdef DPAA2_CGR_SUPPORT
	cong_notif_cfg.units = DPNI_CONGESTION_UNIT_BYTES;
	/*Notify about congestion when the queue size is 128 frames with each \
	  frame 64 bytes size*/
	cong_notif_cfg.threshold_entry = CONG_ENTER_THRESHOLD;
	/*Notify that the queue is not congested when the number of frames in \
	  the queue is below this thershold.
	  TODO: Check if this value is the optimum value for better performance*/
	cong_notif_cfg.threshold_exit = CONG_EXIT_THRESHOLD;
	cong_notif_cfg.message_ctx = 0;
	cong_notif_cfg.message_iova = (uint64_t)dpaa2_q->cscn;
	cong_notif_cfg.dest_cfg.dest_type = DPNI_DEST_NONE;
	cong_notif_cfg.options = DPNI_CONG_OPT_WRITE_MEM_ON_ENTER |
		DPNI_CONG_OPT_WRITE_MEM_ON_EXIT | DPNI_CONG_OPT_COHERENT_WRITE;

	ret = dpni_set_tx_tc_congestion_notification(dpni, CMD_PRI_LOW,
						     priv->token,
						     tc_idx, &cong_notif_cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting tx congestion notification "
			    "settings: ErrorCode = %x", ret);
		return -1;
	}
#endif
	return 0;
}

void
dpaa2_rx_queue_release(void *q)
{
	printf("\n(%s) called for 1=%p\n", __func__, q);
	return;
}

void
dpaa2_tx_queue_release(void *q)
{
	printf("\n(%s) called for 1=%p\n", __func__, q);
	return;
}

static const uint32_t *
dpaa2_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == eth_dpaa2_prefetch_rx ||
	    dev->rx_pkt_burst == eth_dpaa2_rx)
		return ptypes;
	return NULL;
}

static int
dpaa2_dev_start(struct rte_eth_dev *dev)
{
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpni_queue_attr cfg;
	struct dpni_error_cfg	err_cfg;
	uint16_t qdid;
	struct dpaa2_queue *dpaa2_q;
	int ret, i, mask = 0;

	PMD_INIT_FUNC_TRACE();

	dev->data->dev_link.link_status = 1;

	ret = dpni_enable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure %d in enabling dpni %d device\n",
			    ret, priv->hw_id);
		return ret;
	}

	ret = dpni_get_qdid(dpni, CMD_PRI_LOW, priv->token, &qdid);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get qdid:ErrorCode = %d\n", ret);
		return ret;
	}
	priv->qdid = qdid;

	for (i = 0; i < data->nb_rx_queues; i++) {
		dpaa2_q = (struct dpaa2_queue *)data->rx_queues[i];
		ret = dpni_get_rx_flow(dpni, CMD_PRI_LOW, priv->token,
				       dpaa2_q->tc_index, dpaa2_q->flow_id, &cfg);
		if (ret) {
			PMD_DRV_LOG(ERR, "Error to get flow "
				"information Error code = %d\n", ret);
			return ret;
		}
		dpaa2_q->fqid = cfg.fqid;
	}
	ret = dpni_set_l3_chksum_validation(dpni, CMD_PRI_LOW,
		priv->token, TRUE);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get l3 csum:ErrorCode = %d\n", ret);
		return ret;
	}

	ret = dpni_set_l4_chksum_validation(dpni, CMD_PRI_LOW,
		priv->token, TRUE);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get l4 csum:ErrorCode = %d\n", ret);
		return ret;
	}

	/*for checksum issue, send them to normal path and set it in annotation */
	err_cfg.errors = DPNI_ERROR_L3CE | DPNI_ERROR_L4CE;

	err_cfg.error_action = DPNI_ERROR_ACTION_CONTINUE;
	err_cfg.set_frame_annotation = TRUE;

	ret = dpni_set_errors_behavior(dpni, CMD_PRI_LOW,
			priv->token, &err_cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to dpni_set_errors_behavior:"
				"code = %d\n", ret);
		return ret;
	}
	/*
	 * VLAN Offload Settings
	 */
	if (priv->options & DPNI_OPT_VLAN_FILTER)
		mask = ETH_VLAN_FILTER_MASK;

	if (priv->options & DPNI_OPT_VLAN_MANIPULATION)
		mask = ETH_VLAN_STRIP_MASK;

	if (mask)
		dpaa2_vlan_offload_set(dev, mask);

	return 0;
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 *
 **********************************************************************/
static void
dpaa2_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;
	struct rte_eth_link link;

	dev->data->dev_link.link_status = 0;

	ret = dpni_disable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in disabling dpni %d device\n", priv->hw_id);
		return;
	}

	/* clear the recorded link status */
	memset(&link, 0, sizeof(link));
	rte_dpni_dev_atomic_write_link_status(dev, &link);
}

static void
dpaa2_dev_close(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;
	struct rte_eth_link link;

	/*Function is reverse of dpaa2_dev_init.
	 * It does the following:
	 * 1. Detach a DPNI from attached resources i.e. buffer pools, dpbp_id.
	 * 2. Close the DPNI device
	 * 3. Free the allocated reqources.
	 */

	/* Clean the device first */
	ret = dpni_reset(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure cleaning dpni device with"
			"error code %d\n", ret);
		return;
	}

	/*Close the device at underlying layer*/
	ret = dpni_close(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure closing dpni device with"
			"error code %d\n", ret);
		return;
	}

	/*Free the allocated memory for ethernet private data and dpni*/
	priv->hw = NULL;
	free(dpni);

	memset(&link, 0, sizeof(link));
	rte_dpni_dev_atomic_write_link_status(dev, &link);
}

static void
dpaa2_dev_promiscuous_enable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, TRUE);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static void
dpaa2_dev_promiscuous_disable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, FALSE);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to disable promiscuous mode");
	return;
}

static void
dpaa2_dev_allmulticast_enable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, true);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static void
dpaa2_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, false);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static int dpaa2_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint32_t frame_size = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -EINVAL;
	}

	/* check that mtu is within the allowed range */
	if ((mtu < ETHER_MIN_MTU) || (frame_size > DPAA2_MAX_RX_PKT_LEN))
		return -EINVAL;

	/* Set the Max Rx frame length as 'mtu' +
	 * Maximum Ethernet header length */
	ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW, priv->token,
					mtu + ETH_VLAN_HLEN);
	if (ret) {
		PMD_DRV_LOG(ERR, "setting the max frame length failed");
		return -1;
	}
	if (priv->options & DPNI_OPT_IPF) {
		ret = dpni_set_mtu(dpni, CMD_PRI_LOW, priv->token, mtu);
		if (ret) {
			PMD_DRV_LOG(ERR, "Setting the MTU failed");
			return -1;
		}
	}

	PMD_DRV_LOG(INFO, "MTU is configured %d for the device\n", mtu);
	return 0;
}

static int
dpaa2_flow_ctrl_set(struct rte_eth_dev *dev  __rte_unused,
			struct rte_eth_fc_conf *fc_conf  __rte_unused)
{
	return 0;
}
static void
dpaa2_dev_add_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr,
		 __rte_unused uint32_t index,
		 __rte_unused uint32_t pool)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_add_mac_addr(dpni, CMD_PRI_LOW,
				priv->token, addr->addr_bytes);
	if (ret) {
		PMD_DRV_LOG(ERR, "Adding the MAC ADDR failed");
	}

	return;
}

static void
dpaa2_dev_remove_mac_addr(struct rte_eth_dev *dev,
			  uint32_t index)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct rte_eth_dev_data *data = dev->data;
	struct ether_addr *macaddr;

	macaddr = &data->mac_addrs[index];

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_remove_mac_addr(dpni, CMD_PRI_LOW,
				   priv->token, macaddr->addr_bytes);
	if (ret) {
		PMD_DRV_LOG(ERR, "Removing the MAC ADDR failed");
	}

	return;
}

static void
dpaa2_dev_set_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_primary_mac_addr(dpni, CMD_PRI_LOW,
					priv->token, addr->addr_bytes);

	if (ret) {
		PMD_DRV_LOG(ERR, "Setting the MAC ADDR failed");
	}

	return;
}

int dpaa2_dev_get_mac_addr(struct rte_eth_dev *dev,
			   struct ether_addr *addr)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -EINVAL;
	}

	ret = dpni_get_primary_mac_addr(dpni, CMD_PRI_LOW,
					priv->token, addr->addr_bytes);

	if (ret) {
		PMD_DRV_LOG(ERR, "Getting the MAC ADDR failed");
	}

	return ret;
}

/*int dpni_clear_mac_filters(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   int unicast,
			   int multicast)

int dpni_set_vlan_insertion(struct fsl_mc_io *mc_io,
			    uint32_t cmd_flags,
			    uint16_t token,
			    int en)

*/

static int dpaa2_timestamp_enable(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = TRUE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp for Rx failed with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW,
					     priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return 0;
}

static int dpaa2_timestamp_disable(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = FALSE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Rx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW,
					     priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return ret;
}

/* return 0 means link status changed, -1 means not changed */
static int
dpaa2_dev_get_link_info(struct rte_eth_dev *dev,
			int wait_to_complete __rte_unused)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct rte_eth_link link, old;
	struct dpni_link_state state = {0};

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return 0;
	}
	memset(&old, 0, sizeof(old));
	rte_dpni_dev_atomic_read_link_status(dev, &old);

	ret = dpni_get_link_state(dpni, CMD_PRI_LOW, priv->token, &state);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "dpni_get_link_state");
		return 0;
	}

	if (state.up == 0) {
		rte_dpni_dev_atomic_write_link_status(dev, &link);
		if (state.up == old.link_status)
			return -1;
		return 0;
	}
	link.link_status = state.up;
	link.link_speed = state.rate;

	if (state.options & DPNI_LINK_OPT_HALF_DUPLEX)
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
	else
		link.link_duplex = ETH_LINK_FULL_DUPLEX;

	rte_dpni_dev_atomic_write_link_status(dev, &link);

	if (link.link_status == old.link_status)
		return -1;

	return 0;
}

static
void dpaa2_dev_stats_get(struct rte_eth_dev *dev,
			 struct rte_eth_stats *stats)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	int32_t  retcode;
	uint64_t value;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	if (!stats) {
		PMD_DRV_LOG(ERR, "stats is NULL");
		return;
	}

	retcode = dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				   DPNI_CNT_ING_FRAME, &value);
	if (retcode)
		goto error;
	stats->ipackets = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BYTE, &value);
	if (retcode)
		goto error;
	stats->ibytes = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DROP, &value);
	if (retcode)
		goto error;
	stats->ierrors = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DISCARD, &value);
	if (retcode)
		goto error;
	stats->ierrors = stats->ierrors + value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME, &value);
	if (retcode)
		goto error;
	stats->opackets = value;
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
			 DPNI_CNT_EGR_BYTE, &value);
	if (retcode)
		goto error;
	stats->obytes = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME_DISCARD, &value);
	if (retcode)
		goto error;
	stats->oerrors = value;

	return;

error:
	PMD_DRV_LOG(ERR, "Operation not completed:Error Code = %d\n", retcode);
	return;
};

static
void dpaa2_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	int32_t  retcode;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BCAST_BYTES, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_MCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_MCAST_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DROP, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DISCARD, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME_DISCARD, 0);
	if (retcode)
		goto error;

	return;

error:
	PMD_DRV_LOG(ERR, "Operation not completed:Error Code = %d\n", retcode);
	return;
};

static struct eth_dev_ops ops = {
	.dev_configure	      = dpaa2_eth_dev_configure,
	.dev_start	      = dpaa2_dev_start,
	.dev_stop	      = dpaa2_dev_stop,
	.dev_close	      = dpaa2_dev_close,
	.promiscuous_enable   = dpaa2_dev_promiscuous_enable,
	.promiscuous_disable  = dpaa2_dev_promiscuous_disable,
	.allmulticast_enable  = dpaa2_dev_allmulticast_enable,
	.allmulticast_disable = dpaa2_dev_allmulticast_disable,
	.dev_set_link_up      = NULL,
	.dev_set_link_down    = NULL,
	.link_update	      = dpaa2_dev_get_link_info,
	.stats_get	      = dpaa2_dev_stats_get,
	.stats_reset	      = dpaa2_dev_stats_reset,
	.dev_infos_get	      = dpaa2_eth_dev_info,
	.dev_supported_ptypes_get = dpaa2_supported_ptypes_get,
	.mtu_set	      = dpaa2_dev_mtu_set,
	.vlan_filter_set      = dpaa2_vlan_filter_set,
	.vlan_tpid_set        = NULL,
	.vlan_offload_set     = dpaa2_vlan_offload_set,
	.vlan_strip_queue_set = NULL,
	.vlan_pvid_set        = NULL,
	.rx_queue_setup	      = dpaa2_rx_queue_setup,
	.rx_queue_release      = dpaa2_rx_queue_release,
	.tx_queue_setup	      = dpaa2_tx_queue_setup,
	.tx_queue_release      = dpaa2_tx_queue_release,
	.dev_led_on           = NULL,
	.dev_led_off          = NULL,
	.set_queue_rate_limit = NULL,
	.flow_ctrl_get	      = NULL,
	.flow_ctrl_set	      = dpaa2_flow_ctrl_set,
	.priority_flow_ctrl_set = NULL,
	.mac_addr_add         = dpaa2_dev_add_mac_addr,
	.mac_addr_remove      = dpaa2_dev_remove_mac_addr,
	.rxq_info_get         = NULL,
	.txq_info_get         = NULL,
	.timesync_enable      = dpaa2_timestamp_enable,
	.timesync_disable     = dpaa2_timestamp_disable,
	.mac_addr_set         = dpaa2_dev_set_mac_addr,
};

static int
dpaa2_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_eth_dev_data *data = eth_dev->data;
	struct fsl_mc_io *dpni_dev;
	struct dpni_attr attr;
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct dpni_buffer_layout layout;
	int i, ret, hw_id = eth_dev->pci_dev->addr.devid;
	struct dpni_extended_cfg *ext_cfg = NULL;
	int tot_size;

	PMD_INIT_FUNC_TRACE();

	dpni_dev = (struct fsl_mc_io *)malloc(sizeof(struct fsl_mc_io));
	if (!dpni_dev) {
		PMD_DRV_LOG(ERR, "malloc failed for dpni device\n");
		return -1;
	}

	dpni_dev->regs = mcp_ptr_list[0];
	ret = dpni_open(dpni_dev, CMD_PRI_LOW, hw_id, &priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in opening dpni@%d device with"
			"error code %d\n", hw_id, ret);
		return -1;
	}

	/* Clean the device first */
	ret = dpni_reset(dpni_dev, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure cleaning dpni@%d device with"
			"error code %d\n", hw_id, ret);
		return -1;
	}

	ext_cfg = (struct dpni_extended_cfg *)rte_malloc(NULL, 256,
							RTE_CACHE_LINE_SIZE);
	if (!ext_cfg) {
		PMD_DRV_LOG(ERR, "No data memory\n");
		return -1;
	}
	attr.ext_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(ext_cfg));

	ret = dpni_get_attributes(dpni_dev, CMD_PRI_LOW, priv->token, &attr);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in getting dpni@%d attribute, "
			"error code %d\n", hw_id, ret);
		return -1;
	}

	priv->num_tc = attr.max_tcs;
	for (i = 0; i < attr.max_tcs; i++) {
		priv->num_dist_per_tc[i] = ext_cfg->tc_cfg[i].max_dist;
		priv->nb_rx_queues += priv->num_dist_per_tc[i];
		break;
	}
	if (attr.max_tcs == 1)
		priv->nb_tx_queues = attr.max_senders;
	else
		priv->nb_tx_queues = attr.max_tcs;
	PMD_DRV_LOG(INFO, "num_tc %d", priv->num_tc);
	PMD_DRV_LOG(INFO, "nb_rx_queues %d", priv->nb_rx_queues);

	eth_dev->data->nb_rx_queues = priv->nb_rx_queues;
	eth_dev->data->nb_tx_queues = priv->nb_tx_queues;

	priv->hw = dpni_dev;
	priv->hw_id = hw_id;
	priv->options = attr.options;

	priv->max_unicast_filters = attr.max_unicast_filters;
	priv->max_multicast_filters = attr.max_multicast_filters;

	if (attr.options & DPNI_OPT_VLAN_FILTER)
		priv->max_vlan_filters = attr.max_vlan_filters;
	else
		priv->max_vlan_filters = 0;

	ret = dpaa2_alloc_rx_tx_queues(eth_dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "dpaa2_alloc_rx_tx_queuesFailed\n");
		return -1;
	}

	data->mac_addrs = (struct ether_addr *)malloc(sizeof(struct ether_addr));

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("dpni",
		ETHER_ADDR_LEN * attr.max_unicast_filters, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate %d bytes needed to "
						"store MAC addresses",
				ETHER_ADDR_LEN * attr.max_unicast_filters);
		return -ENOMEM;
	}

	ret = dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW,
					priv->token,
				(uint8_t *)(data->mac_addrs[0].addr_bytes));
	if (ret) {
		PMD_DRV_LOG(ERR, "DPNI get mac address failed:"
					" Error Code = %d\n", ret);
		return -1;
	}

	PMD_DRV_LOG(INFO, "Adding Broadcast Address...");
	memset(data->mac_addrs[1].addr_bytes, 0xff, ETH_ADDR_LEN);
	ret = dpni_add_mac_addr(dpni_dev, CMD_PRI_LOW,
				priv->token,
				(uint8_t *)(data->mac_addrs[1].addr_bytes));
	if (ret) {
		PMD_DRV_LOG(ERR, "DPNI set broadcast mac address failed:"
					" Error Code = %0x\n", ret);
		return -1;
	}

	/* ... rx buffer layout ... */
	tot_size = DPAA2_HW_BUF_RESERVE + RTE_PKTMBUF_HEADROOM;
	tot_size = RTE_ALIGN_CEIL(tot_size,
				       DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP |
				DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
				DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM |
				DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;

	layout.pass_frame_status = 1;
	layout.data_head_room = tot_size
		- DPAA2_FD_PTA_SIZE - DPAA2_MBUF_HW_ANNOTATION;
	layout.private_data_size = DPAA2_FD_PTA_SIZE;
	layout.pass_timestamp = 1;
	layout.pass_parser_result = 1;
	PMD_DRV_LOG(INFO, "Tot_size = %d, head room = %d, private = %d",
			tot_size, layout.data_head_room, layout.private_data_size);
	ret = dpni_set_rx_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token,
					&layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Err(%d) in setting rx buffer layout\n", ret);
		return -1;
	}

	/* ... tx buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_frame_status = 1;
	layout.pass_timestamp = 1;
	ret = dpni_set_tx_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error (%d) in setting tx buffer layout\n", ret);
		return -1;
	}

	/* ... tx-conf and error buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_frame_status = 1;
	layout.pass_timestamp = 1;
	ret = dpni_set_tx_conf_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error (%d) in setting tx-conf buffer layout\n", ret);
		return -1;
	}

	/* TODO - Set the MTU if required */

	eth_dev->dev_ops = &ops;
	eth_dev->rx_pkt_burst = eth_dpaa2_prefetch_rx;/*eth_dpaa2_rx;*/
	eth_dev->tx_pkt_burst = eth_dpaa2_tx;

	rte_free(ext_cfg);

	return 0;
}

static struct eth_driver rte_dpaa2_dpni = {
	{
		.name = "rte_dpaa2_dpni",
		.id_table = pci_id_dpaa2_map,
	},
	.eth_dev_init = dpaa2_dev_init,
	.dev_private_size = sizeof(struct dpaa2_dev_priv),
};

static int
rte_pmd_dpaa2_devinit(
		const char *name __rte_unused,
		const char *params __rte_unused)
{
	PMD_DRV_LOG(INFO, "Initializing dpaa2_pmd for %s\n", name);
	rte_eth_driver_register(&rte_dpaa2_dpni);

	return 0;
}

static struct rte_driver pmd_dpaa2_drv = {
	.name = "dpaa2_pmd",
	.type = PMD_PDEV,
	.init = rte_pmd_dpaa2_devinit,
};

PMD_REGISTER_DRIVER(pmd_dpaa2_drv, dpaa2);
