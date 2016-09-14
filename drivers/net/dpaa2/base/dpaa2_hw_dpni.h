/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
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

#ifndef _DPAA2_HW_DPNI_H_
#define _DPAA2_HW_DPNI_H_

#include <dpaa2_logs.h>
#include <dpaa2_hw_dpni_annot.h>

/* #define DPAA2_CGR_SUPPORT */

#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		16
#define MAX_TX_QUEUES		16

/*! Maximum number of flow distributions per traffic class */
#define MAX_DIST_PER_TC		16

/* Threshold for a queue to *Enter* Congestion state.
 * It is set to 128 frames of size 64 bytes.
 */
#define CONG_ENTER_THRESHOLD   (128 * 64)

/* Threshold for a queue to *Exit* Congestion state.
 * It is set to 98 frames of size 64 bytes.
 */
#define CONG_EXIT_THRESHOLD    (98 * 64)

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

#define DPAA2_TX_CKSUM_OFFLOAD_MASK ( \
		PKT_TX_IP_CKSUM | \
		PKT_TX_TCP_CKSUM | \
		PKT_TX_UDP_CKSUM)

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

/* Externally exposed functions */
/* FIXME */
void dpaa2_dev_print_stats(struct rte_eth_dev *dev);

/* FIXME */
int dpaa2_setup_flow_distribution(struct rte_eth_dev *eth_dev,
				  uint32_t req_dist_set);

/* FIXME */
int dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv, void *blist);

/* FIXME */
int
dpaa2_alloc_dq_storage(struct queue_storage_info_t *q_storage);

void
dpaa2_free_dq_storage(struct queue_storage_info_t *q_storage);

static inline uint32_t __attribute__((hot))
dpaa2_dev_rx_parse(uint64_t hw_annot_addr)
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
dpaa2_dev_rx_offload(uint64_t hw_annot_addr, struct rte_mbuf *mbuf)
{
	struct dpaa2_annot_hdr *annotation =
		(struct dpaa2_annot_hdr *)hw_annot_addr;

	if (BIT_ISSET_AT_POS(annotation->word3,
			L2_VLAN_1_PRESENT | L2_VLAN_N_PRESENT))
		mbuf->ol_flags |= PKT_RX_VLAN_PKT;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= PKT_RX_IP_CKSUM_BAD;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= PKT_RX_L4_CKSUM_BAD;
}

static inline struct rte_mbuf *__attribute__((hot))
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
	mbuf->packet_type = dpaa2_dev_rx_parse(
			(uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd))
			 + DPAA2_FD_PTA_SIZE);

	dpaa2_dev_rx_offload((uint64_t)DPAA2_IOVA_TO_VADDR(
			     DPAA2_GET_FD_ADDR(fd)) +
			     DPAA2_FD_PTA_SIZE, mbuf);

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

	eth_check_offload(mbuf, fd);

	return;
}

static inline int __attribute__((hot))
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

	PMD_DRV_LOG(DEBUG, " mbuf %p BMAN buf addr %p",
		    (void *)mbuf, mbuf->buf_addr);

	PMD_DRV_LOG(DEBUG, " fdaddr =%lx bpid =%d meta =%d off =%d, len =%d",
		    DPAA2_GET_FD_ADDR(fd),
		DPAA2_GET_FD_BPID(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_OFFSET(fd),
		DPAA2_GET_FD_LEN(fd));
	/*free the original packet */
	rte_pktmbuf_free(mbuf);

	return 0;
}

#endif /* _DPAA2_DPNI_H_ */
