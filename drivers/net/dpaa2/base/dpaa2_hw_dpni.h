/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright (c) 2016 NXP. All rights reserved.
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

#include <dpaa2_hw_dpni_annot.h>

#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		16
#define MAX_TX_QUEUES		16

/*! Maximum number of flow distributions per traffic class */
#define MAX_DIST_PER_TC		16

/*default tc to be used for ,congestion, distribution etc configuration. */
#define DPAA2_DEF_TC		0

/* Threshold for a queue to *Enter* Congestion state.
 * It is set to 32KB
 */
#define CONG_ENTER_TX_THRESHOLD   (32 * 1024)

/* Threshold for a queue to *Exit* Congestion state.
 */
#define CONG_EXIT_TX_THRESHOLD    (24 * 1024)

/* RX queue tail drop threshold
 * currently considering 32 KB packets */
#define CONG_THRESHOLD_RX_Q  (32 * 1024)

#define CONG_THRESHOLD_RX_TC  (32 * 1024)

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

#define DPAA2_TX_CKSUM_OFFLOAD_MASK ( \
		PKT_TX_IP_CKSUM | \
		PKT_TX_TCP_CKSUM | \
		PKT_TX_UDP_CKSUM)

/* Enable TX Congestion control support
 * default is disable */
#define DPAA2_TX_CGR_SUPPORT		0x01

/* Per TC tail drop or Per queue tail drop
 * default is per queue tail drop */
#define DPAA2_PER_TC_RX_TAILDROP	0x02

/*Disable RX tail drop */
#define DPAA2_RX_TAILDROP_OFF	0x04

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
	uint32_t options;
	uint16_t num_dist_per_tc[MAX_TCS];
	uint8_t max_mac_filters;
	uint8_t max_vlan_filters;
	uint8_t num_tc;
	uint8_t flags; /*dpaa2 config flags */
};

/* Externally exposed functions */
void dpaa2_dev_print_stats(struct rte_eth_dev *dev);

int dpaa2_setup_flow_dist(struct rte_eth_dev *eth_dev,
			  uint32_t req_dist_set);

int dpaa2_remove_flow_dist(struct rte_eth_dev *eth_dev,
			   uint8_t tc_index);

int dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv, void *blist);

static inline uint32_t __attribute__((hot))
dpaa2_dev_rx_parse(uint64_t hw_annot_addr)
{
	uint32_t pkt_type = RTE_PTYPE_UNKNOWN;
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	PMD_RX_LOG(DEBUG, "annotation = 0x%lx   ", annotation->word4);

	if (BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT)) {
		pkt_type = RTE_PTYPE_L2_ETHER_ARP;
		goto parse_done;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT)) {
		pkt_type = RTE_PTYPE_L2_ETHER;
	} else {
		goto parse_done;
	}

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
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_FIRST_FRAGMENT |
	    L3_IP_1_MORE_FRAGMENT |
	    L3_IP_N_FIRST_FRAGMENT |
	    L3_IP_N_MORE_FRAGMENT)) {
		pkt_type |= RTE_PTYPE_L4_FRAG;
		goto parse_done;
	} else {
		pkt_type |= RTE_PTYPE_L4_NONFRAG;
	}

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
eth_sg_fd_to_mbuf(const struct qbman_fd *fd)
{
	struct qbman_sge *sgt, *sge;
	dma_addr_t sg_addr;
	int i = 0;
	uint64_t fd_addr;
	struct rte_mbuf *first_seg, *next_seg, *cur_seg;

	fd_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));

	/*Get Scatter gather table address*/
	sgt = (struct qbman_sge *)(fd_addr + DPAA2_GET_FD_OFFSET(fd));

	sge = &sgt[i++];
	sg_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FLE_ADDR(sge));

	/*First Scatter gather entry*/
	first_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	/*Prepare all the metadata for first segment*/
	first_seg->buf_addr = (uint8_t *)sg_addr;
	first_seg->ol_flags = 0;
	first_seg->data_off = DPAA2_GET_FLE_OFFSET(sge);
	first_seg->data_len = sge->length  & 0x1FFFF;
	first_seg->pkt_len = DPAA2_GET_FD_LEN(fd);
	first_seg->nb_segs = 1;

	first_seg->packet_type = dpaa2_dev_rx_parse(
			 (uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd))
			 + DPAA2_FD_PTA_SIZE);
	dpaa2_dev_rx_offload((uint64_t)DPAA2_IOVA_TO_VADDR(
			DPAA2_GET_FD_ADDR(fd)) +
			DPAA2_FD_PTA_SIZE, first_seg);
	rte_mbuf_refcnt_set(first_seg, 1);
	cur_seg = first_seg;
	while (!DPAA2_SG_IS_FINAL(sge)) {
		sge = &sgt[i++];
		sg_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(
				DPAA2_GET_FLE_ADDR(sge));
		next_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
			bpid_info[DPAA2_GET_FLE_BPID(sge)].meta_data_size);
		next_seg->buf_addr  = (uint8_t *)sg_addr;
		next_seg->data_off  = DPAA2_GET_FLE_OFFSET(sge);
		next_seg->data_len  = sge->length  & 0x1FFFF;
		first_seg->nb_segs += 1;
		rte_mbuf_refcnt_set(next_seg, 1);
		cur_seg->next = next_seg;
		cur_seg = next_seg;
	}
	/* Saving the S/G Table in the end without incrementing the nb_segs,
	 * so that it can be reused in case of forwarding. While in rxonly
	 * case it will be freed automatically in rte_pktmbuf_free() call,
	 * because it free all the segments till the next pointer is NULL */
	cur_seg->next = DPAA2_INLINE_MBUF_FROM_BUF(fd_addr,
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	rte_mbuf_refcnt_set(cur_seg->next, 1);

	return (void *)first_seg;
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

	PMD_RX_LOG(DEBUG, "to mbuf - mbuf =%p, mbuf->buf_addr =%p, off = %d,"
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
eth_mbuf_to_sg_fd(struct rte_mbuf *mbuf,
		  struct qbman_fd *fd, uint16_t bpid)
{
	struct rte_mbuf *last_seg = mbuf, *cur_seg = mbuf;
	struct qbman_sge *sgt, *sge = NULL;
	int i;

	/*First Prepare FD to be transmited*/
	/*Resetting the buffer pool id and offset field*/
	fd->simple.bpid_offset = 0;

	/* last segment of pkt is used to save the S/G table. In case of
	 * forwarding SGT is stored as a mbuf in last segment without
	 * incrementing the nb_segs. In case of TX only, S/G table is
	 * is allocated here and set in the last seg. */
	for (i = 0; i < mbuf->nb_segs - 1; i++)
		last_seg = last_seg->next;

	if (last_seg->next == NULL) {
		last_seg->next = rte_pktmbuf_alloc(mbuf->pool);
		if (last_seg->next == NULL) {
			PMD_TX_LOG(ERR, "No memory to allocate S/G table");
			return;
		}
	}

	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(last_seg->next));
	DPAA2_SET_FD_LEN(fd, mbuf->pkt_len);
	DPAA2_SET_FD_OFFSET(fd, last_seg->next->data_off);
	DPAA2_SET_FD_BPID(fd, bpid);
	DPAA2_SET_FD_ASAL(fd, DPAA2_ASAL_VAL);
	DPAA2_FD_SET_FORMAT(fd, qbman_fd_sg);
	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (struct qbman_sge *)
		(DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd))
				+ DPAA2_GET_FD_OFFSET(fd));
	for (i = 0; i < mbuf->nb_segs; i++) {
		/*First Scatter gather entry*/
		sge = &sgt[i];
		/*Resetting the buffer pool id and offset field*/
		sge->fin_bpid_offset = 0;
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(cur_seg));
		DPAA2_SET_FLE_OFFSET(sge, cur_seg->data_off);
		sge->length = cur_seg->data_len;
		DPAA2_SET_FLE_BPID(sge, mempool_to_bpid(cur_seg->pool));
		cur_seg = cur_seg->next;
	};
	DPAA2_SG_SET_FINAL(sge, true);
	eth_check_offload(mbuf, fd);
}

static void
eth_mbuf_to_fd(struct rte_mbuf *mbuf,
	       struct qbman_fd *fd, uint16_t bpid) __attribute__((unused));

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

	PMD_TX_LOG(DEBUG, "mbuf =%p, mbuf->buf_addr =%p, off = %d,"
		"fd_off=%d fd =%lx, meta = %d  bpid =%d, len=%d\n",
		mbuf, mbuf->buf_addr, mbuf->data_off,
		DPAA2_GET_FD_OFFSET(fd), DPAA2_GET_FD_ADDR(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_BPID(fd), DPAA2_GET_FD_LEN(fd));

	eth_check_offload(mbuf, fd);
}

static inline int __attribute__((hot))
eth_copy_mbuf_to_fd(struct rte_mbuf *mbuf,
		    struct qbman_fd *fd, uint16_t bpid)
{
	struct rte_mbuf *m;
	void *mb = NULL;

	if (hw_mbuf_alloc_bulk(bpid_info[bpid].bp_list->buf_pool.mp, &mb, 1)) {
		PMD_TX_LOG(WARNING, "Unable to allocated DPAA2 buffer");
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

	PMD_TX_LOG(DEBUG, " mbuf %p BMAN buf addr %p",
		   (void *)mbuf, mbuf->buf_addr);

	PMD_TX_LOG(DEBUG, " fdaddr =%lx bpid =%d meta =%d off =%d, len =%d",
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
