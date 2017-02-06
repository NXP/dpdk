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
 *     * Neither the name of  Freescale Semiconductor, Inc nor the names of its
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

#ifndef __DPDK_RXTX_H__
#define __DPDK_RXTX_H__

#define L2_ERROR_MASK	  0x001f  /* bits 11:15 */
#define L3_ERROR_MASK	  0x0200 /* bit 6 */
#define L4_ERROR_MASK	  0x10	 /* bit 3 */
#define ETH_LEN_ERR	  2
#define VLAN_LEN_ERR	  4

#define ETH_PRESENT_MASK  0x8000 /* bit 0 */
#define L2_BIT_POS 15		/* bit 0 */
#define ETH_BIT_POS L2_BIT_POS	/* bit 0 */
#define VLAN_PRESENT_MASK 0x4000 /* bit 1 */
#define VLAN_BIT_POS (ETH_BIT_POS - 1) /* bit 1 */
#define QINQ_PRESENT_MASK 0x100 /* bit 7 */
#define VLAN_QINQ_BIT_POS (ETH_BIT_POS - 7) /* bit 7 */

#define FIRST_IPV4_PRESENT_MASK 0x8000 /* bit 0 */
#define L3_BIT_POS 15		/* bit 0 */
#define FIRST_IPV4_BIT_POS 15		/* bit 0 */
#define FIRST_IPV6_PRESENT_MASK 0x4000 /* bit 1 */
#define FIRST_IPV6_BIT_POS (FIRST_IPV4_BIT_POS - 1) /* bit 1 */
#define UNKNOWN_PROTO_MASK	0x0080 /* bit 8 */
#define UNKNOWN_PROTO_BIT_POS	7 /* bit 8 */
#define IPOPT_MASK		0x0100 /* bit 7 */
#define IPOPT_BIT_POS		8 /* bit 7 */
#define IPFRAG_MASK		0x0040 /* bit 9 */
#define IPFRAG_BIT_POS		6 /* bit 9 */

#define L4_TYPE_MASK	0xe0 /* bits 0:2 */
#define L4_BIT_POS 6		/* bit 1 */
#define L4_TYPE_SHIFT	5
#define TCP_PRESENT	1
#define UDP_PRESENT	2
#define IPSEC_PRESENT	3
#define SCTP_PRESENT	4

/* internal offset from where IC is copied to packet buffer*/
#define DEFAULT_ICIOF          32
/* IC transfer size */
#define DEFAULT_ICSZ	48

/* IC offsets from buffer header address */
#define DEFAULT_RX_ICEOF	16
#define DEFAULT_TX_ICEOF	16

/*
 * Values for the L3R field of the FM Parse Results
 */
/* L3 Type field: First IP Present IPv4 */
#define DPAA_L3_PARSE_RESULT_IPV4 0x80
/* L3 Type field: First IP Present IPv6 */
#define DPAA_L3_PARSE_RESULT_IPV6	0x40
/* Values for the L4R field of the FM Parse Results
 * See $8.8.4.7.20 - L4 HXS - L4 Results from DPAA-Rev2 Reference Manual.
 */
/* L4 Type field: UDP */
#define DPAA_L4_PARSE_RESULT_UDP	0x40
/* L4 Type field: TCP */
#define DPAA_L4_PARSE_RESULT_TCP	0x20

#define DPA_SGT_MAX_ENTRIES 16 /* maximum number of entries in SG Table */

/* Parsing mask (Little Endian) - 0x00E044EC00800000
 *	Classification Plan ID 0x00
 *	L4R 0xE0 -
 *		0x20 - TCP
 *		0x40 - UDP
 *		0x80 - SCTP
 *	L3R 0xEC44 (in Big Endian) -
 *		0x8000 - IPv4
 *		0x4000 - IPv6
 *		0x8040 - IPv4 Ext
 *		0x4040 - IPv6 Ext
 *	L2R 0x8000 (in Big Endian) -
 *		0x8000 - Ethernet type
 *	ShimR & Logical Port ID 0x0000
 */
#define DPAA_PARSE_MASK		0x00E044EC00800000
#define DPAA_PARSE_VLAN_MASK		0x0000000000700000

/* Parsed values (Little Endian) */
#define DPAA_PKT_TYPE_NONE		0x0000000000000000
#define DPAA_PKT_TYPE_ETHER		0x0000000000800000
#define DPAA_PKT_TYPE_IPV4		0x0000008000800000
#define DPAA_PKT_TYPE_IPV6		0x0000004000800000
#define DPAA_PKT_TYPE_IPV4_EXT		0x0000408000800000
#define DPAA_PKT_TYPE_IPV6_EXT		0x0000404000800000
#define DPAA_PKT_TYPE_IPV4_TCP		0x0020008000800000
#define DPAA_PKT_TYPE_IPV6_TCP		0x0020004000800000
#define DPAA_PKT_TYPE_IPV4_UDP		0x0040008000800000
#define DPAA_PKT_TYPE_IPV6_UDP		0x0040004000800000
#define DPAA_PKT_TYPE_IPV4_SCTP	0x0080008000800000
#define DPAA_PKT_TYPE_IPV6_SCTP	0x0080004000800000
#define DPAA_PKT_L3_LEN_SHIFT	7
 
/* FD structure masks and offset */
#define DPAA_FD_FORMAT_MASK 0xE0000000
#define DPAA_FD_OFFSET_MASK 0x1FF00000
#define DPAA_FD_LENGTH_MASK 0xFFFFF
#define DPAA_FD_FORMAT_SHIFT 29
#define DPAA_FD_OFFSET_SHIFT 20


/**
 * FMan parse result array
 */
struct dpaa_eth_parse_results_t {
	 uint8_t     lpid;		 /**< Logical port id */
	 uint8_t     shimr;		 /**< Shim header result  */
	 uint16_t    l2r;		 /**< Layer 2 result */
	 uint16_t    l3r;		 /**< Layer 3 result */
	 uint8_t     l4r;		 /**< Layer 4 result */
	 uint8_t     cplan;		 /**< Classification plan id */
	 uint16_t    nxthdr;		 /**< Next Header  */
	 uint16_t    cksum;		 /**< Checksum */
	 uint32_t    lcv;		 /**< LCV */
	 uint8_t     shim_off[3];	 /**< Shim offset */
	 uint8_t     eth_off;		 /**< ETH offset */
	 uint8_t     llc_snap_off;	 /**< LLC_SNAP offset */
	 uint8_t     vlan_off[2];	 /**< VLAN offset */
	 uint8_t     etype_off;		 /**< ETYPE offset */
	 uint8_t     pppoe_off;		 /**< PPP offset */
	 uint8_t     mpls_off[2];	 /**< MPLS offset */
	 uint8_t     ip_off[2];		 /**< IP offset */
	 uint8_t     gre_off;		 /**< GRE offset */
	 uint8_t     l4_off;		 /**< Layer 4 offset */
	 uint8_t     nxthdr_off;	 /**< Parser end point */
} __attribute__ ((__packed__));

/* The structure is the Prepended Data to the Frame which is used by FMAN */
struct annotations_t {
	uint8_t reserved[DEFAULT_RX_ICEOF];
	struct dpaa_eth_parse_results_t parse;	/**< Pointer to Parsed result*/
	uint64_t reserved1;
	uint64_t hash;			/**< Hash Result */
};

#define GET_ANNOTATIONS(_buf) \
	(struct annotations_t *)(_buf)

#define GET_RX_PRS(_buf) \
	(struct dpaa_eth_parse_results_t *)((uint8_t *)_buf + DEFAULT_RX_ICEOF)

#define GET_TX_PRS(_buf) \
	(struct dpaa_eth_parse_results_t *)((uint8_t *)_buf + DEFAULT_TX_ICEOF)

#define L2_ETH_MAC_PRESENT(prs) \
	(rte_be_to_cpu_16((prs)->l2r) & ETH_PRESENT_MASK)

#define L3_IPV4_PRESENT(prs) \
	(rte_be_to_cpu_16((prs)->l3r) & FIRST_IPV4_PRESENT_MASK)

#define L3_IPV6_PRESENT(prs) \
	(rte_be_to_cpu_16((prs)->l3r) & FIRST_IPV6_PRESENT_MASK)

#define L3_OPT_PRESENT(prs) \
	(rte_be_to_cpu_16((prs)->l3r) & IPOPT_MASK)

#define L4_UDP_PRESENT(prs) \
	((((prs)->l4r & L4_TYPE_MASK) >> L4_TYPE_SHIFT) == UDP_PRESENT)
#define L4_TCP_PRESENT(prs) \
	((((prs)->l4r & L4_TYPE_MASK) >> L4_TYPE_SHIFT) == TCP_PRESENT)
#define L4_IPSEC_PRESENT(prs) \
	((((prs)->l4r & L4_TYPE_MASK) >> L4_TYPE_SHIFT) == IPSEC_PRESENT)
#define L4_SCTP_PRESENT(prs) \
	((((prs)->l4r & L4_TYPE_MASK) >> L4_TYPE_SHIFT) == SCTP_PRESENT)

uint16_t dpaa_eth_queue_rx(void *q,
			   struct rte_mbuf **bufs,
		uint16_t nb_bufs);

uint16_t dpaa_eth_queue_tx(void *q,
			   struct rte_mbuf **bufs,
			uint16_t nb_bufs);

uint16_t dpaa_eth_tx_drop_all(void *q  __rte_unused,
			      struct rte_mbuf **bufs __rte_unused,
		uint16_t nb_bufs __rte_unused);

void  dpaa_buf_free(struct pool_info_entry *bp_info,
		    uint64_t addr);

int dpaa_eth_mbuf_to_sg_fd(struct rte_mbuf *mbuf,
		struct qm_fd *fd,
		uint32_t bpid);

struct rte_mbuf *dpaa_eth_sg_to_mbuf(struct qm_fd *fd, uint32_t ifid);

#endif
