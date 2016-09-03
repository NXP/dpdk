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

#include <time.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_common.h>
#include <rte_eth_dpaa2_pvt.h>
#include "dpaa2_sec_priv.h"

#include <net/if.h>

#include "dpaa2_sec_logs.h"

/* MC header files */
#include <fsl_dpbp.h>
#include <fsl_dpseci.h>
#include <fsl_dpio.h>

/*QBMAN header files*/
#include <fsl_qbman_portal.h>
#include <fsl_qbman_base.h>

/* RTA header files */
#include <flib/desc/ipsec.h>
#include <flib/desc/pdcp.h>
#include <flib/desc/algo.h>

enum rta_sec_era rta_sec_era = RTA_SEC_ERA_8;
extern struct dpaa2_bp_info bpid_info[MAX_BPID];

static inline void print_fd(const struct qbman_fd *fd)
{
	printf("addr_lo:          %p\n", fd->simple.addr_lo);
	printf("addr_hi:          %p\n", fd->simple.addr_hi);
	printf("len:              %lu\n", fd->simple.len);
	printf("bpid:             %lu\n", DPAA2_GET_FD_BPID(fd));
	printf("fi_bpid_off:      %lu\n", fd->simple.bpid_offset);
	printf("frc:              %lu\n", fd->simple.frc);
	printf("ctrl:             %lu\n", fd->simple.ctrl);
	printf("flc_lo:           %p\n", fd->simple.flc_lo);
	printf("flc_hi:           %p\n\n", fd->simple.flc_hi);
}

static inline void print_fle(const struct qbman_fle *fle)
{
	printf("addr_lo:          %p\n", fle->addr_lo);
	printf("addr_hi:          %p\n", fle->addr_hi);
	printf("len:              %lu\n", fle->length);
	printf("fi_bpid_off:      %lu\n", fle->fin_bpid_offset);
	printf("frc:              %lu\n", fle->frc);
}

static inline int build_authenc_fd(dpaa2_sec_session *sess,
				   struct rte_crypto_op *op,
		struct qbman_fd *fd, uint16_t bpid)
{
	struct rte_crypto_sym_op *sym_op = op->sym;
	struct ctxt_priv *priv = sess->ctxt;
	struct qbman_fle *fle, *sge;
	struct sec_flow_context *flc;
	uint32_t auth_only_len = sym_op->auth.data.length -
				sym_op->cipher.data.length;
	int icv_len = sym_op->auth.digest.length;
	int iv_len = sym_op->cipher.iv.length;
	uint8_t *old_icv;
	uint32_t mem_len = (7 * sizeof(struct qbman_fle)) + icv_len;

	/* TODO we are using the first FLE entry to store Mbuf.
	   Currently we donot know which FLE has the mbuf stored.
	   So while retreiving we can go back 1 FLE from the FD -ADDR
	   to get the MBUF Addr from the previous FLE.
	   We can have a better approach to use the inline Mbuf*/
	/* todo - we can use some mempool to avoid malloc here */
	fle = rte_zmalloc(NULL, mem_len, RTE_CACHE_LINE_SIZE);
	if (!fle) {
		PMD_DRV_LOG(ERR, "Memory alloc failed for SGE\n");
		return -1;
	}
	DPAA2_SET_FLE_ADDR(fle, DPAA2_OP_VADDR_TO_IOVA(op));
	fle = fle + 1;
	sge = fle + 2;
	if (likely(bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, bpid);
		DPAA2_SET_FLE_BPID(fle, bpid);
		DPAA2_SET_FLE_BPID(fle + 1, bpid);
		DPAA2_SET_FLE_BPID(sge, bpid);
		DPAA2_SET_FLE_BPID(sge + 1, bpid);
		DPAA2_SET_FLE_BPID(sge + 2, bpid);
		DPAA2_SET_FLE_BPID(sge + 3, bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle + 1));
		DPAA2_SET_FLE_IVP(sge);
		DPAA2_SET_FLE_IVP((sge + 1));
		DPAA2_SET_FLE_IVP((sge + 2));
		DPAA2_SET_FLE_IVP((sge + 3));
	}

	/* Save the shared descriptor */
	flc = &priv->flc_desc[0].flc;
	/* Configure FD as a FRAME LIST */
	DPAA2_SET_FD_ADDR(fd, DPAA2_VADDR_TO_IOVA(fle));
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, DPAA2_VADDR_TO_IOVA(flc));

	PMD_DRV_LOG(DEBUG, "\nauth_off: 0x%x/length %d, digest-len=%d\n"
			"cipher_off: 0x%x/length %d, iv-len=%d data_off: 0x%x\n",
		sym_op->auth.data.offset,
		sym_op->auth.data.length,
		sym_op->auth.digest.length,
		sym_op->cipher.data.offset,
		sym_op->cipher.data.length,
		sym_op->cipher.iv.length,
		sym_op->m_src->data_off);

	/* Configure Output FLE with Scatter/Gather Entry */
	DPAA2_SET_FLE_ADDR(fle, DPAA2_VADDR_TO_IOVA(sge));
	if (auth_only_len)
		DPAA2_SET_FLE_INTERNAL_JD(fle, auth_only_len);
	fle->length = (sess->dir == DIR_ENC) ?
		(sym_op->cipher.data.length + icv_len) : sym_op->cipher.data.length;

	DPAA2_SET_FLE_SG_EXT(fle);

	/* Configure Output SGE for Encap/Decap */
	DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
	DPAA2_SET_FLE_OFFSET(sge, sym_op->cipher.data.offset + sym_op->m_src->data_off);
	sge->length = sym_op->cipher.data.length;

	if (sess->dir == DIR_ENC) {
		sge++;
		DPAA2_SET_FLE_ADDR(sge, DPAA2_VADDR_TO_IOVA(sym_op->auth.digest.data));
		sge->length = sym_op->auth.digest.length;
		DPAA2_SET_FD_LEN(fd, (sym_op->auth.data.length + sym_op->cipher.iv.length));
	}
	DPAA2_SET_FLE_FIN(sge);

	sge++;
	fle++;

	/* Configure Input FLE with Scatter/Gather Entry */
	DPAA2_SET_FLE_ADDR(fle, DPAA2_VADDR_TO_IOVA(sge));
	DPAA2_SET_FLE_SG_EXT(fle);
	DPAA2_SET_FLE_FIN(fle);
	fle->length = (sess->dir == DIR_ENC) ?
			(sym_op->auth.data.length + sym_op->cipher.iv.length) :
			(sym_op->auth.data.length + sym_op->cipher.iv.length +
			 sym_op->auth.digest.length);

	/* Configure Input SGE for Encap/Decap */
	DPAA2_SET_FLE_ADDR(sge, DPAA2_VADDR_TO_IOVA(sym_op->cipher.iv.data));
	sge->length = sym_op->cipher.iv.length;
	sge++;

	DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
	DPAA2_SET_FLE_OFFSET(sge, sym_op->auth.data.offset + sym_op->m_src->data_off);
	sge->length = sym_op->auth.data.length;
	if (sess->dir == DIR_DEC) {
		sge++;
		old_icv = (uint8_t *)(sge + 1);
		memcpy(old_icv,	sym_op->auth.digest.data, sym_op->auth.digest.length);
		memset(sym_op->auth.digest.data, 0, sym_op->auth.digest.length);
		DPAA2_SET_FLE_ADDR(sge, DPAA2_VADDR_TO_IOVA(old_icv));
		sge->length = sym_op->auth.digest.length;
		DPAA2_SET_FD_LEN(fd, (sym_op->auth.data.length +
			sym_op->auth.digest.length + sym_op->cipher.iv.length));
	}
	DPAA2_SET_FLE_FIN(sge);
	if (auth_only_len) {
		DPAA2_SET_FLE_INTERNAL_JD(fle, auth_only_len);
		DPAA2_SET_FD_INTERNAL_JD(fd, auth_only_len);
	}
	return 0;
}

static inline int build_auth_fd(
		dpaa2_sec_session *sess,
		struct rte_crypto_op *op,
		struct qbman_fd *fd,
		uint16_t bpid)
{
	struct rte_crypto_sym_op *sym_op = op->sym;
	struct qbman_fle *fle, *sge;
	uint32_t mem_len = (sess->dir == DIR_ENC) ? (3 * sizeof(struct qbman_fle)) :
			(5 * sizeof(struct qbman_fle) + sym_op->auth.digest.length);
	struct sec_flow_context *flc;
	struct ctxt_priv *priv = sess->ctxt;
	uint8_t *old_digest;

	fle = rte_zmalloc(NULL, mem_len, RTE_CACHE_LINE_SIZE);
	if (!fle) {
		PMD_DRV_LOG(ERR, "Memory alloc failed for FLE\n");
		return -1;
	}
	/* TODO we are using the first FLE entry to store Mbuf.
	   Currently we donot know which FLE has the mbuf stored.
	   So while retreiving we can go back 1 FLE from the FD -ADDR
	   to get the MBUF Addr from the previous FLE.
	   We can have a better approach to use the inline Mbuf*/
	DPAA2_SET_FLE_ADDR(fle, DPAA2_OP_VADDR_TO_IOVA(op));
	fle = fle + 1;

	if (likely(bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, bpid);
		DPAA2_SET_FLE_BPID(fle, bpid);
		DPAA2_SET_FLE_BPID(fle + 1, bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle + 1));
	}
	flc = &priv->flc_desc[DESC_INITFINAL].flc;
	DPAA2_SET_FD_FLC(fd, DPAA2_VADDR_TO_IOVA(flc));

	DPAA2_SET_FLE_ADDR(fle, DPAA2_VADDR_TO_IOVA(sym_op->auth.digest.data));
	fle->length = sym_op->auth.digest.length;

	DPAA2_SET_FD_ADDR(fd, DPAA2_VADDR_TO_IOVA(fle));
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	fle++;

	if (sess->dir == DIR_ENC) {
		DPAA2_SET_FLE_ADDR(fle, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
		DPAA2_SET_FLE_OFFSET(fle, sym_op->auth.data.offset + sym_op->m_src->data_off);
		DPAA2_SET_FD_LEN(fd, sym_op->auth.data.length);
		fle->length = sym_op->auth.data.length;
	} else {
		sge = fle + 2;
		DPAA2_SET_FLE_SG_EXT(fle);
		DPAA2_SET_FLE_ADDR(fle, DPAA2_VADDR_TO_IOVA(sge));

		if (likely(bpid < MAX_BPID)) {
			DPAA2_SET_FLE_BPID(sge, bpid);
			DPAA2_SET_FLE_BPID(sge + 1, bpid);
		} else {
			DPAA2_SET_FLE_IVP(sge);
			DPAA2_SET_FLE_IVP((sge + 1));
		}
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
		DPAA2_SET_FLE_OFFSET(sge, sym_op->auth.data.offset +
				sym_op->m_src->data_off);

		DPAA2_SET_FD_LEN(fd, sym_op->auth.data.length +
				sym_op->auth.digest.length);
		sge->length = sym_op->auth.data.length;
		sge++;
		old_digest = (uint8_t *)(sge + 1);
		rte_memcpy(old_digest, sym_op->auth.digest.data,
			   sym_op->auth.digest.length);
		memset(sym_op->auth.digest.data, 0, sym_op->auth.digest.length);
		DPAA2_SET_FLE_ADDR(sge, DPAA2_VADDR_TO_IOVA(old_digest));
		sge->length = sym_op->auth.digest.length;
		fle->length = sym_op->auth.data.length +
				sym_op->auth.digest.length;
		DPAA2_SET_FLE_FIN(sge);
	}
	DPAA2_SET_FLE_FIN(fle);

	return 0;
}

static int build_cipher_fd(dpaa2_sec_session *sess, struct rte_crypto_op *op,
			   struct qbman_fd *fd, uint16_t bpid)
{
	struct rte_crypto_sym_op *sym_op = op->sym;
	struct qbman_fle *fle, *sge;
	uint32_t mem_len = (5 * sizeof(struct qbman_fle));
	struct sec_flow_context *flc;
	struct ctxt_priv *priv = sess->ctxt;

	/* todo - we can use some mempool to avoid malloc here */
	fle = rte_zmalloc(NULL, mem_len, RTE_CACHE_LINE_SIZE);
	if (!fle) {
		PMD_DRV_LOG(ERR, "Memory alloc failed for SGE\n");
		return -1;
	}
	/* TODO we are using the first FLE entry to store Mbuf.
	   Currently we donot know which FLE has the mbuf stored.
	   So while retreiving we can go back 1 FLE from the FD -ADDR
	   to get the MBUF Addr from the previous FLE.
	   We can have a better approach to use the inline Mbuf*/
	DPAA2_SET_FLE_ADDR(fle, DPAA2_OP_VADDR_TO_IOVA(op));
	fle = fle + 1;
	sge = fle + 2;

	if (likely(bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, bpid);
		DPAA2_SET_FLE_BPID(fle, bpid);
		DPAA2_SET_FLE_BPID(fle + 1, bpid);
		DPAA2_SET_FLE_BPID(sge, bpid);
		DPAA2_SET_FLE_BPID(sge + 1, bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle + 1));
		DPAA2_SET_FLE_IVP(sge);
		DPAA2_SET_FLE_IVP((sge + 1));
	}

	flc = &priv->flc_desc[0].flc;
	DPAA2_SET_FD_ADDR(fd, DPAA2_VADDR_TO_IOVA(fle));
	DPAA2_SET_FD_LEN(fd, sym_op->cipher.data.length + sym_op->cipher.iv.length);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, DPAA2_VADDR_TO_IOVA(flc));

	PMD_DRV_LOG(DEBUG, "cipher_off: 0x%x/length %d, iv-len=%d data_off: 0x%x",
		    sym_op->cipher.data.offset,
		sym_op->cipher.data.length,
		sym_op->cipher.iv.length,
		sym_op->m_src->data_off);

	DPAA2_SET_FLE_ADDR(fle, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
	DPAA2_SET_FLE_OFFSET(fle, sym_op->cipher.data.offset + sym_op->m_src->data_off);

	/*todo - check the length stuff, idealy this should be only cipher data length */
	fle->length = sym_op->cipher.data.length + sym_op->cipher.iv.length;

	PMD_DRV_LOG(DEBUG, "1 - flc = %p, fle = %p FLE addr = %x - %x, length\n",
		    flc, fle,
		fle->addr_hi, fle->addr_lo, fle->length);

	fle++;

	DPAA2_SET_FLE_ADDR(fle, DPAA2_VADDR_TO_IOVA(sge));
	fle->length = sym_op->cipher.data.length + sym_op->cipher.iv.length;

	DPAA2_SET_FLE_SG_EXT(fle);

	DPAA2_SET_FLE_ADDR(sge, DPAA2_VADDR_TO_IOVA(sym_op->cipher.iv.data));
	sge->length = sym_op->cipher.iv.length;

	sge++;
	DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(sym_op->m_src));
	DPAA2_SET_FLE_OFFSET(sge, sym_op->cipher.data.offset + sym_op->m_src->data_off);

	sge->length = sym_op->cipher.data.length;
	DPAA2_SET_FLE_FIN(sge);
	DPAA2_SET_FLE_FIN(fle);

	PMD_DRV_LOG(DEBUG, "fdaddr =%p bpid =%d meta =%d off =%d, len =%d",
		    DPAA2_GET_FD_ADDR(fd),
			DPAA2_GET_FD_BPID(fd),
			bpid_info[bpid].meta_data_size,
			DPAA2_GET_FD_OFFSET(fd),
			DPAA2_GET_FD_LEN(fd));

	return 0;
}

static uint16_t
dpaa2_sec_enqueue_burst(void *qp, struct rte_crypto_op **ops,
			uint16_t nb_ops)
{
	/* Function to transmit the frames to given device and VQ*/
	uint32_t loop;
	int32_t ret;
	struct qbman_fd fd;
	struct qbman_eq_desc eqdesc;
	struct dpaa2_sec_qp *dpaa2_qp = (struct dpaa2_sec_qp *)qp;
	struct qbman_swp *swp;
	uint16_t num_tx = 0;
	/*todo - need to support multiple buffer pools */
	uint16_t bpid;
	struct rte_mempool *mb_pool;
	struct rte_cryptodev *dev = dpaa2_qp->tx_vq.dev;
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	dpaa2_sec_session *sess;

	if (unlikely(nb_ops == 0))
		return 0;

	if (ops[0]->sym->sess_type != RTE_CRYPTO_SYM_OP_WITH_SESSION) {
		PMD_DRV_LOG(ERR, "sessionless crypto op not supported\n");
		return 0;
	}
	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);
	qbman_eq_desc_set_fq(&eqdesc, dpaa2_qp->tx_vq.fqid);

	if (!thread_io_info.sec_dpio_dev) {
		ret = dpaa2_affine_qbman_swp_sec();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.sec_dpio_dev->sw_portal;

	/*Prepare each packet which is to be sent*/
	for (loop = 0; loop < nb_ops; loop++) {
		memset(&fd, 0, sizeof(struct qbman_fd));
		sess = (dpaa2_sec_session *)ops[loop]->sym->session->_private;
		mb_pool = ops[loop]->sym->m_src->pool;
		bpid = mempool_to_bpid(mb_pool);
		switch (sess->ctxt_type) {
		case DPAA2_SEC_CIPHER:
			ret = build_cipher_fd(sess, ops[loop], &fd, bpid);
			break;
		case DPAA2_SEC_AUTH:
			ret = build_auth_fd(sess, ops[loop], &fd, bpid);
			break;
		case DPAA2_SEC_CIPHER_HASH:
			ret = build_authenc_fd(sess, ops[loop], &fd, bpid);
			break;
		case DPAA2_SEC_HASH_CIPHER:
		default:
			PMD_DRV_LOG(ERR, "Unsupported session\n");
			return 0;
		}
		if (ret) {
			PMD_DRV_LOG(ERR, "Improper packet contents for crypto operation\n");
			return 0;
		}
		/*Enqueue a packet to the QBMAN*/
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				PMD_DRV_LOG(ERR, "Error in transmiting the frame\n");
			}
		} while (ret != 0);

		/* Free the buffer shell */
		/* rte_pktmbuf_free(bufs[loop]); */
		num_tx++;
	}
	dpaa2_qp->tx_vq.tx_pkts += num_tx;
	dpaa2_qp->tx_vq.err_pkts += nb_ops - num_tx;
	return num_tx;
}

static inline
struct rte_crypto_op *sec_fd_to_mbuf(const struct qbman_fd *fd)
{
	struct qbman_fle *fle, *fle1, *sge;
	struct rte_crypto_op *op;

	fle = (struct qbman_fle *)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));

	PMD_DRV_LOG(DEBUG, "FLE addr = %x - %x, offset = %x",
		    fle->addr_hi, fle->addr_lo, fle->fin_bpid_offset);

	/* TODO we are using the first FLE entry to store Mbuf.
	   Currently we donot know which FLE has the mbuf stored.
	   So while retreiving we can go back 1 FLE from the FD -ADDR
	   to get the MBUF Addr from the previous FLE.
	   We can have a better approach to use the inline Mbuf*/

	if (unlikely(DPAA2_GET_FD_IVP(fd))) {
		/* TODO complete it. */
		printf("\n????????? Non inline buffer - WHAT to DO?");
		return NULL;
	} else
		op = (struct rte_crypto_op *)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FLE_ADDR((fle - 1)));

	PMD_DRV_LOG(DEBUG, "\nmbuf %p BMAN buf addr %p",
		    (void *)op->sym->m_src, op->sym->m_src->buf_addr);

	if (unlikely(DPAA2_GET_FD_IVP(fd))) {
		printf("\nHit wrong leg\n");
	}
	PMD_DRV_LOG(DEBUG, "fdaddr =%p bpid =%d meta =%d off =%d, len =%d",
		    DPAA2_GET_FD_ADDR(fd),
		DPAA2_GET_FD_BPID(fd),
		bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_OFFSET(fd),
		DPAA2_GET_FD_LEN(fd));

	/* Not the inline used fle */
	if (fle != op->sym->m_src->buf_addr)
		rte_free(fle - 1);

	return op;
}

static uint16_t
dpaa2_sec_dequeue_burst(void *qp, struct rte_crypto_op **ops,
			uint16_t nb_ops)
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_sec_qp *dpaa2_qp = (struct dpaa2_sec_qp *)qp;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_qp->rx_vq.fqid;
	int ret, num_rx = 0;
	uint8_t is_last = 0, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;

	if (!thread_io_info.sec_dpio_dev) {
		ret = dpaa2_affine_qbman_swp_sec();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.sec_dpio_dev->sw_portal;
	dq_storage = dpaa2_qp->rx_vq.q_storage->dq_storage[0];

	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, nb_ops);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
				    (dma_addr_t)DPAA2_VADDR_TO_IOVA(dq_storage), 1);

	/*Issue a volatile dequeue command. */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			PMD_DRV_LOG(ERR, "SEC VDQ command is not issued."
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
		ops[num_rx] = sec_fd_to_mbuf(fd);

		if (unlikely(fd->simple.frc)) {
			/* TODO Parse SEC errors */
			printf("SEC returned Error - %x\n", fd->simple.frc);
			ops[num_rx]->status = RTE_CRYPTO_OP_STATUS_ERROR;
		} else
			ops[num_rx]->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

		num_rx++;
		dq_storage++;
	} /* End of Packet Rx loop */

	dpaa2_qp->rx_vq.rx_pkts += num_rx;

	PMD_DRV_LOG(DEBUG, "SEC Received %d Packets\n", num_rx);
	/*Return the total number of packets received to DPAA2 app*/
	return num_rx;
}

/** Release queue pair */
static int
dpaa2_sec_queue_pair_release(struct rte_cryptodev *dev, uint16_t queue_pair_id)
{
	struct dpaa2_sec_qp *qp =
		(struct dpaa2_sec_qp *)dev->data->queue_pairs[queue_pair_id];

	if (qp->rx_vq.q_storage)
		rte_free(qp->rx_vq.q_storage);
	rte_free(qp);

	dev->data->queue_pairs[queue_pair_id] = NULL;

	return 0;
}

/** Setup a queue pair */
static int
dpaa2_sec_queue_pair_setup(struct rte_cryptodev *dev, uint16_t qp_id,
			   __rte_unused const struct rte_cryptodev_qp_conf *qp_conf,
		__rte_unused int socket_id)
{
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	struct dpaa2_sec_qp *qp;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)priv->hw;
	struct dpseci_rx_queue_cfg cfg;
	int32_t retcode;

	/* If qp is already in use free ring memory and qp metadata. */
	if (dev->data->queue_pairs[qp_id] != NULL) {
		PMD_DRV_LOG(INFO, "QP already setup");
		return 0;
	}

	PMD_DRV_LOG(DEBUG, "dev =%p, queue =%d, conf =%p",
		    dev, qp_id, qp_conf);

	memset(&cfg, 0, sizeof(struct dpseci_rx_queue_cfg));

	qp = rte_malloc(NULL, sizeof(struct dpaa2_sec_qp),
			RTE_CACHE_LINE_SIZE);
	if (!qp) {
		PMD_DRV_LOG(ERR, "malloc failed for rx/tx queues\n");
		return -1;
	}

	qp->rx_vq.dev = dev;
	qp->tx_vq.dev = dev;
	qp->rx_vq.q_storage = rte_malloc("sec dq storage",
		sizeof(struct queue_storage_info_t),
		RTE_CACHE_LINE_SIZE);
	if (!qp->rx_vq.q_storage)
		return -1;
	memset(qp->rx_vq.q_storage, 0, sizeof(struct queue_storage_info_t));

	dev->data->queue_pairs[qp_id] = qp;

	cfg.options = cfg.options | DPSECI_QUEUE_OPT_USER_CTX;
	cfg.user_ctx = (uint64_t)(&qp->rx_vq);
	retcode = dpseci_set_rx_queue(dpseci, CMD_PRI_LOW, priv->token,
				      qp_id, &cfg);
	return retcode;
}

/** Start queue pair */
static int
dpaa2_sec_queue_pair_start(__rte_unused struct rte_cryptodev *dev,
			   __rte_unused uint16_t queue_pair_id)
{
	return 0;
}

/** Stop queue pair */
static int
dpaa2_sec_queue_pair_stop(__rte_unused struct rte_cryptodev *dev,
			  __rte_unused uint16_t queue_pair_id)
{
	return 0;
}

/** Return the number of allocated queue pairs */
static uint32_t
dpaa2_sec_queue_pair_count(struct rte_cryptodev *dev)
{
	return dev->data->nb_queue_pairs;
}

/** Returns the size of the aesni gcm session structure */
static unsigned
dpaa2_sec_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(dpaa2_sec_session);
}

static void
dpaa2_sec_session_initialize(struct rte_mempool *mp,
			     void *sess)
{
	sess = (dpaa2_sec_session *)rte_zmalloc(NULL,
			sizeof(dpaa2_sec_session), RTE_CACHE_LINE_SIZE);
	return;
}

static int dpaa2_sec_cipher_init(struct rte_cryptodev *dev,
				 struct rte_crypto_sym_xform *xform,
		dpaa2_sec_session *session)
{
	struct dpaa2_sec_cipher_ctxt *ctxt = &session->ext_params.cipher_ctxt;
	struct alginfo cipherdata;
	unsigned int bufsize, i;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;

	/* For SEC CIPHER only one descriptor is required. */
	priv = (struct ctxt_priv *)rte_zmalloc(NULL,
			sizeof(struct ctxt_priv) + sizeof(struct sec_flc_desc),
			RTE_CACHE_LINE_SIZE);
	if (priv == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for priv CTXT");
		return -1;
	}

	flc = &priv->flc_desc[0].flc;

	session->cipher_key.data = rte_zmalloc(NULL, xform->cipher.key.length,
			RTE_CACHE_LINE_SIZE);
	if (session->cipher_key.data == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for cipher key");
		return -1;
	}
	session->cipher_key.length = xform->cipher.key.length;

	memcpy(session->cipher_key.data, xform->cipher.key.data, xform->cipher.key.length);
	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;

	switch (xform->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_AES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		session->cipher_alg = RTE_CRYPTO_CIPHER_AES_CBC;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_3DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		session->cipher_alg = RTE_CRYPTO_CIPHER_3DES_CBC;
		break;
	case RTE_CRYPTO_CIPHER_AES_GCM:
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
	case RTE_CRYPTO_CIPHER_NULL:
	case RTE_CRYPTO_CIPHER_3DES_ECB:
	case RTE_CRYPTO_CIPHER_AES_ECB:
	case RTE_CRYPTO_CIPHER_AES_CTR:
	case RTE_CRYPTO_CIPHER_AES_CCM:
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		PMD_DRV_LOG(ERR, "Crypto: Unsupported Cipher alg %u",
			    xform->cipher.algo);
		goto error_out;
	default:
		PMD_DRV_LOG(ERR, "Crypto: Undefined Cipher specified %u\n",
			    xform->cipher.algo);
		goto error_out;
	}
	session->dir = (xform->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) ?
				DIR_ENC : DIR_DEC;

	bufsize = cnstr_shdsc_blkcipher(priv->flc_desc[0].desc, 1, 0,
					&cipherdata, NULL, ctxt->iv.length,
			session->dir);
	flc->dhr = 0;
	flc->bpv0 = 0x1;
	flc->mode_bits = 0x8000;

	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	session->ctxt = priv;

	for (i = 0; i < bufsize; i++)
		PMD_DRV_LOG(DEBUG, "DESC[%d]:0x%x\n",
			    i, priv->flc_desc[0].desc[i]);

	return 0;

error_out:
	rte_free(session->cipher_key.data);
	return -1;
}

static int dpaa2_sec_auth_init(struct rte_cryptodev *dev,
			       struct rte_crypto_sym_xform *xform,
		dpaa2_sec_session *session)
{
	struct dpaa2_sec_auth_ctxt *ctxt = &session->ext_params.auth_ctxt;
	struct alginfo authdata;
	unsigned int bufsize;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;

	/* For SEC AUTH three descriptors are required for various stages */
	priv = (struct ctxt_priv *)rte_zmalloc(NULL,
			sizeof(struct ctxt_priv) + 3 *
			sizeof(struct sec_flc_desc),
			RTE_CACHE_LINE_SIZE);
	if (priv == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for priv CTXT");
		return -1;
	}

	flc = &priv->flc_desc[DESC_INITFINAL].flc;

	session->auth_key.data = rte_zmalloc(NULL, xform->auth.key.length,
			RTE_CACHE_LINE_SIZE);
	session->auth_key.length = xform->auth.key.length;

	memcpy(session->auth_key.data, xform->auth.key.data,
	       xform->auth.key.length);
	authdata.key = (uint64_t)session->auth_key.data;
	authdata.keylen = session->auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.key_type = RTA_DATA_IMM;

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA1_HMAC;
		break;
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_MD5;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_MD5_HMAC;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
	case RTE_CRYPTO_AUTH_AES_XCBC_MAC:
	case RTE_CRYPTO_AUTH_AES_GCM:
	case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
	case RTE_CRYPTO_AUTH_NULL:
	case RTE_CRYPTO_AUTH_SHA1:
	case RTE_CRYPTO_AUTH_SHA256:
	case RTE_CRYPTO_AUTH_SHA512:
	case RTE_CRYPTO_AUTH_SHA224:
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
	case RTE_CRYPTO_AUTH_SHA384:
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
	case RTE_CRYPTO_AUTH_MD5:
	case RTE_CRYPTO_AUTH_AES_CCM:
	case RTE_CRYPTO_AUTH_AES_GMAC:
	case RTE_CRYPTO_AUTH_KASUMI_F9:
	case RTE_CRYPTO_AUTH_AES_CMAC:
	case RTE_CRYPTO_AUTH_AES_CBC_MAC:
	case RTE_CRYPTO_AUTH_ZUC_EIA3:
		PMD_DRV_LOG(ERR, "Crypto: Unsupported auth alg %u",
			    xform->auth.algo);
		goto error_out;
	default:
		PMD_DRV_LOG(ERR, "Crypto: Undefined Auth specified %u\n",
			    xform->auth.algo);
		goto error_out;
	}
	session->dir = (xform->auth.op == RTE_CRYPTO_AUTH_OP_GENERATE) ?
				DIR_ENC : DIR_DEC;

	bufsize = cnstr_shdsc_hmac(priv->flc_desc[DESC_INITFINAL].desc,
				   1, 0, &authdata, !session->dir, ctxt->trunc_len);

	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	session->ctxt = priv;

	return 0;

error_out:
	rte_free(session->auth_key.data);
	return -1;
}

static int dpaa2_sec_aead_init(struct rte_cryptodev *dev,
			       struct rte_crypto_sym_xform *xform,
		dpaa2_sec_session *session)
{
	struct dpaa2_sec_aead_ctxt *ctxt = &session->ext_params.aead_ctxt;
	struct alginfo authdata, cipherdata;
	unsigned int bufsize;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;
	struct rte_crypto_cipher_xform *cipher_xform;
	struct rte_crypto_auth_xform *auth_xform;

	if (session->ext_params.aead_ctxt.auth_cipher_text == TRUE) {
		cipher_xform = &xform->cipher;
		auth_xform = &xform->next->auth;
		session->ctxt_type =
			(cipher_xform->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) ?
			DPAA2_SEC_CIPHER_HASH : DPAA2_SEC_HASH_CIPHER;
	} else {
		cipher_xform = &xform->next->cipher;
		auth_xform = &xform->auth;
		session->ctxt_type =
			(cipher_xform->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) ?
			DPAA2_SEC_HASH_CIPHER : DPAA2_SEC_CIPHER_HASH;
	}
	/* For SEC AEAD only one descriptor is required */
	priv = (struct ctxt_priv *)rte_zmalloc(NULL,
			sizeof(struct ctxt_priv) + sizeof(struct sec_flc_desc),
			RTE_CACHE_LINE_SIZE);
	if (priv == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for priv CTXT");
		return -1;
	}

	flc = &priv->flc_desc[0].flc;

	session->cipher_key.data = rte_zmalloc(NULL, cipher_xform->key.length,
			RTE_CACHE_LINE_SIZE);
	if (session->cipher_key.data == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for cipher key");
		return -1;
	}
	session->cipher_key.length = cipher_xform->key.length;
	session->auth_key.data = rte_zmalloc(NULL, auth_xform->key.length,
			RTE_CACHE_LINE_SIZE);
	if (session->auth_key.data == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for auth key");
		goto error_out;
	}
	session->auth_key.length = auth_xform->key.length;
	memcpy(session->cipher_key.data, cipher_xform->key.data,
	       cipher_xform->key.length);
	memcpy(session->auth_key.data, auth_xform->key.data,
	       auth_xform->key.length);

	ctxt->trunc_len = auth_xform->digest_length;
	authdata.key = (uint64_t)session->auth_key.data;
	authdata.keylen = session->auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.key_type = RTA_DATA_IMM;

	switch (auth_xform->algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA1_HMAC;
		break;
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_MD5;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_MD5_HMAC;
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA224;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA224_HMAC;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA256;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA256_HMAC;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA384;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA384_HMAC;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		authdata.algtype = OP_ALG_ALGSEL_SHA512;
		authdata.algmode = OP_ALG_AAI_HMAC;
		session->auth_alg = RTE_CRYPTO_AUTH_SHA512_HMAC;
		break;
	case RTE_CRYPTO_AUTH_AES_XCBC_MAC:
	case RTE_CRYPTO_AUTH_AES_GCM:
	case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
	case RTE_CRYPTO_AUTH_NULL:
	case RTE_CRYPTO_AUTH_SHA1:
	case RTE_CRYPTO_AUTH_SHA256:
	case RTE_CRYPTO_AUTH_SHA512:
	case RTE_CRYPTO_AUTH_SHA224:
	case RTE_CRYPTO_AUTH_SHA384:
	case RTE_CRYPTO_AUTH_MD5:
	case RTE_CRYPTO_AUTH_AES_CCM:
	case RTE_CRYPTO_AUTH_AES_GMAC:
	case RTE_CRYPTO_AUTH_KASUMI_F9:
	case RTE_CRYPTO_AUTH_AES_CMAC:
	case RTE_CRYPTO_AUTH_AES_CBC_MAC:
	case RTE_CRYPTO_AUTH_ZUC_EIA3:
		PMD_DRV_LOG(ERR, "Crypto: Unsupported auth alg %u",
			    auth_xform->algo);
		goto error_out;
	default:
		PMD_DRV_LOG(ERR, "Crypto: Undefined Auth specified %u\n",
			    auth_xform->algo);
		goto error_out;
	}
	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;

	switch (cipher_xform->algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_AES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		session->cipher_alg = RTE_CRYPTO_CIPHER_AES_CBC;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_3DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		session->cipher_alg = RTE_CRYPTO_CIPHER_3DES_CBC;
		break;
	case RTE_CRYPTO_CIPHER_AES_GCM:
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
	case RTE_CRYPTO_CIPHER_NULL:
	case RTE_CRYPTO_CIPHER_3DES_ECB:
	case RTE_CRYPTO_CIPHER_AES_ECB:
	case RTE_CRYPTO_CIPHER_AES_CTR:
	case RTE_CRYPTO_CIPHER_AES_CCM:
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		PMD_DRV_LOG(ERR, "Crypto: Unsupported Cipher alg %u",
			    cipher_xform->algo);
		goto error_out;
	default:
		PMD_DRV_LOG(ERR, "Crypto: Undefined Cipher specified %u\n",
			    cipher_xform->algo);
		goto error_out;
	}
	session->dir = (cipher_xform->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) ?
				DIR_ENC : DIR_DEC;

	if (session->ctxt_type == DPAA2_SEC_CIPHER_HASH) {
		/* TODO: add support for other Algos. IV length = 16 for AES */
		bufsize = cnstr_shdsc_authenc(priv->flc_desc[0].desc, 1,
					      0, &cipherdata, &authdata, 16,/*ctxt->iv.length,*/
				ctxt->auth_only_len, ctxt->trunc_len,
				session->dir);
	} else {
		PMD_DRV_LOG(ERR, "Hash before cipher not supported");
		goto error_out;
	}

	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)&(((struct dpaa2_sec_qp *)
			dev->data->queue_pairs[0])->rx_vq));
	session->ctxt = priv;

	return 0;

error_out:
	rte_free(session->cipher_key.data);
	rte_free(session->auth_key.data);
	return -1;
}


static void *
dpaa2_sec_session_configure(struct rte_cryptodev *dev,
			    struct rte_crypto_sym_xform *xform,	void *sess)
{
	struct dpaa2_sec_dev_private *internals = dev->data->dev_private;
	dpaa2_sec_session *session = sess;

	if (unlikely(sess == NULL)) {
		PMD_DRV_LOG(ERR, "invalid session struct");
		return NULL;
	}
	/* Cipher Only */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER && xform->next == NULL) {
		session->ctxt_type = DPAA2_SEC_CIPHER;
		dpaa2_sec_cipher_init(dev, xform, session);

	/* Authentication Only */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
			xform->next == NULL) {
		session->ctxt_type = DPAA2_SEC_AUTH;
		dpaa2_sec_auth_init(dev, xform, session);

	/* Cipher then Authenticate */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		session->ext_params.aead_ctxt.auth_cipher_text = TRUE;
		dpaa2_sec_aead_init(dev, xform, session);

	/* Authenticate then Cipher */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		session->ext_params.aead_ctxt.auth_cipher_text = FALSE;
		dpaa2_sec_aead_init(dev, xform, session);
	} else {
		PMD_DRV_LOG(ERR, "Invalid crypto type");
		return NULL;
	}

	return session;
}

/** Clear the memory of session so it doesn't leave key material behind */
static void
dpaa2_sec_session_clear(struct rte_cryptodev *dev __rte_unused, void *sess)
{
	if (sess)
		memset(sess, 0, sizeof(dpaa2_sec_session));
}

static int
dpaa2_sec_dev_configure(struct rte_cryptodev *dev)
{
	return -ENOTSUP;
}

static int
dpaa2_alloc_dq_storage(struct queue_storage_info_t *q_storage)
{
	int i;

	for (i = 0; i < 1/*NUM_DQS_PER_QUEUE*/; i++) {
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
	while (i >= 0) {
		rte_free(q_storage->dq_storage[i]);
	}
	return -1;
}

static int
dpaa2_sec_dev_start(struct rte_cryptodev *dev)
{
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)priv->hw;
	struct dpseci_attr attr;
	struct dpaa2_queue *dpaa2_q;
	struct dpaa2_sec_qp **qp = (struct dpaa2_sec_qp **)
					dev->data->queue_pairs;
	struct dpseci_rx_queue_attr rx_attr;
	struct dpseci_tx_queue_attr tx_attr;
	int ret, i;

	memset(&attr, 0, sizeof(struct dpseci_attr));

	ret = dpseci_enable(dpseci, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "DPSECI with HW_ID = %d ENABLE FAILED\n",
			    priv->hw_id);
		goto get_attr_failure;
	}
	ret = dpseci_get_attributes(dpseci, CMD_PRI_LOW, priv->token, &attr);
	if (ret) {
		PMD_DRV_LOG(ERR, "DPSEC ATTRIBUTE READ FAILED, disabling DPSEC\n");
		goto get_attr_failure;
	}
	for (i = 0; i < attr.num_rx_queues && qp[i]; i++) {
		dpaa2_q = &qp[i]->rx_vq;
		if (dpaa2_alloc_dq_storage(dpaa2_q->q_storage))
			return -1;
		dpseci_get_rx_queue(dpseci, CMD_PRI_LOW, priv->token, i,
				    &rx_attr);
		dpaa2_q->fqid = rx_attr.fqid;
		PMD_DRV_LOG(DEBUG, "rx_fqid: %d", dpaa2_q->fqid);
	}
	for (i = 0; i < attr.num_tx_queues && qp[i]; i++) {
		dpaa2_q = &qp[i]->tx_vq;
		dpseci_get_tx_queue(dpseci, CMD_PRI_LOW, priv->token, i,
				    &tx_attr);
		dpaa2_q->fqid = tx_attr.fqid;
		PMD_DRV_LOG(DEBUG, "tx_fqid: %d", dpaa2_q->fqid);
	}

	return 0;
get_attr_failure:
	dpseci_disable(dpseci, CMD_PRI_LOW, priv->token);
	return -1;
}

static void
dpaa2_sec_dev_stop(struct rte_cryptodev *dev)
{
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)priv->hw;
	int ret;

	ret = dpseci_disable(dpseci, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in disabling dpseci %d device\n",
			    priv->hw_id);
		return;
	}

	ret = dpseci_reset(dpseci, CMD_PRI_LOW, priv->token);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "SEC Device cannot be reset:Error Code = %0x\n",
			    ret);
		return;
	}
	return;
}

static int
dpaa2_sec_dev_close(struct rte_cryptodev *dev)
{
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)priv->hw;
	int ret;

	/*Function is reverse of dpaa2_sec_dev_init.
	 * It does the following:
	 * 1. Detach a DPSECI from attached resources i.e. buffer pools, dpbp_id.
	 * 2. Close the DPSECI device
	 * 3. Free the allocated resources.
	 */

	/*Close the device at underlying layer*/
	ret = dpseci_close(dpseci, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure closing dpseci device with"
			"error code %d\n", ret);
		return -1;
	}

	/*Free the allocated memory for ethernet private data and dpseci*/
	priv->hw = NULL;
	free(dpseci);

	return 0;
}

static void
dpaa2_sec_dev_infos_get(struct rte_cryptodev *dev, struct rte_cryptodev_info *info)
{
	struct dpaa2_sec_dev_private *internals = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();
	if (info != NULL) {
		info->max_nb_queue_pairs = internals->max_nb_queue_pairs;
		info->feature_flags = dev->feature_flags;
		info->capabilities = dpaa2_sec_capabilities;
		info->sym.max_nb_sessions = internals->max_nb_sessions;
		info->dev_type = RTE_CRYPTODEV_DPAA2_SEC_PMD;
	}
}

static
void dpaa2_sec_stats_get(struct rte_cryptodev *dev,
			 struct rte_cryptodev_stats *stats)
{
	struct dpaa2_sec_dev_private *priv = dev->data->dev_private;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)priv->hw;
	struct dpseci_sec_counters counters = {0};
	struct dpaa2_sec_qp **qp = (struct dpaa2_sec_qp **)
					dev->data->queue_pairs;
	int ret, i;

	PMD_INIT_FUNC_TRACE();
	if (stats == NULL) {
		PMD_DRV_LOG(ERR, "invalid stats ptr NULL");
		return;
	}
	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		if (qp[i] == NULL) {
			PMD_DRV_LOG(DEBUG, "Uninitialised queue pair");
			continue;
		}

		stats->enqueued_count += qp[i]->tx_vq.tx_pkts;
		stats->dequeued_count += qp[i]->rx_vq.rx_pkts;
		stats->enqueue_err_count += qp[i]->tx_vq.err_pkts;
		stats->dequeue_err_count += qp[i]->rx_vq.err_pkts;
	}

	ret = dpseci_get_sec_counters(dpseci, CMD_PRI_LOW, priv->token, &counters);
	if (ret) {
		PMD_DRV_LOG(ERR, "dpseci_get_sec_counters failed\n");
	} else {
		PMD_DRV_LOG(INFO, "dpseci hw stats:"
			"\n\tNumber of Requests Dequeued = %ul"
			"\n\tNumber of Outbound Encrypt Requests = %ul"
			"\n\tNumber of Inbound Decrypt Requests = %ul"
			"\n\tNumber of Outbound Bytes Encrypted = %ul"
			"\n\tNumber of Outbound Bytes Protected = %ul"
			"\n\tNumber of Inbound Bytes Decrypted = %ul"
			"\n\tNumber of Inbound Bytes Validated = %ul",
			counters.dequeued_requests,
			counters.ob_enc_requests,
			counters.ib_dec_requests,
			counters.ob_enc_bytes,
			counters.ob_prot_bytes,
			counters.ib_dec_bytes,
			counters.ib_valid_bytes);
	}

	return;
}

static
void dpaa2_sec_stats_reset(struct rte_cryptodev *dev)
{
	int i;
	struct dpaa2_sec_qp **qp = (struct dpaa2_sec_qp **)(dev->data->queue_pairs);

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		if (qp[i] == NULL) {
			PMD_DRV_LOG(DEBUG, "Uninitialised queue pair");
			continue;
		}
		qp[i]->tx_vq.rx_pkts = 0;
		qp[i]->tx_vq.tx_pkts = 0;
		qp[i]->tx_vq.err_pkts = 0;
		qp[i]->rx_vq.rx_pkts = 0;
		qp[i]->rx_vq.tx_pkts = 0;
		qp[i]->rx_vq.err_pkts = 0;
	}
	return;
}

static struct rte_cryptodev_ops crypto_ops = {
	.dev_configure	      = dpaa2_sec_dev_configure,
	.dev_start	      = dpaa2_sec_dev_start,
	.dev_stop	      = dpaa2_sec_dev_stop,
	.dev_close	      = dpaa2_sec_dev_close,
	.dev_infos_get        = dpaa2_sec_dev_infos_get,
	.stats_get	      = dpaa2_sec_stats_get,
	.stats_reset	      = dpaa2_sec_stats_reset,
	.queue_pair_setup     = dpaa2_sec_queue_pair_setup,
	.queue_pair_release   = dpaa2_sec_queue_pair_release,
	.queue_pair_start     = dpaa2_sec_queue_pair_start,
	.queue_pair_stop      = dpaa2_sec_queue_pair_stop,
	.queue_pair_count     = dpaa2_sec_queue_pair_count,
	.session_get_size     = dpaa2_sec_session_get_size,
	.session_initialize   = dpaa2_sec_session_initialize,
	.session_configure    = dpaa2_sec_session_configure,
	.session_clear        = dpaa2_sec_session_clear,
};

static int
dpaa2_sec_uninit(const char *name)
{
	if (name == NULL)
		return -EINVAL;

	PMD_DRV_LOG(INFO, "Closing DPAA2_SEC device %s on numa socket %u\n",
			   name, rte_socket_id());

	return 0;
}

static int
dpaa2_sec_dev_init(__attribute__((unused)) struct rte_cryptodev_driver *crypto_drv,
		   struct rte_cryptodev *dev)
{
	struct dpaa2_sec_dev_private *internals;
	struct fsl_mc_io *dpseci;
	uint16_t token;
	struct dpseci_attr attr;
	int retcode, hw_id = dev->pci_dev->addr.devid;

	PMD_INIT_FUNC_TRACE();
	PMD_DRV_LOG(DEBUG, "Found crypto device at %02x:%02x.%x\n",
		    dev->pci_dev->addr.bus,
		dev->pci_dev->addr.devid,
		dev->pci_dev->addr.function);

	dev->dev_type = RTE_CRYPTODEV_DPAA2_SEC_PMD;
	dev->dev_ops = &crypto_ops;

	dev->enqueue_burst = dpaa2_sec_enqueue_burst;
	dev->dequeue_burst = dpaa2_sec_dequeue_burst;
	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_HW_ACCELERATED |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING;

	internals = dev->data->dev_private;
	internals->max_nb_sessions = 2048;/*RTE_DPAA2_SEC_PMD_MAX_NB_SESSIONS*/

	/*
	 * For secondary processes, we don't initialise any further as primary
	 * has already done this work. Only check we don't need a different
	 * RX function
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(DEBUG, "Device already initialised by primary process");
		return 0;
	}

	/*Open the rte device via MC and save the handle for further use*/
	dpseci = (struct fsl_mc_io *)rte_calloc(NULL, 1,
				sizeof(struct fsl_mc_io), 0);
	if (!dpseci) {
		printf("Error in allocating the memory for dpsec object\n");
		return -1;
	}
	dpseci->regs = mcp_ptr_list[0];

	retcode = dpseci_open(dpseci, CMD_PRI_LOW, hw_id, &token);
	if (retcode != 0) {
		printf("Cannot open the dpsec device: Error Code = %x\n",
		       retcode);
		return -1;
	}
	retcode = dpseci_get_attributes(dpseci, CMD_PRI_LOW, token, &attr);
	if (retcode != 0) {
		printf("Cannot get dpsec device attributed: Error Code = %x\n",
		       retcode);
		return -1;
	}
	sprintf(dev->data->name, "dpsec-%u", hw_id);

	internals->max_nb_queue_pairs = attr.num_tx_queues;
	dev->data->nb_queue_pairs = internals->max_nb_queue_pairs;
	internals->hw = dpseci;
	internals->token = token;

	PMD_DRV_LOG(DEBUG, "driver %s: created\n", dev->data->name);
	return 0;

init_error:
	printf("driver %s: create failed\n", dev->data->name);

	/* dpaa2_sec_uninit(crypto_dev_name); */
	return -EFAULT;
}

static struct rte_pci_id pci_id_dpaa2_sec_map[] = {
		{
			RTE_PCI_DEVICE(FSL_VENDOR_ID, FSL_MC_DPSECI_DEVID),
		},
		{.device_id = 0},
};

static struct rte_cryptodev_driver rte_dpaa2_sec_pmd = {
	{
		.name = "rte_dpaa2_sec_pmd",
		.id_table = pci_id_dpaa2_sec_map,
	},
	.cryptodev_init = dpaa2_sec_dev_init,
	.dev_private_size = sizeof(struct dpaa2_sec_dev_private),
};

static int
rte_dpaa2_sec_pmd_init(const char *name __rte_unused, const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();
	return rte_cryptodev_pmd_driver_register(&rte_dpaa2_sec_pmd, PMD_PDEV);
}

static struct rte_driver pmd_dpaa2_sec_drv = {
	.type = PMD_PDEV,
	.init = rte_dpaa2_sec_pmd_init,
};

PMD_REGISTER_DRIVER(pmd_dpaa2_sec_drv, CRYPTODEV_NAME_DPAA2_SEC_PMD);
