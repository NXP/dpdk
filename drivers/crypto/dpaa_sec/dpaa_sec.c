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

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_cryptodev_pmd.h>

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
/* RTA header files */
#include <flib/desc/common.h>
#include <flib/desc/algo.h>
#include <flib/desc/ipsec.h>
#include <flib/rta.h>

#include "dpaa_sec.h"
#include "dpaa_sec_log.h"

#define FSL_VENDOR_ID		0x1957
#define FSL_DEVICE_ID		0x410
#define FSL_SUBSYSTEM_SEC	1
#define FSL_USDPAA_DOMAIN	2
#define FSL_USDPAA_BUSID	16
#define PCI_DEV_ADDR(dev) \
		((dev->addr.domain << 24) | (dev->addr.bus << 16) | \
		 (dev->addr.devid << 8) | (dev->addr.function))

#define NUM_POOL_CHANNELS	4
#define DPAA_SEC_MAX_DEVS	4
#define DPAA_SEC_DEV_ID_START	16
#define DPAA_SEC_BURST		32
#define DPAA_SEC_ALG_UNSUPPORT	(-1)

enum rta_sec_era rta_sec_era;

static __thread struct rte_crypto_op **dpaa_sec_ops;
static __thread int dpaa_sec_op_nb;

static inline struct dpaa_sec_ses *dpaa_sec_get_ses(struct rte_crypto_op *op)
{
	return (struct dpaa_sec_ses *)op->sym->session->_private;
}

static inline void dpaa_sec_op_ending(struct dpaa_sec_op_ctx *ctx)
{
	if (!ctx->fd_status)
		ctx->op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
	else {
		PMD_DRV_LOG(ERR,"\nSEC return err: %x\n",ctx->fd_status);
		ctx->op->status = RTE_CRYPTO_OP_STATUS_ERROR;
	}

	/* report op status to sym->op and then free the ctx memeory  */
	rte_free(ctx);
}

static inline struct dpaa_sec_job *dpaa_sec_alloc_job(void)
{
	struct dpaa_sec_op_ctx *ctx;

	ctx = rte_zmalloc(NULL, sizeof(*ctx), RTE_CACHE_LINE_SIZE);
	if (!ctx) {
		printf("Alloc sec descriptor failed!\n");
		return NULL;
	}

	return &ctx->job;
}

static inline phys_addr_t dpaa_mem_vtop(void *vaddr)
{
	const struct rte_memseg *memseg = rte_eal_get_physmem_layout();
	uint64_t vaddr_64, paddr;
	int i;

	vaddr_64 = (uint64_t)vaddr;
	for (i = 0; i < RTE_MAX_MEMSEG && memseg[i].addr_64 != 0; i++) {
		if (vaddr_64 >= memseg[i].addr_64 &&
		    vaddr_64 < memseg[i].addr_64 + memseg[i].len) {
			paddr = memseg[i].phys_addr +
				(vaddr_64 - memseg[i].addr_64);

			return (phys_addr_t)paddr;
		}
	}
	return (phys_addr_t)(NULL);
}

static inline void *dpaa_mem_ptov(phys_addr_t paddr)
{
	const struct rte_memseg *memseg = rte_eal_get_physmem_layout();
	int i;

	for (i = 0; i < RTE_MAX_MEMSEG && memseg[i].addr_64 != 0; i++) {
		if (paddr >= memseg[i].phys_addr &&
		    (char *)paddr < (char *)memseg[i].phys_addr + memseg[i].len)
			return (void *)(memseg[i].addr_64 +
					(paddr - memseg[i].phys_addr));
	}
	return NULL;
}

static void ern_sec_fq_handler(struct qman_portal *qm __rte_unused,
						       struct qman_fq *fq,
							   const struct qm_mr_entry *msg)
{
	printf("sec fq %d error, RC = %x, seqnum = %x\n", fq->fqid,
	       msg->ern.rc, msg->ern.seqnum);
}

/* initialize the queue with dest chan as caam chan so that
 * all the packets in this queue could be dispatched into caam
 */
static int dpaa_sec_init_rx(struct qman_fq *fq_in, phys_addr_t hwdesc,
			    uint32_t fqid_out)
{
	struct qm_mcc_initfq fq_opts;
	uint32_t flags;
	int ret = -1;

	/* Clear FQ options */
	memset(&fq_opts, 0x00, sizeof(struct qm_mcc_initfq));

	flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_DYNAMIC_FQID |
		QMAN_FQ_FLAG_TO_DCPORTAL;

	ret = qman_create_fq(0, flags, fq_in);
	if (unlikely(ret != 0)) {
		printf("qman_create_fq failed in %s\n", __func__);
		return ret;
	}

	flags = QMAN_INITFQ_FLAG_SCHED;
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
			  QM_INITFQ_WE_CONTEXTB;

	qm_fqd_context_a_set64(&fq_opts.fqd, hwdesc);
	fq_opts.fqd.context_b = fqid_out;
	fq_opts.fqd.dest.channel = qm_channel_caam;
	fq_opts.fqd.dest.wq = 0;

	fq_in->cb.ern  = ern_sec_fq_handler;

	ret = qman_init_fq(fq_in, flags, &fq_opts);
	if (unlikely(ret != 0))
		printf("qman_init_fq failed in %s\n", __func__);

	return ret;
}

/* something is put into in_fq and caam put the crypto result into out_fq */
static enum qman_cb_dqrr_result
dqrr_out_fq_cb_rx(struct qman_portal *qm __always_unused,
		  struct qman_fq *fq __always_unused,
		  const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd;
	struct dpaa_sec_job *job;
	struct dpaa_sec_op_ctx *ctx;

	if (dpaa_sec_op_nb >= DPAA_SEC_BURST)
		return qman_cb_dqrr_defer;

	if (!(dqrr->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

	fd = &dqrr->fd;
	/* sg is embedded in an op ctx,
	 * sg[0] is for output
	 * sg[1] for input
	 */
	job = dpaa_mem_ptov(qm_fd_addr_get64(fd));
	ctx = container_of(job, struct dpaa_sec_op_ctx, job);
	ctx->fd_status = fd->status;
	dpaa_sec_ops[dpaa_sec_op_nb++] = ctx->op;
	dpaa_sec_op_ending(ctx);

	return qman_cb_dqrr_consume;
}

/* caam result is put into this queue */
static int dpaa_sec_init_tx(struct qman_fq *fq)
{
	int ret;
	struct qm_mcc_initfq opts;
	uint32_t flags;

	flags = QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_LOCKED |
		QMAN_FQ_FLAG_DYNAMIC_FQID;

	ret = qman_create_fq(0, flags, fq);
	if (unlikely(ret)) {
		printf("qman_create_fq failed in %s\n", __func__);
		return ret;
	}

	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;

	/* opts.fqd.dest.channel = dpaa_sec_pool_chan; */

	fq->cb.dqrr = dqrr_out_fq_cb_rx;
	fq->cb.ern  = ern_sec_fq_handler;

	ret = qman_init_fq(fq, 0, &opts);
	if (unlikely(ret)) {
		printf("%s: unable to init caam source fq!\n", __func__);
		return ret;
	}

	return ret;
}

static inline int is_cipher_only(struct dpaa_sec_ses *ses)
{
	return ((ses->cipher.alg != RTE_CRYPTO_CIPHER_NULL) &&
		(ses->auth.alg == RTE_CRYPTO_AUTH_NULL));
}

static inline int is_auth_only(struct dpaa_sec_ses *ses)
{
	return ((ses->cipher.alg == RTE_CRYPTO_CIPHER_NULL) &&
		(ses->auth.alg != RTE_CRYPTO_AUTH_NULL));
}

static inline int is_auth_cipher(struct dpaa_sec_ses *ses)
{
	return ((ses->cipher.alg != RTE_CRYPTO_CIPHER_NULL) &&
		(ses->auth.alg != RTE_CRYPTO_AUTH_NULL));
}

static inline int is_encode(struct dpaa_sec_ses *ses)
{
	return ses->dir == DPAA_CRYPTO_ENCODE;
}

static inline int is_decode(struct dpaa_sec_ses *ses)
{
	return ses->dir == DPAA_CRYPTO_DECODE;
}

static inline uint32_t caam_auth_alg(struct dpaa_sec_ses *ses)
{
	switch (ses->auth.alg) {
	case RTE_CRYPTO_AUTH_NULL:
		ses->auth_trunc_len = 0;
		return 0;

	case RTE_CRYPTO_AUTH_MD5_HMAC:
		return OP_ALG_ALGSEL_MD5;

	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		return OP_ALG_ALGSEL_SHA1;

	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		return OP_ALG_ALGSEL_SHA224;

	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		return OP_ALG_ALGSEL_SHA256;

	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		return OP_ALG_ALGSEL_SHA384;

	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		return OP_ALG_ALGSEL_SHA512;

	default:
		PMD_DRV_LOG(ERR, "Crypto: unsupported auth alg %u\n",
			    ses->auth.alg);
		return DPAA_SEC_ALG_UNSUPPORT;
	}

	return 0;
}

static inline uint32_t caam_cipher_alg(struct dpaa_sec_ses *ses)
{
	switch (ses->cipher.alg) {
	case RTE_CRYPTO_CIPHER_NULL:
		return 0;

	case RTE_CRYPTO_CIPHER_AES_CBC:
		return OP_ALG_ALGSEL_AES;

	case RTE_CRYPTO_CIPHER_3DES_CBC:
		return OP_ALG_ALGSEL_3DES;

	default:
		PMD_DRV_LOG(ERR, "Crypto: unsupported cipher alg %d\n",
			    ses->cipher.alg);
		return DPAA_SEC_ALG_UNSUPPORT;
	}

	return 0;
}

static inline void dpaa_dump_bytes(char *p, int len)
{
	int i;

	printf("========================\n");
	for (i = 0; i < len; i++)
		printf("%02x ", p[i]);
	printf("\n========= done ===============\n");
}

#define POOL_BUF_SIZE 1024
#define CAAM_BURST_NUM_DEFAULT 1
/* prepare command block of the session */
static int dpaa_sec_prep_cdb(struct dpaa_sec_ses *ses)
{
	struct alginfo alginfo_c, alginfo_a;
	uint32_t shared_desc_len;
	struct dpaa_sec_qi *qi;
	struct sec_cdb *cdb;
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	int swap = false;
#else
	int swap = true;
#endif

	qi = ses->priv;
	cdb = &qi->cdb;
	memset(cdb, 0, sizeof(struct sec_cdb));

	alginfo_c.algtype = caam_cipher_alg(ses);
	if (alginfo_c.algtype == (unsigned)DPAA_SEC_ALG_UNSUPPORT) {
		PMD_DRV_LOG(ERR, "not supported cipher alg\n");
		return -1;
	}

	alginfo_c.key = (uint64_t)ses->cipher.key_data;
	alginfo_c.keylen = ses->cipher.key_len;
	alginfo_c.key_enc_flags = 0;
	alginfo_c.key_type = RTA_DATA_IMM;
	alginfo_c.algmode = OP_ALG_AAI_CBC;

	alginfo_a.algtype = caam_auth_alg(ses);
	if (alginfo_c.algtype == (unsigned)DPAA_SEC_ALG_UNSUPPORT) {
		PMD_DRV_LOG(ERR, "not supported auth alg\n");
		return -1;
	}

	alginfo_a.key = (uint64_t)ses->auth.key_data;
	alginfo_a.keylen = ses->auth.key_len;
	alginfo_a.key_enc_flags = 0;
	alginfo_a.key_type = RTA_DATA_IMM;
	alginfo_a.algmode = OP_ALG_AAI_HMAC;

	if (is_cipher_only(ses)) {
		/* TODO: add support for other Algos. IV length = 16 for AES */
		ses->cipher.iv_len = 16;
		shared_desc_len = cnstr_shdsc_blkcipher(cdb->sh_desc, true,
					swap, &alginfo_c,
					NULL, ses->cipher.iv_len,
					ses->dir);
	} else if (is_auth_only(ses)) {
		shared_desc_len = cnstr_shdsc_hmac(cdb->sh_desc, true,
					swap, &alginfo_a,
					!ses->dir, ses->auth_trunc_len);
	} else {
		/* TODO: add support for other Algos. IV length = 16 for AES */
		/* Auth_only_len is set as 0 here and it will be overwritten
		   in fd for each packet.*/
		ses->cipher.iv_len = 16;
		shared_desc_len = cnstr_shdsc_authenc(cdb->sh_desc, true,
					swap, &alginfo_c, &alginfo_a,
					ses->cipher.iv_len, 0,
					ses->auth_trunc_len, ses->dir);
	}
	cdb->sh_hdr.hi.field.idlen = shared_desc_len;
	cdb->sh_hdr.hi.word = rte_cpu_to_be_32(cdb->sh_hdr.hi.word);

	cdb->sh_hdr.lo.field.pool_buffer_size = rte_cpu_to_be_16(POOL_BUF_SIZE);
	cdb->sh_hdr.lo.field.offset = CAAM_BURST_NUM_DEFAULT;
	cdb->sh_hdr.lo.word = rte_cpu_to_be_32(cdb->sh_hdr.lo.word);

	return 0;
}

static inline unsigned usdpaa_volatile_deq(
	struct qman_fq *fq, unsigned len, bool exact)
{
	unsigned pkts = 0;
	int ret;
	struct qm_mcr_queryfq_np np;
	enum qman_fq_state state;
	uint32_t flags;
	uint32_t vdqcr;

	qman_query_fq_np(fq, &np);
	if (np.frm_cnt) {
		vdqcr = QM_VDQCR_NUMFRAMES_SET(len);
		if (exact)
			vdqcr |= QM_VDQCR_EXACT;
		ret = qman_volatile_dequeue(fq, 0, vdqcr);
		if (ret)
			return 0;
		do {
			pkts += qman_poll_dqrr(len);
			qman_fq_state(fq, &state, &flags);
		} while (flags & QMAN_FQ_STATE_VDQCR);
	}
	return pkts;
}

/* qp is lockless, should be accessed by only one thread */
static int dpaa_sec_deq(struct dpaa_sec_qp *qp, struct rte_crypto_op **ops,
			int nb_ops)
{
	struct qman_fq *fq;

	fq = &qp->outq;
	dpaa_sec_op_nb = 0;
	dpaa_sec_ops = ops;

	if (unlikely(DPAA_SEC_BURST < nb_ops))
		nb_ops = DPAA_SEC_BURST;

	return usdpaa_volatile_deq(fq, nb_ops, 1);
}

static inline struct dpaa_sec_ses *dpaa_get_sec_ses(struct rte_crypto_op *op)
{
	return (struct dpaa_sec_ses *)op->sym->session->_private;
}

/**
 * packet looks like:
 *		|<----data_len------->|
 *    |ip_header|ah_header|icv|payload|
 *              ^
 *		|
 *	   mbuf->pkt.data
 */
static inline struct dpaa_sec_job *build_auth_only(struct rte_crypto_op *op)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct rte_mbuf *mbuf = sym->m_src;
	struct dpaa_sec_ses *ses;
	struct dpaa_sec_job *cf;
	struct dpaa_sec_op_ctx *ctx;
	struct qm_sg_entry *sg;
	phys_addr_t start_addr;
	uint8_t *old_digest;

	cf = dpaa_sec_alloc_job();
	if (!cf)
		return NULL;

	ctx = container_of(cf, struct dpaa_sec_op_ctx, job);
	ctx->op = op;
	old_digest = ctx->digest;
	ses = dpaa_get_sec_ses(op);

	start_addr = rte_pktmbuf_mtophys(mbuf);
	/* output */
	sg = &cf->sg[0];
	qm_sg_entry_set64(sg, sym->auth.digest.phys_addr);
	sg->length = sym->auth.digest.length;
	cpu_to_hw_sg(sg);

	/* input */
	sg = &cf->sg[1];
	if (is_decode(ses)) {
		/* need to extend the input to a compound frame */
		sg->extension = 1;
		qm_sg_entry_set64(sg, dpaa_mem_vtop(&cf->sg[2]));
		sg->length = sym->auth.data.length;
		sg->final = 1;
		cpu_to_hw_sg(sg);

		sg = &cf->sg[2];
		/* hash result or digest, save digest first */
		rte_memcpy(old_digest, sym->auth.digest.data,
			   sym->auth.digest.length);
		memset(sym->auth.digest.data, 0, sym->auth.digest.length);
		qm_sg_entry_set64(sg, sym->auth.digest.phys_addr);
		sg->length = sym->auth.digest.length;
		cpu_to_hw_sg(sg);

		sg++;
		qm_sg_entry_set64(sg, start_addr + sym->auth.data.offset);
		sg->length = sym->auth.data.length;
		cpu_to_hw_sg(sg);

		/* let's check digest by hw */
		start_addr = dpaa_mem_vtop(old_digest);
		sg++;
		qm_sg_entry_set64(sg, start_addr);
		sg->length = sym->auth.digest.length;
		sg->final = 1;
		cpu_to_hw_sg(sg);
	} else {
		qm_sg_entry_set64(sg, start_addr + sym->auth.data.offset);
		sg->length = sym->auth.data.length;
		sg->final = 1;
		cpu_to_hw_sg(sg);
	}

	return cf;
}

static inline struct dpaa_sec_job *build_cipher_only(struct rte_crypto_op *op)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct rte_mbuf *mbuf = sym->m_src;
	struct dpaa_sec_job *cf;
	struct dpaa_sec_op_ctx *ctx;
	struct qm_sg_entry *sg;
	phys_addr_t start_addr;

	cf = dpaa_sec_alloc_job();
	if (!cf)
		return NULL;

	ctx = container_of(cf, struct dpaa_sec_op_ctx, job);
	ctx->op = op;
	start_addr = rte_pktmbuf_mtophys(mbuf);

	/* output */
	sg = &cf->sg[0];
	qm_sg_entry_set64(sg, start_addr + sym->cipher.data.offset);
	sg->length = sym->cipher.data.length + sym->cipher.iv.length;
	cpu_to_hw_sg(sg);

	/* input */
	sg = &cf->sg[1];

	/* need to extend the input to a compound frame */
	sg->extension = 1;
	sg->final = 1;
	sg->length = sym->cipher.data.length + sym->cipher.iv.length;
	qm_sg_entry_set64(sg, dpaa_mem_vtop(&cf->sg[2]));
	cpu_to_hw_sg(sg);

	sg = &cf->sg[2];
	qm_sg_entry_set64(sg, sym->cipher.iv.phys_addr);
	sg->length = sym->cipher.iv.length;
	cpu_to_hw_sg(sg);

	sg++;
	qm_sg_entry_set64(sg, start_addr + sym->cipher.data.offset);
	sg->length = sym->cipher.data.length;
	sg->final = 1;
	cpu_to_hw_sg(sg);

	return cf;
}

static inline struct dpaa_sec_job *build_cipher_auth(struct rte_crypto_op *op)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct rte_mbuf *mbuf = sym->m_src;
	struct dpaa_sec_ses *ses;
	struct dpaa_sec_job *cf;
	struct dpaa_sec_op_ctx *ctx;
	struct qm_sg_entry *sg;
	phys_addr_t start_addr;
	uint32_t length = 0;

	start_addr = mbuf->buf_physaddr + mbuf->data_off;

	cf = dpaa_sec_alloc_job();
	if (!cf)
		return NULL;

	ctx = container_of(cf, struct dpaa_sec_op_ctx, job);
	ctx->op = op;
	ctx->auth_only_len = sym->auth.data.length - sym->cipher.data.length;
	ses = dpaa_get_sec_ses(op);

	/* input */
	sg = &cf->sg[2];
	qm_sg_entry_set64(&cf->sg[1], dpaa_mem_vtop(sg));
	if (is_encode(ses)) {
		qm_sg_entry_set64(sg, sym->cipher.iv.phys_addr);
		sg->length = sym->cipher.iv.length;
		length += sg->length;
		cpu_to_hw_sg(sg);

		sg++;
		qm_sg_entry_set64(sg, start_addr + sym->auth.data.offset);
		sg->length = sym->auth.data.length;
		length += sg->length;
		sg->final = 1;
		cpu_to_hw_sg(sg);
	} else {
		qm_sg_entry_set64(sg, sym->cipher.iv.phys_addr);
		sg->length = sym->cipher.iv.length;
		length += sg->length;
		cpu_to_hw_sg(sg);

		sg++;

		qm_sg_entry_set64(sg, start_addr + sym->auth.data.offset);
		sg->length = sym->auth.data.length;
		length += sg->length;
		cpu_to_hw_sg(sg);

		memcpy(ctx->digest, sym->auth.digest.data, sym->auth.digest.length);
		memset(sym->auth.digest.data, 0, sym->auth.digest.length);
		sg++;

		qm_sg_entry_set64(sg, dpaa_mem_vtop(ctx->digest));
		sg->length = sym->auth.digest.length;
		length += sg->length;
		sg->final = 1;
		cpu_to_hw_sg(sg);
	}
	/* input compound frame */
	cf->sg[1].length = length;
	cf->sg[1].extension = 1;
	cf->sg[1].final = 1;
	cpu_to_hw_sg(&cf->sg[1]);

	/* output */
	sg++;
	qm_sg_entry_set64(&cf->sg[0], dpaa_mem_vtop(sg));
	qm_sg_entry_set64(sg, start_addr + sym->cipher.data.offset);
	sg->length = sym->cipher.data.length;
	length = sg->length;
	if (is_encode(ses)) {
		cpu_to_hw_sg(sg);
		/* set auth output */
		sg++;
		qm_sg_entry_set64(sg, sym->auth.digest.phys_addr);
		sg->length = sym->auth.digest.length;
		length += sg->length;
	}
	sg->final = 1;
	cpu_to_hw_sg(sg);

	/* output compound frame */
	cf->sg[0].length = length;
	cf->sg[0].extension = 1;
	cpu_to_hw_sg(&cf->sg[0]);

	return cf;
}

static int
dpaa_sec_enqueue_op(struct rte_crypto_op *op,  struct dpaa_sec_qp *qp)
{
	struct dpaa_sec_job *cf;
	struct dpaa_sec_ses *ses;
	struct qm_fd fd;
	int ret;
	uint32_t auth_only_len = op->sym->auth.data.length -
				op->sym->cipher.data.length;

	ses = dpaa_get_sec_ses(op);

	if (is_auth_only(ses))
		cf = build_auth_only(op);
	else if (is_cipher_only(ses))
		cf = build_cipher_only(op);
	else if (is_auth_cipher(ses))
		cf = build_cipher_auth(op);
	else {
		printf("not supported sec op\n");
		return -1;
	}
	if (unlikely(!cf))
		return -1;

	memset(&fd, 0, sizeof(struct qm_fd));
	qm_fd_addr_set64(&fd, dpaa_mem_vtop(cf->sg));
	fd._format1 = qm_fd_compound;
	fd.length29 = sizeof(2 * sizeof(struct qm_sg_entry));
	/* Auth_only_len is set as 0 in descriptor and it is overwritten
	   here in the fd.cmd which will update the DPOVRD reg. */
	if (auth_only_len)
		fd.cmd = 0x80000000 | auth_only_len;
	do {
		ret = qman_enqueue(&qp->inq, &fd, 0);
	} while (ret != 0);

	return 0;
}

static uint16_t
dpaa_sec_enqueue_burst(void *qp, struct rte_crypto_op **ops,
		       uint16_t nb_ops)
{
	/* Function to transmit the frames to given device and queuepair */
	uint32_t loop;
	int32_t ret;
	struct dpaa_sec_qp *dpaa_qp = (struct dpaa_sec_qp *)qp;
	uint16_t num_tx = 0;

	if (unlikely(nb_ops == 0))
		return 0;

	if (ops[0]->sym->sess_type != RTE_CRYPTO_SYM_OP_WITH_SESSION) {
		PMD_DRV_LOG(ERR, "sessionless crypto op not supported\n");
		return 0;
	}

	/*Prepare each packet which is to be sent*/
	for (loop = 0; loop < nb_ops; loop++) {
		ret = dpaa_sec_enqueue_op(ops[loop], dpaa_qp);
		if (!ret)
			num_tx++;
	}
	dpaa_qp->tx_pkts += num_tx;
	dpaa_qp->tx_errs += nb_ops - num_tx;

	return num_tx;
}

static uint16_t
dpaa_sec_dequeue_burst(void *qp, struct rte_crypto_op **ops,
		       uint16_t nb_ops)
{
	uint16_t num_rx;
	struct dpaa_sec_qp *dpaa_qp = (struct dpaa_sec_qp *)qp;

	num_rx = dpaa_sec_deq(dpaa_qp, ops, nb_ops);

	dpaa_qp->rx_pkts += num_rx;
	dpaa_qp->rx_errs += nb_ops - num_rx;

	PMD_DRV_LOG(DEBUG, "SEC Received %d Packets\n", num_rx);

	return num_rx;
}

/** Setup a queue pair */
static int
dpaa_sec_queue_pair_setup(struct rte_cryptodev *dev, uint16_t qp_id,
		__rte_unused const struct rte_cryptodev_qp_conf *qp_conf,
		__rte_unused int socket_id)
{
	struct dpaa_sec_qi *qi;
	struct dpaa_sec_qp *qp = NULL;

	PMD_DRV_LOG(DEBUG, "dev =%p, queue =%d, conf =%p", dev, qp_id, qp_conf);

	qi = dev->data->dev_private;
	if (qp_id >= qi->max_nb_queue_pairs) {
		printf("Max supported qpid %d\n", qi->max_nb_queue_pairs);
		return -1;
	}

	qp = &qi->qps[qp_id];
	qp->qi = qi;
	dev->data->queue_pairs[qp_id] = qp;

	return 0;
}

/** Start queue pair */
static int
dpaa_sec_queue_pair_start(__rte_unused struct rte_cryptodev *dev,
			  __rte_unused uint16_t queue_pair_id)
{
	return 0;
}

/** Release queue pair */
static int
dpaa_sec_queue_pair_release(__rte_unused struct rte_cryptodev *dev,
			    __rte_unused uint16_t queue_pair_id)
{
	return 0;
}

/** Stop queue pair */
static int
dpaa_sec_queue_pair_stop(__rte_unused struct rte_cryptodev *dev,
			 __rte_unused uint16_t queue_pair_id)
{
	return 0;
}

/** Return the number of allocated queue pairs */
static uint32_t
dpaa_sec_queue_pair_count(struct rte_cryptodev *dev)
{
	return dev->data->nb_queue_pairs;
}

/** Returns the size of session structure */
static unsigned
dpaa_sec_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct dpaa_sec_ses);
}

static void
dpaa_sec_session_initialize(struct rte_mempool *mp __rte_unused,
						    void *ses __rte_unused)
{
}

static int dpaa_ses_cipher_init(struct rte_cryptodev *dev __rte_unused,
				struct rte_crypto_sym_xform *xform,
				struct dpaa_sec_ses *session)
{
	session->cipher.alg = xform->cipher.algo;
	session->cipher.key_data = rte_zmalloc(NULL, xform->cipher.key.length,
					       RTE_CACHE_LINE_SIZE);
	if (session->cipher.key_data == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for cipher key");
		return -1;
	}
	session->cipher.key_len = xform->cipher.key.length;

	memcpy(session->cipher.key_data, xform->cipher.key.data,
	       xform->cipher.key.length);
	session->dir = (xform->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) ?
			DPAA_CRYPTO_ENCODE : DPAA_CRYPTO_DECODE;

	return 0;
}

static int dpaa_ses_auth_init(struct rte_cryptodev *dev __rte_unused,
			      struct rte_crypto_sym_xform *xform,
			      struct dpaa_sec_ses *session)
{
	session->auth.alg = xform->auth.algo;
	session->auth.key_data = rte_zmalloc(NULL, xform->auth.key.length,
					     RTE_CACHE_LINE_SIZE);
	if (session->auth.key_data == NULL) {
		PMD_DRV_LOG(ERR, "\nNo Memory for auth key");
		return -1;
	}
	session->auth.key_len = xform->auth.key.length;
	session->auth_trunc_len = xform->auth.digest_length;

	memcpy(session->auth.key_data, xform->auth.key.data,
	       xform->auth.key.length);
	session->dir = (xform->auth.op == RTE_CRYPTO_AUTH_OP_GENERATE) ?
		       DPAA_CRYPTO_ENCODE : DPAA_CRYPTO_DECODE;

	return 0;
}

static void *
dpaa_sec_session_configure(struct rte_cryptodev *dev,
			   struct rte_crypto_sym_xform *xform, void *ses)
{
	struct dpaa_sec_qi *qi;
	struct dpaa_sec_ses *session = ses;

	if (unlikely(ses == NULL)) {
		PMD_DRV_LOG(ERR, "invalid session struct");
		return NULL;
	}

	/* Cipher Only */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER && xform->next == NULL) {
		session->auth.alg = RTE_CRYPTO_AUTH_NULL;
		dpaa_ses_cipher_init(dev, xform, session);

	/* Authentication Only */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		   xform->next == NULL) {
		session->cipher.alg = RTE_CRYPTO_CIPHER_NULL;
		dpaa_ses_auth_init(dev, xform, session);

	/* Cipher then Authenticate */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		   xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		if (xform->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) {
			dpaa_ses_cipher_init(dev, xform, session);
			dpaa_ses_auth_init(dev, xform->next, session);
		} else {
			PMD_DRV_LOG(ERR, "Not supported: Authenticate then Cipher");
			return NULL;
		}

	/* Authenticate then Cipher */
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		   xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		if (xform->auth.op == RTE_CRYPTO_AUTH_OP_VERIFY) {
			dpaa_ses_auth_init(dev, xform, session);
			dpaa_ses_cipher_init(dev, xform->next, session);
		} else {
			PMD_DRV_LOG(ERR, "Not supported: Authenticate then Cipher");
			return NULL;
		}
	} else {
		PMD_DRV_LOG(ERR, "Invalid crypto type");
		return NULL;
	}

	qi = dev->data->dev_private;
	session->priv = qi;
	qi->ses = session;
	dpaa_sec_prep_cdb(session/*, cf*/);

	return session;
}

/** Clear the memory of session so it doesn't leave key material behind */
static void
dpaa_sec_session_clear(struct rte_cryptodev *dev __rte_unused, void *sess)
{
	if (sess)
		memset(sess, 0, sizeof(struct dpaa_sec_ses));
}

static int
dpaa_sec_dev_configure(struct rte_cryptodev *dev)
{
	struct dpaa_sec_qi *qi;
	struct dpaa_sec_qp *qp;
	uint32_t i;
	int ret;

	qi = dev->data->dev_private;
	for (i = 0; i < qi->max_nb_queue_pairs; i++) {
		/* init qman fq for queue pair */
		qp = &qi->qps[i];
		ret = dpaa_sec_init_tx(&qp->outq);
		if (ret) {
			PMD_DRV_LOG(ERR, "config tx of queue pair  %d\n", i);
			return -1;
		}

		ret = dpaa_sec_init_rx(&qp->inq, dpaa_mem_vtop(&qi->cdb),
				       qman_fq_fqid(&qp->outq));
		if (ret) {
			PMD_DRV_LOG(ERR, "config rx of queue pair %d\n", i);
			return -1;
		}
	}

	return 0;
}

static int
dpaa_sec_dev_start(struct rte_cryptodev *dev __rte_unused)
{
	return 0;
}

static void
dpaa_sec_dev_stop(struct rte_cryptodev *dev __rte_unused)
{
}

static int
dpaa_sec_dev_close(struct rte_cryptodev *dev __rte_unused)
{
	return 0;
}

static void
dpaa_sec_dev_infos_get(struct rte_cryptodev *dev,
		       struct rte_cryptodev_info *info)
{
	struct dpaa_sec_qi *qi = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();
	if (info != NULL) {
		info->max_nb_queue_pairs = qi->max_nb_queue_pairs;
		info->feature_flags = dev->feature_flags;
		info->capabilities = dpaa_sec_capabilities;
		info->sym.max_nb_sessions = qi->max_nb_sessions;
		info->dev_type = RTE_CRYPTODEV_DPAA_SEC_PMD;
	}
}

static
void dpaa_sec_stats_get(struct rte_cryptodev *dev __rte_unused,
			struct rte_cryptodev_stats *stats __rte_unused)
{
	/* -ENOTSUP; */
}

static
void dpaa_sec_stats_reset(struct rte_cryptodev *dev __rte_unused)
{
	/* -ENOTSUP; */
}

static int
dpaa_sec_dev_uninit(__attribute__((unused))
		  const struct rte_cryptodev_driver *crypto_drv,
		  struct rte_cryptodev *dev)
{
	if (dev->data->name == NULL)
		return -EINVAL;

	PMD_DRV_LOG(INFO, "Closing dpaa crypto device %s\n", dev->data->name);

	return 0;
}

static struct rte_cryptodev_ops crypto_ops = {
	.dev_configure	      = dpaa_sec_dev_configure,
	.dev_start	      = dpaa_sec_dev_start,
	.dev_stop	      = dpaa_sec_dev_stop,
	.dev_close	      = dpaa_sec_dev_close,
	.dev_infos_get        = dpaa_sec_dev_infos_get,
	.stats_get	      = dpaa_sec_stats_get,
	.stats_reset	      = dpaa_sec_stats_reset,
	.queue_pair_setup     = dpaa_sec_queue_pair_setup,
	.queue_pair_release   = dpaa_sec_queue_pair_release,
	.queue_pair_start     = dpaa_sec_queue_pair_start,
	.queue_pair_stop      = dpaa_sec_queue_pair_stop,
	.queue_pair_count     = dpaa_sec_queue_pair_count,
	.session_get_size     = dpaa_sec_session_get_size,
	.session_initialize   = dpaa_sec_session_initialize,
	.session_configure    = dpaa_sec_session_configure,
	.session_clear        = dpaa_sec_session_clear,
};

static int
dpaa_sec_dev_init(__attribute__((unused))
		  struct rte_cryptodev_driver *crypto_drv,
		  struct rte_cryptodev *dev)
{
	struct dpaa_sec_qi *qi;

	PMD_INIT_FUNC_TRACE();
	PMD_DRV_LOG(DEBUG, "Found crypto device at %02x:%02x.%x\n",
		    dev->pci_dev->addr.bus,
		    dev->pci_dev->addr.devid,
		    dev->pci_dev->addr.function);

	dev->dev_type = RTE_CRYPTODEV_DPAA_SEC_PMD;
	dev->dev_ops = &crypto_ops;

	dev->enqueue_burst = dpaa_sec_enqueue_burst;
	dev->dequeue_burst = dpaa_sec_dequeue_burst;
	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			     RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			     RTE_CRYPTODEV_FF_HW_ACCELERATED;

	/* allocate private device */
	qi = rte_zmalloc(NULL, crypto_drv->dev_private_size,
			 RTE_CACHE_LINE_SIZE);
	if (unlikely(!qi)) {
		PMD_DRV_LOG(ERR, "cannot alloc private device for sec!\n");
		return -1;
	}
	qi->max_nb_queue_pairs = RTE_MAX_NB_SEC_QPS;
	qi->max_nb_sessions = RTE_MAX_NB_SEC_SES;
	dev->data->dev_private = qi;

	dpaa_sec_dev_configure(dev);

	PMD_DRV_LOG(DEBUG, "driver %s: created\n", dev->data->name);

	return 0;
}

static struct rte_pci_id pci_id_dpaa_sec_map[] = {
		{
			RTE_PCI_DEVICE(FSL_VENDOR_ID, FSL_DEVICE_ID),
		},
};

static struct rte_cryptodev_driver dpaa_sec_pmd = {
	{
		.name = "rte_dpaa_sec_pmd",
		.id_table = pci_id_dpaa_sec_map,
	},
	.cryptodev_init = dpaa_sec_dev_init,
	.cryptodev_uninit = dpaa_sec_dev_uninit,
	.dev_private_size = sizeof(struct dpaa_sec_qi),
};

static inline void insert_devices_into_pcilist(struct rte_pci_device *dev)
{
	uint32_t devaddr;
	uint32_t newdevaddr;
	struct rte_pci_device *dev2 = NULL;

	if (!(TAILQ_EMPTY(&pci_device_list))) {
		newdevaddr = PCI_DEV_ADDR(dev);
		TAILQ_FOREACH(dev2, &pci_device_list, next) {
			devaddr = PCI_DEV_ADDR(dev2);

			if (newdevaddr < devaddr) {
				TAILQ_INSERT_BEFORE(dev2, dev, next);
				return;
			}
		}
	}
	TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
}

#include <internal/of.h>
/**
 * @brief	Reads the SEC device and ERA from DTS by using the of library
 * @returns	-1 if the SEC device not available (i.e. the property does
 *		not exist in DTS),
 */
static inline int dpaa_sec_available(void)
{
	const struct device_node *caam_node;

	for_each_compatible_node(caam_node, NULL, "fsl,sec-v4.0") {
		const uint32_t *prop = of_get_property(caam_node,
				"fsl,sec-era",
				NULL);
		if (prop) {
			rta_set_sec_era(INTL_SEC_ERA(rte_cpu_to_be_32(*prop)));
		}
		return 0;
	}

	return -1;
}

static int
dpaa_sec_pmd_init(const char *name __rte_unused,
		  const char *params __rte_unused)
{
	struct rte_pci_device *dev;
	int i;

	if (dpaa_sec_available()) {
		PMD_DRV_LOG(INFO, "FSL DPAA SEC not available");
		return -1;
	}

	for (i = 0; i < DPAA_SEC_MAX_DEVS; i++) {
		dev = rte_zmalloc(0, sizeof(struct rte_pci_device),
				  RTE_CACHE_LINE_SIZE);
		if (!dev) {
			printf("Failed to allocate dev for sec\n");
			return -1;
		}

		dev->addr.domain = FSL_USDPAA_DOMAIN;
		dev->addr.bus = FSL_USDPAA_BUSID;
		dev->addr.devid = DPAA_SEC_DEV_ID_START + i;
		dev->id.vendor_id = FSL_VENDOR_ID;
		dev->id.device_id = FSL_DEVICE_ID;
		dev->id.subsystem_vendor_id = FSL_VENDOR_ID;
		dev->id.subsystem_device_id = FSL_SUBSYSTEM_SEC;
		dev->numa_node = 0;

		/* device is valid, add in list (sorted) */
		insert_devices_into_pcilist(dev);
	}

	return rte_cryptodev_pmd_driver_register(&dpaa_sec_pmd, PMD_PDEV);
}

static struct rte_driver dpaa_sec_pmd_drv = {
	.type = PMD_PDEV,
	.init = dpaa_sec_pmd_init,
};

PMD_REGISTER_DRIVER(dpaa_sec_pmd_drv, CRYPTODEV_NAME_DPAA_SEC_PMD);
