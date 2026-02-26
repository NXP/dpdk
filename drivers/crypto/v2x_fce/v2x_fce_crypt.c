/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <cryptodev_pmd.h>
#include <rte_crypto_sym.h>
#include <common/dpaax/compat.h>

#include "v2x_fce_pvt.h"
#include "v2x_fce_api.h"

int
is_auth_cipher(struct fce_crypto_session *sess)
{
	return ((sess->cipher.algo != 0) &&
		(sess->auth.sha_algo != 0));
}

int
is_cipher_only(struct fce_crypto_session *sess)
{
	return ((sess->cipher.algo != 0) &&
		(sess->auth.sha_algo == 0));
}

int
is_aead(struct fce_crypto_session *sess)
{
	return ((sess->cipher.algo == 0) &&
		(sess->auth.sha_algo == 0) &&
		(sess->aead.algo != 0));
}

int
is_auth_only(struct fce_crypto_session *sess)
{
	return ((sess->auth.sha_algo != 0) &&
		(sess->cipher.algo == 0));
}

int
fce_auth_build(struct rte_crypto_op *op,
	       uint8_t buf_off,
	       uint8_t flag)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct fce_crypto_session *sess;
	rte_iova_t src_addr;
	uint8_t *mu_buf, *data;
	uint32_t pktlen, i;

	sess = CRYPTODEV_GET_SYM_SESS_PRIV(sym->session);

	/* FCE MU buffer address */
	mu_buf = (uint8_t *)sess->fce_mu_base + sess->fce_mu_offset + buf_off;

	/* source address */
	src_addr = rte_pktmbuf_iova_offset(sym->m_src,
					   sym->auth.data.offset);

	/* cache flush */
	pktlen = rte_pktmbuf_pkt_len(sym->m_src);
	data = rte_pktmbuf_mtod(sym->m_src, void *);
	for (i = 0; i <= pktlen; i += RTE_CACHE_LINE_SIZE)
		dcbf(data + i);

	for (i = 0; i <= sess->auth.digest_len; i += RTE_CACHE_LINE_SIZE)
		dcbf(sym->auth.digest.data + i);

	fce_auth_construct((uint32_t *)mu_buf, sess->auth.key_slot,
			   (uint32_t)src_addr, sym->auth.data.length,
			   (uint32_t)sym->auth.digest.phys_addr,
			   sess->auth.sha_algo, flag,
			   sess->auth.op);

	return 0;
}

int
fce_cipher_build(struct rte_crypto_op *op,
		 uint8_t buf_off,
		 uint8_t flag)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct fce_crypto_session *sess;
	rte_iova_t src_addr, dst_addr;
	uint32_t digest_addr;
	uint8_t sha_algo;
	uint8_t *mu_buf, *data, *iv = NULL;
	uint32_t pktlen, i;

	sess = CRYPTODEV_GET_SYM_SESS_PRIV(sym->session);

	/* FCE MU buffer address */
	mu_buf = (uint8_t *)sess->fce_mu_base + sess->fce_mu_offset + buf_off;

	/* source address */
	src_addr = rte_pktmbuf_iova_offset(sym->m_src,
					   sym->cipher.data.offset);

	/* dest address */
	if (sym->m_dst)
		dst_addr = rte_pktmbuf_iova_offset(sym->m_dst,
						   sym->cipher.data.offset);
	else
		dst_addr = src_addr;

	if (sess->auth.sha_algo != 0) {
		digest_addr = (uint32_t)sym->auth.digest.phys_addr;
		sha_algo = sess->auth.sha_algo;
	} else {
		digest_addr = 0;
		sha_algo = 0;
	}

	/* cache flush */
	pktlen = rte_pktmbuf_pkt_len(sym->m_src);
	data = rte_pktmbuf_mtod(sym->m_src, void *);
	for (i = 0; i <= pktlen; i += RTE_CACHE_LINE_SIZE)
		dcbf(data + i);

	switch (sess->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		iv = rte_crypto_op_ctod_offset(op, uint8_t *,
					       sess->cipher.iv_offset);
		fce_cbc_construct((uint32_t *)mu_buf, sess->cipher.key_slot,
				  (uint32_t)src_addr, (uint32_t)dst_addr,
				  sym->cipher.data.length, sess->cipher.op,
				  iv, sess->cipher.iv_len,
				  digest_addr, sha_algo, flag);
		break;
	case RTE_CRYPTO_CIPHER_AES_ECB:
		fce_ecb_construct((uint32_t *)mu_buf, sess->cipher.key_slot,
				  (uint32_t)src_addr, (uint32_t)dst_addr,
				  sym->cipher.data.length, sess->cipher.op,
				  digest_addr, sha_algo, flag);
		break;
	default:
		FCE_ERR("unsupported cipher algo %u", sess->cipher.algo);
		return -1;
	}

	return 0;
}


int
fce_aead_build(struct rte_crypto_op *op,
	       uint8_t buf_off)
{
	struct rte_crypto_sym_op *sym = op->sym;
	struct fce_crypto_session *sess;
	rte_iova_t src_addr, dst_addr;
	uint8_t *mu_buf, *data, *iv = NULL;
	uint32_t pktlen, i;

	sess = CRYPTODEV_GET_SYM_SESS_PRIV(sym->session);

	/* FCE MU buffer address */
	mu_buf = (uint8_t *)sess->fce_mu_base + sess->fce_mu_offset + buf_off;

	/* src address */
	src_addr = rte_pktmbuf_iova_offset(sym->m_src,
					   sym->aead.data.offset);

	/* dest address */
	if (sym->m_dst)
		dst_addr = rte_pktmbuf_iova_offset(sym->m_dst,
						   sym->aead.data.offset);
	else
		dst_addr = src_addr;

	/* cache flush */
	pktlen = rte_pktmbuf_pkt_len(sym->m_src);
	data = rte_pktmbuf_mtod(sym->m_src, void *);
	for (i = 0; i <= pktlen; i += RTE_CACHE_LINE_SIZE)
		dcbf(data + i);

	switch (sess->aead.algo) {
	case RTE_CRYPTO_AEAD_AES_GCM:
		iv = rte_crypto_op_ctod_offset(op, uint8_t *,
					       sess->aead.iv_offset);
		fce_gcm_construct((uint32_t *)mu_buf, sess->aead.key_slot,
				  (uint32_t)src_addr, (uint32_t)dst_addr,
				  sym->aead.data.length, sess->aead.op,
				  iv, sess->aead.iv_len,
				  (uint32_t)sym->aead.aad.phys_addr,
				  sess->aead.aad_len,
				  0, 0);
		break;
	case RTE_CRYPTO_AEAD_AES_CCM:
	default:
		FCE_ERR("unsupported aead algo %u", sess->aead.algo);
		return -1;
	}

	return 0;
}
