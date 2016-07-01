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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_cryptodev_pmd.h>
#include <rte_dev.h>
#include <rte_malloc.h>
#include <rte_cpuflags.h>

#include "armce_pmd_private.h"

/**
 * Global static parameter used to create a unique name for each crypto device.
 */
static unsigned unique_name_id;

static inline int
create_unique_device_name(char *name, size_t size)
{
	int ret;

	if (name == NULL)
		return -EINVAL;

	ret = snprintf(name, size, "%s_%u", CRYPTODEV_NAME_ARMCE_PMD,
			unique_name_id++);
	if (ret < 0)
		return ret;
	return 0;
}

static const EVP_CIPHER *
xform_get_evp_cipher(const struct rte_crypto_sym_xform *xform)
{
	int key_len_bytes = xform->cipher.key.length;
	int key_len_bits = key_len_bytes * 8;

	switch (xform->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		switch (key_len_bits) {
		case 128:
			return EVP_aes_128_cbc();
		case 192:
			return EVP_aes_192_cbc();
		case 256:
			return EVP_aes_256_cbc();
		default:
			ARMCE_LOG_ERR("Could not find a valid "
				      "key cipher config");
			return NULL;
		}
	case RTE_CRYPTO_CIPHER_AES_CTR:
		switch (key_len_bits) {
		case 128:
			return EVP_aes_128_ctr();
		case 192:
			return EVP_aes_192_ctr();
		case 256:
			return EVP_aes_256_ctr();
		default:
			ARMCE_LOG_ERR("Could not find a valid "
				      "key cipher config");
			return NULL;
		}
	default:
		ARMCE_LOG_ERR("Could not find a valid cipher algorithm");
		return NULL;
	}
	return NULL;
}

static int
armce_set_cipher_session_parameters(struct armce_session *sess,
				    const struct rte_crypto_sym_xform *xform)
{
	enum rte_crypto_cipher_operation dir = xform->cipher.op;
	uint8_t *key = xform->cipher.key.data;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx;
	int rv;

	sess->algo.cipher = xform->cipher.algo;

	cipher = xform_get_evp_cipher(xform);
	if (unlikely(cipher == NULL)) {
		ARMCE_LOG_ERR("Could not find a valid cipher algorithm");
		return -1;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (unlikely(ctx == NULL)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Cipher: could not allocate new OpenSSL EVP ctx");
		return -1;
	}

	sess->data.cipher.dir = dir;
	/*
	 * It is safe to call EVP with NULL key later, but for GCM, CCM and
	 * other AEAD algorithms this is not ok, as the cipher->init()
	 * primitive is forcefully called although the key is NULL
	 */
	if (dir == RTE_CRYPTO_CIPHER_OP_ENCRYPT) {
		rv = EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
	} else {
		rv = EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL);
		EVP_CIPHER_CTX_set_padding(ctx, 0);
	}
	if (rv != 1) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Cipher: OpenSSL EVP ctx initialization failed");
		return -1;
	}
	sess->data.cipher.ctx = ctx;

	return 0;
}

static const EVP_MD *
xform_get_evp_auth(const struct rte_crypto_sym_xform *xform)
{
	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		return EVP_sha1();
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		return EVP_sha256();
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		return EVP_sha512();
	default:
		ARMCE_LOG_ERR("Could not find a valid hmac algorithm");
		return NULL;
	}
	return NULL;
}

static int
armce_set_auth_session_parameters(struct armce_session *sess,
				  const struct rte_crypto_sym_xform *xform)
{
	enum rte_crypto_auth_operation op = xform->auth.op;
	int key_len = xform->auth.key.length;
	HMAC_CTX *ctx = &sess->data.auth.ctx;
	uint8_t *key = xform->auth.key.data;
	const EVP_MD *auth;
	int rv;

	sess->algo.auth = xform->auth.algo;

	auth = xform_get_evp_auth(xform);
	if (unlikely(auth == NULL)) {
		ARMCE_LOG_ERR("Could not find a valid hmac algorithm");
		return -1;
	}

	sess->data.auth.op = op;
	HMAC_CTX_init(ctx);
	rv = HMAC_Init_ex(ctx, key, key_len, auth, NULL);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("failed configure hmac session parameters");
		return -1;
	}

	return 0;
}

/** verify and set session parameters */
int
armce_set_session_parameters(
		struct armce_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	int rv_auth = 0, rv_cipher = 0;

	if (unlikely(xform == NULL)) {
		ARMCE_LOG_ERR("xform request is NULL");
		return -1;
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
			xform->next == NULL) {
		/* Authentication Only */
		sess->algo.chaining = HASH_ONLY;
		rv_auth = armce_set_auth_session_parameters(sess, xform);
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		/* Authentication then Cipher */
		sess->algo.chaining = HASH_CIPHER;
		rv_auth = armce_set_auth_session_parameters(sess, xform);
		rv_cipher = armce_set_cipher_session_parameters(sess,
								xform->next);
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
			xform->next == NULL) {
		/* Cipher Only */
		sess->algo.chaining = CIPHER_ONLY;
		rv_cipher = armce_set_cipher_session_parameters(sess, xform);
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		/* Cipher then Authentication */
		sess->algo.chaining = CIPHER_HASH;
		rv_cipher = armce_set_cipher_session_parameters(sess, xform);
		rv_auth = armce_set_auth_session_parameters(sess, xform->next);
	}

	if (unlikely(rv_cipher | rv_auth)) {
		ARMCE_LOG_ERR("Set session parameters failed");
		return -1;
	}

	return 0;
}

static inline int
process_cipher_op_enc(EVP_CIPHER_CTX *ctx,
		      unsigned char *dst, unsigned char *src,
		      unsigned char *iv, int length)
{
	int len;
	int rv;

	rv = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Setting IV failed");
		return -EINVAL;
	}
	rv = EVP_EncryptUpdate(ctx, dst, &len, src, length);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Encryption failed");
		return -EINVAL;
	}
	rv = EVP_EncryptFinal_ex(ctx, dst + len, &len);
	if (rv != 1) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Encryption completion failed");
		return -EINVAL;
	}

	return 0;
}

static inline int
process_cipher_op_dec(EVP_CIPHER_CTX *ctx,
		      unsigned char *dst, unsigned char *src,
		      unsigned char *iv, int length)
{
	int len;
	int rv;

	rv = EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Setting failed");
		return -EINVAL;
	}
	rv = EVP_DecryptUpdate(ctx, dst, &len, src, length);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Decryption failed");
		return -EINVAL;
	}
	rv = EVP_DecryptFinal_ex(ctx, dst + len, &len);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Decryption completion failed");
		return -EINVAL;
	}

	return 0;
}

static int
process_cipher_op(struct rte_crypto_sym_op *op, struct armce_session *sess)
{
	unsigned char *src = (unsigned char *)op->m_src->buf_addr +
			     op->m_src->data_off +
			     op->cipher.data.offset;
	EVP_CIPHER_CTX *ctx = sess->data.cipher.ctx;
	unsigned char *iv = op->cipher.iv.data;
	int length = op->cipher.data.length;
	unsigned char *dst;
	int rv;

	if (op->m_dst != NULL)
		dst = (unsigned char *)op->m_dst->buf_addr +
		      op->m_dst->data_off;
	else
		dst = src;

	if (sess->data.cipher.dir == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		rv = process_cipher_op_enc(ctx, dst, src, iv, length);
	else
		rv = process_cipher_op_dec(ctx, dst, src, iv, length);

	return rv;
}

static inline int
process_auth_op_generate(struct rte_crypto_sym_op *op, HMAC_CTX *ctx,
			 unsigned char *src)
{
	unsigned char *dst;
	unsigned int len;
	int rv;

	if (op->auth.digest.data != NULL) {
		dst = (unsigned char *)op->auth.digest.data;
	} else {
		if (op->m_dst != NULL)
			dst = (unsigned char *)op->m_dst->buf_addr +
			      op->m_dst->data_off;
		else
			dst = src + op->auth.data.length;
	}
	rv = HMAC_Final(ctx, dst, &len);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Digest generation failed");
		return -EINVAL;
	}

	return 0;
}

#define SHA512_DIGEST_LENGTH_IN_BYTES (512 / 8)
#define LONGEST_DIGEST_SIZE SHA512_DIGEST_LENGTH_IN_BYTES
static inline int
process_auth_op_verify(struct rte_crypto_sym_op *op, HMAC_CTX *ctx,
		       unsigned char *src)
{
	unsigned char new_digest[LONGEST_DIGEST_SIZE] __rte_cache_aligned;
	const unsigned char *old_digest;
	unsigned char *dst;
	unsigned int len;
	int rv;

	if (op->auth.digest.data == NULL)
		old_digest = src + op->auth.data.length;
	else
		old_digest = op->auth.digest.data;
	dst = new_digest;

	rv = HMAC_Final(ctx, dst, &len);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Digest generation failed");
		return -EINVAL;
	}
	if (memcmp(new_digest, old_digest, op->auth.digest.length) != 0)
		return -EPROTO;

	return 0;
}

static int
process_auth_op(struct rte_crypto_sym_op *op, struct armce_session *sess)
{
	enum rte_crypto_auth_operation dir = sess->data.auth.op;
	unsigned char *src = (unsigned char *)op->m_src->buf_addr +
			     op->m_src->data_off +
			     op->auth.data.offset;
	HMAC_CTX *ctx = &sess->data.auth.ctx;
	int rv = 0;

	rv = HMAC_Update(ctx, src, op->auth.data.length);
	if (unlikely(rv != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Hashing operation failed");
		return -EINVAL;
	}

	if (dir == RTE_CRYPTO_AUTH_OP_GENERATE)
		rv = process_auth_op_generate(op, ctx, src);
	else
		rv = process_auth_op_verify(op, ctx, src);

	if (unlikely(HMAC_Init_ex(ctx, NULL, 0, NULL, NULL) != 1)) {
		ERR_print_errors_fp(stderr);
		ARMCE_LOG_ERR("Could not reinitialise HMAC session ctx\n");
	}

	return rv;
}

/** Process crypto operation for mbuf */
static int
process_op(const struct armce_qp *qp, struct rte_crypto_op *op,
	   struct armce_session *sess)
{
	int rv_auth = 0, rv_cipher = 0;

	op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

	switch (sess->algo.chaining) {
	case HASH_ONLY:
		rv_auth = process_auth_op(op->sym, sess);
		break;
	case CIPHER_ONLY:
		rv_cipher = process_cipher_op(op->sym, sess);
		break;
	case HASH_CIPHER:
		rv_auth = process_auth_op(op->sym, sess);
		rv_cipher = process_cipher_op(op->sym, sess);
		break;
	case CIPHER_HASH:
		rv_cipher = process_cipher_op(op->sym, sess);
		rv_auth = process_auth_op(op->sym, sess);
		break;
	default:
		ARMCE_LOG_ERR("Unsupported algorithm type");
		break;
	}

	if (unlikely(rv_auth < 0 || rv_cipher < 0)) {
		if (rv_auth == -EPROTO)
			op->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
		else
			op->status = RTE_CRYPTO_OP_STATUS_ERROR;
	}

	return rte_ring_enqueue(qp->processed_pkts, (void *)op);
}

static struct armce_session *
get_session(struct armce_qp *qp, struct rte_crypto_sym_op *op)
{
	struct armce_session *sess;

	if (op->sess_type == RTE_CRYPTO_SYM_OP_WITH_SESSION) {
		if (unlikely(op->session == NULL ||
			     op->session->dev_type !=
			     RTE_CRYPTODEV_ARMCE_PMD)) {
			ARMCE_LOG_ERR("Could not find valid session");
			return NULL;
		}

		sess = (struct armce_session *)op->session->_private;
	} else  {
		struct rte_cryptodev_session *c_sess = NULL;

		if (rte_mempool_get(qp->sess_mp, (void **)&c_sess)) {
			ARMCE_LOG_ERR("Could not allocate temporary session "
				      "for sessionless request");
			return NULL;
		}

		sess = (struct armce_session *)c_sess->_private;

		if (armce_set_session_parameters(sess, op->xform) != 0) {
			ARMCE_LOG_ERR("Failed to set parameteres for "
				      "sessionless request");
			return NULL;
		}
	}

	return sess;
}

/** Enqueue burst */
static uint16_t
armce_pmd_enqueue_burst(void *queue_pair, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct armce_qp *qp = queue_pair;
	struct armce_session *sess;

	int i, retval;

	for (i = 0; i < nb_ops; i++) {
		sess = get_session(qp, ops[i]->sym);
		if (unlikely(sess == NULL)) {
			ARMCE_LOG_ERR("failed to get session");
			goto enqueue_err;
		}

		retval = process_op(qp, ops[i], sess);
		if (unlikely(retval < 0)) {
			ARMCE_LOG_ERR("failed to process operation");
			goto enqueue_err;
		}
	}

	qp->qp_stats.enqueued_count += i;
	return i;

enqueue_err:
	if (ops[i])
		ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;

	qp->qp_stats.enqueue_err_count++;
	return i;
}

/** Dequeue burst */
static uint16_t
armce_pmd_dequeue_burst(void *queue_pair, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct armce_qp *qp = queue_pair;

	unsigned nb_dequeued;

	nb_dequeued = rte_ring_dequeue_burst(qp->processed_pkts,
			(void **)ops, nb_ops);
	qp->qp_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

static int cryptodev_armce_uninit(const char *name);

/** Create crypto device */
static int
cryptodev_armce_create(const char *name,
		struct rte_crypto_vdev_init_params *init_params)
{
	struct rte_cryptodev *dev;
	char crypto_dev_name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct armce_private *internals;

	/* Check CPU for support for AES instruction set */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_AES)) {
		ARMCE_LOG_ERR("AES instructions not supported by CPU");
		return -EFAULT;
	}

	/* Check CPU for support for SHA1 instruction set */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_SHA1)) {
		ARMCE_LOG_ERR("SHA1 instructions not supported by CPU");
		return -EFAULT;
	}

	/* Check CPU for support for SHA2 instruction set */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_SHA2)) {
		ARMCE_LOG_ERR("SHA2 instructions not supported by CPU");
		return -EFAULT;
	}

	/* create a unique device name */
	if (create_unique_device_name(crypto_dev_name,
			RTE_CRYPTODEV_NAME_MAX_LEN) != 0) {
		ARMCE_LOG_ERR("failed to create unique cryptodev name");
		return -EINVAL;
	}

	dev = rte_cryptodev_pmd_virtual_dev_init(crypto_dev_name,
			sizeof(struct armce_private),
			init_params->socket_id);
	if (dev == NULL) {
		ARMCE_LOG_ERR("failed to create cryptodev vdev");
		goto init_error;
	}

	dev->dev_type = RTE_CRYPTODEV_ARMCE_PMD;
	dev->dev_ops = rte_armce_pmd_ops;

	/* register rx/tx burst functions for data path */
	dev->dequeue_burst = armce_pmd_dequeue_burst;
	dev->enqueue_burst = armce_pmd_enqueue_burst;

	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING;

	internals = dev->data->dev_private;

	internals->max_nb_qpairs = init_params->max_nb_queue_pairs;
	internals->max_nb_sessions = init_params->max_nb_sessions;

	return 0;

init_error:
	ARMCE_LOG_ERR("driver %s: cryptodev_armce_create failed", name);
	cryptodev_armce_uninit(crypto_dev_name);

	return -EFAULT;
}

/** Initialise armce device */
static int
cryptodev_armce_init(const char *name,
		const char *input_args)
{
	struct rte_crypto_vdev_init_params init_params = {
		RTE_CRYPTODEV_VDEV_DEFAULT_MAX_NB_QUEUE_PAIRS,
		RTE_CRYPTODEV_VDEV_DEFAULT_MAX_NB_SESSIONS,
		rte_socket_id()
	};

	rte_cryptodev_parse_vdev_init_params(&init_params, input_args);

	RTE_LOG(INFO, PMD, "Initialising %s on NUMA node %d\n", name,
			init_params.socket_id);
	RTE_LOG(INFO, PMD, "  Max number of queue pairs = %d\n",
			init_params.max_nb_queue_pairs);
	RTE_LOG(INFO, PMD, "  Max number of sessions = %d\n",
			init_params.max_nb_sessions);

	/* OpenSSL init */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	return cryptodev_armce_create(name, &init_params);
}

/** Uninitialise armce device */
static int
cryptodev_armce_uninit(const char *name)
{
	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Closing armce device %s on numa socket %u\n",
			name, rte_socket_id());

	/* OpenSSL cleanup */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}

static struct rte_driver cryptodev_armce_pmd_drv = {
	.name = CRYPTODEV_NAME_ARMCE_PMD,
	.type = PMD_VDEV,
	.init = cryptodev_armce_init,
	.uninit = cryptodev_armce_uninit
};

PMD_REGISTER_DRIVER(cryptodev_armce_pmd_drv);
