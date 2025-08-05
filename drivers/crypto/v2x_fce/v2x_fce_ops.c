/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <cryptodev_pmd.h>

#include "v2x_fce_pvt.h"
#include "v2x_fce_api.h"

extern volatile struct fce_crypto_qp *fce_qp;

static int
fce_cipher_init(struct fce_crypto_private *internals,
		struct fce_crypto_session *sess,
		struct rte_crypto_sym_xform *xform)
{
	switch (xform->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_ECB:
		sess->cipher.iv_len = 0;
		sess->cipher.iv_offset = 0;
		break;
	case RTE_CRYPTO_CIPHER_AES_CBC:
		sess->cipher.iv_len = xform->cipher.iv.length;
		sess->cipher.iv_offset = xform->cipher.iv.offset;
		break;
	default:
		FCE_ERR("Unsupported cipher algo %u", xform->cipher.algo);
		return -ENOTSUP;
	}

	if (!internals->num_cipher_keyslot) {
		FCE_ERR("Max Cipher keyslot: %u, available %u",
			 FCE_MAX_KEYSLOT, internals->num_cipher_keyslot);
		return -1;
	}

	sess->cipher.algo = xform->cipher.algo;
	sess->cipher.op = xform->cipher.op;
	sess->cipher.key_slot = FCE_MAX_KEYSLOT - internals->num_cipher_keyslot;
	internals->num_cipher_keyslot--;
	sess->cipher.keylen = xform->cipher.key.length;

	return fce_load_aes_key(sess->fce_mu_base,
				xform->cipher.key.data,
				sess->cipher.keylen,
				sess->cipher.key_slot);
}

static int
fce_auth_init(struct fce_crypto_private *internals,
	      struct fce_crypto_session *sess,
	      struct rte_crypto_sym_xform *xform)
{
	sess->auth.digest_len = xform->auth.digest_length;

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_SHA256:
		sess->auth.sha_algo = 1;
		sess->auth.op = HASH_ONLY;
		return 0;
	case RTE_CRYPTO_AUTH_SHA384:
		sess->auth.sha_algo = 2;
		sess->auth.op = HASH_ONLY;
		return 0;
	case RTE_CRYPTO_AUTH_SHA512:
		sess->auth.sha_algo = 3;
		sess->auth.op = HASH_ONLY;
		return 0;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		sess->auth.sha_algo = 1;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		sess->auth.sha_algo = 2;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		sess->auth.sha_algo = 3;
		break;
	default:
		FCE_ERR("Unsupported auth algo %u", xform->auth.algo);
		return -ENOTSUP;
	}

	/* HMAC operations requires loading key */
	if (!internals->num_auth_keyslot) {
		FCE_ERR("Max Auth keyslot: %u, available %u",
			 FCE_MAX_KEYSLOT, internals->num_auth_keyslot);
		return -1;
	}

	sess->auth.op = (xform->auth.op == RTE_CRYPTO_AUTH_OP_GENERATE) ?
			 HMAC_GEN : HMAC_VERIFY;
	sess->auth.key_slot = FCE_MAX_KEYSLOT - internals->num_auth_keyslot;
	internals->num_auth_keyslot--;
	sess->auth.keylen = xform->auth.key.length;

	return fce_load_hmac_key(sess->fce_mu_base,
				 xform->auth.key.data,
				 sess->auth.keylen,
				 sess->auth.key_slot,
				 sess->auth.sha_algo);
}

static int
fce_aead_init(struct fce_crypto_session *sess,
	      struct rte_crypto_sym_xform *xform)
{
	switch (xform->aead.algo) {
	case RTE_CRYPTO_AEAD_AES_GCM:
		break;
	case RTE_CRYPTO_AEAD_AES_CCM:
	default:
		FCE_ERR("unsupported aead algo %u", xform->aead.algo);
		return -1;
	}

	sess->aead.algo = xform->aead.algo;
	sess->aead.op = xform->aead.op;
	sess->aead.key_slot = 0;
	sess->aead.keylen = xform->aead.key.length;
	sess->aead.iv_len = xform->aead.iv.length;
	sess->aead.iv_offset = xform->aead.iv.offset;
	sess->aead.aad_len = xform->aead.aad_length;
	sess->aead.digest_len = xform->aead.digest_length;

	return fce_load_aes_key(sess->fce_mu_base,
				xform->aead.key.data,
				sess->aead.keylen,
				sess->aead.key_slot);
}

static int
fce_set_session_parameters(struct fce_crypto_private *internals,
			   struct fce_crypto_session *sess,
			   struct rte_crypto_sym_xform *xform)
{
	int ret;

	sess->cipher.algo = 0;
	sess->auth.sha_algo = 0;
	sess->aead.algo = 0;

	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
	    xform->next == NULL)
		ret = fce_cipher_init(internals, sess, xform);
	else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		 xform->next == NULL)
		ret = fce_auth_init(internals, sess, xform);
	else if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD &&
		 xform->next == NULL)
		ret = fce_aead_init(sess, xform);
	else if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		   xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		if (xform->cipher.op != RTE_CRYPTO_CIPHER_OP_ENCRYPT)
			return -ENOTSUP;

		ret = fce_cipher_init(internals, sess, xform);
		if (ret)
			return ret;

		ret = fce_auth_init(internals, sess, xform->next);
	} else if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		   xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		if (xform->next->cipher.op != RTE_CRYPTO_CIPHER_OP_DECRYPT)
			return -ENOTSUP;

		ret = fce_auth_init(internals, sess, xform);
		if (ret)
			return ret;

		ret = fce_cipher_init(internals, sess, xform->next);
	} else
		return -ENOTSUP;

	return ret;
}

static void
fce_ring_create(struct fce_crypto_qp *qp,
		unsigned int ring_size,
		int socket_id)
{
	struct rte_ring *ring;
	char name[64] = {0};

	/* input ring */
	snprintf(name, sizeof(name), "%s_%s", qp->name, "in");

	ring = rte_ring_lookup(name);
	if (ring) {
		if (rte_ring_get_size(ring) >= ring_size) {
			FCE_INFO("Reusing existing ring %s", name);
			qp->in_ring = ring;
		} else {
			FCE_ERR("Existing ring %s is too small", name);
			qp->in_ring = NULL;
			return;
		}
	} else {
		qp->in_ring = rte_ring_create(name, ring_size, socket_id,
					      RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!qp->in_ring)
			return;
	}

	/* output ring */
	snprintf(name, sizeof(name), "%s_%s", qp->name, "out");

	ring = rte_ring_lookup(name);
	if (ring) {
		if (rte_ring_get_size(ring) >= ring_size) {
			FCE_INFO("Reusing existing ring %s", name);
			qp->out_ring = ring;
		} else {
			FCE_ERR("Existing ring %s is too small", name);
			qp->out_ring =  NULL;
			return;
		}
	} else {
		qp->out_ring = rte_ring_create(name, ring_size, socket_id,
					       RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!qp->out_ring)
			rte_ring_free(qp->in_ring);
	}
}

static int
fce_config(__rte_unused struct rte_cryptodev *dev,
	   __rte_unused struct rte_cryptodev_config *config)
{
	return 0;
}

static int
fce_start(__rte_unused struct rte_cryptodev *dev)
{
	return 0;
}

static void
fce_stop(__rte_unused struct rte_cryptodev *dev)
{
}

static int
fce_close(__rte_unused struct rte_cryptodev *dev)
{
	return 0;
}

static void
fce_info_get(struct rte_cryptodev *dev,
	     struct rte_cryptodev_info *dev_info)
{
	struct fce_crypto_private *internals = dev->data->dev_private;

	if (dev_info != NULL) {
		dev_info->driver_id = dev->driver_id;
		dev_info->feature_flags = dev->feature_flags;
		dev_info->capabilities = fce_get_cryptodev_capabilities();
		dev_info->max_nb_queue_pairs = internals->max_nb_queue_pairs;
		/* No limit of number of sessions */
		dev_info->sym.max_nb_sessions = 0;
	}
}

static void
fce_stats_get(struct rte_cryptodev *dev,
	      struct rte_cryptodev_stats *stats)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct fce_crypto_qp *qp = dev->data->queue_pairs[qp_id];

		stats->enqueued_count += qp->stats.enqueued_count;
		stats->dequeued_count += qp->stats.dequeued_count;

		stats->enqueue_err_count += qp->stats.enqueue_err_count;
		stats->dequeue_err_count += qp->stats.dequeue_err_count;
	}
}

static void
fce_stats_reset(struct rte_cryptodev *dev)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct fce_crypto_qp *qp = dev->data->queue_pairs[qp_id];
		memset(&qp->stats, 0, sizeof(qp->stats));
	}
}

static int
fce_qp_release(__rte_unused struct rte_cryptodev *dev,
	       __rte_unused uint16_t qp_id)
{
#if 0
	if (dev->data->queue_pairs[qp_id] != NULL) {
		fce_qp = NULL;
		rte_free(dev->data->queue_pairs[qp_id]);
		dev->data->queue_pairs[qp_id] = NULL;
	}
#endif

	return 0;
}

static int
fce_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
	     const struct rte_cryptodev_qp_conf *qp_conf,
	     int socket_id)
{
	struct fce_crypto_qp *qp = NULL;

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		return 0; /*fce_qp_release(dev, qp_id);*/

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc_socket("FCE Queue Pair", sizeof(*qp),
				RTE_CACHE_LINE_SIZE, socket_id);
	if (qp == NULL)
		return -ENOMEM;

	qp->id = qp_id;
	dev->data->queue_pairs[qp_id] = qp;

	/* Set queue pair name */
	snprintf(qp->name, sizeof(qp->name), "fce_%u_qp_%u",
		 dev->data->dev_id, qp->id);

	/* Create Ring */
	fce_ring_create(qp, qp_conf->nb_descriptors, socket_id);
	if (!qp->in_ring || !qp->out_ring) {
		rte_free(qp);
		return -1;
	}

	qp->mempool = qp_conf->mp_session;

	memset(&qp->stats, 0, sizeof(qp->stats));

	/* Assign the global queue pair */
	fce_qp = qp;

	return 0;
}

static unsigned
fce_sym_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct fce_crypto_session);
}

static int
fce_sym_session_configure(struct rte_cryptodev *dev,
			  struct rte_crypto_sym_xform *xform,
			  struct rte_cryptodev_sym_session *sess)
{
	struct fce_crypto_private *internals = dev->data->dev_private;
	struct fce_crypto_session *sess_priv_data;
	int ret;

	if (unlikely(sess == NULL || xform == NULL)) {
		FCE_ERR("invalid session or xform");
		return -EINVAL;
	}

	sess_priv_data = CRYPTODEV_GET_SYM_SESS_PRIV(sess);
	sess_priv_data->fce_mu_base = internals->fce_mu_base;
	sess_priv_data->fce_mu_offset = internals->fce_mu_offset;

	ret = fce_service_open(sess_priv_data->fce_mu_base);
	if (ret)
		return ret;

	ret = fce_set_session_parameters(internals, sess_priv_data, xform);
	if (ret)
		FCE_ERR("failed configure session parameters");

	return ret;
}

static void
fce_sym_session_clear(struct rte_cryptodev *dev __rte_unused,
		      struct rte_cryptodev_sym_session *sess)
{
	struct fce_crypto_session *sess_priv_data;

	sess_priv_data = CRYPTODEV_GET_SYM_SESS_PRIV(sess);
	if (sess_priv_data)
		fce_service_close(sess_priv_data->fce_mu_base);
}

struct rte_cryptodev_ops fce_ops = {
	.dev_configure		= fce_config,
	.dev_start		= fce_start,
	.dev_stop		= fce_stop,
	.dev_close		= fce_close,
	.dev_infos_get		= fce_info_get,
	.stats_get		= fce_stats_get,
	.stats_reset		= fce_stats_reset,
	.queue_pair_setup	= fce_qp_setup,
	.queue_pair_release	= fce_qp_release,
	.sym_session_get_size	= fce_sym_session_get_size,
	.sym_session_configure	= fce_sym_session_configure,
	.sym_session_clear	= fce_sym_session_clear
};

struct rte_cryptodev_ops *
fce_get_cryptodev_ops(void)
{
	return &fce_ops;
}
