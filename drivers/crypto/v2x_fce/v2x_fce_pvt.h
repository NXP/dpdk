/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#ifndef _V2X_FCE_PVT_H_
#define _V2X_FCE_PVT_H_

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <rte_cryptodev.h>
#include "v2x_fce_log.h"

#define HMAC_GEN	0
#define HMAC_VERIFY	1
#define HASH_ONLY	2

#define FCE_SIG_POP_REQ	0x3
#define FCE_POP_REQ	0x2

#define FCE_REQ_ID_DIFF	0x10
#define FCE_MAX_OPS	252
#define FCE_MAX_KEYSLOT	8

#define REQ_VERIFY_FAIL	0x6029

/* FCE crypto queue pair */
struct fce_crypto_qp {
	uint16_t id;	/* Queue Pair Identifier */
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct rte_ring *in_ring;
	struct rte_ring *out_ring;
	struct rte_mempool *mempool;
	struct rte_cryptodev_stats stats;
} __rte_cache_aligned;

/* FCE crypto private session structure */
struct fce_crypto_session {
	void *fce_mu_base;
	uint32_t fce_mu_offset;
	uint32_t req_id;

	/* Cipher Parameters */
	struct {
		enum rte_crypto_cipher_algorithm algo;
		enum rte_crypto_cipher_operation op;
		uint8_t key_slot;
		size_t keylen;
		uint16_t iv_len;
		uint16_t iv_offset;
	} cipher;

	/* Authentication Parameters */
	struct {
		uint16_t digest_len;
		int sha_algo;
		int op;
		uint8_t key_slot;
		size_t keylen;
	} auth;

	/* AEAD Parameters */
	struct {
		enum rte_crypto_aead_algorithm algo;
		enum rte_crypto_aead_operation op;
		uint8_t key_slot;
		size_t keylen;
		uint16_t iv_len;
		uint16_t iv_offset;
		uint16_t aad_len;
		uint16_t digest_len;
	} aead;
} __rte_cache_aligned;


typedef struct {
	int core_id;
} dispatcher_args_t;

/* private data structure for each fce crypto device */
struct fce_crypto_private {
	int fce_mu_fd;
	void *fce_mu_base;
	uint32_t fce_mu_offset;
	uint32_t num_cipher_keyslot;
	uint32_t num_auth_keyslot;
	uint32_t max_nb_queue_pairs;
	pthread_t dispatcher_tid;
	dispatcher_args_t *args;
};

/* Get cryptodev capabilities */
const struct rte_cryptodev_capabilities *
fce_get_cryptodev_capabilities(void);

/* Get cryptodev operations */
struct rte_cryptodev_ops *
fce_get_cryptodev_ops(void);

#endif /* _V2X_FCE_PVT_H_ */
