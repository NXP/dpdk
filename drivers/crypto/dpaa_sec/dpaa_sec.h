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

#ifndef _RTE_DPAA_SEC_PMD_PRIVATE_H_
#define _RTE_DPAA_SEC_PMD_PRIVATE_H_

enum dpaa_sec_op_type {
	DPAA_SEC_NONE,  /*!< No Cipher operations*/
	DPAA_SEC_CIPHER,/*!< CIPHER operations */
	DPAA_SEC_AUTH,  /*!< Authentication Operations */
	DPAA_SEC_AEAD,  /*!< Authenticated Encryption with associated data */
	DPAA_SEC_IPSEC, /*!< IPSEC protocol operations*/
	DPAA_SEC_PDCP,  /*!< PDCP protocol operations*/
	DPAA_SEC_PKC,   /*!< Public Key Cryptographic Operations */
	DPAA_SEC_MAX
};

enum dpaa_crypto_dir {
	DPAA_CRYPTO_DECODE = 0,
	DPAA_CRYPTO_ENCODE
};

struct dpaa_cipher {
	enum rte_crypto_cipher_algorithm alg;
	uint8_t *key_data;
	uint32_t key_len;

	uint8_t *iv_data;
	uint32_t iv_len;
	uint64_t iv_phys;
};

struct dpaa_auth {
	enum rte_crypto_auth_algorithm alg;
	uint8_t *key_data;
	uint32_t key_len;
};

struct dpaa_sec_qp {
	struct dpaa_sec_qi *qi;
	struct qman_fq inq;
	struct qman_fq outq;
	int rx_pkts;
	int rx_errs;
	int tx_pkts;
	int tx_errs;
};

#define DPAA_SEC_MAX_DESC_SIZE  128
/* code or cmd block to caam */
struct sec_cdb {
	struct {
		union {
			uint32_t word;
			struct {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
				uint16_t rsvd63_48;
				unsigned int rsvd47_39:9;
				unsigned int idlen:7;
#else
				unsigned int idlen:7;
				unsigned int rsvd47_39:9;
				uint16_t rsvd63_48;
#endif
			} field;
		} __packed hi;

		union {
			uint32_t word;
			struct {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
				unsigned int rsvd31_30:2;
				unsigned int fsgt:1;
				unsigned int lng:1;
				unsigned int offset:2;
				unsigned int abs:1;
				unsigned int add_buf:1;
				uint8_t pool_id;
				uint16_t pool_buffer_size;
#else
				uint16_t pool_buffer_size;
				uint8_t pool_id;
				unsigned int add_buf:1;
				unsigned int abs:1;
				unsigned int offset:2;
				unsigned int lng:1;
				unsigned int fsgt:1;
				unsigned int rsvd31_30:2;
#endif
			} field;
		} __packed lo;
	} __packed sh_hdr;

	uint32_t sh_desc[DPAA_SEC_MAX_DESC_SIZE];
};

struct dpaa_sec_ses {
	enum dpaa_crypto_dir dir;
	struct dpaa_cipher cipher;
	struct dpaa_auth   auth;
	uint32_t auth_trunc_len;
	void   *priv; /* private interface to do crypto */
};

#define RTE_MAX_NB_SEC_QPS 8
#define RTE_MAX_NB_SEC_SES 2048
/* internal sec queue interface */
struct dpaa_sec_qi {
	void *sec_hw;
	struct dpaa_sec_qp qps[RTE_MAX_NB_SEC_QPS]; /* i/o queue for sec */
	unsigned max_nb_queue_pairs;
	unsigned max_nb_sessions;
	struct dpaa_sec_ses *ses; /* session associated with the sec */
	struct sec_cdb cdb; /* code block for sec session */
};

struct dpaa_sec_job {
	/* sg[0] output, sg[1] input, others are possible sub frames */
	struct qm_sg_entry sg[16];
};

#define DPAA_MAX_NB_MAX_DIGEST	32
struct dpaa_sec_op_ctx {
	struct dpaa_sec_job job;
	struct rte_crypto_op *op;
	uint32_t fd_status;
	uint32_t auth_only_len;
	uint8_t digest[DPAA_MAX_NB_MAX_DIGEST];
};

static const struct rte_cryptodev_capabilities dpaa_sec_capabilities[] = {
	{	/* SHA1 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 64,
					.max = 64,
					.increment = 0
				},
				.digest_size = {
					.min = 20,
					.max = 20,
					.increment = 0
				},
				.aad_size = { 0 }
			}
		}
	},
	{	/* SHA256 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 64,
					.max = 64,
					.increment = 0
				},
				.digest_size = {
					.min = 32,
					.max = 32,
					.increment = 0
				},
				.aad_size = { 0 }
			}
		}
	},
	{	/* SHA384 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA384_HMAC,
				.block_size = 128,
				.key_size = {
					.min = 128,
					.max = 128,
					.increment = 0
				},
				.digest_size = {
					.min = 48,
					.max = 48,
					.increment = 0
				},
				.aad_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA512 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA512_HMAC,
				.block_size = 128,
				.key_size = {
					.min = 128,
					.max = 128,
					.increment = 0
				},
				.digest_size = {
					.min = 64,
					.max = 64,
					.increment = 0
				},
				.aad_size = { 0 }
			}
		}
	},
	{	/* AES XCBC MAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_AES_XCBC_MAC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.aad_size = { 0 }
			}
		}
	},
	{	/* AES GCM (AUTH) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_AES_GCM,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.digest_size = {
					.min = 8,
					.max = 16,
					.increment = 4
				},
				.aad_size = {
					.min = 8,
					.max = 12,
					.increment = 4
				}
			}
		}
	},
	{	/* SNOW3G (UIA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			.auth = {
				.algo = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 4,
					.max = 4,
					.increment = 0
				},
				.aad_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}
		}
	},
	{	/* AES GCM (CIPHER) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_GCM,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}
		}
	},
	{	/* AES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			.cipher = {
				RTE_CRYPTO_CIPHER_AES_CBC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}
		}
	},
	{	/* SNOW3G (UEA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			.cipher = {
				.algo = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}
		}
	},
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};
#endif /* _RTE_DPAA_SEC_PMD_PRIVATE_H_ */
