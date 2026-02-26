/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#ifndef _V2X_FCE_API_H_
#define _V2X_FCE_API_H_

#include <stddef.h>
#include <stdint.h>

#include <rte_crypto.h>

/* FCE commands */
#define FCE_PING_REQ			0x1
#define FCE_PING_REQ_SZ			0x4
#define FCE_PING_RSP_SZ			0x8

#define FCE_LOAD_AES_KEY_REQ		0x41
#define FCE_LOAD_HMAC_KEY_REQ		0x45
#define FCE_LOAD_AES_KEY_REQ_SZ		0x2C
#define FCE_LOAD_HMAC_KEY_REQ_SZ	0x8C

#define FCE_ECB_ENC			0x60
#define FCE_ECB_DEC			0x61
#define FCE_ECB_SZ			0x1C

#define FCE_CBC_ENC			0x64
#define FCE_CBC_DEC			0x65
#define FCE_CBC_SZ			0x2C

#define FCE_GCM_ENC			0x68
#define FCE_GCM_DEC			0x69
#define FCE_GCM_SZ			0x34

#define FCE_HASH			0x80
#define FCE_HMAC_GEN			0x88
#define FCE_HMAC_VERIFY			0x89
#define FCE_AUTH_SZ			0x18

#define FCE_KEY_SLOT_SHIFT		0x10

#define FCE_PUSH_REQ(SLOT)		(0xB0 | (SLOT))
#define FCE_PUSH_REQ_SZ			0x4

#define FCE_GET_REQ_STATUS		0xC0
#define FCE_GET_REQ_STATUS_SZ		0x8
#define FCE_REQ_ONGOING			0x10D6

#define FCE_SERVICE_OPEN_REQ		0x10
#define FCE_SERVICE_CLOSE_REQ		0x11
#define FCE_SERVICE_REQ_SZ		0x4

#define FCE_VERSION			0x02
#define FCE_CMD_TAG			0x1B
#define FCE_RSP_TAG			0xE5

/* FCE message construction APIs, using mailbox to communicate with FW */
int fce_load_aes_key(void *mu_base, const uint8_t *key, size_t keylen,
		     uint8_t key_slot);
int fce_load_hmac_key(void *mu_base, const uint8_t *key, size_t keylen,
		      uint8_t key_slot, uint8_t sha_algo);
void fce_cbc_construct(uint32_t *mu_buf, uint8_t key_slot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t iv_len,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag);
void fce_ecb_construct(uint32_t *mu_buf, uint8_t key_slot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag);
void fce_auth_construct(uint32_t *mu_buf, uint8_t key_slot,
			uint32_t src_addr, size_t len,
			uint32_t digest_addr, uint8_t sha_algo,
			uint8_t flag, uint8_t op);
void fce_gcm_construct(uint32_t *mu_buf, uint8_t key_slot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t iv_len,
		       uint32_t aad_addr, size_t aad_len,
		       uint32_t digest_addr, uint8_t sha_algo);
int fce_push(void *mu_base, uint8_t slot);
int fce_get_request_status(void *mu_base, uint32_t *req_id);
int fce_read_clear_gsr(void *mu_base);
int fce_service_open(void *mu_base);
void fce_service_close(void *mu_base);

/* FCE Cryptographic APIs */
int is_auth_cipher(struct fce_crypto_session *sess);
int is_auth_only(struct fce_crypto_session *sess);
int is_cipher_only(struct fce_crypto_session *sess);
int is_aead(struct fce_crypto_session *sess);
int fce_auth_build(struct rte_crypto_op *op, uint8_t buf_off, uint8_t flag);
int fce_cipher_build(struct rte_crypto_op *op, uint8_t buf_off, uint8_t flag);
int fce_aead_build(struct rte_crypto_op *op, uint8_t buf_off);

#endif /* _V2X_FCE_API_H_ */
