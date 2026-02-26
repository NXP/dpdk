/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <string.h>

#include "v2x_fce_pvt.h"
#include "v2x_fce_api.h"
#include "v2x_fce_mu_regs.h"

static uint32_t
crc_compute(uint32_t *msg, size_t len)
{
	uint32_t nb_words = len / 4;
	uint32_t crc = 0;
	uint32_t i;

	for (i = 0; i < nb_words - 1; i++)
		crc ^= *(msg + i);

	return crc;
}

static void
imx_mu_word_copy(uint32_t *buf, uint32_t *data, uint8_t size)
{
	uint8_t i;

	for (i = 0; i < size; i++)
		buf[i] = data[i];
}

void
fce_cbc_construct(uint32_t *mu_buf, uint8_t key_slot,
		  uint32_t src_addr, uint32_t dst_addr,
		  size_t len, uint8_t op,
		  uint8_t *iv, size_t iv_len,
		  uint32_t digest_addr, uint8_t sha_algo,
		  uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_CBC_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_CBC_DEC;
	else
		msg.command = FCE_CBC_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (key_slot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;
	memcpy(&msg.data[6], iv, iv_len);

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void
fce_ecb_construct(uint32_t *mu_buf, uint8_t key_slot,
		  uint32_t src_addr, uint32_t dst_addr,
		  size_t len, uint8_t op,
		  uint32_t digest_addr, uint8_t sha_algo,
		  uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_ECB_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_ECB_DEC;
	else
		msg.command = FCE_ECB_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (key_slot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void
fce_auth_construct(uint32_t *mu_buf, uint8_t key_slot,
		   uint32_t src_addr, size_t len,
		   uint32_t digest_addr, uint8_t sha_algo,
		   uint8_t flag, uint8_t op)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_AUTH_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op == HMAC_GEN)
		msg.command = FCE_HMAC_GEN;
	else if (op == HMAC_VERIFY)
		msg.command = FCE_HMAC_VERIFY;
	else if (op == HASH_ONLY)
		msg.command = FCE_HASH;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (key_slot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void
fce_gcm_construct(uint32_t *mu_buf, uint8_t key_slot,
		  uint32_t src_addr, uint32_t dst_addr,
		  size_t len, uint8_t op,
		  uint8_t *iv, size_t iv_len,
		  uint32_t aad_addr, size_t aad_len,
		  uint32_t digest_addr, uint8_t sha_algo)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_GCM_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_GCM_DEC;
	else
		msg.command = FCE_GCM_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (iv_len << 24) |
		      (key_slot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4);
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;
	memcpy(&msg.data[6], iv, iv_len);
	msg.data[10] = aad_len;
	msg.data[11] = aad_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

int
fce_load_aes_key(void *mu_base,
		 const uint8_t *key,
		 size_t keylen,
		 uint8_t key_slot)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_LOAD_AES_KEY_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_LOAD_AES_KEY_REQ;

	/* message data */
	msg.data[0] = key_slot;
	memcpy(&msg.data[1], key, keylen);
	msg.data[9] = crc_compute((uint32_t *)&msg, FCE_LOAD_AES_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		FCE_ERR("Load AES Key Error 0x%x", msg.data[0]);

	return ret;
}

int
fce_load_hmac_key(void *mu_base,
		  const uint8_t *key,
		  size_t keylen,
		  uint8_t key_slot,
		  uint8_t sha_algo)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_LOAD_HMAC_KEY_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_LOAD_HMAC_KEY_REQ;

	/* message data */
	msg.data[0] = (sha_algo << 8) | key_slot;
	memcpy(&msg.data[1], key, keylen);
	msg.data[33] = crc_compute((uint32_t *)&msg, FCE_LOAD_HMAC_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		FCE_ERR("Load HMAC Key Err 0x%x", msg.data[0]);

	return ret;
}

int
fce_push(void *mu_base, uint8_t slot)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_PUSH_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_PUSH_REQ(slot);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		FCE_ERR("Push Error 0x%x", msg.data[0]);
		return ret;
	}

	return msg.data[1];
}

int
fce_get_request_status(void *mu_base, uint32_t *req_id)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_GET_REQ_STATUS_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_GET_REQ_STATUS;
	msg.data[0] = *req_id;

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		FCE_ERR("Session request id: 0x%x, "
			"Error request id: 0x%x, Error: 0x%x",
			*req_id, msg.data[1],  msg.data[0]);

	*req_id = msg.data[1];

	return msg.data[0];
}

int
fce_read_clear_gsr(void *mu_base)
{
	return imx_mu_read_clear_gsr(mu_base);
}

int
fce_service_open(void *mu_base)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_SERVICE_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_SERVICE_OPEN_REQ;

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		if (msg.data[0] == 0x1529)
			return 0;

		FCE_ERR("Service Open Error 0x%x", msg.data[0]);
	}

	return ret;
}

void
fce_service_close(void *mu_base)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_SERVICE_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_SERVICE_CLOSE_REQ;

	imx_mu_send_recv(mu_base, &msg, &msg);
}
