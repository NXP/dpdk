/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *	 * Neither the name of Intel Corporation nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
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

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>

#include "test.h"
#include "test_cryptodev.h"
#include "test_cryptodev_operations.h"

static int
create_auth_session(struct crypto_unittest_params *ut_params,
		uint8_t dev_id,
		const struct test_crypto_vector *reference,
		enum rte_crypto_auth_operation auth_op,
		uint8_t *auth_key)
{
	memcpy(auth_key, reference->auth_key.data, reference->auth_key.len);

	/* Setup Authentication Parameters */
	ut_params->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	ut_params->auth_xform.auth.op = auth_op;
	ut_params->auth_xform.next = NULL;
	ut_params->auth_xform.auth.algo = reference->auth_algo;
	ut_params->auth_xform.auth.key.length = reference->auth_key.len;
	ut_params->auth_xform.auth.key.data = auth_key;
	ut_params->auth_xform.auth.digest_length = reference->digest.len;
	ut_params->auth_xform.auth.add_auth_data_length = reference->aad.len;

	/* Create Crypto session*/
	ut_params->sess = rte_cryptodev_sym_session_create(dev_id,
				&ut_params->auth_xform);

	TEST_ASSERT_NOT_NULL(ut_params->sess, "Session creation failed");

	return 0;
}

static int
create_cipher_session(struct crypto_unittest_params *ut_params,
		uint8_t dev_id,
		const struct test_crypto_vector *reference,
		enum rte_crypto_cipher_operation cipher_op,
		uint8_t *cipher_key)
{
	memcpy(cipher_key, reference->cipher_key.data, reference->cipher_key.len);

	/* Setup Cipher Parameters */
	ut_params->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	ut_params->cipher_xform.next = NULL;
	ut_params->cipher_xform.cipher.algo = reference->crypto_algo;
	ut_params->cipher_xform.cipher.op = cipher_op;
	ut_params->cipher_xform.cipher.key.data = cipher_key;
	ut_params->cipher_xform.cipher.key.length = reference->cipher_key.len;

	/* Create Crypto session*/
	ut_params->sess = rte_cryptodev_sym_session_create(dev_id,
				&ut_params->cipher_xform);

	TEST_ASSERT_NOT_NULL(ut_params->sess, "Session creation failed");

	return 0;
}

static int
create_cipher_auth_session(struct crypto_unittest_params *ut_params,
		uint8_t dev_id,
		const struct test_crypto_vector *reference,
		enum rte_crypto_cipher_operation cipher_op,
		enum rte_crypto_auth_operation auth_op,
		uint8_t *cipher_key,
		uint8_t *auth_key)
{
	memcpy(cipher_key, reference->cipher_key.data, reference->cipher_key.len);
	memcpy(auth_key, reference->auth_key.data, reference->auth_key.len);

	/* Setup Authentication Parameters */
	ut_params->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	ut_params->auth_xform.auth.op = auth_op;
	ut_params->auth_xform.next = NULL;
	ut_params->auth_xform.auth.algo = reference->auth_algo;
	ut_params->auth_xform.auth.key.length = reference->auth_key.len;
	ut_params->auth_xform.auth.key.data = auth_key;
	ut_params->auth_xform.auth.digest_length = reference->digest.len;
	ut_params->auth_xform.auth.add_auth_data_length = reference->aad.len;

	/* Setup Cipher Parameters */
	ut_params->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	ut_params->cipher_xform.next = &ut_params->auth_xform;
	ut_params->cipher_xform.cipher.algo = reference->crypto_algo;
	ut_params->cipher_xform.cipher.op = cipher_op;
	ut_params->cipher_xform.cipher.key.data = cipher_key;
	ut_params->cipher_xform.cipher.key.length = reference->cipher_key.len;

	/* Create Crypto session*/
	ut_params->sess = rte_cryptodev_sym_session_create(dev_id,
				&ut_params->cipher_xform);

	TEST_ASSERT_NOT_NULL(ut_params->sess, "Session creation failed");

	return 0;
}

static int
create_auth_cipher_session(struct crypto_unittest_params *ut_params,
		uint8_t dev_id,
		const struct test_crypto_vector *reference,
		enum rte_crypto_auth_operation auth_op,
		enum rte_crypto_cipher_operation cipher_op,
		uint8_t *auth_key,
		uint8_t *cipher_key)
{
	memcpy(cipher_key, reference->cipher_key.data, reference->cipher_key.len);
	memcpy(auth_key, reference->auth_key.data, reference->auth_key.len);

	/* Setup Authentication Parameters */
	ut_params->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	ut_params->auth_xform.auth.op = auth_op;
	ut_params->auth_xform.next = &ut_params->cipher_xform;
	ut_params->auth_xform.auth.algo = reference->auth_algo;
	ut_params->auth_xform.auth.key.length = reference->auth_key.len;
	ut_params->auth_xform.auth.key.data = auth_key;
	ut_params->auth_xform.auth.digest_length = reference->digest.len;
	ut_params->auth_xform.auth.add_auth_data_length = reference->aad.len;

	/* Setup Cipher Parameters */
	ut_params->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	ut_params->cipher_xform.next = NULL;
	ut_params->cipher_xform.cipher.algo = reference->crypto_algo;
	ut_params->cipher_xform.cipher.op = cipher_op;
	ut_params->cipher_xform.cipher.key.data = cipher_key;
	ut_params->cipher_xform.cipher.key.length = reference->cipher_key.len;

	/* Create Crypto session*/
	ut_params->sess = rte_cryptodev_sym_session_create(dev_id,
				&ut_params->auth_xform);

	TEST_ASSERT_NOT_NULL(ut_params->sess, "Session creation failed");

	return 0;
}

static int
create_cipher_auth_xforms(struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		enum rte_crypto_cipher_operation cipher_op,
		enum rte_crypto_auth_operation auth_op,
		uint8_t *cipher_key,
		uint8_t *auth_key)
{
	memcpy(cipher_key, reference->cipher_key.data, reference->cipher_key.len);
	memcpy(auth_key, reference->auth_key.data, reference->auth_key.len);

	TEST_ASSERT_NOT_NULL(rte_crypto_op_sym_xforms_alloc(ut_params->op, 2),
			"failed to allocate space for crypto transforms");

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* Setup Authentication Parameters */
	sym_op->xform->next->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	sym_op->xform->next->auth.op = auth_op;
	sym_op->xform->next->auth.algo = reference->auth_algo;
	sym_op->xform->next->auth.key.length = reference->auth_key.len;
	sym_op->xform->next->auth.key.data = auth_key;
	sym_op->xform->next->auth.digest_length = reference->digest.len;
	sym_op->xform->next->auth.add_auth_data_length = reference->aad.len;

	/* Setup Cipher Parameters */
	sym_op->xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	sym_op->xform->cipher.algo = reference->crypto_algo;
	sym_op->xform->cipher.op = cipher_op;
	sym_op->xform->cipher.key.data = cipher_key;
	sym_op->xform->cipher.key.length = reference->cipher_key.len;

	return 0;
}

static int
create_auth_cipher_xforms(struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		enum rte_crypto_auth_operation auth_op,
		enum rte_crypto_cipher_operation cipher_op,
		uint8_t *auth_key,
		uint8_t *cipher_key)
{
	memcpy(cipher_key, reference->cipher_key.data, reference->cipher_key.len);
	memcpy(auth_key, reference->auth_key.data, reference->auth_key.len);

	TEST_ASSERT_NOT_NULL(rte_crypto_op_sym_xforms_alloc(ut_params->op, 2),
			"failed to allocate space for crypto transforms");

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* Setup Authentication Parameters */
	sym_op->xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	sym_op->xform->auth.op = auth_op;
	sym_op->xform->auth.algo = reference->auth_algo;
	sym_op->xform->auth.key.length = reference->auth_key.len;
	sym_op->xform->auth.key.data = auth_key;
	sym_op->xform->auth.digest_length = reference->digest.len;
	sym_op->xform->auth.add_auth_data_length = reference->aad.len;

	/* Setup Cipher Parameters */
	sym_op->xform->next->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	sym_op->xform->next->cipher.algo = reference->crypto_algo;
	sym_op->xform->next->cipher.op = cipher_op;
	sym_op->xform->next->cipher.key.data = cipher_key;
	sym_op->xform->next->cipher.key.length = reference->cipher_key.len;

	return 0;
}

static int
create_auth_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		unsigned int auth_generate)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(ut_params->op, ut_params->sess);

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	/* digest */
	sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
			ut_params->ibuf, reference->digest.len);

	TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
			"no room to append auth tag");

	sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
			ut_params->ibuf, reference->plaintext.len);
	sym_op->auth.digest.length = reference->digest.len;

	if (auth_generate)
		memset(sym_op->auth.digest.data, 0, reference->digest.len);
	else
		memcpy(sym_op->auth.digest.data,
				reference->digest.data,
				reference->digest.len);

	TEST_HEXDUMP(stdout, "digest:",
			sym_op->auth.digest.data,
			sym_op->auth.digest.length);

	sym_op->auth.data.length = reference->plaintext.len;
	sym_op->auth.data.offset = 0;

	return 0;
}

static int
create_auth_generate_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_auth_operation(ts_params, ut_params, reference, 1);
}

static int
create_auth_verify_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_auth_operation(ts_params, ut_params, reference, 0);
}

static int
create_cipher_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(ut_params->op, ut_params->sess);

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	sym_op->cipher.iv.data = (uint8_t *)rte_pktmbuf_prepend(
		ut_params->ibuf, reference->iv.len);
	TEST_ASSERT_NOT_NULL(sym_op->cipher.iv.data, "no room to prepend iv");

	sym_op->cipher.iv.phys_addr = rte_pktmbuf_mtophys(ut_params->ibuf);
	sym_op->cipher.iv.length = reference->iv.len;

	memcpy(sym_op->cipher.iv.data, reference->iv.data, reference->iv.len);

	sym_op->cipher.data.length = reference->ciphertext.len;
	sym_op->cipher.data.offset = reference->iv.len;

	return 0;
}

static int
create_cipher_auth_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		unsigned int auth_generate)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(ut_params->op, ut_params->sess);

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	/* digest */
	sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
			ut_params->ibuf, reference->digest.len);

	TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
			"no room to append auth tag");

	sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
			ut_params->ibuf, reference->ciphertext.len);
	sym_op->auth.digest.length = reference->digest.len;

	if (auth_generate)
		memset(sym_op->auth.digest.data, 0, reference->digest.len);
	else
		memcpy(sym_op->auth.digest.data,
				reference->digest.data,
				reference->digest.len);

	TEST_HEXDUMP(stdout, "digest:",
			sym_op->auth.digest.data,
			sym_op->auth.digest.length);

	sym_op->cipher.iv.data = (uint8_t *)rte_pktmbuf_prepend(
		ut_params->ibuf, reference->iv.len);
	TEST_ASSERT_NOT_NULL(sym_op->cipher.iv.data, "no room to prepend iv");

	sym_op->cipher.iv.phys_addr = rte_pktmbuf_mtophys(ut_params->ibuf);
	sym_op->cipher.iv.length = reference->iv.len;

	memcpy(sym_op->cipher.iv.data, reference->iv.data, reference->iv.len);

	sym_op->cipher.data.length = reference->ciphertext.len;
	sym_op->cipher.data.offset = reference->iv.len;

	sym_op->auth.data.length = reference->ciphertext.len;
	sym_op->auth.data.offset = reference->iv.len;

	return 0;
}

static int
create_cipher_auth_generate_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_operation(ts_params, ut_params, reference, 1);
}

static int
create_cipher_auth_verify_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_operation(ts_params, ut_params, reference, 0);
}

static int
create_cipher_auth_sessionless_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		unsigned int auth_generate)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	/* digest */
	sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
			ut_params->ibuf, reference->digest.len);

	TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
			"no room to append auth tag");

	sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
			ut_params->ibuf, reference->ciphertext.len);
	sym_op->auth.digest.length = reference->digest.len;

	if (auth_generate)
		memset(sym_op->auth.digest.data, 0, reference->digest.len);
	else
		memcpy(sym_op->auth.digest.data,
				reference->digest.data,
				reference->digest.len);

	TEST_HEXDUMP(stdout, "digest:",
			sym_op->auth.digest.data,
			sym_op->auth.digest.length);

	sym_op->cipher.iv.data = (uint8_t *)rte_pktmbuf_prepend(
		ut_params->ibuf, reference->iv.len);
	TEST_ASSERT_NOT_NULL(sym_op->cipher.iv.data, "no room to prepend iv");

	sym_op->cipher.iv.phys_addr = rte_pktmbuf_mtophys(ut_params->ibuf);
	sym_op->cipher.iv.length = reference->iv.len;

	memcpy(sym_op->cipher.iv.data, reference->iv.data, reference->iv.len);

	sym_op->cipher.data.length = reference->ciphertext.len;
	sym_op->cipher.data.offset = reference->iv.len;

	sym_op->auth.data.length = reference->ciphertext.len;
	sym_op->auth.data.offset = reference->iv.len;

	return 0;
}

static int
create_cipher_auth_generate_sessionless_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_sessionless_operation(
			ts_params, ut_params, reference, 1);
}

static int
create_cipher_auth_verify_sessionless_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_sessionless_operation(
			ts_params, ut_params, reference, 0);
}

static int
create_cipher_auth_out_of_place_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		unsigned int auth_generate)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(ut_params->op, ut_params->sess);

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	/* set crypto operation destination mbuf */
	sym_op->m_dst = ut_params->obuf;

	/* digest */
	if (auth_generate) {
		sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
				ut_params->obuf, reference->digest.len);

		TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
				"no room to append auth tag");

		sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
				ut_params->obuf, reference->ciphertext.len);
		sym_op->auth.digest.length = reference->digest.len;
		memset(sym_op->auth.digest.data, 0, reference->digest.len);
	} else {
		sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
				ut_params->ibuf, reference->digest.len);

		TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
				"no room to append auth tag");

		sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
				ut_params->ibuf, reference->ciphertext.len);
		sym_op->auth.digest.length = reference->digest.len;
		memcpy(sym_op->auth.digest.data,
				reference->digest.data,
				reference->digest.len);
	}

	TEST_HEXDUMP(stdout, "digest:",
			sym_op->auth.digest.data,
			sym_op->auth.digest.length);

	sym_op->cipher.iv.data = (uint8_t *)rte_pktmbuf_prepend(
		ut_params->ibuf, reference->iv.len);
	TEST_ASSERT_NOT_NULL(sym_op->cipher.iv.data, "no room to prepend input iv");

	TEST_ASSERT_NOT_NULL(
			rte_pktmbuf_prepend(ut_params->obuf, reference->iv.len),
			"no room to prepend output iv");

	sym_op->cipher.iv.phys_addr = rte_pktmbuf_mtophys(ut_params->ibuf);
	sym_op->cipher.iv.length = reference->iv.len;

	memcpy(sym_op->cipher.iv.data, reference->iv.data, reference->iv.len);

	sym_op->cipher.data.length = reference->ciphertext.len;
	sym_op->cipher.data.offset = reference->iv.len;

	sym_op->auth.data.length = reference->ciphertext.len;
	sym_op->auth.data.offset = reference->iv.len;

	return 0;
}

static int
create_cipher_auth_generate_out_of_place_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_out_of_place_operation(
			ts_params, ut_params, reference, 1);
}

static int
create_cipher_auth_verify_out_of_place_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_cipher_auth_out_of_place_operation(
			ts_params, ut_params, reference, 0);
}

static int
create_auth_GMAC_operation(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference,
		unsigned int auth_generate)
{
	/* Generate Crypto op data structure */
	ut_params->op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	TEST_ASSERT_NOT_NULL(ut_params->op,
			"Failed to allocate pktmbuf offload");

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(ut_params->op, ut_params->sess);

	struct rte_crypto_sym_op *sym_op = ut_params->op->sym;

	/* set crypto operation source mbuf */
	sym_op->m_src = ut_params->ibuf;

	/* digest */
	sym_op->auth.digest.data = (uint8_t *)rte_pktmbuf_append(
			ut_params->ibuf, reference->digest.len);

	TEST_ASSERT_NOT_NULL(sym_op->auth.digest.data,
			"no room to append auth tag");

	sym_op->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
			ut_params->ibuf, reference->ciphertext.len);
	sym_op->auth.digest.length = reference->digest.len;

	if (auth_generate)
		memset(sym_op->auth.digest.data, 0, reference->digest.len);
	else
		memcpy(sym_op->auth.digest.data,
				reference->digest.data,
				reference->digest.len);

	TEST_HEXDUMP(stdout, "digest:",
			sym_op->auth.digest.data,
			sym_op->auth.digest.length);

	sym_op->cipher.iv.data = (uint8_t *)rte_pktmbuf_prepend(
		ut_params->ibuf, reference->iv.len);
	TEST_ASSERT_NOT_NULL(sym_op->cipher.iv.data, "no room to prepend iv");

	sym_op->cipher.iv.phys_addr = rte_pktmbuf_mtophys(ut_params->ibuf);
	sym_op->cipher.iv.length = reference->iv.len;

	memcpy(sym_op->cipher.iv.data, reference->iv.data, reference->iv.len);

	sym_op->cipher.data.length = 0;
	sym_op->cipher.data.offset = 0;

	sym_op->auth.data.length = reference->plaintext.len;
	sym_op->auth.data.offset = reference->iv.len;

	return 0;
}

static int
create_auth_generate_GMAC_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_auth_GMAC_operation(ts_params, ut_params, reference, 1);
}

static int
create_auth_verify_GMAC_operation(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	return create_auth_GMAC_operation(ts_params, ut_params, reference, 0);
}

static struct rte_crypto_op *
process_crypto_request(uint8_t dev_id, struct rte_crypto_op *op)
{
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		printf("Error sending packet for encryption");
		return NULL;
	}

	op = NULL;

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &op, 1) == 0)
		rte_pause();

	return op;
}

int
test_authentication(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *digest;
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_GENERATE,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_auth_generate_operation(ts_params, ut_params, reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *);

	digest = plaintext + reference->plaintext.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
			plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	TEST_HEXDUMP(stdout, "digest:", digest, reference->digest.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		digest,
		reference->digest.data,
		reference->digest.len,
		"Generated auth tag not as expected");

	return 0;
}

int
test_authentication_verify(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext;
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_VERIFY,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_auth_verify_operation(ts_params, ut_params, reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_NOT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_AUTH_FAILED,
			"authentication failed");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}

int
test_encryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext;
	uint8_t cipher_key[reference->cipher_key.len + 1];

	/* Create session */
	retval = create_cipher_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_CIPHER_OP_ENCRYPT,
			cipher_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_cipher_operation(ts_params, ut_params, reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	ciphertext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		ciphertext,
		reference->ciphertext.data,
		reference->ciphertext.len,
		"Ciphertext data not as expected");

	return 0;
}

int
test_decryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext;
	uint8_t cipher_key[reference->cipher_key.len + 1];

	/* Create session */
	retval = create_cipher_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			cipher_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->ciphertext.len);
	TEST_ASSERT_NOT_NULL(ciphertext, "no room to append ciphertext");
	memcpy(ciphertext, reference->ciphertext.data, reference->ciphertext.len);

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	/* Create operation */
	retval = create_cipher_operation(ts_params, ut_params, reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}

int
test_authenticated_encryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext, *digest;
	uint8_t cipher_key[reference->cipher_key.len + 1];
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_cipher_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_CIPHER_OP_ENCRYPT,
			RTE_CRYPTO_AUTH_OP_GENERATE,
			cipher_key,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_cipher_auth_generate_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	ciphertext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	digest = ciphertext + reference->ciphertext.len;

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		ciphertext,
		reference->ciphertext.data,
		reference->ciphertext.len,
		"Ciphertext data not as expected");

	TEST_HEXDUMP(stdout, "digest:", digest, reference->digest.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		digest,
		reference->digest.data,
		reference->digest.len,
		"Generated auth tag not as expected");

	return 0;
}

int
test_authenticated_decryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext;
	uint8_t auth_key[reference->auth_key.len + 1];
	uint8_t cipher_key[reference->cipher_key.len + 1];

	/* Create session */
	retval = create_auth_cipher_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_VERIFY,
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			auth_key,
			cipher_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->ciphertext.len);
	TEST_ASSERT_NOT_NULL(ciphertext, "no room to append ciphertext");
	memcpy(ciphertext, reference->ciphertext.data, reference->ciphertext.len);

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	/* Create operation */
	retval = create_cipher_auth_verify_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_NOT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_AUTH_FAILED,
			"authentication failed");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}

int
test_authenticated_encryption_sessionless(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext, *digest;
	uint8_t cipher_key[reference->cipher_key.len + 1];
	uint8_t auth_key[reference->auth_key.len + 1];

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_cipher_auth_generate_sessionless_operation(ts_params,
			ut_params,
			reference);
	if (retval < 0)
		return retval;

	/* Create xforms */
	retval = create_cipher_auth_xforms(ut_params,
			reference,
			RTE_CRYPTO_CIPHER_OP_ENCRYPT,
			RTE_CRYPTO_AUTH_OP_GENERATE,
			cipher_key,
			auth_key);
	if (retval < 0)
		return retval;

	TEST_ASSERT_EQUAL(ut_params->op->sym->sess_type,
			RTE_CRYPTO_SYM_OP_SESSIONLESS,
			"crypto op session type not sessionless");

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	ciphertext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	digest = ciphertext + reference->ciphertext.len;

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		ciphertext,
		reference->ciphertext.data,
		reference->ciphertext.len,
		"Ciphertext data not as expected");

	TEST_HEXDUMP(stdout, "digest:", digest, reference->digest.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		digest,
		reference->digest.data,
		reference->digest.len,
		"Generated auth tag not as expected");

	return 0;
}

int
test_authenticated_decryption_sessionless(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext;
	uint8_t auth_key[reference->auth_key.len + 1];
	uint8_t cipher_key[reference->cipher_key.len + 1];

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->ciphertext.len);
	TEST_ASSERT_NOT_NULL(ciphertext, "no room to append ciphertext");
	memcpy(ciphertext, reference->ciphertext.data, reference->ciphertext.len);

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	/* Create operation */
	retval = create_cipher_auth_verify_sessionless_operation(ts_params,
			ut_params,
			reference);
	if (retval < 0)
		return retval;

	/* Create xforms */
	retval = create_auth_cipher_xforms(ut_params,
			reference,
			RTE_CRYPTO_AUTH_OP_VERIFY,
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			auth_key,
			cipher_key);
	if (retval < 0)
		return retval;

	TEST_ASSERT_EQUAL(ut_params->op->sym->sess_type,
			RTE_CRYPTO_SYM_OP_SESSIONLESS,
			"crypto op session type not sessionless");

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_NOT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_AUTH_FAILED,
			"authentication failed");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}

int
test_authenticated_encryption_out_of_place(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext, *digest;
	uint8_t cipher_key[reference->cipher_key.len + 1];
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_cipher_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_CIPHER_OP_ENCRYPT,
			RTE_CRYPTO_AUTH_OP_GENERATE,
			cipher_key,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");
	ut_params->obuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->obuf,
			"Failed to allocate output buffer in mempool");

	/* clear mbufs payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));
	memset(rte_pktmbuf_mtod(ut_params->obuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->obuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->obuf,
			reference->ciphertext.len);
	TEST_ASSERT_NOT_NULL(ciphertext, "no room to append ciphertext");
	memset(ciphertext, 0, reference->ciphertext.len);

	/* Create operation */
	retval = create_cipher_auth_generate_out_of_place_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_dst;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	ciphertext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	digest = ciphertext + reference->ciphertext.len;

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		ciphertext,
		reference->ciphertext.data,
		reference->ciphertext.len,
		"Ciphertext data not as expected");

	TEST_HEXDUMP(stdout, "digest:", digest, reference->digest.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		digest,
		reference->digest.data,
		reference->digest.len,
		"Generated auth tag not as expected");

	return 0;
}

int
test_authenticated_decryption_out_of_place(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *ciphertext;
	uint8_t auth_key[reference->auth_key.len + 1];
	uint8_t cipher_key[reference->cipher_key.len + 1];

	/* Create session */
	retval = create_auth_cipher_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_VERIFY,
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			auth_key,
			cipher_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");
	ut_params->obuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->obuf,
			"Failed to allocate output buffer in mempool");

	/* clear mbufs payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));
	memset(rte_pktmbuf_mtod(ut_params->obuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->obuf));

	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->ciphertext.len);
	TEST_ASSERT_NOT_NULL(ciphertext, "no room to append ciphertext");
	memcpy(ciphertext, reference->ciphertext.data, reference->ciphertext.len);

	TEST_HEXDUMP(stdout, "ciphertext:", ciphertext, reference->ciphertext.len);

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->obuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memset(plaintext, 0, reference->plaintext.len);

	/* Create operation */
	retval = create_cipher_auth_verify_out_of_place_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_NOT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_AUTH_FAILED,
			"authentication failed");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_dst;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}

int
test_authentication_GMAC(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext, *digest;
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_GENERATE,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_auth_generate_GMAC_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_EQUAL(ut_params->op->status, RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	digest = plaintext + reference->plaintext.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	TEST_HEXDUMP(stdout, "digest:", digest, reference->digest.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		digest,
		reference->digest.data,
		reference->digest.len,
		"Generated auth tag not as expected");

	return 0;
}

int
test_authentication_verify_GMAC(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference)
{
	int retval;

	uint8_t *plaintext;
	uint8_t auth_key[reference->auth_key.len + 1];

	/* Create session */
	retval = create_auth_session(ut_params,
			ts_params->valid_devs[0],
			reference,
			RTE_CRYPTO_AUTH_OP_VERIFY,
			auth_key);
	if (retval < 0)
		return retval;

	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	TEST_ASSERT_NOT_NULL(ut_params->ibuf,
			"Failed to allocate input buffer in mempool");

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(ut_params->ibuf));

	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
			reference->plaintext.len);
	TEST_ASSERT_NOT_NULL(plaintext, "no room to append plaintext");
	memcpy(plaintext, reference->plaintext.data, reference->plaintext.len);

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	/* Create operation */
	retval = create_auth_verify_GMAC_operation(ts_params,
			ut_params,
			reference);

	if (retval < 0)
		return retval;

	ut_params->op = process_crypto_request(ts_params->valid_devs[0],
			ut_params->op);
	TEST_ASSERT_NOT_NULL(ut_params->op, "failed crypto process");
	TEST_ASSERT_NOT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_AUTH_FAILED,
			"authentication failed");
	TEST_ASSERT_EQUAL(ut_params->op->status,
			RTE_CRYPTO_OP_STATUS_SUCCESS,
			"crypto op status not success");

	ut_params->obuf = ut_params->op->sym->m_src;
	TEST_ASSERT_NOT_NULL(ut_params->obuf, "failed to retrieve obuf");

	plaintext = rte_pktmbuf_mtod(ut_params->obuf, uint8_t *)
			+ reference->iv.len;

	TEST_HEXDUMP(stdout, "plaintext:", plaintext, reference->plaintext.len);

	TEST_ASSERT_BUFFERS_ARE_EQUAL(
		plaintext,
		reference->plaintext.data,
		reference->plaintext.len,
		"Plaintext data not as expected");

	return 0;
}
