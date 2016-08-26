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

#ifndef TEST_CRYPTODEV_OPERATIONS_H_
#define TEST_CRYPTODEV_OPERATIONS_H_

struct test_crypto_vector {
	enum rte_crypto_cipher_algorithm crypto_algo;

	struct {
		uint8_t data[64];
		unsigned int len;
	} cipher_key;

	struct {
		uint8_t data[64];
		unsigned int len;
	} iv;

	struct {
		const uint8_t *data;
		unsigned int len;
	} plaintext;

	struct {
		const uint8_t *data;
		unsigned int len;
	} ciphertext;

	enum rte_crypto_auth_algorithm auth_algo;

	struct {
		uint8_t data[128];
		unsigned int len;
	} auth_key;

	struct {
		uint8_t data[64];
		unsigned int len;
	} aad;

	struct {
		uint8_t data[128];
		unsigned int len;
	} digest;
};

int
test_authentication(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authentication_verify(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_encryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_decryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_encryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_decryption(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_encryption_sessionless(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_decryption_sessionless(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_encryption_out_of_place(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authenticated_decryption_out_of_place(
		struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authentication_GMAC(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

int
test_authentication_verify_GMAC(struct crypto_testsuite_params *ts_params,
		struct crypto_unittest_params *ut_params,
		const struct test_crypto_vector *reference);

#endif /* TEST_CRYPTODEV_OPERATIONS_H_ */
