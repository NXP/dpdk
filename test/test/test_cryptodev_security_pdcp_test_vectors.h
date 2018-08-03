/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc.
 * Copyright 2018 NXP
 */

#ifndef SECURITY_PDCP_TEST_VECTOR_H_
#define SECURITY_PDCP_TEST_VECTOR_H_

#include <rte_security.h>

/*
 * PDCP test vectors and related structures.
 */
#define PDCP_CPLANE_OFFSET	0
#define CPLANE_NULL_ENC_OFFSET 0
#define CPLANE_SNOW_ENC_OFFSET 8
#define CPLANE_AES_ENC_OFFSET 16
#define CPLANE_ZUC_ENC_OFFSET 24
#define CPLANE_NULL_AUTH_OFFSET 0
#define CPLANE_SNOW_AUTH_OFFSET 2
#define CPLANE_AES_AUTH_OFFSET 4
#define CPLANE_ZUC_AUTH_OFFSET 6

#define PDCP_UPLANE_OFFSET	32
#define NULL_PROTO_OFFSET 0
#define SNOW_PROTO_OFFSET 6
#define AES_PROTO_OFFSET 12
#define ZUC_PROTO_OFFSET 18
#define LONG_SEQ_NUM_OFFSET 0
#define SHORT_SEQ_NUM_OFFSET 2
#define FIFTEEN_BIT_SEQ_NUM_OFFSET 4
#define UPLINK_OFFSET 0
#define DOWNLINK_OFFSET 1
#define F8_KEY_LEN      16      /**< key length(in bytes) for F8 */

enum pdcp_dir {
	PDCP_DIR_UPLINK = 0,
	PDCP_DIR_DOWNLINK = 1,
	PDCP_DIR_INVALID
};

struct pdcp_test_param {
	uint8_t type;
	enum rte_security_pdcp_domain domain;
	enum rte_crypto_cipher_algorithm cipher_alg;
	uint8_t cipher_key_len;
	enum rte_crypto_auth_algorithm auth_alg;
	uint8_t auth_key_len;
	const char *name;
};

static struct pdcp_test_param pdcp_test_params[] = {
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and NULL integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and NULL integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and SNOW f9 integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and SNOW f9 integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and AES CMAC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and AES CMAC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and ZUC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with NULL encryption and ZUC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 0,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and NULL integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and NULL integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and SNOW f9 integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and SNOW f9 integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and AES CMAC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and AES CMAC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and ZUC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with SNOW f8 encryption and ZUC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and NULL integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and NULL integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and SNOW f9 integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and SNOW f9 integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and AES CMAC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and AES CMAC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and ZUC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with AES CTR encryption and ZUC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and NULL integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and NULL integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and SNOW f9 integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and SNOW f9 integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and AES CMAC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and AES CMAC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_AES_CMAC,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and ZUC integrity Uplink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP Control Plane with ZUC encryption and ZUC integrity Downlink",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_ZUC_EIA3,
	 .cipher_key_len = 16,
	 .auth_key_len = 16,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Uplink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Downlink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Uplink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Downlink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Uplink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with NULL encryption Downlink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_NULL,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 0,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Uplink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Downlink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Uplink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Downlink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Uplink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with SNOW f8 encryption Downlink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Uplink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Downlink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Uplink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Downlink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Uplink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with AES CTR encryption Downlink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_AES_CTR,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Uplink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Downlink with long sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Uplink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Downlink with short sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Uplink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0,
	 },
	{
	 .name =
	 "PDCP User Plane with ZUC encryption Downlink with 15 bit sequence number",
	 .cipher_alg = RTE_CRYPTO_CIPHER_ZUC_EEA3,
	 .auth_alg = RTE_CRYPTO_AUTH_NULL,
	 .domain = RTE_SECURITY_PDCP_MODE_DATA,
	 .cipher_key_len = 16,
	 .auth_key_len = 0
	 },
};

static uint32_t pdcp_test_hfn[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	0x000fa557,
	/* Control Plane w/NULL enc. + NULL int. DL */
	0x000fa557,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	0x000fa557,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	0x000fa557,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	0x000fa557,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	0x000fa557,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	0x000fa557,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	0x000fa557,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	0x000fa557,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	0x000fa557,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	0x000fa557,
	/* User Plane w/NULL enc. UL LONG SN */
	0x000fa557,
	/* User Plane w/NULL enc. DL LONG SN */
	0x000fa557,
	/* User Plane w/NULL enc. UL SHORT SN */
	0x000fa557,
	/* User Plane w/NULL enc. DL SHORT SN */
	0x000fa557,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	0x000fa557,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	0x000fa557,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. UL LONG SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. DL LONG SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	0x000fa557,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	0x000fa557,
	/* User Plane w/ZUC enc. UL LONG SN */
	0x000fa557,
	/* User Plane w/ZUC enc. DL LONG SN */
	0x000fa557,
	/* User Plane w/ZUC enc. UL SHORT SN */
	0x000fa557,
	/* User Plane w/ZUC enc. DL SHORT SN */
	0x000fa557,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	0x000fa557,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	0x000fa557,
};

static uint32_t pdcp_test_hfn_threshold[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	0x000fa558,
	/* Control Plane w/NULL enc. + NULL int. DL */
	0x000fa558,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	0x000fa558,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	0x000fa558,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	0x000fa558,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	0x000fa558,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	0x000fa558,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	0x000fa558,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	0x000fa558,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	0x000fa558,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	0x000fa558,
	/* User Plane w/NULL enc. UL LONG SN */
	0x000fa558,
	/* User Plane w/NULL enc. DL LONG SN */
	0x000fa558,
	/* User Plane w/NULL enc. UL SHORT SN */
	0x000fa558,
	/* User Plane w/NULL enc. DL SHORT SN */
	0x000fa558,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	0x000fa558,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	0x000fa558,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. UL LONG SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. DL LONG SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	0x000fa558,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	0x000fa558,
	/* User Plane w/ZUC enc. UL LONG SN */
	0x000fa558,
	/* User Plane w/ZUC enc. DL LONG SN */
	0x000fa558,
	/* User Plane w/ZUC enc. UL SHORT SN */
	0x000fa558,
	/* User Plane w/ZUC enc. DL SHORT SN */
	0x000fa558,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	0x000fa558,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	0x000fa558,
};

static uint8_t pdcp_test_bearer[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	0x03,
	/* Control Plane w/NULL enc. + NULL int. DL */
	0x03,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	0x03,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	0x03,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	0x03,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	0x03,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	0x03,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	0x03,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	0x03,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	0x03,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	0x03,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	0x03,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	0x03,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	0x03,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	0x03,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	0x03,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	0x03,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	0x03,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	0x03,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	0x03,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	0x03,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	0x03,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	0x03,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	0x03,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	0x03,
	/* User Plane w/NULL enc. UL LONG SN */
	0x03,
	/* User Plane w/NULL enc. DL LONG SN */
	0x03,
	/* User Plane w/NULL enc. UL SHORT SN */
	0x03,
	/* User Plane w/NULL enc. DL SHORT SN */
	0x03,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	0x03,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	0x03,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	0x03,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	0x03,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	0x03,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	0x03,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	0x03,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	0x03,
	/* User Plane w/AES CTR enc. UL LONG SN */
	0x03,
	/* User Plane w/AES CTR enc. DL LONG SN */
	0x03,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	0x03,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	0x03,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	0x03,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	0x03,
	/* User Plane w/ZUC enc. UL LONG SN */
	0x03,
	/* User Plane w/ZUC enc. DL LONG SN */
	0x03,
	/* User Plane w/ZUC enc. UL SHORT SN */
	0x03,
	/* User Plane w/ZUC enc. DL SHORT SN */
	0x03,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	0x03,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	0x03,
};

static uint8_t pdcp_test_packet_direction[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/NULL enc. + NULL int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	PDCP_DIR_DOWNLINK,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	PDCP_DIR_UPLINK,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/NULL enc. UL LONG SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/NULL enc. DL LONG SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/NULL enc. UL SHORT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/NULL enc. DL SHORT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/AES CTR enc. UL LONG SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/AES CTR enc. DL LONG SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/ZUC enc. UL LONG SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/ZUC enc. DL LONG SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/ZUC enc. UL SHORT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/ZUC enc. DL SHORT SN */
	PDCP_DIR_DOWNLINK,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	PDCP_DIR_UPLINK,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	PDCP_DIR_DOWNLINK,
};

static uint8_t pdcp_test_data_sn_size[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	5,
	/* Control Plane w/NULL enc. + NULL int. DL */
	5,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	5,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	5,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	5,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	5,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	5,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	5,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	5,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	5,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	5,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	5,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	5,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	5,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	5,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	5,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	5,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	5,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	5,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	5,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	5,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	5,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	5,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	5,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	5,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	5,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	5,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	5,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	5,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	5,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	5,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	5,
	/* User Plane w/NULL enc. UL LONG SN */
	12,
	/* User Plane w/NULL enc. DL LONG SN */
	12,
	/* User Plane w/NULL enc. UL SHORT SN */
	7,
	/* User Plane w/NULL enc. DL SHORT SN */
	7,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	15,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	15,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	12,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	12,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	7,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	7,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	15,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	15,
	/* User Plane w/AES CTR enc. UL LONG SN */
	12,
	/* User Plane w/AES CTR enc. DL LONG SN */
	12,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	7,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	7,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	15,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	15,
	/* User Plane w/ZUC enc. UL LONG SN */
	12,
	/* User Plane w/ZUC enc. DL LONG SN */
	12,
	/* User Plane w/ZUC enc. UL SHORT SN */
	7,
	/* User Plane w/ZUC enc. DL SHORT SN */
	7,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	15,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	15,
};

static uint8_t *pdcp_test_crypto_key[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + NULL int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + ZUC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/NULL enc. + ZUC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + NULL int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + NULL int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. UL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. DL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. UL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. DL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. UL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/NULL enc. DL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. UL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. DL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. UL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. DL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. UL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. DL LONG SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. UL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. DL SHORT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	(uint8_t[]){0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5,
		    0xf1, 0x45, 0x10, 0x10, 0xd8, 0x52},
};

static uint8_t *pdcp_test_auth_key[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + NULL int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + ZUC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/NULL enc. + ZUC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + NULL int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + NULL int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	(uint8_t[]){0xc7, 0x36, 0xc6, 0xaa, 0xb2, 0x2b, 0xff, 0xf9, 0x1e, 0x26,
		    0x98, 0xd2, 0xe2, 0x2a, 0xd5, 0x7e},
	/* User Plane w/NULL enc. UL LONG SN */
	NULL,
	/* User Plane w/NULL enc. DL LONG SN */
	NULL,
	/* User Plane w/NULL enc. UL SHORT SN */
	NULL,
	/* User Plane w/NULL enc. DL SHORT SN */
	NULL,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	NULL,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	NULL,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	NULL,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	NULL,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	NULL,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	NULL,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	NULL,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	NULL,
	/* User Plane w/AES CTR enc. UL LONG SN */
	NULL,
	/* User Plane w/AES CTR enc. DL LONG SN */
	NULL,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	NULL,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	NULL,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	NULL,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	NULL,
	/* User Plane w/ZUC enc. UL LONG SN */
	NULL,
	/* User Plane w/ZUC enc. DL LONG SN */
	NULL,
	/* User Plane w/ZUC enc. UL SHORT SN */
	NULL,
	/* User Plane w/ZUC enc. DL SHORT SN */
	NULL,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	NULL,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	NULL,
};

static uint8_t *pdcp_test_data_in[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/NULL enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
};

static uint32_t pdcp_test_data_in_len[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	16,
	/* Control Plane w/NULL enc. + NULL int. DL */
	16,
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	16,
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	16,
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	16,
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	16,
	/* Control Plane w/NULL enc. + ZUC int. UL */
	16,
	/* Control Plane w/NULL enc. + ZUC int. DL */
	16,
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	16,
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	16,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	16,
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	16,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	16,
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	16,
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	16,
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	16,
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	16,
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	16,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	16,
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	16,
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	16,
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	16,
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	16,
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	16,
	/* Control Plane w/ZUC enc. + NULL int. UL */
	16,
	/* Control Plane w/ZUC enc. + NULL int. DL */
	16,
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	16,
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	16,
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	16,
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	16,
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	16,
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	16,
	/* User Plane w/NULL enc. UL LONG SN */
	17,
	/* User Plane w/NULL enc. DL LONG SN */
	17,
	/* User Plane w/NULL enc. UL SHORT SN */
	16,
	/* User Plane w/NULL enc. DL SHORT SN */
	16,
	/* User Plane w/NULL enc. UL 15 BIT SN */
	17,
	/* User Plane w/NULL enc. DL 15 BIT SN */
	17,
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	17,
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	17,
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	16,
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	16,
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	17,
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	17,
	/* User Plane w/AES CTR enc. UL LONG SN */
	17,
	/* User Plane w/AES CTR enc. DL LONG SN */
	17,
	/* User Plane w/AES CTR enc. UL SHORT SN */
	16,
	/* User Plane w/AES CTR enc. DL SHORT SN */
	16,
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	17,
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	17,
	/* User Plane w/ZUC enc. UL LONG SN */
	17,
	/* User Plane w/ZUC enc. DL LONG SN */
	17,
	/* User Plane w/ZUC enc. UL SHORT SN */
	16,
	/* User Plane w/ZUC enc. DL SHORT SN */
	16,
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	17,
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	17,
};

static uint8_t *pdcp_test_data_out[] = {
	/* Control Plane w/NULL enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x00, 0x00, 0x00, 0x00},
	/* Control Plane w/NULL enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x00, 0x00, 0x00, 0x00},
	/* Control Plane w/NULL enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x88, 0x7f, 0x4e, 0x59},
	/* Control Plane w/NULL enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x9d, 0x9e, 0x45, 0x36},
	/* Control Plane w/NULL enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0xf3, 0xdd, 0x01, 0xdf},
	/* Control Plane w/NULL enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x5d, 0x8e, 0x5d, 0x05},
	/* Control Plane w/NULL enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x18, 0xc3, 0x2e, 0x66},
	/* Control Plane w/NULL enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8, 0x72, 0x44, 0xab, 0x64},
	/* Control Plane w/SNOW f8 enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0x39, 0xd1, 0x2b, 0xbd, 0x2a, 0x4c, 0x91, 0x59, 0xff,
		    0xfa, 0xce, 0x68, 0xc0, 0x7c, 0x30, 0xd0, 0xc5, 0x08, 0x58},
	/* Control Plane w/SNOW f8 enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0x26, 0xf3, 0x67, 0xf1, 0x42, 0x50, 0x1a, 0x85, 0x02,
		    0xb9, 0x00, 0xa8, 0x9b, 0xcf, 0x06, 0xd1, 0x2c, 0x86, 0x7c},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0x39, 0xd1, 0x2b, 0xbd, 0x2a, 0x4c, 0x91, 0x59, 0xff,
		    0xfa, 0xce, 0x68, 0xc0, 0x7c, 0x30, 0x58, 0xba, 0x46, 0x01},
	/* Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0x26, 0xf3, 0x67, 0xf1, 0x42, 0x50, 0x1a, 0x85, 0x02,
		    0xb9, 0x00, 0xa8, 0x9b, 0xcf, 0x06, 0x4c, 0xb2, 0xc3, 0x4a},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0x39, 0xd1, 0x2b, 0xbd, 0x2a, 0x4c, 0x91, 0x59, 0xff,
		    0xfa, 0xce, 0x68, 0xc0, 0x7c, 0x30, 0x23, 0x18, 0x09, 0x87},
	/* Control Plane w/SNOW f8 enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0x26, 0xf3, 0x67, 0xf1, 0x42, 0x50, 0x1a, 0x85, 0x02,
		    0xb9, 0x00, 0xa8, 0x9b, 0xcf, 0x06, 0x8c, 0xa2, 0xdb, 0x79},
	/* Control Plane w/SNOW f8 enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0x39, 0xd1, 0x2b, 0xbd, 0x2a, 0x4c, 0x91, 0x59, 0xff,
		    0xfa, 0xce, 0x68, 0xc0, 0x7c, 0x30, 0xc8, 0x06, 0x26, 0x3e},
	/* Control Plane w/SNOW f8 enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0x26, 0xf3, 0x67, 0xf1, 0x42, 0x50, 0x1a, 0x85, 0x02,
		    0xb9, 0x00, 0xa8, 0x9b, 0xcf, 0x06, 0xa3, 0x68, 0x2d, 0x18},
	/* Control Plane w/AES CTR enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0x2c, 0x59, 0x74, 0xab, 0xdc, 0xd8, 0x36, 0xf6, 0x1b,
		    0x54, 0x8d, 0x46, 0x93, 0x1c, 0xff, 0x32, 0x4f, 0x1a, 0x6b},
	/* Control Plane w/AES CTR enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0xf2, 0xb9, 0x9d, 0x96, 0x51, 0xcc, 0x1e, 0xe8, 0x55,
		    0x3e, 0x98, 0xc5, 0x58, 0xec, 0x4c, 0x92, 0x40, 0x52, 0x8e},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0x2c, 0x59, 0x74, 0xab, 0xdc, 0xd8, 0x36, 0xf6, 0x1b,
		    0x54, 0x8d, 0x46, 0x93, 0x1c, 0xff, 0xba, 0x30, 0x54, 0x32},
	/* Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0xf2, 0xb9, 0x9d, 0x96, 0x51, 0xcc, 0x1e, 0xe8, 0x55,
		    0x3e, 0x98, 0xc5, 0x58, 0xec, 0x4c, 0x0f, 0xde, 0x17, 0xb8},
	/* Control Plane w/AES CTR enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0x2c, 0x59, 0x74, 0xab, 0xdc, 0xd8, 0x36, 0xf6, 0x1b,
		    0x54, 0x8d, 0x46, 0x93, 0x1c, 0xff, 0xc1, 0x92, 0x1b, 0xb4},
	/* Control Plane w/AES CTR enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0xf2, 0xb9, 0x9d, 0x96, 0x51, 0xcc, 0x1e, 0xe8, 0x55,
		    0x3e, 0x98, 0xc5, 0x58, 0xec, 0x4c, 0xcf, 0xce, 0x0f, 0x8b},
	/* Control Plane w/AES CTR enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0x2c, 0x59, 0x74, 0xab, 0xdc, 0xd8, 0x36, 0xf6, 0x1b,
		    0x54, 0x8d, 0x46, 0x93, 0x1c, 0xff, 0x2a, 0x8c, 0x34, 0x0d},
	/* Control Plane w/AES CTR enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0xf2, 0xb9, 0x9d, 0x96, 0x51, 0xcc, 0x1e, 0xe8, 0x55,
		    0x3e, 0x98, 0xc5, 0x58, 0xec, 0x4c, 0xe0, 0x04, 0xf9, 0xea},
	/* Control Plane w/ZUC enc. + NULL int. UL */
	(uint8_t[]){0x8b, 0xa6, 0x23, 0xf8, 0xca, 0x98, 0x03, 0x33, 0x81, 0x8a,
		    0x6b, 0xfe, 0x37, 0xf2, 0x20, 0xd6, 0x68, 0x82, 0xb9, 0x06},
	/* Control Plane w/ZUC enc. + NULL int. DL */
	(uint8_t[]){0x8b, 0x3b, 0x42, 0xfc, 0x73, 0x83, 0x09, 0xb1, 0x3f, 0x66,
		    0x86, 0x3a, 0x5d, 0xe7, 0x47, 0xf4, 0x44, 0x81, 0x49, 0x0e},
	/* Control Plane w/ZUC enc. + SNOW f9 int. UL */
	(uint8_t[]){0x8b, 0xa6, 0x23, 0xf8, 0xca, 0x98, 0x03, 0x33, 0x81, 0x8a,
		    0x6b, 0xfe, 0x37, 0xf2, 0x20, 0xd6, 0xe0, 0xfd, 0xf7, 0x5f},
	/* Control Plane w/ZUC enc. + SNOW f9 int. DL */
	(uint8_t[]){0x8b, 0x3b, 0x42, 0xfc, 0x73, 0x83, 0x09, 0xb1, 0x3f, 0x66,
		    0x86, 0x3a, 0x5d, 0xe7, 0x47, 0xf4, 0xd9, 0x1f, 0x0c, 0x38},
	/* Control Plane w/ZUC enc. + AES CMAC int. UL */
	(uint8_t[]){0x8b, 0xa6, 0x23, 0xf8, 0xca, 0x98, 0x03, 0x33, 0x81, 0x8a,
		    0x6b, 0xfe, 0x37, 0xf2, 0x20, 0xd6, 0x9b, 0x5f, 0xb8, 0xd9},
	/* Control Plane w/ZUC enc. + AES CMAC int. DL */
	(uint8_t[]){0x8b, 0x3b, 0x42, 0xfc, 0x73, 0x83, 0x09, 0xb1, 0x3f, 0x66,
		    0x86, 0x3a, 0x5d, 0xe7, 0x47, 0xf4, 0x19, 0x0f, 0x14, 0x0b},
	/* Control Plane w/ZUC enc. + ZUC int. UL */
	(uint8_t[]){0x8b, 0xa6, 0x23, 0xf8, 0xca, 0x98, 0x03, 0x33, 0x81, 0x8a,
		    0x6b, 0xfe, 0x37, 0xf2, 0x20, 0xd6, 0x70, 0x41, 0x97, 0x60},
	/* Control Plane w/ZUC enc. + ZUC int. DL */
	(uint8_t[]){0x8b, 0x3b, 0x42, 0xfc, 0x73, 0x83, 0x09, 0xb1, 0x3f, 0x66,
		    0x86, 0x3a, 0x5d, 0xe7, 0x47, 0xf4, 0x36, 0xc5, 0xe2, 0x6a},
	/* User Plane w/NULL enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57,
		    0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/NULL enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4,
		    0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07, 0xe8},
	/* User Plane w/SNOW f8 enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0x7a, 0xe0, 0x00, 0x07, 0x2a, 0xa6, 0xef, 0xdc,
		    0x75, 0xef, 0x2e, 0x27, 0x0f, 0x69, 0x3d},
	/* User Plane w/SNOW f8 enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0x7e, 0xbb, 0x80, 0x20, 0xba, 0xef, 0xe7, 0xf7,
		    0xef, 0x69, 0x51, 0x85, 0x09, 0xa5, 0xab},
	/* User Plane w/SNOW f8 enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0x80, 0xcf, 0xe5, 0x27, 0xe2, 0x88, 0x2a, 0xac, 0xc5,
		    0xaf, 0x49, 0x9b, 0x3e, 0x48, 0x89},
	/* User Plane w/SNOW f8 enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xe2, 0x51, 0x58, 0x88, 0xff, 0x1a, 0x00, 0xe4, 0x67,
		    0x05, 0x46, 0x24, 0x2f, 0x07, 0xb7},
	/* User Plane w/SNOW f8 enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xbe, 0x72, 0x05, 0x78, 0x92, 0xec, 0xb1, 0x4f,
		    0xdd, 0x5d, 0xfc, 0x60, 0x2c, 0x9a, 0x85},
	/* User Plane w/SNOW f8 enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0x0b, 0x50, 0xf3, 0xff, 0x37, 0xe3, 0x6b, 0xaf,
		    0x08, 0xd8, 0xf6, 0x1f, 0xca, 0x6f, 0xbc},
	/* User Plane w/AES CTR enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xde, 0x0a, 0x59, 0xca, 0x7d, 0x93, 0xa3, 0xb5,
		    0xd2, 0x88, 0xb3, 0x04, 0xa2, 0x12, 0x09},
	/* User Plane w/AES CTR enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0x69, 0x92, 0x25, 0xd8, 0xe9, 0xd5, 0xe9, 0x53,
		    0x60, 0x49, 0x9f, 0xe9, 0x8f, 0xbe, 0x6a},
	/* User Plane w/AES CTR enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0x0f, 0xa1, 0xf2, 0x56, 0x6e, 0xee, 0x62, 0x1c, 0x62,
		    0x06, 0x7e, 0x38, 0x4a, 0x02, 0xa4},
	/* User Plane w/AES CTR enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0x00, 0x8d, 0x50, 0x80, 0x30, 0xda, 0xc7, 0x14, 0xc5,
		    0xe0, 0xc8, 0xfb, 0x83, 0xd0, 0x73},
	/* User Plane w/AES CTR enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xa1, 0x2e, 0xa3, 0x64, 0xa9, 0x81, 0xbc, 0xd3,
		    0x6f, 0xef, 0xee, 0x30, 0x71, 0x23, 0x85},
	/* User Plane w/AES CTR enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xc7, 0xf2, 0x23, 0xb3, 0xbe, 0xc0, 0xdf, 0xc5,
		    0xed, 0x37, 0x35, 0x7c, 0x66, 0xa3, 0xf9},
	/* User Plane w/ZUC enc. UL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0xfb, 0xb6, 0x0e, 0x81, 0xa1, 0x9e, 0xc8, 0xeb,
		    0x90, 0xa8, 0xc7, 0x0e, 0x27, 0xcb, 0xb0},
	/* User Plane w/ZUC enc. DL LONG SN */
	(uint8_t[]){0x8b, 0x26, 0x2f, 0x5d, 0xa4, 0x82, 0xfb, 0xce, 0x1f, 0x3a,
		    0xb5, 0x66, 0x60, 0x40, 0x65, 0x2b, 0x40},
	/* User Plane w/ZUC enc. UL SHORT SN */
	(uint8_t[]){0x8b, 0xcb, 0x75, 0x03, 0xd5, 0xed, 0xea, 0x73, 0x39, 0xf5,
		    0x07, 0x03, 0x04, 0x51, 0xc9, 0x5e},
	/* User Plane w/ZUC enc. DL SHORT SN */
	(uint8_t[]){0x8b, 0xe9, 0xd2, 0x49, 0x7f, 0xfd, 0x98, 0x9f, 0xc4, 0x6a,
		    0xcb, 0xe6, 0x4e, 0x21, 0x33, 0xd2},
	/* User Plane w/ZUC enc. UL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0x01, 0x0a, 0xba, 0x79, 0xf8, 0xe5, 0x9f, 0x22,
		    0x37, 0xab, 0x5c, 0x7e, 0xad, 0xd6, 0x6b},
	/* User Plane w/ZUC enc. DL 15 BIT SN */
	(uint8_t[]){0x8b, 0x26, 0xa3, 0x1a, 0x1e, 0x22, 0xf7, 0x17, 0x8a, 0xb5,
		    0x59, 0xd8, 0x2b, 0x13, 0xdd, 0x12, 0x4e},
};

#endif /* SECURITY_PDCP_TEST_VECTOR_H_ */
