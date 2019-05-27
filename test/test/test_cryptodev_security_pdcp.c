/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc.
 * Copyright 2018-2019 NXP
 */

#include <time.h>

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pause.h>
#include <rte_bus_vdev.h>
#include <rte_byteorder.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_security.h>

#include <rte_lcore.h>
#include "test.h"
#include "test_cryptodev_security_pdcp_test_func.h"

#define PDCP_CPLANE_OFFSET	0
#define CPLANE_NULL_ENC_OFFSET 0
#define CPLANE_SNOW_ENC_OFFSET 8
#define CPLANE_AES_ENC_OFFSET 16
#define CPLANE_ZUC_ENC_OFFSET 24
#define CPLANE_NULL_AUTH_OFFSET 0
#define CPLANE_SNOW_AUTH_OFFSET 2
#define CPLANE_AES_AUTH_OFFSET 4
#define CPLANE_ZUC_AUTH_OFFSET 6

#define PDCP_CPLANE_LONG_SN_OFFSET	32

#define PDCP_UPLANE_OFFSET	64
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

#define PDCP_UPLANE_12BIT_OFFSET	88
#define UPLANE_NULL_ENC_OFFSET 0
#define UPLANE_SNOW_ENC_OFFSET 8
#define UPLANE_AES_ENC_OFFSET 16
#define UPLANE_ZUC_ENC_OFFSET 24
#define UPLANE_NULL_AUTH_OFFSET 0
#define UPLANE_SNOW_AUTH_OFFSET 2
#define UPLANE_AES_AUTH_OFFSET 4
#define UPLANE_ZUC_AUTH_OFFSET 6

__rte_unused static int cplane_null_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

/*************** For C-plane 12-bit ******************/

__rte_unused static int cplane_null_null_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_null_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_snow_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_snow_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_aes_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_aes_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_zuc_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_zuc_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_null_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_null_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_snow_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_snow_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_aes_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_aes_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_zuc_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_snow_zuc_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_null_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_null_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_snow_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_snow_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_aes_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_aes_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_zuc_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_aes_zuc_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_null_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_null_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_snow_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_snow_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_aes_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_aes_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_zuc_long_sn_ul_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_zuc_zuc_long_sn_dl_encap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_encap(i);
}

__rte_unused static int cplane_null_null_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_null_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_snow_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_snow_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_aes_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_aes_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_zuc_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_null_zuc_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_NULL_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_null_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_null_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_snow_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_snow_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_aes_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_aes_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_zuc_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_snow_zuc_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_SNOW_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_null_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_null_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_snow_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_snow_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_aes_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_aes_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_zuc_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_aes_zuc_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_AES_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_null_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_null_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_snow_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_snow_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_aes_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_aes_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_zuc_long_sn_ul_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

__rte_unused static int cplane_zuc_zuc_long_sn_dl_decap(void)
{
	int i = PDCP_CPLANE_LONG_SN_OFFSET + CPLANE_ZUC_ENC_OFFSET +
	CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_cplane_decap(i);
}

/*****************************************************/

__rte_unused static int uplane_null_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_snow_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_aes_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_zuc_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap(i);
}

__rte_unused static int uplane_null_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_null_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_null_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_null_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_null_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_null_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_snow_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_aes_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

__rte_unused static int uplane_zuc_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFFSET
		+ DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap(i);
}

/*************** For u-plane 12-bit with integrity ***/

__rte_unused static int uplane_null_null_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_null_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_snow_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_snow_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_aes_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_aes_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_zuc_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_zuc_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_null_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_null_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_snow_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_snow_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_aes_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_aes_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_zuc_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_snow_zuc_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_null_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_null_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_snow_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_snow_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_aes_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_aes_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_zuc_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_aes_zuc_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_null_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_null_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_snow_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_snow_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_aes_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_aes_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_zuc_12bit_ul_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_zuc_zuc_12bit_dl_encap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_encap_with_int(i);
}

__rte_unused static int uplane_null_null_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_null_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_snow_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_snow_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_aes_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_aes_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_zuc_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_null_zuc_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_NULL_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_null_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_null_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_snow_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_snow_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_aes_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_aes_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_zuc_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_snow_zuc_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_SNOW_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_null_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_null_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_snow_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_snow_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_aes_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_aes_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_zuc_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_aes_zuc_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_AES_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_null_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_null_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_snow_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_snow_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_aes_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_aes_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_zuc_12bit_ul_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

__rte_unused static int uplane_zuc_zuc_12bit_dl_decap(void)
{
	int i = PDCP_UPLANE_12BIT_OFFSET + UPLANE_ZUC_ENC_OFFSET +
	UPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	return test_pdcp_proto_uplane_decap_with_int(i);
}

#define TEST_PDCP_COUNT(func) do { \
	if (func == TEST_SUCCESS)  {\
		printf("\t%d)", i++);\
		printf(#func"-PASS\n"); \
	} else {			   \
		printf("\t%d)", i++);\
		printf("+++++ FAILED:" #func"\n"); \
	} \
	n++;   \
} while (0)

int
test_PDCP_PROTO_cplane_encap_all(void)
{
	int i = 0, n = 0;

	TEST_PDCP_COUNT(cplane_null_null_ul_encap());
	TEST_PDCP_COUNT(cplane_null_null_dl_encap());
	TEST_PDCP_COUNT(cplane_null_snow_ul_encap());
	TEST_PDCP_COUNT(cplane_null_snow_dl_encap());
	TEST_PDCP_COUNT(cplane_null_aes_ul_encap());
	TEST_PDCP_COUNT(cplane_null_aes_dl_encap());
	TEST_PDCP_COUNT(cplane_null_zuc_ul_encap());
	TEST_PDCP_COUNT(cplane_null_zuc_dl_encap());
	TEST_PDCP_COUNT(cplane_snow_null_ul_encap());
	TEST_PDCP_COUNT(cplane_snow_null_dl_encap());
	TEST_PDCP_COUNT(cplane_snow_snow_ul_encap());
	TEST_PDCP_COUNT(cplane_snow_snow_dl_encap());
	TEST_PDCP_COUNT(cplane_snow_aes_ul_encap());
	TEST_PDCP_COUNT(cplane_snow_aes_dl_encap());
	TEST_PDCP_COUNT(cplane_snow_zuc_ul_encap());
	TEST_PDCP_COUNT(cplane_snow_zuc_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_null_ul_encap());
	TEST_PDCP_COUNT(cplane_aes_null_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_snow_ul_encap());
	TEST_PDCP_COUNT(cplane_aes_snow_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_aes_ul_encap());
	TEST_PDCP_COUNT(cplane_aes_aes_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_zuc_ul_encap());
	TEST_PDCP_COUNT(cplane_aes_zuc_dl_encap());
	TEST_PDCP_COUNT(cplane_zuc_null_ul_encap());
	TEST_PDCP_COUNT(cplane_zuc_null_dl_encap());
	TEST_PDCP_COUNT(cplane_zuc_snow_ul_encap());
	TEST_PDCP_COUNT(cplane_zuc_snow_dl_encap());
	TEST_PDCP_COUNT(cplane_zuc_aes_ul_encap());
	TEST_PDCP_COUNT(cplane_zuc_aes_dl_encap());
	TEST_PDCP_COUNT(cplane_zuc_zuc_ul_encap());
	TEST_PDCP_COUNT(cplane_zuc_zuc_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_snow_long_sn_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_aes_long_sn_dl_encap());
	TEST_PDCP_COUNT(cplane_aes_zuc_long_sn_dl_encap());
	if (n - i)
		printf("## %s: %d passed out of %d\n", __func__, i, n);

	return n - i;
};

int
test_PDCP_PROTO_cplane_decap_all(void)
{
	int i = 0, n = 0;

	TEST_PDCP_COUNT(cplane_null_null_ul_decap());
	TEST_PDCP_COUNT(cplane_null_null_dl_decap());
	TEST_PDCP_COUNT(cplane_null_snow_ul_decap());
	TEST_PDCP_COUNT(cplane_null_snow_dl_decap());
	TEST_PDCP_COUNT(cplane_null_aes_ul_decap());
	TEST_PDCP_COUNT(cplane_null_aes_dl_decap());
	TEST_PDCP_COUNT(cplane_null_zuc_ul_decap());
	TEST_PDCP_COUNT(cplane_null_zuc_dl_decap());
	TEST_PDCP_COUNT(cplane_snow_null_ul_decap());
	TEST_PDCP_COUNT(cplane_snow_null_dl_decap());
	TEST_PDCP_COUNT(cplane_snow_snow_ul_decap());
	TEST_PDCP_COUNT(cplane_snow_snow_dl_decap());
	TEST_PDCP_COUNT(cplane_snow_aes_ul_decap());
	TEST_PDCP_COUNT(cplane_snow_aes_dl_decap());
	TEST_PDCP_COUNT(cplane_snow_zuc_ul_decap());
	TEST_PDCP_COUNT(cplane_snow_zuc_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_null_ul_decap());
	TEST_PDCP_COUNT(cplane_aes_null_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_snow_ul_decap());
	TEST_PDCP_COUNT(cplane_aes_snow_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_aes_ul_decap());
	TEST_PDCP_COUNT(cplane_aes_aes_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_zuc_ul_decap());
	TEST_PDCP_COUNT(cplane_aes_zuc_dl_decap());
	TEST_PDCP_COUNT(cplane_zuc_null_ul_decap());
	TEST_PDCP_COUNT(cplane_zuc_null_dl_decap());
	TEST_PDCP_COUNT(cplane_zuc_snow_ul_decap());
	TEST_PDCP_COUNT(cplane_zuc_snow_dl_decap());
	TEST_PDCP_COUNT(cplane_zuc_aes_ul_decap());
	TEST_PDCP_COUNT(cplane_zuc_aes_dl_decap());
	TEST_PDCP_COUNT(cplane_zuc_zuc_ul_decap());
	TEST_PDCP_COUNT(cplane_zuc_zuc_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_snow_long_sn_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_aes_long_sn_dl_decap());
	TEST_PDCP_COUNT(cplane_aes_zuc_long_sn_dl_decap());
	if (n - i)
		printf("## %s: %d passed out of %d\n", __func__, i, n);

	return n - i;
};

int
test_PDCP_PROTO_uplane_encap_all(void)
{
	int i = 0, n = 0;

	TEST_PDCP_COUNT(uplane_null_ul_12bit_encap());
	TEST_PDCP_COUNT(uplane_null_dl_12bit_encap());
	TEST_PDCP_COUNT(uplane_null_ul_7bit_encap());
	TEST_PDCP_COUNT(uplane_null_dl_7bit_encap());
	TEST_PDCP_COUNT(uplane_null_ul_15bit_encap());
	TEST_PDCP_COUNT(uplane_null_dl_15bit_encap());
	TEST_PDCP_COUNT(uplane_snow_ul_12bit_encap());
	TEST_PDCP_COUNT(uplane_snow_dl_12bit_encap());
	TEST_PDCP_COUNT(uplane_snow_ul_7bit_encap());
	TEST_PDCP_COUNT(uplane_snow_dl_7bit_encap());
	TEST_PDCP_COUNT(uplane_snow_ul_15bit_encap());
	TEST_PDCP_COUNT(uplane_snow_dl_15bit_encap());
	TEST_PDCP_COUNT(uplane_aes_ul_12bit_encap());
	TEST_PDCP_COUNT(uplane_aes_dl_12bit_encap());
	TEST_PDCP_COUNT(uplane_aes_ul_7bit_encap());
	TEST_PDCP_COUNT(uplane_aes_dl_7bit_encap());
	TEST_PDCP_COUNT(uplane_aes_ul_15bit_encap());
	TEST_PDCP_COUNT(uplane_aes_dl_15bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_ul_12bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_dl_12bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_ul_7bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_dl_7bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_ul_15bit_encap());
	TEST_PDCP_COUNT(uplane_zuc_dl_15bit_encap());
	/* For 12-bit SN with integrity */
	TEST_PDCP_COUNT(uplane_null_null_12bit_ul_encap());
	TEST_PDCP_COUNT(uplane_null_null_12bit_dl_encap());
	TEST_PDCP_COUNT(uplane_aes_snow_12bit_dl_encap());
	TEST_PDCP_COUNT(uplane_aes_aes_12bit_dl_encap());
	TEST_PDCP_COUNT(uplane_aes_zuc_12bit_dl_encap());
	if (n - i)
		printf("## %s: %d passed out of %d\n", __func__, i, n);

	return n - i;
};

int
test_PDCP_PROTO_uplane_decap_all(void)
{
	int i = 0, n = 0;

	TEST_PDCP_COUNT(uplane_null_ul_12bit_decap());
	TEST_PDCP_COUNT(uplane_null_dl_12bit_decap());
	TEST_PDCP_COUNT(uplane_null_ul_7bit_decap());
	TEST_PDCP_COUNT(uplane_null_dl_7bit_decap());
	TEST_PDCP_COUNT(uplane_null_ul_15bit_decap());
	TEST_PDCP_COUNT(uplane_null_dl_15bit_decap());
	TEST_PDCP_COUNT(uplane_snow_ul_12bit_decap());
	TEST_PDCP_COUNT(uplane_snow_dl_12bit_decap());
	TEST_PDCP_COUNT(uplane_snow_ul_7bit_decap());
	TEST_PDCP_COUNT(uplane_snow_dl_7bit_decap());
	TEST_PDCP_COUNT(uplane_snow_ul_15bit_decap());
	TEST_PDCP_COUNT(uplane_snow_dl_15bit_decap());
	TEST_PDCP_COUNT(uplane_aes_ul_12bit_decap());
	TEST_PDCP_COUNT(uplane_aes_dl_12bit_decap());
	TEST_PDCP_COUNT(uplane_aes_ul_7bit_decap());
	TEST_PDCP_COUNT(uplane_aes_dl_7bit_decap());
	TEST_PDCP_COUNT(uplane_aes_ul_15bit_decap());
	TEST_PDCP_COUNT(uplane_aes_dl_15bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_ul_12bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_dl_12bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_ul_7bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_dl_7bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_ul_15bit_decap());
	TEST_PDCP_COUNT(uplane_zuc_dl_15bit_decap());

	/* u-plane 12-bit with integrity */
	TEST_PDCP_COUNT(uplane_null_null_12bit_ul_decap());
	TEST_PDCP_COUNT(uplane_null_null_12bit_dl_decap());
	TEST_PDCP_COUNT(uplane_aes_snow_12bit_dl_decap());
	TEST_PDCP_COUNT(uplane_aes_aes_12bit_dl_decap());
	TEST_PDCP_COUNT(uplane_aes_zuc_12bit_dl_decap());
	if (n - i)
		printf("## %s: %d passed out of %d\n", __func__, i, n);

	return n - i;
};
