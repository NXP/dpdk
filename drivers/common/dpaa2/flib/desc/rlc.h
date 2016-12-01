/*
 * Copyright 2014 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_RLC_H__
#define __DESC_RLC_H__

#include "flib/rta.h"
#include "common.h"
#include "pdcp.h"

/**
 * DOC: WCDMA RLC Shared Descriptor Constructors
 *
 * Shared descriptors for WCDMA RLC protocol.
 */

/*
 * RLC Protocol Data Blocks
 */
#define RLC_PDB_OPT_SNS_SHIFT	1
#define RLC_PDB_OPT_SNS_AM	(0 << RLC_PDB_OPT_SNS_SHIFT)
#define RLC_PDB_OPT_SNS_UM	(1 << RLC_PDB_OPT_SNS_SHIFT)

#define RLC_PDB_OPT_4B_SHIFT	0
#define RLC_PDB_OPT_4B_SHIFT_EN	(1 << RLC_PDB_OPT_4B_SHIFT)

#define RLC_PDB_HFN_SHIFT_UM	7
#define RLC_PDB_HFN_SHIFT_AM	12

#define RLC_PDB_BEARER_SHIFT	27
#define RLC_PDB_DIR_SHIFT	26

/**
 * enum rlc_mode - WCDMA RLC mode selector
 * @RLC_UNACKED_MODE: unacknowledged mode
 * @RLC_ACKED_MODE: acknowledged mode
 */
enum rlc_mode {
	RLC_UNACKED_MODE = 7,
	RLC_ACKED_MODE = 12
};

/**
 * enum rlc_dir - WCDMA RLC direction selector
 * @RLC_DIR_UPLINK: uplink direction
 * @RLC_DIR_DOWNLINK: downlink direction
 */
enum rlc_dir {
	RLC_DIR_UPLINK,
	RLC_DIR_DOWNLINK
};

/**
 * enum cipher_type_rlc - Type selectors for cipher types in RLC protocol OP
 *                        instructions.
 * @RLC_CIPHER_TYPE_NULL: NULL
 * @RLC_CIPHER_TYPE_KASUMI: Kasumi
 * @RLC_CIPHER_TYPE_SNOW: SNOW F8
 * @RLC_CIPHER_TYPE_INVALID: invalid option
 */
enum cipher_type_rlc {
	RLC_CIPHER_TYPE_NULL,
	RLC_CIPHER_TYPE_KASUMI,
	RLC_CIPHER_TYPE_SNOW,
	RLC_CIPHER_TYPE_INVALID
};

struct rlc_pdb {
	uint32_t opt_res;	/* RLC options bitfield:
				 * - bit 30: 1 = unacknowledged mode
				 *           0 = acknowldeged mode
				 * - bit 31: 1 = shift output data
				 *               by 4 bits (pad with 0)
				 */
	uint32_t hfn_res;	/* HyperFrame number,(27 or 20 bits), left
				   aligned & right-padded with zeros. */
	uint32_t bearer_dir_res;/* Bearer(5 bits), packet direction (1 bit),
				 * left aligned & right-padded with zeros. */
	uint32_t hfn_thr_res;	/* HyperFrame number threshold (27 or 20 bits),
				   left aligned & right-padded with zeros. */
};

/*
 * RLC internal PDB type
 */
#define RLC_PDB_TYPE_FULL_PDB PDCP_PDB_TYPE_FULL_PDB

/**
 * cnstr_shdsc_rlc_encap - Function for creating a WCDMA RLC encapsulation
 *                         descriptor.
 * @descbuf: pointer to buffer for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @mode: indicates if ACKed or non-ACKed mode is used
 * @hfn: starting Hyper Frame Number to be used together with the SN from the
 *       RLC frames.
 * @bearer: radio bearer ID
 * @direction: the direction of the RLC PDU (UL/DL)
 * @hfn_threshold: HFN value that once reached triggers a warning from SEC that
 *                 keys should be renegotiated at the earliest convenience.
 * @cipherdata: pointer to block cipher transform definitions
 *              Valid algorithm values are those from cipher_type_rlc enum.
 *
 * Return: size of descriptor written in words or negative number on error.
 *         Once the function returns, the value of this parameter can be used
 *         for reclaiming the space that wasn't used for the descriptor.
 *
 * Note: descbuf must be large enough to contain a full 256 byte long
 * descriptor; after the function returns, by subtracting the actual number of
 * bytes used, the user can reuse the remaining buffer space for other purposes.
 */
static inline int cnstr_shdsc_rlc_encap(uint32_t *descbuf,
		bool ps,
		enum rlc_mode mode,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata)
{
	struct program prg;
	struct program *p = &prg;
	struct rlc_pdb pdb;
	int err;
	LABEL(pdb_end);
	LABEL(keyjmp);
	REFERENCE(phdr);
	REFERENCE(pkeyjmp);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);

	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);

	memset(&pdb, 0, sizeof(struct rlc_pdb));

	/*
	 * Read options from user:  depending on sequence number length,
	 * the HFN and HFN threshold have different lengths.
	 */
	switch (mode) {
	case RLC_UNACKED_MODE:
		pdb.opt_res = RLC_PDB_OPT_SNS_UM;
		pdb.hfn_res = hfn << RLC_PDB_HFN_SHIFT_UM;
		pdb.hfn_thr_res = hfn_threshold << RLC_PDB_HFN_SHIFT_UM;
		break;

	case RLC_ACKED_MODE:
		pdb.opt_res = RLC_PDB_OPT_SNS_AM;
		pdb.hfn_res = hfn << RLC_PDB_HFN_SHIFT_AM;
		pdb.hfn_thr_res = hfn_threshold << RLC_PDB_HFN_SHIFT_AM;
		break;

	default:
		pr_debug("Invalid RLC mode setting in PDB\n");
		return -EINVAL;
	}

	pdb.bearer_dir_res = (uint32_t)
				((bearer << RLC_PDB_BEARER_SHIFT) |
				 (direction << RLC_PDB_DIR_SHIFT));

	/* copy PDB in descriptor*/
	COPY_DATA(p, (uint8_t *)&pdb, sizeof(struct rlc_pdb));

	SET_LABEL(p, pdb_end);

	err = insert_hfn_ov_op(p, mode, RLC_PDB_TYPE_FULL_PDB, 0);
	if (err)
		return err;

	switch (mode) {
	case RLC_UNACKED_MODE:
	case RLC_ACKED_MODE:
		switch (cipherdata->algtype) {
		case RLC_CIPHER_TYPE_KASUMI:
			pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
			/* Insert Cipher Key */
			KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
			    cipherdata->keylen, INLINE_KEY(cipherdata));
			SET_LABEL(p, keyjmp);

			PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL,
				 OP_PCLID_3G_RLC_PDU,
				 (uint16_t)cipherdata->algtype);

			PATCH_JUMP(p, pkeyjmp, keyjmp);

			break;

		case RLC_CIPHER_TYPE_SNOW:
			/*
			 * The SNOW-f8 CHA generates the sX and rX  context
			 * state variables, and overwrites the original  key in
			 * the key register even if using initfinal. This is
			 * an expected behavior and the resolution is to reload
			 * the KEY register
			 */

			/* Insert Cipher Key */
			KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
			    cipherdata->keylen, INLINE_KEY(cipherdata));

			PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL,
				 OP_PCLID_3G_RLC_PDU,
				 (uint16_t)cipherdata->algtype);

			break;

		case RLC_CIPHER_TYPE_NULL:
			insert_copy_frame_op(p,
					     cipherdata,
					     OP_TYPE_ENCAP_PROTOCOL);
			break;
		default:
			pr_debug("%s: Invalid encrypt algorithm selected: %d\n",
				 "cnstr_shdsc_rlc_encap",
				 cipherdata->algtype);
			return -EINVAL;
		}
		break;

	default:
		break;
	}

	PATCH_HDR(p, phdr, pdb_end);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_rlc_decap - Function for creating a WCDMA RLC decapsulation
 *                         descriptor.
 * @descbuf: pointer to buffer for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @mode: indicates if ACKed or non-ACKed mode is used
 * @hfn: starting Hyper Frame Number to be used together with the SN from the
 *       RLC frames.
 * @bearer: radio bearer ID
 * @direction: the direction of the RLC PDU (UL/DL)
 * @hfn_threshold: HFN value that once reached triggers a warning from SEC that
 *                 keys should be renegotiated at the earliest convenience.
 * @cipherdata: pointer to block cipher transform definitions
 *              Valid algorithm values are those from cipher_type_rlc enum.
 *
 * Return: size of descriptor written in words or negative number on error.
 *         Once the function returns, the value of this parameter can be used
 *         for reclaiming the space that wasn't used for the descriptor.
 *
 * Note: descbuf must be large enough to contain a full 256 byte long
 * descriptor; after the function returns, by subtracting the actual number of
 * bytes used, the user can reuse the remaining buffer space for other purposes.
 */
static inline int cnstr_shdsc_rlc_decap(uint32_t *descbuf,
		bool ps,
		enum rlc_mode mode,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata)
{
	struct program prg;
	struct program *p = &prg;
	struct rlc_pdb pdb;
	int err;
	LABEL(pdb_end);
	LABEL(keyjmp);
	REFERENCE(phdr);
	REFERENCE(pkeyjmp);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);

	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);

	memset(&pdb, 0, sizeof(struct rlc_pdb));

	/*
	 * Read options from user:  depending on sequence number length,
	 * the HFN and HFN threshold have different lengths.
	 */
	switch (mode) {
	case RLC_UNACKED_MODE:
		pdb.opt_res = RLC_PDB_OPT_SNS_UM;
		pdb.hfn_res = hfn << RLC_PDB_HFN_SHIFT_UM;
		pdb.hfn_thr_res = hfn_threshold << RLC_PDB_HFN_SHIFT_UM;
		break;

	case RLC_ACKED_MODE:
		pdb.opt_res = RLC_PDB_OPT_SNS_AM;
		pdb.hfn_res = hfn << RLC_PDB_HFN_SHIFT_AM;
		pdb.hfn_thr_res = hfn_threshold << RLC_PDB_HFN_SHIFT_AM;
		break;

	default:
		pr_debug("Invalid RLC mode setting in PDB\n");
		return -EINVAL;
	}

	pdb.bearer_dir_res = (uint32_t)
				((bearer << RLC_PDB_BEARER_SHIFT) |
				 (direction << RLC_PDB_DIR_SHIFT));

	/* copy PDB in descriptor*/
	COPY_DATA(p, (uint8_t *)&pdb, sizeof(struct rlc_pdb));

	SET_LABEL(p, pdb_end);

	err = insert_hfn_ov_op(p, mode, RLC_PDB_TYPE_FULL_PDB, 0);
	if (err)
		return err;

	switch (mode) {
	case RLC_UNACKED_MODE:
	case RLC_ACKED_MODE:
		switch (cipherdata->algtype) {
		case RLC_CIPHER_TYPE_KASUMI:
			pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
			/* Insert Cipher Key */
			KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
			    cipherdata->keylen, INLINE_KEY(cipherdata));
			SET_LABEL(p, keyjmp);

			PROTOCOL(p, OP_TYPE_DECAP_PROTOCOL,
				 OP_PCLID_3G_RLC_PDU,
				 (uint16_t)cipherdata->algtype);

			PATCH_JUMP(p, pkeyjmp, keyjmp);
			break;

		case RLC_CIPHER_TYPE_SNOW:
			/*
			 * The SNOW-f8 CHA generates the sX and rX  context
			 * state variables, and overwrites the original  key in
			 * the key register even if using initfinal. This is
			 * an expected behavior and the resolution is to reload
			 * the KEY register
			 */

			/* Insert Cipher Key */
			KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
			    cipherdata->keylen, INLINE_KEY(cipherdata));
			SET_LABEL(p, keyjmp);

			PROTOCOL(p, OP_TYPE_DECAP_PROTOCOL,
				 OP_PCLID_3G_RLC_PDU,
				 (uint16_t)cipherdata->algtype);

			break;

		case RLC_CIPHER_TYPE_NULL:
			insert_copy_frame_op(p,
					     cipherdata,
					     OP_TYPE_ENCAP_PROTOCOL);
			break;

		default:
			pr_debug("%s: Invalid encrypt algorithm selected: %d\n",
				 "cnstr_shdsc_rlc_decap",
				 cipherdata->algtype);
			return -EINVAL;
		}
		break;

	default:
		break;
	}

	PATCH_HDR(p, phdr, pdb_end);
	return PROGRAM_FINALIZE(p);
}

#endif  /* __DESC_RLC_H__ */
