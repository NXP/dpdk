/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_WIMAX_H__
#define __DESC_WIMAX_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: WiMAX Shared Descriptor Constructors
 *
 * Shared descriptors for WiMAX (802.16) protocol.
 */

/**
 * CRC_8_ATM_POLY - This CRC Polynomial is used for the GMH Header Check
 *                  Sequence.
 */
#define CRC_8_ATM_POLY			0x07000000

/**
 * WIMAX_GMH_EC_MASK - This mask is used in the WiMAX encapsulation /
 *                     decapsulation descriptor for setting / clearing the
 *                     Encryption Control bit from the Generic Mac Header.
 */
#define WIMAX_GMH_EC_MASK		0x4000000000000000ull

/**
 * WIMAX_ICV_LEN - The length of the Integrity Check Value for WiMAX
 */
#define WIMAX_ICV_LEN			0x0000000000000008ull

/**
 * WIMAX_FCS_LEN - The length of the Frame Check Sequence for WiMAX
 */
#define WIMAX_FCS_LEN			0x00000000000000004ull

/**
 * WIMAX_PN_LEN - The length of the Packet Number for WiMAX
 */
#define WIMAX_PN_LEN			0x0000000000000004ull

/**
 * WIMAX_PDBOPTS_FCS - Options Byte with FCS enabled
 */
#define WIMAX_PDBOPTS_FCS		0x01

/**
 * WIMAX_PDBOPTS_AR - Options Byte with AR enabled
 */
#define WIMAX_PDBOPTS_AR		0x40

/*
 * IEEE 802.16 WiMAX Protocol Data Block
 */

#define WIMAX_PDB_B0            0x19    /* Initial Block B0 Flags */
#define WIMAX_PDB_CTR           0x01    /* Counter Block Flags */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct wimax_encap_pdb {
	union {
		struct {
			uint8_t rsvd[3];	/* Reserved Bits */
			uint8_t options;	/* Options Byte */
		};
		uint32_t word1;
	};
	uint32_t nonce;				/* Nonce Constant */
	union {
		struct {
			uint8_t b0_flags;	/* Initial Block B0 */
			uint8_t ctr_flags;	/* Counter Block Flags */
			uint16_t ctr_init_count;
		};
		uint32_t word2;
	};
	/* begin DECO writeback region */
	uint32_t pn;				/* Packet Number */
	/* end DECO writeback region */
};
#else
struct wimax_encap_pdb {
	union {
		struct {
			uint8_t options;	/* Options Byte */
			uint8_t rsvd[3];	/* Reserved Bits */
		};
		uint32_t word1;
	};
	uint32_t nonce;				/* Nonce Constant */
	union {
		struct {
			uint16_t ctr_init_count;
			uint8_t ctr_flags;	/* Counter Block Flags */
			uint8_t b0_flags;	/* Initial Block B0 */
		};
		uint32_t word2;
	};
	/* begin DECO writeback region */
	uint32_t pn;				/* Packet Number */
	/* end DECO writeback region */
};
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct wimax_decap_pdb {
	union {
		struct {
			uint8_t rsvd[3];	/* Reserved Bits */
			uint8_t options;	/* Options Byte */
		};
		uint32_t word1;
	};
	uint32_t nonce;				/* Nonce Constant */
	union {
		struct {
			uint8_t b0_flags;	/* Initial Block B0 */
			uint8_t ctr_flags;	/* Counter Block Flags */
			uint16_t ctr_init_count;
		};
		uint32_t word2;
	};
	/* begin DECO writeback region */
	uint32_t pn;				/* Packet Number */
	union {
		struct {
			uint8_t rsvd1[2];	/* Reserved Bits */
			uint16_t antireplay_len;
		};
		uint32_t word3;
	};
	uint32_t antireplay_scorecard_hi;
	uint32_t antireplay_scorecard_lo;
	/** end DECO writeback region */
};
#else
struct wimax_decap_pdb {
	union {
		struct {
			uint8_t options;	/* Options Byte */
			uint8_t rsvd[3];	/* Reserved Bits */
		};
		uint32_t word1;
	};
	uint32_t nonce;				/* Nonce Constant */
	union {
		struct {
			uint16_t ctr_init_count;
			uint8_t ctr_flags;	/* Counter Block Flags */
			uint8_t b0_flags;	/* Initial Block B0 */
		};
		uint32_t word2;
	};
	/* begin DECO writeback region */
	uint32_t pn;				/* Packet Number */
	union {
		struct {
			uint16_t antireplay_len;
			uint8_t rsvd1[2];	/* Reserved Bits */
		};
		uint32_t word3;
	};
	uint32_t antireplay_scorecard_hi;
	uint32_t antireplay_scorecard_lo;
	/** end DECO writeback region */
};
#endif

static inline void __rta_copy_wimax_encap_pdb(struct program *p,
					      struct wimax_encap_pdb *encap_pdb)
{
	__rta_out32(p, encap_pdb->word1);
	__rta_out32(p, encap_pdb->nonce);
	__rta_out32(p, encap_pdb->word2);
	__rta_out32(p, encap_pdb->pn);
}

static inline void __rta_copy_wimax_decap_pdb(struct program *p,
					      struct wimax_decap_pdb *decap_pdb)
{
	__rta_out32(p, decap_pdb->word1);
	__rta_out32(p, decap_pdb->nonce);
	__rta_out32(p, decap_pdb->word2);
	__rta_out32(p, decap_pdb->pn);
	__rta_out32(p, decap_pdb->word3);
	__rta_out32(p, decap_pdb->antireplay_scorecard_hi);
	__rta_out32(p, decap_pdb->antireplay_scorecard_lo);
}

/**
 * cnstr_shdsc_wimax_encap_era5 - WiMAX(802.16) encapsulation descriptor for
 *                                platforms with SEC ERA >= 5.
 * @descbuf: pointer to descriptor-under-construction buffer
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb_opts: PDB Options Byte
 * @pn: PDB Packet Number
 * @cipherdata: pointer to block cipher transform definitions
 * @protinfo: protocol information: OP_PCL_WIMAX_OFDM/OFDMA
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * This descriptor addreses the prefetch problem when modifying the header of
 * the input frame by invalidating the prefetch mechanism.
 *
 * For performance reasons (due to the long read latencies), the JQ will
 * prefetch the input frame if a job cannot go immediately into a DECO. As a
 * result, the rewind is rewinding into the prefetch buffer, not into memory.
 * Therefore, in those cases where prefetch is done, an unaware descriptor would
 * update the memory but read from the prefetched buffer and, as a result, it
 * would not get the updated header.
 *
 * This descriptor invalidates the prefetch data and reads the updated header
 * from memory. The descriptor reads enough data to read to the end of the
 * prefetched data, dumps that data, rewinds the input frame and just starts
 * reading from the beginning again.
 */
static inline int cnstr_shdsc_wimax_encap_era5(uint32_t *descbuf, bool swap,
					       uint8_t pdb_opts, uint32_t pn,
					       uint16_t protinfo,
					       struct alginfo *cipherdata)
{
	struct wimax_encap_pdb pdb;
	struct program prg;
	struct program *p = &prg;

	LABEL(hdr);
	LABEL(out_len);
	LABEL(keyjump);
	LABEL(local_offset);
	LABEL(mathjump);
	LABEL(seqout_ptr);
	LABEL(swapped_seqout_ptr);
	REFERENCE(phdr);
	REFERENCE(move_seqin_ptr);
	REFERENCE(move_seqout_ptr);
	REFERENCE(pmathjump);
	REFERENCE(pkeyjump);
	REFERENCE(seqout_ptr_jump1);
	REFERENCE(seqout_ptr_jump2);
	REFERENCE(write_seqout_ptr);
	REFERENCE(write_swapped_seqout_ptr);

	memset(&pdb, 0, sizeof(struct wimax_encap_pdb));
	pdb.options = pdb_opts;
	pdb.pn = pn;
	pdb.b0_flags = WIMAX_PDB_B0;
	pdb.ctr_flags = WIMAX_PDB_CTR;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, hdr, 0);
	__rta_copy_wimax_encap_pdb(p, &pdb);
	SET_LABEL(p, hdr);

	/*
	 * Figure out how much data has been prefetched.
	 * The prefetch buffer will have 128 bytes (or less, if the input frame
	 * is less than 128 bytes)
	 */
	MATHB(p, MATH0, ADD, 128, VSEQINSZ, 4, IMMED2);
	MATHB(p, SEQINSZ, SUB, VSEQINSZ, NONE, 4, 0);
	/* If not negative, then input is bigger than 128 bytes */
	pmathjump = JUMP(p, mathjump, LOCAL_JUMP, ALL_FALSE, MATH_N);
	MATHB(p, SEQINSZ, ADD, ZERO, VSEQINSZ, 4, 0);
	SET_LABEL(p, mathjump);
	MATHB(p, VSEQINSZ, ADD, ZERO, MATH3, 4, 0);

	/* Save SEQOUTPTR, Output Pointer and Output Length. */
	move_seqout_ptr = MOVE(p, DESCBUF, 0, OFIFO, 0, 16, WAITCOMP | IMMED);
/*
 * TODO: RTA currently doesn't support creating a LOAD command
 * with another command as IMM. In this particular case "0xa00000fa" is a JUMP
 * command used for jumping back after rewinding and reseting the sequence
 * output pointer and length.
 * To be changed when proper support is added in RTA.
 */
	LOAD(p, 0xa00000fa, OFIFO, 0, 4, IMMED);

	/* Swap SEQOUTPTR to the SEQINPTR. */
	move_seqin_ptr = MOVE(p, DESCBUF, 0, MATH0, 0, 20, WAITCOMP | IMMED);
	MATHB(p, MATH0, OR, CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR, MATH0, 8,
	      IFB | IMMED2);
/*
 * TODO: RTA currently doesn't support creating a LOAD command
 * with another command as IMM. In this particular case "0xa00000dc" is a JUMP
 * command used for jumping back after starting the new output sequence using
 * the pointer and length used when the current input sequence was defined.
 * To be changed when proper support is added in RTA.
 */
	LOAD(p, 0xa00000dc, MATH2, 4, 4, IMMED);
	write_swapped_seqout_ptr = MOVE(p, MATH0, 0, DESCBUF, 0, 24,
					WAITCOMP | IMMED);
	seqout_ptr_jump1 = JUMP(p, swapped_seqout_ptr, LOCAL_JUMP, ALL_TRUE, 0);
	write_seqout_ptr = MOVE(p, OFIFO, 0, DESCBUF, 0, 20, WAITCOMP | IMMED);

	/*
	 * Read exactly the amount of data that would have been prefetched if,
	 * in fact, the data was prefetched. This will cause DECO to flush
	 * the prefetched data
	 */
	SEQFIFOLOAD(p, IFIFO, 0, VLF);
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);
	/* Get header into Math 0 */
	MOVE(p, IFIFOABD, 0, MATH0, 4, 8, WAITCOMP | IMMED);

	/* Clear input data FIFO and Class 1,2 registers*/
	LOAD(p, LDST_SRCDST_WORD_CLRW | CLRW_CLR_C2MODE | CLRW_CLR_C2DATAS |
	     CLRW_CLR_C2CTX | CLRW_CLR_C2KEY | CLRW_RESET_CLS2_CHA |
	     CLRW_RESET_CLS1_CHA | CLRW_RESET_IFIFO_DFIFO, CLRW, 0, 4, IMMED);

	/*
	 * Set Encryption Control bit.
	 * Header is loaded at offset four in Math 0 register.
	 * Use the 32 bit value of the WIMAX_GMH_EC_MASK macro.
	 */
	MATHB(p, MATH0, OR, upper_32_bits(WIMAX_GMH_EC_MASK), MATH0, 4, IMMED2);

	/*
	 * Update Generic Mac Header Length field.
	 * The left shift is used in order to update the GMH LEN field
	 * and nothing else.
	 */
	if (pdb_opts & WIMAX_PDBOPTS_FCS)
		MATHB(p, MATH0, ADD, (WIMAX_PN_LEN + WIMAX_ICV_LEN +
				   WIMAX_FCS_LEN) << 8,
		      MATH0, 4, IMMED2);
	else
		MATHB(p, MATH0, ADD, (WIMAX_PN_LEN + WIMAX_ICV_LEN) << 8, MATH0,
		      4, IMMED2);

	/*
	 * Compute the CRC-8-ATM value for the first five bytes
	 * of the header and insert the result into the sixth
	 * MATH0 byte field.
	 */
	KEY(p, KEY2, 0, CRC_8_ATM_POLY, 2, IMMED);
	ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
		      OP_ALG_AAI_CUST_POLY | OP_ALG_AAI_DIS, OP_ALG_AS_UPDATE,
		      ICV_CHECK_DISABLE, DIR_ENC);
	MOVE(p, MATH0, 4, IFIFOAB2, 0, 5, LAST1 | IMMED);
	MOVE(p, CONTEXT2, 0, MATH2, 0, 4, WAITCOMP | IMMED);
	MOVE(p, MATH2, 0, MATH1, 1, 1, WAITCOMP | IMMED);
	SEQSTORE(p, MATH0, 4, 8, 0);
	LOAD(p, LDST_SRCDST_WORD_CLRW | CLRW_CLR_C2MODE | CLRW_CLR_C2DATAS |
	     CLRW_CLR_C2CTX | CLRW_CLR_C2KEY | CLRW_RESET_CLS2_CHA,
	     CLRW, 0, 4, IMMED);
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);
	SEQINPTR(p, 0, 0, RTO);

	/* Add what was removed */
	MATHB(p, SEQINSZ, ADD, MATH3, SEQINSZ, 4, 0);

	pkeyjump = JUMP(p, keyjump, LOCAL_JUMP, ALL_TRUE, SHRD);
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjump);
	seqout_ptr_jump2 = JUMP(p, local_offset, LOCAL_JUMP, ALL_TRUE, 0);
	PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_WIMAX, protinfo);
/*
 * TODO: RTA currently doesn't support adding labels in or after Job Descriptor.
 * To be changed when proper support is added in RTA.
 */
	SET_LABEL(p, local_offset);
	local_offset += 1;

	SET_LABEL(p, swapped_seqout_ptr);
	swapped_seqout_ptr += 2;

	SET_LABEL(p, seqout_ptr);
	seqout_ptr += 3;
	SET_LABEL(p, out_len);
	out_len += 6;

	PATCH_HDR(p, phdr, hdr);
	PATCH_JUMP(p, pkeyjump, keyjump);
	PATCH_JUMP(p, pmathjump, mathjump);
	PATCH_JUMP(p, seqout_ptr_jump1, swapped_seqout_ptr);
	PATCH_JUMP(p, seqout_ptr_jump2, local_offset);
	PATCH_MOVE(p, move_seqin_ptr, out_len);
	PATCH_MOVE(p, move_seqout_ptr, seqout_ptr);
	PATCH_MOVE(p, write_seqout_ptr, local_offset);
	PATCH_MOVE(p, write_swapped_seqout_ptr, local_offset);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_wimax_encap - WiMAX(802.16) encapsulation
 * @descbuf: pointer to descriptor-under-construction buffer
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb_opts: PDB Options Byte
 * @pn: PDB Packet Number
 * @cipherdata: pointer to block cipher transform definitions
 * @protinfo: protocol information: OP_PCL_WIMAX_OFDM/OFDMA
 *
 * Note: Descriptor is valid on platforms with support for SEC ERA 4.
 * On platforms with SEC ERA 5 or above, cnstr_shdsc_wimax_encap_era5 is
 * automatically called.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_wimax_encap(uint32_t *descbuf, bool swap,
					  uint8_t pdb_opts, uint32_t pn,
					  uint16_t protinfo,
					  struct alginfo *cipherdata)
{
	struct wimax_encap_pdb pdb;
	struct program prg;
	struct program *p = &prg;

	LABEL(hdr);
	LABEL(out_len);
	LABEL(keyjump);
	LABEL(local_offset);
	LABEL(seqout_ptr);
	LABEL(swapped_seqout_ptr);
	REFERENCE(phdr);
	REFERENCE(move_seqin_ptr);
	REFERENCE(move_seqout_ptr);
	REFERENCE(pkeyjump);
	REFERENCE(seqout_ptr_jump1);
	REFERENCE(seqout_ptr_jump2);
	REFERENCE(write_seqout_ptr);
	REFERENCE(write_swapped_seqout_ptr);

	if (rta_sec_era >= RTA_SEC_ERA_5)
		return cnstr_shdsc_wimax_encap_era5(descbuf, swap, pdb_opts, pn,
						    protinfo, cipherdata);

	memset(&pdb, 0x00, sizeof(struct wimax_encap_pdb));
	pdb.options = pdb_opts;
	pdb.pn = pn;
	pdb.b0_flags = WIMAX_PDB_B0;
	pdb.ctr_flags = WIMAX_PDB_CTR;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	phdr = SHR_HDR(p, SHR_SERIAL, hdr, 0);
	{
		__rta_copy_wimax_encap_pdb(p, &pdb);
		SET_LABEL(p, hdr);
		/* Save SEQOUTPTR, Output Pointer and Output Length. */
		move_seqout_ptr = MOVE(p, DESCBUF, 0, OFIFO, 0, 16,
				       WAITCOMP | IMMED);
/*
 * TODO: RTA currently doesn't support creating a LOAD command
 * with another command as IMM.
 * To be changed when proper support is added in RTA.
 */
		LOAD(p, 0xa00000fa, OFIFO, 0, 4, IMMED);

		/* Swap SEQOUTPTR to the SEQINPTR. */
		move_seqin_ptr = MOVE(p, DESCBUF, 0, MATH0, 0, 20,
				      WAITCOMP | IMMED);
		MATHB(p, MATH0, OR, CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR, MATH0,
		      8, IFB | IMMED2);
/*
 * TODO: RTA currently doesn't support creating a LOAD command
 * with another command as IMM.
 * To be changed when proper support is added in RTA.
 */
		LOAD(p, 0xa00000dd, MATH2, 4, 4, IMMED);
		write_swapped_seqout_ptr = MOVE(p, MATH0, 0, DESCBUF, 0, 24,
						WAITCOMP | IMMED);
		seqout_ptr_jump1 = JUMP(p, swapped_seqout_ptr, LOCAL_JUMP,
					ALL_TRUE, 0);

		write_seqout_ptr = MOVE(p, OFIFO, 0, DESCBUF, 0, 20,
					WAITCOMP | IMMED);

		SEQLOAD(p, MATH0, 0, 8, 0);
		LOAD(p, LDST_SRCDST_WORD_CLRW |
		     CLRW_CLR_C1MODE |
		     CLRW_CLR_C2MODE |
		     CLRW_CLR_C2DATAS |
		     CLRW_CLR_C2CTX |
		     CLRW_CLR_C2KEY |
		     CLRW_RESET_CLS2_CHA |
		     CLRW_RESET_CLS1_CHA,
		     CLRW, 0, 4, IMMED);
		JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);
		/* Set Encryption Control bit */
		MATHB(p, MATH0, OR, WIMAX_GMH_EC_MASK, MATH0, 8, IMMED2);

		/*
		 * Update Generic Mac Header Length field.
		 * The left shift is used in order to update the GMH LEN field
		 * and nothing else.
		 */
		if (pdb_opts & WIMAX_PDBOPTS_FCS)
			MATHB(p, MATH0, ADD, (WIMAX_PN_LEN << 0x28) +
					  (WIMAX_ICV_LEN << 0x28) +
					  (WIMAX_FCS_LEN << 0x28),
			      MATH0, 8, IMMED2);
		else
			MATHB(p, MATH0, ADD, (WIMAX_PN_LEN << 0x28) +
					  (WIMAX_ICV_LEN << 0x28),
			      MATH0, 8, IMMED2);

		/*
		 * Compute the CRC-8-ATM value for the first five bytes
		 * of the header and insert the result into the sixth
		 * MATH0 byte field.
		 */
		KEY(p, KEY2, 0, CRC_8_ATM_POLY, 2, IMMED);
		ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
			      OP_ALG_AAI_CUST_POLY | OP_ALG_AAI_DIS,
			      OP_ALG_AS_UPDATE, ICV_CHECK_DISABLE, DIR_ENC);
		MOVE(p, MATH0, 0, IFIFOAB2, 0, 5, LAST1 | IMMED);
		MOVE(p, CONTEXT2, 0, MATH1, 0, 4, WAITCOMP | IMMED);
		MOVE(p, MATH1, 0, MATH0, 5, 1, WAITCOMP | IMMED);
		SEQSTORE(p, MATH0, 0, 8, 0);

		SEQINPTR(p, 0, 8, RTO);
		LOAD(p, LDST_SRCDST_WORD_CLRW |
		     CLRW_CLR_C1MODE |
		     CLRW_CLR_C2MODE |
		     CLRW_CLR_C2DATAS |
		     CLRW_CLR_C2CTX |
		     CLRW_CLR_C2KEY |
		     CLRW_RESET_CLS2_CHA |
		     CLRW_RESET_CLS1_CHA,
		     CLRW, 0, 4, IMMED);
		pkeyjump = JUMP(p, keyjump, LOCAL_JUMP, ALL_TRUE, SHRD | SELF);
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, INLINE_KEY(cipherdata));
		SET_LABEL(p, keyjump);
		/*
		 * Wait for the updated header to be written into memory, then
		 * rewind and reset the sequence output pointer and length.
		 */
		seqout_ptr_jump2 = JUMP(p, swapped_seqout_ptr, LOCAL_JUMP,
					ALL_TRUE, CALM);
		PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_WIMAX, protinfo);
/*
 * TODO: RTA currently doesn't support adding labels in or after Job Descriptor.
 * To be changed when proper support is added in RTA.
 */
		SET_LABEL(p, local_offset);
		local_offset += 1;

		SET_LABEL(p, swapped_seqout_ptr);
		swapped_seqout_ptr += 2;

		SET_LABEL(p, seqout_ptr);
		seqout_ptr += 3;
		SET_LABEL(p, out_len);
		out_len += 6;
	}
	PATCH_HDR(p, phdr, hdr);
	PATCH_JUMP(p, pkeyjump, keyjump);
	PATCH_JUMP(p, seqout_ptr_jump1, swapped_seqout_ptr);
	PATCH_JUMP(p, seqout_ptr_jump2, local_offset);
	PATCH_MOVE(p, move_seqin_ptr, out_len);
	PATCH_MOVE(p, move_seqout_ptr, seqout_ptr);
	PATCH_MOVE(p, write_seqout_ptr, local_offset);
	PATCH_MOVE(p, write_swapped_seqout_ptr, local_offset);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_wimax_decap - WiMAX(802.16) decapsulation
 * @descbuf: pointer to descriptor-under-construction buffer
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb_opts: PDB Options Byte
 * @pn: PDB Packet Number
 * @cipherdata: pointer to block cipher transform definitions
 * @ar_len: anti-replay window length
 * @protinfo: protocol information: OP_PCL_WIMAX_OFDM/OFDMA
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * Note: Descriptor valid on platforms with support for SEC ERA 4.
 */
static inline int cnstr_shdsc_wimax_decap(uint32_t *descbuf, bool swap,
					  uint8_t pdb_opts, uint32_t pn,
					  uint16_t ar_len, uint16_t protinfo,
					  struct alginfo *cipherdata)
{
	struct wimax_decap_pdb pdb;
	struct program prg;
	struct program *p = &prg;

	LABEL(gmh);
	LABEL(hdr);
	LABEL(keyjump);
	REFERENCE(load_gmh);
	REFERENCE(move_gmh);
	REFERENCE(phdr);
	REFERENCE(pkeyjump);

	memset(&pdb, 0x00, sizeof(struct wimax_decap_pdb));
	pdb.options = pdb_opts;
	pdb.pn = pn;
	pdb.antireplay_len = ar_len;
	pdb.b0_flags = WIMAX_PDB_B0;
	pdb.ctr_flags = WIMAX_PDB_CTR;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	phdr = SHR_HDR(p, SHR_SERIAL, hdr, 0);
	{
		__rta_copy_wimax_decap_pdb(p, &pdb);
		SET_LABEL(p, hdr);
		load_gmh = SEQLOAD(p, DESCBUF, 0, 8, 0);
		LOAD(p, LDST_SRCDST_WORD_CLRW |
		     CLRW_CLR_C1MODE |
		     CLRW_CLR_C2MODE |
		     CLRW_CLR_C2DATAS |
		     CLRW_CLR_C2CTX |
		     CLRW_CLR_C2KEY |
		     CLRW_RESET_CLS2_CHA |
		     CLRW_RESET_CLS1_CHA,
		     CLRW, 0, 4, IMMED);
		SEQINPTR(p, 0, 8, RTO);

		pkeyjump = JUMP(p, keyjump, LOCAL_JUMP, ALL_TRUE, SHRD | SELF);
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, INLINE_KEY(cipherdata));
		SET_LABEL(p, keyjump);
		PROTOCOL(p, OP_TYPE_DECAP_PROTOCOL, OP_PCLID_WIMAX, protinfo);

		SEQOUTPTR(p, 0, 8, RTO);
		move_gmh = MOVE(p, DESCBUF, 0, MATH0, 0, 8, WAITCOMP | IMMED);

		/* Clear Encryption Control bit. */
		MATHB(p, MATH0, AND, ~WIMAX_GMH_EC_MASK, MATH0, 8, IMMED2);

		/*
		 * Update Generic Mac Header Length field.
		 * The left shift is used in order to update the GMH LEN field
		 * and nothing else.
		 */
		if (pdb_opts & WIMAX_PDBOPTS_FCS)
			MATHB(p, MATH0, SUB, (WIMAX_PN_LEN << 0x28) +
					  (WIMAX_ICV_LEN << 0x28) +
					  (WIMAX_FCS_LEN << 0x28),
			      MATH0, 8, IMMED2);
		else
			MATHB(p, MATH0, SUB, (WIMAX_PN_LEN << 0x28) +
					  (WIMAX_ICV_LEN << 0x28),
			      MATH0, 8, IMMED2);

		/*
		 * Compute the CRC-8-ATM value for the first five bytes
		 * of the header and insert the result into the sixth
		 * MATH0 byte field.
		 */
		LOAD(p, LDST_SRCDST_WORD_CLRW |
		     CLRW_CLR_C1MODE |
		     CLRW_CLR_C2MODE |
		     CLRW_CLR_C2DATAS |
		     CLRW_CLR_C2CTX |
		     CLRW_CLR_C2KEY |
		     CLRW_RESET_CLS2_CHA |
		     CLRW_RESET_CLS1_CHA,
		     CLRW, 0, 4, IMMED);
		KEY(p, KEY2, 0, CRC_8_ATM_POLY, 2, IMMED);
		ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
			      OP_ALG_AAI_CUST_POLY | OP_ALG_AAI_DIS,
			      OP_ALG_AS_UPDATE, ICV_CHECK_DISABLE, DIR_ENC);
		MOVE(p, MATH0, 0, IFIFOAB2, 0, 5, LAST1 | IMMED);
		MOVE(p, CONTEXT2, 0, MATH1, 0, 4, WAITCOMP | IMMED);
		MOVE(p, MATH1, 0, MATH0, 5, 1, WAITCOMP | IMMED);

		/* Rewrite decapsulation Generic Mac Header. */
		SEQSTORE(p, MATH0, 0, 6, 0);
/*
 * TODO: RTA currently doesn't support adding labels in or after Job Descriptor.
 * To be changed when proper support is added in RTA.
 */
		SET_LABEL(p, gmh);
		gmh += 11;
	}
	PATCH_HDR(p, phdr, hdr);
	PATCH_JUMP(p, pkeyjump, keyjump);
	PATCH_LOAD(p, load_gmh, gmh);
	PATCH_MOVE(p, move_gmh, gmh);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_WIMAX_H__ */
