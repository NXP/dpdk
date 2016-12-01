/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_MBMS_H__
#define __DESC_MBMS_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: MBMS Shared Descriptor Constructors
 *
 * Shared descriptors for MBMS protocol.
 */

/**
 * MBMS_HEADER_POLY - CRC6 polynomial for MBMS PDU header.
 *                    Equals to D^6 + D^5 + D^3 + D^2 + D^1 + 1.
 */
#define MBMS_HEADER_POLY	0xBC000000

/**
 * MBMS_PAYLOAD_POLY - CRC10 polynomial for MBMS PDU header.
 *                     Equals to D^10 + D^9 + D^5 + D^4 + D^1 + 1.
 */
#define MBMS_PAYLOAD_POLY	0x8CC00000

/**
 * MBMS_TYPE0_HDR_LEN - The length of a MBMS Type 0 PDU header
 */
#define MBMS_TYPE0_HDR_LEN	18

/**
 * MBMS_TYPE1_HDR_LEN - The length of a MBMS Type 1 PDU header
 */
#define MBMS_TYPE1_HDR_LEN	11

/**
 * MBMS_TYPE3_HDR_LEN - The length of a MBMS Type 3 PDU header
 */
#define MBMS_TYPE3_HDR_LEN	19

/**
 * DUMMY_BUF_BASE - A dummy address used as immediate value when reading the
 *                  parser result from before the frame buffer.
 */
#define DUMMY_BUF_BASE		0xDEADC000

/**
 * HDR_PAYLOAD_MASK - Mask to be used for extracting only the header CRC from
 *                    the corresponding field in the MBMS Type 1 & 3 PDUs SYNC
 *                    headers.
 */
#define HDR_CRC_MASK		0xFC00000000000000ll

/**
 * FM_RX_PRIV_SIZE - Size of the private part, reserved for DPA ETH in the
 *                   buffer before the frame.
 */
#define FM_RX_PRIV_SIZE		0x10

/**
 * FM_RX_EXTRA_HEADROOM - The size of the extra space reserved by Frame Manager
 *                        at the beginning of a data buffer on the receive path.
 */
#define FM_RX_EXTRA_HEADROOM	0x40

/**
 * IC_PR_OFFSET - Offset of the Parser Results field in the Internal Context
 *                field.
 */
#define IC_PR_OFFSET		0x20

/**
 * PR_L4_OFFSET - Offset of the L4 header offset result in the Parser Results
 *                field.
 */
#define PR_L4_OFFSET		0x1E

/**
 * BUF_IC_OFFSET - Offset of the Internal Context in the buffer before the frame
 */
#define BUF_IC_OFFSET		(FM_RX_PRIV_SIZE + FM_RX_EXTRA_HEADROOM)

/**
 * BUF_PR_OFFSET - Offset of the Parser Results in the buffer before the frame
 */
#define BUF_PR_OFFSET		(BUF_IC_OFFSET + IC_PR_OFFSET)

/**
 * BUF_L4_OFFSET - Offset of the L4 header offset in the buffer before the frame
 */
#define BUF_L4_OFFSET		(BUF_PR_OFFSET + PR_L4_OFFSET)

/**
 * UDP_HDR_LEN - The length of the UDP header
 */
#define UDP_HDR_LEN		8

/**
 * GTP_HDR_LEN - The length of the GTP header with no options and no sequence
 *               number
 */
#define GTP_HDR_LEN		8

/**
 * MBMS_HDR_OFFSET - MBMS header offset in the frame buffer
 */
#define MBMS_HDR_OFFSET		(UDP_HDR_LEN + GTP_HDR_LEN)

/**
 * MBMS_CRC_HDR_FAIL - Status returned by SEC in case the header CRC of the MBMS
 *                     PDU failed.
 */
#define MBMS_CRC_HDR_FAIL	0xAA

/**
 * MBMS_CRC_PAYLOAD_FAIL - Status returned by SEC in case the payload CRC of the
 *                         MBMS PDU failed.
 */
#define MBMS_CRC_PAYLOAD_FAIL	0xAB

/**
 * enum mbms_pdu_type - Type selectors for MBMS PDUs in SYNC protocol
 * @MBMS_PDU_TYPE0: MBMS PDU type 0
 * @MBMS_PDU_TYPE1: MBMS PDU type 1
 * @MBMS_PDU_TYPE2: MBMS PDU type 2 is not supported
 * @MBMS_PDU_TYPE3: MBMS PDU type 3
 * @MBMS_PDU_TYPE_INVALID: invalid option
 */
enum mbms_pdu_type {
	MBMS_PDU_TYPE0,
	MBMS_PDU_TYPE1,
	MBMS_PDU_TYPE2,
	MBMS_PDU_TYPE3,
	MBMS_PDU_TYPE_INVALID
};

/**
 * struct mbms_type_0_pdb - MBMS Type 0 PDB
 * @crc_header_fail: number of PDUs with incorrect header CRC
 */
struct mbms_type_0_pdb {
	uint32_t crc_header_fail;
};

/**
 * struct mbms_type_1_3_pdb - MBMS Type 1 and Type 3 PDB
 * @crc_header_fail: number of PDUs with incorrect header CRC
 * @crc_payload_fail: number of PDUs with incorrect payload CRC
 */
struct mbms_type_1_3_pdb {
	uint32_t crc_header_fail;
	uint32_t crc_payload_fail;
};

static inline void cnstr_shdsc_mbms_type0(uint32_t *descbuf, int *bufsize,
					  bool ps, bool swap)
{
	struct program prg;
	struct program *p = &prg;
	struct mbms_type_0_pdb pdb;

	LABEL(pdb_end);
	LABEL(end_of_sd);
	LABEL(seq_in_ptr);
	LABEL(rto);
	LABEL(crc_pass);
	LABEL(keyjmp);
	REFERENCE(jump_write_crc);
	REFERENCE(phdr);
	REFERENCE(seq_in_address);
	REFERENCE(patch_load);
	REFERENCE(pkeyjmp);
	REFERENCE(load_start_of_buf);
	REFERENCE(read_rto);
	REFERENCE(write_rto);

	memset(&pdb, 0, sizeof(pdb));
	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);
	COPY_DATA(p, (uint8_t *)&pdb, sizeof(pdb));
	SET_LABEL(p, pdb_end);

	/*
	 * Read the pointer to data from JD. The last byte is ignored. This
	 * is done for reading the IC & implicitly the PR portion of the IC.
	 */
	seq_in_address = MOVE(p, DESCBUF, 0, MATH0, 0, 7, IMMED);
	patch_load = MOVE(p, MATH0, 0, DESCBUF, 0, 7, IMMED);

	/*
	 * Next, do some stuff since the above commands overwrite the
	 * descriptor buffer and due to pipelining, it's possible that
	 * the modifications aren't taken into consideration.
	 */

	/*
	 * Set Non-SEQ LIODN equal to SEQ LIODN. This is needed for
	 * transferring data that is in the input buffer by the (non-SEQ) LOAD
	 * command below
	 */
	LOAD(p, 0, DCTRL, LDOFF_CHG_NONSEQLIODN_SEQ, 0, IMMED);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD|SELF);

	/* Load the polynomial to KEY2 register */
	KEY(p, KEY2, 0, MBMS_HEADER_POLY, 1, IMMED);

	SET_LABEL(p, keyjmp);

	ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
		      OP_ALG_AAI_CUST_POLY |
		      OP_ALG_AAI_DIS | OP_ALG_AAI_DOS | OP_ALG_AAI_DOC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);

	/* Put UDP offset in least significant byte of M1 */
	load_start_of_buf = LOAD(p, DUMMY_BUF_BASE | BUF_L4_OFFSET, MATH1, 7,
				 1, 0);
	load_start_of_buf++;

	/* Restore LIODN */
	LOAD(p, 0, DCTRL, LDOFF_CHG_NONSEQLIODN_NON_SEQ, 0, IMMED);

	/* Wait for transfer to end */
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);

	/* Calculate offset to MBMS SYNC header offset from start of frame */
	MATHB(p, MATH1, ADD, MBMS_HDR_OFFSET, VSEQINSZ, 4, IMMED2);

	/*
	 * Put the full input length in M1, used below to patch the rereading
	 * of the frame
	 */
	MATHB(p, VSEQINSZ, ADD, MBMS_TYPE0_HDR_LEN, MATH1, 4, IMMED2);

	/* Calculate length of output frame to be stored (if CRC passes) */
	MATHB(p, MATH1, SUB, ZERO, VSEQOUTSZ, 4, 0);

	/* SKIP all headers */
	SEQFIFOLOAD(p, SKIP, 0, VLF);

	/* Read the MBMS header, minus the CRC */
	SEQFIFOLOAD(p, MSG2,
		    MBMS_TYPE0_HDR_LEN - 1,
		    LAST2);

	/* READ CRC in MSB of M2 */
	SEQLOAD(p, MATH2, 0, 1, 0);

	/* Restore VSIL before mangling MATH1 below */
	MATHB(p, MATH1, ADD, ZERO, VSEQINSZ, 4, 0);

	/*
	 * Patch the SEQINPTR RTO command below to revert the frame input
	 * to the beginning.
	 * Note: One can remove these commands and use a large value for the
	 * length in SEQINPTR RTO.
	 */
	read_rto = MOVE(p, DESCBUF, 0, MATH1, 0, 6, IMMED);
	write_rto = MOVE(p, MATH1, 0, DESCBUF, 0, 8, IMMED);

	/*
	 * Wait here for CRCA to finish processing AND for the external transfer
	 * of the CRC to finish before proceeding in comparing the CRC
	 */
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);

	/* Put in the MSB of M3 the CRC as calculated by CRCA */
	MOVE(p, CONTEXT2, 0, MATH3, 0, 1, WAITCOMP | IMMED);

	/* Do Frame_CRC XOR Calculated_CRC */
	MATHB(p, MATH2, XOR, MATH3, NONE, 8, 0);

	/*
	 * If the last math operation sets the zero flag, it means the two CRCs
	 * match and the descriptor can start copying things into the OFIFO and
	 * subsequently write them to external memory.
	 */
	jump_write_crc = JUMP(p, 0, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/*
	 * If here, then the two CRCs are different. Thus, the descriptor
	 * will increment the failed CRCs count and then halt execution with
	 * the status indicating the Header CRC failed.
	 */

	/*
	 * Read the first two words of the descriptor into M0 (the 2nd word
	 * contains the statistic to be incremented
	 */
	MOVE(p, DESCBUF, 0, MATH0, 0, 8, WAITCOMP | IMMED);

	/*
	 * Increment the read statistic with 1, while not mangling the header
	 * of the descriptor
	 */
	MATHB(p, MATH0, ADD, ONE, MATH0, 8, 0);

	/* Write back the modifications in the descriptor buffer */
	MOVE(p, MATH0, 0, DESCBUF, 0, 8, WAITCOMP | IMMED);

	/* Store the updated statistic in external memory */
	STORE(p, SHAREDESCBUF_EFF, 4, DUMMY_BUF_BASE, 4, 0);

	SET_LABEL(p, rto);

	/* Halt here with the appropriate status */
	JUMP(p, MBMS_CRC_HDR_FAIL, HALT_STATUS, ALL_FALSE, CALM);

	/*
	 * If here, all is fine, so prepare the frame-copying. First revert
	 * the input frame
	 */
	SET_LABEL(p, crc_pass);
	SEQINPTR(p, 0, 0, RTO);

	/* Store everything */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/*
	 * Move M1 bytes from IFIFO to OFIFO
	 * Note: Only bits 16:31 of M1 are used, so the fact that it's mangled
	 *       because of the RTO patching above is not relevant.
	 */
	MOVE(p, AB1, 0, OFIFO, 0, MATH1, 0);

	/* Read all frame */
	SEQFIFOLOAD(p, MSG1, 0, VLF | LAST1 | FLUSH1);

	SET_LABEL(p, end_of_sd);
	seq_in_ptr = end_of_sd + 8;

	PATCH_MOVE(p, seq_in_address, seq_in_ptr);
	PATCH_MOVE(p, patch_load, load_start_of_buf);
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_MOVE(p, read_rto, rto);
	PATCH_MOVE(p, write_rto, rto);
	PATCH_JUMP(p, jump_write_crc, crc_pass);

	PATCH_HDR(p, phdr, pdb_end);

	*bufsize = PROGRAM_FINALIZE(p);
}

static inline unsigned cnstr_shdsc_mbms_type1_3(uint32_t *descbuf, int *bufsize,
						bool ps, bool swap,
						enum mbms_pdu_type pdu_type)
{
	struct program part1_prg, part2_prg;
	struct program *p = &part1_prg;
	struct mbms_type_1_3_pdb pdb;
	uint32_t *part1_buf, *part2_buf;

	LABEL(pdb_end);
	LABEL(end_of_sd);
	LABEL(seq_in_ptr);
	LABEL(sd_ptr);
	LABEL(keyjmp);
	LABEL(hdr_crc_pass);
	LABEL(load_2nd_part);
	LABEL(all_crc_pass);
	LABEL(end_of_part2);
	REFERENCE(jump_chk_payload_crc);
	REFERENCE(jump_start_of_desc);
	REFERENCE(patch_load_2nd_part);
	REFERENCE(jump_all_crc_ok);
	REFERENCE(phdr);
	REFERENCE(seq_in_address);

	REFERENCE(move_sd_address);
	REFERENCE(patch_move_load_2nd_part);

	REFERENCE(patch_load);
	REFERENCE(pkeyjmp);
	REFERENCE(load_start_of_buf);

	part1_buf = descbuf;

	memset(&pdb, 0, sizeof(pdb));
	PROGRAM_CNTXT_INIT(p, part1_buf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);
	COPY_DATA(p, (uint8_t *)&pdb, sizeof(pdb));
	SET_LABEL(p, pdb_end);

	/*
	 * Read the pointer to data from JD. The last byte is ignored. This
	 * is done for reading the IC & implicitly the PR portion of the IC.
	 */
	seq_in_address = MOVE(p, DESCBUF, 0, MATH0, 0, 7, IMMED);
	patch_load = MOVE(p, MATH0, 0, DESCBUF, 0, 7, IMMED);

	/*
	 * Next, do some stuff since the above commands overwrite the
	 * descriptor buffer and due to pipelining, it's possible that
	 * the modifications aren't taken into consideration.
	 */

	/*
	 * Set Non-SEQ LIODN equal to SEQ LIODN. This is needed for
	 * transferring data that is in the input buffer by the (non-SEQ) LOAD
	 * command below
	 */
	LOAD(p, 0, DCTRL, LDOFF_CHG_NONSEQLIODN_SEQ, 0, IMMED);

	/*
	 * Note: The assumption here is that the base adress where the preheader
	 * and the descriptor are allocated is 256B aligned.
	 */
	move_sd_address = MOVE(p, DESCBUF, 0, MATH2, 0, 7, IMMED);
	patch_move_load_2nd_part = MOVE(p, MATH2, 0, DESCBUF, 0, 7, IMMED);

	/*
	 * This descriptor overwrites itself ("overlay methodology").
	 * The descriptor buffer is contiguous and the descriptor will
	 * bring from external memory into descriptor buffer the supplementary
	 * data which cannot fit in the descriptor buffer. In order to do that,
	 * the descriptor reads (LOAD) at SD_PTR + 51W (13W is the max
	 * JD size) from JD and brings data back into the descriptor buffer.
	 * The following instructions take care of patching the first before
	 * last command that can be pushed in the current descriptor buffer
	 */
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD|SELF);

	/* Load the header polynomial to KEY2 register */
	KEY(p, KEY2, 0, MBMS_HEADER_POLY, 1, IMMED);

	SET_LABEL(p, keyjmp);

	ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
		      OP_ALG_AAI_CUST_POLY |
		      OP_ALG_AAI_DIS | OP_ALG_AAI_DOS | OP_ALG_AAI_DOC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);

	/* Put UDP offset in least significant byte of M1 */
	load_start_of_buf = LOAD(p, DUMMY_BUF_BASE | BUF_L4_OFFSET, MATH1, 7,
				 1, 0);
	load_start_of_buf++;

	/* Restore LIODN */
	LOAD(p, 0, DCTRL, LDOFF_CHG_NONSEQLIODN_NON_SEQ, 0, IMMED);

	/* Wait for transfer to end */
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);

	/* Calculate offset to MBMS SYNC header offset from start of frame */
	MATHB(p, MATH1, ADD, MBMS_HDR_OFFSET, VSEQINSZ, 4, IMMED2);

	/* Put full frame length into M0 */
	MATHB(p, SEQINSZ, SUB, ZERO, MATH0, 4, 0);

	/* M1 will contain the offset to MBMS payload */
	if (pdu_type == MBMS_PDU_TYPE1)
		MATHB(p, VSEQINSZ, ADD, MBMS_TYPE1_HDR_LEN, MATH1, 4,
		      IMMED2);
	else
		MATHB(p, VSEQINSZ, ADD, MBMS_TYPE3_HDR_LEN, MATH1, 4,
		      IMMED2);

	/*
	 * Save frame length and MBMS Header Offset (all frame data to be
	 * skipped into Context1
	 */
	MOVE(p, MATH0, 0, CONTEXT1, 0, 16, IMMED);

	/* SKIP all headers */
	SEQFIFOLOAD(p, SKIP, 0, VLF);

	/* Read the MBMS header, minus the CRC */
	if (pdu_type == MBMS_PDU_TYPE1)
		SEQFIFOLOAD(p, MSG2,
			    MBMS_TYPE1_HDR_LEN - 2,
			    LAST2);
	else
		SEQFIFOLOAD(p, MSG2,
			    MBMS_TYPE3_HDR_LEN - 2,
			    LAST2);

	/* READ Header CRC and Payload CRC and save it in ... */
	SEQLOAD(p, MATH3, 0, 2, 0);

	/*
	 * Wait here for CRCA to finish processing AND for the external transfer
	 * of the CRC to finish before proceeding in comparing the CRC
	 */
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM | CLASS2);

	/* Clear the payload CRC */
	MATHB(p, MATH3, AND, HDR_CRC_MASK, MATH2, 8, IMMED2);

	/* Put in M3 the payload CRC */
	MATHB(p, MATH3, XOR, MATH2, MATH3, 8, STL);

	/*
	 * Align the payload CRC properly (so it can be compared easily with
	 * the calculated CRC.
	 */
	MATHB(p, MATH3, LSHIFT, 6, MATH3, 8, IFB | IMMED2);

	/* Save header & payload CRC for future checking and/or updating */
	MOVE(p, MATH2, 0, CONTEXT1, 16, 16, IMMED);

	/* Put in the MSB of M3 the header CRC as calculated by CRCA */
	MOVE(p, CONTEXT2, 0, MATH3, 0, 8, WAITCOMP | IMMED);

	/* Do Frame_CRC XOR Calculated_CRC */
	MATHB(p, MATH2, XOR, MATH3, NONE, 8, 0);

	/*
	 * If the last math operation sets the zero flag, it means the two CRCs
	 * match and the descriptor can start copying things into the OFIFO and
	 * subsequently write them to external memory.
	 */
	jump_chk_payload_crc = JUMP(p, 0, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/*
	 * If here, then the two CRCs are different. Thus, the descriptor
	 * will increment the failed CRCs count and then halt execution with
	 * the status indicating the Header CRC failed.
	 */

	/*
	 * Read the first two words of the descriptor into M0 (the 2nd word
	 * contains the statistic to be incremented
	 */
	MOVE(p, DESCBUF, 0, MATH0, 0, 8, WAITCOMP | IMMED);

	/*
	 * Increment the read statistic with 1, while not mangling the header
	 * of the descriptor
	 */
	MATHB(p, MATH0, ADD, ONE, MATH0, 8, 0);

	/* Write back the modifications in the descriptor buffer */
	MOVE(p, MATH0, 0, DESCBUF, 0, 8, WAITCOMP | IMMED);

	/* Store the updated statistic in external memory */
	STORE(p, SHAREDESCBUF_EFF, 4, DUMMY_BUF_BASE, 4, 0);

	/* Halt here with the appropriate status */
	JUMP(p, MBMS_CRC_HDR_FAIL, HALT_STATUS, ALL_TRUE, CALM);

	/*
	 * If here, header is OK. Payload must be checked next
	 */
	SET_LABEL(p, hdr_crc_pass);

	/* Reset C2 related stuff */
	LOAD(p, LDST_SRCDST_WORD_CLRW |
		 CLRW_CLR_C2MODE |
		 CLRW_CLR_C2DATAS |
		 CLRW_CLR_C2CTX |
		 CLRW_CLR_C2KEY |
		 CLRW_RESET_CLS2_CHA,
	     CLRW, 0, 4, IMMED);

	/*
	 * Set VSIL so that the length to be read is:
	 * original SIL - MBMS Hdr Offset - MBMS Header Length
	 */
	MATHB(p, MATH0, SUB, MATH1, VSEQINSZ, 4, 0);

	/*
	 * Insert the overlaying procedure here. This is quite simple:
	 * - the LOAD command below was patched in the beginning
	 *   so that it reads from the SD_PTR + (total descriptor length -
	 *   <HERE>) and puts into the descriptor buffer AFTER the PDB
	 * - sharing is disabled (because the descriptor buffer needs to be
	 *   re-fetched
	 * - a jump back is done so the execution resumes after the PDB
	 */
	LOAD(p, 0, DCTRL, LDOFF_CHG_SHARE_NEVER, 0, IMMED);

	/*
	 * Note1: For now, RTA doesn't support to update the length of the LOAD
	 * So the length is hardcoded. If the descriptor get modified, this
	 * will have to be updated.
	 *
	 * Note2: The "+8" below is due to the preheader that is before the SD
	 */
	SET_LABEL(p, load_2nd_part);
	patch_load_2nd_part = LOAD(p, DUMMY_BUF_BASE, DESCBUF, 0, 8, 0);

	jump_start_of_desc = JUMP(p, 0, LOCAL_JUMP, ALL_TRUE, CALM);

	/*
	 * HERE ENDS THE FIRST PART OF THE DESCRIPTOR. ALL INSTRUCTIONS
	 * FOLLOWING THIS POINT ARE EXECUTED IN THE SECOND HALF OF THE
	 * DESCRIPTOR THAT HAS JUST BEEN TRANSFERED ABOVE
	 *
	 * Note: because of the above, all labels pointing to JD must be set
	 *       here
	 */
	SET_LABEL(p, end_of_sd);
	seq_in_ptr = end_of_sd + 8;
	sd_ptr = end_of_sd + 1;

	PATCH_MOVE(p, seq_in_address, seq_in_ptr);
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_MOVE(p, patch_load, load_start_of_buf);
	PATCH_MOVE(p, move_sd_address, sd_ptr);
	/*
	 * +1 here is needed because the PTR field (2WORDs) in the LOAD
	 * command needs to be updated by the MOVE command, not the LOAD command
	 * itself.
	 */
	PATCH_MOVE(p, patch_move_load_2nd_part, load_2nd_part + 1);
	PATCH_JUMP(p, jump_chk_payload_crc, hdr_crc_pass);
	PATCH_JUMP(p, jump_start_of_desc, pdb_end);
	PATCH_LOAD(p, patch_load_2nd_part, pdb_end);

	/*
	 * This patches the pointer in the load command so that it points after
	 * the "first part" SD.
	 * Note1: The +2 in the REFERENCE is needed because the least
	 *        significant byte in the PTR field of the LOAD command (the
	 *        offset from the base) needs to be updated; this resides 2
	 *        WORDS from the actual LOAD command
	 * Note2: The "+8" below is due to the preheader that is before the SD
	 */
	PATCH_RAW(p, patch_load_2nd_part + 2, 0xFF, end_of_sd * 4 + 8);

	PATCH_HDR(p, phdr, pdb_end);

	*bufsize = PROGRAM_FINALIZE(p);

	/* Here goes the 2nd part of the descriptor, as a separate program */
	p = &part2_prg;

	/*
	 * Start to write instructions in descriptor buffer after the
	 * instructions in the first program
	 */
	part2_buf = part1_buf + end_of_sd;

	/*
	 * The offset is set to the end of the PDB because the 2nd part of the
	 * descriptor is brought after the PDB in the SD (overwriting is done
	 * after the PDB).
	 */
	PROGRAM_CNTXT_INIT(p, part2_buf, pdb_end);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	/* Load the payload polynomial to KEY2 register */
	KEY(p, KEY2, 0, MBMS_PAYLOAD_POLY, 2, IMMED);

	/* Request the CRC engine */
	ALG_OPERATION(p, OP_ALG_ALGSEL_CRC,
		      OP_ALG_AAI_CUST_POLY |
		      OP_ALG_AAI_DIS | OP_ALG_AAI_DOS | OP_ALG_AAI_DOC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);

	/* Get the payload CRC, saved previously */
	MOVE(p, CONTEXT1, 24, MATH2, 0, 8, IMMED);

	/* Read the payload data */
	SEQFIFOLOAD(p, MSG2, 0, LAST2 | VLF);

	/* Get the calculated CRC */
	MOVE(p, CONTEXT2, 0, MATH3, 0, 8, WAITCOMP | IMMED);

	/* Check if the two CRCs match */
	MATHB(p, MATH3, XOR, MATH2, NONE, 8, 0);

	jump_all_crc_ok = JUMP(p, 0, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/*
	 * If here, then the two CRCs are different. Thus, the descriptor
	 * will increment the failed payload CRCs count, copy the frame
	 * up to and including the MBMS Header, minus the Payload CRC which
	 * is going to be updated with the calculated CRC. Then the execution
	 * will be halted with the status indicating the Payload CRC failed.
	 */

	/* Revert the frame back to the beginning */
	SEQINPTR(p, 0, 9600, RTO);

	/* Bytes to copy = MAC/VLAN/IP/UDP/GTP/MBMS minus CRC (2B) */
	MATHB(p, MATH1, SUB, 2, MATH1, 4, IMMED2);
	MATHB(p, MATH1, SUB, ZERO, VSEQINSZ, 4, 0);

	/* Prepare the CRC Hdr to be written */
	MOVE(p, CONTEXT1, 16, MATH2, 0, 8, IMMED);

	/* Align the Calculated Payload CRC to be written properly */
	MATHB(p, MATH3, RSHIFT, 6, MATH3, 8, IFB | IMMED2);

	/* Bytes to write in output memory =  MAC/VLAN/IP/UDP/GTP/MBMS */
	MATHB(p, MATH1, SUB, ZERO, VSEQOUTSZ, 4, 0);

	/* Initiate writing to external memory */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* Read everything w/o the CRCs */
	SEQFIFOLOAD(p, MSG1, 0, LAST1 | FLUSH1 | VLF);

	/* Move M1 bytes from IFIFO to OFIFO */
	MOVE(p, AB1, 0, OFIFO, 0, MATH1, 0);

	/* Add the calculated payload CRC to the header CRC */
	MATHB(p, MATH2, OR, MATH3, MATH2, 8, 0);

	/* Now store the updated CRCs to the output frame */
	SEQSTORE(p, MATH2, 0, 2, 0);

	/*
	 * Read the 2nd two words of the descriptor into M0 (the 3rd word
	 * contains the statistic to be incremented
	 */
	MOVE(p, DESCBUF, 4, MATH0, 0, 8, WAITCOMP | IMMED);

	/*
	 * Increment the read statistic with 1, while not mangling the failed
	 * CRC header statistics
	 */
	MATHB(p, MATH0, ADD, ONE, MATH0, 8, 0);

	/* Write back the modifications in the descriptor buffer */
	MOVE(p, MATH0, 0, DESCBUF, 4, 8, WAITCOMP | IMMED);

	/* Store the updated statistic in external memory */
	STORE(p, SHAREDESCBUF, 8, DUMMY_BUF_BASE, 4, 0);

	/*
	 * Halt here with the appropriate status, but wait first for data
	 * to reach the memory
	 */
	JUMP(p, MBMS_CRC_PAYLOAD_FAIL, HALT_STATUS, ALL_TRUE, CALM);

	SET_LABEL(p, all_crc_pass);
	/* If here, both the header CRC and the payload CRC are correct */

	/* Revert the frame back to beginning */
	SEQINPTR(p, 0, 9600, RTO);

	/* Bytes to read = MAC/VLAN/IP/UDP/GTP/MBMS + Payload*/
	MATHB(p, MATH0, SUB, ZERO, VSEQINSZ, 4, 0);

	/* Bytes to write = bytes to read */
	MATHB(p, VSEQINSZ, SUB, ZERO, VSEQOUTSZ, 4, 0);

	/* Store everything */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* Read all frame */
	SEQFIFOLOAD(p, MSG1, 0, VLF | LAST1 | FLUSH1);

	/* Move M1 bytes from IFIFO to OFIFO */
	MOVE(p, AB1, 0, OFIFO, 0, MATH0, 0);

	/*
	 * Halt with 0 (i.e. no error).
	 * This is needed because the descriptor is overlayed, and otherwise
	 * the DECO will continue executing stuff that is leftover from the
	 * original descriptor buffer.
	 */
	JUMP(p, 0x00, HALT_STATUS, ALL_TRUE, CALM);

	SET_LABEL(p, end_of_part2);

	PATCH_JUMP(p, jump_all_crc_ok, all_crc_pass);
	PATCH_RAW(&part1_prg, patch_load_2nd_part, 0xFF, end_of_part2);

	*bufsize += PROGRAM_FINALIZE(p);

	return end_of_sd;
}

/**
 * cnstr_shdsc_mbms - MBMS PDU CRC checking descriptor
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @preheader_len: length to be set in the corresponding preheader field. Unless
 *                 the descriptor is split in multiple parts, this will be equal
 *                 to bufsize.
 * @pdu_type: type of the MBMS PDU required to be processed by this descriptor
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * Note: This function can be called only for SEC ERA >= 5.
 */
static inline int cnstr_shdsc_mbms(uint32_t *descbuf, bool ps, bool swap,
				   unsigned *preheader_len,
				   enum mbms_pdu_type pdu_type)
{
	int bufsize;

	if (rta_sec_era < RTA_SEC_ERA_5) {
		pr_err("MBMS protocol processing is available only for SEC ERA >= 5\n");
		return -ENOTSUP;
	}

	switch (pdu_type) {
	case MBMS_PDU_TYPE0:
		cnstr_shdsc_mbms_type0(descbuf, &bufsize, ps, swap);
		*preheader_len = (unsigned) bufsize;
		break;

	case MBMS_PDU_TYPE1:
		*preheader_len = cnstr_shdsc_mbms_type1_3(descbuf, &bufsize, ps,
							  swap, MBMS_PDU_TYPE1);
		break;

	case MBMS_PDU_TYPE3:
		*preheader_len = cnstr_shdsc_mbms_type1_3(descbuf, &bufsize, ps,
							  swap, MBMS_PDU_TYPE3);
		break;

	default:
		pr_err("Invalid MBMS PDU Type selected %d\n", pdu_type);
		return -EINVAL;
	}

	return bufsize;
}

/**
 * get_mbms_stats - Helper function for retrieving MBMS descriptor statistics
 * @descbuf: pointer to descriptor buffer, previously populated by the
 *           cnstr_shdsc_mbms() function.
 * @stats: points to a statistics structure matching the MBMS PDU type, as
 *         specified by the pdu_type parameter.
 * @pdu_type: MBMS PDU type
 */
static inline void get_mbms_stats(uint32_t *descbuf,
				  void *stats,
				  enum mbms_pdu_type pdu_type)
{
	uint32_t *pdb_ptr;

	/*
	 * The structure of the MBMS descriptor is the following:
	 * HEADER (1W)
	 * Header CRC failed (1W)
	 * Payload CRC failed (1W, valid only for MBMS Type 1 and Type 3)
	 */
	pdb_ptr = descbuf + 1;

	switch (pdu_type) {
	case MBMS_PDU_TYPE0:
		memcpy(stats, pdb_ptr, sizeof(struct mbms_type_0_pdb));
		break;

	case MBMS_PDU_TYPE1:
	case MBMS_PDU_TYPE3:
		memcpy(stats, pdb_ptr, sizeof(struct mbms_type_1_3_pdb));
		break;

	default:
		pr_err("Invalid MBMS PDU Type selected %d\n", pdu_type);
		break;
	}
}

#endif /* __DESC_MBMS_H__ */
