/*
 * Copyright 2017 NXP.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_ADDL_ALGO_H__
#define __DESC_ADDL_ALGO_H__

#include "hw/rta.h"
#include "common.h"

/**
 * DOC: Algorithms - Shared Descriptor Constructors
 *
 * Shared descriptors for algorithms (i.e. not for protocols).
 */

/**
 * cnstr_shdsc_gcm_encap - AES-GCM as a shared descriptor
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @cipherdata: pointer to block cipher transform definitions
 * 		Valid algorithm values - OP_ALG_ALGSEL_AES ANDed with
 *		OP_ALG_AAI_GCM.
 * @ivlen: Initialization vector length
 * @icvsize: integrity check value (ICV) size (truncated or full)
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int
cnstr_shdsc_gcm_encap(uint32_t *descbuf, bool ps, bool swap,
		      struct alginfo *cipherdata,
		      uint32_t ivlen, uint32_t icvsize)
{
	struct program prg;
	struct program *p = &prg;
	PROGRAM_CNTXT_INIT(p, descbuf, 0);

	LABEL(keyjmp);
	LABEL(zeroassocjump2);
	LABEL(zeroassocjump1);
	LABEL(zeropayloadjump);
	REFERENCE(pkeyjmp);
	REFERENCE(pzeroassocjump2);
	REFERENCE(pzeroassocjump1);
	REFERENCE(pzeropayloadjump);

	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	SHR_HDR(p, SHR_SERIAL, 1, SC);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SELF | SHRD);
	/* Insert Key */
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));

	SET_LABEL(p, keyjmp);

	/* class 1 operation */
	ALG_OPERATION(p, cipherdata->algtype, cipherdata->algmode,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);

	/* if assoclen + cryptlen is ZERO, skip to ICV write */
	MATHB(p, DPOVRD, AND, 0x7fffffff, MATH3, 4, IMMED2);
	MATHB(p, SEQINSZ, SUB, ivlen, VSEQOUTSZ, 4, IMMED2);
	pzeroassocjump2 = JUMP(p, zeroassocjump2, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	SEQFIFOLOAD(p, IV1,ivlen,FLUSH1);
	/* if assoclen is ZERO, skip reading the assoc data */
	MATHB(p, ZERO, ADD, MATH3, VSEQINSZ, 4, 0);
	pzeroassocjump1 = JUMP(p, zeroassocjump1, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	MATHB(p, ZERO, ADD, MATH3, VSEQOUTSZ, 4, 0);

	/* skip assoc data */
	SEQFIFOSTORE(p, SKIP, 0, 0, VLF);

	/* cryptlen = seqinlen - assoclen */
	MATHB(p, SEQINSZ, SUB, MATH3, VSEQOUTSZ, 4, 0);

	/* if cryptlen is ZERO jump to zero-payload commands */
	pzeropayloadjump = JUMP(p, zeropayloadjump, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/* read assoc data */
	SEQFIFOLOAD(p, AAD1, 0, CLASS1 | VLF | FLUSH1);
	SET_LABEL(p, zeroassocjump1);

	MATHB(p, SEQINSZ, SUB, MATH0, VSEQINSZ, 4, 0);


	/* write encrypted data */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* read payload data */
	SEQFIFOLOAD(p, MSG1, 0, CLASS1 | VLF | LAST1);

	/* jump the zero-payload commands */
	JUMP(p, 4, LOCAL_JUMP, ALL_TRUE, 0);

	/* zero-payload commands */
	SET_LABEL(p, zeropayloadjump);

	/* read assoc data */
	SEQFIFOLOAD(p, AAD1, 0, CLASS1 | VLF | LAST1);

	JUMP(p, 2, LOCAL_JUMP, ALL_TRUE, 0);
	/* There is no input data */
	SET_LABEL(p, zeroassocjump2);
	SEQFIFOLOAD(p, IV1, ivlen, FLUSH1 | LAST1);

	/* write ICV */
	SEQSTORE(p, CONTEXT1, 0, icvsize, 0);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, pzeroassocjump2, zeroassocjump2);
	PATCH_JUMP(p, pzeroassocjump1, zeroassocjump1);
	PATCH_JUMP(p, pzeropayloadjump, zeropayloadjump);

	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_gcm_decap - AES-GCM decap shared descriptor
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @cipherdata: pointer to block cipher transform definitions
 * 		Valid algorithm values - OP_ALG_ALGSEL_AES ANDed with
 *		OP_ALG_AAI_GCM.
 * @icvsize: integrity check value (ICV) size (truncated or full)
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int
cnstr_shdsc_gcm_decap(uint32_t *descbuf, bool ps, bool swap,
		      struct alginfo *cipherdata,
		      uint32_t ivlen, uint32_t icvsize)
{
	struct program prg;
	struct program *p = &prg;
	PROGRAM_CNTXT_INIT(p, descbuf, 0);

	LABEL(keyjmp);
	LABEL(zeroassocjump1);
	LABEL(zeropayloadjump);
	REFERENCE(pkeyjmp);
	REFERENCE(pzeroassocjump1);
	REFERENCE(pzeropayloadjump);

	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	SHR_HDR(p, SHR_SERIAL, 1, SC);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SELF | SHRD);
	/* Insert Key */
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));

	SET_LABEL(p, keyjmp);

	/* class 1 operation */
	ALG_OPERATION(p, cipherdata->algtype, cipherdata->algmode,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_ENABLE, DIR_DEC);

	/* if assoclen is ZERO, skip reading the assoc data */
	MATHB(p, DPOVRD, AND, 0x7fffffff, MATH3, 4, IMMED2);
	SEQFIFOLOAD(p, IV1, ivlen, FLUSH1);

	MATHB(p, ZERO, ADD, MATH3, VSEQINSZ, 4, 0);
	pzeroassocjump1 = JUMP(p, zeroassocjump1, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	MATHB(p, ZERO, ADD, MATH3, VSEQOUTSZ, 4, 0);

	/* skip assoc data */
	SEQFIFOSTORE(p, SKIP, 0, 0, VLF);

	/* read assoc data */
	SEQFIFOLOAD(p, AAD1, 0, CLASS1 | VLF | FLUSH1);
	SET_LABEL(p, zeroassocjump1);

	/* cryptlen = seqoutlen - assoclen */
	MATHB(p, SEQOUTSZ, SUB, MATH0, VSEQINSZ, 4, 0);

	/* jump to zero-payload command if cryptlen is zero */
	pzeropayloadjump = JUMP(p, zeropayloadjump, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	MATHB(p, SEQOUTSZ, SUB, MATH0, VSEQOUTSZ, 4, 0);

	/* store encrypted data */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* read payload data */
	SEQFIFOLOAD(p, MSG1, 0, CLASS1 | VLF | FLUSH1);

	/* zero-payload command */
	SET_LABEL(p, zeropayloadjump);

	/* read ICV */
	SEQFIFOLOAD(p, ICV1, icvsize, CLASS1 | LAST1);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, pzeroassocjump1, zeroassocjump1);
	PATCH_JUMP(p, pzeropayloadjump, zeropayloadjump);

	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_ADDL_ALGO_H__ */
