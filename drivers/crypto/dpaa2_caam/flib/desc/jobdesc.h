/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_JOBDESC_H__
#define __DESC_JOBDESC_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: Job Descriptor Constructors
 *
 * Job descriptors for certain tasks, like generating MDHA split keys.
 */

/**
 * cnstr_jobdesc_mdsplitkey - Generate an MDHA split key
 * @descbuf: pointer to buffer to hold constructed descriptor
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @alg_key: pointer to HMAC key to generate ipad/opad from
 * @keylen: HMAC key length
 * @cipher: HMAC algorithm selection, one of OP_ALG_ALGSEL_*
 *     The algorithm determines key size (bytes):
 *     -  OP_ALG_ALGSEL_MD5    - 16
 *     -  OP_ALG_ALGSEL_SHA1   - 20
 *     -  OP_ALG_ALGSEL_SHA224 - 28
 *     -  OP_ALG_ALGSEL_SHA256 - 32
 *     -  OP_ALG_ALGSEL_SHA384 - 48
 *     -  OP_ALG_ALGSEL_SHA512 - 64
 * @padbuf: pointer to buffer to store generated ipad/opad
 *
 * Split keys are IPAD/OPAD pairs. For details, refer to MDHA Split Keys chapter
 * in SEC Reference Manual.
 *
 * Return: size of descriptor written in words or negative number on error
 */

static inline int cnstr_jobdesc_mdsplitkey(uint32_t *descbuf, bool ps,
					   bool swap, uint64_t alg_key,
					   uint8_t keylen, uint32_t cipher,
					   uint64_t padbuf)
{
	struct program prg;
	struct program *p = &prg;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	JOB_HDR(p, SHR_NEVER, 1, 0, 0);
	KEY(p, KEY2, 0, alg_key, keylen, 0);
	ALG_OPERATION(p, cipher, OP_ALG_AAI_HMAC, OP_ALG_AS_INIT,
		      ICV_CHECK_DISABLE, DIR_DEC);
	FIFOLOAD(p, MSG2, 0, 0, LAST2 | IMMED | COPY);
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CLASS2);
	FIFOSTORE(p, MDHA_SPLIT_KEY, 0, padbuf, split_key_len(cipher), 0);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_JOBDESC_H__ */
