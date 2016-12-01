/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_TLS_H__
#define __DESC_TLS_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: SSL/TLS/DTLS Shared Descriptor Constructors
 *
 * Shared descriptors for SSL / TLS and DTLS protocols.
 */

/*
 * TLS family encapsulation/decapsulation PDB definitions.
 */
#define DTLS_PDBOPTS_ARS_MASK	0xC0
#define DTLS_PDBOPTS_ARS32	0x40	/* DTLS only */
#define DTLS_PDBOPTS_ARS128	0x80	/* DTLS only */
#define DTLS_PDBOPTS_ARS64	0xc0	/* DTLS only */
#define TLS_PDBOPTS_OUTFMT	0x08
#define TLS_PDBOPTS_IV_WRTBK	0x02	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_EXP_RND_IV	0x01	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_TR_ICV	0x10	/* Available starting with SEC ERA 5 */

/**
 * struct tls_block_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block encapsulation PDB
 *                        part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_block_enc {
	union {
		uint32_t word1;
		struct {

			uint8_t type;
			uint8_t version[2];
			uint8_t options;
		};
	};
	uint64_t seq_num;
};
#else
struct tls_block_enc {
	union {
		uint32_t word1;
		struct {
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
		};
	};
	uint64_t seq_num;
};
#endif

/**
 * struct dtls_block_enc - DTLS1.0 block encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_block_enc {
	struct {
		union {
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_block_enc {
	struct {
		union {
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_block_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block decapsulation PDB
 *                        part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number
 */

struct tls_block_dec {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};

/**
 * struct dtls_block_dec - DTLS1.0 block decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_block_dec {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_block_dec {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_block_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2/DTLS1.0 block
 *                        encapsulation / decapsulation PDB.
 * @iv: initialization vector
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Options Byte, it expands for
 *             ICVLen.
 */
struct tls_block_pdb {
	union {
		struct tls_block_enc tls_enc;
		struct dtls_block_enc dtls_enc;
		struct tls_block_dec tls_dec;
		struct dtls_block_dec dtls_dec;
	};
	uint32_t iv[4];
	uint32_t end_index[0];
};

/**
 * struct tls_stream_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream encapsulation PDB
 *                         part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 */
struct tls_stream_enc {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
};

/**
 * struct tls_stream_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream decapsulation PDB
 *                         part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 */
struct tls_stream_dec {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
};

/**
 * struct tls_stream_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream
 *                         encapsulation / decapsulation PDB.
 * @seq_num: protocol sequence number
 * @end_index: the zero-length array expands for ICVLen if SEC ERA is equal or
 *             greater than SEC ERA 5 and TLS_PDBOPTS_TR_ICV is set in the PDB
 *             Options Byte.
 */
struct tls_stream_pdb {
	union {
		struct tls_stream_enc enc;
		struct tls_stream_dec dec;
	};
	uint64_t seq_num;
	uint32_t end_index[0];
};

/**
 * struct tls_ctr_enc - TLS1.1/TLS1.2 AES CTR encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls_ctr_enc {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};

/**
 * struct tls_ctr - PDB part for TLS1.1/TLS1.2 AES CTR decapsulation and
 *                  DTLS1.0 AES CTR encapsulation/decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ctr {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct tls_ctr {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_ctr_pdb - TLS1.1/TLS1.2/DTLS1.0 AES CTR
 *                      encapsulation / decapsulation PDB.
 * @write_iv: server write IV / client write IV
 * @constant: constant equal to 0x0000
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options Byte.
 *             If TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands
 *             for ICVLen.
 *
 * TLS1.1/TLS1.2/DTLS1.0 AES CTR encryption processing is supported starting
 * with SEC ERA 5.
 */
struct tls_ctr_pdb {
	union {
		struct tls_ctr_enc tls_enc;
		struct tls_ctr ctr;
	};
	uint32_t write_iv_hi;
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint16_t write_iv_lo;
			uint16_t constant;
#else
			uint16_t constant;
			uint16_t write_iv_lo;
#endif
		};
		uint32_t word1;
	};
	uint32_t end_index[0];
};

/**
 * struct tls12_gcm_encap - TLS1.2 AES GCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_gcm_encap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};

/**
 * struct tls12_gcm_decap - TLS1.2 AES GCM decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_gcm_decap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};

/**
 * struct dtls_gcm - DTLS1.0 AES GCM encapsulation / decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_gcm {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_gcm {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_gcm_pdb - TLS1.2/DTLS1.0 AES GCM encapsulation / decapsulation PDB
 * @salt: 4-byte salt
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands for
 *             ICVLen.
 */
struct tls_gcm_pdb {
	union {
		struct tls12_gcm_encap tls12_enc;
		struct tls12_gcm_decap tls12_dec;
		struct dtls_gcm dtls;
	};
	uint32_t salt;
	uint32_t end_index[0];
};

/**
 * struct tls12_ccm_encap - TLS1.2 AES CCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_ccm_encap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};

/**
 * struct tls_ccm - PDB part for TLS12 AES CCM decapsulation PDB and
 *                  DTLS1.0 AES CCM encapsulation / decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ccm {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct tls_ccm {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_ccm_pdb - TLS1.2/DTLS1.0 AES CCM encapsulation / decapsulation PDB
 * @write_iv: server write IV / client write IV
 * @b0_flags: use 0x5A for 8-byte ICV, 0x7A for 16-byte ICV
 * @ctr0_flags: equal to 0x2
 * @rsvd: reserved, do not use
 * @ctr0: CR0 lower 3 bytes, set to 0
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands for
 *             ICVLen.
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ccm_pdb {
	union {
		struct tls12_ccm_encap tls12;
		struct tls_ccm ccm;
	};
	uint32_t write_iv;
	union {
		struct {
			uint8_t b0_flags;
			uint8_t ctr0_flags;
			uint8_t rsvd1[2];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint8_t rsvd2;
			uint8_t ctr0[3];
		};
		uint32_t word2;
	};
	uint32_t end_index[0];
};
#else
struct tls_ccm_pdb {
	union {
		struct tls12_ccm_encap tls12;
		struct tls_ccm ccm;
	};
	uint32_t write_iv;
	union {
		struct {
			uint8_t rsvd1[2];
			uint8_t ctr0_flags;
			uint8_t b0_flags;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint8_t ctr0[3];
			uint8_t rsvd2;
		};
		uint32_t word2;
	};
	uint32_t end_index[0];
};
#endif

static inline uint8_t __rta_tls_pdb_ars(uint32_t options)
{
	uint8_t ars = 0;

	switch (options & DTLS_PDBOPTS_ARS_MASK) {
	case DTLS_PDBOPTS_ARS32:
	case DTLS_PDBOPTS_ARS64:
		ars = 2;
		break;

	case DTLS_PDBOPTS_ARS128:
		ars = 4;
		break;

	default:
		pr_err("Invalid AntiReplay Window size in options: 0x%08x\n",
		       options);
		break;
	}

	return ars;
}
static inline void __rta_copy_tls_block_pdb(struct program *p, void *pdb,
					    uint32_t protid)
{
	struct tls_block_pdb *block_pdb = (struct tls_block_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_SSL30:
	case OP_PCLID_TLS10:
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		__rta_out32(p, block_pdb->tls_enc.word1);
		__rta_out64(p, true, block_pdb->tls_enc.seq_num);
		break;

	case OP_PCLID_DTLS10:
		__rta_out32(p, block_pdb->dtls_enc.word1);
		__rta_out32(p, block_pdb->dtls_enc.word2);
		__rta_out32(p, block_pdb->dtls_enc.seq_num_lo);

		if (!encap)
			ars = __rta_tls_pdb_ars(block_pdb->dtls_dec.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	rta_copy_data(p, block_pdb->iv, sizeof(block_pdb->iv));

	/* Copy 0, 2 or 4 words of AR scorecard */
	for (i = 0; i < ars; i++)
		__rta_out32(p, block_pdb->end_index[i]);

	/* If ICV is truncated, then another word is needed */
	if (block_pdb->tls_enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, block_pdb->end_index[i]);
}

static inline void __rta_copy_tls_stream_pdb(struct program *p, void *pdb,
					     uint32_t protid)
{
	struct tls_stream_pdb *stream_pdb = (struct tls_stream_pdb *)pdb;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_SSL30:
	case OP_PCLID_TLS10:
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		__rta_out32(p, stream_pdb->enc.word1);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out64(p, true, stream_pdb->seq_num);

	/* If ICV is truncated, then another word is needed */
	if (stream_pdb->enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, stream_pdb->end_index[i]);
}

static inline void __rta_copy_tls_ctr_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_ctr_pdb *ctr_pdb = (struct tls_ctr_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		if (encap) {
			__rta_out32(p, ctr_pdb->tls_enc.word1);
			__rta_out64(p, true, ctr_pdb->tls_enc.seq_num);
		} else {
			__rta_out32(p, ctr_pdb->ctr.word1);
			__rta_out32(p, ctr_pdb->ctr.word2);
			__rta_out32(p, ctr_pdb->ctr.seq_num_lo);
		}

		break;

	case OP_PCLID_DTLS10:
		__rta_out32(p, ctr_pdb->ctr.word1);
		__rta_out32(p, ctr_pdb->ctr.word2);
		__rta_out32(p, ctr_pdb->ctr.seq_num_lo);

		if (!encap)
			ars = __rta_tls_pdb_ars(ctr_pdb->ctr.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out32(p, ctr_pdb->word1);

	/* Copy 0, 2 or 4 words of AR scorecard */
	for (i = 0; i < ars; i++)
		__rta_out32(p, ctr_pdb->end_index[i]);

	/* If ICV is truncated, then another word is needed */
	if (ctr_pdb->ctr.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, ctr_pdb->end_index[i]);
}

static inline void __rta_copy_tls_gcm_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_gcm_pdb *gcm_pdb = (struct tls_gcm_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS12:
		__rta_out32(p, gcm_pdb->tls12_enc.word1);
		__rta_out64(p, true, gcm_pdb->tls12_enc.seq_num);
		break;

	case OP_PCLID_DTLS10:
		__rta_out32(p, gcm_pdb->dtls.word1);
		__rta_out32(p, gcm_pdb->dtls.word2);
		__rta_out32(p, gcm_pdb->dtls.seq_num_lo);

		if (!encap)
			ars = __rta_tls_pdb_ars(gcm_pdb->dtls.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out32(p, gcm_pdb->salt);

	/* Copy 0, 2 or 4 words of AR scorecard */
	for (i = 0; i < ars; i++)
		__rta_out32(p, gcm_pdb->end_index[i]);

	/* If ICV is truncated, then another word is needed */
	if (gcm_pdb->tls12_enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, gcm_pdb->end_index[i]);
}

static inline void __rta_copy_tls_ccm_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_ccm_pdb *ccm_pdb = (struct tls_ccm_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS12:
		if (encap) {
			__rta_out32(p, ccm_pdb->tls12.word1);
			__rta_out64(p, true, ccm_pdb->tls12.seq_num);
		} else {
			__rta_out32(p, ccm_pdb->ccm.word1);
			__rta_out32(p, ccm_pdb->ccm.word2);
			__rta_out32(p, ccm_pdb->ccm.seq_num_lo);
		}
		break;

	case OP_PCLID_DTLS10:
		__rta_out32(p, ccm_pdb->ccm.word1);
		__rta_out32(p, ccm_pdb->ccm.word2);
		__rta_out32(p, ccm_pdb->ccm.seq_num_lo);

		if (!encap)
			ars = __rta_tls_pdb_ars(ccm_pdb->ccm.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out32(p, ccm_pdb->write_iv);
	__rta_out32(p, ccm_pdb->word1);
	__rta_out32(p, ccm_pdb->word2);

	/* Copy 0, 2 or 4 words of AR scorecard */
	for (i = 0; i < ars; i++)
		__rta_out32(p, ccm_pdb->end_index[i]);

	/* If ICV is truncated, then another word is needed */
	if (ccm_pdb->ccm.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, ccm_pdb->end_index[i]);
}

static inline __rta_copy_tls_pdb(struct program *p, void *pdb,
				 struct protcmd *protcmd)
{
	uint16_t protinfo = protcmd->protinfo;
	uint32_t protid = protcmd->protid;

	switch (protinfo) {
	case OP_PCL_SSL30_AES_128_GCM_SHA256_1:
	case OP_PCL_SSL30_AES_256_GCM_SHA384_1:
	case OP_PCL_SSL30_AES_128_GCM_SHA256_2:
	case OP_PCL_SSL30_AES_256_GCM_SHA384_2:
	case OP_PCL_SSL30_AES_128_GCM_SHA256_3:
	case OP_PCL_SSL30_AES_256_GCM_SHA384_3:
	case OP_PCL_SSL30_AES_128_GCM_SHA256_4:
	case OP_PCL_SSL30_AES_256_GCM_SHA384_4:
	case OP_PCL_SSL30_AES_128_GCM_SHA256_5:
	case OP_PCL_SSL30_AES_256_GCM_SHA384_5:
	case OP_PCL_SSL30_AES_128_GCM_SHA256_6:
	case OP_PCL_TLS_DH_ANON_AES_256_GCM_SHA384:
	case OP_PCL_TLS_PSK_AES_128_GCM_SHA256:
	case OP_PCL_TLS_PSK_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DHE_PSK_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DHE_PSK_AES_256_GCM_SHA384:
	case OP_PCL_TLS_RSA_PSK_AES_128_GCM_SHA256:
	case OP_PCL_TLS_RSA_PSK_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDHE_ECDSA_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDHE_ECDSA_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDH_ECDSA_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDH_ECDSA_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDHE_RSA_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDHE_RSA_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDH_RSA_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDH_RSA_AES_256_GCM_SHA384:
		__rta_copy_tls_gcm_pdb(p, pdb, protid);
		break;

	case OP_PCL_SSL30_RC4_128_MD5:
	case OP_PCL_SSL30_RC4_128_MD5_2:
	case OP_PCL_SSL30_RC4_128_MD5_3:
	case OP_PCL_SSL30_RC4_40_MD5:
	case OP_PCL_SSL30_RC4_40_MD5_2:
	case OP_PCL_SSL30_RC4_40_MD5_3:
	case OP_PCL_SSL30_RC4_128_SHA:
	case OP_PCL_SSL30_RC4_128_SHA_2:
	case OP_PCL_SSL30_RC4_128_SHA_3:
	case OP_PCL_SSL30_RC4_128_SHA_4:
	case OP_PCL_SSL30_RC4_128_SHA_5:
	case OP_PCL_SSL30_RC4_128_SHA_6:
	case OP_PCL_SSL30_RC4_128_SHA_7:
	case OP_PCL_SSL30_RC4_128_SHA_8:
	case OP_PCL_SSL30_RC4_128_SHA_9:
	case OP_PCL_SSL30_RC4_128_SHA_10:
	case OP_PCL_SSL30_RC4_40_SHA:
		__rta_copy_tls_stream_pdb(p, pdb, protid);
		break;

	case OP_PCL_SSL30_AES_128_CBC_SHA:
	case OP_PCL_SSL30_AES_128_CBC_SHA_2:
	case OP_PCL_SSL30_AES_128_CBC_SHA_3:
	case OP_PCL_SSL30_AES_128_CBC_SHA_4:
	case OP_PCL_SSL30_AES_128_CBC_SHA_5:
	case OP_PCL_SSL30_AES_128_CBC_SHA_6:
	case OP_PCL_SSL30_AES_128_CBC_SHA_7:
	case OP_PCL_SSL30_AES_128_CBC_SHA_8:
	case OP_PCL_SSL30_AES_128_CBC_SHA_9:
	case OP_PCL_SSL30_AES_128_CBC_SHA_10:
	case OP_PCL_SSL30_AES_128_CBC_SHA_11:
	case OP_PCL_SSL30_AES_128_CBC_SHA_12:
	case OP_PCL_SSL30_AES_128_CBC_SHA_13:
	case OP_PCL_SSL30_AES_128_CBC_SHA_14:
	case OP_PCL_SSL30_AES_128_CBC_SHA_15:
	case OP_PCL_SSL30_AES_128_CBC_SHA_16:
	case OP_PCL_SSL30_AES_128_CBC_SHA_17:
	case OP_PCL_SSL30_AES_256_CBC_SHA:
	case OP_PCL_SSL30_AES_256_CBC_SHA_2:
	case OP_PCL_SSL30_AES_256_CBC_SHA_3:
	case OP_PCL_SSL30_AES_256_CBC_SHA_4:
	case OP_PCL_SSL30_AES_256_CBC_SHA_5:
	case OP_PCL_SSL30_AES_256_CBC_SHA_6:
	case OP_PCL_SSL30_AES_256_CBC_SHA_7:
	case OP_PCL_SSL30_AES_256_CBC_SHA_8:
	case OP_PCL_SSL30_AES_256_CBC_SHA_9:
	case OP_PCL_SSL30_AES_256_CBC_SHA_10:
	case OP_PCL_SSL30_AES_256_CBC_SHA_11:
	case OP_PCL_SSL30_AES_256_CBC_SHA_12:
	case OP_PCL_SSL30_AES_256_CBC_SHA_13:
	case OP_PCL_SSL30_AES_256_CBC_SHA_14:
	case OP_PCL_SSL30_AES_256_CBC_SHA_15:
	case OP_PCL_SSL30_AES_256_CBC_SHA_16:
	case OP_PCL_SSL30_AES_256_CBC_SHA_17:
	case OP_PCL_TLS_PSK_AES_128_CBC_SHA256:
	case OP_PCL_TLS_PSK_AES_256_CBC_SHA384:
	case OP_PCL_TLS_DHE_PSK_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DHE_PSK_AES_256_CBC_SHA384:
	case OP_PCL_TLS_RSA_PSK_AES_128_CBC_SHA256:
	case OP_PCL_TLS_RSA_PSK_AES_256_CBC_SHA384:
	case OP_PCL_SSL30_3DES_EDE_CBC_MD5:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_2:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_3:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_4:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_5:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_6:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_7:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_8:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_9:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_10:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_11:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_12:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_13:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_14:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_15:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_16:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_17:
	case OP_PCL_SSL30_3DES_EDE_CBC_SHA_18:
	case OP_PCL_SSL30_DES40_CBC_MD5:
	case OP_PCL_SSL30_DES_CBC_MD5:
	case OP_PCL_SSL30_DES40_CBC_SHA:
	case OP_PCL_SSL30_DES40_CBC_SHA_2:
	case OP_PCL_SSL30_DES40_CBC_SHA_3:
	case OP_PCL_SSL30_DES40_CBC_SHA_4:
	case OP_PCL_SSL30_DES40_CBC_SHA_5:
	case OP_PCL_SSL30_DES40_CBC_SHA_6:
	case OP_PCL_SSL30_DES40_CBC_SHA_7:
	case OP_PCL_SSL30_DES_CBC_SHA:
	case OP_PCL_SSL30_DES_CBC_SHA_2:
	case OP_PCL_SSL30_DES_CBC_SHA_3:
	case OP_PCL_SSL30_DES_CBC_SHA_4:
	case OP_PCL_SSL30_DES_CBC_SHA_5:
	case OP_PCL_SSL30_DES_CBC_SHA_6:
	case OP_PCL_SSL30_DES_CBC_SHA_7:
	case OP_PCL_TLS_ECDHE_ECDSA_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_ECDSA_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDH_ECDSA_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDH_ECDSA_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDHE_RSA_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_RSA_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDH_RSA_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDH_RSA_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDHE_PSK_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_PSK_AES_256_CBC_SHA384:
		__rta_copy_tls_block_pdb(p, pdb, protid);
		break;

	default:
		pr_err("Invalid protinfo 0x%08x\n", protinfo);
	}
}

/**
 * cnstr_shdsc_tls - TLS family block cipher encapsulation / decapsulation
 *                   shared descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb: pointer to the PDB to be used in this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the block guide
 *       for details of the PDB.
 * @pdb_len: the length of the Protocol Data Block in bytes
 * @protcmd: pointer to Protocol Operation Command definitions
 * @cipherdata: pointer to block cipher transform definitions
 * @authdata: pointer to authentication transform definitions
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * The following built-in protocols are supported:
 * SSL3.0 / TLS1.0 / TLS1.1 / TLS1.2 / DTLS10
 */
static inline int cnstr_shdsc_tls(uint32_t *descbuf, bool ps, bool swap,
				  uint8_t *pdb, unsigned pdb_len,
				  struct protcmd *protcmd,
				  struct alginfo *cipherdata,
				  struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;

	LABEL(pdb_end);
	LABEL(keyjmp);
	REFERENCE(phdr);
	REFERENCE(pkeyjmp);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);
	__rta_copy_tls_pdb(p, pdb, protcmd);
	SET_LABEL(p, pdb_end);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH|SHRD|SELF);
	/*
	 * SSL3.0 uses SSL-MAC (SMAC) instead of HMAC, thus MDHA Split Key
	 * does not apply.
	 */
	if (protcmd->protid == OP_PCLID_SSL30)
		KEY(p, KEY2, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	else
		KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, protcmd->optype, protcmd->protid, protcmd->protinfo);

	PATCH_HDR(p, phdr, pdb_end);
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_TLS_H__ */
