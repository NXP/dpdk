/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_WIFI_H__
#define __DESC_WIFI_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: WiFi Shared Descriptor Constructors
 *
 * Shared descriptors for WiFi (802.11i) protocol.
 */

/*
 * IEEE 802.11 WiFi Protocol Data Block
 */
#define WIFI_PDBOPTS_FCS	0x01
#define WIFI_PDBOPTS_AR		0x40

/**
 * WIFI_B0_FLAGS - The value of B0 flags used for WiFi AES-CCM Context
 *                 construction.
 */
#define WIFI_B0_FLAGS			0x59

/**
 * WIFI_FRM_CTRL_MASK - The Frame Control Mask value used in computing the
 *                      additional authentication data (AAD).
 */
#define WIFI_FRM_CTRL_MASK		0x8fc7

/**
 * WIFI_SEQ_CTRL_MASK - The Sequence Control Mask value used in computing the
 *                      additional authentication data (AAD).
 */
#define WIFI_SEQ_CTRL_MASK		0x0f00

/**
 * WIFI_CTR_FLAGS - The value of Counter Flags used for CCM Counter block
 *                  construction.
 */
#define WIFI_CTR_FLAGS			0x01

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct wifi_encap_pdb {
	union {
		struct {
			uint16_t mac_hdr_len;	/* MAC Header Length - 24 or
						   30 bytes */
			uint8_t rsvd;		/* Reserver bits */
			uint8_t options;	/* Options byte */
		};
		uint32_t word1;
	};
	union {
		struct {
			uint8_t b0_flags;	/* CCM B0 block flags */
			uint8_t pri;		/* Frame Priority */
			uint16_t pn1;		/* Packet Number MS 16 bits */
		};
		uint32_t word2;
	};
	uint32_t pn2;				/* Packet Number LS 32 bits */
	union {
		struct {
			uint16_t frm_ctrl_mask; /* Frame Control mask */
			uint16_t seq_ctrl_mask; /* Sequence Control mask */
		};
		uint32_t word3;
	};
	union {
		struct {
			uint16_t rsvd1;		/* Reserved bits */
			uint8_t cnst;		/* CCM Counter block constant -
						   0x0000 */
			uint8_t key_id;		/* Key ID*/
		};
		uint32_t word4;
	};
	union {
		struct {
			uint8_t ctr_flags;	/* CCM Counter block flags */
			uint8_t rsvd2;		/* Reserved bits */
			uint16_t ctr_init;	/* CCM Counter block init
						   counter */
		};
		uint32_t word5;
	};
};
#else
struct wifi_encap_pdb {
	union {
		struct {
			uint8_t options;	/* Options byte */
			uint8_t rsvd;		/* Reserver bits */
			uint16_t mac_hdr_len;	/* MAC Header Length - 24 or
						   30 bytes */
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t pn1;		/* Packet Number MS 16 bits */
			uint8_t pri;		/* Frame Priority */
			uint8_t b0_flags;	/* CCM B0 block flags */
		};
		uint32_t word2;
	};
	uint32_t pn2;				/* Packet Number LS 32 bits */
	union {
		struct {
			uint16_t seq_ctrl_mask; /* Sequence Control mask */
			uint16_t frm_ctrl_mask; /* Frame Control mask */
		};
		uint32_t word3;
	};
	union {
		struct {
			uint8_t key_id;		/* Key ID*/
			uint8_t cnst;		/* CCM Counter block constant -
						   0x0000 */
			uint16_t rsvd1;		/* Reserved bits */
		};
		uint32_t word4;
	};
	union {
		struct {
			uint16_t ctr_init;	/* CCM Counter block init
						   counter */
			uint8_t rsvd2;		/* Reserved bits */
			uint8_t ctr_flags;	/* CCM Counter block flags */
		};
		uint32_t word5;
	};
};
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct wifi_decap_pdb {
	union {
		struct {
			uint16_t mac_hdr_len;	/* MAC Header Length - 24 or
						   30 bytes */
			uint8_t rsvd;		/* Reserver bits */
			uint8_t options;	/* Options byte */
		};
		uint32_t word1;
	};
	union {
		struct{
			uint8_t b0_flags;	/* CCM B0 block flags */
			uint8_t pri;		/* Frame Priority */
			uint16_t pn1;		/* Packet Number MS 16 bits */
		};
		uint32_t word2;
	};
	uint32_t pn2;		/* Packet Number LS 32 bits */
	union {
		struct {
			uint16_t frm_ctrl_mask; /* Frame Control mask */
			uint16_t seq_ctrl_mask; /* Sequence Control mask */
		};
		uint32_t word3;
	};
	uint32_t rsvd1;	    /* Reserved bits */
	union {
		struct {
			uint8_t ctr_flags;	/* CCM Counter block flags */
			uint8_t rsvd2;		/* Reserved bits */
			uint16_t ctr_init;	/* CCM Counter block init
						   counter */
		};
		uint32_t word4;
	};
};
#else
struct wifi_decap_pdb {
	union {
		struct {
			uint8_t options;	/* Options byte */
			uint8_t rsvd;		/* Reserver bits */
			uint16_t mac_hdr_len;	/* MAC Header Length - 24 or
						   30 bytes */
		};
		uint32_t word1;
	};
	union {
		struct{
			uint16_t pn1;		/* Packet Number MS 16 bits */
			uint8_t pri;		/* Frame Priority */
			uint8_t b0_flags;	/* CCM B0 block flags */
		};
		uint32_t word2;
	};
	uint32_t pn2;		/* Packet Number LS 32 bits */
	union {
		struct {
			uint16_t seq_ctrl_mask; /* Sequence Control mask */
			uint16_t frm_ctrl_mask; /* Frame Control mask */
		};
		uint32_t word3;
	};
	uint32_t rsvd1;	    /* Reserved bits */
	union {
		struct {
			uint16_t ctr_init;	/* CCM Counter block init
						   counter */
			uint8_t rsvd2;		/* Reserved bits */
			uint8_t ctr_flags;	/* CCM Counter block flags */
		};
		uint32_t word4;
	};
};
#endif

static inline void __rta_copy_wifi_encap_pdb(struct program *p,
					     struct wifi_encap_pdb *encap_pdb)
{
	__rta_out32(p, encap_pdb->word1);
	__rta_out32(p, encap_pdb->word2);
	__rta_out32(p, encap_pdb->pn2);
	__rta_out32(p, encap_pdb->word3);
	__rta_out32(p, encap_pdb->word4);
	__rta_out32(p, encap_pdb->word5);
}

static inline void __rta_copy_wifi_decap_pdb(struct program *p,
					     struct wifi_decap_pdb *decap_pdb)
{
	__rta_out32(p, decap_pdb->word1);
	__rta_out32(p, decap_pdb->word2);
	__rta_out32(p, decap_pdb->pn2);
	__rta_out32(p, decap_pdb->word3);
	__rta_out32(p, decap_pdb->rsvd1);
	__rta_out32(p, decap_pdb->word4);
}

/**
 * cnstr_shdsc_wifi_encap - IEEE 802.11i WiFi encapsulation
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @mac_hdr_len: PDB MAC header length (24 or 28 bytes)
 * @pn: PDB Packet Number
 * @priority: PDB Packet priority
 * @key_id: PDB Key ID
 * @cipherdata: block cipher transform definitions
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_wifi_encap(uint32_t *descbuf, bool ps, bool swap,
					 uint16_t mac_hdr_len, uint64_t pn,
					 uint8_t priority, uint8_t key_id,
					 struct alginfo *cipherdata)
{
	struct program prg;
	struct program *p = &prg;
	struct wifi_encap_pdb pdb;

	LABEL(pdbend);
	REFERENCE(phdr);
	LABEL(keyjump);
	REFERENCE(pkeyjump);
	LABEL(startloop);
	REFERENCE(pstartloop);

	memset(&pdb, 0, sizeof(struct wifi_encap_pdb));
	pdb.mac_hdr_len = mac_hdr_len;
	pdb.b0_flags = WIFI_B0_FLAGS;
	pdb.pri = priority;
	pdb.pn1 = (uint16_t)upper_32_bits(pn);
	pdb.pn2 = lower_32_bits(pn);
	pdb.frm_ctrl_mask = WIFI_FRM_CTRL_MASK;
	pdb.seq_ctrl_mask = WIFI_SEQ_CTRL_MASK;
	pdb.key_id = key_id;
	pdb.ctr_flags = WIFI_CTR_FLAGS;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, pdbend, SC);
	__rta_copy_wifi_encap_pdb(p, &pdb);
	SET_LABEL(p, pdbend);
	pkeyjump = JUMP(p, keyjump, LOCAL_JUMP, ALL_TRUE, SHRD | SELF);
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjump);
	PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_WIFI, OP_PCL_WIFI);

	/* Errata A-005487: PN is written in reverse order in CCM Header. */
	if (rta_sec_era <= RTA_SEC_ERA_5) {
		/*
		 * Copy MAC Header len in MATH2 and (Const + KeyID) in MATH3
		 * to be used later in CCMP header reconstruction.
		 */
		MATHB(p, ZERO, AND, MATH3, MATH3, 8, IFB|NFU);
		MOVE(p, DESCBUF, 0, MATH2, 0, 6, IMMED);
		MOVE(p, DESCBUF, 20, MATH3, 0, 4, IMMED);

		/*
		 * Protocol operation leaves in MATH0 the incremented PN as
		 * xx xx PN0 PN1 PN2 PN3 PN4 PN5. Before byte-reversing the
		 * MATH0, first the PN is decremented and transformed as
		 * PN0 PN1 PN2 PN3 00 00 PN4 PN5.
		 */
		MATHB(p, MATH0, SUB, ONE, MATH0, 8, IFB|NFU);
		MATHB(p, ZERO, ADD, MATH0, MATH1, 2, IFB|NFU);
		MATHB(p, MATH0, XOR, MATH1, MATH0, 8, IFB|NFU);
		MATHB(p, MATH0, LSHIFT, 16, MATH0, 8, IFB|NFU|IMMED2);
		MATHB(p, MATH1, OR, MATH0, MATH0, 8, IFB|NFU);

		/*
		 * Prepare to byte-reverse MATH0: copy MATH0 input into Input
		 * DATA FIFO and place loop value (8) into MATH1.
		 */
		LOAD(p, 0, DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0, IMMED);
		MOVE(p, MATH0, 0, IFIFOAB1, 0, 8, IMMED);
		LOAD(p, 0, DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0, IMMED);

		MOVE(p, IFIFOABD, 0, MATH0, 0, 1, IMMED);
		MATHB(p, ZERO, ADD, 8, MATH1, 4, IFB|NFU|IMMED2);
		MATHB(p, MATH1, SUB, ONE, VSEQINSZ, 4, IFB|NFU);

		/*
		 * loop to reverse MATH0 content from PN0 PN1 PN2 PN3 00 00
		 * PN4 PN5 --> PN5 PN4 00 00 PN3 PN2 PN1 PN0; during n-th
		 * iteration, right shift MATH0 with 8 bytes and copy into
		 * MATH0 at offset 0 the n-th byte from Input Data FIFO.
		 */
		SET_LABEL(p, startloop);
		MATHB(p, VSEQINSZ, SUB, ONE, VSEQINSZ, 4, IFB);
		MATHB(p, MATH0, RSHIFT, MATH1, MATH0, 8, IFB|NFU);
		MOVE(p, IFIFOABD, 0, MATH0, 0, 1, IMMED);
		JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, 0);
		pstartloop = JUMP(p, startloop, LOCAL_JUMP, ALL_FALSE, MATH_Z);

		/*
		 * Prepare to write the correct CCMP header to output frame.
		 * Copy MAC Header Len into VSOL and complete CCMP header in
		 * MATH3 with Const + keyID.
		 */
		MATHB(p, MATH2, RSHIFT, 16, VSEQOUTSZ, 2, IFB|NFU|IMMED2);
		MATHB(p, MATH0, OR, MATH3, MATH3, 8, IFB|NFU);

		/*
		 * write the correct CCMP header from MATH3 to output frame.
		 * set length for Ouput Sequence operation at 48B, larger than
		 * largest MAC header length(30) + CCMP header length(8)
		 */
		SEQOUTPTR(p, 0, 48, RTO);
		SEQFIFOSTORE(p, SKIP, 0, 0, VLF);
		SEQSTORE(p, MATH3, 0, 8, 0);

		PATCH_JUMP(p, pstartloop, startloop);
	}
	PATCH_HDR(p, phdr, pdbend);
	PATCH_JUMP(p, pkeyjump, keyjump);

	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_wifi_decap - IEEE 802.11 WiFi decapsulation
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @mac_hdr_len: PDB MAC header length (24 or 28 bytes)
 * @pn: PDB Packet Number
 * @priority: PDB Packet priority
 * @cipherdata: block cipher transform definitions
 *
 * Return: size of descriptor written in words or negative number on error
 **/
static inline int cnstr_shdsc_wifi_decap(uint32_t *descbuf, bool ps, bool swap,
					 uint16_t mac_hdr_len, uint64_t pn,
					 uint8_t priority,
					 struct alginfo *cipherdata)
{
	struct program prg;
	struct program *p = &prg;
	struct wifi_decap_pdb pdb;

	LABEL(phdr);
	REFERENCE(pdbend);
	LABEL(keyjump);
	REFERENCE(pkeyjump);

	memset(&pdb, 0x00, sizeof(struct wifi_encap_pdb));
	pdb.mac_hdr_len = mac_hdr_len;
	pdb.b0_flags = WIFI_B0_FLAGS;
	pdb.pri = priority;
	pdb.pn1 = (uint16_t)upper_32_bits(pn);
	pdb.pn2 = lower_32_bits(pn);
	pdb.frm_ctrl_mask = WIFI_FRM_CTRL_MASK;
	pdb.seq_ctrl_mask = WIFI_SEQ_CTRL_MASK;
	pdb.ctr_flags = WIFI_CTR_FLAGS;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	phdr = SHR_HDR(p, SHR_SERIAL, pdbend, SC);
	__rta_copy_wifi_decap_pdb(p, &pdb);
	SET_LABEL(p, pdbend);
	pkeyjump = JUMP(p, keyjump, LOCAL_JUMP, ALL_TRUE, SHRD | SELF);
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjump);
	PROTOCOL(p, OP_TYPE_DECAP_PROTOCOL, OP_PCLID_WIFI, OP_PCL_WIFI);

	PATCH_HDR(p, phdr, pdbend);
	PATCH_JUMP(p, pkeyjump, keyjump);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_WIFI_H__ */
