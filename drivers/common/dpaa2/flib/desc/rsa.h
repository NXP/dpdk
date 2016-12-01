/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_RSA_H__
#define __DESC_RSA_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: RSA Shared Descriptor Constructors
 *
 * Shared descriptors for RSA algorithm.
 */

/**
 * enum rsa_decrypt_form - Type selectors for decrypt forms in RSA protocol
 * @RSA_DECRYPT_FORM1: g, f, n, d
 * @RSA_DECRYPT_FORM2: g, f, d, p, q, tmp1, tmp2
 * @RSA_DECRYPT_FORM3: g, f, c, p, q, dp, dq, tmp1, tmp2
 */
enum rsa_decrypt_form {
	RSA_DECRYPT_FORM1 = 1,
	RSA_DECRYPT_FORM2,
	RSA_DECRYPT_FORM3
};

/*
 * RSA encryption/decryption PDB definitions.
 */

#define RSA_ENC_SGF_SHIFT	28
#define RSA_ENC_RSV_SHIFT	24
#define RSA_ENC_E_LEN_SHIFT	12

/**
 * struct rsa_encrypt_pdb_64b - RSA encryption PDB for 64 bits addresses
 * @header: contains sgf, rsv, #e, #n fields
 * @f_ref_high: reference to input (upper 32 bits)
 * @f_ref_low: reference to input (lower 32 bits)
 * @g_ref_high: reference to output (upper 32 bits)
 * @g_ref_low: reference to output (lower 32 bits)
 * @n_ref_high: reference to modulus (upper 32 bits)
 * @n_ref_low: reference to modulus (lower 32 bits)
 * @e_ref_high: reference to public key (upper 32 bits)
 * @e_ref_low: reference to public key (lower 32 bits)
 * @f_len: input length
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct rsa_encrypt_pdb_64b {
	uint32_t header;
	union {
		struct {
			uint32_t f_ref_high;
			uint32_t f_ref_low;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t g_ref_high;
			uint32_t g_ref_low;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t n_ref_high;
			uint32_t n_ref_low;
		};
		uint64_t n_ref;
	};
	union {
		struct {
			uint32_t e_ref_high;
			uint32_t e_ref_low;
		};
		uint64_t e_ref;
	};
	uint32_t f_len;
};
#else
struct rsa_encrypt_pdb_64b {
	uint32_t header;
	union {
		struct {
			uint32_t f_ref_low;
			uint32_t f_ref_high;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t g_ref_low;
			uint32_t g_ref_high;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t n_ref_low;
			uint32_t n_ref_high;
		};
		uint64_t n_ref;
	};
	union {
		struct {
			uint32_t e_ref_low;
			uint32_t e_ref_high;
		};
		uint64_t e_ref;
	};
	uint32_t f_len;
};
#endif

/**
 * struct rsa_encrypt_pdb - RSA encryption PDB for 32 bits addresses
 * @header: contains sgf, rsv, #e, #n fields
 * @f_ref: reference to input
 * @g_ref: reference to output
 * @n_ref: reference to modulus
 * @e_ref: reference to public key
 * @f_len: input length
 */
struct rsa_encrypt_pdb {
	uint32_t header;
	uint32_t f_ref;
	uint32_t g_ref;
	uint32_t n_ref;
	uint32_t e_ref;
	uint32_t f_len;
};

#define RSA_DEC1_SGF_SHIFT	28
#define RSA_DEC1_RSV_SHIFT	24
#define RSA_DEC1_D_LEN_SHIFT	12

/**
 * struct rsa_dec_pdb_form1_64b - RSA decryption form1 PDB for 64 bits addresses
 * @header: contains sgf, rsv, #d, #n fields
 * @g_ref_high: reference to input (upper 32 bits)
 * @g_ref_low: reference to input (lower 32 bits)
 * @f_ref_high: reference to output (upper 32 bits)
 * @f_ref_low: reference to output (lower 32 bits)
 * @n_ref_high: reference to modulus (upper 32 bits)
 * @n_ref_low: reference to modulus (lower 32 bits)
 * @d_ref_high: reference to private key (upper 32 bits)
 * @d_ref_low: reference to private key (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct rsa_dec_pdb_form1_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_high;
			uint32_t g_ref_low;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_high;
			uint32_t f_ref_low;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t n_ref_high;
			uint32_t n_ref_low;
		};
		uint64_t n_ref;
	};
	union {
		struct {
			uint32_t d_ref_high;
			uint32_t d_ref_low;
		};
		uint64_t d_ref;
	};
};
#else
struct rsa_dec_pdb_form1_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_low;
			uint32_t g_ref_high;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_low;
			uint32_t f_ref_high;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t n_ref_low;
			uint32_t n_ref_high;
		};
		uint64_t n_ref;
	};
	union {
		struct {
			uint32_t d_ref_low;
			uint32_t d_ref_high;
		};
		uint64_t d_ref;
	};
};
#endif

/**
 * struct rsa_dec_pdb_form1 - RSA decryption form1 PDB for 32 bits addresses
 * @header: contains sgf, rsv, #d, #n fields
 * @g_ref: reference to input
 * @f_ref: reference to output
 * @n_ref: reference to modulus
 * @d_ref: reference to private key
 */
struct rsa_dec_pdb_form1 {
	uint32_t header;
	uint32_t g_ref;
	uint32_t f_ref;
	uint32_t n_ref;
	uint32_t d_ref;
};

#define RSA_DEC2_SGF_SHIFT	25
#define RSA_DEC2_D_LEN_SHIFT	12
#define RSA_DEC2_Q_LEN_SHIFT	12

/**
 * struct rsa_dec_pdb_form2_64b - RSA decryption form2 PDB for 64 bits addresses
 * @header: contains sgf, rsv, #d, #n fields
 * @g_ref_high: reference to input (upper 32 bits)
 * @g_ref_low: reference to input (lower 32 bits)
 * @f_ref_high: reference to output (upper 32 bits)
 * @f_ref_low: reference to output (lower 32 bits)
 * @d_ref_high: reference to private key (upper 32 bits)
 * @d_ref_low: reference to private key (lower 32 bits)
 * @p_ref_high: reference to prime p (upper 32 bits)
 * @p_ref_low: reference to prime p (lower 32 bits)
 * @q_ref_high: reference to prime q (upper 32 bits)
 * @q_ref_low: reference to prime q (lower 32 bits)
 * @tmp1_ref_high: reference to tmp1 (upper 32 bits)
 * @tmp1_ref_low: reference to tmp1 (lower 32 bits)
 * @tmp2_ref_high: reference to tmp2 (upper 32 bits)
 * @tmp2_ref_low: reference to tmp2 (lower 32 bits)
 * @trailer: contains rsv, #q, #p fields
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct rsa_dec_pdb_form2_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_high;
			uint32_t g_ref_low;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_high;
			uint32_t f_ref_low;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t d_ref_high;
			uint32_t d_ref_low;
		};
		uint64_t d_ref;
	};
	union {
		struct {
			uint32_t p_ref_high;
			uint32_t p_ref_low;
		};
		uint64_t p_ref;
	};
	union {
		struct {
			uint32_t q_ref_high;
			uint32_t q_ref_low;
		};
		uint64_t q_ref;
	};
	union {
		struct {
			uint32_t tmp1_ref_high;
			uint32_t tmp1_ref_low;
		};
		uint64_t tmp1_ref;
	};
	union {
		struct {
			uint32_t tmp2_ref_high;
			uint32_t tmp2_ref_low;
		};
		uint64_t tmp2_ref;
	};
	uint32_t trailer;
};
#else
struct rsa_dec_pdb_form2_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_low;
			uint32_t g_ref_high;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_low;
			uint32_t f_ref_high;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t d_ref_low;
			uint32_t d_ref_high;
		};
		uint64_t d_ref;
	};
	union {
		struct {
			uint32_t p_ref_low;
			uint32_t p_ref_high;
		};
		uint64_t p_ref;
	};
	union {
		struct {
			uint32_t q_ref_low;
			uint32_t q_ref_high;
		};
		uint64_t q_ref;
	};
	union {
		struct {
			uint32_t tmp1_ref_low;
			uint32_t tmp1_ref_high;
		};
		uint64_t tmp1_ref;
	};
	union {
		struct {
			uint32_t tmp2_ref_low;
			uint32_t tmp2_ref_high;
		};
		uint64_t tmp2_ref;
	};
	uint32_t trailer;
};
#endif

/**
 * struct rsa_dec_pdb_form2 - RSA decryption form2 PDB for 32 bits addresses
 * @header: contains sgf, rsv, #d, #n fields
 * @g_ref: reference to input
 * @f_ref: reference to output
 * @d_ref: reference to private key
 * @p_ref: reference to prime p
 * @q_ref: reference to prime q
 * @tmp1_ref: reference to tmp1
 * @tmp2_ref: reference to tmp2
 * @trailer: contains rsv, #q, #p fields
 */
struct rsa_dec_pdb_form2 {
	uint32_t header;
	uint32_t g_ref;
	uint32_t f_ref;
	uint32_t d_ref;
	uint32_t p_ref;
	uint32_t q_ref;
	uint32_t tmp1_ref;
	uint32_t tmp2_ref;
	uint32_t trailer;
};

#define RSA_DEC3_SGF_SHIFT	25
#define RSA_DEC3_Q_LEN_SHIFT	12

/**
 * struct rsa_dec_pdb_form3_64b - RSA decryption form3 PDB for 64 bits addresses
 * @header: contains sgf, rsv, #n fields
 * @g_ref_high: reference to input (upper 32 bits)
 * @g_ref_low: reference to input (lower 32 bits)
 * @f_ref_high: reference to output (upper 32 bits)
 * @f_ref_low: reference to output (lower 32 bits)
 * @c_ref_high: reference to c (upper 32 bits)
 * @c_ref_low: reference to c (lower 32 bits)
 * @p_ref_high: reference to prime p (upper 32 bits)
 * @p_ref_low: reference to prime p (lower 32 bits)
 * @q_ref_high: reference to prime q (upper 32 bits)
 * @q_ref_low: reference to prime q (lower 32 bits)
 * @dp_ref_high: reference to dp (upper 32 bits)
 * @dp_ref_low: reference to dp (lower 32 bits)
 * @dq_ref_high: reference to dq (upper 32 bits)
 * @dq_ref_low: reference to dq (lower 32 bits)
 * @tmp1_ref_high: reference to tmp1 (upper 32 bits)
 * @tmp1_ref_low: reference to tmp1 (lower 32 bits)
 * @tmp2_ref_high: reference to tmp2 (upper 32 bits)
 * @tmp2_ref_low: reference to tmp2 (lower 32 bits)
 * @trailer: contains rsv, #q, #p fields
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct rsa_dec_pdb_form3_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_high;
			uint32_t g_ref_low;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_high;
			uint32_t f_ref_low;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t c_ref_high;
			uint32_t c_ref_low;
		};
		uint64_t c_ref;
	};
	union {
		struct {
			uint32_t p_ref_high;
			uint32_t p_ref_low;
		};
		uint64_t p_ref;
	};
	union {
		struct {
			uint32_t q_ref_high;
			uint32_t q_ref_low;
		};
		uint64_t q_ref;
	};
	union {
		struct {
			uint32_t dp_ref_high;
			uint32_t dp_ref_low;
		};
		uint64_t dp_ref;
	};
	union {
		struct {
			uint32_t dq_ref_high;
			uint32_t dq_ref_low;
		};
		uint64_t dq_ref;
	};
	union {
		struct {
			uint32_t tmp1_ref_high;
			uint32_t tmp1_ref_low;
		};
		uint64_t tmp1_ref;
	};
	union {
		struct {
			uint32_t tmp2_ref_high;
			uint32_t tmp2_ref_low;
		};
		uint64_t tmp2_ref;
	};
	uint32_t trailer;
};
#else
struct rsa_dec_pdb_form3_64b {
	uint32_t header;
	union {
		struct {
			uint32_t g_ref_low;
			uint32_t g_ref_high;
		};
		uint64_t g_ref;
	};
	union {
		struct {
			uint32_t f_ref_low;
			uint32_t f_ref_high;
		};
		uint64_t f_ref;
	};
	union {
		struct {
			uint32_t c_ref_low;
			uint32_t c_ref_high;
		};
		uint64_t c_ref;
	};
	union {
		struct {
			uint32_t p_ref_low;
			uint32_t p_ref_high;
		};
		uint64_t p_ref;
	};
	union {
		struct {
			uint32_t q_ref_low;
			uint32_t q_ref_high;
		};
		uint64_t q_ref;
	};
	union {
		struct {
			uint32_t dp_ref_low;
			uint32_t dp_ref_high;
		};
		uint64_t dp_ref;
	};
	union {
		struct {
			uint32_t dq_ref_low;
			uint32_t dq_ref_high;
		};
		uint64_t dq_ref;
	};
	union {
		struct {
			uint32_t tmp1_ref_low;
			uint32_t tmp1_ref_high;
		};
		uint64_t tmp1_ref;
	};
	union {
		struct {
			uint32_t tmp2_ref_low;
			uint32_t tmp2_ref_high;
		};
		uint64_t tmp2_ref;
	};
	uint32_t trailer;
};
#endif
/**
 * struct rsa_dec_pdb_form3 - RSA decryption form3 PDB for 32 bits addresses
 * @header: contains sgf, rsv, #n fields
 * @g_ref: reference to input
 * @f_ref: reference to output
 * @c_ref: reference to c
 * @p_ref: reference to prime p
 * @q_ref: reference to prime q
 * @dp_ref: reference to dp
 * @dq_ref: reference to dq
 * @tmp1_ref: reference to tmp1
 * @tmp2_ref: reference to tmp2
 * @trailer: contains rsv, #q, #p fields
 */
struct rsa_dec_pdb_form3 {
	uint32_t header;
	uint32_t g_ref;
	uint32_t f_ref;
	uint32_t c_ref;
	uint32_t p_ref;
	uint32_t q_ref;
	uint32_t dp_ref;
	uint32_t dq_ref;
	uint32_t tmp1_ref;
	uint32_t tmp2_ref;
	uint32_t trailer;
};

static inline void __rta_copy_rsa_encrypt_pdb(struct program *p, void *pdb)
{
	if (p->ps) {
		struct rsa_encrypt_pdb_64b *encrypt_pdb =
					(struct rsa_encrypt_pdb_64b *)pdb;
		__rta_out32(p, encrypt_pdb->header);
		__rta_out64(p, true, encrypt_pdb->f_ref);
		__rta_out64(p, true, encrypt_pdb->g_ref);
		__rta_out64(p, true, encrypt_pdb->n_ref);
		__rta_out64(p, true, encrypt_pdb->e_ref);
		__rta_out32(p, encrypt_pdb->f_len);
	} else {
		struct rsa_encrypt_pdb *encrypt_pdb =
						(struct rsa_encrypt_pdb *)pdb;
		__rta_out32(p, encrypt_pdb->header);
		__rta_out32(p, encrypt_pdb->f_ref);
		__rta_out32(p, encrypt_pdb->g_ref);
		__rta_out32(p, encrypt_pdb->n_ref);
		__rta_out32(p, encrypt_pdb->e_ref);
		__rta_out32(p, encrypt_pdb->f_len);
	}
}

static inline void __rta_copy_rsa_decrypt_f1_pdb(struct program *p, void *pdb)
{
	if (p->ps) {
		struct rsa_dec_pdb_form1_64b *decrypt_pdb =
					(struct rsa_dec_pdb_form1_64b *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out64(p, true, decrypt_pdb->g_ref);
		__rta_out64(p, true, decrypt_pdb->f_ref);
		__rta_out64(p, true, decrypt_pdb->n_ref);
		__rta_out64(p, true, decrypt_pdb->d_ref);
	} else {
		struct rsa_dec_pdb_form1 *decrypt_pdb =
					(struct rsa_dec_pdb_form1 *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out32(p, decrypt_pdb->g_ref);
		__rta_out32(p, decrypt_pdb->f_ref);
		__rta_out32(p, decrypt_pdb->n_ref);
		__rta_out32(p, decrypt_pdb->d_ref);
	}
}

static inline void __rta_copy_rsa_decrypt_f2_pdb(struct program *p, void *pdb)
{
	if (p->ps) {
		struct rsa_dec_pdb_form2_64b *decrypt_pdb =
					(struct rsa_dec_pdb_form2_64b *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out64(p, true, decrypt_pdb->g_ref);
		__rta_out64(p, true, decrypt_pdb->f_ref);
		__rta_out64(p, true, decrypt_pdb->d_ref);
		__rta_out64(p, true, decrypt_pdb->p_ref);
		__rta_out64(p, true, decrypt_pdb->q_ref);
		__rta_out64(p, true, decrypt_pdb->tmp1_ref);
		__rta_out64(p, true, decrypt_pdb->tmp2_ref);
		__rta_out32(p, decrypt_pdb->trailer);
	} else {
		struct rsa_dec_pdb_form2 *decrypt_pdb =
					(struct rsa_dec_pdb_form2 *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out32(p, decrypt_pdb->g_ref);
		__rta_out32(p, decrypt_pdb->f_ref);
		__rta_out32(p, decrypt_pdb->d_ref);
		__rta_out32(p, decrypt_pdb->p_ref);
		__rta_out32(p, decrypt_pdb->q_ref);
		__rta_out32(p, decrypt_pdb->tmp1_ref);
		__rta_out32(p, decrypt_pdb->tmp2_ref);
		__rta_out32(p, decrypt_pdb->trailer);
	}
}

static inline void __rta_copy_rsa_decrypt_f3_pdb(struct program *p, void *pdb)
{
	if (p->ps) {
		struct rsa_dec_pdb_form3_64b *decrypt_pdb =
					(struct rsa_dec_pdb_form3_64b *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out64(p, true, decrypt_pdb->g_ref);
		__rta_out64(p, true, decrypt_pdb->f_ref);
		__rta_out64(p, true, decrypt_pdb->c_ref);
		__rta_out64(p, true, decrypt_pdb->p_ref);
		__rta_out64(p, true, decrypt_pdb->q_ref);
		__rta_out64(p, true, decrypt_pdb->dp_ref);
		__rta_out64(p, true, decrypt_pdb->dq_ref);
		__rta_out64(p, true, decrypt_pdb->tmp1_ref);
		__rta_out64(p, true, decrypt_pdb->tmp2_ref);
		__rta_out32(p, decrypt_pdb->trailer);
	} else {
		struct rsa_dec_pdb_form3 *decrypt_pdb =
					(struct rsa_dec_pdb_form3 *)pdb;

		__rta_out32(p, decrypt_pdb->header);
		__rta_out32(p, decrypt_pdb->g_ref);
		__rta_out32(p, decrypt_pdb->f_ref);
		__rta_out32(p, decrypt_pdb->c_ref);
		__rta_out32(p, decrypt_pdb->p_ref);
		__rta_out32(p, decrypt_pdb->q_ref);
		__rta_out32(p, decrypt_pdb->dp_ref);
		__rta_out32(p, decrypt_pdb->dq_ref);
		__rta_out32(p, decrypt_pdb->tmp1_ref);
		__rta_out32(p, decrypt_pdb->tmp2_ref);
		__rta_out32(p, decrypt_pdb->trailer);
	}
}

static inline void __rta_copy_rsa_decrypt_pdb(struct program *p, void *pdb,
					      uint16_t protinfo)
{
	switch (protinfo) {
	case OP_PCL_RSAPROT_OP_DEC_ND:
		__rta_copy_rsa_decrypt_f1_pdb(p, pdb);
		break;

	case OP_PCL_RSAPROT_OP_DEC_PQD:
		__rta_copy_rsa_decrypt_f2_pdb(p, pdb);
		break;

	case OP_PCL_RSAPROT_OP_DEC_PQDPDQC:
		__rta_copy_rsa_decrypt_f3_pdb(p, pdb);
		break;

	default:
		pr_err("Invalid RSA decrypt protinfo %d", protinfo);
		break;
	}
}

/**
 * cnstr_shdsc_rsa - Function for creating a RSA encryption/decryption shared
 *                   descriptor. Supports decryption implemented in 3 forms.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb: pointer to the Protocol Data Block to be used for descriptor
 *       construction. Must be mapped over a defined rsa structure. The PDB is
 *       assumed to be valid.
 * @pdb_len: size of the PDB in bytes
 * @protcmd: protocol Operation Command definitions
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_rsa(uint32_t *descbuf, bool ps, bool swap,
				  uint8_t *pdb, struct protcmd *protcmd)
{
	struct program prg;
	struct program *p = &prg;

	LABEL(phdr);
	REFERENCE(pdbend);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	phdr = SHR_HDR(p, SHR_SERIAL, pdbend, 0);

	if (protcmd->protid == OP_PCLID_RSAENCRYPT)
		__rta_copy_rsa_encrypt_pdb(p, pdb);
	else
		__rta_copy_rsa_decrypt_pdb(p, pdb, protcmd->protinfo);

	SET_LABEL(p, pdbend);
	PROTOCOL(p, protcmd->optype, protcmd->protid, protcmd->protinfo);
	PATCH_HDR(p, phdr, pdbend);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_RSA_H__ */
