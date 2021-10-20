/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include <rte_common.h>

#include "bbdev_la12xx_feca_param.h"

static void
calc_int_start_ofst(uint32_t Q_m,
		    uint32_t rv_id,
		    uint32_t use_def_k0,
		    uint32_t N_cb,
		    uint32_t BGnumber,
		    uint32_t K,
		    uint32_t K_dash,
		    uint32_t Zc,
		    uint32_t e_div_qm,
		    uint32_t *ncb_eff,
		    uint32_t *int_start_ofst)
{
	uint32_t i, k0 = 0, num_filler_bits;
	uint32_t filler_end, filler_start, k0_eff;

	num_filler_bits = K - K_dash;
	if (use_def_k0 == 1)
		k0 = 0;
	else if (rv_id == 0)
		k0 = 0;
	else if (rv_id == 1)
		k0 = (BGnumber == 1) ?  ((17*N_cb)/(66*Zc))*Zc :
		     ((13*N_cb)/(50*Zc))*Zc;
	else if (rv_id == 2)
		k0 = (BGnumber == 1) ?  ((33*N_cb)/(66*Zc))*Zc :
		     ((25*N_cb)/(50*Zc))*Zc;
	else if (rv_id == 3)
		k0 = (BGnumber == 1) ?  ((56*N_cb)/(66*Zc))*Zc :
		     ((43*N_cb)/(50*Zc))*Zc;

	/* index after filler end */
	filler_end = K - (2 * Zc);
	/* index at filler_start */
	filler_start = filler_end - num_filler_bits;

	k0_eff = (k0 > filler_end) ? (k0 - num_filler_bits) :
		 (k0 > filler_start) ? filler_start : k0;

	*ncb_eff = (N_cb > filler_end) ? N_cb - num_filler_bits :
		   (N_cb > filler_start) ? filler_start : N_cb;

	for (i = 0; i < Q_m; i++)
		int_start_ofst[i] = (k0_eff + i*e_div_qm) % *ncb_eff;
	for (int i = Q_m; i < 8; i++)
		int_start_ofst[i] = 0;	// optional, not used
}

static void
offset_x1_x2(uint32_t c_init,
	     uint32_t offset,
	     uint32_t *X1,
	     uint32_t *X2)
{
	uint32_t n;
	uint32_t x1[100000];
	uint32_t x2[100000];

	for (n = 0; n < 31; n++) {
		x1[n] = 0;
		x2[n] = (c_init >> n) & 0x01;
	}
	x1[0] = 1;

	for (n = 0; n < offset; n++) {
		x1[n+31] = (x1[n+3] + x1[n]) & 0x01;
		x2[n+31] = (x2[n+3] + x2[n+2] + x2[n+1] + x2[n]) & 0x01;
	}

	*X1 = 0;
	*X2 = 0;
	for (n = 0; n < 31; n++) {
		*X1 ^= (x1[offset+n] << n);
		*X2 ^= (x2[offset+n] << n);
	}
}

static void
LDPC_evaluate_parameters(uint32_t A,
			 uint32_t BGnumber,
			 uint32_t *codeblock_mask,
			 uint32_t *B,
			 uint32_t *i_LS,
			 uint32_t *Zc,
			 uint32_t *N,
			 uint32_t *K,
			 uint32_t *K_dash,
			 uint32_t *C,
			 uint32_t *C_prime,
			 int16_t *TBS_VALID)
{
	static uint32_t Z[51] = {2, 4, 8, 16, 32, 64, 128, 256, 3, 6, 12, 24,
				48, 96, 192, 384, 5, 10, 20, 40, 80, 160, 320,
				7, 14, 28, 56, 112, 224, 9, 18, 36, 72, 144,
				288, 11, 22, 44, 88, 176, 352, 13, 26, 52, 104,
				208, 15, 30, 60, 120, 240};
	static uint32_t i_LS_vec[51] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
				       1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3,
				       3, 3, 3, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5,
				       5, 5, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7};
	uint32_t i, K_cb, K_b;

	/* find B */
	if (A > 3824)   // CRC 24-bits type A
		*B = A + 24;
	else		// CRC 16-bits
		*B = A + 16;

	/* find K_b, K_cb */
	if (BGnumber == 1) {
		K_cb = 8448;
		K_b = 22;
	} else {
		K_cb = 3840;
		if (*B > 640)
			K_b = 10;
		else if (*B > 560)
			K_b = 9;
		else if (*B > 192)
			K_b = 8;
		else
			K_b = 6;
	}

	/* find K_dash, C */
	if (*B <= K_cb) {	// single code block (no CRC)
		*C = 1;
		*K_dash = *B;
	} else {		// more thank one code block (CRC is added)
		*C = ((*B) / (K_cb-24)) + (((*B) % (K_cb-24)) != 0);
		*K_dash = ((*B)+(24*(*C)))/(*C);
	}

	/* find out Zc, i_LS */
	*Zc = 384;
	*i_LS = 1;
	for (i = 0; i < 51; i++) {
		if ((K_b*Z[i] >= (*K_dash)) && Z[i] < *Zc) {
			*Zc = Z[i];
			*i_LS = i_LS_vec[i];
		}
	}

	/* calculate K, N */
	if (BGnumber == 1) {
		*K = 22 * (*Zc);
		*N = 66 * (*Zc);
	} else {
		*K = 10 * (*Zc);
		*N = 50 * (*Zc);
	}

	/* check if transport block size A is valid or not */
	if (*B % (8*(*C)))
		*TBS_VALID = 0;
	else
		*TBS_VALID = 1;

	*C_prime = 0;
	for (i = 0; i < *C; i++)
		*C_prime += ((codeblock_mask[i/32] >> (i % 32)) & 1);
}

void
la12xx_sch_encode_param_convert(uint32_t BGnumber,
				uint32_t Q_m,
				uint32_t *e,
				uint32_t rv_id,
				uint32_t A,
				uint32_t q,
				uint32_t n_ID,
				uint32_t n_RNTI,
				uint32_t scrambler_bypass,
				uint32_t N_cb,
				uint32_t *codeblock_mask,
				int16_t *TBS_VALID,
				// HW parameters
				uint32_t *set_index,
				uint32_t *base_graph2,
				uint32_t *lifting_index,
				uint32_t *mod_order,
				uint32_t *tb_24_bit_crc,
				uint32_t *num_code_blocks,
				uint32_t *num_input_bytes,
				uint32_t *e_floor_thresh,
				uint32_t *num_output_bits_floor,
				uint32_t *num_output_bits_ceiling,
				uint32_t *SE_SC_X1_INIT,
				uint32_t *SE_SC_X2_INIT,
				uint32_t *int_start_ofst_floor,
				uint32_t *int_start_ofst_ceiling,
				uint32_t *SE_CIRC_BUF)
{
	uint32_t B, i_LS, Zc, K_dash, i, K, N, C_prime;
	uint32_t C, cb_counter = 0;
	uint32_t e_div_qm_floor, e_div_qm_ceiling;
	uint32_t E_sum = 0;

	/* evaluate parameters */
	LDPC_evaluate_parameters(A, BGnumber, codeblock_mask,
				 &B, &i_LS, &Zc, &N, &K, &K_dash,
				 &C, &C_prime, TBS_VALID);

	for (i = 0; i < C; i++)
		E_sum += e[i];

	if (E_sum) {
		*set_index = i_LS;
		if (BGnumber == 2)
			*base_graph2 = 1;
		else
			*base_graph2 = 0;

		if (Zc == 2 || Zc == 3 || Zc == 5 || Zc == 7 || Zc == 9 ||
				Zc == 11 || Zc == 13 || Zc == 15)
			*lifting_index = 0;
		else if (Zc == 4 || Zc == 6 || Zc == 10 || Zc == 14 ||
				Zc == 18 || Zc == 22 || Zc == 26 || Zc == 30)
			*lifting_index = 1;
		else if (Zc == 8 || Zc == 12 || Zc == 20 || Zc == 28 ||
				Zc == 36 || Zc == 44 || Zc == 52 || Zc == 60)
			*lifting_index = 2;
		else if (Zc == 16 || Zc == 24 || Zc == 40 || Zc == 56 ||
				Zc == 72 || Zc == 88 || Zc == 104 || Zc == 120)
			*lifting_index = 3;
		else if (Zc == 32 || Zc == 48 || Zc == 80 || Zc == 112 ||
				Zc == 144 || Zc == 176 || Zc == 208 ||
				Zc == 240)
			*lifting_index = 4;
		else if (Zc == 64 || Zc == 96 || Zc == 160 || Zc == 224 ||
				Zc == 288 || Zc == 352)
			*lifting_index = 5;
		else if (Zc == 128 || Zc == 192 || Zc == 320)
			*lifting_index = 6;
		else if (Zc == 256 || Zc == 384)
			*lifting_index = 7;

		*mod_order = Q_m;
		if ((B - A) == 24)
			*tb_24_bit_crc = 1;
		else
			*tb_24_bit_crc = 0;

		*num_code_blocks = C;
		*num_input_bytes = K_dash/8;
		for (i = 0; i < C; i++) {
			if ((codeblock_mask[i/32] >> (i % 32)) & 1) {
				if (cb_counter == 0) {
					*num_output_bits_floor = e[i];
					*e_floor_thresh = -1;
				}
				if (cb_counter == (C_prime - 1))
					*num_output_bits_ceiling = e[i];
				if (e[i] == *num_output_bits_floor)
					*e_floor_thresh = *e_floor_thresh + 1;
				cb_counter++;
			}
		}
		if (scrambler_bypass) {
			*SE_SC_X1_INIT = 0;
			*SE_SC_X2_INIT = 0;
		} else {
			offset_x1_x2(((uint32_t)n_RNTI << 15) +
				     ((uint32_t)q << 14) + n_ID, 1600,
				     SE_SC_X1_INIT, SE_SC_X2_INIT);
		}

		e_div_qm_floor = *num_output_bits_floor / Q_m;
		e_div_qm_ceiling = *num_output_bits_ceiling / Q_m;
		calc_int_start_ofst(Q_m, rv_id, 0, N_cb, BGnumber, K, K_dash, Zc,
				    e_div_qm_floor, SE_CIRC_BUF,
				    int_start_ofst_floor);
		calc_int_start_ofst(Q_m, rv_id, 0, N_cb, BGnumber, K, K_dash, Zc,
				    e_div_qm_ceiling, SE_CIRC_BUF,
				    int_start_ofst_ceiling);

	} else { // no ULSCH
		*set_index = 3;
		*base_graph2 = 1;
		*lifting_index = 0;
		*mod_order = 1;
		*tb_24_bit_crc = 0;
		*num_code_blocks = 1;
		*num_input_bytes = 5;
		*e_floor_thresh = 0;
		*num_output_bits_floor = 0;
		*num_output_bits_ceiling = 0;
		if (scrambler_bypass) {
			*SE_SC_X1_INIT = 0;
			*SE_SC_X2_INIT = 0;
		} else {
			offset_x1_x2((n_RNTI << 15) + (q << 14) + n_ID, 1600,
				     SE_SC_X1_INIT, SE_SC_X2_INIT);
		}

		*SE_CIRC_BUF = 320;
		for (i = 0; i < 7; i++) {
			int_start_ofst_floor[i] = 0;
			int_start_ofst_ceiling[i] = 0;
		}
	}
}

void
la12xx_sch_decode_param_convert(uint32_t BGnumber,
				uint32_t Q_m,
				uint32_t *e,
				uint32_t rv_id,
				uint32_t A,
				uint32_t q,
				uint32_t n_ID,
				uint32_t n_RNTI,
				uint32_t scrambler_bypass,
				uint32_t N_cb,
				uint32_t remove_tb_crc,
				uint32_t harq_en,
				uint32_t *size_harq_buffer,
				uint32_t *C,
				uint32_t *codeblock_mask,
				int16_t *TBS_VALID,
				// HW parameters
				uint32_t *set_index,
				uint32_t *base_graph2,
				uint32_t *lifting_index,
				uint32_t *mod_order,
				uint32_t *tb_24_bit_crc,
				uint32_t *one_code_block,
				uint32_t *e_floor_thresh,
				uint32_t *num_output_bytes,
				uint32_t *bits_per_cb,
				uint32_t *num_filler_bits,
				uint32_t *SD_SC_X1_INIT,
				uint32_t *SD_SC_X2_INIT,
				uint32_t *e_div_qm_floor,
				uint32_t *e_div_qm_ceiling,
				uint32_t *di_start_ofst_floor,
				uint32_t *di_start_ofst_ceiling,
				uint32_t *SD_CIRC_BUF,
				uint32_t *axi_data_num_bytes)
{
	uint32_t B, i_LS, Zc, K_dash, i, K, N;
	uint32_t C_prime, cb_counter = 0;
	uint32_t offset_harq_buffer;

	// evaluate parameters
	LDPC_evaluate_parameters(A, BGnumber, codeblock_mask,
				 &B, &i_LS, &Zc, &N, &K, &K_dash,
				 C, &C_prime, TBS_VALID);

	*set_index = i_LS;
	if (BGnumber == 2)
		*base_graph2 = 1;
	else
		*base_graph2 = 0;

	if (Zc == 2 || Zc == 3 || Zc == 5 || Zc == 7 || Zc == 9 || Zc == 11 ||
			Zc == 13 || Zc == 15)
		*lifting_index = 0;
	else if (Zc == 4 || Zc == 6 || Zc == 10 || Zc == 14 || Zc == 18 ||
			Zc == 22 || Zc == 26 || Zc == 30)
		*lifting_index = 1;
	else if (Zc == 8 || Zc == 12 || Zc == 20 || Zc == 28 || Zc == 36 ||
			Zc == 44 || Zc == 52 || Zc == 60)
		*lifting_index = 2;
	else if (Zc == 16 || Zc == 24 || Zc == 40 || Zc == 56 || Zc == 72 ||
			Zc == 88 || Zc == 104 || Zc == 120)
		*lifting_index = 3;
	else if (Zc == 32 || Zc == 48 || Zc == 80 || Zc == 112 || Zc == 144 ||
			Zc == 176 || Zc == 208 || Zc == 240)
		*lifting_index = 4;
	else if (Zc == 64 || Zc == 96 || Zc == 160 || Zc == 224 || Zc == 288 ||
			Zc == 352)
		*lifting_index = 5;
	else if (Zc == 128 || Zc == 192 || Zc == 320)
		*lifting_index = 6;
	else if (Zc == 256 || Zc == 384)
		*lifting_index = 7;

	*mod_order = Q_m;
	if ((B - A) == 24)
		*tb_24_bit_crc = 1;
	else
		*tb_24_bit_crc = 0;

	*one_code_block = (*C == 1) ? 1 : 0;
	*num_output_bytes = K_dash/8;
	*bits_per_cb = K;
	*num_filler_bits = K - K_dash;

	if (remove_tb_crc) {
		*axi_data_num_bytes = A/8;
	} else {
		if (*tb_24_bit_crc)
			*axi_data_num_bytes = (A + 24)/8;
		else
			*axi_data_num_bytes = (A + 16)/8;
	}

	if (scrambler_bypass) {
		*SD_SC_X1_INIT = 0;
		*SD_SC_X2_INIT = 0;
	} else {
		offset_x1_x2(((uint32_t)n_RNTI << 15) +
			     ((uint32_t)q << 14) + n_ID, 1600,
			     SD_SC_X1_INIT, SD_SC_X2_INIT);
	}

	*e_div_qm_floor = 0;
	for (i = 0; i < *C; i++) {
		if ((codeblock_mask[i/32] >> (i % 32)) & 1) {
			if (cb_counter == 0) {
				*e_div_qm_floor = e[i]/Q_m;
				*e_floor_thresh = -1;
			}
			if (cb_counter == C_prime-1)
				*e_div_qm_ceiling = e[i]/Q_m;
			if (e[i] == ((uint32_t)(*e_div_qm_floor) * Q_m))
				*e_floor_thresh = *e_floor_thresh + 1;
			cb_counter++;

		}
	}

	calc_int_start_ofst(Q_m, rv_id, !harq_en, N_cb, BGnumber, K, K_dash, Zc,
			    *e_div_qm_floor, SD_CIRC_BUF, di_start_ofst_floor);
	calc_int_start_ofst(Q_m, rv_id, !harq_en, N_cb, BGnumber, K, K_dash, Zc,
			    *e_div_qm_ceiling, SD_CIRC_BUF,
			    di_start_ofst_ceiling);

	offset_harq_buffer = 128 * ((*SD_CIRC_BUF / 128) +
				((*SD_CIRC_BUF % 128) != 0));
	*size_harq_buffer = (*C) * offset_harq_buffer;
}
