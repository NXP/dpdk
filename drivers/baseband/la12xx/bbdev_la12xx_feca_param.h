/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _BBDEV_LA12XX_FECA_PARAM_H_
#define _BBDEV_LA12XX_FECA_PARAM_H_

/**
 * Convert BBDEV parameters for shared encode to FECA parameters
 *
 * @param BGnumber
 *   Base Graph Number
 *   1: LDPC Base graph 1, 2: LDPC Base graph 2 (input)
 * @param Q_m
 *   modulation order, Q_m={2,4,6,8} (input)
 * @param e
 *   array of size C (number of code blocks) where each entry has the number
 *   of encoded bits inside each code block. Note that E_0 + E_1 + ... +
 *   E_(C-1) = G_sch (input)
 * @param rv_id
 *   redundancy version ID (input)
 * @param A
 *   transport block payload size. Amin=24, Amax=1213032.
 *   A has to be multiple of (8*C) (input)
 * @param q
 *   parameter for c_init in scrambler, q = 0 or 1 for downlink,
 *   q = 0 for uplink (input)
 * @param n_ID
 *   parameter for c_init in scrambler, n_ID={0, ..., 1023} (input)
 * @param n_RNTI
 *   parameter for c_init in scrambler, n_RNTI={0, ..., 65535} (input)
 * @param scrambler_bypass
 *   when scrambler_bypass = 1, it will bypass scrambler (input)
 * @param N_cb
 *   circular buffer size for rate matching parameter (input)
 * @param codeblock_mask
 *   binary mask to indicate the number of transmitted code blocks.
 *   codeblock_mask is an array of size 8.  If the code block is transmitted,
 *   the corresponding bit is 1, otherwise, it will be zero (input)
 * @param TBS_VALID
 *   if *TBS_VALID=1 --> A is valid number. if *TBS_VALID=0 --> A
 *   is invalid number (output)
 *
 */
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
				uint32_t *SE_CIRC_BUF);

/**
 * Convert BBDEV parameters for shared encode to FECA parameters
 *
 * @param BGnumber
 *   Base Graph Number
 *   1: LDPC Base graph 1, 2: LDPC Base graph 2 (input)
 * @param Q_m
 *   modulation order, Q_m={2,4,6,8} (input)
 * @param e
 *   array of size C (number of code blocks) where each entry has the number
 *   of encoded bits inside each code block. Note that E_0 + E_1 + ... +
 *   E_(C-1) = G_sch (input)
 * @param rv_id
 *   redundancy version ID (input)
 * @param A
 *   transport block payload size. Amin=24, Amax=1213032.
 *   A has to be multiple of (8*C) (input)
 * @param q
 *   parameter for c_init in scrambler, q = 0 or 1 for downlink,
 *   q = 0 for uplink (input)
 * @param n_ID
 *   parameter for c_init in scrambler, n_ID={0, ..., 1023} (input)
 * @param n_RNTI
 *   parameter for c_init in scrambler, n_RNTI={0, ..., 65535} (input)
 * @param scrambler_bypass
 *   when scrambler_bypass = 1, it will bypass scrambler (input)
 * @param N_cb
 *   circular buffer size for rate matching parameter (input)
 * @param remove_tb_crc
 *   If 0, transport block CRC will be attached to the decoded bits.
 *   If 1, transport block CRC will be removed from the decoded bits (input)
 * @param harq_en
 *   HARQ enable (input)
 * @param size_harq_buffer
 *   HARQ buffer size (output)
 * @param pC
 *   number of code blocks per transport block (output)
 * @param codeblock_mask
 *   binary mask to indicate the number of transmitted code blocks.
 *   codeblock_mask is an array of size 8.  If the code block is transmitted,
 *   the corresponding bit is 1, otherwise, it will be zero (input)
 * @param TBS_VALID
 *   if *TBS_VALID=1 --> A is valid number. if *TBS_VALID=0 --> A
 *   is invalid number (output)
 *
 */
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
;

#endif /* BBDEV_LA12XX_FECA_PARAM_H_ */
