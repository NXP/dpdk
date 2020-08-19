/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _PMD_LA12XX_H_
#define _PMD_LA12XX_H_

#include <rte_bbdev.h>

#include <geul_feca.h>

/** Structure specifying a single operation for la12xx */
struct rte_pmd_la12xx_op {
	/** Status of operation that was performed */
	int status;
	/** Mempool which op instance is in */
	struct rte_mempool *mempool;
	/** Opaque pointer for user data */
	void *opaque_data;
	/** Parameters for FECA job */
	feca_job_t feca_obj;
	/** The input buffer */
	struct rte_bbdev_op_data input;
	/** The output buffer */
	struct rte_bbdev_op_data output;
};

#define RTE_PMD_LA12xx_SET_POLAR_DEC(p) \
	(p)->feca_obj.job_type =  FECA_JOB_CD;
#define RTE_PMD_LA12xx_SET_POLAR_DEC_DEMUX(p) \
	(p)->feca_obj.job_type =  FECA_JOB_CD_DCM_ACK;
#define RTE_PMD_LA12xx_SET_POLAR_ENC(p) \
	(p)->feca_obj.job_type =  FECA_JOB_CE;
#define RTE_PMD_LA12xx_GET_POLAR_DEC_DEMUX(p) \
	((p)->feca_obj.job_type ==  FECA_JOB_CD_DCM_ACK)

#define RTE_PMD_LA12xx_PD_pd_n(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.pd_n
#define RTE_PMD_LA12xx_PD_input_deint_bypass(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.input_deint_bypass
#define RTE_PMD_LA12xx_PD_output_deint_bypass(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.output_deint_bypass
#define	RTE_PMD_LA12xx_PD_rm_mode(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.rm_mode
#define RTE_PMD_LA12xx_PD_pc_en(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.pc_en
#define RTE_PMD_LA12xx_PD_crc_type(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.crc_type
#define RTE_PMD_LA12xx_PD_K(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.K
#define RTE_PMD_LA12xx_PD_E(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg2.E
#define RTE_PMD_LA12xx_PD_crc_rnti(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg2.crc_rnti
#define RTE_PMD_LA12xx_PD_pc_index0(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index0
#define RTE_PMD_LA12xx_PD_pc_index1(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index1
#define RTE_PMD_LA12xx_PD_pc_index2(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index2
#define RTE_PMD_LA12xx_PD_FZ_LUT(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_fz_lut

#define RTE_PMD_LA12xx_PE_pe_n(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.pe_n
#define RTE_PMD_LA12xx_PE_input_int_bypass(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.input_int_bypass
#define RTE_PMD_LA12xx_PE_output_int_bypass(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.output_int_bypass
#define	RTE_PMD_LA12xx_PE_rm_mode(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.rm_mode
#define RTE_PMD_LA12xx_PE_pc_en(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.pc_en
#define RTE_PMD_LA12xx_PE_crc_type(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.crc_type
#define RTE_PMD_LA12xx_PE_dst_sel(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.dst_sel
#define RTE_PMD_LA12xx_PE_K(p) \
	(p)->feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.K
#define RTE_PMD_LA12xx_PE_E(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg2.E
#define RTE_PMD_LA12xx_PE_crc_rnti(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg2.crc_rnti
#define RTE_PMD_LA12xx_PE_out_pad_bytes(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg3.out_pad_bytes
#define RTE_PMD_LA12xx_PE_block_concat_en(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg3.block_concat_en
#define RTE_PMD_LA12xx_PE_pc_index0(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index0
#define RTE_PMD_LA12xx_PE_pc_index1(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index1
#define RTE_PMD_LA12xx_PE_pc_index2(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index2
#define RTE_PMD_LA12xx_PE_FZ_LUT(p) \
	(p)->feca_obj.command_chain_t.ce_command_ch_obj.ce_fz_lut

	
#define RTE_PMD_LA12xx_POLAR_OP_DESC(p) \
	(p)->feca_obj
void
rte_pmd_la12xx_op_init(struct rte_mempool *mempool, __rte_unused void *arg, void *element,
		__rte_unused unsigned int n);

/**
 * Enqueue a burst of operations for encode or decode to a queue of the device.
 * This functions only enqueues as many operations as currently possible and
 * does not block until @p num_ops entries in the queue are available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array containing operations to be enqueued Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to enqueue.
 *
 * @return
 *   The number of operations actually enqueued (this is the number of processed
 *   entries in the @p ops array).
 */
uint16_t
rte_pmd_la12xx_enqueue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops);

/**
 * Dequeue a burst of processed encode/decode operations from a queue of
 * the device.
 * This functions returns only the current contents of the queue, and does not
 * block until @ num_ops is available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array where operations will be dequeued to. Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to dequeue.
 *
 * @return
 *   The number of operations actually dequeued (this is the number of entries
 *   copied into the @p ops array).
 */
uint16_t
rte_pmd_la12xx_dequeue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops);

#endif
