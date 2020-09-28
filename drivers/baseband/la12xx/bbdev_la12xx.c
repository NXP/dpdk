/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <math.h>

#include <rte_common.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_kvargs.h>
#include <rte_hexdump.h>

#include <rte_bbdev.h>
#include <rte_bbuf.h>
#include <rte_bbdev_pmd.h>
#include <rte_pmd_bbdev_la12xx.h>

#include <geul_bbdev_ipc.h>
#include <geul_ipc_um.h>
#include <gul_host_if.h>

#include "bbdev_la12xx.h"
#include "bbdev_la12xx_pmd_logs.h"
#include "bbdev_la12xx_feca_param.h"

#define DRIVER_NAME baseband_la12xx

/* SG table final entry */
#define QDMA_SGT_F	0x80000000

#define LA12XX_MAX_CORES	4

/* TX retry count */
#define BBDEV_LA12XX_TX_RETRY_COUNT 10000

/* la12xx BBDev logging ID */
int bbdev_la12xx_logtype_pmd;

uint32_t num_ldpc_enc_queues;
uint32_t num_ldpc_dec_queues;
uint32_t num_polar_enc_queues;
uint32_t num_polar_dec_queues;

int la12xx_polar_enc_core = -1;
int la12xx_polar_dec_core = -1;

uint32_t per_queue_hram_size;

struct gul_ipc_stats *h_stats;
struct gul_stats *stats; /**< Stats for Host & modem (HIF) */

static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
	{
		.type   = RTE_BBDEV_OP_LDPC_ENC,
		.cap.ldpc_enc = {
			.capability_flags =
					RTE_BBDEV_LDPC_CRC_24A_ATTACH |
					RTE_BBDEV_LDPC_CRC_24B_ATTACH |
					RTE_BBDEV_LDPC_ENC_SCRAMBLING_OFFLOAD,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_dst =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
		}
	},
	{
		.type   = RTE_BBDEV_OP_LDPC_DEC,
		.cap.ldpc_dec = {
			.capability_flags =
					RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP |
					RTE_BBDEV_LDPC_DEC_LLR_CONV_OFFLOAD |
					RTE_BBDEV_LDPC_DEC_SCRAMBLING_OFFLOAD |
					RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE |
					RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_hard_out =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
		}
	},
	{
		.type   = RTE_BBDEV_OP_POLAR_DEC,
	},
	{
		.type   = RTE_BBDEV_OP_POLAR_ENC,
	},
	RTE_BBDEV_END_OF_CAPABILITIES_LIST()
};

static struct rte_bbdev_queue_conf default_queue_conf = {
	.queue_size = MAX_CHANNEL_DEPTH,
};

/* Get device info */
static void
la12xx_info_get(struct rte_bbdev *dev,
		struct rte_bbdev_driver_info *dev_info)
{
	PMD_INIT_FUNC_TRACE();

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = LA12XX_MAX_QUEUES;
	dev_info->queue_size_lim = MAX_CHANNEL_DEPTH;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 64;

	BBDEV_LA12XX_PMD_DEBUG("got device info from %u", dev->data->dev_id);
}

/* Release queue */
static int
la12xx_queue_release(struct rte_bbdev *dev, uint16_t q_id)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(q_id);

	PMD_INIT_FUNC_TRACE();

	/* TODO: Implement */

	return 0;
}

#define HUGEPG_OFFSET(A) \
		((uint64_t) ((unsigned long) (A) \
		- ((uint64_t)ipc_priv->hugepg_start.host_vaddr)))

static int ipc_queue_configure(uint32_t channel_id,
		ipc_t instance, const struct rte_bbdev_queue_conf *conf)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	void *vaddr;
	uint32_t i = 0;
	uint32_t msg_size = sizeof(struct bbdev_ipc_enqueue_op);

	PMD_INIT_FUNC_TRACE();

	RTE_SET_USED(conf);

	BBDEV_LA12XX_PMD_DEBUG("%x %p", ipc_instance->initialized,
		ipc_priv->instance);
	ch = &(ipc_instance->ch_list[channel_id]);

	BBDEV_LA12XX_PMD_DEBUG("channel: %u, depth: %u, msg size: %u",
		channel_id, conf->queue_size, msg_size);

	/* Start init of channel */
	ch->br_msg_desc.md.ring_size = conf->queue_size;
	ch->br_msg_desc.md.ci_flag = 0;
	ch->br_msg_desc.md.pi_flag = 0;
	ch->br_msg_desc.md.pi = 0;
	ch->br_msg_desc.md.ci = 0;
	ch->br_msg_desc.md.msg_size = msg_size;
	for (i = 0; i < conf->queue_size; i++) {
		vaddr = rte_malloc(NULL, msg_size, RTE_CACHE_LINE_SIZE);
		if (!vaddr) {
			h_stats->ipc_ch_stats[channel_id].err_host_buf_alloc_fail++;
			return IPC_HOST_BUF_ALLOC_FAIL;
		}
		/* Only offset now */
		ch->br_msg_desc.bd[i].modem_ptr = HUGEPG_OFFSET(vaddr);
		ch->br_msg_desc.bd[i].host_virt_l = SPLIT_VA32_L(vaddr);
		ch->br_msg_desc.bd[i].host_virt_h = SPLIT_VA32_H(vaddr);
		/* Not sure use of this len may be for CRC*/
		ch->br_msg_desc.bd[i].len = 0;
	}
	ch->bl_initialized = 1;

	BBDEV_LA12XX_PMD_DEBUG("Channel configured");
	return IPC_SUCCESS;

}

/* Setup a queue */
static int
la12xx_queue_setup(struct rte_bbdev *dev, uint16_t q_id,
		const struct rte_bbdev_queue_conf *queue_conf)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipcu = priv->ipc_priv;
	struct rte_bbdev_queue_data *q_data;
	struct bbdev_la12xx_q_priv *q_priv;
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int instance_id = 0;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	/* Move to setup_queues callback */
	q_data = &dev->data->queues[q_id];
	q_data->queue_private = rte_zmalloc(NULL,
		sizeof(struct bbdev_la12xx_q_priv), 0);
	if (!q_data->queue_private) {
		BBDEV_LA12XX_PMD_ERR("Memory allocation failed for qpriv");
		return -ENOMEM;
	}
	q_priv = q_data->queue_private;
	q_priv->q_id = q_id;
	q_priv->bbdev_priv = dev->data->dev_private;

	mhif = (struct gul_hif *)ipcu->mhif_start.host_vaddr;
	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipcu->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);
	ch = &ipc_md->instance_list[instance_id].ch_list[q_id];

	if (q_id < priv->num_valid_queues) {
		q_priv->feca_blk_id = rte_cpu_to_be_32(ch->feca_blk_id);
		q_priv->feca_blk_id_be32 = ch->feca_blk_id;
		BBDEV_LA12XX_PMD_WARN(
			"Queue [%d] already configured, not configuring again",
			q_id);
		return 0;
	}

	BBDEV_LA12XX_PMD_DEBUG("setting up queue %d", q_id);

	/* Call ipc_configure_channel */
	ret = ipc_queue_configure((q_id + HOST_RX_QUEUEID_OFFSET),
				  ipcu, queue_conf);
	if (ret) {
		BBDEV_LA12XX_PMD_ERR("Unable to setup queue (%d) (err=%d)",
		       q_id, ret);
		return ret;
	}

	/* Set queue properties for LA12xx device */
	switch (queue_conf->op_type) {
	case RTE_BBDEV_OP_LDPC_ENC:
		if (num_ldpc_enc_queues >= MAX_LDPC_ENC_FECA_QUEUES) {
			BBDEV_LA12XX_PMD_ERR(
				"num_ldpc_enc_queues reached max value");
			return -1;
		}
		ch->la12xx_core_id = rte_cpu_to_be_32(0);
		ch->feca_blk_id = rte_cpu_to_be_32(num_ldpc_enc_queues++);
		break;
	case RTE_BBDEV_OP_LDPC_DEC:
		if (num_ldpc_dec_queues >= MAX_LDPC_DEC_FECA_QUEUES) {
			BBDEV_LA12XX_PMD_ERR(
				"num_ldpc_dec_queues reached max value");
			return -1;
		}
		ch->la12xx_core_id = rte_cpu_to_be_32(1);
		ch->feca_blk_id = rte_cpu_to_be_32(num_ldpc_dec_queues++);
		break;
	case RTE_BBDEV_OP_POLAR_ENC:
		if (num_polar_enc_queues >= MAX_POLAR_ENC_FECA_QUEUES) {
			BBDEV_LA12XX_PMD_ERR(
				"num_polar_enc_queues reached max value");
			return -1;
		}
		ch->la12xx_core_id = rte_cpu_to_be_32(2);
		ch->feca_blk_id = rte_cpu_to_be_32(0);
		num_polar_enc_queues++;
		break;
	case RTE_BBDEV_OP_POLAR_DEC:
		if (num_polar_dec_queues >= MAX_POLAR_DEC_FECA_QUEUES) {
			BBDEV_LA12XX_PMD_ERR(
				"num_polar_dec_queues reached max value");
			return -1;
		}
		ch->la12xx_core_id = rte_cpu_to_be_32(3);
		ch->feca_blk_id = rte_cpu_to_be_32(0);
		num_polar_dec_queues++;
		break;
	default:
		BBDEV_LA12XX_PMD_ERR("Not supported op type\n");
		return -1;
	}
	ch->op_type = rte_cpu_to_be_32(queue_conf->op_type);
	ch->depth = rte_cpu_to_be_32(queue_conf->queue_size);

	/* Store queue config here */
	priv->num_valid_queues++;
	q_priv->feca_blk_id = rte_cpu_to_be_32(ch->feca_blk_id);
	q_priv->feca_blk_id_be32 = ch->feca_blk_id;

	per_queue_hram_size = FECA_HRAM_SIZE / num_ldpc_dec_queues;

	return 0;
}

uint16_t
rte_pmd_la12xx_queue_core_config(uint16_t dev_id, uint16_t queue_ids[],
		uint16_t core_ids[], uint16_t num_queues)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipcu = priv->ipc_priv;
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int queue_id, core_id;
	int i, instance_id = 0;
	uint32_t op_type;

	mhif = (struct gul_hif *)ipcu->mhif_start.host_vaddr;
	ipc_md = (ipc_metadata_t *)((uint64_t)ipcu->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);

	for (i = 0; i < num_queues; i++) {
		queue_id = queue_ids[i];
		core_id = core_ids[i];

		if (queue_id >= dev->data->num_queues) {
			BBDEV_LA12XX_PMD_ERR(
				"Invalid queue ID %d", queue_id);
			return -1;
		}

		if (core_id >= GUL_EP_CORE_MAX) {
			BBDEV_LA12XX_PMD_ERR(
				"Invalid core ID %d for queue %d",
				core_id, queue_id);
			return -1;
		}

		ch = &ipc_md->instance_list[instance_id].ch_list[queue_id];
		op_type = rte_be_to_cpu_32(ch->op_type);

		if (op_type == RTE_BBDEV_OP_POLAR_ENC) {
			if (la12xx_polar_enc_core == -1)
				la12xx_polar_enc_core = core_id;
			else if (la12xx_polar_enc_core != core_id) {
				BBDEV_LA12XX_PMD_ERR(
					"All polar encode queue not configuerd on same LA12xx e200 core");
			}
		}

		if (op_type == RTE_BBDEV_OP_POLAR_DEC) {
			if (la12xx_polar_dec_core == -1)
				la12xx_polar_dec_core = core_id;
			else if (la12xx_polar_dec_core != core_id) {
				BBDEV_LA12XX_PMD_ERR(
					"All polar decode queues not configuerd on same LA12xx e200 core");
			}
		}

		ch->la12xx_core_id = rte_cpu_to_be_32(core_id);
	}

	return 0;
}

static int
la12xx_start(struct rte_bbdev *dev)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipcu = priv->ipc_priv;
	int ready = 0;
	struct gul_hif *hif_start;

	PMD_INIT_FUNC_TRACE();

	hif_start = (struct gul_hif *)ipcu->mhif_start.host_vaddr;

	/* Set Host Read bit */
	SET_HIF_HOST_RDY(hif_start, HIF_HOST_READY_IPC_APP);

	/* Now wait for modem ready bit */
	while (!ready)
		ready = CHK_HIF_MOD_RDY(hif_start, HIF_MOD_READY_IPC_APP);

	return 0;
}

static const struct rte_bbdev_ops pmd_ops = {
	.info_get = la12xx_info_get,
	.queue_setup = la12xx_queue_setup,
	.queue_release = la12xx_queue_release,
	.start = la12xx_start
};

/* To handle glibc memcpy unaligned access issue, we need
 * our own wrapper layer to handle corner cases. We use memcpy
 * for size aligned bytes and do left opver byets copy manually.
 */
static inline void ipc_memcpy(void *dst, void *src, uint32_t len)
{
	uint32_t extra_b;

	extra_b = (len & 0x7);
	/* Adjust the length to multiple of 8 byte
	 * and copy extra bytes to avoid BUS error
	 */
	if (extra_b)
		len += (0x8 - extra_b);

	memcpy(dst, src, len);
}

static inline int is_bd_ring_full(ipc_br_md_t *md)
{
	uint32_t ci = md->ci;
	uint32_t pi = md->pi;

	if (pi == ci) {
		uint32_t ci_flag = md->ci_flag;
		uint32_t pi_flag = md->pi_flag;

		if (pi_flag != ci_flag)
			return 1; /* Ring is Full */
	}
	return 0;
}

static int
fill_feca_desc_enc(struct bbdev_la12xx_q_priv *q_priv,
		   struct rte_mbuf *mbuf,
		   struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
		   struct rte_bbdev_enc_op *bbdev_enc_op,
		   char *huge_start_addr)
{
	struct rte_bbdev_op_ldpc_enc *ldpc_enc = &bbdev_enc_op->ldpc_enc;
	uint32_t A = bbdev_enc_op->ldpc_enc.input.length * 8;
	uint32_t e[RTE_BBDEV_LDPC_MAX_CODE_BLOCKS];
	uint32_t codeblock_mask[8], i;
	uint32_t set_index, base_graph2, lifting_index, mod_order;
	uint32_t tb_24_bit_crc, num_code_blocks;
	uint32_t num_input_bytes, e_floor_thresh;
	uint32_t num_output_bits_floor, num_output_bits_ceiling;
	uint32_t SE_SC_X1_INIT, SE_SC_X2_INIT, SE_CIRC_BUF;
	uint32_t int_start_ofst_floor[8], int_start_ofst_ceiling[8];
	se_command_t se_cmd, *se_command;
	se_dcm_command_t *se_dcm_command;
	int16_t TBS_VALID;
	char *data_ptr;
	uint32_t l1_pcie_addr;

	for (i = 0; i < ldpc_enc->tb_params.cab; i++)
		e[i] = ldpc_enc->tb_params.ea;
	for (; i < ldpc_enc->tb_params.c; i++)
		e[i] = ldpc_enc->tb_params.eb;

	memset(codeblock_mask, 0xFF, (8 * sizeof(uint32_t)));

	la12xx_sch_encode_param_convert(ldpc_enc->basegraph, ldpc_enc->q_m,
			e, ldpc_enc->rv_index, A, ldpc_enc->q, ldpc_enc->n_id,
			ldpc_enc->n_rnti, !ldpc_enc->en_scramble,
			ldpc_enc->n_cb, codeblock_mask, &TBS_VALID,
			&set_index, &base_graph2, &lifting_index, &mod_order,
			&tb_24_bit_crc,	&num_code_blocks, &num_input_bytes,
			&e_floor_thresh, &num_output_bits_floor,
			&num_output_bits_ceiling, &SE_SC_X1_INIT,
			&SE_SC_X2_INIT,	int_start_ofst_floor,
			int_start_ofst_ceiling, &SE_CIRC_BUF);

	if (TBS_VALID == 0) {
		BBDEV_LA12XX_PMD_ERR("Invalid input for SE");
		return -1;
	}

	bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(FECA_JOB_SE);
	bbdev_ipc_op->feca_job.t_blk_id = q_priv->feca_blk_id_be32;

	se_command = &bbdev_ipc_op->feca_job.command_chain_t.se_command_ch_obj;

	/* TODO: Currently setting all fields for clarity.
	 * Remove unrequried fields
	 */
	se_cmd.se_cfg1.raw_se_cfg1 = 0;
	se_cmd.se_cfg1.out_pad_bytes = 0;
	se_cmd.se_cfg1.num_code_blocks = num_code_blocks;
	se_cmd.se_cfg1.tb_24_bit_crc = tb_24_bit_crc;
	se_cmd.se_cfg1.complete_trig_en = 1;
	se_cmd.se_cfg1.mod_order = mod_order;
	se_cmd.se_cfg1.control_data_mux = ldpc_enc->se_ce_mux;
	se_cmd.se_cfg1.lifting_size = lifting_index;
	se_cmd.se_cfg1.base_graph2 = base_graph2;
	se_cmd.se_cfg1.set_index = set_index;
	se_command->se_cfg1.raw_se_cfg1 =
		rte_cpu_to_be_32(se_cmd.se_cfg1.raw_se_cfg1);

	se_cmd.se_sizes1.raw_se_sizes1 = 0;
	se_cmd.se_sizes1.num_input_bytes = num_input_bytes;
	se_cmd.se_sizes1.e_floor_thresh = e_floor_thresh;
	se_command->se_sizes1.raw_se_sizes1 =
		rte_cpu_to_be_32(se_cmd.se_sizes1.raw_se_sizes1);

	se_command->se_circ_buf = rte_cpu_to_be_32(SE_CIRC_BUF);
	se_command->se_floor_num_output_bits =
		rte_cpu_to_be_32(num_output_bits_floor);
	se_command->se_ceiling_num_output_bits =
		rte_cpu_to_be_32(num_output_bits_ceiling);
	se_command->se_sc_x1_init = rte_cpu_to_be_32(SE_SC_X1_INIT);
	se_command->se_sc_x2_init = rte_cpu_to_be_32(SE_SC_X2_INIT);

	data_ptr =  rte_pktmbuf_mtod(mbuf, char *);
	l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR + data_ptr - huge_start_addr;
	se_command->se_axi_in_addr_low = rte_cpu_to_be_32(l1_pcie_addr);
	se_command->se_axi_in_addr_high = 0;
	se_command->se_axi_in_num_bytes = rte_cpu_to_be_32(mbuf->pkt_len);

	memset(se_command->se_cb_mask, 0xFF, (8 * sizeof(uint32_t)));

	se_command->se_di_start_ofst_floor[0] =
		rte_cpu_to_be_32((int_start_ofst_floor[1] << 16) |
		int_start_ofst_floor[0]);
	se_command->se_di_start_ofst_floor[1] =
		rte_cpu_to_be_32((int_start_ofst_floor[3] << 16) |
		int_start_ofst_floor[2]);
	se_command->se_di_start_ofst_floor[2] =
		rte_cpu_to_be_32((int_start_ofst_floor[5] << 16) |
		int_start_ofst_floor[4]);
	se_command->se_di_start_ofst_floor[3] =
		rte_cpu_to_be_32((int_start_ofst_floor[7] << 16) |
		int_start_ofst_floor[6]);
	se_command->se_di_start_ofst_ceiling[0] =
		rte_cpu_to_be_32((int_start_ofst_ceiling[1] << 16) |
		int_start_ofst_ceiling[0]);
	se_command->se_di_start_ofst_ceiling[1] =
		rte_cpu_to_be_32((int_start_ofst_ceiling[3] << 16) |
		int_start_ofst_ceiling[2]);
	se_command->se_di_start_ofst_ceiling[2] =
		rte_cpu_to_be_32((int_start_ofst_ceiling[5] << 16) |
		int_start_ofst_ceiling[4]);
	se_command->se_di_start_ofst_ceiling[3] =
		rte_cpu_to_be_32((int_start_ofst_ceiling[7] << 16) |
		int_start_ofst_ceiling[6]);

	if (ldpc_enc->se_ce_mux) {
		bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(FECA_JOB_SE_DCM);
		se_dcm_command = &bbdev_ipc_op->feca_job.command_chain_t.se_dcm_command_ch_obj;

		se_dcm_command->se_bits_per_re = rte_cpu_to_be_32(ldpc_enc->se_bits_per_re);
		for (i = 0; i < RTE_BBDEV_5G_MAX_SYMBOLS; i++) {
			se_dcm_command->mux[i].se_n_re_ack_re =
				rte_cpu_to_be_32(ldpc_enc->mux[i].se_n_re_ack_re);
			se_dcm_command->mux[i].se_n_csi1_re_n_csi2_re =
				rte_cpu_to_be_32(ldpc_enc->mux[i].se_n_csi1_re_n_csi2_re);
			se_dcm_command->mux[i].se_n_ulsch_re_d_ack =
				rte_cpu_to_be_32(ldpc_enc->mux[i].se_n_ulsch_re_d_ack);
			se_dcm_command->mux[i].se_d_csi1_d_csi2 =
				rte_cpu_to_be_32(ldpc_enc->mux[i].se_d_csi1_d_csi2);
			se_dcm_command->mux[i].se_d_ack2_ack2_re =
				rte_cpu_to_be_32(ldpc_enc->mux[i].se_d_ack2_ack2_re);
		}
	}

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
	rte_bbuf_dump(stdout, bbdev_enc_op->ldpc_enc.input.data,
		bbdev_enc_op->ldpc_enc.input.data->pkt_len);
	if (ldpc_enc->se_ce_mux)
		rte_hexdump(stdout, "SE DCM COMMAND", se_dcm_command, sizeof(se_dcm_command_t));
	else
		rte_hexdump(stdout, "SE COMMAND", se_command, sizeof(se_command_t));
#endif

	return 0;
}

static int
fill_feca_desc_dec(struct bbdev_la12xx_q_priv *q_priv,
		   struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
		   struct rte_bbdev_dec_op *bbdev_dec_op)
{
	struct rte_bbdev_op_ldpc_dec *ldpc_dec = &bbdev_dec_op->ldpc_dec;
	uint32_t A = bbdev_dec_op->ldpc_dec.hard_output.length * 8;
	uint32_t e[RTE_BBDEV_LDPC_MAX_CODE_BLOCKS], remove_tb_crc;
	uint32_t harq_en = 0, compact_harq = 1, size_harq_buffer, C, i;
	uint32_t set_index, base_graph2, lifting_index, mod_order;
	uint32_t tb_24_bit_crc, one_code_block;
	uint32_t num_output_bytes, e_floor_thresh, bits_per_cb;
	uint32_t num_filler_bits, e_div_qm_floor, e_div_qm_ceiling;
	uint32_t SD_SC_X1_INIT, SD_SC_X2_INIT, SD_CIRC_BUF;
	uint32_t di_start_ofst_floor[8], di_start_ofst_ceiling[8];
	uint32_t axi_data_num_bytes;
	sd_command_t sd_cmd, *sd_command;
	sd_dcm_command_t *sd_dcm_command;
	int16_t TBS_VALID;

	for (i = 0; i < ldpc_dec->tb_params.cab; i++)
		e[i] = ldpc_dec->tb_params.ea;
	for (; i < ldpc_dec->tb_params.c; i++)
		e[i] = ldpc_dec->tb_params.eb;

	remove_tb_crc =
		!!(ldpc_dec->op_flags & RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP);

	if (ldpc_dec->non_compact_harq)
		compact_harq = 0;

	if ((bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
	    ldpc_dec->harq_combined_input.bdata)
		harq_en = 1;

	la12xx_sch_decode_param_convert(ldpc_dec->basegraph, ldpc_dec->q_m,
			e, ldpc_dec->rv_index, A, ldpc_dec->q, ldpc_dec->n_id,
			ldpc_dec->n_rnti, !ldpc_dec->en_scramble,
			ldpc_dec->n_cb, remove_tb_crc, &size_harq_buffer, &C,
			ldpc_dec->codeblock_mask, &TBS_VALID, &set_index,
			&base_graph2, &lifting_index, &mod_order,
			&tb_24_bit_crc, &one_code_block, &e_floor_thresh,
			&num_output_bytes, &bits_per_cb, &num_filler_bits,
			&SD_SC_X1_INIT, &SD_SC_X2_INIT, &e_div_qm_floor,
			&e_div_qm_ceiling, di_start_ofst_floor,
			di_start_ofst_ceiling, &SD_CIRC_BUF,
			&axi_data_num_bytes);

	if (TBS_VALID == 0) {
		BBDEV_LA12XX_PMD_ERR("Invalid input for SD");
		return -1;
	}

	bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(FECA_JOB_SD);
	bbdev_ipc_op->feca_job.t_blk_id = q_priv->feca_blk_id_be32;

	sd_command = &bbdev_ipc_op->feca_job.command_chain_t.sd_command_ch_obj;

	/* TODO: Currently setting all fields for clarity.
	 * Remove unrequried fields
	 */
	sd_cmd.sd_cfg1.raw_sd_cfg1 = 0;
	sd_cmd.sd_cfg1.max_num_iterations = ldpc_dec->iter_max;
	sd_cmd.sd_cfg1.min_num_iterations = 1;
	sd_cmd.sd_cfg1.remove_tb_crc = remove_tb_crc;
	sd_cmd.sd_cfg1.tb_24_bit_crc = tb_24_bit_crc;
	sd_cmd.sd_cfg1.data_control_mux = ldpc_dec->sd_cd_demux;
	sd_cmd.sd_cfg1.one_code_block = one_code_block;
	sd_cmd.sd_cfg1.lifting_index = lifting_index;
	sd_cmd.sd_cfg1.base_graph2 = base_graph2;
	sd_cmd.sd_cfg1.set_index = set_index;
	sd_command->sd_cfg1.raw_sd_cfg1 =
		rte_cpu_to_be_32(sd_cmd.sd_cfg1.raw_sd_cfg1);

	sd_cmd.sd_cfg2.raw_sd_cfg2 = 0;
	sd_cmd.sd_cfg2.send_msi = 0;
	sd_cmd.sd_cfg2.complete_trig_en = 1;
	sd_cmd.sd_cfg2.harq_en = harq_en;
	sd_cmd.sd_cfg2.compact_harq = compact_harq;
	sd_cmd.sd_cfg2.mod_order = mod_order;
	sd_command->sd_cfg2.raw_sd_cfg2 =
		rte_cpu_to_be_32(sd_cmd.sd_cfg2.raw_sd_cfg2);

	sd_cmd.sd_sizes1.raw_sd_sizes1 = 0;
	sd_cmd.sd_sizes1.num_output_bytes = num_output_bytes;
	sd_cmd.sd_sizes1.e_floor_thresh = e_floor_thresh;
	sd_command->sd_sizes1.raw_sd_sizes1 =
		rte_cpu_to_be_32(sd_cmd.sd_sizes1.raw_sd_sizes1);

	sd_cmd.sd_sizes2.raw_sd_sizes2 = 0;
	sd_cmd.sd_sizes2.num_filler_bits = num_filler_bits;
	sd_cmd.sd_sizes2.bits_per_cb = bits_per_cb;
	sd_command->sd_sizes2.raw_sd_sizes2 =
		rte_cpu_to_be_32(sd_cmd.sd_sizes2.raw_sd_sizes2);

	sd_command->sd_circ_buf = rte_cpu_to_be_32(SD_CIRC_BUF);
	sd_command->sd_floor_num_input_bytes =
		rte_cpu_to_be_32(e_div_qm_floor);
	sd_command->sd_ceiling_num_input_bytes =
		rte_cpu_to_be_32(e_div_qm_ceiling);
	sd_command->sd_hram_base =
		rte_cpu_to_be_32(q_priv->feca_blk_id * per_queue_hram_size);
	sd_command->sd_sc_x1_init = rte_cpu_to_be_32(SD_SC_X1_INIT);
	sd_command->sd_sc_x2_init = rte_cpu_to_be_32(SD_SC_X2_INIT);

	/* out_addr has already been swapped in the calling function */
	sd_command->sd_axi_data_addr_low = bbdev_ipc_op->out_addr;
	sd_command->sd_axi_data_addr_high = 0;
	sd_command->sd_axi_data_num_bytes =
		rte_cpu_to_be_32(bbdev_dec_op->ldpc_dec.hard_output.length);
	sd_command->sd_axi_stat_addr_low = 0;
	sd_command->sd_axi_stat_addr_high = 0;

	for (i = 0; i < 8; i++)
		sd_command->sd_cb_mask[i] =
			rte_cpu_to_be_32(ldpc_dec->codeblock_mask[i]);

	sd_command->sd_di_start_ofst_floor[0] =
		rte_cpu_to_be_32((di_start_ofst_floor[1] << 16) |
		di_start_ofst_floor[0]);
	sd_command->sd_di_start_ofst_floor[1] =
		rte_cpu_to_be_32((di_start_ofst_floor[3] << 16) |
		di_start_ofst_floor[2]);
	sd_command->sd_di_start_ofst_floor[2] =
		rte_cpu_to_be_32((di_start_ofst_floor[5] << 16) |
		di_start_ofst_floor[4]);
	sd_command->sd_di_start_ofst_floor[3] =
		rte_cpu_to_be_32((di_start_ofst_floor[7] << 16) |
		di_start_ofst_floor[6]);
	sd_command->sd_di_start_ofst_ceiling[0] =
		rte_cpu_to_be_32((di_start_ofst_ceiling[1] << 16) |
		di_start_ofst_ceiling[0]);
	sd_command->sd_di_start_ofst_ceiling[1] =
		rte_cpu_to_be_32((di_start_ofst_ceiling[3] << 16) |
		di_start_ofst_ceiling[2]);
	sd_command->sd_di_start_ofst_ceiling[2] =
		rte_cpu_to_be_32((di_start_ofst_ceiling[5] << 16) |
		di_start_ofst_ceiling[4]);
	sd_command->sd_di_start_ofst_ceiling[3] =
		rte_cpu_to_be_32((di_start_ofst_ceiling[7] << 16) |
		di_start_ofst_ceiling[6]);

	if (ldpc_dec->sd_cd_demux) {
		bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(FECA_JOB_SD_DCM);
		sd_dcm_command = &bbdev_ipc_op->feca_job.command_chain_t.sd_dcm_command_ch_obj;

		sd_dcm_command->sd_llrs_per_re = rte_cpu_to_be_32(ldpc_dec->sd_llrs_per_re);
		for (i = 0; i < RTE_BBDEV_5G_MAX_SYMBOLS; i++) {
			sd_dcm_command->demux[i].sd_n_re_ack_re =
				rte_cpu_to_be_32(ldpc_dec->demux[i].sd_n_re_ack_re);
			sd_dcm_command->demux[i].sd_n_csi1_re_n_csi2_re =
				rte_cpu_to_be_32(ldpc_dec->demux[i].sd_n_csi1_re_n_csi2_re);
			sd_dcm_command->demux[i].sd_n_dlsch_re_d_ack =
				rte_cpu_to_be_32(ldpc_dec->demux[i].sd_n_dlsch_re_d_ack);
			sd_dcm_command->demux[i].sd_d_csi1_d_csi2 =
				rte_cpu_to_be_32(ldpc_dec->demux[i].sd_d_csi1_d_csi2);
			sd_dcm_command->demux[i].sd_d_ack2_ack2_re =
				rte_cpu_to_be_32(ldpc_dec->demux[i].sd_d_ack2_ack2_re);
		}
	}

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
	rte_bbuf_dump(stdout, bbdev_dec_op->ldpc_dec.input.data,
		bbdev_dec_op->ldpc_dec.input.data->data_len);
	if (ldpc_dec->sd_cd_demux)
		rte_hexdump(stdout, "SD DCM COMMAND", sd_dcm_command, sizeof(sd_dcm_command_t));
	else
		rte_hexdump(stdout, "SD COMMAND", sd_command, sizeof(sd_command_t));
#endif

	return 0;
}

static void
fill_feca_desc_polar_op(struct rte_mbuf *in_mbuf, struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
	       struct rte_pmd_la12xx_op *rte_pmd_op,  char *huge_start_addr)
{
	char *data_ptr;
	uint32_t l1_pcie_addr, i;

	if (rte_pmd_op->feca_obj.job_type ==  FECA_JOB_CE ||
	    rte_pmd_op->feca_obj.job_type == FECA_JOB_CE_DCM) {
		ce_command_t *l_ce_cmd = &rte_pmd_op->feca_obj.command_chain_t.ce_command_ch_obj;
		ce_command_t *ce_cmd = &bbdev_ipc_op->feca_job.command_chain_t.ce_command_ch_obj;

		rte_pmd_op->output.length = (l_ce_cmd->ce_cfg2.E + 7)/8 + l_ce_cmd->ce_cfg3.out_pad_bytes;
		bbdev_ipc_op->out_len = rte_cpu_to_be_32(rte_pmd_op->output.length);
		bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(rte_pmd_op->feca_obj.job_type);
		/* Set complete trigger */
		l_ce_cmd->ce_cfg1.complete_trig_en = 1;
		ce_cmd->ce_cfg1.raw_ce_cfg1 = rte_cpu_to_be_32(l_ce_cmd->ce_cfg1.raw_ce_cfg1);
		ce_cmd->ce_cfg2.raw_ce_cfg2 = rte_cpu_to_be_32(l_ce_cmd->ce_cfg2.raw_ce_cfg2);
		ce_cmd->ce_cfg3.raw_ce_cfg3 = rte_cpu_to_be_32(l_ce_cmd->ce_cfg3.raw_ce_cfg3);
		ce_cmd->ce_pe_indices.raw_ce_pe_indices = rte_cpu_to_be_32(l_ce_cmd->ce_pe_indices.raw_ce_pe_indices);
		data_ptr =  rte_pktmbuf_mtod(in_mbuf, char *);
		l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR + data_ptr - huge_start_addr;
		ce_cmd->ce_axi_addr_low = rte_cpu_to_be_32(l1_pcie_addr);
		ce_cmd->ce_axi_addr_high = 0;

		for (i = 0; i< 32; i++)
			ce_cmd->ce_fz_lut[i] =  rte_cpu_to_be_32(l_ce_cmd->ce_fz_lut[i]);

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, rte_pmd_op->input.data,
			rte_pmd_op->input.data->pkt_len);
		rte_hexdump(stdout, "CE COMMAND", ce_cmd, sizeof(ce_command_t));
#endif
	} else {
		cd_command_t *l_cd_cmd = &rte_pmd_op->feca_obj.command_chain_t.cd_command_ch_obj;
		cd_command_t *cd_cmd = &bbdev_ipc_op->feca_job.command_chain_t.cd_command_ch_obj;

		rte_pmd_op->output.length = (l_cd_cmd->cd_cfg1.K + 7)/8;
		bbdev_ipc_op->out_len = rte_cpu_to_be_32(rte_pmd_op->output.length);
		bbdev_ipc_op->feca_job.job_type = rte_cpu_to_be_32(rte_pmd_op->feca_obj.job_type);
		l_cd_cmd->cd_cfg1.complete_trig_en = 1;
		/* Set complete trigger */
		cd_cmd->cd_cfg1.raw_cd_cfg1 = rte_cpu_to_be_32(l_cd_cmd->cd_cfg1.raw_cd_cfg1);
		cd_cmd->cd_cfg2.raw_cd_cfg2 = rte_cpu_to_be_32(l_cd_cmd->cd_cfg2.raw_cd_cfg2);
		cd_cmd->cd_pe_indices.raw_cd_pe_indices = rte_cpu_to_be_32(l_cd_cmd->cd_pe_indices.raw_cd_pe_indices);
		cd_cmd->cd_axi_data_addr_low = bbdev_ipc_op->out_addr;
		cd_cmd->cd_axi_data_addr_high = 0;

		for (i = 0; i< 32; i++)
			cd_cmd->cd_fz_lut[i] =  rte_cpu_to_be_32(l_cd_cmd->cd_fz_lut[i]);

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		if (rte_pmd_op->input.data)
			rte_bbuf_dump(stdout, rte_pmd_op->input.data,
				rte_pmd_op->input.data->data_len);
		rte_hexdump(stdout, "CD COMMAND", cd_cmd, sizeof(cd_command_t));
#endif
	}	
}

#define MODEM_P2V(A) \
	((uint64_t) ((unsigned long) (A) \
		+ (unsigned long)(ipc_priv->peb_start.host_vaddr)))

static int
enqueue_single_op(struct bbdev_la12xx_q_priv *q_priv,
		void *bbdev_op, uint32_t op_type)
{
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_dequeue_op *bbdev_ipc_op;
	uint32_t q_id = q_priv->q_id, pi;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md = &(ch->br_msg_desc.md);
	ipc_bd_t *bdr, *bd;
	uint64_t virt, retry_count = 0;
	char *huge_start_addr =
		(char *)q_priv->bbdev_priv->ipc_priv->hugepg_start.host_vaddr;
	struct rte_mbuf *in_mbuf, *out_mbuf;
	struct rte_mbuf *harq_in_mbuf, *harq_out_mbuf;
	char *data_ptr;
	uint32_t l1_pcie_addr, sd_circ_buf;
	uint32_t total_out_bits;
	uint32_t harq_out_len_per_cb;
	uint16_t sys_cols;
	int ret;

	RTE_SET_USED(op_type);

	BBDEV_LA12XX_PMD_DP_DEBUG(
		"before bd_ring_full: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		md->pi, md->ci, md->pi_flag, md->ci_flag, md->ring_size);

	while (is_bd_ring_full(md) &&
			(retry_count < BBDEV_LA12XX_TX_RETRY_COUNT))
		retry_count++;

	if (retry_count == BBDEV_LA12XX_TX_RETRY_COUNT) {
		BBDEV_LA12XX_PMD_DP_DEBUG(
				"bd ring full for queue id: %d", q_id);
		h_stats->ipc_ch_stats[q_id].err_channel_full++;
		return IPC_CH_FULL;
	}

	pi = md->pi;
	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];

	virt = MODEM_P2V(bd->modem_ptr);
	bbdev_ipc_op = (struct bbdev_ipc_dequeue_op *)virt;
	bbdev_ipc_op->l2_cntx_l =
	       lower_32_bits((uint64_t)bbdev_op);
	bbdev_ipc_op->l2_cntx_h =
	       upper_32_bits((uint64_t)bbdev_op);
	bbdev_ipc_op->queue_id = rte_cpu_to_be_16(q_id);
	bd->len = sizeof(struct bbdev_ipc_dequeue_op);

	if (op_type == BBDEV_IPC_ENC_OP_TYPE) {
		in_mbuf = ((struct rte_bbdev_enc_op *)
			bbdev_op)->ldpc_enc.input.data;
		out_mbuf = ((struct rte_bbdev_enc_op *)
			bbdev_op)->ldpc_enc.output.data;
	} else if (op_type == BBDEV_IPC_DEC_OP_TYPE) {
		in_mbuf = ((struct rte_bbdev_dec_op *)
			bbdev_op)->ldpc_dec.input.data;
		out_mbuf = ((struct rte_bbdev_dec_op *)
			bbdev_op)->ldpc_dec.hard_output.data;
	} else {
		in_mbuf = ((struct rte_pmd_la12xx_op *)bbdev_op)->input.data;
		out_mbuf = ((struct rte_pmd_la12xx_op *)bbdev_op)->output.data;
	}

	if (in_mbuf) {
		data_ptr =  rte_pktmbuf_mtod(in_mbuf, char *);
		l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR +
			       data_ptr - huge_start_addr;
		bbdev_ipc_op->in_addr = l1_pcie_addr;
		bbdev_ipc_op->in_len = in_mbuf->pkt_len;
	}

	if (out_mbuf) {
		data_ptr =  rte_pktmbuf_mtod(out_mbuf, char *);
		l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR +
			data_ptr - huge_start_addr;
		bbdev_ipc_op->out_addr = rte_cpu_to_be_32(l1_pcie_addr);
	}

	if (op_type == BBDEV_IPC_ENC_OP_TYPE) {
		struct rte_bbdev_enc_op *bbdev_enc_op = bbdev_op;
		struct rte_bbdev_op_ldpc_enc *ldpc_enc =
					&bbdev_enc_op->ldpc_enc;

		total_out_bits = (ldpc_enc->tb_params.cab *
			ldpc_enc->tb_params.ea) + (ldpc_enc->tb_params.c -
			ldpc_enc->tb_params.cab) * ldpc_enc->tb_params.eb;


		if (ldpc_enc->se_ce_mux)
			ldpc_enc->output.length =
					ldpc_enc->se_ce_mux_output_size;
		else
			ldpc_enc->output.length = (total_out_bits + 7)/8;

		ret = fill_feca_desc_enc(q_priv, in_mbuf, bbdev_ipc_op,
					 bbdev_op, huge_start_addr);
		if (ret) {
			BBDEV_LA12XX_PMD_ERR(
				"fill_feca_desc_enc failed, ret: %d", ret);
			return ret;
		}
		bbdev_ipc_op->out_len =
			rte_cpu_to_be_32(ldpc_enc->output.length);
		rte_bbuf_append(out_mbuf,
				ldpc_enc->output.length);
	} else if (op_type == BBDEV_IPC_DEC_OP_TYPE) {
		struct rte_bbdev_dec_op *bbdev_dec_op = bbdev_op;
		struct rte_bbdev_op_ldpc_dec *ldpc_dec =
					&bbdev_dec_op->ldpc_dec;
		uint32_t byte, bit, num_code_blocks = 0;
		uint32_t *codeblock_mask, i;

		sys_cols =  (ldpc_dec->basegraph == 1) ? 22 : 10;
		if (ldpc_dec->tb_params.c == 1) {
			total_out_bits = ((sys_cols * ldpc_dec->z_c) -
					ldpc_dec->n_filler);
			/* 5G-NR protocol uses 16 bit CRC when output packet
			 * size <= 3824 (bits). Otherwise 24 bit CRC is used.
			 * Adjust the output bits accordingly
			 */
			if (total_out_bits - 16 <= 3824)
				total_out_bits -= 16;
			else
				total_out_bits -= 24;
			ldpc_dec->hard_output.length = (total_out_bits / 8);
		} else {
			total_out_bits = (((sys_cols * ldpc_dec->z_c) -
					ldpc_dec->n_filler - 24) *
					ldpc_dec->tb_params.c);
			ldpc_dec->hard_output.length =
					(total_out_bits / 8) - 3;
		}

		codeblock_mask = ldpc_dec->codeblock_mask;
		if (!ldpc_dec->non_compact_harq && (ldpc_dec->op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE)) {
			/* Get the total number of enabled code blocks */
			for (i = 0; i < ldpc_dec->tb_params.c; i++) {
				byte = i / 32;
				bit = i % 32;
				if (codeblock_mask[byte] & (1 << bit))
					num_code_blocks++;
			}
		} else {
			/* Set the codeblock mask */
			for (i = 0; i < ldpc_dec->tb_params.c; i++) {
				/* Set the bit in codeblock */
				byte = i / 32;
				bit = i % 32;
				codeblock_mask[byte] |= (1 << bit);
			}
			num_code_blocks = ldpc_dec->tb_params.c;
		}

		bbdev_ipc_op->num_code_blocks =
			rte_cpu_to_be_32(num_code_blocks);

		ret = fill_feca_desc_dec(q_priv, bbdev_ipc_op, bbdev_op);
		if (ret) {
			BBDEV_LA12XX_PMD_ERR(
				"fill_feca_desc_dec failed, ret: %d", ret);
			return ret;
		}

		/* Set up HARQ related information */
		harq_in_mbuf = bbdev_dec_op->ldpc_dec.harq_combined_input.data;
		if ((bbdev_dec_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    harq_in_mbuf) {
			data_ptr =  rte_pktmbuf_mtod(harq_in_mbuf, char *);
			l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR +
				data_ptr - huge_start_addr;
			bbdev_ipc_op->harq_in_addr = l1_pcie_addr;
			bbdev_ipc_op->harq_in_len = harq_in_mbuf->pkt_len;
		}

		harq_out_mbuf = bbdev_dec_op->ldpc_dec.harq_combined_output.data;
		if ((bbdev_dec_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) &&
		    harq_out_mbuf) {
			sd_circ_buf = rte_be_to_cpu_32(
				bbdev_ipc_op->feca_job.command_chain_t.sd_command_ch_obj.sd_circ_buf);
			data_ptr =  rte_pktmbuf_mtod(harq_out_mbuf, char *);
			l1_pcie_addr = (uint32_t)GUL_USER_HUGE_PAGE_ADDR +
				data_ptr - huge_start_addr;
			bbdev_ipc_op->harq_out_addr =
				rte_cpu_to_be_32(l1_pcie_addr);
			harq_out_len_per_cb =
				(128 * (uint32_t)ceil((double)sd_circ_buf/128));

			if (harq_out_len_per_cb * ldpc_dec->tb_params.c >
			    per_queue_hram_size) {
				BBDEV_LA12XX_PMD_ERR(
					"harq len required (%d) is more than allocated (%d)",
					harq_out_len_per_cb *
					ldpc_dec->tb_params.c,
					per_queue_hram_size);
				return -1;
			}

			bbdev_ipc_op->harq_out_len_per_cb =
				rte_cpu_to_be_32(harq_out_len_per_cb);
		}

		bbdev_ipc_op->out_len =
			rte_cpu_to_be_32(ldpc_dec->hard_output.length);

		/* In case of retransmission, mbuf already have been filled in
		 * the previous transmission. So skip appending data in mbuf.
		 */
		if ((rte_bbuf_data_len(out_mbuf)) == 0 ||
		    (ldpc_dec->rv_index == 0))
			rte_bbuf_append(out_mbuf,
					ldpc_dec->hard_output.length);

		if (ldpc_dec->max_num_harq_contexts)
			bbdev_ipc_op->max_num_harq_contexts =
				rte_cpu_to_be_32(ldpc_dec->max_num_harq_contexts);
	} else {
		/* Polar encode/decode processing */
		struct rte_pmd_la12xx_op *rte_pmd_op =
				(struct rte_pmd_la12xx_op *)bbdev_op;

		fill_feca_desc_polar_op(in_mbuf, bbdev_ipc_op, rte_pmd_op,
					huge_start_addr);

		if (out_mbuf) {
			bbdev_ipc_op->out_len =
				rte_cpu_to_be_32(rte_pmd_op->output.length);
			rte_bbuf_append(out_mbuf,
				rte_pmd_op->output.length);
		}
	}

	/* Move Producer Index forward */
	pi++;
	/* Wait for Data Copy and pi_flag update to complete
	 * before updating pi
	 */
	rte_mb();
	/* Flip the PI flag, if wrapping */
	if (md->ring_size == pi) {
		md->pi = 0;
		md->pi_flag = md->pi_flag ? 0 : 1;
	} else
		md->pi = pi;

	h_stats->ipc_ch_stats[q_id].num_of_msg_sent++;
	h_stats->ipc_ch_stats[q_id].total_msg_length += bd->len;

	BBDEV_LA12XX_PMD_DP_DEBUG(
			"enter: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
			md->pi, md->ci, md->pi_flag, md->ci_flag, md->ring_size);

	return 0;
}

/* Enqueue decode burst */
	static uint16_t
enqueue_dec_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < nb_ops; nb_enqueued++) {
		ret = enqueue_single_op(q_priv, ops[nb_enqueued],
				BBDEV_IPC_DEC_OP_TYPE);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += nb_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

/* Enqueue encode burst */
static uint16_t
enqueue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < nb_ops; nb_enqueued++) {
		ret = enqueue_single_op(q_priv, ops[nb_enqueued],
				BBDEV_IPC_ENC_OP_TYPE);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += nb_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

#define JOIN_VA32_64(H, L) ((uint64_t)(((H) << 32) | (L)))
static inline uint64_t join_va2_64(uint32_t h, uint32_t l)
{
	uint64_t high = 0x0;

	high = h;
	return JOIN_VA32_64(high, l);
}

static inline int is_bd_ring_empty(ipc_br_md_t *md)
{
	uint32_t ci = md->ci;
	uint32_t pi = md->pi;

	if (ci == pi) {
		uint32_t ci_flag = md->ci_flag;
		uint32_t pi_flag = md->pi_flag;

		if (ci_flag == pi_flag)
			return 1; /* No more Buffer */
	}
	return 0;
}

/* Dequeue encode burst */
static int
dequeue_single_op(struct bbdev_la12xx_q_priv *q_priv, void *dst)
{
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	uint32_t q_id = q_priv->q_id + HOST_RX_QUEUEID_OFFSET;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md;
	uint32_t ci, msg_len;
	uint64_t vaddr2 = 0;
	ipc_bd_t *bdr, *bd;

	md = &(ch->br_msg_desc.md);
	if (is_bd_ring_empty(md)) {
		h_stats->ipc_ch_stats[q_id].err_channel_empty++;
		return IPC_CH_EMPTY;
	}
	BBDEV_LA12XX_PMD_DP_DEBUG(
		"pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		md->pi, md->ci, md->pi_flag, md->ci_flag, md->ring_size);

	ci = md->ci;
	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];
	/* Move Consumer Index forward */
	ci++;
	/* Flip the CI flag, if wrapping */
	if (md->ring_size == ci) {
		ci = 0;
		md->ci_flag = md->ci_flag ? 0 : 1;
	}
	md->ci = ci;

	msg_len = bd->len;
	if (msg_len > md->msg_size) {
		h_stats->ipc_ch_stats[q_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}
	vaddr2 = join_va2_64(bd->host_virt_h, bd->host_virt_l);
	ipc_memcpy(dst, (void *)(vaddr2), msg_len);

	h_stats->ipc_ch_stats[q_id].num_of_msg_recved++;
	h_stats->ipc_ch_stats[q_id].total_msg_length += msg_len;
	BBDEV_LA12XX_PMD_DP_DEBUG(
		"exit: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		md->pi, md->ci, md->pi_flag, md->ci_flag, md->ring_size);

	return 0;
}

/* Dequeue decode burst */
static uint16_t
dequeue_dec_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	struct rte_bbdev_dec_op *l_op;
	struct rte_mbuf *harq_out_mbuf;
	int nb_dequeued, ret, tb_crc, cb_cnt;
	uint32_t harq_out_len;

	for (nb_dequeued = 0; nb_dequeued < nb_ops; nb_dequeued++) {
		ret = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (ret)
			break;
		ops[nb_dequeued] = (struct rte_bbdev_dec_op *)(((uint64_t)
			bbdev_ipc_op.l2_cntx_h << 32) |
			bbdev_ipc_op.l2_cntx_l);

		l_op = ops[nb_dequeued];
		l_op->status = bbdev_ipc_op.status;

		harq_out_mbuf = l_op->ldpc_dec.harq_combined_output.data;
		if ((l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) &&
		    harq_out_mbuf) {
			harq_out_len =
				rte_be_to_cpu_32(bbdev_ipc_op.harq_out_len);
			l_op->ldpc_dec.harq_combined_output.length =
				harq_out_len;
			rte_bbuf_append(harq_out_mbuf, harq_out_len);
			l_op->status = 1 << RTE_BBDEV_CRC_ERROR;
		}

		tb_crc = 0;
		if (l_op->ldpc_dec.code_block_mode ||
		    (l_op->ldpc_dec.tb_params.c == 1)) {
			cb_cnt = 1;
			tb_crc = 0;
		} else {
			cb_cnt = l_op->ldpc_dec.tb_params.c;
			tb_crc = l_op->ldpc_dec.tb_params.c;
		}

		/* Copy code block crc status bits + TB status bit */
		ipc_memcpy(l_op->crc_stat, (void *)MODEM_P2V(bbdev_ipc_op.crc_stat_addr), (cb_cnt >> 3) + 1);
		if (!(l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) &&
		    !(l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    !(l_op->crc_stat[tb_crc >> 3] & (1 << (tb_crc & 0x7))))
			l_op->status = 1 << RTE_BBDEV_CRC_ERROR;

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, ops[nb_dequeued]->ldpc_dec.hard_output.data,
			ops[nb_dequeued]->ldpc_dec.hard_output.data->data_len);
#endif
	}

	if (ret != IPC_CH_EMPTY)
		q_data->queue_stats.dequeue_err_count += nb_ops - nb_dequeued;
	q_data->queue_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

/* Dequeue encode burst */
static uint16_t
dequeue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	int nb_dequeued, ret;

	for (nb_dequeued = 0; nb_dequeued < nb_ops; nb_dequeued++) {
		ret = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (ret)
			break;
		ops[nb_dequeued] = (struct rte_bbdev_enc_op *)(((uint64_t)
			bbdev_ipc_op.l2_cntx_h << 32) |
			bbdev_ipc_op.l2_cntx_l);
		ops[nb_dequeued]->status = bbdev_ipc_op.status;
#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, ops[nb_dequeued]->ldpc_enc.output.data,
			ops[nb_dequeued]->ldpc_enc.output.data->data_len);
#endif
	}

	if (ret != IPC_CH_EMPTY)
		q_data->queue_stats.dequeue_err_count += nb_ops - nb_dequeued;
	q_data->queue_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

uint16_t
rte_pmd_la12xx_enqueue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_queue_data *q_data = &dev->data->queues[queue_id];
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < num_ops; nb_enqueued++) {
		ret = enqueue_single_op(q_priv, ops[nb_enqueued],
					BBDEV_IPC_POLAR_OP_TYPE);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += num_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;
	
	return nb_enqueued;
}

uint16_t
rte_pmd_la12xx_dequeue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_queue_data *q_data = &dev->data->queues[queue_id];
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	int nb_dequeued, ret;

	for (nb_dequeued = 0; nb_dequeued < num_ops; nb_dequeued++) {
		ret = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (ret)
			break;
		ops[nb_dequeued] = (struct rte_pmd_la12xx_op *)(((uint64_t)
			bbdev_ipc_op.l2_cntx_h << 32) |
			bbdev_ipc_op.l2_cntx_l);
		ops[nb_dequeued]->status = bbdev_ipc_op.status;
#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, ops[nb_dequeued]->output.data,
			ops[nb_dequeued]->output.data->data_len);
#endif
	}

	if (ret != IPC_CH_EMPTY)
		q_data->queue_stats.dequeue_err_count += num_ops - nb_dequeued;
	q_data->queue_stats.dequeued_count += nb_dequeued;
	
	return nb_dequeued;
}


void
rte_pmd_la12xx_op_init(struct rte_mempool *mempool, __rte_unused void *arg, void *element,
		__rte_unused unsigned int n)
{
	struct rte_pmd_la12xx_op *op = element;

	memset(op, 0, mempool->elt_size);
	op->mempool = mempool;
}

static struct hugepage_info *
get_hugepage_info(void)
{
	struct hugepage_info *hp_info;
	struct rte_memseg *mseg;

	PMD_INIT_FUNC_TRACE();

	/* TODO - Use a better way */
	hp_info = rte_malloc(NULL, sizeof(struct hugepage_info), 0);
	if (!hp_info) {
		BBDEV_LA12XX_PMD_ERR("Unable to allocate on local heap");
		return NULL;
	}

	mseg = rte_mem_virt2memseg(hp_info, NULL);
	hp_info->vaddr = mseg->addr;
	hp_info->paddr = rte_mem_virt2phy(mseg->addr);
	hp_info->len = mseg->len;

	return hp_info;
}

static int open_ipc_dev(void)
{
	char dev_initials[] = "gulipcgul", dev_path[PATH_MAX];
	struct dirent *entry;
	int dev_ipc = 0;
	DIR *dir;

	dir = opendir("/dev/");
	if (!dir) {
		BBDEV_LA12XX_PMD_ERR("Unable to open /dev/");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (!strncmp(dev_initials, entry->d_name,
		    sizeof(dev_initials) - 1))
			break;
	}

	if (!entry) {
		BBDEV_LA12XX_PMD_ERR("Error: No gulipcgul device");
		return -1;
	}

	sprintf(dev_path, "/dev/%s", entry->d_name);
	dev_ipc = open(dev_path, O_RDWR);
	if (dev_ipc  < 0) {
		BBDEV_LA12XX_PMD_ERR("Error: Cannot open %s", dev_path);
		return -errno;
	}

	return dev_ipc;
}

static int
setup_bbdev(struct rte_bbdev *dev)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = NULL;
	struct hugepage_info *hp = NULL;
	ipc_channel_us_t *ipc_priv_ch = NULL;
	int dev_ipc = 0, dev_mem = 0, i;
	ipc_metadata_t *ipc_md;
	struct gul_hif *mhif;
	uint32_t phy_align = 0;
	int ret, instance_id = 0;
	struct gul_hif *hif_start = NULL;

	PMD_INIT_FUNC_TRACE();

	/* TODO - get a better way */
	/* Get the hugepage info against it */
	hp = get_hugepage_info();
	if (!hp) {
		BBDEV_LA12XX_PMD_ERR("Unable to get hugepage info");
		ret = -ENOMEM;
		goto err;
	}

	BBDEV_LA12XX_PMD_DEBUG("%lx %p %lx", hp->paddr, hp->vaddr, hp->len);

	ipc_priv = rte_zmalloc(0, sizeof(ipc_userspace_t), 0);
	if (ipc_priv == NULL) {
		BBDEV_LA12XX_PMD_ERR(
			"Unable to allocate memory for ipc priv");
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
		ipc_priv_ch = rte_zmalloc(0, sizeof(ipc_channel_us_t), 0);
		if (ipc_priv_ch == NULL) {
			BBDEV_LA12XX_PMD_ERR(
				"Unable to allocate memory for channels");
			ret = -ENOMEM;
		}
		ipc_priv->channels[i] = ipc_priv_ch;
	}

	dev_mem = open("/dev/mem", O_RDWR);
	if (dev_mem < 0) {
		BBDEV_LA12XX_PMD_ERR("Error: Cannot open /dev/mem");
		ret = -errno;
		goto err;
	}

	dev_ipc = open_ipc_dev();
	if (dev_ipc < 0) {
		BBDEV_LA12XX_PMD_ERR("Error: open_ipc_dev failed");
		goto err;
	}

	/* TODO - Get instance id from vdev */
	ipc_priv->instance_id = instance_id;
	ipc_priv->dev_ipc = dev_ipc;
	ipc_priv->dev_mem = dev_mem;
	BBDEV_LA12XX_PMD_DEBUG("hugepg input %lx %p %lx",
		hp->paddr, hp->vaddr, hp->len);

	ipc_priv->sys_map.hugepg_start.host_phys = hp->paddr;
	ipc_priv->sys_map.hugepg_start.size = hp->len;
	/* Send IOCTL to get system map */
	/* Send IOCTL to put hugepg_start map */
	ret = ioctl(dev_ipc, IOCTL_GUL_IPC_GET_SYS_MAP, &ipc_priv->sys_map);
	if (ret) {
		BBDEV_LA12XX_PMD_ERR(
			"IOCTL_GUL_IPC_GET_SYS_MAP ioctl failed");
		goto err;
	}

	phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
	ipc_priv->mhif_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.mhif_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, dev_mem,
		     (ipc_priv->sys_map.mhif_start.host_phys - phy_align));
	if (ipc_priv->mhif_start.host_vaddr == MAP_FAILED) {
		BBDEV_LA12XX_PMD_ERR("MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->mhif_start.host_vaddr = (void *) ((uint64_t)
		(ipc_priv->mhif_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.peb_start.host_phys % 0x1000);
	ipc_priv->peb_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.peb_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, dev_mem,
		     (ipc_priv->sys_map.peb_start.host_phys - phy_align));
	if (ipc_priv->peb_start.host_vaddr == MAP_FAILED) {
		BBDEV_LA12XX_PMD_ERR("MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->peb_start.host_vaddr = (void *)((uint64_t)
		(ipc_priv->peb_start.host_vaddr) + phy_align);

	ipc_priv->hugepg_start.host_phys = hp->paddr;
	ipc_priv->hugepg_start.host_vaddr = hp->vaddr;
	ipc_priv->hugepg_start.size = ipc_priv->sys_map.hugepg_start.size;
	ipc_priv->hugepg_start.modem_phys =
		ipc_priv->sys_map.hugepg_start.modem_phys;

	ipc_priv->mhif_start.host_phys =
		ipc_priv->sys_map.mhif_start.host_phys;
	ipc_priv->mhif_start.size = ipc_priv->sys_map.mhif_start.size;
	ipc_priv->peb_start.host_phys = ipc_priv->sys_map.peb_start.host_phys;
	ipc_priv->peb_start.size = ipc_priv->sys_map.peb_start.size;

	BBDEV_LA12XX_PMD_INFO("peb %lx %p %x",
			ipc_priv->peb_start.host_phys,
			ipc_priv->peb_start.host_vaddr,
			ipc_priv->peb_start.size);
	BBDEV_LA12XX_PMD_INFO("hugepg %lx %p %x",
			ipc_priv->hugepg_start.host_phys,
			ipc_priv->hugepg_start.host_vaddr,
			ipc_priv->hugepg_start.size);
	BBDEV_LA12XX_PMD_INFO("mhif %lx %p %x",
			ipc_priv->mhif_start.host_phys,
			ipc_priv->mhif_start.host_vaddr,
			ipc_priv->mhif_start.size);
	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	/* initiatlize Host instance stats */
	h_stats = &(mhif->stats.h_ipc_stats);

	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
			mhif->ipc_regs.ipc_mdata_offset);

	if (sizeof(ipc_metadata_t) != mhif->ipc_regs.ipc_mdata_size) {
		h_stats->err_md_sz_mismatch++;
		BBDEV_LA12XX_PMD_ERR(
			"\n ipc_metadata_t =%lx, mhif->ipc_regs.ipc_mdata_size=%x",
			sizeof(ipc_metadata_t), mhif->ipc_regs.ipc_mdata_size);
		BBDEV_LA12XX_PMD_ERR(
			"--> mhif->ipc_regs.ipc_mdata_offset= %x",
			mhif->ipc_regs.ipc_mdata_offset);
		BBDEV_LA12XX_PMD_ERR(
			"gul_hif size=%lx", sizeof(struct gul_hif));
		return IPC_MD_SZ_MISS_MATCH;
	}

	ipc_priv->instance = (ipc_instance_t *)
		(&ipc_md->instance_list[instance_id]);

	BBDEV_LA12XX_PMD_DEBUG("finish host init");

	priv->ipc_priv = ipc_priv;

	hif_start = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;

	/* Point to the HIF stats */
	stats = &(hif_start->stats);

	return 0;

err:
	rte_free(hp);
	rte_free(ipc_priv);
	rte_free(ipc_priv_ch);
	if (dev_mem)
		close(dev_mem);
	if (dev_ipc)
		close(dev_ipc);
	if (ipc_priv->mhif_start.host_vaddr &&
	    (ipc_priv->mhif_start.host_vaddr != MAP_FAILED)) {
		phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
		munmap(ipc_priv->mhif_start.host_vaddr,
			ipc_priv->sys_map.mhif_start.size + phy_align);
	}
	if (ipc_priv->peb_start.host_vaddr &&
	    (ipc_priv->peb_start.host_vaddr != MAP_FAILED)) {
		phy_align = (ipc_priv->sys_map.peb_start.host_phys % 0x1000);
		munmap(ipc_priv->peb_start.host_vaddr,
			ipc_priv->sys_map.peb_start.size + phy_align);
	}

	return ret;
}

/* Create device */
static int
la12xx_bbdev_create(struct rte_vdev_device *vdev)
{
	struct rte_bbdev *bbdev;
	const char *name = rte_vdev_device_name(vdev);
	int ret;

	PMD_INIT_FUNC_TRACE();

	bbdev = rte_bbdev_allocate(name);
	if (bbdev == NULL)
		return -ENODEV;

	bbdev->data->dev_private = rte_zmalloc(name,
			sizeof(struct bbdev_la12xx_private),
			RTE_CACHE_LINE_SIZE);
	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_release(bbdev);
		return -ENOMEM;
	}

	ret = setup_bbdev(bbdev);
	if (ret) {
		BBDEV_LA12XX_PMD_ERR("IPC Setup failed");
		rte_free(bbdev->data->dev_private);
		return ret;
	}

	bbdev->dev_ops = &pmd_ops;
	bbdev->device = &vdev->device;
	bbdev->data->socket_id = 0;
	bbdev->intr_handle = NULL;

	/* register rx/tx burst functions for data path */
	bbdev->dequeue_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_dec_ops = enqueue_dec_ops;

	bbdev->dequeue_ldpc_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_ldpc_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_ldpc_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_ldpc_dec_ops = enqueue_dec_ops;

	return 0;
}

/* Initialise device */
static int
la12xx_bbdev_probe(struct rte_vdev_device *vdev)
{
	const char *name;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	return la12xx_bbdev_create(vdev);
}

/* Uninitialise device */
static int
la12xx_bbdev_remove(struct rte_vdev_device *vdev)
{
	struct rte_bbdev *bbdev;
	const char *name;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	bbdev = rte_bbdev_get_named_dev(name);
	if (bbdev == NULL)
		return -EINVAL;

	rte_free(bbdev->data->dev_private);

	return rte_bbdev_release(bbdev);
}

static struct rte_vdev_driver bbdev_la12xx_pmd_drv = {
	.probe = la12xx_bbdev_probe,
	.remove = la12xx_bbdev_remove
};

RTE_PMD_REGISTER_VDEV(DRIVER_NAME, bbdev_la12xx_pmd_drv);
RTE_PMD_REGISTER_ALIAS(DRIVER_NAME, bbdev_la12xx);

RTE_INIT(la12xx_bbdev_init_log)
{
	bbdev_la12xx_logtype_pmd = rte_log_register("pmd.bb.la12xx");
	if (bbdev_la12xx_logtype_pmd >= 0)
		rte_log_set_level(bbdev_la12xx_logtype_pmd, RTE_LOG_NOTICE);
}
