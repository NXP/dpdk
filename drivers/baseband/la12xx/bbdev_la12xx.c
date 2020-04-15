/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <rte_common.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_kvargs.h>

#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>

#include <geul_bbdev_ipc.h>
#include <geul_ipc_um.h>
#include <gul_host_if.h>

#include "bbdev_la12xx.h"
#include "bbdev_la12xx_pmd_logs.h"

#define DRIVER_NAME baseband_la12xx

/* la12xx BBDev logging ID */
int bbdev_la12xx_logtype_pmd;

struct gul_ipc_stats *h_stats;
struct gul_stats *stats; /**< Stats for Host & modem (HIF) */

/* Get device info */
static void
la12xx_info_get(struct rte_bbdev *dev,
		struct rte_bbdev_driver_info *dev_info)
{
	/* TODO: Add LDPC capability */
	static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
		RTE_BBDEV_END_OF_CAPABILITIES_LIST(),
	};
	static struct rte_bbdev_queue_conf default_queue_conf = {
		.queue_size = MAX_CHANNEL_DEPTH,
	};

	PMD_INIT_FUNC_TRACE();

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = LS12XX_MAX_QUEUES;
	dev_info->queue_size_lim = MAX_CHANNEL_DEPTH;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 0;

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

static int
is_channel_configured(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;

	PMD_INIT_FUNC_TRACE();

	/* Read mask */
	ipc_bitmask_t mask = ipc_instance->cfgmask[channel_id /
				bitcount(ipc_bitmask_t)];

	/* !! to return either 0 or 1 */
	return !!(mask & (1 << (channel_id % bitcount(mask))));
}

static void
mark_channel_as_configured(uint32_t channel_id,
			       ipc_instance_t *instance)
{
	/* Read mask */
	ipc_bitmask_t mask = instance->cfgmask[channel_id /
				bitcount(ipc_bitmask_t)];

	PMD_INIT_FUNC_TRACE();

	/* Set channel specific bit */
	mask |= 1 << (channel_id % bitcount(mask));

	/* Write mask */
	instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)] = mask;
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

	if (is_channel_configured(channel_id, ipc_priv)) {
		BBDEV_LA12XX_PMD_WARN(
			"Channel already configured. NOT configuring again");
		return IPC_SUCCESS;
	}

	BBDEV_LA12XX_PMD_DEBUG("channel: %u, depth: %u, msg size: %u",
		channel_id, MAX_CHANNEL_DEPTH, msg_size);

	/* Start init of channel */
	/* TODO: Use conf->queue_size instead of MAX_CHANNEL_DEPTH */
	ch->br_msg_desc.md.ring_size = MAX_CHANNEL_DEPTH;
	ch->br_msg_desc.md.ci_flag = 0;
	ch->br_msg_desc.md.pi_flag = 0;
	ch->br_msg_desc.md.pi = 0;
	ch->br_msg_desc.md.ci = 0;
	ch->br_msg_desc.md.msg_size = msg_size;
	for (i = 0; i < MAX_CHANNEL_DEPTH; i++) {
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

	mark_channel_as_configured(channel_id, ipc_priv->instance);
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

	BBDEV_LA12XX_PMD_DEBUG("setting up queue %d", q_id);

	/* Call ipc_configure_channel */
	ret = ipc_queue_configure((q_id + HOST_RX_QUEUEID_OFFSET),
				  ipcu, queue_conf);
	if (ret) {
		BBDEV_LA12XX_PMD_ERR("Unable to setup queue (%d) (err=%d)",
		       q_id, ret);
		return ret;
	}

	return 0;
}

static int
la12xx_start(struct rte_bbdev *dev)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipcu = priv->ipc_priv;
	int ready = 1;
	struct gul_hif *hif_start;

	PMD_INIT_FUNC_TRACE();

	hif_start = (struct gul_hif *)ipcu->mhif_start.host_vaddr;

	/* Set Host Read bit */
	SET_HIF_HOST_RDY(hif_start, HIF_HOST_READY_IPC_APP);

	/* Now wait for modem ready bit */
	while (ready)
		ready = !CHK_HIF_MOD_RDY(hif_start, HIF_MOD_READY_IPC_APP);

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
	uint64_t virt;

	BBDEV_LA12XX_PMD_DP_DEBUG(
		"before bd_ring_full: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		md->pi, md->ci, md->pi_flag, md->ci_flag, md->ring_size);

	if (is_bd_ring_full(md)) {
		h_stats->ipc_ch_stats[q_id].err_channel_full++;
		return IPC_CH_FULL;
	}

	pi = md->pi;
	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];

	virt = MODEM_P2V(bd->modem_ptr);
	bbdev_ipc_op = (struct bbdev_ipc_dequeue_op *)virt;
	/* TODO: Copy other fields and have separate API for it */
	bbdev_ipc_op->op_type = op_type;
	bbdev_ipc_op->l2_cntx_l =
	       lower_32_bits((uint64_t)bbdev_op);
	bbdev_ipc_op->l2_cntx_h =
	       upper_32_bits((uint64_t)bbdev_op);
	bd->len = sizeof(struct bbdev_ipc_dequeue_op);

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

	if (ret != IPC_CH_FULL)
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

	if (ret != IPC_CH_FULL)
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
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	int nb_dequeued, ret;

	for (nb_dequeued = 0; nb_dequeued < nb_ops; nb_dequeued++) {
		ret = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (ret)
			break;
		ops[nb_dequeued] = (struct rte_bbdev_dec_op *)(((uint64_t)
			bbdev_ipc_op.l2_cntx_h << 32) |
			bbdev_ipc_op.l2_cntx_l);
		ops[nb_dequeued]->status = bbdev_ipc_op.status;
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
	}

	if (ret != IPC_CH_EMPTY)
		q_data->queue_stats.dequeue_err_count += nb_ops - nb_dequeued;
	q_data->queue_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
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

	dev_ipc = open("/dev/gulipcgul0", O_RDWR);
	if (dev_ipc  < 0) {
		BBDEV_LA12XX_PMD_ERR("Error: Cannot open /dev/ipc_gul_x");
		ret = -errno;
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
