/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
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
#include <rte_io.h>

#include <rte_bbdev.h>
#include <rte_bbuf.h>
#include <rte_bbdev_pmd.h>

#include "bbdev_la93xx.h"
#include "bbdev_la93xx_pmd_logs.h"

#include "la9310_host_if.h"
#include "la93xx_bbdev_ipc.h"

#define DRIVER_NAME baseband_la93xx

/*  Initialisation params structure that can be used by LA93xx BBDEV driver */
struct bbdev_la93xx_params {
	int8_t modem_id; /*< LA93xx modem instance id */
};

#define BBDEV_LA93XX_VDEV_MODEM_ID_ARG	"modem"
#define LA93XX_MAX_MODEM 4

#define LA93XX_MAX_CORES	1

static const char * const bbdev_la93xx_valid_params[] = {
	BBDEV_LA93XX_VDEV_MODEM_ID_ARG,
};

static inline char *
get_data_ptr(struct rte_bbdev_op_data *op_data)
{
	if (op_data->is_direct_mem)
		return op_data->mem;

	return rte_bbuf_mtod((struct rte_bbuf *)op_data->bdata, char *);
}

/* la93xx BBDev logging ID */
int bbdev_la93xx_logtype;

static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
	{
		.type   = RTE_BBDEV_OP_RAW,
	},
	RTE_BBDEV_END_OF_CAPABILITIES_LIST()
};

static struct rte_bbdev_queue_conf default_queue_conf = {
	.queue_size = IPC_MAX_DEPTH,
};

/* Get device info */
static void
la93xx_info_get(struct rte_bbdev *dev,
		struct rte_bbdev_driver_info *dev_info)
{
	PMD_INIT_FUNC_TRACE();

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = IPC_MAX_CHANNEL_COUNT;
	dev_info->queue_size_lim = IPC_MAX_DEPTH;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 64;

	BBDEV_LA93XX_PMD_DEBUG("got device info from %u", dev->data->dev_id);
}

/* Release queue */
static int
la93xx_queue_release(struct rte_bbdev *dev, uint16_t q_id)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(q_id);

	PMD_INIT_FUNC_TRACE();

	/* TODO: Implement */

	return 0;
}

#define HUGEPG_OFFSET(A) \
		(LA9310_USER_HUGE_PAGE_PHYS_ADDR + ((uint64_t) ((unsigned long) (A) \
		- ((uint64_t)ipc_priv->hugepg_start.host_vaddr))))

#define MODEM_P2V(A) \
	((uint64_t) ((unsigned long) (A) \
		+ (unsigned long)(ipc_priv->tcml_start.host_vaddr)))

#pragma GCC push_options
#pragma GCC optimize("O1")
static int ipc_queue_configure(uint32_t channel_id,
		ipc_t instance, struct bbdev_la93xx_q_priv *q_priv)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	void *vaddr;
	uint32_t i = 0;
	uint32_t msg_size = sizeof(struct bbdev_ipc_raw_op_t);

	PMD_INIT_FUNC_TRACE();

	BBDEV_LA93XX_PMD_DEBUG("%x %p", ipc_instance->initialized,
		ipc_priv->instance);
	ch = &(ipc_instance->ch_list[channel_id]);

	BBDEV_LA93XX_PMD_DEBUG("channel: %u, depth: %u, msg size: %u",
		channel_id, q_priv->queue_size, msg_size);

	/* Start init of channel */
	ch->md.ring_size = q_priv->queue_size;
	ch->md.pi = 0;
	ch->md.ci = 0;
	ch->md.msg_size = msg_size;
	for (i = 0; i < q_priv->queue_size; i++) {
		vaddr = rte_malloc(NULL, msg_size, RTE_CACHE_LINE_SIZE);
		if (!vaddr)
			return IPC_HOST_BUF_ALLOC_FAIL;
		/* Only offset now */
		ch->bd_h[i].modem_ptr =	HUGEPG_OFFSET(vaddr);
		ch->bd_h[i].host_virt_l = lower_32_bits(vaddr);
		ch->bd_h[i].host_virt_h = upper_32_bits(vaddr);
		q_priv->msg_ch_vaddr[i] = vaddr;
		/* Not sure use of this len may be for CRC*/
		ch->bd_h[i].len = 0;
	}
	q_priv->host_params = rte_zmalloc(NULL, sizeof(host_ipc_params_t),
			RTE_CACHE_LINE_SIZE);
	ch->host_ipc_params = HUGEPG_OFFSET(q_priv->host_params);

	BBDEV_LA93XX_PMD_DEBUG("Channel configured");
	return IPC_SUCCESS;
}

/* Setup a queue */
static int
la93xx_queue_setup(struct rte_bbdev *dev, uint16_t q_id,
		const struct rte_bbdev_queue_conf *queue_conf)
{
	struct bbdev_la93xx_private *priv = dev->data->dev_private;
	struct rte_bbdev_queue_data *q_data;
	struct bbdev_la93xx_q_priv *q_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct la9310_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int instance_id = 0, i;
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* Move to setup_queues callback */
	q_data = &dev->data->queues[q_id];
	q_data->queue_private = rte_zmalloc(NULL,
		sizeof(struct bbdev_la93xx_q_priv), 0);
	if (!q_data->queue_private) {
		BBDEV_LA93XX_PMD_ERR("Memory allocation failed for qpriv");
		return -ENOMEM;
	}
	q_priv = q_data->queue_private;
	q_priv->q_id = q_id;
	q_priv->bbdev_priv = dev->data->dev_private;
	q_priv->queue_size = queue_conf->queue_size;
	q_priv->op_type = queue_conf->op_type;

	mhif = (struct la9310_hif *)ipc_priv->mhif_start.host_vaddr;
	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->tcml_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);
	ch = &ipc_md->instance_list[instance_id].ch_list[q_priv->q_id];

	ch->is_host_to_modem = queue_conf->raw_queue_conf.direction;
	ch->conf_enable = queue_conf->raw_queue_conf.conf_enable;

	if (!ch->is_host_to_modem) {
		for (i = 0; i < IPC_MAX_DEPTH; i++)
			q_priv->bbdev_op[i] = rte_zmalloc(NULL,
					sizeof(struct rte_bbdev_raw_op), 0);
	}

	if (q_priv->q_id < priv->num_valid_queues) {
		ipc_br_md_t *md = &(ch->md);

		q_priv->host_pi = md->pi;
		q_priv->host_ci = md->ci;
		q_priv->host_params = (host_ipc_params_t *)
			(ch->host_ipc_params +
			((uint64_t)ipc_priv->hugepg_start.host_vaddr));

		for (i = 0; i < q_priv->queue_size; i++) {
			uint32_t h, l;

			h = ch->bd_h[i].host_virt_h;
			l = ch->bd_h[i].host_virt_l;
			q_priv->msg_ch_vaddr[i] = (void *)join_32_bits(h, l);
		}

		BBDEV_LA93XX_PMD_WARN(
			"Queue [%d] already configured, not configuring again",
			q_priv->q_id);
		return 0;
	}

	BBDEV_LA93XX_PMD_DEBUG("setting up queue %d", q_priv->q_id);

	/* Call ipc_configure_channel */
	ret = ipc_queue_configure(q_priv->q_id, ipc_priv, q_priv);
	if (ret) {
		BBDEV_LA93XX_PMD_ERR("Unable to setup queue (%d) (err=%d)",
		       q_priv->q_id, ret);
		return ret;
	}

	if (priv->num_valid_queues >= MAX_RAW_QUEUES) {
		BBDEV_LA93XX_PMD_ERR(
			"num_raw_queues reached max value");
		return -1;
	}
	ch->op_type = q_priv->op_type;
	ch->depth = q_priv->queue_size;

	/* Store queue config here */
	priv->num_valid_queues++;

	return 0;
}

static int
la93xx_start(struct rte_bbdev *dev)
{
	struct bbdev_la93xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	int ready = 0;
	struct la9310_hif *hif_start;

	PMD_INIT_FUNC_TRACE();

	hif_start = (struct la9310_hif *)ipc_priv->mhif_start.host_vaddr;

	/* Set Host Read bit */
	SET_HIF_HOST_RDY(hif_start, LA9310_HIF_STATUS_IPC_APP_READY);

	/* Now wait for modem ready bit */
	/* TODO: remove sleep */
	sleep(1);
	while (!ready)
		ready = CHK_HIF_MOD_RDY(hif_start,
			LA9310_HIF_MOD_READY_IPC_APP);

	return 0;
}

static inline int
is_bd_ring_full(uint32_t ci, uint32_t ci_flag,
		uint32_t pi, uint32_t pi_flag)
{
	if (pi == ci) {
		if (pi_flag != ci_flag)
			return 1; /* Ring is Full */
	}
	return 0;
}

static inline int
is_bd_ring_empty(uint32_t ci, uint32_t ci_flag,
		 uint32_t pi, uint32_t pi_flag)
{
	if (ci == pi) {
		if (ci_flag == pi_flag)
			return 1; /* No more Buffer */
	}
	return 0;
}

/* Enqueue raw operation */
static int
enqueue_raw_op(struct rte_bbdev_queue_data *q_data,
	       struct rte_bbdev_raw_op *bbdev_op)
{
	struct bbdev_la93xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la93xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_raw_op_t *raw_op;
	uint32_t q_id = q_priv->q_id;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md = &(ch->md);
	uint64_t virt;
	char *huge_start_addr =
		(char *)q_priv->bbdev_priv->ipc_priv->hugepg_start.host_vaddr;
	struct rte_bbdev_op_data *in_op_data, *out_op_data;
	char *data_ptr;
	uint32_t l1_pcie_addr;
	int conf_enable = q_data->conf.raw_queue_conf.conf_enable;

	/**
	 * In case of confirmation mode, local consumer index is incremented
	 * after receiving the output data(dequeue). Hence, before enqueuing the
	 * raw operation, we need to compare this local consumer index and
	 * producer index to check if bd ring is full.
	 * But, in case of non confirmation mode, since we will not receive the
	 * output data(dequeue function will not be called), local consumer
	 * index will not be updated. Hence, to check if bd ring is full, we
	 * will rely on the shared consumer index, which will be incrememnted by
	 * other side after consuming the packet.
	 */
	if (conf_enable) {
		ci = IPC_GET_CI_INDEX(q_priv->host_ci);
		ci_flag = IPC_GET_CI_FLAG(q_priv->host_ci);
	} else {
		ci = IPC_GET_CI_INDEX(q_priv->host_params->ci);
		ci_flag = IPC_GET_CI_FLAG(q_priv->host_params->ci);
	}

	pi = IPC_GET_PI_INDEX(q_priv->host_pi);
	pi_flag = IPC_GET_PI_FLAG(q_priv->host_pi);

	BBDEV_LA93XX_PMD_DP_DEBUG(
		"before bd_ring_full: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		pi, ci, pi_flag, ci_flag, q_priv->queue_size);

	if (is_bd_ring_full(ci, ci_flag, pi, pi_flag)) {
		BBDEV_LA93XX_PMD_DP_DEBUG(
			"bd ring full for queue id: %d", q_id);
		return -EBUSY;
	}

	virt = MODEM_P2V(q_priv->host_params->bd_m_modem_ptr[pi]);
	raw_op = (struct bbdev_ipc_raw_op_t *)virt;
	q_priv->bbdev_op[pi] = bbdev_op;

	in_op_data = &bbdev_op->input;
	out_op_data = &bbdev_op->output;

	if (!out_op_data)
		raw_op->out_addr = 0;

	if (in_op_data->bdata) {
		data_ptr = get_data_ptr(in_op_data);
		l1_pcie_addr = (uint32_t)LA9310_USER_HUGE_PAGE_PHYS_ADDR +
			       data_ptr - huge_start_addr;
		raw_op->in_addr = l1_pcie_addr;
		raw_op->in_len = in_op_data->length;
	}

	if (out_op_data->bdata) {
		data_ptr = get_data_ptr(out_op_data);
		l1_pcie_addr = (uint32_t)LA9310_USER_HUGE_PAGE_PHYS_ADDR +
			       data_ptr - huge_start_addr;
		raw_op->out_addr = l1_pcie_addr;
		raw_op->out_len = out_op_data->length;
	}

	/* Move Producer Index forward */
	pi++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(q_priv->queue_size == pi)) {
		pi = 0;
		pi_flag = pi_flag ? 0 : 1;
	}

	if (pi_flag)
		IPC_SET_PI_FLAG(pi);
	else
		IPC_RESET_PI_FLAG(pi);
	/* Wait for Data Copy & pi_flag update to complete before updating pi */
	rte_mb();
	/* now update pi */
	md->pi = pi;
	q_priv->host_pi = pi;

	BBDEV_LA93XX_PMD_DP_DEBUG(
			"enter: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
			pi, ci, pi_flag, ci_flag, q_priv->queue_size);

	return IPC_SUCCESS;
}

/* Dequeue raw operation */
static struct rte_bbdev_raw_op *
dequeue_raw_op(struct rte_bbdev_queue_data *q_data)
{
	struct bbdev_la93xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la93xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_ipc_raw_op_t *dequeue_op;
	struct rte_bbdev_raw_op *op;
	uint32_t ci, ci_flag, pi, pi_flag;
	uint32_t temp_ci;
	int is_host_to_modem = q_data->conf.raw_queue_conf.direction;

	if (is_host_to_modem) {
		temp_ci = q_priv->host_params->ci;
		if (temp_ci == q_priv->host_ci)
			return NULL;

		ci = IPC_GET_CI_INDEX(q_priv->host_ci);
		ci_flag = IPC_GET_CI_FLAG(q_priv->host_ci);

		BBDEV_LA93XX_PMD_DP_DEBUG(
			"ci: %u, ci_flag: %u, ring size: %u",
			ci, ci_flag, q_priv->queue_size);

		op = q_priv->bbdev_op[ci];

		dequeue_op = q_priv->msg_ch_vaddr[ci];

		op->status = dequeue_op->status;
		op->output.length = dequeue_op->out_len;

		/* Move Consumer Index forward */
		ci++;
		/* Flip the CI flag, if wrapping */
		if (q_priv->queue_size == ci) {
			ci = 0;
			ci_flag = ci_flag ? 0 : 1;
		}
		if (ci_flag)
			IPC_SET_CI_FLAG(ci);
		else
			IPC_RESET_CI_FLAG(ci);
		q_priv->host_ci = ci;

		BBDEV_LA93XX_PMD_DP_DEBUG(
			"exit: ci: %u, ci_flag: %u, ring size: %u",
			ci, ci_flag, q_priv->queue_size);

	} else {
		ci = IPC_GET_CI_INDEX(q_priv->host_params->ci);
		ci_flag = IPC_GET_CI_FLAG(q_priv->host_params->ci);
		pi = IPC_GET_PI_INDEX(q_priv->host_params->pi);
		pi_flag = IPC_GET_PI_FLAG(q_priv->host_params->pi);

		if (is_bd_ring_empty(ci, ci_flag, pi, pi_flag))
			return NULL;

		BBDEV_LA93XX_PMD_DP_DEBUG(
			"ci: %u, ci_flag: %u, ring size: %u",
			ci, ci_flag, q_priv->queue_size);

		dequeue_op = q_priv->msg_ch_vaddr[ci];

		op = q_priv->bbdev_op[ci];

		op->input.length = dequeue_op->in_len;
		op->output.length = dequeue_op->out_len;
		op->input.mem = (void *)MODEM_P2V(dequeue_op->in_addr);
		op->output.mem = (void *)MODEM_P2V(dequeue_op->out_addr);

		BBDEV_LA93XX_PMD_DP_DEBUG(
			"exit: ci: %u, ci_flag: %u, ring size: %u",
			ci, ci_flag, q_priv->queue_size);
	}

	return op;
}

/* Consume raw operation */
static uint16_t
consume_raw_op(struct rte_bbdev_queue_data *q_data,
	       struct rte_bbdev_raw_op *bbdev_op)
{
	struct bbdev_la93xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la93xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_raw_op_t *raw_op;
	uint32_t q_id = q_priv->q_id;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md = &(ch->md);
	uint64_t virt;

	pi = IPC_GET_PI_INDEX(q_priv->host_params->pi);
	pi_flag = IPC_GET_PI_FLAG(q_priv->host_params->pi);
	ci = IPC_GET_CI_INDEX(q_priv->host_params->ci);
	ci_flag = IPC_GET_CI_FLAG(q_priv->host_params->ci);

	BBDEV_LA93XX_PMD_DP_DEBUG(
		"before bd_ring_full: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
	pi, ci, pi_flag, ci_flag, q_priv->queue_size);

	virt = MODEM_P2V(q_priv->host_params->bd_m_modem_ptr[ci]);
	raw_op = (struct bbdev_ipc_raw_op_t *)virt;
	raw_op->status = bbdev_op->status;
	raw_op->out_len = bbdev_op->output.length;

	/* Move Producer Index forward */
	ci++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(q_priv->queue_size == ci)) {
		ci = 0;
		ci_flag = ci_flag ? 0 : 1;
	}

	if (ci_flag)
		IPC_SET_CI_FLAG(ci);
	else
		IPC_RESET_CI_FLAG(ci);
	q_priv->host_params->ci = ci;
	/* Wait for Data Copy & ci_flag update to complete before updating ci */
	rte_mb();
	/* now update ci */
	md->ci = ci;

	BBDEV_LA93XX_PMD_DP_DEBUG(
		"enter: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u",
		pi, ci, pi_flag, ci_flag, q_priv->queue_size);

	return IPC_SUCCESS;
}

static const struct rte_bbdev_ops pmd_ops = {
	.info_get = la93xx_info_get,
	.queue_setup = la93xx_queue_setup,
	.queue_release = la93xx_queue_release,
	.start = la93xx_start
};

#pragma GCC pop_options

static struct hugepage_info *
get_hugepage_info(void)
{
	struct hugepage_info *hp_info;
	struct rte_memseg *mseg;

	PMD_INIT_FUNC_TRACE();

	/* TODO - find a better way */
	hp_info = rte_malloc(NULL, sizeof(struct hugepage_info), 0);
	if (!hp_info) {
		BBDEV_LA93XX_PMD_ERR("Unable to allocate on local heap");
		return NULL;
	}

	mseg = rte_mem_virt2memseg(hp_info, NULL);
	hp_info->vaddr = mseg->addr;
	hp_info->paddr = rte_mem_virt2phy(mseg->addr);
	hp_info->len = mseg->len;

	return hp_info;
}

static int open_ipc_dev(int modem_id)
{
	char dev_initials[32], dev_path[PATH_MAX];
	struct dirent *entry;
	int dev_ipc = 0, ret;
	DIR *dir;

	dir = opendir("/dev/");
	if (!dir) {
		BBDEV_LA93XX_PMD_ERR("Unable to open /dev/");
		return -1;
	}

	sprintf(dev_initials, "la9310ipcnlm%d", modem_id);

	while ((entry = readdir(dir)) != NULL) {
		if (!strncmp(dev_initials, entry->d_name,
		    sizeof(dev_initials) - 1))
			break;
	}

	if (!entry) {
		BBDEV_LA93XX_PMD_ERR("Error: No la9310ipcwlan_mon%d device",
			modem_id);
		return -1;
	}

	sprintf(dev_path, "/dev/%s", entry->d_name);
	dev_ipc = open(dev_path, O_RDWR);
	if (dev_ipc  < 0) {
		BBDEV_LA93XX_PMD_ERR("Error: Cannot open %s", dev_path);
		ret = closedir(dir);
		if (ret == -1)
			BBDEV_LA93XX_PMD_ERR("Unable to close /dev/");
		return -errno;
	}

	return dev_ipc;
}

static int
setup_la93xx_dev(struct rte_bbdev *dev)
{
	struct bbdev_la93xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct hugepage_info *hp = NULL;
	ipc_channel_us_t *ipc_priv_ch = NULL;
	int dev_ipc = 0, dev_mem = 0, i;
	ipc_metadata_t *ipc_md;
	struct la9310_hif *mhif;
	uint32_t phy_align = 0;
	int ret = -1;

	PMD_INIT_FUNC_TRACE();

	if (!ipc_priv) {
		/* TODO - get a better way */
		/* Get the hugepage info against it */
		hp = get_hugepage_info();
		if (!hp) {
			BBDEV_LA93XX_PMD_ERR("Unable to get hugepage info");
			ret = -ENOMEM;
			goto err;
		}

		BBDEV_LA93XX_PMD_DEBUG("%lx %p %lx",
				hp->paddr, hp->vaddr, hp->len);

		ipc_priv = rte_zmalloc(0, sizeof(ipc_userspace_t), 0);
		if (ipc_priv == NULL) {
			BBDEV_LA93XX_PMD_ERR(
				"Unable to allocate memory for ipc priv");
			ret = -ENOMEM;
			goto err;
		}

		for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
			ipc_priv_ch = rte_zmalloc(0,
				sizeof(ipc_channel_us_t), 0);
			if (ipc_priv_ch == NULL) {
				BBDEV_LA93XX_PMD_ERR(
					"Unable to allocate memory for channels");
				ret = -ENOMEM;
			}
			ipc_priv->channels[i] = ipc_priv_ch;
		}

		dev_mem = open("/dev/mem", O_RDWR);
		if (dev_mem < 0) {
			BBDEV_LA93XX_PMD_ERR("Error: Cannot open /dev/mem");
			ret = -errno;
			goto err;
		}

		ipc_priv->instance_id = 0;
		ipc_priv->dev_mem = dev_mem;

		BBDEV_LA93XX_PMD_DEBUG("hugepg input %lx %p %lx",
			hp->paddr, hp->vaddr, hp->len);

		ipc_priv->sys_map.hugepg_start.host_phys = hp->paddr;
		ipc_priv->sys_map.hugepg_start.size = hp->len;

		ipc_priv->hugepg_start.host_phys = hp->paddr;
		ipc_priv->hugepg_start.host_vaddr = hp->vaddr;
		ipc_priv->hugepg_start.size = hp->len;

		rte_free(hp);
	}

	dev_ipc = open_ipc_dev(priv->modem_id);
	if (dev_ipc < 0) {
		BBDEV_LA93XX_PMD_ERR("Error: open_ipc_dev failed");
		ret = dev_ipc;
		goto err;
	}
	ipc_priv->dev_ipc = dev_ipc;

	/* Send IOCTL to get system map and put hugepg_start map */
	ret = ioctl(ipc_priv->dev_ipc, IOCTL_LA93XX_IPC_GET_SYS_MAP,
		    &ipc_priv->sys_map);
	if (ret) {
		BBDEV_LA93XX_PMD_ERR(
			"IOCTL_LA93XX_IPC_GET_SYS_MAP ioctl failed");
		goto err;
	}

	phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
	ipc_priv->mhif_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.mhif_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.mhif_start.host_phys - phy_align));
	if (ipc_priv->mhif_start.host_vaddr == MAP_FAILED) {
		BBDEV_LA93XX_PMD_ERR("MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->mhif_start.host_vaddr = (void *) ((uint64_t)
		(ipc_priv->mhif_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.tcml_start.host_phys % 0x1000);
	ipc_priv->tcml_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.tcml_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.tcml_start.host_phys - phy_align));
	if (ipc_priv->tcml_start.host_vaddr == MAP_FAILED) {
		BBDEV_LA93XX_PMD_ERR("MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->tcml_start.host_vaddr = (void *)((uint64_t)
		(ipc_priv->tcml_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.modem_ccsrbar.host_phys % 0x1000);
	ipc_priv->modem_ccsrbar.host_vaddr =
		mmap(0, ipc_priv->sys_map.modem_ccsrbar.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.modem_ccsrbar.host_phys - phy_align));
	if (ipc_priv->modem_ccsrbar.host_vaddr == MAP_FAILED) {
		BBDEV_LA93XX_PMD_ERR("MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->modem_ccsrbar.host_vaddr = (void *)((uint64_t)
		(ipc_priv->modem_ccsrbar.host_vaddr) + phy_align);

	ipc_priv->hugepg_start.modem_phys =
		ipc_priv->sys_map.hugepg_start.modem_phys;

	ipc_priv->mhif_start.host_phys =
		ipc_priv->sys_map.mhif_start.host_phys;
	ipc_priv->mhif_start.size = ipc_priv->sys_map.mhif_start.size;
	ipc_priv->tcml_start.host_phys = ipc_priv->sys_map.tcml_start.host_phys;
	ipc_priv->tcml_start.size = ipc_priv->sys_map.tcml_start.size;

	BBDEV_LA93XX_PMD_INFO("tcml %lx %p %x",
			ipc_priv->tcml_start.host_phys,
			ipc_priv->tcml_start.host_vaddr,
			ipc_priv->tcml_start.size);
	BBDEV_LA93XX_PMD_INFO("hugepg %lx %p %x",
			ipc_priv->hugepg_start.host_phys,
			ipc_priv->hugepg_start.host_vaddr,
			ipc_priv->hugepg_start.size);
	BBDEV_LA93XX_PMD_INFO("mhif %lx %p %x",
			ipc_priv->mhif_start.host_phys,
			ipc_priv->mhif_start.host_vaddr,
			ipc_priv->mhif_start.size);
	mhif = (struct la9310_hif *)ipc_priv->mhif_start.host_vaddr;

	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->tcml_start.host_vaddr +
			mhif->ipc_regs.ipc_mdata_offset);
	ipc_md->ipc_host_signature = IPC_HOST_SIGNATURE;

	if (sizeof(ipc_metadata_t) != mhif->ipc_regs.ipc_mdata_size) {
		BBDEV_LA93XX_PMD_ERR(
			"\n ipc_metadata_t =%lx, mhif->ipc_regs.ipc_mdata_size=%x",
			sizeof(ipc_metadata_t), mhif->ipc_regs.ipc_mdata_size);
		BBDEV_LA93XX_PMD_ERR(
			"--> mhif->ipc_regs.ipc_mdata_offset= %x",
			mhif->ipc_regs.ipc_mdata_offset);
		BBDEV_LA93XX_PMD_ERR(
			"la9310_hif size=%lx", sizeof(struct la9310_hif));
		return IPC_MD_SZ_MISS_MATCH;
	}

	if (ipc_md->ipc_modem_signature != IPC_MODEM_SIGNATURE) {
		BBDEV_LA93XX_PMD_ERR(
			"Modem signature does not match. Expected: %x, Got: %x",
			IPC_MODEM_SIGNATURE, ipc_md->ipc_modem_signature);
		return -1;
	}

	ipc_priv->instance = (ipc_instance_t *)
		(&ipc_md->instance_list[ipc_priv->instance_id]);

	BBDEV_LA93XX_PMD_DEBUG("finish host init");

	priv->ipc_priv = ipc_priv;

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
	if (ipc_priv->tcml_start.host_vaddr &&
	    (ipc_priv->tcml_start.host_vaddr != MAP_FAILED)) {
		phy_align = (ipc_priv->sys_map.tcml_start.host_phys % 0x1000);
		munmap(ipc_priv->tcml_start.host_vaddr,
			ipc_priv->sys_map.tcml_start.size + phy_align);
	}

	return ret;
}

static inline int
parse_u16_arg(const char *key, const char *value, void *extra_args)
{
	uint16_t *u16 = extra_args;

	unsigned int long result;
	if ((value == NULL) || (extra_args == NULL))
		return -EINVAL;
	errno = 0;
	result = strtoul(value, NULL, 0);
	if ((result >= (1 << 16)) || (errno != 0)) {
		BBDEV_LA93XX_PMD_ERR("Invalid value %lu for %s", result, key);
		return -ERANGE;
	}
	*u16 = (uint16_t)result;
	return 0;
}

/* Parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int i;
	char *end;

	errno = 0;

	i = strtol(value, &end, 10);
	if (*end != 0 || errno != 0 || i < 0 || i > LA93XX_MAX_MODEM) {
		BBDEV_LA93XX_PMD_ERR("Supported Port IDS are 0 to %d",
			LA93XX_MAX_MODEM - 1);
		return -EINVAL;
	}

	*((uint32_t *)extra_args) = i;

	return 0;
}

/* Parse parameters used to create device */
static int
parse_bbdev_la93xx_params(struct bbdev_la93xx_params *params,
		const char *input_args)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (params == NULL)
		return -EINVAL;
	if (input_args) {
		kvlist = rte_kvargs_parse(input_args,
				bbdev_la93xx_valid_params);
		if (kvlist == NULL)
			return -EFAULT;

		ret = rte_kvargs_process(kvlist,
					bbdev_la93xx_valid_params[0],
					&parse_integer_arg,
					&params->modem_id);
		if (ret < 0)
			goto exit;

		if (params->modem_id >= LA93XX_MAX_MODEM) {
			BBDEV_LA93XX_PMD_ERR("Invalid modem id, must be < %u",
					LA93XX_MAX_MODEM);
			goto exit;
		}
	}

exit:
	if (kvlist)
		rte_kvargs_free(kvlist);
	return ret;
}

/* Create device */
static int
la93xx_bbdev_create(struct rte_vdev_device *vdev,
		struct bbdev_la93xx_params *init_params)
{
	struct rte_bbdev *bbdev;
	const char *name = rte_vdev_device_name(vdev);
	struct bbdev_la93xx_private *priv;
	int ret;

	PMD_INIT_FUNC_TRACE();

	bbdev = rte_bbdev_allocate(name);
	if (bbdev == NULL)
		return -ENODEV;

	bbdev->data->dev_private = rte_zmalloc(name,
			sizeof(struct bbdev_la93xx_private),
			RTE_CACHE_LINE_SIZE);
	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_release(bbdev);
		return -ENOMEM;
	}

	priv = bbdev->data->dev_private;
	priv->modem_id = init_params->modem_id;
	/* if modem id is not configured */
	if (priv->modem_id == -1)
		priv->modem_id = bbdev->data->dev_id;

	BBDEV_LA93XX_PMD_INFO("Initializing bbdev for:%s  modem-id=%d",
		name, init_params->modem_id);

	/* Reset Global variables */
	priv->num_valid_queues = 0;

	BBDEV_LA93XX_PMD_INFO("Setting Up %s: DevId=%d, ModemId=%d",
				name, bbdev->data->dev_id, priv->modem_id);
	ret = setup_la93xx_dev(bbdev);
	if (ret) {
		BBDEV_LA93XX_PMD_ERR("IPC Setup failed for %s", name);
		rte_free(bbdev->data->dev_private);
		return ret;
	}
	bbdev->dev_ops = &pmd_ops;
	bbdev->device = &vdev->device;
	bbdev->data->socket_id = 0;
	bbdev->intr_handle = NULL;

	bbdev->enqueue_raw_op = enqueue_raw_op;
	bbdev->dequeue_raw_op = dequeue_raw_op;
	bbdev->consume_raw_op = consume_raw_op;

	return 0;
}

/* Initialise device */
static int
la93xx_bbdev_probe(struct rte_vdev_device *vdev)
{
	struct bbdev_la93xx_params init_params = {
		-1,
	};
	const char *name;
	const char *input_args;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	input_args = rte_vdev_device_args(vdev);
	parse_bbdev_la93xx_params(&init_params, input_args);

	return la93xx_bbdev_create(vdev, &init_params);
}

/* Uninitialise device */
static int
la93xx_bbdev_remove(struct rte_vdev_device *vdev)
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

static struct rte_vdev_driver bbdev_la93xx_pmd_drv = {
	.probe = la93xx_bbdev_probe,
	.remove = la93xx_bbdev_remove
};

RTE_PMD_REGISTER_ALIAS(DRIVER_NAME, bbdev_la93xx);
RTE_PMD_REGISTER_VDEV(DRIVER_NAME, bbdev_la93xx_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(DRIVER_NAME,
	BBDEV_LA93XX_VDEV_MODEM_ID_ARG "=<int> ");
RTE_INIT(la93xx_bbdev_init_log)
{
	bbdev_la93xx_logtype = rte_log_register("pmd.bb.la93xx");
	if (bbdev_la93xx_logtype >= 0)
		rte_log_set_level(bbdev_la93xx_logtype, RTE_LOG_NOTICE);
}

