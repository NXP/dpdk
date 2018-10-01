/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2018 Intel Corporation
 */

#include "qat_comp.h"
#include "qat_comp_pmd.h"

static const struct rte_compressdev_capabilities qat_comp_gen_capabilities[] = {
	{/* COMPRESSION - deflate */
	 .algo = RTE_COMP_ALGO_DEFLATE,
	 .comp_feature_flags = RTE_COMP_FF_MULTI_PKT_CHECKSUM |
				RTE_COMP_FF_CRC32_CHECKSUM |
				RTE_COMP_FF_ADLER32_CHECKSUM |
				RTE_COMP_FF_CRC32_ADLER32_CHECKSUM |
				RTE_COMP_FF_SHAREABLE_PRIV_XFORM |
				RTE_COMP_FF_HUFFMAN_FIXED |
				RTE_COMP_FF_OOP_SGL_IN_SGL_OUT |
				RTE_COMP_FF_OOP_SGL_IN_LB_OUT |
				RTE_COMP_FF_OOP_LB_IN_SGL_OUT,
	 .window_size = {.min = 15, .max = 15, .increment = 0} },
	{RTE_COMP_ALGO_LIST_END, 0, {0, 0, 0} } };

static void
qat_comp_stats_get(struct rte_compressdev *dev,
		struct rte_compressdev_stats *stats)
{
	struct qat_common_stats qat_stats = {0};
	struct qat_comp_dev_private *qat_priv;

	if (stats == NULL || dev == NULL) {
		QAT_LOG(ERR, "invalid ptr: stats %p, dev %p", stats, dev);
		return;
	}
	qat_priv = dev->data->dev_private;

	qat_stats_get(qat_priv->qat_dev, &qat_stats, QAT_SERVICE_COMPRESSION);
	stats->enqueued_count = qat_stats.enqueued_count;
	stats->dequeued_count = qat_stats.dequeued_count;
	stats->enqueue_err_count = qat_stats.enqueue_err_count;
	stats->dequeue_err_count = qat_stats.dequeue_err_count;
}

static void
qat_comp_stats_reset(struct rte_compressdev *dev)
{
	struct qat_comp_dev_private *qat_priv;

	if (dev == NULL) {
		QAT_LOG(ERR, "invalid compressdev ptr %p", dev);
		return;
	}
	qat_priv = dev->data->dev_private;

	qat_stats_reset(qat_priv->qat_dev, QAT_SERVICE_COMPRESSION);

}

static int
qat_comp_qp_release(struct rte_compressdev *dev, uint16_t queue_pair_id)
{
	struct qat_comp_dev_private *qat_private = dev->data->dev_private;

	QAT_LOG(DEBUG, "Release comp qp %u on device %d",
				queue_pair_id, dev->data->dev_id);

	qat_private->qat_dev->qps_in_use[QAT_SERVICE_COMPRESSION][queue_pair_id]
						= NULL;

	return qat_qp_release((struct qat_qp **)
			&(dev->data->queue_pairs[queue_pair_id]));
}

static int
qat_comp_qp_setup(struct rte_compressdev *dev, uint16_t qp_id,
		  uint32_t max_inflight_ops, int socket_id)
{
	struct qat_qp *qp;
	int ret = 0;
	uint32_t i;
	struct qat_qp_config qat_qp_conf;

	struct qat_qp **qp_addr =
			(struct qat_qp **)&(dev->data->queue_pairs[qp_id]);
	struct qat_comp_dev_private *qat_private = dev->data->dev_private;
	const struct qat_qp_hw_data *comp_hw_qps =
			qat_gen_config[qat_private->qat_dev->qat_dev_gen]
				      .qp_hw_data[QAT_SERVICE_COMPRESSION];
	const struct qat_qp_hw_data *qp_hw_data = comp_hw_qps + qp_id;

	/* If qp is already in use free ring memory and qp metadata. */
	if (*qp_addr != NULL) {
		ret = qat_comp_qp_release(dev, qp_id);
		if (ret < 0)
			return ret;
	}
	if (qp_id >= qat_qps_per_service(comp_hw_qps,
					 QAT_SERVICE_COMPRESSION)) {
		QAT_LOG(ERR, "qp_id %u invalid for this device", qp_id);
		return -EINVAL;
	}

	qat_qp_conf.hw = qp_hw_data;
	qat_qp_conf.build_request = qat_comp_build_request;
	qat_qp_conf.cookie_size = sizeof(struct qat_comp_op_cookie);
	qat_qp_conf.nb_descriptors = max_inflight_ops;
	qat_qp_conf.socket_id = socket_id;
	qat_qp_conf.service_str = "comp";

	ret = qat_qp_setup(qat_private->qat_dev, qp_addr, qp_id, &qat_qp_conf);
	if (ret != 0)
		return ret;

	/* store a link to the qp in the qat_pci_device */
	qat_private->qat_dev->qps_in_use[QAT_SERVICE_COMPRESSION][qp_id]
							= *qp_addr;

	qp = (struct qat_qp *)*qp_addr;

	for (i = 0; i < qp->nb_descriptors; i++) {

		struct qat_comp_op_cookie *cookie =
				qp->op_cookies[i];

		cookie->qat_sgl_src_phys_addr =
				rte_mempool_virt2iova(cookie) +
				offsetof(struct qat_comp_op_cookie,
				qat_sgl_src);

		cookie->qat_sgl_dst_phys_addr =
				rte_mempool_virt2iova(cookie) +
				offsetof(struct qat_comp_op_cookie,
				qat_sgl_dst);
	}

	return ret;
}

static struct rte_mempool *
qat_comp_create_xform_pool(struct qat_comp_dev_private *comp_dev,
			      uint32_t num_elements)
{
	char xform_pool_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;

	snprintf(xform_pool_name, RTE_MEMPOOL_NAMESIZE,
			"%s_xforms", comp_dev->qat_dev->name);

	QAT_LOG(DEBUG, "xformpool: %s", xform_pool_name);
	mp = rte_mempool_lookup(xform_pool_name);

	if (mp != NULL) {
		QAT_LOG(DEBUG, "xformpool already created");
		if (mp->size != num_elements) {
			QAT_LOG(DEBUG, "xformpool wrong size - delete it");
			rte_mempool_free(mp);
			mp = NULL;
			comp_dev->xformpool = NULL;
		}
	}

	if (mp == NULL)
		mp = rte_mempool_create(xform_pool_name,
				num_elements,
				qat_comp_xform_size(), 0, 0,
				NULL, NULL, NULL, NULL, rte_socket_id(),
				0);
	if (mp == NULL) {
		QAT_LOG(ERR, "Err creating mempool %s w %d elements of size %d",
			xform_pool_name, num_elements, qat_comp_xform_size());
		return NULL;
	}

	return mp;
}

static void
_qat_comp_dev_config_clear(struct qat_comp_dev_private *comp_dev)
{
	/* Free private_xform pool */
	if (comp_dev->xformpool) {
		/* Free internal mempool for private xforms */
		rte_mempool_free(comp_dev->xformpool);
		comp_dev->xformpool = NULL;
	}
}

static int
qat_comp_dev_config(struct rte_compressdev *dev,
		struct rte_compressdev_config *config)
{
	struct qat_comp_dev_private *comp_dev = dev->data->dev_private;
	int ret = 0;

	if (config->max_nb_streams != 0) {
		QAT_LOG(ERR,
	"QAT device does not support STATEFUL so max_nb_streams must be 0");
		return -EINVAL;
	}

	comp_dev->xformpool = qat_comp_create_xform_pool(comp_dev,
					config->max_nb_priv_xforms);
	if (comp_dev->xformpool == NULL) {

		ret = -ENOMEM;
		goto error_out;
	}
	return 0;

error_out:
	_qat_comp_dev_config_clear(comp_dev);
	return ret;
}

static int
qat_comp_dev_start(struct rte_compressdev *dev __rte_unused)
{
	return 0;
}

static void
qat_comp_dev_stop(struct rte_compressdev *dev __rte_unused)
{

}

static int
qat_comp_dev_close(struct rte_compressdev *dev)
{
	int i;
	int ret = 0;
	struct qat_comp_dev_private *comp_dev = dev->data->dev_private;

	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		ret = qat_comp_qp_release(dev, i);
		if (ret < 0)
			return ret;
	}

	_qat_comp_dev_config_clear(comp_dev);

	return ret;
}


static void
qat_comp_dev_info_get(struct rte_compressdev *dev,
			struct rte_compressdev_info *info)
{
	struct qat_comp_dev_private *comp_dev = dev->data->dev_private;
	const struct qat_qp_hw_data *comp_hw_qps =
		qat_gen_config[comp_dev->qat_dev->qat_dev_gen]
			      .qp_hw_data[QAT_SERVICE_COMPRESSION];

	if (info != NULL) {
		info->max_nb_queue_pairs =
			qat_qps_per_service(comp_hw_qps,
					    QAT_SERVICE_COMPRESSION);
		info->feature_flags = dev->feature_flags;
		info->capabilities = comp_dev->qat_dev_capabilities;
	}
}

static uint16_t
qat_comp_pmd_enqueue_op_burst(void *qp, struct rte_comp_op **ops,
		uint16_t nb_ops)
{
	return qat_enqueue_op_burst(qp, (void **)ops, nb_ops);
}

static uint16_t
qat_comp_pmd_dequeue_op_burst(void *qp, struct rte_comp_op **ops,
			      uint16_t nb_ops)
{
	return qat_dequeue_op_burst(qp, (void **)ops, nb_ops);
}

static uint16_t
qat_comp_pmd_enq_deq_dummy_op_burst(void *qp __rte_unused,
				    struct rte_comp_op **ops __rte_unused,
				    uint16_t nb_ops __rte_unused)
{
	QAT_DP_LOG(ERR, "QAT PMD detected wrong FW version !");
	return 0;
}

static struct rte_compressdev_ops compress_qat_dummy_ops = {

	/* Device related operations */
	.dev_configure		= NULL,
	.dev_start		= NULL,
	.dev_stop		= qat_comp_dev_stop,
	.dev_close		= qat_comp_dev_close,
	.dev_infos_get		= NULL,

	.stats_get		= NULL,
	.stats_reset		= qat_comp_stats_reset,
	.queue_pair_setup	= NULL,
	.queue_pair_release	= qat_comp_qp_release,

	/* Compression related operations */
	.private_xform_create	= NULL,
	.private_xform_free	= qat_comp_private_xform_free
};

static uint16_t
qat_comp_pmd_dequeue_frst_op_burst(void *qp, struct rte_comp_op **ops,
				   uint16_t nb_ops)
{
	uint16_t ret = qat_dequeue_op_burst(qp, (void **)ops, nb_ops);
	struct qat_qp *tmp_qp = (struct qat_qp *)qp;

	if (ret) {
		if ((*ops)->debug_status ==
				(uint64_t)ERR_CODE_QAT_COMP_WRONG_FW) {
			tmp_qp->qat_dev->comp_dev->compressdev->enqueue_burst =
					qat_comp_pmd_enq_deq_dummy_op_burst;
			tmp_qp->qat_dev->comp_dev->compressdev->dequeue_burst =
					qat_comp_pmd_enq_deq_dummy_op_burst;

			tmp_qp->qat_dev->comp_dev->compressdev->dev_ops =
					&compress_qat_dummy_ops;
			QAT_LOG(ERR, "QAT PMD detected wrong FW version !");

		} else {
			tmp_qp->qat_dev->comp_dev->compressdev->dequeue_burst =
					qat_comp_pmd_dequeue_op_burst;
		}
	}
	return ret;
}

static struct rte_compressdev_ops compress_qat_ops = {

	/* Device related operations */
	.dev_configure		= qat_comp_dev_config,
	.dev_start		= qat_comp_dev_start,
	.dev_stop		= qat_comp_dev_stop,
	.dev_close		= qat_comp_dev_close,
	.dev_infos_get		= qat_comp_dev_info_get,

	.stats_get		= qat_comp_stats_get,
	.stats_reset		= qat_comp_stats_reset,
	.queue_pair_setup	= qat_comp_qp_setup,
	.queue_pair_release	= qat_comp_qp_release,

	/* Compression related operations */
	.private_xform_create	= qat_comp_private_xform_create,
	.private_xform_free	= qat_comp_private_xform_free
};

/* An rte_driver is needed in the registration of the device with compressdev.
 * The actual qat pci's rte_driver can't be used as its name represents
 * the whole pci device with all services. Think of this as a holder for a name
 * for the compression part of the pci device.
 */
static const char qat_comp_drv_name[] = RTE_STR(COMPRESSDEV_NAME_QAT_PMD);
static const struct rte_driver compdev_qat_driver = {
	.name = qat_comp_drv_name,
	.alias = qat_comp_drv_name
};
int
qat_comp_dev_create(struct qat_pci_device *qat_pci_dev)
{
	if (qat_pci_dev->qat_dev_gen == QAT_GEN1) {
		QAT_LOG(ERR, "Compression PMD not supported on QAT dh895xcc");
		return 0;
	}

	struct rte_compressdev_pmd_init_params init_params = {
		.name = "",
		.socket_id = qat_pci_dev->pci_dev->device.numa_node,
	};
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
	struct rte_compressdev *compressdev;
	struct qat_comp_dev_private *comp_dev;

	snprintf(name, RTE_COMPRESSDEV_NAME_MAX_LEN, "%s_%s",
			qat_pci_dev->name, "comp");
	QAT_LOG(DEBUG, "Creating QAT COMP device %s", name);

	/* Populate subset device to use in compressdev device creation */
	qat_pci_dev->comp_rte_dev.driver = &compdev_qat_driver;
	qat_pci_dev->comp_rte_dev.numa_node =
					qat_pci_dev->pci_dev->device.numa_node;
	qat_pci_dev->comp_rte_dev.devargs = NULL;

	compressdev = rte_compressdev_pmd_create(name,
			&(qat_pci_dev->comp_rte_dev),
			sizeof(struct qat_comp_dev_private),
			&init_params);

	if (compressdev == NULL)
		return -ENODEV;

	compressdev->dev_ops = &compress_qat_ops;

	compressdev->enqueue_burst = qat_comp_pmd_enqueue_op_burst;
	compressdev->dequeue_burst = qat_comp_pmd_dequeue_frst_op_burst;

	compressdev->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED;

	comp_dev = compressdev->data->dev_private;
	comp_dev->qat_dev = qat_pci_dev;
	comp_dev->compressdev = compressdev;
	qat_pci_dev->comp_dev = comp_dev;

	switch (qat_pci_dev->qat_dev_gen) {
	case QAT_GEN1:
	case QAT_GEN2:
	case QAT_GEN3:
		comp_dev->qat_dev_capabilities = qat_comp_gen_capabilities;
		break;
	default:
		comp_dev->qat_dev_capabilities = qat_comp_gen_capabilities;
		QAT_LOG(DEBUG,
			"QAT gen %d capabilities unknown, default to GEN1",
					qat_pci_dev->qat_dev_gen);
		break;
	}

	QAT_LOG(DEBUG,
		    "Created QAT COMP device %s as compressdev instance %d",
			name, compressdev->data->dev_id);
	return 0;
}

int
qat_comp_dev_destroy(struct qat_pci_device *qat_pci_dev)
{
	struct qat_comp_dev_private *comp_dev;

	if (qat_pci_dev == NULL)
		return -ENODEV;

	comp_dev = qat_pci_dev->comp_dev;
	if (comp_dev == NULL)
		return 0;

	/* clean up any resources used by the device */
	qat_comp_dev_close(comp_dev->compressdev);

	rte_compressdev_pmd_destroy(comp_dev->compressdev);
	qat_pci_dev->comp_dev = NULL;

	return 0;
}
