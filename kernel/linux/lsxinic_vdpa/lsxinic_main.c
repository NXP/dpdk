// SPDX-License-Identifier: GPL-2.0
/*
 * NXP LSX NIC driver for virtio dataplane offloading
 *
 * Copyright 2020-2021 NXP
 *
 * Code was mostly borrowed from linux/drivers/vdpa/ifcvf/ifcvf_main.c
 * See linux/drivers/vdpa/ifcvf/ifcvf_main.c for additional Copyrights.
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif
#endif

#include "lsxinic_base.h"

#define VERSION_STRING  "0.1"
#define DRIVER_AUTHOR   "Intel Corporation"
#define LSXINIC_DRIVER_NAME       "lsxinic"

static irqreturn_t lsxvdpa_config_changed(int irq, void *arg)
{
	struct lsxvdpa_hw *vf = arg;

	if (vf->config_cb.callback)
		return vf->config_cb.callback(vf->config_cb.private);

	return IRQ_HANDLED;
}

static irqreturn_t lsxvdpa_intr_handler(int irq, void *arg)
{
	struct vring_info *vring = arg;

	if (vring->cb.callback)
		return vring->cb.callback(vring->cb.private);

	return IRQ_HANDLED;
}

static void lsxvdpa_free_irq_vectors(void *data)
{
	pci_free_irq_vectors(data);
}

static void lsxvdpa_free_irq(struct lsxvdpa_adapter *adapter, int queues)
{
	struct pci_dev *pdev = adapter->pdev;
	struct lsxvdpa_hw *vf = &adapter->vf;
	int i;


	for (i = 0; i < queues; i++) {
		devm_free_irq(&pdev->dev, vf->vring[i].irq, &vf->vring[i]);
		vf->vring[i].irq = -EINVAL;
	}

	devm_free_irq(&pdev->dev, vf->config_irq, vf);
	lsxvdpa_free_irq_vectors(pdev);
}

static int lsxvdpa_request_irq(struct lsxvdpa_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct lsxvdpa_hw *vf = &adapter->vf;
	int vector, i, ret, irq;

	ret = pci_alloc_irq_vectors(pdev, LSXINIC_MIN_INTR,
				    LSXINIC_MAX_INTR, PCI_IRQ_MSIX);
	if (ret < 0) {
		LSX_ERR(pdev, "Failed to alloc IRQ vectors\n");
		return ret;
	}

	snprintf(vf->config_msix_name, 256, "lsxinic[%s]-config\n",
		 pci_name(pdev));
	vector = 0;
	vf->config_irq = pci_irq_vector(pdev, vector);
	ret = devm_request_irq(&pdev->dev, vf->config_irq,
			lsxvdpa_config_changed, 0,
			vf->config_msix_name, vf);

	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		snprintf(vf->vring[i].msix_name, 256, "lsxvio[%s]-%d\n",
			 pci_name(pdev), i);
		vector = i + LSXINIC_MSI_QUEUE_OFF;
		irq = pci_irq_vector(pdev, vector);
		ret = devm_request_irq(&pdev->dev, irq,
				lsxvdpa_intr_handler, 0,
				vf->vring[i].msix_name,
				&vf->vring[i]);
		if (ret) {
			LSX_ERR(pdev,
				  "Failed to request irq for vq %d\n", i);
			lsxvdpa_free_irq(adapter, i);

			return ret;
		}

		vf->vring[i].irq = irq;
	}

	return 0;
}

static int lsxvdpa_start_datapath(void *private)
{
	struct lsxvdpa_hw *vf = lsxvdpa_private_to_vf(private);
	u8 status;
	int ret;

	vf->nr_vring = LSXVIO_MAX_QUEUE_PAIRS * 2;
	ret = lsxvdpa_hw_start_hw(vf);
	if (ret < 0) {
		status = lsxvdpa_hw_get_status(vf);
		status |= VIRTIO_CONFIG_S_FAILED;
		lsxvdpa_hw_set_status(vf, status);
	}

	return ret;
}

static int lsxvdpa_stop_datapath(void *private)
{
	struct lsxvdpa_hw *vf = lsxvdpa_private_to_vf(private);
	int i;

	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++)
		vf->vring[i].cb.callback = NULL;

	lsxvdpa_hw_stop_hw(vf);

	return 0;
}

static void lsxvdpa_reset_vring(struct lsxvdpa_adapter *adapter)
{
	struct lsxvdpa_hw *vf = lsxvdpa_private_to_vf(adapter);
	int i;

	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		vf->vring[i].last_avail_idx = 0;
		vf->vring[i].desc = 0;
		vf->vring[i].avail = 0;
		vf->vring[i].used = 0;
		vf->vring[i].ready = 0;
		vf->vring[i].cb.callback = NULL;
		vf->vring[i].cb.private = NULL;
	}

	lsxvdpa_hw_reset(vf);
}

static struct lsxvdpa_adapter *vdpa_to_adapter(struct vdpa_device *vdpa_dev)
{
	return container_of(vdpa_dev, struct lsxvdpa_adapter, vdpa);
}

static struct lsxvdpa_hw *vdpa_to_vf(struct vdpa_device *vdpa_dev)
{
	struct lsxvdpa_adapter *adapter = vdpa_to_adapter(vdpa_dev);

	return &adapter->vf;
}

static u64 lsxvdpa_get_features(struct vdpa_device *vdpa_dev)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);
	u64 features;

	features = lsxvdpa_hw_get_features(vf) & LSXINIC_SUPPORTED_FEATURES;

	return features;
}

static int lsxvdpa_set_features(struct vdpa_device *vdpa_dev, u64 features)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->req_features = features;

	lsxvdpa_hw_set_features(vf, features);

	return 0;
}

static u8 lsxvdpa_get_status(struct vdpa_device *vdpa_dev)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	return lsxvdpa_hw_get_status(vf);
}

static void lsxvdpa_set_status(struct vdpa_device *vdpa_dev, u8 status)
{
	struct lsxvdpa_adapter *adapter;
	struct lsxvdpa_hw *vf;
	u8 status_old;
	int ret;

	vf  = vdpa_to_vf(vdpa_dev);
	adapter = dev_get_drvdata(vdpa_dev->dev.parent);
	status_old = lsxvdpa_hw_get_status(vf);

	if (status_old == status)
		return;

	if ((status_old & VIRTIO_CONFIG_S_DRIVER_OK) &&
	    !(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
		lsxvdpa_stop_datapath(adapter);
		lsxvdpa_free_irq(adapter, LSXVIO_MAX_QUEUE_PAIRS * 2);
	}

	if (status == 0) {
		lsxvdpa_reset_vring(adapter);
		return;
	}

	if ((status & VIRTIO_CONFIG_S_DRIVER_OK) &&
	    !(status_old & VIRTIO_CONFIG_S_DRIVER_OK)) {
		ret = lsxvdpa_request_irq(adapter);
		if (ret) {
			status = lsxvdpa_hw_get_status(vf);
			status |= VIRTIO_CONFIG_S_FAILED;
			lsxvdpa_hw_set_status(vf, status);
			return;
		}

		if (lsxvdpa_start_datapath(adapter) < 0)
			LSX_ERR(adapter->pdev,
				  "Failed to set lsxinic vdpa  status %u\n",
				  status);
	}

	lsxvdpa_hw_set_status(vf, status);
}

static u16 lsxvdpa_get_vq_num_max(struct vdpa_device *vdpa_dev)
{
	return LSXINIC_QUEUE_MAX;
}

static int lsxvdpa_get_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
				   struct vdpa_vq_state *state)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	state->avail_index = lsxvdpa_hw_get_vq_state(vf, qid);
	return 0;
}

static int lsxvdpa_set_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
				   const struct vdpa_vq_state *state)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	return lsxvdpa_hw_set_vq_state(vf, qid, state->avail_index);
}

static void lsxvdpa_set_vq_cb(struct vdpa_device *vdpa_dev, u16 qid,
				 struct vdpa_callback *cb)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->vring[qid].cb = *cb;
}

static void lsxvdpa_set_vq_ready(struct vdpa_device *vdpa_dev,
				    u16 qid, bool ready)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->vring[qid].ready = ready;
}

static bool lsxvdpa_get_vq_ready(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	return vf->vring[qid].ready;
}

static void lsxvdpa_set_vq_num(struct vdpa_device *vdpa_dev, u16 qid,
				  u32 num)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->vring[qid].size = num;
}

static int lsxvdpa_set_vq_address(struct vdpa_device *vdpa_dev, u16 qid,
				     u64 desc_area, u64 driver_area,
				     u64 device_area)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->vring[qid].desc = desc_area;
	vf->vring[qid].avail = driver_area;
	vf->vring[qid].used = device_area;

	return 0;
}

static void lsxvdpa_kick_vq(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	lsxvdpa_hw_notify_queue(vf, qid);
}

static u32 lsxvdpa_get_generation(struct vdpa_device *vdpa_dev)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	return ioread8(&vf->common_cfg->config_generation);
}

static u32 lsxvdpa_get_device_id(struct vdpa_device *vdpa_dev)
{
	struct lsxvdpa_adapter *adapter = vdpa_to_adapter(vdpa_dev);

	return (adapter->pdev->device - VIRTIO_ID_DEVICE_ID_BASE);
}

static u32 lsxvdpa_get_vendor_id(struct vdpa_device *vdpa_dev)
{
	return NXP_PCI_VENDOR_ID;
}

static u32 lsxvdpa_get_vq_align(struct vdpa_device *vdpa_dev)
{
	return LSXINIC_QUEUE_ALIGNMENT;
}

static void lsxvdpa_get_config(struct vdpa_device *vdpa_dev,
				  unsigned int offset,
				  void *buf, unsigned int len)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	WARN_ON(offset + len > sizeof(struct virtio_net_config));
	lsxvdpa_hw_read_net_config(vf, offset, buf, len);
}

static void lsxvdpa_set_config(struct vdpa_device *vdpa_dev,
				  unsigned int offset, const void *buf,
				  unsigned int len)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	WARN_ON(offset + len > sizeof(struct virtio_net_config));
	lsxvdpa_hw_write_net_config(vf, offset, buf, len);
}

static void lsxvdpa_set_config_cb(struct vdpa_device *vdpa_dev,
				     struct vdpa_callback *cb)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	vf->config_cb.callback = cb->callback;
	vf->config_cb.private = cb->private;
}

static int lsxvdpa_get_vq_irq(struct vdpa_device *vdpa_dev,
				 u16 qid)
{
	struct lsxvdpa_hw *vf = vdpa_to_vf(vdpa_dev);

	return vf->vring[qid].irq;
}

/*
 * LSXINIC currently does't have on-chip IOMMU, so not
 * implemented set_map()/dma_map()/dma_unmap()
 */
static const struct vdpa_config_ops lsxvdpa_ops = {
	.get_features	= lsxvdpa_get_features,
	.set_features	= lsxvdpa_set_features,
	.get_status	= lsxvdpa_get_status,
	.set_status	= lsxvdpa_set_status,
	.get_vq_num_max	= lsxvdpa_get_vq_num_max,
	.get_vq_state	= lsxvdpa_get_vq_state,
	.set_vq_state	= lsxvdpa_set_vq_state,
	.set_vq_cb	= lsxvdpa_set_vq_cb,
	.set_vq_ready	= lsxvdpa_set_vq_ready,
	.get_vq_ready	= lsxvdpa_get_vq_ready,
	.set_vq_num	= lsxvdpa_set_vq_num,
	.set_vq_address	= lsxvdpa_set_vq_address,
	.get_vq_irq	= lsxvdpa_get_vq_irq,
	.kick_vq	= lsxvdpa_kick_vq,
	.get_generation	= lsxvdpa_get_generation,
	.get_device_id	= lsxvdpa_get_device_id,
	.get_vendor_id	= lsxvdpa_get_vendor_id,
	.get_vq_align	= lsxvdpa_get_vq_align,
	.get_config	= lsxvdpa_get_config,
	.set_config	= lsxvdpa_set_config,
	.set_config_cb  = lsxvdpa_set_config_cb,
};

static int lsxvdpa_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct lsxvdpa_adapter *adapter;
	struct vdpa_device *vdpa;
	struct lsxvdpa_hw *vf;
	int ret, i;

	ret = pcim_enable_device(pdev);
	if (ret) {
		LSX_ERR(pdev, "Failed to enable device\n");
		return ret;
	}

	ret = pcim_iomap_regions(pdev, BIT(0) | BIT(2) | BIT(4),
			LSXINIC_DRIVER_NAME);
	if (ret) {
		LSX_ERR(pdev, "Failed to request MMIO region\n");
		return ret;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		LSX_ERR(pdev, "No usable DMA confiugration\n");
		return ret;
	}

#if (KERNEL_VERSION(5, 13, 0) <= LINUX_VERSION_CODE)
	vdpa = __vdpa_alloc_device(dev, &lsxvdpa_ops,
		sizeof(struct lsxvdpa_adapter), NULL);
#else
	vdpa = __vdpa_alloc_device(dev, &lsxvdpa_ops,
		LSXVIO_MAX_QUEUE_PAIRS * 2,
		sizeof(struct lsxvdpa_adapter));
#endif
	adapter = (struct lsxvdpa_adapter *)vdpa;
	if (adapter == NULL) {
		LSX_ERR(pdev, "Failed to allocate vDPA structure");
		return -ENOMEM;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, adapter);

	vf = &adapter->vf;
	vf->bar_addr = pcim_iomap_table(pdev);
	LSX_INFO(pdev, "######## show pcie bar info ########\n");
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		LSX_INFO(pdev, "index=%d, virt=%px, phy=%llx, size=%llx\n",
			i, vf->bar_addr[i], pdev->resource[i].start,
			pdev->resource[i].end - pdev->resource[i].start + 1);
	}

	adapter->pdev = pdev;
	adapter->vdpa.dma_dev = &pdev->dev;

	ret = lsxvdpa_hw_init_hw(vf, pdev);
	if (ret) {
		LSX_ERR(pdev, "Failed to init LSXINIC hw\n");
		goto err;
	}

	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++)
		vf->vring[i].irq = -EINVAL;

#if (KERNEL_VERSION(5, 13, 0) <= LINUX_VERSION_CODE)
	ret = vdpa_register_device(&adapter->vdpa,
		LSXVIO_MAX_QUEUE_PAIRS * 2);
#else
	ret = vdpa_register_device(&adapter->vdpa);
#endif
	if (ret) {
		LSX_ERR(pdev, "Failed to register lsxinic to vdpa bus");
		goto err;
	}

	return 0;

err:
	put_device(&adapter->vdpa.dev);
	return ret;
}

static void lsxvdpa_remove(struct pci_dev *pdev)
{
	struct lsxvdpa_adapter *adapter = pci_get_drvdata(pdev);

	vdpa_unregister_device(&adapter->vdpa);
}

static struct pci_device_id lsxvdpa_pci_ids[] = {
	{ PCI_DEVICE(VIRTIO_PCI_VENDORID, PCI_ANY_ID) },
	{ 0 },
};
MODULE_DEVICE_TABLE(pci, lsxvdpa_pci_ids);

static struct pci_driver lsxvdpa_driver = {
	.name     = LSXINIC_DRIVER_NAME,
	.id_table = lsxvdpa_pci_ids,
	.probe    = lsxvdpa_probe,
	.remove   = lsxvdpa_remove,
};

module_pci_driver(lsxvdpa_driver);

MODULE_LICENSE("GPL v2");
MODULE_VERSION(VERSION_STRING);
