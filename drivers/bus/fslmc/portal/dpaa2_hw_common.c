/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2017 NXP. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of NXP nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <rte_malloc.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include <fslmc_logs.h>
#include <fslmc_vfio.h>

static struct rte_pci_device *
dpaa2_create_dev(int object_id, int object_type)
{
	struct rte_pci_device *dev;

	dev = rte_malloc(NULL, sizeof(struct rte_pci_device), 0);
	if (dev == NULL) {
		PMD_INIT_LOG(ERR, "device malloc failed");
		return NULL;
	}

	memset(dev, 0, sizeof(*dev));
	/* store hw_id of device */
	dev->addr.devid = object_id;
	dev->id.vendor_id = DPAA2_VENDOR_ID;
	dev->id.device_id = object_type;
	dev->addr.function = dev->id.device_id;

	TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
	return dev;
}

int
dpaa2_create_dpni_dev(struct fslmc_vfio_device *vdev,
		      struct vfio_device_info *obj_info,
		      int object_id)

{
	struct rte_pci_device *dev;

	dev = dpaa2_create_dev(object_id, DPAA2_MC_DPNI_DEVID);
	if (!dev)
		return -1;

	PMD_INIT_LOG(DEBUG, "DPAA2:Added [dpni-%d]", object_id);
	/* Enable IRQ for DPNI devices */
	dpaa2_vfio_setup_intr(&dev->intr_handle, vdev->fd, obj_info->num_irqs);

	return 0;
}

int
dpaa2_create_dpseci_dev(struct fslmc_vfio_device *vdev __rte_unused,
			struct vfio_device_info *obj_info __rte_unused,
			int object_id)
{
	struct rte_pci_device *dev;

	dev = dpaa2_create_dev(object_id, DPAA2_MC_DPSECI_DEVID);
	if (!dev)
		return -1;

	PMD_INIT_LOG(DEBUG, "DPAA2:Added [dpseci-%d]", object_id);
	return 0;
}
