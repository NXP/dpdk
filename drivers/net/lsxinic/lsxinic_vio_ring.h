// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2022 NXP  */

#ifndef _LSX_VIRTIO_RING_H_
#define _LSX_VIRTIO_RING_H_

#include <stdint.h>

#include <rte_common.h>

static inline size_t
lsx_vring_size(unsigned int num, unsigned long align)
{
	size_t size;

	size = num * sizeof(struct vring_desc);
	size += sizeof(struct vring_avail) + (num * sizeof(uint16_t));
	size = RTE_ALIGN_CEIL(size, align);
	size += sizeof(struct vring_used) +
		(num * sizeof(struct vring_used_elem));
	return size;
}

#endif /* _VIRTIO_RING_H_ */
