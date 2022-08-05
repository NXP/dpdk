/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 *   Copyright 2022 NXP
 *
 */

#ifndef KPG_NC_MODULE_H
#define KPG_NC_MODULE_H

#define KPG_NC_DEVICE_NAME "page_ncache"
#define KPG_NC_DEVICE_PATH "/dev/" KPG_NC_DEVICE_NAME

/* IOCTL */
#define KPG_NC_MAGIC_NUM		0xf0f0
#define KPG_NC_IOCTL_UPDATE  _IOWR(KPG_NC_MAGIC_NUM, 1, size_t)

#endif // PG_NC_MODULE_H
