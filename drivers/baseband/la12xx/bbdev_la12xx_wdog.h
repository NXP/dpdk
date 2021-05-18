/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef __BBDEV_LA12XX_WDOG_H__
#define __BBDEV_LA12XX_WDOG_H__

#include <linux/ioctl.h>

#define GUL_WDOG_MAGIC   'W'

#define IOCTL_GUL_MODEM_WDOG_REGISTER    _IOWR(GUL_WDOG_MAGIC, 1, struct wdog *)
#define IOCTL_GUL_MODEM_WDOG_DEREGISTER  _IOWR(GUL_WDOG_MAGIC, 2, struct wdog *)
#define IOCTL_GUL_MODEM_WDOG_RESET       _IOWR(GUL_WDOG_MAGIC, 3, struct wdog *)
#define IOCTL_GUL_MODEM_WDOG_GET_STATUS  _IOWR(GUL_WDOG_MAGIC, 4, struct wdog *)
#define IOCTL_GUL_MODEM_WDOG_GET_DOMAIN  _IOWR(GUL_WDOG_MAGIC, 5, struct wdog *)

/**
 * Maximum number of watchdog instances
 */
#define MAX_WDOG_COUNT   1

/**
 * A structure holds modem watchdog information
 */
struct wdog {
	uint32_t	wdogid; /**< modem watchdog id */
	int32_t		dev_wdog_handle; /**< fd of modem watchdog device */
	int32_t		wdog_eventfd; /**< eventfd for watchdog events */
	int32_t		wdog_modem_status; /**< modem status */
	int32_t		domain_nr; /**< pci domain assigned by linux */
};

/**
 * A modem watchdog status
 */
enum wdog_modem_status {
	WDOG_MODEM_NOT_READY = 0,/**< Modem not ready */
	WDOG_MODEM_READY	/**< Modem ready */
};

#define PCI_DOMAIN_NR_INVALID		-1
#define MODEM_PCI_RESCAN_FILE		"/sys/bus/pci/rescan"
#define MODEM_PCI_DEVICE_PATH		"/sys/bus/pci/devices"

/* WDOG Lib error codes */
#define MODEM_WDOG_OK			0
#define MODEM_WDOG_OPEN_FAIL		1
#define MODEM_WDOG_WRITE_FAIL		2

int libwdog_register(struct wdog *wdog_t, int modem_id);
int libwdog_reinit_modem(struct wdog *wdog_t, uint32_t timeout);
int libwdog_deregister(struct wdog *wdog_t);
int libwdog_get_modem_status(struct wdog *wdog_t);

#endif /*__BBDEV_LA12XX_WDOG_H__*/

