/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 NXP
 */

#ifndef __BBDEV_LA93XX_WDOG_H__
#define __BBDEV_LA93XX_WDOG_H__

#include <linux/ioctl.h>

#define LA9310_WDOG_MAGIC   'W'

#define IOCTL_LA9310_MODEM_WDOG_REGISTER    _IOWR(LA9310_WDOG_MAGIC, 1, struct wdog *)
#define IOCTL_LA9310_MODEM_WDOG_DEREGISTER  _IOWR(LA9310_WDOG_MAGIC, 2, struct wdog *)
#define IOCTL_LA9310_MODEM_WDOG_RESET       _IOWR(LA9310_WDOG_MAGIC, 3, struct wdog *)
#define IOCTL_LA9310_MODEM_WDOG_GET_STATUS  _IOWR(LA9310_WDOG_MAGIC, 4, struct wdog *)
#define IOCTL_LA9310_MODEM_WDOG_GET_DOMAIN  _IOWR(LA9310_WDOG_MAGIC, 5, struct wdog *)

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

int la93xx_wdog_open(struct wdog *wdog_t, int modem_id);
int la93xx_wdog_close(struct wdog *wdog_t);
int la93xx_wdog_register(struct wdog *wdog_t);
int la93xx_wdog_reinit_modem(struct wdog *wdog_t, uint32_t timeout);
int la93xx_wdog_deregister(struct wdog *wdog_t);
int la93xx_wdog_get_modem_status(struct wdog *wdog_t);
int la93xx_wdog_readwait(int dev_wdog_handle, void *buf, int count);

#endif /*__BBDEV_LA93XX_WDOG_H__*/

