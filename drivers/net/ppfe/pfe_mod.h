/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#ifndef _PFE_MOD_H_
#define _PFE_MOD_H_

struct pfe;

#include <rte_dev.h>
#include "pfe.h"
#include "pfe_hif.h"
#include "pfe_hif_lib.h"
#include "pfe_eth.h"

#define PHYID_MAX_VAL 32

struct pfe {
	uint64_t ddr_phys_baseaddr;
	void *ddr_baseaddr;
	uint64_t ddr_size;
	void *cbus_baseaddr;
	struct ls1012a_pfe_platform_data platform_data;
	struct pfe_hif hif;
	struct pfe_eth eth;
	struct hif_client_s *hif_client[HIF_CLIENTS_MAX];
	int mdio_muxval[PHYID_MAX_VAL];
	uint8_t nb_devs;
	uint8_t max_intf;
	int cdev_fd;
};

/* for link status and IOCTL support using pfe character device
 * XXX: Should be kept in sync with Kernel module
 */

/* Extracted from ls1012a_pfe_platform_data, there are 3 interfaces which are
 * supported by PFE driver. Should be updated if number of eth devices are
 * changed.
 */
#define PFE_CDEV_ETH_COUNT 3

#define PFE_CDEV_PATH		"/dev/pfe_us_cdev"
#define PFE_CDEV_INVALID_FD	-1

/* used when 'read' call is issued, returning PFE_CDEV_ETH_COUNT number of
 * pfe_shared_info as array.
 */
struct pfe_shared_info {
	uint32_t phy_id; /* Link phy ID */
	uint8_t state;  /* Has either 0 or 1 */
};

/* IOCTL Commands */
#define PFE_CDEV_ETH0_STATE_GET		_IOR('R', 0, int)
#define PFE_CDEV_ETH1_STATE_GET		_IOR('R', 1, int)
#define PFE_CDEV_HIF_INTR_EN		_IOWR('R', 2, int)
#endif /* _PFE_MOD_H */
