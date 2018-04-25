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
};

#endif /* _PFE_MOD_H */
