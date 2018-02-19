/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#ifndef _PFE_MOD_H_
#define _PFE_MOD_H_

struct pfe;

#include <rte_dev.h>
#include "pfe/pfe.h"
#include "pfe_hif.h"
#include "pfe_hif_lib.h"
#include "pfe_eth.h"

#define PHYID_MAX_VAL 32

struct pfe_tmu_credit {
	/* Number of allowed TX packet in-flight, matches TMU queue size */
	unsigned int tx_credit[NUM_GEMAC_SUPPORT][EMAC_TXQ_CNT];
	unsigned int tx_credit_max[NUM_GEMAC_SUPPORT][EMAC_TXQ_CNT];
	unsigned int tx_packets[NUM_GEMAC_SUPPORT][EMAC_TXQ_CNT];
};

struct pfe {
	uint64_t ddr_phys_baseaddr;
	void *ddr_baseaddr;
	uint64_t ddr_size;
	void *cbus_baseaddr;
	struct ls1012a_pfe_platform_data platform_data;
	struct pfe_hif hif;
	struct pfe_eth eth;
	struct hif_client_s *hif_client[HIF_CLIENTS_MAX];
	struct pfe_tmu_credit tmu_credit;
	int mdio_muxval[PHYID_MAX_VAL];
	uint8_t nb_devs;
	uint8_t max_intf;
};

/* DDR Mapping in reserved memory*/
#define SZ_1K 1000
#define ROUTE_TABLE_BASEADDR	0
#define ROUTE_TABLE_HASH_BITS	15	/* 32K entries */
#define ROUTE_TABLE_SIZE	((1 << ROUTE_TABLE_HASH_BITS) \
				  * CLASS_ROUTE_SIZE)
#define BMU2_DDR_BASEADDR	(ROUTE_TABLE_BASEADDR + ROUTE_TABLE_SIZE)
#define BMU2_BUF_COUNT		(4096 - 256)
/* This is to get a total DDR size of 12MiB */
#define BMU2_DDR_SIZE		(DDR_BUF_SIZE * BMU2_BUF_COUNT)
#define UTIL_CODE_BASEADDR	(BMU2_DDR_BASEADDR + BMU2_DDR_SIZE)
#define UTIL_CODE_SIZE		(128 * SZ_1K)
#define UTIL_DDR_DATA_BASEADDR	(UTIL_CODE_BASEADDR + UTIL_CODE_SIZE)
#define UTIL_DDR_DATA_SIZE	(64 * SZ_1K)
#define CLASS_DDR_DATA_BASEADDR	(UTIL_DDR_DATA_BASEADDR + UTIL_DDR_DATA_SIZE)
#define CLASS_DDR_DATA_SIZE	(32 * SZ_1K)
#define TMU_DDR_DATA_BASEADDR	(CLASS_DDR_DATA_BASEADDR + CLASS_DDR_DATA_SIZE)
#define TMU_DDR_DATA_SIZE	(32 * SZ_1K)
#define TMU_LLM_BASEADDR	(TMU_DDR_DATA_BASEADDR + TMU_DDR_DATA_SIZE)
#define TMU_LLM_QUEUE_LEN	(8 * 512)
/* Must be power of two and at least 16 * 8 = 128 bytes */
#define TMU_LLM_SIZE		(4 * 16 * TMU_LLM_QUEUE_LEN)
/* (4 TMU's x 16 queues x queue_len) */

#define DDR_MAX_SIZE		(TMU_LLM_BASEADDR + TMU_LLM_SIZE)

/* LMEM Mapping */
#define BMU1_LMEM_BASEADDR	0
#define BMU1_BUF_COUNT		256
#define BMU1_LMEM_SIZE		(LMEM_BUF_SIZE * BMU1_BUF_COUNT)

#define TMU_DM_SH_STATIC                (0x80)
#define TMU_DM_CPU_TICKS                (TMU_DM_SH_STATIC)
#define TMU_DM_SYNC_MBOX                (0x88)
#define TMU_DM_MSG_MBOX                 (0x90)
#define TMU_DM_RESUME                   (0xA0)
#define TMU_DM_PESTATUS                 (0xB0)
#define TMU_DM_CONTEXT                  (0x300)
#define TMU_DM_TX_TRANS                 (0x480)

#endif /* _PFE_MOD_H */
