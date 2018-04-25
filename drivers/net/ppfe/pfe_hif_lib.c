/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#include <rte_net.h>

#include "pfe_logs.h"
#include "pfe_mod.h"
#include "pfe_hif.h"
#include "pfe_hif_lib.h"

unsigned int emac_txq_cnt;

/*
 * @pfe_hal_lib.c
 * Common functions used by HIF client drivers
 */

/*HIF shared memory Global variable */
struct hif_shm ghif_shm;

/* Cleanup the HIF shared memory, release HIF rx_buffer_pool.
 * This function should be called after pfe_hif_exit
 *
 * @param[in] hif_shm		Shared memory address location in DDR
 */
void pfe_hif_shm_clean(struct hif_shm *hif_shm)
{
	unsigned int i;
	void *pkt;

	for (i = 0; i < hif_shm->rx_buf_pool_cnt; i++) {
		pkt = hif_shm->rx_buf_pool[i];
		if (pkt)
			rte_pktmbuf_free((struct rte_mbuf *)pkt);
	}
}

/* Initialize shared memory used between HIF driver and clients,
 * allocate rx_buffer_pool required for HIF Rx descriptors.
 * This function should be called before initializing HIF driver.
 *
 * @param[in] hif_shm		Shared memory address location in DDR
 * @rerurn			0 - on succes, <0 on fail to initialize
 */
int pfe_hif_shm_init(struct hif_shm *hif_shm, struct rte_mempool *mb_pool)
{
	unsigned int i;
	struct rte_mbuf *mbuf;

	memset(hif_shm, 0, sizeof(struct hif_shm));
	hif_shm->rx_buf_pool_cnt = HIF_RX_DESC_NT;

	for (i = 0; i < hif_shm->rx_buf_pool_cnt; i++) {
		mbuf = rte_cpu_to_le_64(rte_pktmbuf_alloc(mb_pool));
		if (mbuf)
			hif_shm->rx_buf_pool[i] = mbuf;
		else
			goto err0;
	}

	return 0;

err0:
	PFE_PMD_ERR("Low memory");
	pfe_hif_shm_clean(hif_shm);
	return -ENOMEM;
}

int pfe_hif_lib_init(struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();

	emac_txq_cnt = EMAC_TXQ_CNT;
	pfe->hif.shm = &ghif_shm;

	return 0;
}

void pfe_hif_lib_exit(__rte_unused struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();
}
