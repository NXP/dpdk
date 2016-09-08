/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014-2016 Freescale Semiconductor, Inc. All rights reserved.
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
 *     * Neither the name of  Freescale Semiconductor, Inc nor the names of its
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
/* System headers */
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include <pthread.h>

#include <rte_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "dpaa_ethdev.h"
#include "dpaa_rxtx.h"

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>

static struct rte_pci_id dpaa_pci_id[2] = {
	{FSL_CLASS_ID,
		FSL_VENDOR_ID,
		FSL_DEVICE_ID,
		FSL_SUBSYSTEM_VENDOR,
		FSL_SUBSYSTEM_DEVICE},
	{0, 0, 0, 0}
};

#define PCI_DEV_ADDR(dev) \
	((dev->addr.domain << 24) | (dev->addr.bus << 16) | \
	 (dev->addr.devid << 8) | (dev->addr.function))

struct dpaa_if *dpaa_ifacs;
static struct usdpaa_netcfg_info *netcfg;

__thread bool thread_portal_init;
static unsigned int num_dpaa_ports;

/* Static BPID index allocator, increments continuously */
rte_atomic32_t bpid_alloc = RTE_ATOMIC64_INIT(0);

struct pool_info_entry dpaa_pool_table[NUM_BP_POOL_ENTRIES];

static int dpaa_pci_devinit(struct rte_pci_driver *pci_drv __rte_unused,
			    struct rte_pci_device *pci_dev);

/* Initialise a admin FQ ([rt]x_error, rx_default, tx_confirm). */
static int dpaa_admin_queue_init(struct dpaa_if *dpaa_intf, uint32_t fqid, int idx)
{
	struct qman_fq *a = &dpaa_intf->admin[idx];
	struct qm_mcc_initfq opts;
	int ret;

	/* Offline ports don't support tx_error nor tx_confirm */
	if ((idx <= ADMIN_FQ_RX_DEFAULT) ||
	    (dpaa_intf->cfg->fman_if->mac_type != fman_offline))
		return 0;

	ret = qman_reserve_fqid(fqid);
	if (ret)
		return -EINVAL;

	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, a);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.wq = DPAA_IF_ADMIN_PRIORITY;
	return qman_init_fq(a, 0, &opts);
}

/* Initialise an Rx FQ */
static int dpaa_rx_queue_init(struct qman_fq *fq,
			      uint32_t fqid)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_reserve_fqid(fqid);
	if (ret) {
		PMD_DRV_LOG(ERROR, "reserve rx fqid %d failed", fqid);
		return -EINVAL;
	}
	/* "map" this Rx FQ to one of the interfaces Tx FQID */
	PMD_DRV_LOG(DEBUG, "%s::creating rx fq %p, fqid %d",
		    __func__, fq, fqid);
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	if (ret) {
		PMD_DRV_LOG(ERROR, "create rx fqid %d failed", fqid);
		return ret;
	}
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA;

	PMD_DRV_LOG(DEBUG, "fqid %x, wq %d ifid %d", fqid,
		    DPAA_IF_RX_PRIORITY, dpaa_intf->ifid);

	opts.fqd.dest.wq = DPAA_IF_RX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			   QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_a.stashing.exclusive = 0;
	opts.fqd.context_a.stashing.annotation_cl = DPAA_IF_RX_ANNOTATION_STASH;
	opts.fqd.context_a.stashing.data_cl = DPAA_IF_RX_DATA_STASH;
	opts.fqd.context_a.stashing.context_cl = DPAA_IF_RX_CONTEXT_STASH;
	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		PMD_DRV_LOG(ERROR, "init rx fqid %d failed %d", fqid, ret);
	return ret;
}

/* Initialise a Tx FQ */
static int dpaa_tx_queue_init(struct qman_fq *fq,
			      struct fman_if *fif)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
			     QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = fif->tx_channel_id;
	opts.fqd.dest.wq = DPAA_IF_TX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	/* no tx-confirmation */
	opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
	opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	PMD_DRV_LOG(DEBUG, "%s::initializing fqid %d for iface fm%d-gb%d chanl %d\n",
		    __func__, fq->fqid, (fif->fman_idx + 1), fif->mac_idx,
		fif->tx_channel_id);
	return qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}

static struct bman_pool *dpaa_bpid_init(int bpid)
{
	struct bm_buffer bufs[8];
	struct bman_pool *bp = NULL;
	unsigned int num_bufs = 0;
	int ret = 0;

	PMD_DRV_LOG(DEBUG, "request bman pool: bpid %d", bpid);
	/* Drain (if necessary) then seed buffer pools */
	struct bman_pool_params params = {
		.bpid = bpid
	};

	bp = bman_new_pool(&params);
	if (!bp) {
		PMD_DRV_LOG(ERROR, "bman_new_pool() failed");
		return NULL;
	}

	/* Drain the pool of anything already in it. */
	do {
		/* Acquire is all-or-nothing, so we drain in 8s, then in 1s for
		 * the remainder.
		 */
		if (ret != 1)
			ret = bman_acquire(bp, bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(bp, bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);
	if (num_bufs)
		PMD_DRV_LOG(WARN, "drained %u bufs from BPID %d",
			    num_bufs, bpid);

	return bp;
}

int dpaa_mbuf_create_pool(struct rte_mempool *mp)
{
	uint32_t bpid;
	struct bman_pool *bp;

	/*XXX: bpid_alloc needs to be changed to a bitmap, so that
	 * we can take care of destroy_pool kind of API too. Current
	 * implementation doesn't allow deallocation of entry
	 */
	bpid = rte_atomic32_add_return(&bpid_alloc, 1);

	if (bpid > NUM_BP_POOL_ENTRIES) {
		PMD_DRV_LOG(ERROR, "exceeding bpid requirements");
		return -2;
	}

	bp = dpaa_bpid_init(bpid);
	if (!bp) {
		PMD_DRV_LOG(ERROR, "dpaa_bpid_init failed\n");
		return -2;
	}

	dpaa_pool_table[bpid].mp = mp;
	dpaa_pool_table[bpid].bpid = bpid;
	dpaa_pool_table[bpid].size = mp->elt_size;
	dpaa_pool_table[bpid].bp = bp;
	dpaa_pool_table[bpid].meta_data_size =
		sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(mp);
	mp->pool_data = (void *)&dpaa_pool_table[bpid];

	/* TODO: Replace with mp->pool_data->flags after creating appropriate
	 * pool_data structure
	 */
	mp->flags |= MEMPOOL_F_HW_PKT_POOL;

	PMD_DRV_LOG(INFO, "BP List created for bpid =%d\n", bpid);
	return 0;
}

void dpaa_mbuf_free_pool(struct rte_mempool *mp __rte_unused)
{
	/* TODO:
	 * 1. Release bp_list memory allocation
	 * 2. opposite of dpbp_enable()
	 * <More>
	 */

	PMD_DRV_LOG(DEBUG, "(%s) called\n", __func__);
	return;
}

int dpaa_mbuf_alloc_bulk(struct rte_mempool *pool,
		void **obj_table,
		unsigned count)
{
	void *bufaddr;
	int ret;
	unsigned int i = 0, n = 0;
	struct rte_mbuf **m = (struct rte_mbuf **)obj_table;
	struct bm_buffer bufs[RTE_MEMPOOL_CACHE_MAX_SIZE + 1];
	struct pool_info_entry *bp_info;

	bp_info = DPAA_MEMPOOL_TO_POOL_INFO(pool);

	if (!netcfg || !bp_info) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -2;
	}

	if (!thread_portal_init) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERROR, "Failure in affining portal");
			return 0;
		}
	}

	if (count < DPAA_MBUF_MAX_ACQ_REL) {
		ret = bman_acquire(bp_info->bp,
				   &bufs[n], count, 0);
		if (ret <= 0) {
			PMD_DRV_LOG(WARNING, "Failed to allocate buffers %d", ret);
			return -1;
		}
		n = ret;
		goto set_buf;
	}

	while (n < count) {
		ret = 0;
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then in 1s for the remainder. */
		if ((count - n) >= DPAA_MBUF_MAX_ACQ_REL) {
			ret = bman_acquire(bp_info->bp,
					   &bufs[n], DPAA_MBUF_MAX_ACQ_REL, 0);
			if (ret == DPAA_MBUF_MAX_ACQ_REL) {
				n += ret;
			}
		} else {
			ret =  bman_acquire(bp_info->bp,
					    &bufs[n], count - n, 0);
			if (ret > 0) {
				PMD_DRV_LOG(DEBUG, "ret = %d bpid =%d alloc %d,"
					"count=%d Drained buffer: %x",
					ret, bp_info->bpid,
					alloc, count - n, bufs[n]);
				n += ret;
			}
		}
		/* In case of less than requested number of buffers available
		 * in pool, bman_acquire can return 0
		 */
		if (ret <= 0) {
			PMD_DRV_LOG(WARNING, "Buffer acquire failed with"
				"err code: %d", ret);
			break;
		}
	}
	if (count != n)
		goto free_buf;

	if (ret < 0 || n == 0) {
		PMD_DRV_LOG(WARNING, "Failed to allocate buffers %d", ret);
		return -1;
	}
set_buf:
	while (i < count) {
		bufaddr = (void *)dpaa_mem_ptov(bufs[i].addr);
		m[i] = (struct rte_mbuf *)((char *)bufaddr
			- bp_info->meta_data_size);
		RTE_ASSERT(rte_mbuf_refcnt_read(m[i]) == 0);
		rte_mbuf_refcnt_set(m[i], 1);
		i = i + 1;
	}
  	PMD_DRV_LOG(DEBUG, " req = %d done = %d bpid =%d",
		    count, n, bp_info->bpid);
 	return 0;
free_buf:
	PMD_DRV_LOG(WARNING, "unable alloc required bufs count =%d n=%d",
		    count, n);
	i = 0;
	while (i < n) {
retry:
		ret = bman_release(bp_info->bp, &bufs[i], 1, 0);
		if (ret) {
			cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
			goto retry;
		}
		i++;
	}
	return -1;
}

int dpaa_mbuf_free_bulk(struct rte_mempool *pool,
		void *const *obj_table,
		unsigned n)
{
	struct rte_mbuf **mb = (struct rte_mbuf **)obj_table;
	struct pool_info_entry *bp_info;
	unsigned i = 0;
	int ret;

	if (!thread_portal_init) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERROR, "Failure in affining portal");
			return 0;
		}
	}

	if (!netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -1;
	}
	while (i < n) {
		bp_info = DPAA_MEMPOOL_TO_POOL_INFO(pool);
		dpaa_buf_free(bp_info,
			      (uint64_t)rte_mempool_virt2phy(pool, obj_table[i])
				+ bp_info->meta_data_size);
		i = i + 1;
	}

	return 0;
}

unsigned int dpaa_mbuf_get_count(const struct rte_mempool *mp __rte_unused)
{
	/*TBD:XXX: to be implemented*/
	return 0;
}

struct rte_mempool_ops dpaa_mpool_ops = {
	.name = "dpaa",
	.alloc = dpaa_mbuf_create_pool,
	.free = dpaa_mbuf_free_pool,
	.enqueue = dpaa_mbuf_free_bulk,
	.dequeue = dpaa_mbuf_alloc_bulk,
	.get_count = dpaa_mbuf_get_count,
};

MEMPOOL_REGISTER_OPS(dpaa_mpool_ops);

/* Initialise a network interface */
static int dpaa_if_init(struct dpaa_if *dpaa_intf,
			const struct fm_eth_port_cfg *cfg)
{
	struct fman_if *fif = cfg->fman_if;
	int num_cores, loop, ret = 0;
	int num_rx_fqs, fqid;

	dpaa_intf->cfg = cfg;
	/* give the interface a name */
	sprintf(&dpaa_intf->name[0], "fm%d-gb%d", (cfg->fman_if->fman_idx + 1),
		cfg->fman_if->mac_idx);

	/* get the mac address */
	memcpy(&dpaa_intf->mac_addr, &cfg->fman_if->mac_addr.addr_bytes,
	       ETHER_ADDR_LEN);

	printf("%s::interface %s macaddr::", __func__, dpaa_intf->name);
	for (loop = 0; loop < ETHER_ADDR_LEN; loop++) {
		if (loop != (ETHER_ADDR_LEN - 1))
			printf("%02x:", dpaa_intf->mac_addr[loop]);
		else
			printf("%02x\n", dpaa_intf->mac_addr[loop]);
	}

	/* Initialise admin FQs */
	ret = dpaa_admin_queue_init(dpaa_intf, fif->fqid_rx_err,
				    ADMIN_FQ_RX_ERROR);
	if (!ret)
		ret = dpaa_admin_queue_init(dpaa_intf, cfg->rx_def,
					    ADMIN_FQ_RX_DEFAULT);
	if (!ret)
		ret = dpaa_admin_queue_init(dpaa_intf, fif->fqid_tx_err,
					    ADMIN_FQ_TX_ERROR);
	if (!ret)
		ret = dpaa_admin_queue_init(dpaa_intf, fif->fqid_tx_confirm,
					    ADMIN_FQ_TX_CONFIRM);
	if (ret) {
		printf("%s::admin create FQ failed\n", __func__);
		return ret;
	}

	dpaa_intf->admin[ADMIN_FQ_RX_ERROR].ifid = dpaa_intf->ifid;
	dpaa_intf->admin[ADMIN_FQ_RX_DEFAULT].ifid = dpaa_intf->ifid;
	dpaa_intf->admin[ADMIN_FQ_TX_ERROR].ifid = dpaa_intf->ifid;
	dpaa_intf->admin[ADMIN_FQ_TX_CONFIRM].ifid = dpaa_intf->ifid;

	if (getenv("DPAA_NUM_RX_QUEUES"))
		num_rx_fqs = atoi(getenv("DPAA_NUM_RX_QUEUES"));
	else
		num_rx_fqs = DPAA_DEFAULT_NUM_PCD_QUEUES;

	dpaa_intf->rx_queues = rte_zmalloc(NULL,
		sizeof(struct qman_fq) * num_rx_fqs, MAX_CACHELINE);
	for (loop = 0; loop < num_rx_fqs; loop++) {
		fqid = DPAA_PCD_FQID_START + dpaa_intf->ifid *
			DPAA_PCD_FQID_MULTIPLIER + loop;
		ret = dpaa_rx_queue_init(&dpaa_intf->rx_queues[loop], fqid);
		if (ret) {
			printf("%s::dpaa_rx_queue_init failed for %x\n",
			       __func__, fqid);
			return ret;
		}
		dpaa_intf->rx_queues[loop].ifid = dpaa_intf->ifid;
	}
	dpaa_intf->nb_rx_queues = num_rx_fqs;

	/* Initialise Tx FQs. Have as many Tx FQ's as number of cores */
	num_cores = rte_lcore_count();
	dpaa_intf->tx_queues = rte_zmalloc(NULL, sizeof(struct qman_fq) *
		num_cores, MAX_CACHELINE);
	if (!dpaa_intf->tx_queues)
		return -ENOMEM;

	for (loop = 0; loop < num_cores; loop++) {
		ret = dpaa_tx_queue_init(&dpaa_intf->tx_queues[loop], fif);
		if (ret)
			return ret;
		PMD_DRV_LOG(DEBUG, "%s::tx_fqid %x",
			    __func__, dpaa_intf->tx_queues[loop].fqid);
		dpaa_intf->tx_queues[loop].ifid = dpaa_intf->ifid;
	}
	dpaa_intf->nb_tx_queues = num_cores;

	/* save fif in the interface struture */
	dpaa_intf->fif = fif;
	PMD_DRV_LOG(DEBUG, "all rxfqs created");

	/* Disable RX, disable promiscous mode */
	fman_if_disable_rx(fif);
	fman_if_promiscuous_disable(fif);
	return 0;
}

static int dpaa_init(void)
{
	/* Determine number of cores (==number of threads) */
	/* Load the device-tree driver */
	int ii, ret;

	ret = of_init();
	if (ret) {
		printf("of_init Failed %d\n", ret);
		return -1;
	}
	/* Parse FMC policy and configuration files for the network
	 * configuration. This also "extracts" other settings into 'netcfg' that
	 * are not necessarily from the XML files, such as the pool channels
	 * that the application is allowed to use (these are currently
	 * hard-coded into the netcfg code). */
	netcfg = usdpaa_netcfg_acquire();
	if (!netcfg) {
		fprintf(stderr, "Fail: usdpaa_netcfg_acquire\n");
		return -1;
	}
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%d ethports available\n", netcfg->num_ethports);
	dump_usdpaa_netcfg(netcfg);
#endif
	if (!netcfg->num_ethports) {
		fprintf(stderr, "Fail: no network interfaces available\n");
		return -1;
	}
	dpaa_ifacs = calloc(netcfg->num_ethports, sizeof(*dpaa_ifacs));
	if (!dpaa_ifacs)
		return -ENOMEM;

	for (ii = 0; ii < netcfg->num_ethports; ii++) {
		struct fm_eth_port_cfg *cfg;
		struct fman_if *fman_if;

		cfg = &netcfg->port_cfg[ii];
		fman_if = cfg->fman_if;
		sprintf(&dpaa_ifacs->name[0], "fm%d-gb%d",
			(fman_if->fman_idx + 1),
				fman_if->mac_idx);
	}
	/* Load the Qman/Bman drivers */
	ret = qman_global_init();
	if (ret) {
		fprintf(stderr, "Fail: %s: %d\n", "qman_global_init()", ret);
		return -1;
	}
	ret = bman_global_init();
	if (ret) {
		fprintf(stderr, "Fail: %s: %d\n", "bman_global_init()", ret);
		return -1;
	}
	return netcfg->num_ethports;
}

int dpaa_portal_init(void *arg)
{
	cpu_set_t cpuset;
	pthread_t id;
	uint32_t cpu;
	int ret;

	if (thread_portal_init)
		return 0;

	if ((uint64_t)arg == 1)
		cpu = rte_get_master_lcore();
	else
		cpu = rte_lcore_id();

	PMD_DRV_LOG(DEBUG, "arg %p, cpu %d", arg, cpu);
	/* Set CPU affinity for this thread */
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	id = pthread_self();
	ret = pthread_setaffinity_np(id, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		PMD_DRV_LOG(ERROR, "pthread_setaffinity_np failed on core :%d", cpu);
		return -1;
	}

	/* Initialise bman thread portals */
	ret = bman_thread_init();
	if (ret) {
		PMD_DRV_LOG(ERROR, "bman_thread_init failed on core %d", cpu);
		return -1;
	}
	/* Initialise qman thread portals */
	ret = qman_thread_init();
	if (ret) {
		PMD_DRV_LOG(ERROR, "bman_thread_init failed on core %d", cpu);
		return -1;
	}
	thread_portal_init = true;

	return 0;
}

static int dpaa_global_init(void)
{
	unsigned int loop;

	/* Create and initialise the network interfaces */
	PMD_DRV_LOG(DEBUG, "creating %d ifaces", netcfg->num_ethports);
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		struct fman_if_bpool *bp, *tmp_bp;
		struct fm_eth_port_cfg *pcfg;
		int ret;

		pcfg = &netcfg->port_cfg[loop];
		dpaa_ifacs[loop].ifid = loop;

		ret = dpaa_if_init(&dpaa_ifacs[loop], pcfg);
		if (ret) {
			PMD_DRV_LOG(ERROR, "dpaa_if_init(%d) failed", loop);
			return ret;
		}
		/* reset bpool list, initialize bpool dynamically */
		list_for_each_entry_safe(bp, tmp_bp, &pcfg->fman_if->bpool_list, node) {
			list_del(&bp->node);
			free(bp);
		}
	}
	return 0;
}

static inline void insert_devices_into_pcilist(struct rte_pci_device *dev)
{
	uint32_t devaddr;
	uint32_t newdevaddr;
	struct rte_pci_device *dev2 = NULL;

	if (!(TAILQ_EMPTY(&pci_device_list))) {
		newdevaddr = PCI_DEV_ADDR(dev);
		TAILQ_FOREACH(dev2, &pci_device_list, next) {
			devaddr = PCI_DEV_ADDR(dev2);

			if (newdevaddr < devaddr) {
				TAILQ_INSERT_BEFORE(dev2, dev, next);
				return;
			}
		}
	}
	TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
}

static struct rte_pci_driver dpaa_pci_driver = {
	.name = "dpaa_pci_driver",
	.id_table = dpaa_pci_id,
	.devinit = dpaa_pci_devinit
};

int add_dpaa_devices_to_pcilist(int num_ethports)
{
	int ii;
	struct rte_pci_device *dev;

	for (ii = 0; ii < num_ethports; ii++) {
		dev = calloc(1, sizeof(struct rte_pci_device));
		if (!dev) {
			printf("%s::unable to allocate dev for %d\n",
			       __func__, ii);
			return -1;
		}
		dev->addr.domain = FSL_DPAA_DOMAIN;
		dev->addr.bus = FSL_DPAA_BUSID;
		dev->addr.devid = ii;
		dev->id.class_id = FSL_CLASS_ID;
		dev->id.vendor_id = FSL_VENDOR_ID;
		dev->id.device_id = FSL_DEVICE_ID;
		dev->id.subsystem_vendor_id = FSL_SUBSYSTEM_VENDOR;
		dev->id.subsystem_device_id = FSL_SUBSYSTEM_DEVICE;
		dev->numa_node = 0;

		/* device is valid, add in list (sorted) */
		insert_devices_into_pcilist(dev);
	}
	printf("%s::%d devices added to pci list\n", __func__, ii);
	rte_eal_pci_register(&dpaa_pci_driver);

	return 0;
}

int dpaa_pre_rte_eal_init(void)
{
	int ret = 0;

	ret = dpaa_init();
	if (ret <= 0) {
		printf("Cannot init dpaa\n");
		return -1;
	}

	num_dpaa_ports = ret;

	if (dpaa_portal_init((void *)1)) {
		printf("dpaa portal init failed\n");
		return -1;
	}
	PMD_DRV_LOG(DEBUG, "%s::global init, net portals\n", __func__);
	if (dpaa_global_init()) {
		printf("%s::dpaa_global_init failed\n", __func__);
		return -1;
	}
	if (add_dpaa_devices_to_pcilist(num_dpaa_ports)) {
		printf("Cannot init non pci dev list\n");
		return -1;
	}

	return 0;
}

static uint16_t dpaa_eth_tx_drop_all(void *q  __rte_unused,
				     struct rte_mbuf **bufs __rte_unused,
		uint16_t nb_bufs __rte_unused)
{
	/* Drop all incoming packets. No need to free packets here
	 * because the rte_eth f/w frees up the packets through tx_buffer
	 * callback in case this functions returns count less than nb_bufs
	 */
	return 0;
}

static int
dpaa_eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static const uint32_t *
dpaa_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP
	};

	if (dev->rx_pkt_burst == dpaa_eth_queue_rx)
		return ptypes;
	return NULL;
}

static int dpaa_eth_dev_start(struct rte_eth_dev *dev)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	/* Change tx callback to the real one */
	dev->tx_pkt_burst = dpaa_eth_queue_tx;

	fman_if_enable_rx(iface->fif);
	return 0;
}

static void dpaa_eth_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	fman_if_disable_rx(iface->fif);
	dev->tx_pkt_burst = dpaa_eth_tx_drop_all;
}

static void dpaa_eth_dev_close(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_stop(dev);
}

static void dpaa_eth_dev_info(struct rte_eth_dev *dev,
			      struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = DPAA_NUM_RX_QUEUE(dev->data->port_id);
	dev_info->max_tx_queues = DPAA_NUM_TX_QUEUE(dev->data->port_id);
	dev_info->min_rx_bufsize = DPAA_MIN_RX_BUF_SIZE;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = 0;
	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = dev->pci_dev->max_vfs;
	dev_info->max_vmdq_pools = ETH_16_POOLS;
	dev_info->flow_type_rss_offloads = DPAA_RSS_OFFLOAD_ALL;
	dev_info->rx_offload_capa =
		(DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM  |
		DEV_RX_OFFLOAD_TCP_CKSUM);
	dev_info->tx_offload_capa =
		(DEV_TX_OFFLOAD_IPV4_CKSUM  |
		DEV_TX_OFFLOAD_UDP_CKSUM   |
		DEV_TX_OFFLOAD_TCP_CKSUM);
}

static int dpaa_eth_link_update(struct rte_eth_dev *dev,
				int wait_to_complete __rte_unused)
{
	struct dpaa_if *iface =  &dpaa_ifacs[dev->data->port_id];
	struct rte_eth_link *link = &dev->data->dev_link;

	if (iface->fif->mac_type == fman_mac_1g)
		link->link_speed = 1000;
	else if (iface->fif->mac_type == fman_mac_10g)
		link->link_speed = 10000;
	else
		PMD_DRV_LOG(ERROR, "%s:: invalid link_speed %d",
			    iface->name, iface->fif->mac_type);

	link->link_status = iface->valid;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;
	return 0;
}

static void dpaa_eth_stats_get(struct rte_eth_dev *dev,
			       struct rte_eth_stats *stats)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	fman_if_stats_get(iface->fif, stats);
}

static void dpaa_eth_stats_reset(struct rte_eth_dev *dev)
{
	/*TBD:XXX: to be implemented*/
	return;
}

static void dpaa_eth_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	fman_if_promiscuous_enable(iface->fif);
}

static void dpaa_eth_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	fman_if_promiscuous_disable(iface->fif);
}

int dpaa_eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_rxconf *rx_conf __rte_unused,
		struct rte_mempool *mp)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	if (!iface->bp_info || iface->bp_info->mp != mp) {
		struct fman_if_ic_params icp;
		uint32_t fd_offset;

		if (!mp->pool_data) {
			PMD_DRV_LOG(ERROR, "not an offloaded buffer pool");
			return -1;
		}
		iface->bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);

		memset(&icp, 0, sizeof(icp));
		/* set ICEOF for to the default value , which is 0*/
		icp.iciof = DEFAULT_ICIOF;
		icp.iceof = DEFAULT_RX_ICEOF;
		icp.icsz = DEFAULT_ICSZ;
		fman_if_set_ic_params(iface->fif, &icp);

		fd_offset = RTE_PKTMBUF_HEADROOM + DPAA_HW_BUF_RESERVE;
		fman_if_set_fdoff(iface->fif, fd_offset);
		fman_if_set_bp(iface->fif, mp->size,
			       iface->bp_info->bpid, mp->elt_size);
		iface->valid = 1;
		PMD_DRV_LOG(INFO, "if =%s - fd_offset = %d offset = %d",
			    iface->name, fd_offset,
			fman_if_get_fdoff(iface->fif));
	}
	dev->data->rx_queues[queue_idx] = &iface->rx_queues[queue_idx];

	return 0;
}

void dpaa_eth_rx_queue_release(void *rxq)
{
	PMD_DRV_LOG(INFO, "%p Rx queue release", rxq);
	return;
}

int dpaa_eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa_if *iface = &dpaa_ifacs[dev->data->port_id];

	dev->data->tx_queues[queue_idx] = &iface->tx_queues[queue_idx];
	return 0;
}

void dpaa_eth_tx_queue_release(void *txq)
{
	PMD_DRV_LOG(INFO, "%p Tx queue release", txq);
	return;
}

int dpaa_mtu_set(struct rte_eth_dev *dev __rte_unused,
		 uint16_t mtu __rte_unused)
{
	/* Currently we don't need to set anything specefic
	 * in hardware for MTU (to be checked again). So just return zero in
	 * order to make sure that setting mtu from Applicaiton doesn't return
	 * any error
	 */
	return 0;
}

int dpaa_link_down(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_stop(dev);
	return 0;
}

int dpaa_link_up(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_start(dev);
	return 0;
}

static int
dpaa_flow_ctrl_set(struct rte_eth_dev *dev,
		   struct rte_eth_fc_conf *fc_conf)
{
	struct rte_eth_fc_conf *net_fc;
	if (!(dpaa_ifacs[dev->data->port_id].fc_conf)) {
		dpaa_ifacs[dev->data->port_id].fc_conf = rte_zmalloc(NULL,
			sizeof(struct rte_eth_fc_conf), MAX_CACHELINE);
		if (!dpaa_ifacs[dev->data->port_id].fc_conf) {
			printf("%s::unable to save flow control info\n",
								__func__);
			return -ENOMEM;
		}
	}
	net_fc = dpaa_ifacs[dev->data->port_id].fc_conf;
	net_fc->pause_time = fc_conf->pause_time;
	net_fc->high_water = fc_conf->high_water;
	net_fc->low_water = fc_conf->low_water;
	net_fc->send_xon = fc_conf->send_xon;
	net_fc->mac_ctrl_frame_fwd = fc_conf->mac_ctrl_frame_fwd;
	net_fc->mode = fc_conf->mode;
	net_fc->autoneg = fc_conf->autoneg;

	return dpaa_set_flow_control(dev->data->port_id, fc_conf);
}
static int
dpaa_flow_ctrl_get(struct rte_eth_dev *dev,
		     struct rte_eth_fc_conf *fc_conf)
{
	struct rte_eth_fc_conf *net_fc;
	net_fc = dpaa_ifacs[dev->data->port_id].fc_conf;
	if (net_fc) {
		fc_conf->pause_time = net_fc->pause_time;
		fc_conf->high_water = net_fc->high_water;
		fc_conf->low_water = net_fc->low_water;
		fc_conf->send_xon = net_fc->send_xon;
		fc_conf->mac_ctrl_frame_fwd = net_fc->mac_ctrl_frame_fwd;
		fc_conf->mode = net_fc->mode;
		fc_conf->autoneg = net_fc->autoneg;
	}
	return dpaa_get_flow_control(dev->data->port_id, fc_conf);
}

static struct eth_dev_ops dpaa_devops = {
	.dev_configure		  = dpaa_eth_dev_configure,
	.dev_start		  = dpaa_eth_dev_start,
	.dev_stop		  = dpaa_eth_dev_stop,
	.dev_close		  = dpaa_eth_dev_close,
	.dev_infos_get		  = dpaa_eth_dev_info,
	.dev_supported_ptypes_get = dpaa_supported_ptypes_get,

	.rx_queue_setup		  = dpaa_eth_rx_queue_setup,
	.tx_queue_setup		  = dpaa_eth_tx_queue_setup,
	.rx_queue_release	  = dpaa_eth_rx_queue_release,
	.tx_queue_release	  = dpaa_eth_tx_queue_release,

	.flow_ctrl_get		  = dpaa_flow_ctrl_get,
	.flow_ctrl_set		  = dpaa_flow_ctrl_set,

	.link_update		  = dpaa_eth_link_update,
	.stats_get		  = dpaa_eth_stats_get,
	.stats_reset		  = dpaa_eth_stats_reset,
	.promiscuous_enable	  = dpaa_eth_promiscuous_enable,
	.promiscuous_disable	  = dpaa_eth_promiscuous_disable,
	.mtu_set		  = dpaa_mtu_set,
	.dev_set_link_down	  = dpaa_link_down,
	.dev_set_link_up	  = dpaa_link_up,
};

static int dpaa_pci_devinit(struct rte_pci_driver *pci_drv __rte_unused,
			    struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *ethdev;
	char devname[MAX_ETHDEV_NAME];
	char *mac_addr;

	PMD_DRV_LOG(DEBUG, "%s::drv %p, dev %p\n", __func__, pci_drv, pci_dev);

	/* alloc ethdev entry */
	sprintf(devname, "%s%d\n", ETHDEV_NAME_PREFIX, pci_dev->addr.devid);
	ethdev = rte_eth_dev_allocate(devname, RTE_ETH_DEV_VIRTUAL);
	if (!ethdev) {
		PMD_DRV_LOG(ERROR, "unable to allocate ethdev");
		return -1;
	}

	PMD_DRV_LOG(DEBUG, "allocated eth device port id %d",
		    ethdev->data->port_id);

	ethdev->dev_ops = &dpaa_devops;
	ethdev->pci_dev = pci_dev;

	/* assign rx and tx ops */
	ethdev->rx_pkt_burst = dpaa_eth_queue_rx;
	ethdev->tx_pkt_burst = dpaa_eth_tx_drop_all;

	mac_addr = DPAA_IF_MAC_ADDR(ethdev->data->port_id);
	ethdev->data->mac_addrs = (struct ether_addr *)mac_addr;

	return 0;
}
