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
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>

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
#include <rte_malloc.h>
#include <rte_ring.h>

#include "dpaa_ethdev.h"
#include "dpaa_rxtx.h"

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>

static struct usdpaa_netcfg_info *dpaa_netcfg;
RTE_DEFINE_PER_LCORE(bool, _dpaa_io);
struct pool_info_entry dpaa_pool_table[DPAA_MAX_BPOOLS];

/* define a variable to hold the portal_key, once created.*/
static pthread_key_t dpaa_portal_key;

static int dpaa_mbuf_create_pool(struct rte_mempool *mp)
{
	struct bman_pool *bp;
	struct bm_buffer bufs[8];
	uint8_t bpid;
	int num_bufs = 0, ret = 0;
	struct bman_pool_params params = {
		.flags = BMAN_POOL_FLAG_DYNAMIC_BPID
	};

	PMD_INIT_FUNC_TRACE();

	bp = bman_new_pool(&params);
	if (!bp) {
		PMD_DRV_LOG(ERR, "bman_new_pool() failed");
		return -ENODEV;
	}
	bpid = bman_get_params(bp)->bpid;

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
		PMD_DRV_LOG(WARNING, "drained %u bufs from BPID %d",
			    num_bufs, bpid);
	else {
		PMD_DRV_LOG(ERR, "No buffers drained from BPID %d", bpid);
		return -ENOMEM;
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

	PMD_DRV_LOG(INFO, "BMAN pool created for bpid =%d", bpid);
	return 0;
}

static
void dpaa_mbuf_free_pool(struct rte_mempool *mp)
{
	struct pool_info_entry *bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);

	PMD_INIT_FUNC_TRACE();

	bman_free_pool(bp_info->bp);
	PMD_DRV_LOG(INFO, "BMAN pool freed for bpid =%d", bp_info->bpid);
	return;
}

static
int dpaa_mbuf_free_bulk(struct rte_mempool *pool,
		void *const *obj_table,
		unsigned n)
{
	struct pool_info_entry *bp_info = DPAA_MEMPOOL_TO_POOL_INFO(pool);
	int ret;
	unsigned i = 0;

	PMD_TX_FREE_LOG(DEBUG, " Request to free %d buffers in bpid = %d",
		    n, bp_info->bpid);

	if (!RTE_PER_LCORE(_dpaa_io)) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpaa_portal_init failed "
				"with ret: %d", ret);
			return 0;
		}
	}

	while (i < n) {
		dpaa_buf_free(bp_info,
			      (uint64_t)rte_mempool_virt2phy(pool, obj_table[i])
				+ bp_info->meta_data_size);
		i = i + 1;
	}

	PMD_TX_FREE_LOG(DEBUG, " freed %d buffers in bpid =%d",
		    n, bp_info->bpid);

	return 0;
}

static
int dpaa_mbuf_alloc_bulk(struct rte_mempool *pool,
		void **obj_table,
		unsigned count)
{
	struct rte_mbuf **m = (struct rte_mbuf **)obj_table;
	struct bm_buffer bufs[DPAA_MBUF_MAX_ACQ_REL];
	struct pool_info_entry *bp_info;
	void *bufaddr;
	int i, ret;
	unsigned n = 0;

	bp_info = DPAA_MEMPOOL_TO_POOL_INFO(pool);

	PMD_RX_LOG(DEBUG, " Request to alloc %d buffers in bpid = %d",
		    count, bp_info->bpid);

	if (unlikely(count >= (RTE_MEMPOOL_CACHE_MAX_SIZE * 2))) {
		PMD_DRV_LOG(ERR, "Unable to allocate requested (%u) buffers",
			    count);
		return -1;
	}

	if (!RTE_PER_LCORE(_dpaa_io)) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpaa_portal_init failed with "
				"ret: %d", ret);
			return 0;
		}
	}

	while (n < count) {
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then the remainder.
		 */
		if ((count - n) > DPAA_MBUF_MAX_ACQ_REL) {
			ret = bman_acquire(bp_info->bp, bufs,
				DPAA_MBUF_MAX_ACQ_REL, 0);
		} else {
			ret = bman_acquire(bp_info->bp, bufs, count - n, 0);
		}
		/* In case of less than requested number of buffers available
		 * in pool, qbman_swp_acquire returns 0
		 */
		if (ret <= 0) {
			PMD_DRV_LOG(ERR, "Buffer acquire failed with"
				    "err code: %d", ret);
			/* The API expect the exact number of requested buffers */
			/* Releasing all buffers allocated */
			dpaa_mbuf_free_bulk(pool, obj_table, n);
			return -1;
		}
		/* assigning mbuf from the acquired objects */
		for (i = 0; (i < ret) && bufs[i].addr; i++) {
			/* TODO-errata - objerved that bufs may be null
			i.e. first buffer is valid, remaining 6 buffers may be null */
			bufaddr = (void *)dpaa_mem_ptov(bufs[i].addr);
			m[n] = (struct rte_mbuf *)((char *)bufaddr
						- bp_info->meta_data_size);
			rte_mbuf_refcnt_set(m[n], 0);
			PMD_DRV_LOG2(DEBUG, "Acquired %p address %p from BMAN",
				    (void *)bufaddr, (void *)m[n]);
			n++;
		}
	}

	PMD_RX_LOG(DEBUG, " allocated %d buffers from bpid =%d",
		    n, bp_info->bpid);
	return 0;
}

static
unsigned int dpaa_mbuf_get_count(const struct rte_mempool *mp __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	/*TBD:XXX: to be implemented*/
	return 0;
}

static
int dpaa_mbuf_supported(const struct rte_mempool *mp __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	/*if dpaa init fails, means no dpaa pool will be avaialbe */
	if (!dpaa_netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA mempool resources not available");
		return -1;
	}

	return 0;
}

struct rte_mempool_ops dpaa_mpool_ops = {
	.name = "dpaa",
	.alloc = dpaa_mbuf_create_pool,
	.free = dpaa_mbuf_free_pool,
	.enqueue = dpaa_mbuf_free_bulk,
	.dequeue = dpaa_mbuf_alloc_bulk,
	.get_count = dpaa_mbuf_get_count,
	.supported = dpaa_mbuf_supported,
};

MEMPOOL_REGISTER_OPS(dpaa_mpool_ops);

static void dpaa_portal_finish(void* arg)
{
	struct dpaa_portal *dpaa_io_portal = (struct dpaa_portal *)arg;

	PMD_DRV_LOG(DEBUG, "cleanup! I am %p", (void *)syscall(SYS_gettid));

	if (dpaa_io_portal == NULL) {
		PMD_DRV_LOG(ERR, "thread is not having the key");
		return;
	}
	bman_thread_finish();
	qman_thread_finish();

	RTE_PER_LCORE(_dpaa_io) = false;

	/*Free the thread memory */
	free(dpaa_io_portal);
	pthread_setspecific(dpaa_portal_key, NULL);

	return;
}

static int dpaa_init(void)
{
	int dev_id, ret;

	PMD_INIT_FUNC_TRACE();

	/* Load the device-tree driver */
	ret = of_init();
	if (ret) {
		PMD_DRV_LOG(ERR, "of_init failed with ret: %d", ret);
		return -1;
	}

	/* Get the interface configurations from device-tree */
	dpaa_netcfg = usdpaa_netcfg_acquire();
	if (!dpaa_netcfg) {
		PMD_DRV_LOG(ERR, "usdpaa_netcfg_acquire failed");
		return -1;
	}
	if (!dpaa_netcfg->num_ethports) {
		PMD_DRV_LOG(ERR, "no network interfaces available");
		return -1;
	}

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	dump_usdpaa_netcfg(dpaa_netcfg);
#endif

	for (dev_id = 0; dev_id < dpaa_netcfg->num_ethports; dev_id++) {
		struct rte_pci_device *dev;

		dev = malloc(sizeof(struct rte_pci_device));
		if (dev == NULL) {
			return -1;
		}
		memset(dev, 0, sizeof(*dev));
		/* store device id of fman device */
		dev->addr.devid = dev_id;
		dev->id.vendor_id = FSL_VENDOR_ID;
		dev->id.device_id = FSL_DEVICE_ID;
		dev->addr.function = dev->id.device_id;

		TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
	}

	/* create the key, supplying a function that'll be invoked
	 *     when a portal affined thread will be deleted.*/
	ret = pthread_key_create(&dpaa_portal_key, dpaa_portal_finish);
	if (ret) {
		PMD_DRV_LOG(ERR, "pthread_key_create failed with ret: %d", ret);
	}

	/* Load the Qman/Bman drivers */
	ret = qman_global_init();
	if (ret) {
		PMD_DRV_LOG(ERR, "qman_global_init failed with ret: %d", ret);
		return -1;
	}
	ret = bman_global_init();
	if (ret) {
		PMD_DRV_LOG(ERR, "bman_global_init failed with ret: %d", ret);
		return -1;
	}

	return 0;
}

int dpaa_portal_init(void *arg)
{
	cpu_set_t cpuset;
	pthread_t id;
	uint32_t cpu = rte_lcore_id();
	int ret;
	struct dpaa_portal *dpaa_io_portal;

	PMD_INIT_FUNC_TRACE();

	if (RTE_PER_LCORE(_dpaa_io))
		return 0;

	PMD_DRV_LOG(DEBUG, "Init! I am %p", (void *)syscall(SYS_gettid));

	if ((uint64_t)arg == 1 || cpu == LCORE_ID_ANY)
		cpu = rte_get_master_lcore();
	/* if the core id is not supported */
	else if (cpu >= RTE_MAX_LCORE)
		return -1;

	/* Set CPU affinity for this thread */
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	id = pthread_self();
	ret = pthread_setaffinity_np(id, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		PMD_DRV_LOG(ERR, "pthread_setaffinity_np failed on "
			"core :%d with ret: %d", cpu, ret);
		return -1;
	}

	/* Initialise bman thread portals */
	ret = bman_thread_init();
	if (ret) {
		PMD_DRV_LOG(ERR, "bman_thread_init failed on "
			"core %d with ret: %d", cpu, ret);
		return -1;
	}
	/* Initialise qman thread portals */
	ret = qman_thread_init();
	if (ret) {
		PMD_DRV_LOG(ERR, "bman_thread_init failed on "
			"core %d with ret: %d", cpu, ret);
		return -1;
	}

	dpaa_io_portal = malloc(sizeof(struct dpaa_portal));

	dpaa_io_portal->qman_idx = qman_get_portal_config()->index;
	dpaa_io_portal->bman_idx = bman_get_portal_config()->index;
	dpaa_io_portal->tid = syscall(SYS_gettid);

	ret = pthread_setspecific(dpaa_portal_key, (void*)dpaa_io_portal);
	if (ret) {
		PMD_DRV_LOG(ERR, "pthread_setspecific failed on "
			"core %d with ret: %d", cpu, ret);
	}
	RTE_PER_LCORE(_dpaa_io) = true;

	return 0;
}

int dpaa_pre_rte_eal_init(void)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = dpaa_init();
	if (ret)
		return -1;

	ret = dpaa_portal_init((void *)1);
	if (ret) {
		printf("dpaa portal init failed\n");
		return -1;
	}

	return 0;
}

static int dpaa_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	if (mtu < ETHER_MIN_MTU)
		return -EINVAL;

	fman_if_set_maxfrm(dpaa_intf->fif, mtu);

	if (mtu > ETHER_MAX_LEN)
		dev->data->dev_conf.rxmode.jumbo_frame = 1;
	else
		dev->data->dev_conf.rxmode.jumbo_frame = 0;

	dev->data->dev_conf.rxmode.max_rx_pkt_len = mtu;
	return 0;
}

static int
dpaa_eth_dev_configure(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	if (dev->data->dev_conf.rxmode.jumbo_frame == 1) {
		if (dev->data->dev_conf.rxmode.max_rx_pkt_len <= DPAA_MAX_RX_PKT_LEN)
			return dpaa_mtu_set(dev,
				dev->data->dev_conf.rxmode.max_rx_pkt_len);
		else
			return -1;
	}
	return 0;
}

static const uint32_t *
dpaa_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP
	};

	PMD_INIT_FUNC_TRACE();

	if (dev->rx_pkt_burst == dpaa_eth_queue_rx)
		return ptypes;
	return NULL;
}

static int dpaa_eth_dev_start(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	/* Change tx callback to the real one */
	dev->tx_pkt_burst = dpaa_eth_queue_tx;

	fman_if_enable_rx(dpaa_intf->fif);
	return 0;
}

static void dpaa_eth_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_disable_rx(dpaa_intf->fif);
	dev->tx_pkt_burst = dpaa_eth_tx_drop_all;
}

static void dpaa_eth_dev_close(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dpaa_eth_dev_stop(dev);
}

static void dpaa_eth_dev_info(struct rte_eth_dev *dev,
			      struct rte_eth_dev_info *dev_info)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	dev_info->max_rx_queues = dpaa_intf->nb_rx_queues;
	dev_info->max_tx_queues = dpaa_intf->nb_tx_queues;
	dev_info->min_rx_bufsize = DPAA_MIN_RX_BUF_SIZE;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = DPAA_MAX_MAC_FILTER;
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
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_link *link = &dev->data->dev_link;

	PMD_INIT_FUNC_TRACE();

	if (dpaa_intf->fif->mac_type == fman_mac_1g)
		link->link_speed = 1000;
	else if (dpaa_intf->fif->mac_type == fman_mac_10g)
		link->link_speed = 10000;
	else
		PMD_DRV_LOG(ERR, "invalid link_speed %d",
			    dpaa_intf->name, dpaa_intf->fif->mac_type);

	link->link_status = dpaa_intf->valid;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;
	return 0;
}

static void dpaa_eth_stats_get(struct rte_eth_dev *dev,
			       struct rte_eth_stats *stats)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_stats_get(dpaa_intf->fif, stats);
}

static void dpaa_eth_stats_reset(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_stats_reset(dpaa_intf->fif);
}

static void dpaa_eth_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_promiscuous_enable(dpaa_intf->fif);
}

static void dpaa_eth_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_promiscuous_disable(dpaa_intf->fif);
}

static void dpaa_eth_multicast_enable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_set_mcast_filter_table(dpaa_intf->fif);
}

static void dpaa_eth_multicast_disable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	fman_if_reset_mcast_filter_table(dpaa_intf->fif);

}

static
int dpaa_eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_rxconf *rx_conf __rte_unused,
		struct rte_mempool *mp)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	PMD_DRV_LOG(INFO, "Rx queue setup for queue index: %d", queue_idx);

	if (!dpaa_intf->bp_info || dpaa_intf->bp_info->mp != mp) {
		struct fman_if_ic_params icp;
		uint32_t fd_offset;
		uint32_t bp_size;

		if (!mp->pool_data) {
			PMD_DRV_LOG(ERR, "not an offloaded buffer pool");
			return -1;
		}
		dpaa_intf->bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);

		memset(&icp, 0, sizeof(icp));
		/* set ICEOF for to the default value , which is 0*/
		icp.iciof = DEFAULT_ICIOF;
		icp.iceof = DEFAULT_RX_ICEOF;
		icp.icsz = DEFAULT_ICSZ;
		fman_if_set_ic_params(dpaa_intf->fif, &icp);

		fd_offset = RTE_PKTMBUF_HEADROOM + DPAA_HW_BUF_RESERVE;
		fman_if_set_fdoff(dpaa_intf->fif, fd_offset);

		/* Buffer pool size should be equal to Dataroom Size*/
		bp_size = rte_pktmbuf_data_room_size(mp);
		fman_if_set_bp(dpaa_intf->fif, mp->size,
			       dpaa_intf->bp_info->bpid, bp_size);
		dpaa_intf->valid = 1;
		PMD_DRV_LOG(INFO, "if =%s - fd_offset = %d offset = %d",
			    dpaa_intf->name, fd_offset,
			fman_if_get_fdoff(dpaa_intf->fif));
	}
	dev->data->rx_queues[queue_idx] = &dpaa_intf->rx_queues[queue_idx];

	return 0;
}

static
void dpaa_eth_rx_queue_release(void *rxq __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	return;
}

static
int dpaa_eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	PMD_DRV_LOG(INFO, "Tx queue setup for queue index: %d", queue_idx);
	dev->data->tx_queues[queue_idx] = &dpaa_intf->tx_queues[queue_idx];
	return 0;
}

static void dpaa_eth_tx_queue_release(void *txq __rte_unused)
{
	PMD_INIT_FUNC_TRACE();
	return;
}

static int dpaa_link_down(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dpaa_eth_dev_stop(dev);
	return 0;
}

static int dpaa_link_up(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dpaa_eth_dev_start(dev);
	return 0;
}

static int
dpaa_flow_ctrl_set(struct rte_eth_dev *dev,
		   struct rte_eth_fc_conf *fc_conf)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_fc_conf *net_fc;

	PMD_INIT_FUNC_TRACE();

	if (!(dpaa_intf->fc_conf)) {
		dpaa_intf->fc_conf = rte_zmalloc(NULL,
			sizeof(struct rte_eth_fc_conf), MAX_CACHELINE);
		if (!dpaa_intf->fc_conf) {
			PMD_DRV_LOG(ERR, "unable to save flow control info");
			return -ENOMEM;
		}
	}
	net_fc = dpaa_intf->fc_conf;

	if (fc_conf->high_water < fc_conf->low_water) {
		PMD_DRV_LOG(ERR, "Incorrect Flow Control Configuration");
		return -EINVAL;
	}

	/*TBD:XXX: Implementation for RTE_FC_RX_PAUSE mode*/
	/*TBD:XXX: In case of RTE_FC_NONE disable flow control in h/w. */
	if (fc_conf->mode == RTE_FC_NONE)
		return 0;
	else if (fc_conf->mode == RTE_FC_TX_PAUSE ||
		 fc_conf->mode == RTE_FC_FULL) {
		fman_if_set_fc_threshold(dpaa_intf->fif, fc_conf->high_water,
					 fc_conf->low_water,
				dpaa_intf->bp_info->bpid);
		if (fc_conf->pause_time)
			fman_if_set_fc_quanta(dpaa_intf->fif, fc_conf->pause_time);
	}

	/* Save the information in dpaa device */
	net_fc->pause_time = fc_conf->pause_time;
	net_fc->high_water = fc_conf->high_water;
	net_fc->low_water = fc_conf->low_water;
	net_fc->send_xon = fc_conf->send_xon;
	net_fc->mac_ctrl_frame_fwd = fc_conf->mac_ctrl_frame_fwd;
	net_fc->mode = fc_conf->mode;
	net_fc->autoneg = fc_conf->autoneg;

	return 0;
}

static int
dpaa_flow_ctrl_get(struct rte_eth_dev *dev,
		   struct rte_eth_fc_conf *fc_conf)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_fc_conf *net_fc = dpaa_intf->fc_conf;
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (net_fc) {
		fc_conf->pause_time = net_fc->pause_time;
		fc_conf->high_water = net_fc->high_water;
		fc_conf->low_water = net_fc->low_water;
		fc_conf->send_xon = net_fc->send_xon;
		fc_conf->mac_ctrl_frame_fwd = net_fc->mac_ctrl_frame_fwd;
		fc_conf->mode = net_fc->mode;
		fc_conf->autoneg = net_fc->autoneg;
		return 0;
	}
	ret = fman_if_get_fc_threshold(dpaa_intf->fif);
	if (ret) {
		fc_conf->mode = RTE_FC_TX_PAUSE;
		fc_conf->pause_time = fman_if_get_fc_quanta(dpaa_intf->fif);
	} else
		fc_conf->mode = RTE_FC_NONE;

	return 0;
}

static void
dpaa_dev_add_mac_addr(struct rte_eth_dev *dev,
			     struct ether_addr *addr,
			     uint32_t index,
			     __rte_unused uint32_t pool)
{
	int ret;
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	ret = fm_mac_add_exact_match_mac_addr(dpaa_intf->fif,
					      addr->addr_bytes, index);

	if (ret)
		RTE_LOG(ERR, PMD, "error: Adding the MAC ADDR failed:"
			" err = %d", ret);
}

static void
dpaa_dev_remove_mac_addr(struct rte_eth_dev *dev,
			  uint32_t index)
{
	int ret;
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	ret = fm_mac_rem_exact_match_mac_addr(dpaa_intf->fif, index);

	if (ret)
		RTE_LOG(ERR, PMD, "error: Removing the MAC ADDR failed:"
			" err = %d", ret);
}

static void
dpaa_dev_set_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr)
{
	int ret;
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	ret = fm_mac_add_exact_match_mac_addr(dpaa_intf->fif,
					      addr->addr_bytes, 0);
	if (ret)
		RTE_LOG(ERR, PMD, "error: Setting the MAC ADDR failed %d", ret);
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
	.allmulticast_enable	  = dpaa_eth_multicast_enable,
	.allmulticast_disable	  = dpaa_eth_multicast_disable,
	.mtu_set		  = dpaa_mtu_set,
	.dev_set_link_down	  = dpaa_link_down,
	.dev_set_link_up	  = dpaa_link_up,
	.mac_addr_add		  = dpaa_dev_add_mac_addr,
	.mac_addr_remove	  = dpaa_dev_remove_mac_addr,
	.mac_addr_set		  = dpaa_dev_set_mac_addr,

};

static int dpaa_fc_set_default(struct dpaa_if *dpaa_intf)
{
	struct rte_eth_fc_conf *fc_conf;
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (!(dpaa_intf->fc_conf)) {
		dpaa_intf->fc_conf = rte_zmalloc(NULL,
			sizeof(struct rte_eth_fc_conf), MAX_CACHELINE);
		if (!dpaa_intf->fc_conf) {
			PMD_DRV_LOG(ERR, "unable to save flow control info");
			return -ENOMEM;
		}
	}
	fc_conf = dpaa_intf->fc_conf;
	ret = fman_if_get_fc_threshold(dpaa_intf->fif);
	if (ret) {
		fc_conf->mode = RTE_FC_TX_PAUSE;
		fc_conf->pause_time = fman_if_get_fc_quanta(dpaa_intf->fif);
	} else {
		fc_conf->mode = RTE_FC_NONE;
	}

	return 0;
 }

/* Initialise an Rx FQ */
static int dpaa_rx_queue_init(struct qman_fq *fq,
			      uint32_t fqid)
{
	struct qm_mcc_initfq opts;
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = qman_reserve_fqid(fqid);
	if (ret) {
		PMD_DRV_LOG(ERR, "reserve rx fqid %d failed with ret: %d",
			fqid, ret);
		return -EINVAL;
	}
	PMD_DRV_LOG(DEBUG, "creating rx fq %p, fqid %d", fq, fqid);
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	if (ret) {
		PMD_DRV_LOG(ERR, "create rx fqid %d failed with ret: %d",
			fqid, ret);
		return ret;
	}

	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_TDTHRESH;

	opts.fqd.dest.wq = DPAA_IF_RX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			   QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_TDE;
	opts.fqd.context_a.stashing.exclusive = 0;
	opts.fqd.context_a.stashing.annotation_cl = DPAA_IF_RX_ANNOTATION_STASH;
	opts.fqd.context_a.stashing.data_cl = DPAA_IF_RX_DATA_STASH;
	opts.fqd.context_a.stashing.context_cl = DPAA_IF_RX_CONTEXT_STASH;

	qm_fqd_taildrop_set(&opts.fqd.td, CONG_THRESHOLD_RX_Q, 1);

	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		PMD_DRV_LOG(ERR, "init rx fqid %d failed with ret: %d",
			fqid, ret);
	return ret;
}

/* Initialise a Tx FQ */
static int dpaa_tx_queue_init(struct qman_fq *fq,
			      struct fman_if *fman_intf)
{
	struct qm_mcc_initfq opts;
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
			     QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	if (ret) {
		PMD_DRV_LOG(ERR, "create tx fq failed with ret: %d", ret);
		return ret;
	}
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = fman_intf->tx_channel_id;
	opts.fqd.dest.wq = DPAA_IF_TX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	/* no tx-confirmation */
	opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
	opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	PMD_DRV_LOG(DEBUG, "init tx fq %p, fqid %d", fq, fq->fqid);
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (ret)
		PMD_DRV_LOG(ERR, "init tx fqid %d failed %d", fq->fqid, ret);
	return ret;
}

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
/* Initialise a DEBUG FQ ([rt]x_error, rx_default). */
static int dpaa_debug_queue_init(struct qman_fq *fq, uint32_t fqid)
{
	struct qm_mcc_initfq opts;
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = qman_reserve_fqid(fqid);
	if (ret) {
		PMD_DRV_LOG(ERR, "reserve debug fqid %d failed with ret: %d",
			fqid, ret);
		return -EINVAL;
	}
	/* "map" this Rx FQ to one of the interfaces Tx FQID */
	PMD_DRV_LOG(DEBUG, "creating debug fq %p, fqid %d", fq, fqid);
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	if (ret) {
		PMD_DRV_LOG(ERR, "create debug fqid %d failed with ret: %d",
			fqid, ret);
		return ret;
	}
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.wq = DPAA_IF_DEBUG_PRIORITY;
	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		PMD_DRV_LOG(ERR, "init debug fqid %d failed with ret: %d",
			fqid, ret);
	return ret;
}
#endif

/* Initialise a network interface */
static int dpaa_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct dpaa_if *dpaa_intf = eth_dev->data->dev_private;
	int dev_id = eth_dev->pci_dev->addr.devid;
	struct fm_eth_port_cfg *cfg = &dpaa_netcfg->port_cfg[dev_id];
	struct fman_if *fman_intf = cfg->fman_if;
	struct fman_if_bpool *bp, *tmp_bp;
	int num_cores, num_rx_fqs, fqid;
	int loop, ret = 0;

	PMD_INIT_FUNC_TRACE();

	/* give the interface a name */
	sprintf(dpaa_intf->name, "fm%d-gb%d",
		(fman_intf->fman_idx + 1), fman_intf->mac_idx);

	/* save fman_if & cfg in the interface struture */
	dpaa_intf->fif = fman_intf;
	dpaa_intf->ifid = dev_id;
	dpaa_intf->cfg = cfg;

	/* Initialize Rx FQ's */
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
		if (ret)
			return ret;
		dpaa_intf->rx_queues[loop].dpaa_intf = dpaa_intf;
	}
	dpaa_intf->nb_rx_queues = num_rx_fqs;

	/* Initialise Tx FQs. Have as many Tx FQ's as number of cores */
	num_cores = rte_lcore_count();
	dpaa_intf->tx_queues = rte_zmalloc(NULL, sizeof(struct qman_fq) *
		num_cores, MAX_CACHELINE);
	if (!dpaa_intf->tx_queues)
		return -ENOMEM;

	for (loop = 0; loop < num_cores; loop++) {
		ret = dpaa_tx_queue_init(&dpaa_intf->tx_queues[loop], fman_intf);
		if (ret)
			return ret;
		dpaa_intf->tx_queues[loop].dpaa_intf = dpaa_intf;
	}
	dpaa_intf->nb_tx_queues = num_cores;

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	dpaa_debug_queue_init(&dpaa_intf->debug_queues[
		DPAA_DEBUG_FQ_RX_ERROR], fman_intf->fqid_rx_err);
	dpaa_intf->debug_queues[DPAA_DEBUG_FQ_RX_ERROR].dpaa_intf = dpaa_intf;
	dpaa_debug_queue_init(&dpaa_intf->debug_queues[
		DPAA_DEBUG_FQ_TX_ERROR], fman_intf->fqid_tx_err);
	dpaa_intf->debug_queues[DPAA_DEBUG_FQ_TX_ERROR].dpaa_intf = dpaa_intf;
#endif

	PMD_DRV_LOG(DEBUG, "all fqs created");

	/* Get the initial configuration for flow control */
	dpaa_fc_set_default(dpaa_intf);

	/* reset bpool list, initialize bpool dynamically */
	list_for_each_entry_safe(bp, tmp_bp, &cfg->fman_if->bpool_list, node) {
		list_del(&bp->node);
		free(bp);
	}

	/* Populate ethdev structure */
	eth_dev->dev_ops = &dpaa_devops;
	eth_dev->data->nb_rx_queues = dpaa_intf->nb_rx_queues;
	eth_dev->data->nb_tx_queues = dpaa_intf->nb_tx_queues;
	eth_dev->rx_pkt_burst = dpaa_eth_queue_rx;
	eth_dev->tx_pkt_burst = dpaa_eth_tx_drop_all;

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
		ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes needed to "
						"store MAC addresses",
				ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER);
		return -ENOMEM;
	}

	/* copy the primary mac address */
	memcpy(eth_dev->data->mac_addrs[0].addr_bytes,
		fman_intf->mac_addr.addr_bytes,
		ETHER_ADDR_LEN);

	printf("interface %s macaddr::", dpaa_intf->name);
	for (loop = 0; loop < ETHER_ADDR_LEN; loop++) {
		if (loop != (ETHER_ADDR_LEN - 1))
			printf("%02x:", fman_intf->mac_addr.addr_bytes[loop]);
		else
			printf("%02x\n", fman_intf->mac_addr.addr_bytes[loop]);
	}

	/* Disable RX mode */
	fman_if_discard_rx_errors(fman_intf);
	fman_if_disable_rx(fman_intf);
	/* Disable promiscous mode */
	fman_if_promiscuous_disable(fman_intf);
	/* Disable multicast */
	fman_if_reset_mcast_filter_table(fman_intf);
	/* Reset interface statistics */
	fman_if_stats_reset(fman_intf);

	return 0;
}

static struct rte_pci_id pci_id_dpaa_map[] = {
	{FSL_CLASS_ID, FSL_VENDOR_ID, FSL_DEVICE_ID,
		FSL_SUBSYSTEM_VENDOR, FSL_SUBSYSTEM_DEVICE},
	{0, 0, 0, 0, 0}
};

static struct eth_driver rte_dpaa_pmd = {
	{
		.name = "rte_dpaa_pmd",
		.id_table = pci_id_dpaa_map,
	},
	.eth_dev_init = dpaa_eth_dev_init,
	.dev_private_size = sizeof(struct dpaa_if),
};

static int
rte_dpaa_pmd_init(
		const char *name __rte_unused,
		const char *params __rte_unused)
{
	RTE_LOG(INFO, PMD, "rte_dpaa_pmd_init() called for %s\n", name);
	rte_eth_driver_register(&rte_dpaa_pmd);

	return 0;
}

static struct rte_driver rte_dpaa_driver = {
	.name = "rte_dpaa_driver",
	.type = PMD_PDEV,
	.init = rte_dpaa_pmd_init,
};

PMD_REGISTER_DRIVER(rte_dpaa_driver, dpaa);
