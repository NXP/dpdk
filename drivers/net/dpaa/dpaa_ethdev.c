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
__thread bool thread_portal_init;

/* Static BPID index allocator, increments continuously */
rte_atomic32_t bpid_alloc = RTE_ATOMIC64_INIT(0);
struct pool_info_entry dpaa_pool_table[NUM_BP_POOL_ENTRIES];

static struct bman_pool *dpaa_bpid_init(int bpid)
{
	struct bm_buffer bufs[8];
	struct bman_pool *bp = NULL;
	int num_bufs = 0, ret = 0;

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

int hw_mbuf_create_pool(struct rte_mempool *mp)
{
	struct bman_pool *bp;
	uint32_t bpid;

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
	mp->hw_pool_priv = (void *)&dpaa_pool_table[bpid];

	/* TODO: Replace with mp->pool_data->flags after creating appropriate
	 * pool_data structure
	 */
	mp->flags |= MEMPOOL_F_HW_PKT_POOL;

	PMD_DRV_LOG(INFO, "BP List created for bpid =%d\n", bpid);
	return 0;
}

/* hw generated buffer layout:
 *
 *   [struct rte_mbuf][priv_size][HW_ANNOTATION][FD_OFFSET][HEADROOM][DATA]
 */
int hw_mbuf_init(struct rte_mempool *mp, void *_m)
{
	int ret;
	struct pool_info_entry *bp_info;
	struct rte_mbuf *m = _m;
	uint32_t buf_len, head_room;
	struct bm_buffer bufs;

	if (!dpaa_netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA buffer pool not configured\n");
		return -1;
	}

	memset(m, 0, mp->elt_size);
	bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);

	head_room = RTE_PKTMBUF_HEADROOM + DPAA_HW_BUF_RESERVE;

	buf_len = head_room + rte_pktmbuf_data_room_size(mp);

	m->buf_addr = (char *)_m + bp_info->meta_data_size;
	m->buf_physaddr = rte_mempool_virt2phy(mp, m) + bp_info->meta_data_size;

	PMD_DRV_LOG2(INFO, "released buffer : Physical address = %p\t"
		"Virtual Address = %p into pool %p\n",
		m->buf_physaddr, m->buf_addr, mp);

	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = rte_pktmbuf_priv_size(mp);
	m->buf_len = buf_len;

	m->packet_type |= RTE_PTYPE_L3_IPV4;
	m->data_len = rte_pktmbuf_data_room_size(mp);
	m->pkt_len = rte_pktmbuf_data_room_size(mp);
	m->data_off = head_room;

	m->pool = mp;
	m->nb_segs = 1;
	m->port = 0xff;

	PMD_DRV_LOG2(INFO, "init:Phy = %p Virt = %p, mbuf = %p,"
		"buf_addr = %p pool %p\n", buf, _m, m, m->buf_addr, mp);
	bm_buffer_set64(&bufs, m->buf_physaddr);
	do {
		ret = bman_release(bp_info->bp, &bufs, 1, 0);
	} while (ret == -EBUSY);

	return 0;
}

int hw_mbuf_alloc_bulk(struct rte_mempool *pool,
		       void **obj_table,
		unsigned count)
{
	struct rte_mbuf **m = (struct rte_mbuf **)obj_table;
	struct bm_buffer bufs[RTE_MEMPOOL_CACHE_MAX_SIZE + 1];
	struct pool_info_entry *bp_info;
	void *bufaddr;
	int ret;
	unsigned i = 0, n = 0;

	bp_info = DPAA_MEMPOOL_TO_POOL_INFO(pool);

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
			PMD_DRV_LOG(WARNING, "Fail to allocate buffers %d", ret);
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
		rte_mbuf_refcnt_set(m[i], 0);
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

int hw_mbuf_free_bulk(struct rte_mempool *pool,
		      void *const *obj_table,
		unsigned n)
{
	struct pool_info_entry *bp_info;
	int ret;
	unsigned i = 0;

	if (!thread_portal_init) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERROR, "Failure in affining portal");
			return 0;
		}
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


static int dpaa_init(void)
{
	int dev_id, ret;

	/* Load the device-tree driver */
	ret = of_init();
	if (ret) {
		printf("of_init Failed %d\n", ret);
		return -1;
	}

	/* Get the interface configurations from device-tree */
	dpaa_netcfg = usdpaa_netcfg_acquire();
	if (!dpaa_netcfg) {
		fprintf(stderr, "Fail: usdpaa_netcfg_acquire\n");
		return -1;
	}
	if (!dpaa_netcfg->num_ethports) {
		fprintf(stderr, "Fail: no network interfaces available\n");
		return -1;
	}

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%d ethports available\n", dpaa_netcfg->num_ethports);
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

	return 0;
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
		PMD_DRV_LOG(ERROR, "pthread_setaffinity_np failed on core :%d",
				cpu);
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

int dpaa_pre_rte_eal_init(void)
{
	int ret;

	ret = dpaa_init();
	if (ret) {
		printf("Cannot init dpaa\n");
		return -1;
	}

	ret = dpaa_portal_init((void *)1);
	if (ret) {
		printf("dpaa portal init failed\n");
		return -1;
	}

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
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	/* Change tx callback to the real one */
	dev->tx_pkt_burst = dpaa_eth_queue_tx;

	fman_if_enable_rx(dpaa_intf->fif);
	return 0;
}

static void dpaa_eth_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	fman_if_disable_rx(dpaa_intf->fif);
	dev->tx_pkt_burst = dpaa_eth_tx_drop_all;
}

static void dpaa_eth_dev_close(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_stop(dev);
}

static void dpaa_eth_dev_info(struct rte_eth_dev *dev,
			      struct rte_eth_dev_info *dev_info)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	dev_info->max_rx_queues = dpaa_intf->nb_rx_queues;
	dev_info->max_tx_queues = dpaa_intf->nb_tx_queues;
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
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_link *link = &dev->data->dev_link;

	if (dpaa_intf->fif->mac_type == fman_mac_1g)
		link->link_speed = 1000;
	else if (dpaa_intf->fif->mac_type == fman_mac_10g)
		link->link_speed = 10000;
	else
		PMD_DRV_LOG(ERROR, "%s:: invalid link_speed %d",
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

	fman_if_stats_get(dpaa_intf->fif, stats);
}

static void dpaa_eth_stats_reset(struct rte_eth_dev *dev __rte_unused)
{
	/*TBD:XXX: to be implemented*/
	return;
}

static void dpaa_eth_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	fman_if_promiscuous_enable(dpaa_intf->fif);
}

static void dpaa_eth_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	fman_if_promiscuous_disable(dpaa_intf->fif);
}

static
int dpaa_eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_rxconf *rx_conf __rte_unused,
		struct rte_mempool *mp)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	if (!dpaa_intf->bp_info || dpaa_intf->bp_info->mp != mp) {
		struct fman_if_ic_params icp;
		uint32_t fd_offset;

		if (!mp->hw_pool_priv) {
			PMD_DRV_LOG(ERROR, "not an offloaded buffer pool");
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
		fman_if_set_bp(dpaa_intf->fif, mp->size,
			       dpaa_intf->bp_info->bpid, mp->elt_size);
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
	PMD_DRV_LOG(INFO, "%p Rx queue release", rxq);
	return;
}

static
int dpaa_eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    uint16_t nb_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	dev->data->tx_queues[queue_idx] = &dpaa_intf->tx_queues[queue_idx];
	return 0;
}

static void dpaa_eth_tx_queue_release(void *txq __rte_unused)
{
	PMD_DRV_LOG(INFO, "%p Tx queue release", txq);
	return;
}

static int dpaa_mtu_set(struct rte_eth_dev *dev __rte_unused,
		 uint16_t mtu __rte_unused)
{
	/* Currently we don't need to set anything specefic
	 * in hardware for MTU (to be checked again). So just return zero in
	 * order to make sure that setting mtu from Application doesn't return
	 * any error
	 */
	return 0;
}

static int dpaa_link_down(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_stop(dev);
	return 0;
}

static int dpaa_link_up(struct rte_eth_dev *dev)
{
	dpaa_eth_dev_start(dev);
	return 0;
}

static int
dpaa_flow_ctrl_set(struct rte_eth_dev *dev,
		   struct rte_eth_fc_conf *fc_conf)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_fc_conf *net_fc = dpaa_intf->fc_conf;

	if (fc_conf->high_water < fc_conf->low_water) {
		printf("\nERR - %s Incorrect Flow Control Configuration\n",
		       __func__);
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
			fman_if_set_fc_quanta(dpaa_intf->fif,
				fc_conf->pause_time);
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

static int dpaa_fc_set_default(struct dpaa_if *dpaa_intf)
{
	struct rte_eth_fc_conf *fc_conf = dpaa_intf->fc_conf;
	int ret;

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

	PMD_DRV_LOG(DEBUG, "fqid %x, wq %d", fqid,
		    DPAA_IF_RX_PRIORITY);

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
			      struct fman_if *fman_intf)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
			     QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = fman_intf->tx_channel_id;
	opts.fqd.dest.wq = DPAA_IF_TX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	/* no tx-confirmation */
	opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
	opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	PMD_DRV_LOG(DEBUG, "init fqid %d for fman_intf fm%d-gb%d chan %d\n",
		    	fq->fqid, (fman_intf->fman_idx + 1),
			fman_intf->mac_idx, fman_intf->tx_channel_id);
	return qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}

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

	/* give the interface a name */
	sprintf(dpaa_intf->name, "fm%d-gb%d",
		(fman_intf->fman_idx + 1), fman_intf->mac_idx);
	/* get the mac address */
	memcpy(dpaa_intf->mac_addr, fman_intf->mac_addr.addr_bytes,
	       ETHER_ADDR_LEN);
	printf("%s::interface %s macaddr::", __func__, dpaa_intf->name);
	for (loop = 0; loop < ETHER_ADDR_LEN; loop++) {
		if (loop != (ETHER_ADDR_LEN - 1))
			printf("%02x:", dpaa_intf->mac_addr[loop]);
		else
			printf("%02x\n", dpaa_intf->mac_addr[loop]);
	}

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
		if (ret) {
			printf("%s::dpaa_rx_queue_init failed for %x\n",
			       __func__, fqid);
			return ret;
		}
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
		PMD_DRV_LOG(DEBUG, "%s::tx_fqid %x",
			    __func__, dpaa_intf->tx_queues[loop].fqid);
		dpaa_intf->tx_queues[loop].dpaa_intf = dpaa_intf;
	}
	dpaa_intf->nb_tx_queues = num_cores;
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
	eth_dev->data->mac_addrs = (struct ether_addr *)dpaa_intf->mac_addr;

	/* Disable RX, disable promiscuous mode */
	fman_if_disable_rx(fman_intf);
	fman_if_promiscuous_disable(fman_intf);
	fman_if_discard_rx_errors(fman_intf);

	return 0;
}

static struct rte_pci_id pci_id_dpaa_map[] = {
	{FSL_VENDOR_ID, FSL_DEVICE_ID,
		FSL_SUBSYSTEM_VENDOR, FSL_SUBSYSTEM_DEVICE},
	{0, 0, 0, 0}
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

PMD_REGISTER_DRIVER(rte_dpaa_driver);
