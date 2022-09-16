/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 NXP
 */


/* This application will create two mbufs using rte_mempool_alloc API
 * and in 2nd mbuf, it will attach an external buffer
 * (allocated using rte_malloc). First mbuf's next pointer is pointed
 * to 2nd mbuf.
 *
 * Usage:
 * #Attach port0 of the board to a packet capturing device (e.g. Spirent)
 * #run the application as:
 * #./pkt_gen_ext
 *
 * On start, application will first display number of buffers
 * available in pool, then it will transmit 100000 SG packets
 * on port0 and in the end it it will show available
 * buffers in pool and sent count.
 */

#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <stdio.h>

//worker thread methods
struct rte_mempool *l2fwd_pktmbuf_pool;
const uint16_t BurstSize = 1;
const uint16_t DPDK_PORT_ID;
const uint16_t APP_POOL_SIZE = 4096;

const unsigned char OutFrame[] = {
		 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
		 0x0B, 0x0C, 0xAE, 0xFE, 0x0F, 0x10};

void set_mbuf_data(struct rte_mbuf *mbuf, const unsigned char *data,
		   const unsigned int data_len)
{
	mbuf->data_len = data_len; //Amount of data in segment buffer
	rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, char*, 0), data,
			(size_t)data_len);
	mbuf->nb_segs = 1;
	mbuf->pkt_len = data_len; // sum of all segments
	mbuf->next = NULL;
}

int open_port(uint16_t port_id)
{
	int rez = 0;

	if (port_id >= rte_eth_dev_count_avail()) {
		printf("Devices:%d\n", rte_eth_dev_count_avail());
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -1;
	}

	struct rte_eth_conf port_conf = {};

	port_conf.rxmode.max_rx_pkt_len = 1500;
	port_conf.link_speeds = ETH_LINK_SPEED_10G;
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

	port_conf.rx_adv_conf.rss_conf.rss_hf = 0; // ETH_RSS_IPV4;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;

	// Configure the Ethernet device.
	rez = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (rez != 0) {
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -2;
	}

	uint16_t hw_rx_queue_size = 1024;
	uint16_t hw_tx_queue_size = 1024;

	rez = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &hw_rx_queue_size,
						&hw_tx_queue_size);
	if (rez != 0) {
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -3;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 8192,
				512, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
				0);
		if (l2fwd_pktmbuf_pool == NULL)
			printf("Cannot init mbuf pool\n");
	} else {
		l2fwd_pktmbuf_pool = rte_mempool_lookup("mbuf_pool");
	}

	if (!l2fwd_pktmbuf_pool) {
		printf("%s:%d: m_mbuf <%p> rte_errno <%d>\n", __func__,
				__LINE__, l2fwd_pktmbuf_pool, rte_errno);
		return -4;
	}

	// Allocate and set up RX queue
	rez = rte_eth_rx_queue_setup(port_id, 0, 1024,
			rte_eth_dev_socket_id(port_id), NULL,
			l2fwd_pktmbuf_pool);
	if (rez < 0) {
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -5;
	}

	// Allocate and set up 1 TX queue per Ethernet port_id.
	rez = rte_eth_tx_queue_setup(port_id, 0, 1024,
			rte_eth_dev_socket_id(port_id), NULL);
	if (rez < 0) {
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -6;
	}

	rte_eth_stats_reset(port_id);

	// Start the Ethernet port_id.
	rez = rte_eth_dev_start(port_id);
	if (rez < 0) {
		printf("%s:%d: E_FAIL\n", __func__, __LINE__);
		return -7;
	}

	// Enable RX in promiscuous mode for the Ethernet device
	rte_eth_promiscuous_enable(port_id);

	return 0;
}

uint32_t callb;
static void
ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque)
{
	void *ext_buf_addr = opaque;

	if (ext_buf_addr == NULL) {
		printf("External buffer address is invalid\n");
		return;
	}
	callb++;
	rte_free(ext_buf_addr);
	ext_buf_addr = NULL;
}

int main(int argc, char *argv[])
{
	printf("Begin\n");

	// Prepare EAL arguments
	char *_argv[] = {argv[0], (char *)"-l", (char *)"0-2",
		(char *)"--log-level", (char *)"8"};
	int _argc = sizeof(_argv) / (sizeof(_argv[0]));
	uint64_t sent_pkts = 0;

	// Init DPDK EAL
	if (rte_eal_init(_argc, (char **)_argv) < 0) {
		printf("DPDK init failed\n");
		return -1;
	}

	// Open RX port
	if (open_port((uint16_t)DPDK_PORT_ID) != 0) {
		printf("TX ethernet device (destination) open error\n");
		return -1;
	}

	printf("DPDK TX Ethernet device (destination) opened successfully\n");
	printf("in start pool count = %d\n",
			rte_mempool_avail_count(l2fwd_pktmbuf_pool));

	for (uint32_t i = 0; i < 100000; ++i) {
		int ret;
		struct rte_mbuf *m, *hdr = NULL;
		void *ext_buf_addr = NULL;
		uint16_t buf_len = 128;
		struct rte_mbuf_ext_shared_info *ret_shinfo = NULL;
		rte_iova_t buf_iova;

		m = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);
		if (m == NULL)
			printf("mbuf failed\n");
		set_mbuf_data(m, OutFrame, sizeof(OutFrame));
		hdr = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);
		if (hdr == NULL)
			printf("%s: mbuf allocation failed!\n", __func__);
		ext_buf_addr = rte_malloc("External buffer", buf_len,
				RTE_CACHE_LINE_SIZE);
		if (ext_buf_addr == NULL)
			printf("%s: External buffer allocation failed\n",
					__func__);

		ret_shinfo = rte_pktmbuf_ext_shinfo_init_helper(ext_buf_addr,
				&buf_len,
				ext_buf_free_callback_fn, ext_buf_addr);
		if (ret_shinfo == NULL)
			printf("%s: Shared info initialization failed!\n",
					__func__);
		buf_iova = rte_mempool_virt2iova(ext_buf_addr);
		rte_pktmbuf_attach_extbuf(hdr, ext_buf_addr, buf_iova, buf_len,
			ret_shinfo);
		if (hdr->ol_flags != EXT_ATTACHED_MBUF)
			printf("%s: External buffer is not attached to mbuf\n",
				__func__);
		hdr->pkt_len = 100;
		hdr->data_len = 100;
		m->next = hdr;
		m->nb_segs += hdr->nb_segs;
		m->pkt_len = (uint16_t)(hdr->data_len + m->pkt_len);
		/*XXX:  instead of above calc, use rte_pktmbuf_chain here */
		ret = rte_eth_tx_burst(DPDK_PORT_ID, 0, &m, 1);
		sent_pkts += ret;
	}
	printf("Packets sent. Count=%d and callback count = %d\n", sent_pkts,
			callb);
	rte_delay_ms(3000);
	printf("end pool count = %d\n",
			rte_mempool_avail_count(l2fwd_pktmbuf_pool));

	return 0;
}

