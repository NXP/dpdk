/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 NXP
 */


/* This application will use external memory to create a mempool
 * which will be used to send 1000 packets to the first available port
 * to demonstrate the usage of external memory.
 *
 * Usage:
 * #Attach port0 of the board to a packet capturing device (e.g. Spirent)
 * #run the application as:
 * #./pkt_gen_ext_mem 0x2360000000 16777216
 *
 * Both arguments are optional.
 * First argument is start address of scratch memory
 * Second argument is memory size, should be multiple of 2MB
 *
 * If no scratch memory is given then memory will be
 * anonymous and default size is 16MB.
 *
 * Application only support 2MB page sizes so all the
 * memory will be divided into 2MB size pages internally.
 *
 * Application supports scratch memory of modem 0 only.
 *
 * Scratch memory start address and size can be obtained
 * from the yami.ko module load command.
 *
 * On start, application will first display number of buffers
 * available in pool, then it will transmit 1000 packets
 * on port0 and in the end it it will show available
 * buffers in pool and sent count.
 */

#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PAGE_SIZE       (sysconf(_SC_PAGESIZE))
#define PAGE_MASK       (~(PAGE_SIZE - 1))

//worker thread methods
struct rte_mempool *l2fwd_pktmbuf_pool;
const uint16_t BurstSize = 1;
const uint16_t DPDK_PORT_ID;
const uint16_t APP_POOL_SIZE = 4096;

uint64_t maddr, mlen;

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

int open_port(uint16_t port_id, uint64_t iaddr, uint64_t size, int fd)
{
	int rez = 0;
	size_t len = size;
	size_t pgsz = RTE_PGSIZE_2M;
	void *addr;
	int n_pages, i;
	const char *heap_name = "heap";
	int socket_id;
	int k = 0;

	n_pages = size / pgsz;
	rte_iova_t iova[n_pages];

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

	iova[0] = iaddr;
	off_t mask = PAGE_MASK;
	off_t newoff = iova[0] & mask;
	/* reserving 2MB extra to align the mapped virtual address with page size.
	 * Assuming extra 2MB space is available.
	 * user can pass page size aligned virtual address to mmap to avoid
	 * extra 2MB memory reserve.*/
	mlen = len + RTE_PGSIZE_2M;
	if (fd != -1) {
		addr = mmap(NULL, mlen, PROT_WRITE | PROT_READ,
				 MAP_SHARED, fd, newoff);
		if (addr == MAP_FAILED) {
			printf("%s():%i: Failed to create memory area\n",
				__func__, __LINE__);
			return -3;
		}
		close(fd);
	} else {
		addr = mmap(NULL, mlen, PROT_WRITE | PROT_READ,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, newoff);
		if (addr == MAP_FAILED) {
			printf("%s():%i: Failed to create memory area\n",
				__func__, __LINE__);
			return -3;
		}
	}


	maddr = (uint64_t)addr;
	addr = (void *)RTE_ALIGN_CEIL((uint64_t)addr, RTE_PGSIZE_2M);
	if (rte_is_aligned(addr, RTE_PGSIZE_2M) != 1) {
		printf("Mapped addr %p is not aligined to 2MB\n", addr);
		return -4;
	}

	/* Updating iova addr as per the alignment */
	iaddr += (uint64_t)addr - maddr;
	while (k < n_pages) {
		iova[k] = iaddr + (k * RTE_PGSIZE_2M);
		k++;
	}

	if (rte_malloc_heap_create(heap_name) != 0) {
		printf("%s():%i: Failed to create malloc heap\n",
				__func__, __LINE__);
		return -4;
	}

	/* get socket ID corresponding to this heap */
	socket_id = rte_malloc_heap_get_socket(heap_name);
	if (socket_id < 0) {
		printf("%s():%i: cannot find socket for external heap\n",
			__func__, __LINE__);
		return -4;
	}

	if (rte_eal_iova_mode() == RTE_IOVA_VA) {
		for (i = 0; i < n_pages; i++)
			iova[i] = (uint64_t)addr + pgsz * i;
	}

	if (rte_malloc_heap_memory_add(heap_name, addr, len,
				iova, n_pages, pgsz) != 0) {
		printf("%s():%i: Failed to add memory to heap\n",
				__func__, __LINE__);
		return -4;
        }

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 2048,
				512, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
				socket_id);
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

int main(int argc, char *argv[])
{
	uint64_t iaddr, size;
	int fd = -1;
	int ret;
	printf("Begin\n");

	// Prepare EAL arguments
	char *_argv[] = {argv[0], (char *)"-l", (char *)"0-2",
		(char *)"--log-level", (char *)"8"};
	int _argc = sizeof(_argv) / (sizeof(_argv[0]));
	uint64_t sent_pkts = 0;

	if (argc == 2) {
		iaddr = strtol(argv[1], NULL, 16);
		size = RTE_PGSIZE_16M;
		/* Assuming Modem 0 only */
		fd = open("/dev/gul0", O_RDWR|O_SYNC);
		if (fd == -1) {
			printf("Error in opening /dev/mem\n");
			return -1;
		}
		printf("***** Configured addr =%lx and size = %ld *****\n",
			iaddr, size);
	} else if (argc == 3) {
		iaddr = strtol(argv[1], NULL, 16);
		/* Assuming supported page size is given */
		size = atoi(argv[2]);
		/* Assuming Modem 0 only */
		fd = open("/dev/gul0", O_RDWR|O_SYNC);
		if (fd == -1) {
			printf("Error in opening /dev/mem\n");
			return -1;
		}
		printf("***** Configured addr =%lx and size = %ld *****\n",
			iaddr, size);
	}else {
		/* Dummy Physica address for anonymous mapping */
		iaddr = 0x2360000000;
		size = RTE_PGSIZE_16M;
		printf("**** Anonymous mapping of 16MB size *****\n");
	}

	// Init DPDK EAL
	if (rte_eal_init(_argc, (char **)_argv) < 0) {
		printf("DPDK init failed\n");
		return -1;
	}

	// Open RX port
	ret = open_port((uint16_t)DPDK_PORT_ID, iaddr, size, fd);
	if (ret != 0) {
		printf("TX ethernet device (destination) open error\n");
		if (ret < -3)
			munmap((void *)maddr, mlen);

		return -1;
	}

	printf("DPDK TX Ethernet device (destination) opened successfully\n");
	printf("in start pool count = %d\n",
			rte_mempool_avail_count(l2fwd_pktmbuf_pool));

	for (uint32_t i = 0; i < 1000; ++i) {
		struct rte_mbuf *m;
		uint16_t buf_len = 128;

		m = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);
		if (m == NULL) {
			printf("mbuf failed\n");
			return -1;
		}
		set_mbuf_data(m, OutFrame, sizeof(OutFrame));
		/*XXX:  instead of above calc, use rte_pktmbuf_chain here */
		ret = rte_eth_tx_burst(DPDK_PORT_ID, 0, &m, 1);
		sent_pkts += ret;
	}
	printf("Packets sent. Count=%d \n", sent_pkts);
	rte_delay_ms(3000);
	printf("end pool count = %d\n",
			rte_mempool_avail_count(l2fwd_pktmbuf_pool));

	munmap((void *)maddr, mlen);
	return 0;
}

