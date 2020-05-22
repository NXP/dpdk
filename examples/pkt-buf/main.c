/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_flow.h>
#include <rte_pmd_dpaa2.h>

#define DPAA_PMD_RECORD_CORE_CYCLES
static volatile bool force_quit;


#define RTE_LOGTYPE_PKT RTE_LOGTYPE_USER1

#define PKTS_NB_MBUF   8192

#define PKTS_MAX_PKT_BURST 32
int max_burst_size = PKTS_MAX_PKT_BURST;
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define PKTS_MEMPOOL_CACHE_SIZE 512

/*Cache based buffer pool */
static int g_cache_size = PKTS_MEMPOOL_CACHE_SIZE;
static int g_delayed_free = PKTS_MEMPOOL_CACHE_SIZE/2;

uint16_t tx_pkt_length = 1500; /**< TXONLY packet length. */
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr pkt_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t pkt_enabled_port_mask;

/* list of enabled ports */
static uint32_t pkt_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int pkt_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned int n_rx_port;
	unsigned int rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *pkt_pktmbuf_pool;

/* Per-port statistics struct */
struct pkt_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct pkt_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((pkt_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

#define IP_SRC_ADDR ((192U << 24) | (168 << 16) | (0 << 8) | 1)
#define IP_DST_ADDR ((192U << 24) | (168 << 16) | (0 << 8) | 2)

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

static struct ipv4_hdr pkt_ip_hdr;  /**< IP header of transmitted packets. */
static struct udp_hdr pkt_udp_hdr; /**< UDP header of transmitted packets. */
static struct ether_hdr pkt_eth_hdr[RTE_MAX_ETHPORTS]; /**< Ethernet header for transmitted packets */
/* ethernet addresses of ports */
static struct ether_addr dest_eth_addr[RTE_MAX_ETHPORTS];

static inline void
copy_buf_to_pkt(void* buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			buf, (size_t) len);
		return;
	}
}

static void
setup_port_eth_header(int port_id, struct ether_hdr *eth_hdr)
{

	/* Initialize Ethernet header. */
	ether_addr_copy(&dest_eth_addr[port_id],&eth_hdr->d_addr);
	eth_hdr->d_addr.addr_bytes[0] = port_id + 20;
	ether_addr_copy(&pkt_ports_eth_addr[port_id], &eth_hdr->s_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
}

static void
setup_pkt_udp_ip_headers(
		struct ipv4_hdr *ip_hdr,
		struct udp_hdr *udp_hdr,
		uint16_t pkt_data_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	/*
	 * Initialize UDP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(1024);
	udp_hdr->dst_port = rte_cpu_to_be_16(1024);
	udp_hdr->dgram_len      = rte_cpu_to_be_16(pkt_len);
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_len + sizeof(struct ipv4_hdr));
	ip_hdr->version_ihl   = IP_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(IP_SRC_ADDR);
	ip_hdr->dst_addr = rte_cpu_to_be_32(IP_DST_ADDR);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (unaligned_uint16_t*) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

static void
tx_only_prepare(void)
{
	uint16_t pkt_data_len;

	pkt_data_len = (uint16_t) (tx_pkt_length - (sizeof(struct ether_hdr) +
						    sizeof(struct ipv4_hdr) +
						    sizeof(struct udp_hdr)));
	setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);
}

#define HOLD_MAX_BUF 512
struct buf_bkp {
	struct rte_mbuf *buf[HOLD_MAX_BUF];
	uint16_t count;
	uint16_t toggle;
};
__thread struct buf_bkp held_mbufs;

static inline void
__hold_mbuf(struct rte_mbuf *_mbuf)
{
	int i;

	held_mbufs.buf[held_mbufs.count++] = _mbuf;
	if (held_mbufs.count > g_delayed_free - 1) {
		held_mbufs.count = 0;
		held_mbufs.toggle = 1;
		for (i = 0; i < g_delayed_free / 2; i++) {
			rte_pktmbuf_free(held_mbufs.buf[i]);
			held_mbufs.buf[i] = NULL;
		}
	}
	if (held_mbufs.count > ((g_delayed_free / 2) - 1) &&
			held_mbufs.toggle == 1) {
		held_mbufs.toggle = 0;
		for (i = g_delayed_free / 2; i < g_delayed_free; i++) {
			rte_pktmbuf_free(held_mbufs.buf[i]);
			held_mbufs.buf[i] = NULL;
		}
	}
}

/*
 * Transmit a burst of multi-segments packets.
 */
static void
pkt_create_n_send(int port_id)
{
	struct rte_mbuf *pkts_burst[PKTS_MAX_PKT_BURST];

	struct rte_mbuf *pkt;
	uint16_t nb_pkt, nb_tx;
	int ret;
#ifdef DPAA_PMD_RECORD_CORE_CYCLES
	static uint64_t core_cycles[64][2];
	static int count;
	int i;
	uint64_t start_tsc;
	uint64_t alloc_tsc;
	uint64_t end_tsc;

	start_tsc = rte_rdtsc();
#endif
	ret = rte_pktmbuf_alloc_bulk(pkt_pktmbuf_pool, pkts_burst,
			     PKTS_MAX_PKT_BURST);
	
	if (ret)
		rte_exit(EXIT_FAILURE,
			"Cannot get mbuf element in %s\n", __func__);

#ifdef DPAA_PMD_RECORD_CORE_CYCLES
	alloc_tsc = rte_rdtsc();
#endif

	for (nb_pkt = 0; nb_pkt < PKTS_MAX_PKT_BURST; nb_pkt++) {
		pkt = pkts_burst[nb_pkt];
		/*
		 * Using raw alloc is good to improve performance,
		 * but some consumers may use the headroom and so
		 * decrement data_off. We need to make sure it is
		 * reset to default value.
		 */
		rte_pktmbuf_reset_headroom(pkt);
		pkt->data_len = tx_pkt_length;
		pkt->pkt_len = pkt->data_len;
		copy_buf_to_pkt(&pkt_eth_hdr[port_id],
				sizeof(struct ether_hdr), pkt, 0);
		copy_buf_to_pkt(&pkt_ip_hdr, sizeof(pkt_ip_hdr), pkt,
		       sizeof(struct ether_hdr));
		copy_buf_to_pkt(&pkt_udp_hdr, sizeof(pkt_udp_hdr), pkt,
		       sizeof(struct ether_hdr) +
		       sizeof(struct ipv4_hdr));

		/*
		 * Complete first mbuf of packet and append it to the
		 * burst of packets to be transmitted.
		 */
		pkt->nb_segs = 0;
		pkt->pkt_len = pkt->data_len;
		pkt->ol_flags = 0;
		pkt->l2_len = sizeof(struct ether_hdr);
		pkt->l3_len = sizeof(struct ipv4_hdr);
		if (g_delayed_free)
			__hold_mbuf(pkt);
	}
	nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, nb_pkt);

	if (unlikely(nb_tx < nb_pkt)) {
		printf("port %d tx_queue %d - drop "
			       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
			       port_id, 0,
			       (unsigned) nb_pkt, (unsigned) nb_tx,
			       (unsigned) (nb_pkt - nb_tx));
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

#ifdef DPAA_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles[count][0] = (alloc_tsc - start_tsc);
	core_cycles[count][1] = (end_tsc - alloc_tsc);	
	count++;
	if (count == 64) {
		uint64_t alloc_avg = 0;
		uint64_t trans_avg = 0;	
		uint64_t alloc_max = 0;
		uint64_t trans_max = 0;	

		for (i = 0; i < count; i++) {
			printf ("Port-%d, %d-Alloc Cycles = %lu, Tx Cycles = %lu\n",
				port_id, i,
				core_cycles[i][0],
				core_cycles[i][1]);
			alloc_avg += core_cycles[i][0];
			if (alloc_max < core_cycles[i][0])
				alloc_max = core_cycles[i][0];
			trans_avg += core_cycles[i][1];
			if (trans_max < core_cycles[i][1])
				trans_max = core_cycles[i][1];
		}
		
		printf("####Profile Clock @ %lu Hz Alloc Avg = %lu (Max %lu)"
			" Trans Avg = %lu (Max %lu)\n",
			rte_get_tsc_hz(),
			alloc_avg/64, alloc_max,
			trans_avg/64, trans_max);
		count = 0;
	}
#endif
}

/* main processing loop */
static void
pkt_main_loop(void)
{
	int sent;
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned int i, portid;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc =
			(rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, PKT, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, PKT, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, PKT, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = pkt_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid,
								0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];
			pkt_create_n_send(portid);
		}
	}
}

static int
pkt_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	pkt_main_loop();
	return 0;
}

/* display usage */
static void
pkt_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
	       "  -b NUM: burst size for receive packet (default is 32)\n"
	       "  -S NUM: Cache Size (default is 512)\n"
	       "  -D NUM: delayed mbuf free. Size shall be less than Cache Size\n",
	       prgname);
}

static int
pkt_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
pkt_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
pkt_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	"b:"  /* burst size */
	"D:"  /* Delayed free size by app */
	"S:"  /* Cache Size */
	;


enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
pkt_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, burst_size, cache_size, hold_size;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			pkt_enabled_port_mask = pkt_parse_portmask(optarg);
			if (pkt_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				pkt_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			pkt_rx_queue_per_lcore = pkt_parse_nqueue(optarg);
			if (pkt_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				pkt_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = pkt_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				pkt_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size < 0 || burst_size > max_burst_size) {
				printf("invalid burst size\n");
				pkt_usage(prgname);
				return -1;
			}
			max_burst_size = burst_size;
			break;
		/*mempool_cache_size */
		case 'S':
			cache_size = (unsigned int)atoi(optarg);
			if (cache_size < 0 || cache_size > (PKTS_NB_MBUF/2)) {
				printf("invalid burst size\n");
				pkt_usage(prgname);
				return -1;
			}
			g_cache_size= cache_size;
			break;
		/*Delayed TX Free */
		case 'D':
			hold_size = (unsigned int)atoi(optarg);
			if (hold_size < 0 || hold_size > g_cache_size) {
				printf("invalid hold size\n");
				pkt_usage(prgname);
				return -1;
			}
			g_delayed_free = hold_size;
			break;

		/* long options */
		case 0:
			break;

		default:
			pkt_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = pkt_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid PKT arguments\n");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* create the mbuf pool */
	pkt_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", PKTS_NB_MBUF,
		g_cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (pkt_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (pkt_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* reset pkt_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		pkt_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((pkt_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			pkt_dst_ports[portid] = last_port;
			pkt_dst_ports[last_port] = portid;
		} else
			last_port = portid;

		nb_ports_in_mask++;
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		pkt_dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((pkt_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       pkt_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}


	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((pkt_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d,"
				 " port=%u\n", ret, portid);

		rte_eth_macaddr_get(portid, &pkt_ports_eth_addr[portid]);

		setup_port_eth_header(portid,&pkt_eth_hdr[portid]);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     pkt_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);

		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(PKTS_MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], PKTS_MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done:\n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				pkt_ports_eth_addr[portid].addr_bytes[0],
				pkt_ports_eth_addr[portid].addr_bytes[1],
				pkt_ports_eth_addr[portid].addr_bytes[2],
				pkt_ports_eth_addr[portid].addr_bytes[3],
				pkt_ports_eth_addr[portid].addr_bytes[4],
				pkt_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));

		/* set delayed free for each port */
		if (g_delayed_free)
			rte_pmd_dpaax_set_delayed_txfree(portid, 1);
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(pkt_enabled_port_mask);

	tx_only_prepare();

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(pkt_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((pkt_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
