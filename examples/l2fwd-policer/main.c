/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
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
#include <rte_string_fns.h>
#include <rte_pmd_dpaa2.h>
#include <rte_mtr.h>

#define POLICER_RFC_NUM           2698
#define SHIFT_RESERVED_PRIORITY    16

/* Traffic classes */
enum {
	POLICER_TC0 = 0,
	POLICER_TC1,
	POLICER_TC2,
	POLICER_TC3,
	POLICER_TC4,
	POLICER_TC5,
	POLICER_TC6,
	POLICER_TC7,
	POLICER_TC_MAX_NUM
};

#define MAX_QUEUE_NUM_PER_TC 128

#define POLICER_CIR_DEFAULT 2000
#define POLICER_CBS_DEFAULT 10240
#define POLICER_PIR_DEFAULT 2000
#define POLICER_PBS_DEFAULT 20480

#define POLICER_COLOR_BLIND 0
#define POLICER_COLOR_AWARE 1

#define POLICER_UNIT_BYTES_L3              0
#define POLICER_UNIT_FRAMES                1
#define POLICER_UNIT_BYTES_L2_WITHOUT_FCS  2

struct l2fwd_policer_tc_flow {
	int valid;
	uint16_t vlan_id;

	uint16_t qidx;
	uint16_t flow_id;
	void *flow;
};

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT	13
#endif

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK	0xfff
#endif
#define MAX_VLAN_ID VLAN_VID_MASK

#define RTE_LOGTYPE_L2FWD_POLICER RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Flow classification enabled by default */
static int enable_flow = 1;

#define PORT_MAX_FLOWS 128

enum {
	POLICER_PROFILE_UPDATE = (1 << 0),
	POLICER_POLICY_UPDATE = (1 << 1)
};

/* port and vlan id pair configuration */
struct l2fwd_policer_port_params {
	int enable;
	/** Share meter to all flows.*/
	uint32_t *meter_id;
	uint32_t *profile_id;
	uint32_t *policy_id;

	struct rte_meter_trtcm_params trtcm;
	struct rte_flow_action red_action;

	uint16_t queue_ids[POLICER_TC_MAX_NUM][MAX_QUEUE_NUM_PER_TC];
	uint16_t flow_ids[POLICER_TC_MAX_NUM][MAX_QUEUE_NUM_PER_TC];
	uint16_t queue_num[POLICER_TC_MAX_NUM];

	struct l2fwd_policer_tc_flow tc_flow[POLICER_TC_MAX_NUM];
};

static struct l2fwd_policer_port_params s_port_param[RTE_MAX_ETHPORTS];

/* policer default configuration */
static int s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
static int s_default_color = RTE_COLOR_GREEN;
static uint32_t s_color_option = POLICER_COLOR_AWARE;
static enum rte_flow_action_type s_red_action = RTE_FLOW_ACTION_TYPE_DROP;
static enum rte_flow_action_type s_red_action_update;

static uint32_t s_cir = POLICER_CIR_DEFAULT;
static uint32_t s_cbs = POLICER_CBS_DEFAULT;
static uint32_t s_pir = POLICER_PIR_DEFAULT;
static uint32_t s_pbs = POLICER_PBS_DEFAULT;

static uint32_t s_cir_update;
static uint32_t s_cbs_update;
static uint32_t s_pir_update;
static uint32_t s_pbs_update;

static uint16_t s_meter_action = RTE_FLOW_ACTION_TYPE_METER_MARK;

static void *sch_handle;

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_policer_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_policer_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_policer_dst_ports[RTE_MAX_ETHPORTS];

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *l2fwd_policer_pktmbuf_pool;

/* Per-port statistics struct */
struct l2fwd_policer_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_policer_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

#define POLICER_UPDATE_CIR "cir "
#define POLICER_UPDATE_CBS "cbs "
#define POLICER_UPDATE_PIR "pir "
#define POLICER_UPDATE_PBS "pbs "
#define POLICER_UPDATE_QUEUE_IDX "queue index update"
#define POLICER_UPDATE_RED_DROP "red drop"
#define POLICER_UPDATE_RED_PASS "red pass"

#define POLICER_UPDATE_FORMAT \
	"Update policer: %s<num> or %s<num> or %s<num> or %s<num>\n"

enum policer_id_type {
	POLICER_METER_ID_TYPE,
	POLICER_PROFILE_ID_TYPE,
	POLICER_POLICY_ID_TYPE,
	POLICER_ID_TYPE_MAX
};
static struct rte_ring *s_id_pool[RTE_MAX_ETHPORTS][POLICER_ID_TYPE_MAX];

#define POLICER_MAX_ID_NUM 64
static uint32_t s_meter_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];
static uint32_t s_profile_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];
static uint32_t s_policy_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];

static inline uint16_t
l2fwd_policer_tc_map_vlan_prio(uint16_t tc)
{
	return tc << VLAN_PRIO_SHIFT;
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
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

	fflush(stdout);
}

/* set the scheduler WQ priority in reserved_64s[0] */
static inline void
set_scheduler_wq_prio(struct rte_eth_rxconf *rx_conf, int priority)
{
	rx_conf->reserved_64s[0] = priority;
	rx_conf->reserved_64s[0] = rx_conf->reserved_64s[0] << SHIFT_RESERVED_PRIORITY;
	rx_conf->reserved_64s[0] |= POLICER_RFC_NUM;
	if (priority > 7)
		rte_exit(EXIT_FAILURE, "Acceptable scheduler WQ priority are 0-7!\n");
}

/* set the initialized scheduler handle in reserved_64s[1] */
static inline void
set_scheduler_handle(struct rte_eth_rxconf *rx_conf, void *sch_handle)
{
	rx_conf->reserved_64s[1] = (uint64_t)sch_handle;
	if (rx_conf->reserved_64s[1] == 0)
		rte_exit(EXIT_FAILURE, "Scheduler handle not set!\n");
}

static void
l2fwd_policer_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->dst_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_policer_ports_eth_addr[dest_portid], &eth->src_addr);
}

/* Simple forward. 8< */
static void
l2fwd_policer_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_policer_dst_ports[portid];

	if (mac_updating)
		l2fwd_policer_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}
/* >8 End of simple forward. */

/* main processing loop */
static void
l2fwd_policer_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	uint16_t lcore_id, i, portid, nb_rx;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD_POLICER,
			"lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD_POLICER,
		"entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD_POLICER,
			" -- lcoreid=%u portid=%u\n", lcore_id, portid);
	}

	while (!force_quit) {

		/* Drains TX queue in its main loop. 8< */
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_policer_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/* >8 End of draining TX queue. */

		/* sleep(5);
		 * can be used for sanity test: high priority packets receive first.
		 *
		 * Read packet from RX queues
		 */
		nb_rx = rte_dpaa2_scheduler_rx(sch_handle,
			pkts_burst, MAX_PKT_BURST);
		if (unlikely(!nb_rx))
			continue;

		for (i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			portid = pkts_burst[i]->port;
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			l2fwd_policer_simple_forward(m, portid);
		}
		port_statistics[portid].rx += nb_rx;
		/* End of read packet from RX queues. */
	}
}

static int
l2fwd_policer_launch_one_lcore(__rte_unused void *dummy)
{
	l2fwd_policer_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_policer_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		"  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
		"      When enabled:\n"
		"       - The source MAC address is replaced by the TX port MAC address\n"
		"       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
		"  --no-enable-flow: Disable vlan flow control (default is enable)\n"
		"  --config:(portid,vlanid,vlan_prio)[,(portid,vlanid,vlan_prio)]\n"
		"      Example: --config='(0,100,3),(1,400,4)'\n"
		"      portid are acceptable which are used in portmask\n"
		"      vlanid in int, acceptable range 0 to 4095\n"
		"      vlan_prio is number of vlan priorities, maximum is 7 i.e.(0 to 7)\n"
		"  --color: configure policer color (color_aware, color_blind)\n"
		"	  Default: color_aware\n"
		"  --policer_unit: configure policer unit (bytes_l2, bytes_l3, frames)\n"
		"      Default: bytes_l2\n"
		"  --default_color: configure policer default color (red, yellow or green)\n"
		"      Default: green\n"
		"  --red_action: configure action of packet marked as red (red drop or red pass)\n"
		"      Default: red drop\n"
		"  -cir NUM in bytes/frames as selected\n"
		"  -cbs NUM bytes/frames as selected\n"
		"  -pir NUM bytes/frames as selected\n"
		"  -pbs NUM bytes/frames as selected\n"
		"  NOTE: In bytes mode, configure L3 rate(kbps) in cir and pir\n"
		"  --meter_action: Configure meter flow action type (meter_mark or meter)\n"
		"      Default: meter_mark, directly get profile and(or) policy to\n"
		"      configure flow action dynamically.",
		prgname);
}

static int
l2fwd_policer_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
l2fwd_policer_parse_port_vlan_config(const char *q_arg)
{
	enum fieldnames {
		FLD_PORT = 0,
		FLD_VLAN_ID,
		FLD_VLAN_PRIO,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	unsigned int size;
	char s[256];
	char *end;
	int i;
	uint16_t portid, vlan_id, vlan_prio;
	struct l2fwd_policer_tc_flow *tc_flow;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -EINVAL;

		size = p0 - p;
		if (size >= sizeof(s))
			return -EINVAL;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld,
			_NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno || end == str_fld[i])
				return -EINVAL;
		}

		portid = (uint16_t)int_fld[FLD_PORT];
		vlan_id = (uint16_t)int_fld[FLD_VLAN_ID];
		vlan_prio = (uint16_t)int_fld[FLD_VLAN_PRIO];
		if (portid >= RTE_MAX_ETHPORTS) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Invalid portid(%d) >= %d\n",
				portid, RTE_MAX_ETHPORTS);
			return -EINVAL;
		}
		if (vlan_id >= MAX_VLAN_ID) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Invalid vlan ID(%d) >= %d\n",
				vlan_id, MAX_VLAN_ID);
			return -EINVAL;
		}
		if (vlan_prio >= POLICER_TC_MAX_NUM) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Invalid vlan priority(%d) >= %d\n",
				vlan_prio, POLICER_TC_MAX_NUM);
			return -EINVAL;
		}
		tc_flow = &s_port_param[portid].tc_flow[vlan_prio];
		if (tc_flow->valid) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"TC[%d] flow(vlan ID=%d) has been configured.\n",
				vlan_prio, tc_flow->vlan_id);
			return -EINVAL;
		}
		tc_flow->valid = true;
		tc_flow->vlan_id = vlan_id;
		s_port_param[portid].enable = true;
	}

	return 0;
}

static int
l2fwd_policer_parse_timer_period(const char *q_arg)
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

static void
l2fwd_policer_parse_color_option(const char *optarg)
{
	if (!strcmp(optarg, "color_aware")) {
		s_color_option = POLICER_COLOR_AWARE;
	} else if (!strcmp(optarg, "color_blind")) {
		s_color_option = POLICER_COLOR_BLIND;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid color policer option: %s\n", optarg);
	}
}

static void
l2fwd_policer_parse_red_action_option(const char *optarg)
{
	if (!strcmp(optarg, POLICER_UPDATE_RED_DROP)) {
		s_red_action_update = RTE_FLOW_ACTION_TYPE_DROP;
	} else if (!strcmp(optarg, POLICER_UPDATE_RED_PASS)) {
		s_red_action_update = RTE_FLOW_ACTION_TYPE_PASSTHRU;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid red action option: %s\n", optarg);
	}
}

static void
l2fwd_policer_parse_rate_unit(const char *optarg)
{
	if (!strcmp(optarg, "frames")) {
		s_policer_unit = POLICER_UNIT_FRAMES;
	} else if (!strcmp(optarg, "bytes_l3")) {
		s_policer_unit = POLICER_UNIT_BYTES_L3;
	} else if (!strcmp(optarg, "bytes_l2")) {
		s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
	} else {
		s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid Policer Unit, default set to L2 Bytes!!\n");
	}
}

static void
l2fwd_policer_parse_default_color(const char *optarg)
{
	if (!strcmp(optarg, "red")) {
		s_default_color = RTE_COLOR_RED;
	} else if (!strcmp(optarg, "yellow")) {
		s_default_color = RTE_COLOR_YELLOW;
	} else if (!strcmp(optarg, "green")) {
		s_default_color = RTE_COLOR_GREEN;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid default color, set to GREEN!\n");
		s_default_color = RTE_COLOR_GREEN;
	}
}

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_ENABLE_FLOW "no-enable-flow"
#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_RATE_UNIT_CONFIG "unit"
#define CMD_LINE_OPT_RATE_COLOR_CONFIG "color"
#define CMD_LINE_OPT_RATE_DEFAULT_COLOR_CONFIG "default_color"
#define CMD_LINE_OPT_RATE_RED_ACTION_CONFIG "red_action"
#define CMD_LINE_OPT_CIR_CONFIG "cir"
#define CMD_LINE_OPT_CBS_CONFIG "cbs"
#define CMD_LINE_OPT_PIR_CONFIG "pir"
#define CMD_LINE_OPT_PBS_CONFIG "pbs"
#define CMD_LINE_OPT_METER_ACTION_CONFIG "meter_action"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
	CMD_LINE_OPT_ENABLE_FLOW_CTL,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_RATE_UNIT,
	CMD_LINE_OPT_RATE_COLOR,
	CMD_LINE_OPT_RATE_DEFAULT_COLOR,
	CMD_LINE_OPT_RATE_RED_ACTION,
	CMD_LINE_OPT_CIR,
	CMD_LINE_OPT_CBS,
	CMD_LINE_OPT_PIR,
	CMD_LINE_OPT_PBS,
	CMD_LINE_OPT_METER_ACTION
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
		CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
	{CMD_LINE_OPT_ENABLE_FLOW, 1, 0, CMD_LINE_OPT_ENABLE_FLOW_CTL},
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_RATE_UNIT_CONFIG, 1, 0, CMD_LINE_OPT_RATE_UNIT},
	{CMD_LINE_OPT_RATE_COLOR_CONFIG, 1, 0, CMD_LINE_OPT_RATE_COLOR},
	{CMD_LINE_OPT_RATE_DEFAULT_COLOR_CONFIG, 1, 0, CMD_LINE_OPT_RATE_DEFAULT_COLOR},
	{CMD_LINE_OPT_RATE_RED_ACTION_CONFIG, 1, 0, CMD_LINE_OPT_RATE_RED_ACTION},
	{CMD_LINE_OPT_CIR_CONFIG, 1, 0, CMD_LINE_OPT_CIR},
	{CMD_LINE_OPT_CBS_CONFIG, 1, 0, CMD_LINE_OPT_CBS},
	{CMD_LINE_OPT_PIR_CONFIG, 1, 0, CMD_LINE_OPT_PIR},
	{CMD_LINE_OPT_PBS_CONFIG, 1, 0, CMD_LINE_OPT_PBS},
	{CMD_LINE_OPT_METER_ACTION_CONFIG, 1, 0, CMD_LINE_OPT_METER_ACTION},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_policer_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, option_index;
	char **argvopt;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
			lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_policer_enabled_port_mask = l2fwd_policer_parse_portmask(optarg);
			if (!l2fwd_policer_enabled_port_mask) {
				RTE_LOG(ERR, L2FWD_POLICER,
					"invalid portmask\n");
				l2fwd_policer_usage(prgname);
				return -EINVAL;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_policer_parse_timer_period(optarg);
			if (timer_secs < 0) {
				RTE_LOG(ERR, L2FWD_POLICER,
					"invalid timer period\n");
				l2fwd_policer_usage(prgname);
				return -EINVAL;
			}
			timer_period = timer_secs;
			break;

		case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
			mac_updating = atoi(optarg);
			break;

		case CMD_LINE_OPT_ENABLE_FLOW_CTL:
			enable_flow = atoi(optarg);
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = l2fwd_policer_parse_port_vlan_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				l2fwd_policer_usage(prgname);
				return ret;
			}
			break;

		case CMD_LINE_OPT_RATE_UNIT:
			l2fwd_policer_parse_rate_unit(optarg);
			break;

		case CMD_LINE_OPT_RATE_COLOR:
			l2fwd_policer_parse_color_option(optarg);
			break;

		case CMD_LINE_OPT_RATE_DEFAULT_COLOR:
			l2fwd_policer_parse_default_color(optarg);
			break;

		case CMD_LINE_OPT_RATE_RED_ACTION:
			l2fwd_policer_parse_red_action_option(optarg);
			break;

		case CMD_LINE_OPT_CIR:
			s_cir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_CBS:
			s_cbs = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PIR:
			s_pir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PBS:
			s_pbs = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_METER_ACTION:
			if (!strcmp(optarg, "meter_mark")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_METER_MARK;
			} else if (!strcmp(optarg, "meter")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_METER;
			} else if (!strcmp(optarg, "pass")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_PASSTHRU;
			} else {
				fprintf(stderr, "Invalid meter action: %s\n",
					optarg);
				l2fwd_policer_usage(prgname);
				return ret;
			}
			break;

		default:
			l2fwd_policer_usage(prgname);
			return -ENOTSUP;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
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
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

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
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					RTE_LOG(ERR, L2FWD_POLICER,
						"Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				RTE_LOG(INFO, L2FWD_POLICER,
					"Port %d %s\n", portid,
					link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
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

static void *
l2fwd_policer_alloc_id(uint16_t port_id, enum policer_id_type type)
{
	char nm[RTE_MEMZONE_NAMESIZE];
	struct rte_ring *r;
	int i, ret;
	void *pid;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"%s: Invalid port id(%d)\n",
			__func__, port_id);
		return NULL;
	}
	if (!s_id_pool[port_id][type]) {
		sprintf(nm, "id_pool_%d_port%d", type, port_id);
		r = rte_ring_create(nm, POLICER_MAX_ID_NUM * 2, 0, 0);
		if (!r) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Create %s failed!\n", nm);
			return NULL;
		}
		for (i = 0; i < POLICER_MAX_ID_NUM; i++) {
			if (type == POLICER_METER_ID_TYPE) {
				s_meter_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_meter_ids[port_id][i]);
			} else if (type == POLICER_PROFILE_ID_TYPE) {
				s_profile_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_profile_ids[port_id][i]);
			} else if (type == POLICER_POLICY_ID_TYPE) {
				s_policy_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_policy_ids[port_id][i]);
			}
		}
		s_id_pool[port_id][type] = r;
	}

	ret = rte_ring_dequeue(s_id_pool[port_id][type], &pid);
	if (!ret)
		return pid;

	return NULL;
}

static void
l2fwd_policer_free_id(int port_id,
	uint32_t *pid, enum policer_id_type type)
{
	struct rte_ring *r = s_id_pool[port_id][type];
	int ret;

	ret = rte_ring_enqueue(r, pid);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Free port%d's ID(type=%d) failed(%d)\n",
			port_id, type, ret);
	}
}

static void
l2fwd_policer_meter_mark_action_config(uint16_t port_id,
	struct l2fwd_policer_port_params *param,
	struct rte_flow_action *action,
	struct rte_flow_action_meter_mark *action_meter_mark)
{
	struct rte_flow_meter_profile *fm_profile = NULL;
	struct rte_flow_meter_policy *fm_policy = NULL;

	if (param->profile_id) {
		fm_profile = rte_mtr_meter_profile_get(port_id,
			*param->profile_id, NULL);
	}
	if (param->policy_id) {
		fm_policy = rte_mtr_meter_policy_get(port_id,
			*param->policy_id, NULL);
	}
	action_meter_mark->profile = fm_profile;
	action_meter_mark->policy = fm_policy;
	action_meter_mark->color_mode = s_color_option;
	action_meter_mark->init_color = s_default_color;
	action_meter_mark->state = 0;
	action->type = RTE_FLOW_ACTION_TYPE_METER_MARK;
	action->conf = action_meter_mark;
}

static void
l2fwd_policer_meter_action_config(uint16_t port_id,
	struct l2fwd_policer_port_params *param,
	struct rte_flow_action *action,
	struct rte_flow_action_meter *action_meter)
{
	if (!param->meter_id) {
		rte_exit(EXIT_FAILURE,
			"Port%d's meter ID not allocated!\n",
			port_id);
	}
	action_meter->mtr_id = *param->meter_id;
	action->type = RTE_FLOW_ACTION_TYPE_METER;
	action->conf = action_meter;
}

/*
 * Creating maximum 8 classification flows based on
 * vlan priorities mapped to 8 TCs respectively.
 */

#define MAX_PATTERN_NUM 4
static void
l2fwd_policer_vlan_flow_config(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	struct rte_flow_item_vlan vlan_item[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_mask[MAX_PATTERN_NUM];
	struct rte_flow_action flow_action[MAX_PATTERN_NUM];
	struct rte_flow_item flow_item[MAX_PATTERN_NUM];
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_attr flow_attr;
	struct rte_flow_error error;
	uint16_t prio, tc, vlan_id;
	int ret;
	struct rte_flow_action_meter_mark action_meter_mark;
	struct rte_flow_action_meter action_meter;
	struct l2fwd_policer_tc_flow *tc_flow;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	memset(flow_item, 0, MAX_PATTERN_NUM * sizeof(struct rte_flow_item));
	memset(flow_action, 0, MAX_PATTERN_NUM * sizeof(struct rte_flow_action));
	memset(&error, 0, sizeof(struct rte_flow_error));
	memset(vlan_item, 0, sizeof(vlan_item));
	memset(vlan_mask, 0, sizeof(vlan_mask));

	for (tc = 0; tc < POLICER_TC_MAX_NUM; tc++) {
		tc_flow = &param->tc_flow[tc];
		if (!tc_flow->valid)
			continue;

		vlan_id = tc_flow->vlan_id;
		flow_attr.ingress = 1;

		/* RXQ0 is in TC0,  RXQ1 is in TC1 and so on*/
		flow_attr.group = tc;
		/* priority is set to 0 because using single queue of TC.*/
		tc_flow->qidx = 0;
		flow_attr.priority = param->flow_ids[tc][tc_flow->qidx];
		dest_queue.index = param->queue_ids[tc][tc_flow->qidx];

		prio = l2fwd_policer_tc_map_vlan_prio(tc);
		vlan_item[0].hdr.vlan_tci = rte_cpu_to_be_16(prio + vlan_id);
		vlan_item[0].hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		vlan_mask[0].hdr.vlan_tci = RTE_BE16(0xffff);

		flow_item[0].spec = &vlan_item[0];
		flow_item[0].mask = &vlan_mask[0];
		flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		flow_action[0].conf = &dest_queue;
		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
			l2fwd_policer_meter_mark_action_config(port_id,
				param, &flow_action[1], &action_meter_mark);
			flow_action[2].type = RTE_FLOW_ACTION_TYPE_END;
		} else if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
			l2fwd_policer_meter_action_config(port_id,
				param, &flow_action[1], &action_meter);
			flow_action[2].type = RTE_FLOW_ACTION_TYPE_END;
		} else {
			flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
		}

		/* validate and create the flow rule */
		ret = rte_flow_validate(port_id, &flow_attr, flow_item,
			flow_action, &error);
		if (ret) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"flow validate failed(%d) on port%d-TC%d\n",
				ret, port_id, tc);
			continue;
		}
		tc_flow->flow = rte_flow_create(port_id,
			&flow_attr, flow_item, flow_action, &error);
		if (!tc_flow->flow) {
			rte_exit(EXIT_FAILURE,
				"Cannot create flow to TC%d/flow%d on port=%d\n",
				tc, param->flow_ids[tc][tc_flow->qidx], port_id);
		}
		RTE_LOG(INFO, L2FWD_POLICER,
			"vLAN(%04x)Flow created on port%d-TC%d-flow%d(rxq%d)\n",
			prio + vlan_id, port_id, tc,
			param->flow_ids[tc][tc_flow->qidx],
			param->queue_ids[tc][tc_flow->qidx]);
	}
}

static void
_l2fwd_policer_flow_action_update(uint16_t port_id,
	struct l2fwd_policer_port_params *param,
	struct l2fwd_policer_tc_flow *tc_flow, uint16_t tc,
	int queue_update)
{
	uint16_t idx = 0, qidx;
	struct rte_flow_action flow_action[MAX_PATTERN_NUM];
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_action_meter action_meter;
	struct rte_flow_action_meter_mark action_meter_mark;
	int ret;

	memset(flow_action, 0, sizeof(flow_action));
	if (queue_update) {
		qidx = tc_flow->qidx;
		qidx++;
		if (qidx >= param->queue_num[tc])
			qidx = 0;
		tc_flow->qidx = qidx;
		tc_flow->flow_id = param->flow_ids[tc][qidx];
		dest_queue.index = param->queue_ids[tc][qidx];
		flow_action[idx].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		flow_action[idx].conf = &dest_queue;
		idx++;
	}
	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
		l2fwd_policer_meter_action_config(port_id,
			param, &flow_action[idx], &action_meter);
		idx++;
	} else if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
		l2fwd_policer_meter_mark_action_config(port_id,
			param, &flow_action[idx], &action_meter_mark);
		idx++;
	}
	flow_action[idx].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_flow_actions_update(port_id, tc_flow->flow,
			flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Update port%d-flow%d action failed(%d)\n",
			port_id, tc_flow->flow_id, ret);
	}
}

static uint32_t *
l2fwd_policer_meter_profile_create(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	uint32_t *new_mp_id;
	struct rte_mtr_meter_profile mp;
	int ret;

	new_mp_id = l2fwd_policer_alloc_id(port_id,
		POLICER_PROFILE_ID_TYPE);
	if (!new_mp_id) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u alloc Profile ID failed\n",
			port_id);
		return NULL;
	}
	mp.alg = RTE_MTR_TRTCM_RFC2698;
	mp.trtcm_rfc2698.cir = param->trtcm.cir;
	mp.trtcm_rfc2698.pir = param->trtcm.pir;
	mp.trtcm_rfc2698.cbs = param->trtcm.cbs;
	mp.trtcm_rfc2698.pbs = param->trtcm.pbs;

	/** packet_mode = 0 is l3 byte mode.
	 * packet_mode = 1 is packet mode.
	 * packet_mode > 1 is l2 byte mode without FCS.
	 */
	mp.packet_mode = s_policer_unit;
	ret = rte_mtr_meter_profile_add(port_id, *new_mp_id,
		&mp, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u create Profile(%d) failed(%d)\n",
			port_id, *new_mp_id, ret);
		l2fwd_policer_free_id(port_id, new_mp_id,
			POLICER_PROFILE_ID_TYPE);
		return NULL;
	}

	return new_mp_id;
}

static uint32_t *
l2fwd_policer_meter_policy_create(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	uint32_t *new_mpol_id;
	struct rte_mtr_meter_policy_params mpol;
	int ret;

	new_mpol_id = l2fwd_policer_alloc_id(port_id,
		POLICER_POLICY_ID_TYPE);
	if (!new_mpol_id) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u alloc Policy ID failed\n",
			port_id);
		return NULL;
	}
	mpol.actions[RTE_COLOR_GREEN] = NULL;
	mpol.actions[RTE_COLOR_YELLOW] = NULL;
	mpol.actions[RTE_COLOR_RED] = &param->red_action;
	ret = rte_mtr_meter_policy_add(port_id, *new_mpol_id,
		&mpol, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u create Policy(%d) failed(%d)\n",
			port_id, *new_mpol_id, ret);
		l2fwd_policer_free_id(port_id, new_mpol_id,
			POLICER_POLICY_ID_TYPE);
		return NULL;
	}

	return new_mpol_id;
}

static void
l2fwd_policer_meter_profile_del(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	int ret;

	if (param->profile_id) {
		ret = rte_mtr_meter_profile_delete(port_id,
			*param->profile_id, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Profile delete failed(%d)\n",
				port_id, ret);
		}
		l2fwd_policer_free_id(port_id, param->profile_id,
			POLICER_PROFILE_ID_TYPE);
		param->profile_id = NULL;
	}
}

static void
l2fwd_policer_meter_policy_del(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	int ret;

	if (param->policy_id) {
		ret = rte_mtr_meter_policy_delete(port_id,
			*param->policy_id, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Policy delete failed(%d)\n",
				port_id, ret);
		}
		l2fwd_policer_free_id(port_id, param->policy_id,
			POLICER_POLICY_ID_TYPE);
		param->policy_id = NULL;
	}
}

static void
l2fwd_policer_meter_update(uint16_t port_id,
	struct l2fwd_policer_port_params *param, uint8_t update)
{
	uint32_t *mpof_id, *mpol_id;
	int ret;

	if (update & POLICER_PROFILE_UPDATE) {
		mpof_id = l2fwd_policer_meter_profile_create(port_id, param);
		if (!mpof_id) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Profile create failed!\n",
				port_id);
		}
		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
			ret = rte_mtr_meter_profile_update(port_id,
				*param->meter_id, *mpof_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Port %u meter Profile update failed(%d)\n",
					port_id, ret);
			}
		}
		l2fwd_policer_meter_profile_del(port_id, param);
		param->profile_id = mpof_id;
	}

	if (update & POLICER_POLICY_UPDATE) {
		mpol_id = l2fwd_policer_meter_policy_create(port_id, param);
		if (!mpol_id) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Policy create failed!\n",
				port_id);
		}
		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
			ret = rte_mtr_meter_policy_update(port_id,
				*param->meter_id, *mpol_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Port %u meter Policy update failed(%d)\n",
					port_id, ret);
			}
		}
		l2fwd_policer_meter_policy_del(port_id, param);
		param->policy_id = mpol_id;
	}
}

static void
l2fwd_policer_meter_init(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	struct rte_mtr_params mp;
	int ret;

	param->trtcm.cir = s_cir;
	param->trtcm.pir = s_pir;
	param->trtcm.cbs = s_cbs;
	param->trtcm.pbs = s_pbs;
	param->red_action.type = s_red_action;
	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
		l2fwd_policer_meter_update(port_id, param,
			POLICER_PROFILE_UPDATE | POLICER_POLICY_UPDATE);
		return;
	}

	param->meter_id = l2fwd_policer_alloc_id(port_id,
		POLICER_METER_ID_TYPE);
	if (!param->meter_id) {
		rte_exit(EXIT_FAILURE,
			"Alloc port%d's meter ID failed\n", port_id);
	}
	param->profile_id = l2fwd_policer_meter_profile_create(port_id,
		param);
	if (!param->profile_id) {
		rte_exit(EXIT_FAILURE,
			"Port %u No profile ID allocated\n",
			port_id);
	}
	param->policy_id = l2fwd_policer_meter_policy_create(port_id,
		param);
	if (!param->policy_id) {
		rte_exit(EXIT_FAILURE,
			"Port %u No policy ID allocated\n",
			port_id);
	}

	memset(&mp, 0, sizeof(mp));
	mp.meter_profile_id = *param->profile_id;
	mp.meter_policy_id = *param->policy_id;
	mp.default_input_color = s_default_color;
	mp.meter_enable = true;
	ret = rte_mtr_create(port_id, *param->meter_id, &mp, true, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Port %u create Meter(%d) failed(%d)\n",
			port_id, *param->meter_id, ret);
	}
}

static void
l2fwd_policer_flow_action_update(uint16_t port_id,
	struct l2fwd_policer_port_params *param,
	uint8_t update, int queue_update)
{
	uint16_t tc = 0;

	l2fwd_policer_meter_update(port_id, param, update);

	for (tc = 0; tc < POLICER_TC_MAX_NUM; tc++) {
		if (!param->tc_flow[tc].valid)
			continue;
		_l2fwd_policer_flow_action_update(port_id, param,
			&param->tc_flow[tc], tc, queue_update);
	}
}

static void
l2fwd_policer_update_policer(int queue_update)
{
	uint16_t portid;
	uint8_t update;

	RTE_ETH_FOREACH_DEV(portid) {
		/* skip disabled port */
		if (!(l2fwd_policer_enabled_port_mask & (1 << portid)))
			continue;

		update = 0;
		if (s_port_param[portid].trtcm.cir != s_cir_update ||
			s_port_param[portid].trtcm.cbs != s_cbs_update ||
			s_port_param[portid].trtcm.pir != s_pir_update ||
			s_port_param[portid].trtcm.pbs != s_pbs_update)
			update |= POLICER_PROFILE_UPDATE;
		if (s_port_param[portid].red_action.type != s_red_action_update)
			update |= POLICER_POLICY_UPDATE;
		if (!update && !queue_update)
			continue;

		s_port_param[portid].trtcm.cir = s_cir_update;
		s_port_param[portid].trtcm.cbs = s_cbs_update;
		s_port_param[portid].trtcm.pir = s_pir_update;
		s_port_param[portid].trtcm.pbs = s_pbs_update;
		s_port_param[portid].red_action.type = s_red_action_update;
		l2fwd_policer_flow_action_update(portid,
			&s_port_param[portid], update, queue_update);
	}
}

static void *
l2fwd_policer_runtime_policer_update(void *arg)
{
	char command[256];
	int ret, print_hint, queue_update = false, meter_enable = false;

	/* Set this cpu-affinity to CPU 0 */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	ret = pthread_setaffinity_np(pthread_self(),
		sizeof(cpuset), &cpuset);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"%s thread set affinity failed(%d)\n\n",
			__func__, ret);
		pthread_exit(NULL);
	}

	s_cir_update = s_cir;
	s_cbs_update = s_cbs;
	s_pir_update = s_pir;
	s_pbs_update = s_pbs;
	s_red_action_update = s_red_action;

	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER ||
		s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK)
		meter_enable = true;

	print_hint = true;
	while (1) {
		if (force_quit)
			return arg;
		if (print_hint) {
			if (meter_enable) {
				RTE_LOG(INFO, L2FWD_POLICER,
					POLICER_UPDATE_FORMAT,
					POLICER_UPDATE_CIR,
					POLICER_UPDATE_CBS,
					POLICER_UPDATE_PIR,
					POLICER_UPDATE_PBS);
				RTE_LOG(INFO, L2FWD_POLICER,
					"Update policy action: %s or %s\n",
					POLICER_UPDATE_RED_DROP,
					POLICER_UPDATE_RED_PASS);
			}
			RTE_LOG(INFO, L2FWD_POLICER,
				"Update queue index: %s\n",
				POLICER_UPDATE_QUEUE_IDX);
		}
		if (fgets(command, 256, stdin)) {
			if (meter_enable && !strncmp(command,
				POLICER_UPDATE_CIR,
				strlen(POLICER_UPDATE_CIR))) {
				s_cir_update = strtoul(command +
					strlen(POLICER_UPDATE_CIR),
					NULL, 10);
			} else if (meter_enable && !strncmp(command,
				POLICER_UPDATE_CBS,
				strlen(POLICER_UPDATE_CBS))) {
				s_cbs_update = strtoul(command +
					strlen(POLICER_UPDATE_CBS),
					NULL, 10);
			} else if (meter_enable && !strncmp(command,
				POLICER_UPDATE_PIR,
				strlen(POLICER_UPDATE_PIR))) {
				s_pir_update = strtoul(command +
					strlen(POLICER_UPDATE_PIR),
					NULL, 10);
			} else if (meter_enable && !strncmp(command,
				POLICER_UPDATE_PBS,
				strlen(POLICER_UPDATE_PBS))) {
				s_pbs_update = strtoul(command +
					strlen(POLICER_UPDATE_PBS),
					NULL, 10);
			} else if (!strncmp(command,
				POLICER_UPDATE_QUEUE_IDX,
				strlen(POLICER_UPDATE_QUEUE_IDX))) {
				queue_update = true;
			} else if (meter_enable && !strncmp(command,
				POLICER_UPDATE_RED_DROP,
				strlen(POLICER_UPDATE_RED_DROP))) {
				s_red_action_update = RTE_FLOW_ACTION_TYPE_DROP;
			} else if (meter_enable && !strncmp(command,
				POLICER_UPDATE_RED_PASS,
				strlen(POLICER_UPDATE_RED_PASS))) {
				s_red_action_update = RTE_FLOW_ACTION_TYPE_PASSTHRU;
			} else {
				print_hint = false;
				continue;
			}
			print_hint = true;
			l2fwd_policer_update_policer(queue_update);
		}
	}

	return arg;
}

static void
signal_handler(int signum)
{
	if ((signum == SIGINT || signum == SIGTERM)) {
		force_quit = true;
		RTE_LOG(INFO, L2FWD_POLICER,
		"\n\nSignal %d received, preparing to exit...\n",
		signum);
	}
}

int
main(int argc, char **argv)
{
	uint16_t nb_ports_available = 0;
	struct lcore_queue_conf *qconf;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	uint16_t portid, last_port;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
	uint16_t nb_ports, i;
	int ret;
	pthread_t pid;

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_policer_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-POLICER arguments\n");
	/* >8 End of init EAL. */

	RTE_LOG(INFO, L2FWD_POLICER,
		"MAC updating %s\n",
		mac_updating ? "enabled" : "disabled");
	RTE_LOG(INFO, L2FWD_POLICER,
		"Flow classification %s\n",
		enable_flow ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (l2fwd_policer_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_policer_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_policer_dst_ports[portid] = 0;
	last_port = 0;

	/* initialize the scheduler and get the handle */
	sch_handle = rte_dpaa2_scheduler_init();

	/* populate destination port details */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_policer_dst_ports[portid] = last_port;
			l2fwd_policer_dst_ports[last_port] = portid;
		} else {
			last_port = portid;
		}
		nb_ports_in_mask++;
	}

	if (nb_ports_in_mask % 2) {
		RTE_LOG(NOTICE, L2FWD_POLICER,
			"odd number of ports in portmask.\n");
		l2fwd_policer_dst_ports[last_port] = last_port;
	}
	/* >8 End of initialization of the driver. */

	rx_lcore_id = rte_lcore_id();
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;
		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		RTE_LOG(INFO, L2FWD_POLICER,
			"Lcore %u: RX port %u TX port %u\n",
			rx_lcore_id, portid,
			l2fwd_policer_dst_ports[portid]);
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd +
		nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool. 8< */
	l2fwd_policer_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_policer_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_rxq_info qinfo;
		uint8_t tc_id;
		uint16_t flow_id, queue_num;

		/* skip ports that are not enabled */
		if (!(l2fwd_policer_enabled_port_mask & (1 << portid))) {
			RTE_LOG(INFO, L2FWD_POLICER,
				"Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		/* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(portid, dev_info.max_rx_queues,
			dev_info.max_tx_queues, &local_port_conf);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%u\n",
				ret, portid);
		}
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);
		}

		ret = rte_eth_macaddr_get(portid,
			&l2fwd_policer_ports_eth_addr[portid]);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);
		}

		/* init one RX queue */
		fflush(stdout);

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

		/* set the initialized scheduler handle */
		set_scheduler_handle(&rxq_conf, sch_handle);

		for (i = 0; i < dev_info.max_rx_queues; i++) {
			/* set the scheduler WQ priority
			 * TC[0] traffic in WQ prio 0, TC[1] traffic in WQ prio 1 and so on
			 */
			set_scheduler_wq_prio(&rxq_conf, i);

			/* RX queue setup. 8< */
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf,
				l2fwd_policer_pktmbuf_pool);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Setup port%d-rxq%d failed(%d).\n",
					portid, i, ret);
			}

			ret = rte_eth_rx_queue_info_get(portid, i, &qinfo);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Get port%d-rxq%d info failed(%d).\n",
					portid, i, ret);
			}
			rte_pmd_dpaa2_rxq_parse_tc_info(&qinfo,
				&tc_id, &flow_id);
			queue_num = s_port_param[portid].queue_num[tc_id];
			s_port_param[portid].queue_ids[tc_id][queue_num] = i;
			s_port_param[portid].flow_ids[tc_id][queue_num] = flow_id;
			s_port_param[portid].queue_num[tc_id]++;
			/* >8 End of RX queue setup. */
		}

		/* Init one TX queue on each port. 8< */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		/* >8 End of init one TX queue on each port. */

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret) {
			RTE_LOG(WARNING, L2FWD_POLICER,
				"Port %u, Failed to disable Ptype parsing\n",
				portid);
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable:err=%s, port=%u\n",
					rte_strerror(-ret), portid);
			}
		}

		RTE_LOG(INFO, L2FWD_POLICER,
			"Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			portid,
			RTE_ETHER_ADDR_BYTES(&l2fwd_policer_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (enable_flow) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (!s_port_param[portid].enable)
				continue;
			if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER ||
				s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
				l2fwd_policer_meter_init(portid,
					&s_port_param[portid]);
			}
			l2fwd_policer_vlan_flow_config(portid,
				&s_port_param[portid]);
		}

		ret = pthread_create(&pid, NULL,
			l2fwd_policer_runtime_policer_update, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Flow action update thread create failed(%d)\n",
				ret);
		}
	}

	/* start the scheduler */
	ret = rte_dpaa2_scheduler_start(sch_handle);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_dpaa2_scheduler_start:err=%d,\n", ret);


	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_policer_enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_policer_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if (!(l2fwd_policer_enabled_port_mask & (1 << portid)))
			continue;
		for (i = 0; i < POLICER_TC_MAX_NUM; i++) {
			if (!s_port_param[portid].tc_flow[i].valid)
				continue;
			ret = rte_flow_destroy(portid,
				s_port_param[portid].tc_flow[i].flow, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Destroy port%d's flow failed(%d).\n",
					portid, ret);
			}
			s_port_param[portid].tc_flow[i].flow = NULL;
		}
		if (s_port_param[portid].meter_id) {
			ret = rte_mtr_destroy(portid,
				*s_port_param[portid].meter_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Destroy port%d's meter ID(%d) failed(%d).\n",
					portid, *s_port_param[portid].meter_id, ret);
			}
			l2fwd_policer_free_id(portid,
				s_port_param[portid].meter_id,
				POLICER_METER_ID_TYPE);
		}
		if (s_port_param[portid].profile_id) {
			ret = rte_mtr_meter_profile_delete(portid,
				*s_port_param[portid].profile_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Delete port%d's profile ID(%d) failed(%d).\n",
					portid, *s_port_param[portid].profile_id, ret);
			}
			l2fwd_policer_free_id(portid,
				s_port_param[portid].profile_id,
				POLICER_PROFILE_ID_TYPE);
		}
		if (s_port_param[portid].policy_id) {
			ret = rte_mtr_meter_policy_delete(portid,
				*s_port_param[portid].policy_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Delete port%d's policy ID(%d) failed(%d).\n",
					portid, *s_port_param[portid].policy_id, ret);
			}
			l2fwd_policer_free_id(portid,
				s_port_param[portid].policy_id,
				POLICER_POLICY_ID_TYPE);
		}
		for (i = POLICER_METER_ID_TYPE; i < POLICER_ID_TYPE_MAX; i++) {
			if (s_id_pool[portid][i])
				rte_ring_free(s_id_pool[portid][i]);
			s_id_pool[portid][i] = NULL;
		}
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Stop Port %u error(%d)\n",
				portid, ret);
		}
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
