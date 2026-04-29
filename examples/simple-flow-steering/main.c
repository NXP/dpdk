/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
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

#define RTE_LOGTYPE_SIMPLE_FLOW_STEERING RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

static bool force_quit;

static int s_def_tc = -1;
static int s_def_flow = -1;

static void *s_sch_handle;

static int s_flow_table_level = 2;

static int s_print_stat = true;

struct simple_steer_flow_info {
	uint16_t flow_id;
	uint16_t vlan_id;
};

#define MAX_TC_NUM 8
#define MAX_FLOW_NUM 64
static struct simple_steer_flow_info s_flow_info[MAX_FLOW_NUM];
static int s_flow_info_num;
static struct rte_flow *s_qos_flows[MAX_FLOW_NUM];
static struct rte_flow *s_fs_flows[MAX_TC_NUM][MAX_FLOW_NUM];

static uint16_t s_queue_id[MAX_TC_NUM][MAX_FLOW_NUM];

/* main processing loop */
static void
simple_flow_steering_main_loop(void)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint16_t sent, i, nb_rx;
	struct rte_mbuf_sched *sched;

	RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
		"entering main loop on lcore %u\n", rte_lcore_id());

	while (!force_quit) {
		nb_rx = rte_dpaa2_scheduler_rx(s_sch_handle, mbufs, MAX_PKT_BURST);
		if (unlikely(!nb_rx))
			continue;

		for (i = 0; i < nb_rx; i++) {
			if (mbufs[i]->ol_flags & RTE_MBUF_F_RX_FDIR) {
				if (s_print_stat) {
					sched = &mbufs[i]->hash.sched;
					RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
						"Receive packet from TC%d-flow%d\n",
						sched->traffic_class, sched->queue_id);
				}
			} else {
				RTE_LOG(ERR, SIMPLE_FLOW_STEERING, "Receive unexpected packet\n");
			}
			sent = rte_eth_tx_burst(0, 0, &mbufs[i], 1);
			if (sent != 1) {
				RTE_LOG(ERR, SIMPLE_FLOW_STEERING, "Send packet failed\n");
				rte_pktmbuf_free(mbufs[i]);
			}
		}
		/* End of read packet from RX queues. */
	}
}

static int
simple_flow_steering_launch_one_lcore(__rte_unused void *dummy)
{
	simple_flow_steering_main_loop();
	return 0;
}

static int
simple_flow_steering_parse_queue(const char *optarg)
{
	char s[256];
	const char *p, *p0 = optarg;
	char *end;
	enum fieldnames {
		FLD_FLOW,
		FLD_VLAN_ID,
		_NUM_FLD
	};
	int int_fld[_NUM_FLD], i, num;
	char *str_fld[_NUM_FLD];
	uint32_t size;

	p = strchr(p0, '(');
	while (p) {
		++p;
		p0 = strchr(p, ')');
		if (!p0)
			return -EINVAL;

		size = p0 - p;
		if (size >= sizeof(s))
			return -EINVAL;

		snprintf(s, sizeof(s), "%.*s", size, p);
		num = rte_strsplit(s, sizeof(s), str_fld,
			_NUM_FLD, ',');
		if (num != _NUM_FLD)
			return -EINVAL;
		for (i = 0; i < num; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno || end == str_fld[i])
				return -EINVAL;
		}
		if (s_flow_info_num >= MAX_FLOW_NUM)
			return -EINVAL;
		s_flow_info[s_flow_info_num].flow_id = int_fld[FLD_FLOW];
		s_flow_info[s_flow_info_num].vlan_id = int_fld[FLD_VLAN_ID];
		s_flow_info_num++;
		p = strchr(p0, '(');
	}

	return 0;
}

static const char short_options[] = "p";

#define CMD_LINE_OPT_STEER_FLOW_CONFIG "flow_config"
#define CMD_LINE_OPT_FLOW_TABLE_LEVEL_CONFIG "flow_table_level"
#define CMD_LINE_OPT_PRINT_STAT_CONFIG "print_stat"
#define CMD_LINE_OPT_DEFAULT_TC_CONFIG "default_tc"
#define CMD_LINE_OPT_DEFAULT_FLOW_CONFIG "default_flow"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_STEER_FLOW_NUM,
	CMD_LINE_OPT_FLOW_TABLE_LEVEL,
	CMD_LINE_OPT_PRINT_STAT,
	CMD_LINE_OPT_DEFAULT_TC_NUM,
	CMD_LINE_OPT_DEFAULT_FLOW_NUM
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_PRINT_STAT_CONFIG, 1, 0, CMD_LINE_OPT_PRINT_STAT},
	{CMD_LINE_OPT_STEER_FLOW_CONFIG, 1, 0, CMD_LINE_OPT_STEER_FLOW_NUM},
	{CMD_LINE_OPT_FLOW_TABLE_LEVEL_CONFIG, 1, 0, CMD_LINE_OPT_FLOW_TABLE_LEVEL},
	{CMD_LINE_OPT_DEFAULT_TC_CONFIG, 1, 0, CMD_LINE_OPT_DEFAULT_TC_NUM},
	{CMD_LINE_OPT_DEFAULT_FLOW_CONFIG, 1, 0, CMD_LINE_OPT_DEFAULT_FLOW_NUM},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
simple_vlan_flow_steering_parse_args(int argc, char **argv)
{
	int opt, ret, option_index;
	char **argvopt;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
		&option_index)) != EOF) {
		switch (opt) {
		case CMD_LINE_OPT_DEFAULT_TC_NUM:
			s_def_tc = atoi(optarg);
			break;

		case CMD_LINE_OPT_DEFAULT_FLOW_NUM:
			s_def_flow = atoi(optarg);
			break;

		case CMD_LINE_OPT_STEER_FLOW_NUM:
			ret = simple_flow_steering_parse_queue(optarg);
			if (ret)
				return ret;
			break;

		case CMD_LINE_OPT_FLOW_TABLE_LEVEL:
			s_flow_table_level = atoi(optarg);
			if (s_flow_table_level != 1 && s_flow_table_level != 2) {
				RTE_LOG(ERR, SIMPLE_FLOW_STEERING,
					"Invalid flow table level(%d)\n",
					s_flow_table_level);
				return -EINVAL;
			}
			break;

		case CMD_LINE_OPT_PRINT_STAT:
			s_print_stat = atoi(optarg);
			break;

		default:
			return -ENOTSUP;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
simple_flow_steering_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
		RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
			"\n\nSignal %d received, preparing to exit...\n", signum);
	}
}

static struct rte_flow *
simple_flow_steering_create_vlan_flow(uint8_t tc_id,
	uint16_t flow_id, uint8_t vlan_prio, uint16_t vlan_id,
	uint16_t entry_id)
{
	struct rte_flow_item_vlan vlan_item[2];
	struct rte_flow_item_vlan vlan_mask[2];
	struct rte_flow_item flow_item[3];
	struct rte_flow_attr flow_attr;
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_action flow_action[2];
	struct rte_flow *flow;

	/** vlan_prio->tc_id*/
	/** vlan_id->flow_id*/
	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.ingress = 1;
	flow_attr.group = 0xff;
	flow_attr.priority = entry_id;
	memset(vlan_item, 0, sizeof(struct rte_flow_item_vlan) * 2);
	memset(vlan_mask, 0, sizeof(struct rte_flow_item_vlan) * 2);
	vlan_item[0].hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_TCI_MAKE(0, vlan_prio, 0));
	vlan_mask[0].hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_PRI_MASK);
	vlan_item[1].hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_TCI_MAKE(vlan_id, 0, 0));
	vlan_mask[1].hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_ID_MASK);
	flow_item[0].spec = &vlan_item[0];
	flow_item[0].mask = &vlan_mask[0];
	flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
	flow_item[1].spec = &vlan_item[1];
	flow_item[1].mask = &vlan_mask[1];
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	flow_item[2].type = RTE_FLOW_ITEM_TYPE_END;
	dest_queue.index = s_queue_id[tc_id][flow_id];
	flow_action[0].conf = &dest_queue;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	flow = rte_flow_create(0, &flow_attr, flow_item, flow_action, NULL);
	if (flow) {
		RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
			"Direct vlan (prio=%d/id=%d) to flow%d of TC%d\n",
			vlan_prio, vlan_id, flow_id, tc_id);
	}
	return flow;
}

static void
simple_flow_steering_one_level_table_flow_init(uint16_t tc_num,
	uint16_t qos_entries, uint16_t queues_per_tc)
{
	int i, tc, entry, ret;
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_action flow_action[2];
	struct simple_steer_flow_info *flow_info;

	if (s_def_tc >= 0 && s_def_flow >= 0) {
		if (s_def_tc >= tc_num || s_def_flow >= queues_per_tc) {
			rte_exit(EXIT_FAILURE,
				"Invalid default TC(%d)>(%d) or default flow(%d)>(%d)?\n",
				s_def_tc, tc_num, s_def_flow, queues_per_tc);
		}
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		dest_queue.index = s_queue_id[s_def_tc][s_def_flow];
		flow_action[0].conf = &dest_queue;
	} else {
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
	}
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_group_set_miss_actions(0, 0xff, NULL, flow_action, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Create default action of one-level table failed(%d).\n", ret);
	}

	entry = 0;
	for (i = 0; i < s_flow_info_num; i++) {
		flow_info = &s_flow_info[i];
		if (flow_info->flow_id >= queues_per_tc) {
			rte_exit(EXIT_FAILURE,
				"Invalid flow ID(%d)>(%d)\n", flow_info->flow_id, queues_per_tc);
		}
		for (tc = 0; tc < tc_num; tc++) {
			if (entry >= qos_entries) {
				rte_exit(EXIT_FAILURE, "Too many qos flows(%d)>(%d)\n",
					entry, qos_entries);
			}
			s_qos_flows[entry] = simple_flow_steering_create_vlan_flow(tc,
				flow_info->flow_id, tc, flow_info->vlan_id, entry);
			if (!s_qos_flows[entry]) {
				rte_exit(EXIT_FAILURE, "Create flow%d of one-level table failed.\n",
					entry);
			}
			entry++;
		}
	}
}

static void
simple_flow_steering_two_level_table_flow_init(uint16_t tc_num,
	uint16_t qos_entries, uint16_t fs_entries, uint16_t queues_per_tc)
{
	int i, j, vlan_id, flow_id, ret;
	struct rte_flow_item_vlan vlan_item;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item flow_item[2];
	struct rte_flow_attr flow_attr;
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_action_jump action_jump;
	struct rte_flow_action flow_action[2];
	struct simple_steer_flow_info *flow_info;

	if (tc_num > qos_entries) {
		rte_exit(EXIT_FAILURE,
			"Too many TC number(%d)> QoS entries(%d)\n",
			tc_num, qos_entries);
	}

	if (s_flow_info_num > fs_entries) {
		rte_exit(EXIT_FAILURE,
			"Too many flow number(%d)> FS entries(%d)\n",
			s_flow_info_num, fs_entries);
	}

	if (s_def_tc >= 0) {
		if (s_def_tc >= tc_num) {
			rte_exit(EXIT_FAILURE,
				"Invalid default TC(%d)>(%d)\n", s_def_tc, tc_num);
		}
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
		action_jump.group = s_def_tc;
		flow_action[0].conf = &action_jump;
	} else {
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
	}
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_group_set_miss_actions(0, 0xff, NULL, flow_action, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Create default action of QoS table failed(%d).\n", ret);
	}

	for (i = 0; i < tc_num; i++) {
		if (s_def_flow >= 0) {
			if (s_def_flow >= queues_per_tc) {
				rte_exit(EXIT_FAILURE,
					"Invalid default flow(%d)>(%d)\n",
					s_def_flow, queues_per_tc);
			}
			flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
			dest_queue.index = s_queue_id[i][s_def_flow];
			flow_action[0].conf = &dest_queue;
		} else {
			flow_action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		}
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
		ret = rte_flow_group_set_miss_actions(0, i, NULL, flow_action, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Create default action of TC%d's FS table failed(%d).\n",
				i, ret);
		}
		memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
		flow_attr.ingress = 1;
		flow_attr.group = 0xff;/** Force QoS flow*/
		flow_attr.priority = i;/** QoS Entry*/
		memset(&vlan_item, 0, sizeof(struct rte_flow_item_vlan));
		memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
		vlan_item.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_TCI_MAKE(0, i, 0));
		vlan_mask.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_PRI_MASK);
		flow_item[0].spec = &vlan_item;
		flow_item[0].mask = &vlan_mask;
		flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
		action_jump.group = i;
		flow_action[0].conf = &action_jump;
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
		s_qos_flows[i] = rte_flow_create(0, &flow_attr, flow_item, flow_action, NULL);
		if (!s_qos_flows[i])
			rte_exit(EXIT_FAILURE, "Create qos flow%d of two-level table failed.\n", i);
		RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
			"Direct vlan (prio=%d) to TC%d\n", i, i);
		for (j = 0; j < s_flow_info_num; j++) {
			flow_info = &s_flow_info[j];
			memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
			flow_attr.ingress = 1;
			flow_attr.group = i;
			flow_attr.priority = j;
			vlan_id = flow_info->vlan_id;
			flow_id = flow_info->flow_id;
			if (flow_id >= queues_per_tc) {
				rte_exit(EXIT_FAILURE,
					"Invalid flow ID(%d)>(%d)\n", flow_id, queues_per_tc);
			}
			memset(&vlan_item, 0, sizeof(struct rte_flow_item_vlan));
			memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
			vlan_item.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_TCI_MAKE(vlan_id, 0, 0));
			vlan_mask.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_ID_MASK);
			flow_item[0].spec = &vlan_item;
			flow_item[0].mask = &vlan_mask;
			flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
			flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;
			dest_queue.index = s_queue_id[i][flow_id];
			flow_action[0].conf = &dest_queue;
			flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
			flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
			s_fs_flows[i][flow_attr.priority] = rte_dpaa2_flow_create(0, &flow_attr,
				flow_item, flow_action, NULL, RTE_DPAA2_FS_GROUP_FLOW);
			if (!s_fs_flows[i][flow_attr.priority]) {
				rte_exit(EXIT_FAILURE,
					"Create fs flow[%d][%d] of two-level table failed.\n",
					i, flow_attr.priority);
			}
			RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
				"Direct vlan (id=%d) to flow%d of TC%d\n", vlan_id, flow_id, i);
		}
	}
}

static void
simple_flow_steering_sch_dev_init(uint16_t queue_num)
{
	struct rte_pmd_dpaa2_rxq_info qinfo;
	uint16_t flow_id, i;
	uint8_t tc_id;
	int ret;

	s_sch_handle = rte_dpaa2_scheduler_init(RTE_DPAA2_SCH_PUSH);
	if (!s_sch_handle)
		rte_exit(EXIT_FAILURE, "Init schedule failed.\n");
	ret = rte_dpaa2_scheduler_start(s_sch_handle);
	if (ret)
		rte_exit(EXIT_FAILURE, "Start schedule failed(%d).\n", ret);

	for (i = 0; i < queue_num; i++) {
		ret = rte_pmd_dpaa2_rx_queue_info_get(0, i, &qinfo);
		if (ret)
			rte_exit(EXIT_FAILURE, "Get rxq%d info failed(%d).\n", i, ret);
		tc_id = qinfo.tc_id;
		flow_id = qinfo.flow_id;
		s_queue_id[tc_id][flow_id] = i;
		ret = rte_dpaa2_scheduler_add(s_sch_handle, 0, i, tc_id);
		if (ret)
			rte_exit(EXIT_FAILURE, "Schedule rxq%d failed(%d).\n", i, ret);
	}
}

int
main(int argc, char **argv)
{
	uint16_t lcore_id, nb_ports, i, j;
	int ret;
	const struct rte_eth_conf port_conf = {
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
	};

	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_pmd_dpaa2_dev_info dpaa2_dev_info;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint16_t tc_num, qos_entries, fs_entries, queues_per_tc;
	struct rte_mempool *pktmbuf_pool;

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, simple_flow_steering_signal_handler);
	signal(SIGTERM, simple_flow_steering_signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = simple_vlan_flow_steering_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-POLICER arguments\n");
	/* >8 End of init EAL. */

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* Port0 only */
	if (!rte_pmd_dpaa2_dev_is_dpaa2(0))
		rte_exit(EXIT_FAILURE, "DPAA2 support only\n");

	/* init port */
	ret = rte_pmd_dpaa2_dev_info_get(0, &dpaa2_dev_info);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Error during getting device info: %s\n",
			strerror(-ret));
	}
	rte_memcpy(&dev_info, &dpaa2_dev_info.dev_info, sizeof(struct rte_eth_dev_info));
	tc_num = dpaa2_dev_info.rx_tc_num;
	qos_entries = dpaa2_dev_info.qos_entries;
	fs_entries = dpaa2_dev_info.fs_entries;
	queues_per_tc = dpaa2_dev_info.dist_queues;

	ret = rte_eth_dev_configure(0, dev_info.max_rx_queues,
			dev_info.max_tx_queues, &local_port_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d\n", ret);

	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf-pool",
		8192, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (!pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	for (i = 0; i < dev_info.max_rx_queues; i++) {
		/* RX queue setup. 8< */
		ret = rte_eth_rx_queue_setup(0, i, 1024, 0, &rxq_conf, pktmbuf_pool);
		if (ret)
			rte_exit(EXIT_FAILURE, "Setup rxq%d failed(%d).\n", i, ret);

		ret = rte_eth_rx_queue_info_get(0, i, &qinfo);
		if (ret)
			rte_exit(EXIT_FAILURE, "Get rxq%d info failed(%d).\n", i, ret);
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(0, 0, 1024, 0, &txq_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "Setup txq failed(%d).\n", ret);

	/* Start device */
	ret = rte_eth_dev_start(0);
	if (ret)
		rte_exit(EXIT_FAILURE, "Start port failed(%d).\n", ret);

	ret = rte_eth_promiscuous_enable(0);
	if (ret)
		rte_exit(EXIT_FAILURE, "Enable promisc failed(%d)\n", ret);

	simple_flow_steering_sch_dev_init(dev_info.max_rx_queues);

	if (s_flow_table_level == 1) {
		simple_flow_steering_one_level_table_flow_init(tc_num,
			qos_entries, queues_per_tc);
	} else if (s_flow_table_level == 2) {
		simple_flow_steering_two_level_table_flow_init(tc_num,
			qos_entries, fs_entries, queues_per_tc);
	} else {
		rte_exit(EXIT_FAILURE, "Invalid flow table level(%d).\n", s_flow_table_level);
	}

	RTE_LOG(INFO, SIMPLE_FLOW_STEERING,
		"Port info: %d TCs, %d QoS entries, %d FS entries, %d queues per TC\n",
		tc_num, qos_entries, fs_entries, queues_per_tc);

	memset(&link, 0, sizeof(link));
	ret = rte_eth_link_get_nowait(0, &link);
	if (ret) {
		RTE_LOG(ERR, SIMPLE_FLOW_STEERING, "Port link get failed: %s\n",
			rte_strerror(-ret));
	} else {
		rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
		RTE_LOG(INFO, SIMPLE_FLOW_STEERING, "Port %s\n", link_status_text);
	}

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(simple_flow_steering_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	rte_dpaa2_scheduler_destroy(s_sch_handle);

	for (i = 0; i < MAX_FLOW_NUM; i++) {
		if (s_qos_flows[i]) {
			ret = rte_flow_destroy(0, s_qos_flows[i], NULL);
			if (ret) {
				RTE_LOG(ERR, SIMPLE_FLOW_STEERING,
					"Free QoS flow[%d] failed(%d)\n", i, ret);
			}
			s_qos_flows[i] = NULL;
		}
	}
	for (i = 0; i < MAX_TC_NUM; i++) {
		for (j = 0; j < MAX_FLOW_NUM; j++) {
			if (s_fs_flows[i][j]) {
				ret = rte_flow_destroy(0, s_fs_flows[i][j], NULL);
				if (ret) {
					RTE_LOG(ERR, SIMPLE_FLOW_STEERING,
						"Free FS flow[%d][%d] failed(%d)\n", i, j, ret);
				}
				s_fs_flows[i][j] = NULL;
			}
		}
	}
	ret = rte_eth_dev_stop(0);
	if (ret)
		RTE_LOG(ERR, SIMPLE_FLOW_STEERING, "Stop port failed(%d)\n", ret);
	ret = rte_eth_dev_close(0);
	if (ret)
		RTE_LOG(ERR, SIMPLE_FLOW_STEERING, "Close port failed(%d)\n", ret);

	rte_mempool_free(pktmbuf_pool);

	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
