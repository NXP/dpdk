/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_bbdev.h>
#include <rte_cycles.h>

#define TEST_REPETITIONS 10000

#define OPS_POOL_SIZE 16
#define OPS_CACHE_SIZE 4

#define PACKET_LEN 64
#define TEST_BUFFER_INPUT_VAL 0x01020304

/*
 * This modem core mapping for specific test case is only for demo application.
 * User can use any core for any queue/test.
 */
#define MODEM_CONF_VALIDATION_CORE		0
#define MODEM_NON_CONF_VALIDATION_CORE		1
#define MODEM_ROUND_TRIP_LATENCY_CORE		2
#define MODEM_UNIDIRECTIONAL_LATENCY_CORE	3

#define MAX_QUEUES	8

uint32_t dev_id;
struct rte_mempool *mp[MAX_QUEUES];

int run_selected_tests;
int run_conf_mode_validation_test, run_non_conf_mode_validation_test;
int run_round_trip_latency_test, run_unidirectional_mode_latency_test;

int use_internal_buf, internal_buf_size;

static void
host_to_modem_test(int queue_id, int conf_mode)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	uint32_t *input, *output, pkt_len = PACKET_LEN, i, j, len;
	int ret;

	ret = rte_mempool_get_bulk(mp[queue_id],
				   (void **)raw_ops_enq, 1);
	if (ret < 0) {
		printf("rte_mempool_get_bulk failed (%d)\n",
				ret);
		printf("\n============================================================================================\n");
		if (conf_mode)
			printf("HOST->MODEM test failed for confirmation mode.\n");
		else
			printf("HOST->MODEM test failed for non confirmation mode.\n");
		printf("============================================================================================\n");
		return;
	}

	/* Input buffer */
	raw_ops_enq[0]->input.is_direct_mem = 1;
	if (!use_internal_buf)
		raw_ops_enq[0]->input.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->input.length = pkt_len;

	/* Hard Output buffer */
	raw_ops_enq[0]->output.is_direct_mem = 1;
	if (conf_mode && !use_internal_buf)
		raw_ops_enq[0]->output.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->output.length = 0;

	input = raw_ops_enq[0]->input.mem;
	output = raw_ops_enq[0]->output.mem;

	i = 0;
	while (i < TEST_REPETITIONS) {
		/* For LA93xx device use internal buffer */
		if (use_internal_buf) {
			raw_ops_enq[0]->input.mem =
				rte_bbdev_get_next_internal_buf(dev_id,
					queue_id, &len);
			if (!raw_ops_enq[0]->input.mem)
				continue;
			raw_ops_enq[0]->input.length = internal_buf_size/2;

			if (conf_mode)
				raw_ops_enq[0]->output.mem =
					(void *)((uint64_t)raw_ops_enq[0]->input.mem +
					internal_buf_size/2);

			input = raw_ops_enq[0]->input.mem;
			output = raw_ops_enq[0]->output.mem;
		}

		for (j = 0; j < pkt_len/8; j++) {
			input[j] = TEST_BUFFER_INPUT_VAL;
			if (conf_mode)
				output[j] = 0;
		}

		/* Enqueue */
		ret = rte_bbdev_enqueue_raw_op(dev_id, queue_id,
					       raw_ops_enq[0]);
		if (ret < 0)
			continue;

		i++;

		if (conf_mode) {
			/* Dequeue */
			do {
				raw_ops_deq = rte_bbdev_dequeue_raw_op(dev_id,
								queue_id);
			} while (!raw_ops_deq);

			if (raw_ops_enq[0]->output.mem != NULL) {
				for (j = 0; j < pkt_len/8; j++) {
					if (output[j] != input[j]) {
						printf("output %x does not match expected output %x",
							output[j],
							input[j]);
						printf("\n============================================================================================\n");
						printf("HOST->MODEM test failed for confirmation mode.\n");
						printf("============================================================================================\n");
						return;
					}
				}
			} else {
				printf("output.mem is null");
				printf("\n============================================================================================\n");
				printf("HOST->MODEM test failed for confirmation mode.\n");
				printf("============================================================================================\n");
				return;
			}
		}
	}

	rte_mempool_put_bulk(mp[queue_id], (void **)raw_ops_enq[0], 1);
	printf("\n============================================================================================\n");
	if (conf_mode) {
		printf("Validated %d operations for HOST->MODEM\n",
			TEST_REPETITIONS);
		printf("HOST->MODEM test successful for confirmation mode.\n");
	} else {
		printf("HOST->MODEM test completed for non confirmation mode. Check Geul console logs for results.\n");
	}
	printf("============================================================================================\n");
}

static void
modem_to_host_test(int queue_id, int conf_mode)
{
	struct rte_bbdev_raw_op *raw_ops_deq = NULL;
	int ret;
	uint32_t *input, *output, input_length, i, j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {
		do {
			raw_ops_deq = rte_bbdev_dequeue_raw_op(dev_id,
							queue_id);
		} while (!raw_ops_deq);

		if (conf_mode) {
			if (raw_ops_deq->output.mem) {
				input = (uint32_t *)raw_ops_deq->input.mem;
				output = (uint32_t *)raw_ops_deq->output.mem;
				input_length = raw_ops_deq->input.length /
							sizeof(uint32_t);
				for (j = 0; j < input_length; j++)
					output[j] = input[j];
				raw_ops_deq->output.length = input_length *
							sizeof(uint32_t);
			} else {
				printf("output.mem is null\n");
				printf("\n============================================================================================\n");
				printf("MODEM->HOST test failed for confirmation mode.\n");
				printf("============================================================================================\n");
				return;
			}
		}

		ret = rte_bbdev_consume_raw_op(dev_id, queue_id, raw_ops_deq);
		if (ret < 0) {
			printf("rte_bbdev_consume_raw_op failed (%d)\n", ret);
			printf("\n============================================================================================\n");
			if (conf_mode)
				printf("MODEM->HOST test failed for confirmation mode.\n");
			else
				printf("MODEM->HOST test failed for non confirmation mode.\n");
			printf("============================================================================================\n");
			return;
		}
	}

	printf("\n============================================================================================\n");
	if (conf_mode) {
		printf("MODEM->HOST test completed for confirmation mode. Check Geul console logs for results.\n");
	} else {
		printf("Received %d operations for MODEM->HOST\n",
			TEST_REPETITIONS);
		printf("MODEM->HOST test successful for non confirmation mode.\n");
	}
	printf("============================================================================================\n");
}

static void
round_trip_latency_test(int h2m_queue_id, int m2h_queue_id)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	uint32_t pkt_len = PACKET_LEN, i, len;
	uint64_t start_time, end_time;
	uint64_t min_time = UINT64_MAX, max_time = 0, total_time = 0;
	int ret;

	ret = rte_mempool_get_bulk(mp[h2m_queue_id], (void **)raw_ops_enq, 1);
	if (ret < 0) {
		printf("rte_mempool_get_bulk failed (%d)\n", ret);
		printf("\n============================================================================================\n");
		printf("Round trip latency test failed.\n");
		printf("============================================================================================\n");
		return;
	}

	/* Input buffer */
	raw_ops_enq[0]->input.is_direct_mem = 1;
	raw_ops_enq[0]->input.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->input.length = pkt_len;

	/* Hard Output buffer */
	raw_ops_enq[0]->output.is_direct_mem = 1;
	raw_ops_enq[0]->output.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->output.length = 0;

	i = 0;
	while (i < TEST_REPETITIONS) {

		start_time = rte_rdtsc_precise();
		/* For LA93xx device use internal buffer */
		if (use_internal_buf) {
			raw_ops_enq[0]->input.mem =
				rte_bbdev_get_next_internal_buf(dev_id,
					h2m_queue_id, &len);
			if (!raw_ops_enq[0]->input.mem)
				continue;
			raw_ops_enq[0]->input.length = internal_buf_size/2;

			raw_ops_enq[0]->output.mem =
				(void *)((uint64_t)raw_ops_enq[0]->input.mem +
				internal_buf_size/2);
		}

		/* Enqueue */
		ret = rte_bbdev_enqueue_raw_op(dev_id, h2m_queue_id,
					       raw_ops_enq[0]);
		if (ret < 0)
			continue;

		i++;

		/* Dequeue */
		do {
			raw_ops_deq = rte_bbdev_dequeue_raw_op(dev_id,
							m2h_queue_id);
		} while (!raw_ops_deq);

		ret = rte_bbdev_consume_raw_op(dev_id, m2h_queue_id,
					raw_ops_deq);
		if (ret < 0) {
			printf("rte_bbdev_consume_raw_op failed (%d)\n", ret);
			printf("\n============================================================================================\n");
			printf("Round trip latency test failed.\n");
			printf("============================================================================================\n");
			return;
		}

		end_time = rte_rdtsc_precise() - start_time;
		min_time = RTE_MIN(min_time, end_time);
		max_time = RTE_MAX(max_time, end_time);
		total_time += end_time;
	}

	printf("\n============================================================================================\n");
	printf("Round trip operation latency:\n");

	printf("\tavg: %lg cycles, %lg us\n",
			(double)total_time / (double)TEST_REPETITIONS,
			(double)(total_time * 1000000) /
				(double)TEST_REPETITIONS /
				(double)rte_get_tsc_hz());

	printf("\tmin: %lg cycles, %lg us\n", (double)min_time,
			(double)(min_time * 1000000) /
				(double)rte_get_tsc_hz());

	printf("\tmax: %lg cycles, %lg us\n", (double)max_time,
			(double)(max_time * 1000000) /
				(double)rte_get_tsc_hz());

	rte_mempool_put_bulk(mp[h2m_queue_id], (void **)raw_ops_enq[0], 1);

	printf("Round trip latency test successful with %d test cases\n", i);
	printf("============================================================================================\n");
}

static void
host_to_modem_latency_test(int queue_id)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	uint32_t pkt_len = PACKET_LEN, i, len;
	uint64_t start_time, end_time;
	uint64_t min_time = UINT64_MAX, max_time = 0, total_time = 0;
	int ret;

	ret = rte_mempool_get_bulk(mp[queue_id], (void **)raw_ops_enq, 1);
	if (ret < 0) {
		printf("rte_mempool_get_bulk failed (%d)\n", ret);
		printf("\n============================================================================================\n");
		printf("HOST->MODEM latency test failed.\n");
		printf("============================================================================================\n");
		return;
	}

	/* Input buffer */
	raw_ops_enq[0]->input.is_direct_mem = 1;
	raw_ops_enq[0]->input.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->input.length = pkt_len;

	/* Hard Output buffer */
	raw_ops_enq[0]->output.is_direct_mem = 1;
	raw_ops_enq[0]->output.mem =
			rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->output.length = 0;

	i = 0;
	while (i < TEST_REPETITIONS) {

		start_time = rte_rdtsc_precise();
		/* For LA93xx device use internal buffer */
		if (use_internal_buf) {
			raw_ops_enq[0]->input.mem =
				rte_bbdev_get_next_internal_buf(dev_id,
					queue_id, &len);
			if (!raw_ops_enq[0]->input.mem)
				continue;
			raw_ops_enq[0]->input.length = internal_buf_size/2;

			raw_ops_enq[0]->output.mem =
				(void *)((uint64_t)raw_ops_enq[0]->input.mem +
				internal_buf_size/2);
		}

		/* Enqueue */
		ret = rte_bbdev_enqueue_raw_op(dev_id, queue_id,
					       raw_ops_enq[0]);
		if (ret < 0)
			continue;

		i++;

		/* Dequeue */
		do {
			raw_ops_deq = rte_bbdev_dequeue_raw_op(dev_id,
							queue_id);
		} while (!raw_ops_deq);

		end_time = rte_rdtsc_precise() - start_time;
		min_time = RTE_MIN(min_time, end_time);
		max_time = RTE_MAX(max_time, end_time);
		total_time += end_time;
	}

	printf("\n============================================================================================\n");
	printf("HOST->MODEM operation latency:\n");

	printf("\tavg: %lg cycles, %lg us\n",
			(double)total_time / (double)TEST_REPETITIONS,
			(double)(total_time * 1000000) /
				(double)TEST_REPETITIONS /
				(double)rte_get_tsc_hz());

	printf("\tmin: %lg cycles, %lg us\n", (double)min_time,
			(double)(min_time * 1000000) /
				(double)rte_get_tsc_hz());

	printf("\tmax: %lg cycles, %lg us\n", (double)max_time,
			(double)(max_time * 1000000) /
				(double)rte_get_tsc_hz());

	rte_mempool_put_bulk(mp[queue_id], (void **)raw_ops_enq[0], 1);

	printf("HOST->MODEM latency test successful with %d test cases\n", i);
	printf("============================================================================================\n");
}

static int
bbdev_raw_app_launch_one_lcore(__attribute__((unused)) void *dummy)
{

	uint32_t h2m_queue_id, m2h_queue_id;
	unsigned int lcore_id, lcore_index;

	lcore_id = rte_lcore_id();
	lcore_index = rte_lcore_index(lcore_id);
	h2m_queue_id = lcore_index * 2;
	m2h_queue_id = lcore_index * 2 + 1;

	if (run_conf_mode_validation_test) {
		if (!lcore_index) {
			host_to_modem_test(h2m_queue_id, 1);
			modem_to_host_test(m2h_queue_id, 1);
			return 0;
		}
		lcore_index--;
	}

	if (run_non_conf_mode_validation_test) {
		if (!lcore_index) {
			host_to_modem_test(h2m_queue_id, 0);
			modem_to_host_test(m2h_queue_id, 0);
			return 0;
		}
		lcore_index--;
	}

	if (run_round_trip_latency_test) {
		if (!lcore_index) {
			round_trip_latency_test(h2m_queue_id, m2h_queue_id);
			return 0;
		}
		lcore_index--;
	}

	if (run_unidirectional_mode_latency_test) {
		if (!lcore_index) {
			host_to_modem_latency_test(h2m_queue_id);
			modem_to_host_test(m2h_queue_id, 1);
			return 0;
		}
		lcore_index--;
	}

	return 0;
}

#define CMD_LINE_OPT_VALIDATION		"validation"
#define CMD_LINE_OPT_LATENCY		"latency"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_VALIDATION_TEST_LIST,
	CMD_LINE_OPT_LATENCY_TEST_LIST,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_VALIDATION, required_argument, 0,
				CMD_LINE_OPT_VALIDATION_TEST_LIST},
	{CMD_LINE_OPT_LATENCY, required_argument, 0,
				CMD_LINE_OPT_LATENCY_TEST_LIST},
	{NULL, 0, 0, 0}
};

/* display usage */
static void print_usage(const char *prgname)
{
	fprintf(stderr, "%s [EAL options] --"
			" --validation a/c/n : Validation tests. a = All tests, c = conf mode test, n = non conf mode test\n"
			" --latency a/c/n : Latency tests. a = All tests, c = conf mode test, n = non conf mode test\n",
		prgname);
}

static int
parse_validation_test_list(const char *testcase)
{
	run_conf_mode_validation_test = 1;
	run_non_conf_mode_validation_test = 1;

	if (!strcmp(testcase, "c"))
		run_non_conf_mode_validation_test = 0;
	else if (!strcmp(testcase, "n"))
		run_conf_mode_validation_test = 0;
	else if (strcmp(testcase, "a"))
		return -1;

	return 0;
}

static int
parse_latency_test_list(const char *testcase)
{
	run_round_trip_latency_test = 1;
	run_unidirectional_mode_latency_test = 1;

	if (!strcmp(testcase, "n"))
		run_unidirectional_mode_latency_test = 0;
	else if (!strcmp(testcase, "c"))
		run_round_trip_latency_test = 0;
	else if (strcmp(testcase, "a"))
		return -1;

	return 0;
}

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, "", lgopts,
				  &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case CMD_LINE_OPT_VALIDATION_TEST_LIST:
			run_selected_tests = 1;
			ret = parse_validation_test_list(optarg);
			if (ret) {
				fprintf(stderr, "Invalid application argument\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_LATENCY_TEST_LIST:
			run_selected_tests = 1;
			ret = parse_latency_test_list(optarg);
			if (ret) {
				fprintf(stderr, "Invalid application argument\n");
				print_usage(prgname);
				return -1;
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_bbdev_queue_conf qconf;
	struct rte_bbdev_info info;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	uint32_t queue_id, nb_queues = MAX_QUEUES;
	int ret, i;
	unsigned int lcore_id;
	int conf_validation_qconfig_done = 0;
	int non_conf_validation_qconfig_done = 0;
	int round_trip_latency_qconfig_done = 0;
	int unidirectional_latency_qconfig_done = 0;
	unsigned int nb_lcores = 0;
	const struct rte_bbdev_op_cap *op_cap;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid application arguments\n");

	RTE_LCORE_FOREACH(lcore_id) {
		nb_lcores++;
	}

	if (!run_selected_tests) {
		if (nb_lcores == 1) {
			run_round_trip_latency_test = 1;
			printf("Single core available. Running only Round trip latency test.\n");
		} else {
			run_conf_mode_validation_test = 1;
			run_non_conf_mode_validation_test = 1;
			run_round_trip_latency_test = 1;
			run_unidirectional_mode_latency_test = 1;
		}
	}

	nb_queues = (run_conf_mode_validation_test +
		    run_non_conf_mode_validation_test +
		    run_round_trip_latency_test +
		    run_unidirectional_mode_latency_test) * 2;


	if (nb_lcores < nb_queues / 2) {
		rte_exit(EXIT_FAILURE, "Not enough cores\n");
	}

	/* Check if BBDEV device is present or not */
	if (!rte_bbdev_count()) {
		printf("No BBDEV device detected\n");
		return -ENODEV;
	}

	ret = rte_bbdev_info_get(0, &info);
	if (ret < 0) {
		printf("rte_bbdev_info_get failed, ret: %d\n", ret);
		return ret;
	}

	op_cap = info.drv.capabilities;
	for (i = 0; op_cap->type != RTE_BBDEV_OP_NONE; ++i, ++op_cap) {
		if (op_cap->type == RTE_BBDEV_OP_RAW &&
		    op_cap->cap.raw.capability_flags &
		    RTE_BBDEV_RAW_CAP_INTERNAL_MEM) {
			use_internal_buf = 1;
			internal_buf_size =
				op_cap->cap.raw.max_internal_buffer_size;
		}
	}

	/* setup device */
	ret = rte_bbdev_setup_queues(dev_id, nb_queues, info.socket_id);
	if (ret < 0) {
		printf("rte_bbdev_setup_queues(%u, %u, %d) ret %i\n",
				dev_id, nb_queues, info.socket_id, ret);
		return ret;
	}

	/* setup device queues */
	qconf.socket = 0;
	qconf.queue_size = info.drv.default_queue_conf.queue_size;
	qconf.priority = 0;
	qconf.deferred_start = 0;
	qconf.op_type = RTE_BBDEV_OP_RAW;

	for (queue_id = 0; queue_id < nb_queues; ++queue_id) {
		if (run_conf_mode_validation_test &&
				!conf_validation_qconfig_done) {
			qconf.raw_queue_conf.conf_enable = 1;
			qconf.raw_queue_conf.modem_core_id =
					MODEM_CONF_VALIDATION_CORE;
			conf_validation_qconfig_done = 1;
		} else if (run_non_conf_mode_validation_test &&
				!non_conf_validation_qconfig_done) {
			qconf.raw_queue_conf.conf_enable = 0;
			qconf.raw_queue_conf.modem_core_id =
					MODEM_NON_CONF_VALIDATION_CORE;
			non_conf_validation_qconfig_done = 1;
		} else if (run_round_trip_latency_test &&
				!round_trip_latency_qconfig_done) {
			qconf.raw_queue_conf.conf_enable = 0;
			qconf.raw_queue_conf.modem_core_id =
					MODEM_ROUND_TRIP_LATENCY_CORE;
			round_trip_latency_qconfig_done = 1;
		} else if (run_unidirectional_mode_latency_test &&
				!unidirectional_latency_qconfig_done) {
			qconf.raw_queue_conf.conf_enable = 1;
			qconf.raw_queue_conf.modem_core_id =
					MODEM_UNIDIRECTIONAL_LATENCY_CORE;
			unidirectional_latency_qconfig_done = 1;
		}

		qconf.raw_queue_conf.direction = RTE_BBDEV_DIR_HOST_TO_MODEM;

		ret = rte_bbdev_queue_configure(dev_id, queue_id, &qconf);
		if (ret != 0) {
			printf("Failure allocating queue (id=%u) on dev%u\n",
					queue_id, dev_id);
			return ret;
		}

		/* For Host->Modem queue */
		snprintf(pool_name, sizeof(pool_name), "pool_%u_%u",
			 dev_id, queue_id);

		mp[queue_id] = rte_mempool_create(pool_name, OPS_POOL_SIZE,
						sizeof(struct rte_bbdev_raw_op),
						OPS_CACHE_SIZE,	0, NULL, NULL,
						NULL, NULL, info.socket_id, 0);

		++queue_id;

		qconf.raw_queue_conf.direction = RTE_BBDEV_DIR_MODEM_TO_HOST;

		ret = rte_bbdev_queue_configure(dev_id, queue_id, &qconf);
		if (ret != 0) {
			printf("Failure allocating queue (id=%u) on dev%u\n",
					queue_id, dev_id);
			return ret;
		}

		mp[queue_id] = NULL;
	}

	ret = rte_bbdev_start(dev_id);
	if (ret < 0) {
		printf("rte_bbdev_start failed (%d)\n",	ret);
		return ret;
	}

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(bbdev_raw_app_launch_one_lcore, NULL,
				 CALL_MASTER);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
