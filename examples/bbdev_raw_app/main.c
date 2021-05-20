/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#include <stdio.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_bbdev.h>
#include <rte_cycles.h>

#define TEST_REPETITIONS 10000

#define OPS_POOL_SIZE 16
#define OPS_CACHE_SIZE 4

#define PACKET_LEN 64
#define TEST_BUFFER_INPUT_VAL 0x01020304

#define NB_QUEUES	8

uint32_t dev_id;
struct rte_mempool *mp[NB_QUEUES];

static void
host_to_modem_test(int queue_id, int conf_mode)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	int ret;
	uint32_t *input, *output, output_val, pkt_len = PACKET_LEN, i, j;

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
	raw_ops_enq[0]->input.mem =
		rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->input.length = pkt_len;

	/* Hard Output buffer */
	raw_ops_enq[0]->output.is_direct_mem = 1;
	raw_ops_enq[0]->output.mem =
		rte_zmalloc(NULL, pkt_len, RTE_CACHE_LINE_SIZE);
	raw_ops_enq[0]->output.length = 0;

	input = raw_ops_enq[0]->input.mem;
	output = raw_ops_enq[0]->output.mem;
	output_val = rte_bswap32(TEST_BUFFER_INPUT_VAL);

	for (j = 0; j < pkt_len/8; j++)
		input[j] = TEST_BUFFER_INPUT_VAL;

	i = 0;
	while (i < TEST_REPETITIONS) {

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

			if (raw_ops_enq[0]->output.mem != 0) {
				for (j = 0; j < pkt_len/8; j++) {
					if (output[j] != output_val) {
						printf("output %x does not match expected output %x",
							output[j],
							output_val);
						printf("\n============================================================================================\n");
						printf("HOST->MODEM test failed for confirmation mode.\n");
						printf("============================================================================================\n");
						return;
					}
				}
			}
		}
	}

	rte_mempool_put_bulk(mp[queue_id], (void **)raw_ops_enq[0], 1);
	if (conf_mode) {
		printf("\n============================================================================================\n");
		printf("Validated %d operations for HOST->MODEM\n",
			TEST_REPETITIONS);
		printf("HOST->MODEM test successful for confirmation mode.\n");
		printf("============================================================================================\n");
	} else {
		printf("\n============================================================================================\n");
		printf("HOST->MODEM test completed for non confirmation mode. Check Geul console logs for results.\n");
		printf("============================================================================================\n");
	}
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

		if (raw_ops_deq->output.mem) {
			input = (uint32_t *)raw_ops_deq->input.mem;
			output = (uint32_t *)raw_ops_deq->output.mem;
			input_length = raw_ops_deq->input.length /
							sizeof(uint32_t);
			for (j = 0; j < input_length; j++)
				output[j] = input[j];
			raw_ops_deq->output.length = input_length *
							sizeof(uint32_t);
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

	if (conf_mode) {
		printf("\n============================================================================================\n");
		printf("MODEM->HOST test completed for confirmation mode. Check Geul console logs for results.\n");
		printf("============================================================================================\n");
	} else {
		printf("\n============================================================================================\n");
		printf("Received %d operations for MODEM->HOST\n",
			TEST_REPETITIONS);
		printf("MODEM->HOST test successful for non confirmation mode.\n");
		printf("============================================================================================\n");
	}
}

static void
round_trip_latency_test(int h2m_queue_id, int m2h_queue_id)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	int ret;
	uint32_t *input, pkt_len = PACKET_LEN, i, j;
	uint64_t start_time, end_time;
	uint64_t min_time = UINT64_MAX, max_time = 0, total_time = 0;

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

	input = raw_ops_enq[0]->input.mem;

	for (j = 0; j < pkt_len/8; j++)
		input[j] = TEST_BUFFER_INPUT_VAL;

	i = 0;
	while (i < TEST_REPETITIONS) {

		start_time = rte_rdtsc_precise();
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
	int ret;
	uint32_t *input, pkt_len = PACKET_LEN, i, j;
	uint64_t start_time, end_time;
	uint64_t min_time = UINT64_MAX, max_time = 0, total_time = 0;

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

	input = raw_ops_enq[0]->input.mem;

	for (j = 0; j < pkt_len/8; j++)
		input[j] = TEST_BUFFER_INPUT_VAL;

	i = 0;
	while (i < TEST_REPETITIONS) {

		start_time = rte_rdtsc_precise();
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

static void execute_raw_testcases(void)
{
	uint32_t h2m_queue_id, m2h_queue_id;
	unsigned int lcore_id;

	lcore_id = rte_lcore_id();
	h2m_queue_id = lcore_id * 2;
	m2h_queue_id = lcore_id * 2 + 1;

	if (lcore_id == 0) {
		host_to_modem_test(h2m_queue_id, 1);
		modem_to_host_test(m2h_queue_id, 1);
	} else if (lcore_id == 1) {
		host_to_modem_test(h2m_queue_id, 0);
		modem_to_host_test(m2h_queue_id, 0);
	} else if (lcore_id == 2) {
		round_trip_latency_test(h2m_queue_id, m2h_queue_id);
	} else if (lcore_id == 3) {
		host_to_modem_latency_test(h2m_queue_id);
		modem_to_host_test(m2h_queue_id, 1);
	}
}

static int
bbdev_raw_app_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	execute_raw_testcases();
	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_bbdev_queue_conf qconf;
	struct rte_bbdev_info info;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	uint32_t queue_id;
	int ret;
	unsigned int lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	/* Check if BBDEV device is present or not */
	if (!rte_bbdev_count()) {
		printf("No BBDEV device detected\n");
		return -ENODEV;
	}

	rte_bbdev_info_get(0, &info);

	/* setup device */
	ret = rte_bbdev_setup_queues(dev_id, NB_QUEUES, info.socket_id);
	if (ret < 0) {
		printf("rte_bbdev_setup_queues(%u, %u, %d) ret %i\n",
				dev_id, NB_QUEUES, info.socket_id, ret);
		return ret;
	}

	/* setup device queues */
	qconf.socket = 0;
	qconf.queue_size = info.drv.default_queue_conf.queue_size;
	qconf.priority = 0;
	qconf.deferred_start = 0;
	qconf.op_type = RTE_BBDEV_OP_RAW;

	for (queue_id = 0; queue_id < NB_QUEUES; ++queue_id) {
		if (queue_id % 2 == 0)
			qconf.raw_queue_conf.direction =
					RTE_BBDEV_DIR_HOST_TO_MODEM;
		else
			qconf.raw_queue_conf.direction =
					RTE_BBDEV_DIR_MODEM_TO_HOST;

		if (queue_id < 2 || queue_id > 5)
			qconf.raw_queue_conf.conf_enable = 1;
		else
			qconf.raw_queue_conf.conf_enable = 0;

		qconf.raw_queue_conf.modem_core_id = queue_id / 2;

		ret = rte_bbdev_queue_configure(dev_id, queue_id, &qconf);
		if (ret != 0) {
			printf("Failure allocating queue (id=%u) on dev%u\n",
					queue_id, dev_id);
			return ret;
		}

		/* For Host->Modem queue */
		if (queue_id % 2 == 0) {
			snprintf(pool_name, sizeof(pool_name), "pool_%u_%u",
				 dev_id, queue_id);


			mp[queue_id] = rte_mempool_create(pool_name,
					OPS_POOL_SIZE,
					sizeof(struct rte_bbdev_raw_op),
					OPS_CACHE_SIZE,	0, NULL, NULL,
					NULL, NULL, info.socket_id, 0);
		} else {
			mp[queue_id] = NULL;
		}

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
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	return 0;
}
