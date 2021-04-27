/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#include <stdio.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_bbdev.h>

#define TEST_REPETITIONS 10000

#define OPS_POOL_SIZE 16
#define OPS_CACHE_SIZE 4

#define PACKET_LEN 64
#define TEST_BUFFER_INPUT_VAL 0x01020304

int
main(int argc, char **argv)
{
	struct rte_bbdev_queue_conf qconf;
	struct rte_bbdev_info info;
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL}, *raw_ops_deq = NULL;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp = NULL;
	uint32_t nb_queues = 2, queue_id, i, j;
	uint32_t dev_id = 0, pkt_len = PACKET_LEN;
	uint32_t *input, *output, output_val, input_length;
	int ret;

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
		if (queue_id % 2 == 0)
			qconf.raw_queue_conf.direction =
					RTE_BBDEV_DIR_HOST_TO_MODEM;
		else
			qconf.raw_queue_conf.direction =
					RTE_BBDEV_DIR_MODEM_TO_HOST;

		qconf.raw_queue_conf.conf_enable = 1;

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


			mp = rte_mempool_create(pool_name, OPS_POOL_SIZE,
						sizeof(struct rte_bbdev_raw_op),
						OPS_CACHE_SIZE,	0, NULL, NULL,
						NULL, NULL, info.socket_id, 0);

			ret = rte_mempool_get_bulk(mp, (void **)raw_ops_enq, 1);
			if (ret < 0) {
				printf("rte_mempool_get_bulk failed (%d)\n",
						ret);
				return ret;
			}
		}

	}

	ret = rte_bbdev_start(dev_id);
	if (ret < 0) {
		printf("rte_bbdev_start failed (%d)\n",	ret);
		return ret;
	}

	for (queue_id = 0; queue_id < nb_queues; ++queue_id) {
		if (queue_id % 2 == 0) { /**< Host->Modem queue */
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

			i = 0;
			while (i < TEST_REPETITIONS) {

				for (j = 0; j < pkt_len/8; j++)
					input[j] = TEST_BUFFER_INPUT_VAL;

				/* Enqueue */
				ret = rte_bbdev_enqueue_raw_op(dev_id, queue_id,
							       raw_ops_enq[0]);
				if (ret < 0)
					continue;

				i++;

				/* Dequeue */
				do {
					raw_ops_deq =
						rte_bbdev_dequeue_raw_op(dev_id,
								queue_id);
				} while (!raw_ops_deq);

				if (raw_ops_enq[0]->output.mem != 0) {
					for (j = 0; j < pkt_len/8; j++) {
						if (output[j] != output_val)
							printf("output %x does not match expected output %x",
								output[j],
								output_val);
					}
				}
			}

			rte_mempool_put_bulk(mp, (void **)raw_ops_enq[0], 1);

			printf("\nValidated %d operations for HOST->MODEM\n",
				TEST_REPETITIONS);


			printf("HOST->MODEM test Passed\n");

		} else { /**< Modem->Host queue */

			for (i = 0; i < TEST_REPETITIONS; ++i) {
				do {
					raw_ops_deq =
						rte_bbdev_dequeue_raw_op(dev_id,
								queue_id);
				} while (!raw_ops_deq);

				if (raw_ops_deq->output.mem) {
					input = (uint32_t *)
							raw_ops_deq->input.mem;
					output = (uint32_t *)
							raw_ops_deq->output.mem;
					input_length =
						raw_ops_deq->input.length /
							sizeof(uint32_t);
					for (j = 0; j < input_length; j++)
						output[j] = input[j];
					raw_ops_deq->output.length =
						input_length * sizeof(uint32_t);
				}

				ret = rte_bbdev_consume_raw_op(dev_id, queue_id,
						raw_ops_deq);
				if (ret < 0) {
					printf("rte_bbdev_consume_raw_op failed (%d)\n",
						ret);
					return ret;
				}
			}

			printf("MODEM->HOST test completed. Check Geul console logs for results.\n");
		}

	}

	return 0;
}
