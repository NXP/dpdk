/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_version.h>
#include <rte_bbdev.h>

#include <geul_ipc_um.h>
#include <gul_host_if.h>

#define RTE_LOGTYPE_BBDEV_LA12XX RTE_LOGTYPE_USER1

#define LA12XX_DEVICE_ID	0
#define LA12XX_DEVICE_NAME	"baseband_la12xx"
#define LA12XX_MAX_QUEUES	2

#define POISON 0x12

/* OPS pool related counts */
#define OPS_POOL_NUM_BUFS	64
#define OPS_POOL_CACHE_SIZE	0

/* MBUF pool related counts */
#define MBUF_MAX_SEGS		256
#define MBUF_POOL_NUM_BUFS	(2 * MBUF_MAX_SEGS * OPS_POOL_NUM_BUFS)
#define MBUF_POOL_ELEM_SIZE	(RTE_PKTMBUF_HEADROOM + 1024)
#define MBUF_POOL_CACHE_SIZE	0

/* Cycle Times. Default = 1000 */
int cycle_times = 1000;

/* Number of segments */
int nb_mbuf_segs = 1;

/* Driven by ipc_memelem_size, creating mempools which would be passed
 * as it it to the host_init call
 */
struct rte_mempool *bbdev_mbuf_pool;
struct rte_mempool *bbdev_enc_ops_pool;

/* Signal control */
static uint8_t force_quit;

static void
create_ops_pools(void)
{
	struct rte_bbdev_enc_op *ops[OPS_POOL_NUM_BUFS];
	struct rte_mbuf *mbufs[2 * MBUF_MAX_SEGS];
	int i, j, ret, data_size;
	char *data;

	/* Create ops pool */
	bbdev_enc_ops_pool = rte_mempool_create("enc_ops_pool",
		OPS_POOL_NUM_BUFS, sizeof(struct rte_bbdev_enc_op),
		OPS_POOL_CACHE_SIZE, 0,	NULL, NULL, NULL, NULL,
		SOCKET_ID_ANY, 0);
	if (bbdev_enc_ops_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init ops pool\n");

	/* Create a mbuf pool */
	bbdev_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
		(2 * nb_mbuf_segs * OPS_POOL_NUM_BUFS),
		MBUF_POOL_CACHE_SIZE, 0, MBUF_POOL_ELEM_SIZE,
		rte_socket_id());
	if (bbdev_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Now fill the ops */
	ret = rte_mempool_get_bulk(bbdev_enc_ops_pool, (void **)&ops,
			      OPS_POOL_NUM_BUFS);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"Cannot get ops element in %s\n", __func__);

	for (i = 0; i < OPS_POOL_NUM_BUFS; i++) {
		ret = rte_pktmbuf_alloc_bulk(bbdev_mbuf_pool, mbufs,
					     (2 * nb_mbuf_segs));
		if (ret)
			rte_exit(EXIT_FAILURE,
				"Cannot get mbuf element in %s\n", __func__);

		data_size = MBUF_POOL_ELEM_SIZE - RTE_PKTMBUF_HEADROOM;
		data = rte_pktmbuf_append(mbufs[0], data_size);
		memset(data, POISON, data_size);

		for (j = 1; j <= nb_mbuf_segs - 1; j++) {
			/* Set the value */
			data_size = MBUF_POOL_ELEM_SIZE - RTE_PKTMBUF_HEADROOM;
			data = rte_pktmbuf_append(mbufs[j], data_size);
			memset(data, j, data_size);

			/* Create input buffer chain */
			ret = rte_pktmbuf_chain(mbufs[0], mbufs[j]);
			if (ret)
				rte_exit(EXIT_FAILURE,
					"Cannot chain mbuf\n");

			/* Create output buffer chain */
			ret = rte_pktmbuf_chain(mbufs[nb_mbuf_segs],
						mbufs[nb_mbuf_segs + j]);
			if (ret)
				rte_exit(EXIT_FAILURE,
					"Cannot chain mbuf\n");
		}

		ops[i]->ldpc_enc.input.data = mbufs[0];
		ops[i]->ldpc_enc.input.length = MBUF_POOL_ELEM_SIZE;
		ops[i]->ldpc_enc.input.offset = 0;
		ops[i]->ldpc_enc.output.data = mbufs[nb_mbuf_segs];
	}

	rte_mempool_put_bulk(bbdev_enc_ops_pool, (void **)ops,
			     OPS_POOL_NUM_BUFS);

	RTE_LOG(INFO, BBDEV_LA12XX, "Created mbuf and ops pool\n");
}

static void
usage(char *prgname)
{
	fprintf(stderr,
	"Usage: %s [EAL args] -- [-t TIMES]\n"
	"-t TIMES: number of a times the serialized test is run (default 1)\n",
	prgname);
}

static int
parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "t:m:h")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 't':
			if (!optarg) {
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Arg parse error: Invalid TIMES count\n");
				return -1;
			}
			cycle_times = atoi(optarg);
			if (cycle_times < 0) {
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Arg parse error: Invalid value for TIMES: (%d)\n",
					cycle_times);
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Assuming default = 1\n");
				cycle_times = 1;
			}
			RTE_LOG(DEBUG, BBDEV_LA12XX,
				"Argument: Parsed TIMES = %d\n", cycle_times);
			break;
		case 'm':
			if (!optarg) {
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Arg parse error: Invalid mbuf segs\n");
				return -1;
			}
			nb_mbuf_segs = atoi(optarg);
			if ((nb_mbuf_segs < 0) || (nb_mbuf_segs > MBUF_MAX_SEGS)) {
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Arg parse error: Invalid value for nb_mbuf_segs: (%d)\n",
					nb_mbuf_segs);
				RTE_LOG(ERR, BBDEV_LA12XX,
					"Assuming default = 1\n");
				nb_mbuf_segs = 1;
			}
			RTE_LOG(DEBUG, BBDEV_LA12XX,
				"Argument: Parsed mbuf segs = %d\n",
				nb_mbuf_segs);
			break;
		default:
			usage(argv[0]);
		}
	}

	return 0;
}

static int
_send(uint32_t q_id)
{
	struct rte_bbdev_enc_op *send_op;
	int ret;

	rte_mempool_get(bbdev_enc_ops_pool, (void **)&send_op);

	/* TODO: To be expanded to decode ops also */
	ret = rte_bbdev_enqueue_enc_ops(LA12XX_DEVICE_ID, q_id, &send_op, 1);
	if (ret == 0)
		return -1;

	return 0;
}

static int
_recv(uint32_t q_id)
{
	struct rte_bbdev_enc_op *recv_op;
	int ret, jj = 0;

	do {
		ret = rte_bbdev_dequeue_enc_ops(LA12XX_DEVICE_ID,
						q_id, &recv_op, 1);
		if ((++jj % 100000) == 0) {
			printf(".");
			fflush(stdout);
		}
	} while (ret == 0);
	rte_mempool_put(bbdev_enc_ops_pool, recv_op);

	return 0;
}

static int
sender(void *arg)
{
	int ret = 1, i;

	RTE_SET_USED(arg);

	RTE_LOG(INFO, BBDEV_LA12XX,
		" --> Starting Sender (lcore_id=%u)\n", rte_lcore_id());

	for (i = 0; i < cycle_times; i++) {
		/* For the Queue 0 */
		ret = _send(0);
		if (ret) {
			RTE_LOG(ERR, BBDEV_LA12XX,
				"Unable to send msg on queue 0 (%d)\n", ret);
			return ret;
		}

		/* For the Queue 1 */
		ret = _send(1);
		if (ret) {
			RTE_LOG(ERR, BBDEV_LA12XX,
				"Unable to send msg on queue 1 (%d)\n", ret);
			return ret;
		}

		if (force_quit)
			break;
	}

	RTE_LOG(INFO, BBDEV_LA12XX, "Quiting Sender thread\n");

	return ret;
}

static int
receiver(void *arg)
{
	int ret = 1, i;

	RTE_SET_USED(arg);

	RTE_LOG(INFO, BBDEV_LA12XX,
		" --> Starting Receiver (Poll Mode) (lcore_id=%u)\n",
		rte_lcore_id());

	/* XXX Loop on cycle_times */
	for (i = 0; i < cycle_times; i++) {
		ret = _recv(0);
		if (ret) {
			RTE_LOG(ERR, BBDEV_LA12XX,
				"Unable to recv msg on queue 0 (%d)\n", ret);
			return ret;
		}
		ret = _recv(1);
		if (ret) {
			RTE_LOG(ERR, BBDEV_LA12XX,
				"Unable to recv msg on queue 1 (%d)\n", ret);
			return ret;
		}

		if (force_quit)
			break;
	}

	RTE_LOG(INFO, BBDEV_LA12XX, "Quiting Receiver thread\n");

	return ret;
}

static void
dump_stats(void)
{
	struct rte_bbdev_stats stats;

	rte_bbdev_stats_get(0, &stats);
	printf("***************************************\n");
	printf("enqueued_count: %ld\n", stats.enqueued_count);
	printf("dequeued_count: %ld\n", stats.dequeued_count);
	printf("enqueue_err_count: %ld\n", stats.enqueue_err_count);
	printf("dequeue_err_count: %ld\n", stats.dequeue_err_count);
	printf("***************************************\n");
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\n Signal %d received. Preparing to exit\n", signum);
		force_quit = 1;
	}
	/* else, ignore */
}

int
main(int argc, char **argv)
{
	struct rte_bbdev_queue_conf qconf = {0};
	int ret, i, lcore_id;
	int sender_init = 0, receiver_init = 0;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Cannot init EAL\n", argv[0]);

	RTE_LOG(INFO, BBDEV_LA12XX, "Version Info : %s\n", rte_version());
	if (rte_lcore_count() < 3)
		rte_panic("[%s] Cannot Run. Need minimium of 3 Cores\n",
			  argv[0]);
	argc -= ret;
	argv += ret;

	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Unable to parse args.\n", argv[0]);

	create_ops_pools();

	/* Create a vdev device; Name of device contains Instance ID
	 * for the BBDEV LA12XX device instance
	 */
	RTE_LOG(INFO, BBDEV_LA12XX,
		"Creating VDEV with name=%s\n", LA12XX_DEVICE_NAME);
	ret = rte_vdev_init(LA12XX_DEVICE_NAME, "");
	if (ret)
		rte_panic("Unable to create LA12XX device (%s)",
			LA12XX_DEVICE_NAME);

	rte_bbdev_setup_queues(LA12XX_DEVICE_ID, 2, 0);

	qconf.queue_size = 4;
	/* TODO: This should be replaced by LDPC */
	qconf.op_type = RTE_BBDEV_OP_NONE;
	for (i = 0; i < LA12XX_MAX_QUEUES; i++) {
		ret = rte_bbdev_queue_configure(LA12XX_DEVICE_ID, i, &qconf);
		if (ret)
			rte_panic("queue configure failed for id %d", i);
	}

	ret = rte_bbdev_start(LA12XX_DEVICE_ID);
	if (ret)
		rte_panic("device start failed");

	/* Start the test cycle */

	/* Run Test Case
	 * 1. A Sender - for sending on Queue 0 and Queue 1,
	 * 2. A receiver - for receiving on Queue 0 and Queue 1
	 */

	printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf(" \tPrint # : Sender is starting\n");
	printf(" \tPrint * : Receiver is starting\n");
	printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");

	/* send messages to cores */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (!sender_init) {
			rte_eal_remote_launch(sender, NULL, lcore_id);
			sender_init = 1;
		} else if (!receiver_init) {
			rte_eal_remote_launch(receiver, NULL, lcore_id);
			receiver_init = 1;
		}
	}

	rte_eal_mp_wait_lcore();

	dump_stats();

	return 0;
}
