/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 NXP
 */

/* System headers */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <unistd.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_dpaa2_mempool.h>
#include <rte_bus_vdev.h>
#include <rte_rawdev.h>

#include <fsl_cmdif_client.h>
#include <fsl_cmdif_server.h>

/* CMDIF application specific commands */
#define OPEN_CMD 0x100
#define NORESP_CMD 0x101
#define ASYNC_CMD 0x102
#define SYNC_CMD 0x103
#define IC_TEST 0x106
#define CMDIF_TEST_MODULE_NAME "IRA"

/* Maximum number of open commands */
#define MAX_OPEN_CMDS 10

/* Number of times to test the GPP client sync commands */
#define CMDIF_CLIENT_SYNC_NUM 100
/* Number of times to test the GPP client async commands */
#define CMDIF_CLIENT_ASYNC_NUM 10
/* Number of times to test the GPP server async commands */
#define CMDIF_SERVER_ASYNC_NUM 10

/* Buffer and packet related macros */
#define CMDIF_BUF_NUM 128
#define CMDIF_BUF_CACHE_SIZE 32
#define CMDIF_BUF_SIZE 512
#define CMDIF_DATA_SIZE 64

/* Maximum number of tries for receiving the async response */
#define CMDIF_DEMO_NUM_TRIES 1000
/* Wait before each try (in milli-secconds) */
#define CMDIF_DEMO_ASYNC_WAIT (100 * 1000)

/* Represents Command Interface device index */
#define CMDIF_DEV_INDEX0 0

/* Command interface channels */
static struct cmdif_desc cidesc[MAX_OPEN_CMDS];

/* Global pointers to store the CI device handle */
static int client_devid;
static int server_devid;

static void *open_cmd_mem[MAX_OPEN_CMDS];
static struct rte_mempool *cmdif_memory_pool;
static struct rte_mempool *cmdif_packet_pool;

static uint8_t *old_buf;
static int async_count;
static uint32_t num_req, num_reply;

static int
open_for_cmdif(uint64_t index, uint16_t client_device_id)
{
	uint8_t *data;
	int ret = 0;

	data = rte_malloc(NULL, CMDIF_OPEN_SIZE, 0);
	if (!data) {
		RTE_LOG(ERR, USER1, "Unable to get the memory\n");
		return -ENOMEM;
	}

	/* cidesc->regs is required to be set to DPDK device */
	cidesc[index].regs = (void *)(uint64_t)client_device_id;
	ret = cmdif_open(&cidesc[index], "TEST0", 0, data,
		CMDIF_OPEN_SIZE);
	if (ret != 0) {
		RTE_LOG(ERR, USER1, "cmdif_open failed\n");
		rte_free(data);
		return ret;
	}

	open_cmd_mem[index] = data;
	return 0;
}

static int
close_for_cmdif(int index)
{
	int ret;

	ret = cmdif_close(&cidesc[index]);
	if (ret)
		RTE_LOG(ERR, USER1, "cmdif_close_failed\n");

	rte_free(open_cmd_mem[index]);
	open_cmd_mem[index] = NULL;

	return ret;
}

static int
async_cb(void *async_ctx __rte_unused, int err,
	  uint16_t cmd_id __rte_unused,
	  uint32_t size, void *data)
{
	uint32_t j;
	uint8_t *v_data = (uint8_t *)(data);

	if (err != 0) {
		RTE_LOG(ERR, USER1, "ERROR inside async callback\n");
		return err;
	}

	/*
	 * AIOP has filled the buffer with 0xDA.
	 * Check for modified data from the AIOP server.
	 */
	for (j = 0; j < size; j++) {
		if ((v_data)[j] != 0xDA) {
			RTE_LOG(ERR, USER1, "Invalid data from AIOP!!!\n");
			return 0;
		}
	}

	async_count++;
	return 0;
}

static int
cmdif_client_test(void)
{
	uint8_t *data, *async_data[CMDIF_CLIENT_ASYNC_NUM];
	int ret, t;
	uint8_t i, j;

	printf("\n*******************************************\n");
	RTE_LOG(INFO, USER1, "Started %s\n", __func__);

	RTE_LOG(INFO, USER1, "Executing open commands\n");
	/* Open the command interface channel */
	/*
	 * NOTE: In case user needs to open more Command Interface channels,
	 * user should provide separate client device ID so that separate
	 * DPCI is registered for each CMDIF device.
	 */
	ret = open_for_cmdif(CMDIF_DEV_INDEX0, client_devid);
	if (ret) {
		RTE_LOG(ERR, USER1, "Open for cmdif failed\n");
		return ret;
	}
	RTE_LOG(INFO, USER1, "PASSED open commands\n");

	/* Get a memory block */
	/*
	 * NOTE: Here we are using the same memory and same data_buf,
	 * but separate memory can also be used i.e. rte_mempool_get
	 * can be done in the below 'for' loop
	 */
	ret = rte_mempool_get(cmdif_memory_pool, (void **)(&data));
	if (unlikely(ret)) {
		RTE_LOG(ERR, USER1, "Buffer allocation failure\n");
		return ret;
	}

	RTE_LOG(INFO, USER1, "Executing sync commands\n");
	/* Executing sync commands on cmdif instance 0 */
	for (i = 0; i < CMDIF_CLIENT_SYNC_NUM; i++) {
		for (j = 0; j < CMDIF_DATA_SIZE; j++)
			data[j] = i + j;
		ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0], i, /* cmd_id */
				CMDIF_DATA_SIZE, /* size */
				(i & 1), /* priority */
				(uint64_t)(data) /* data */,
				NULL, 0);
		if (ret) {
			RTE_LOG(ERR, USER1, "FAILED sync_send %d\n", i);
			break;
		}
	}
	rte_mempool_put(cmdif_memory_pool, data);
	RTE_LOG(INFO, USER1, "PASSED synchronous send commands\n");

	RTE_LOG(INFO, USER1, "Executing async commands\n");
	/*
	 * Executing async commands on cmdif instance 0.
	 * In this demo we first send all the async commands and
	 * then read all the responses in a separate loop.
	 * User can also use separate threads to read the responses.
	 */
	for (i = 0; i < CMDIF_CLIENT_ASYNC_NUM; i++) {
		ret = rte_mempool_get(cmdif_memory_pool,
				(void **)(&async_data[i]));
		if (unlikely(ret)) {
			RTE_LOG(ERR, USER1, "Buffer allocation failure\n");
			return ret;
		}

		data = async_data[i];
		for (j = 0; j < CMDIF_DATA_SIZE; j++)
			data[j] = i + j;
		ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0],
				(i | CMDIF_ASYNC_CMD), /*cmd_id*/
				CMDIF_DATA_SIZE + CMDIF_ASYNC_OVERHEAD, /*size*/
				(i & 1), /* priority */
				(uint64_t)(data) /* data */,
				async_cb, /*async_cb */
				0); /* async_ctx */
		if (ret) {
			RTE_LOG(ERR, USER1, "FAILED async_send %d\n", i);
			break;
		}
	}

	/* Now read all the responses of the async commands */
	t = 0;
	while (async_count != CMDIF_CLIENT_ASYNC_NUM &&
		       (t < CMDIF_CLIENT_ASYNC_NUM * CMDIF_DEMO_NUM_TRIES)) {
		usleep(CMDIF_DEMO_ASYNC_WAIT);
		/* Use priority as (t & 1) to alternate between high and
		 * low priorities
		 */
		ret = cmdif_resp_read(&cidesc[CMDIF_DEV_INDEX0], (t & 1));
		if (ret)
			RTE_LOG(ERR, USER1,
				"FAILED cmdif_resp_read %d\n", i);
		t++;
	}
	if (async_count != CMDIF_CLIENT_ASYNC_NUM)
		RTE_LOG(ERR, USER1, "FAILED: asynchronous command\n");

	if (async_count == CMDIF_CLIENT_ASYNC_NUM)
		RTE_LOG(INFO, USER1,
			"PASSED asynchronous send/receive commands\n");

	/* Clean-up */
	for (i = 0; i < CMDIF_CLIENT_ASYNC_NUM; i++)
		rte_mempool_put(cmdif_memory_pool, async_data[i]);

	RTE_LOG(INFO, USER1, "Executing close commands\n");
	ret = close_for_cmdif(CMDIF_DEV_INDEX0);
	if (ret != 0)
		RTE_LOG(ERR, USER1, "FAILED: Close command\n");
	else
		RTE_LOG(INFO, USER1, "PASSED: close commands\n");

	RTE_LOG(INFO, USER1, "Exiting %s\n", __func__);
	printf("*******************************************\n");

	return 0;
}

static int
open_cb(uint8_t instance_id __rte_unused,
	void **dev __rte_unused)
{
	return 0;
}

static int
close_cb(void *dev __rte_unused)
{
	return 0;
}

static int
ctrl_cb(void *dev __rte_unused, uint16_t cmd __rte_unused,
	uint32_t size, void *data)
{
	num_reply++;

	if (old_buf)
		rte_mempool_put(cmdif_memory_pool, old_buf);
	memset((uint8_t *)data, 0x01, size);

	/*
	 * AIOP demo application (AIOP side) has incremented the data by 'size'
	 * provided in the async command trigger (GPP->AIOP in cmdif_send())
	 * from the one we provided
	 */
	old_buf = (uint8_t *)(data) - CMDIF_DATA_SIZE;

	return 0;
}

static struct cmdif_module_ops ops = {
	.open_cb = open_cb,
	.close_cb = close_cb,
	.ctrl_cb = ctrl_cb
};

static int
cmdif_server_test(void)
{
	uint8_t *data, *session_data;
	struct rte_mbuf *mbuf;
	uint16_t auth_id = 0;
	uint64_t dpci_id;
	int ret, i, t = 0;

	printf("\n*******************************************\n");
	RTE_LOG(INFO, USER1, "Started %s\n", __func__);

	ret = open_for_cmdif(CMDIF_DEV_INDEX0, client_devid);
	if (ret) {
		RTE_LOG(ERR, USER1, "Open for cmdif failed\n");
		return ret;
	}

	RTE_LOG(INFO, USER1, "Registering the module...\n");
	ret = cmdif_register_module(CMDIF_TEST_MODULE_NAME, &ops);
	if (ret) {
		RTE_LOG(ERR, USER1, "Server registration failed\n");
		return ret;
	}

	/* Get a memory block */
	session_data = rte_malloc(NULL, CMDIF_SESSION_OPEN_SIZE, 0);
	if (!session_data) {
		RTE_LOG(ERR, USER1, "Unable to get the memory\n");
		return ret;
	}

	ret = cmdif_session_open(&cidesc[CMDIF_DEV_INDEX0],
			CMDIF_TEST_MODULE_NAME, 0,
			CMDIF_SESSION_OPEN_SIZE, session_data,
			(void *)(uint64_t)(server_devid), &auth_id);
	if (ret) {
		RTE_LOG(ERR, USER1, "FAILED cmdif session open\n");
		return ret;
	}

	RTE_LOG(INFO, USER1, "PASSED cmdif session open\n");

	ret = rte_mempool_get(cmdif_memory_pool, (void **)(&data));
	if (unlikely(ret)) {
		RTE_LOG(ERR, USER1, "Buffer allocation failure\n");
		return ret;
	}

	/* Trigger open for AIOP client */
	/*
	 * Pass the device ID while triggerring the open.
	 * This is required by the AIOP client
	 */
	rte_rawdev_get_attr(server_devid, NULL, &dpci_id);
	data[0] = (uint8_t)dpci_id;
	ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0], OPEN_CMD, CMDIF_DATA_SIZE,
			CMDIF_PRI_LOW, (uint64_t)data, NULL, 0);
	if (ret)
		RTE_LOG(ERR, USER1, "FAILED open on client\n");

	/* Reusing the previous buffer */
	memset((uint8_t *)data, 0, CMDIF_BUF_SIZE);

	RTE_LOG(INFO, USER1, "Triggering commands on AIOP client\n");
	ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0], NORESP_CMD, CMDIF_DATA_SIZE,
			CMDIF_PRI_LOW, (uint64_t)(data), NULL, 0);
	num_req++;
	if (ret) {
		RTE_LOG(ERR, USER1, "FAILED to send no resp cmd on client\n");
	} else {
		ret = -1;
		while (ret != 0 && (t < CMDIF_DEMO_NUM_TRIES)) {
			usleep(CMDIF_DEMO_ASYNC_WAIT);
			ret = cmdif_srv_cb(CMDIF_PRI_LOW,
				(void *)(uint64_t)(server_devid));
			t++;
		}
		if (ret != 0)
			RTE_LOG(ERR, USER1, "FAILED cmdif_srv_cb\n");
	}

	ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0],
			(SYNC_CMD | CMDIF_NORESP_CMD), 0,
			CMDIF_PRI_LOW, 0, NULL, 0);
	if (ret)
		RTE_LOG(ERR, USER1, "FAILED sync command\n");
	else
		RTE_LOG(INFO, USER1, "PASSED sync command\n");

	RTE_LOG(INFO, USER1, "Activate cmdif_cl_isr() on AIOP\n");
	for (i = 0; i < CMDIF_SERVER_ASYNC_NUM; i++) {
		t = 0;
		ret = rte_mempool_get(cmdif_memory_pool, (void **)(&data));
		if (unlikely(ret)) {
			RTE_LOG(ERR, USER1, "Buffer allocation failure\n");
			return ret;
		}
		memset((uint8_t *)data, 0, CMDIF_BUF_SIZE);

		/*
		 * Here we are allocating and passing the data
		 * using mempool. This data is used by the AIOP in the
		 * AIOP->GPP communication to pass the data. Buffer pool
		 * can be used for this communication and there will be no
		 * requirement of passing this data here
		 */
		ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0],
				ASYNC_CMD, CMDIF_DATA_SIZE,
				CMDIF_PRI_LOW, (uint64_t)(data), NULL, 0);
		num_req++;
		if (ret) {
			RTE_LOG(ERR, USER1,
				"FAILED to send async cmd on client\n");
		} else {
			ret = -1;
			while (ret != 0 && (t < CMDIF_DEMO_NUM_TRIES)) {
				usleep(CMDIF_DEMO_ASYNC_WAIT);
				ret = cmdif_srv_cb(CMDIF_PRI_LOW,
					(void *)(uint64_t)(server_devid));
				t++;
			}
			if (ret != 0)
				RTE_LOG(ERR, USER1, "FAILED cmdif_srv_cb\n");
		}
	}

	if  (num_reply != num_req)
		RTE_LOG(ERR, USER1, "FAILED Async commands\n");
	else
		RTE_LOG(INFO, USER1, "PASSED Async commands\n");

	rte_mempool_put(cmdif_memory_pool, old_buf);

	/* Isolation context test */
	RTE_LOG(INFO, USER1, "Executing Isolation context test\n");
	mbuf = rte_pktmbuf_alloc(cmdif_packet_pool);
	if (!mbuf) {
		RTE_LOG(ERR, USER1, "Failure in mbuf allocation\n");
		return -ENOMEM;
	}
	data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	rte_rawdev_get_attr(server_devid, NULL, &dpci_id);
	data[0] = (uint8_t)dpci_id;

	/* Assuming BPID will fit into uint8_t */
	data[1] = (uint8_t)(rte_dpaa2_mbuf_pool_bpid(cmdif_packet_pool));
	ret = cmdif_send(&cidesc[CMDIF_DEV_INDEX0], IC_TEST,
			CMDIF_DATA_SIZE, CMDIF_PRI_LOW,
			(uint64_t)data, NULL, 0);
	if (ret)
		RTE_LOG(ERR, USER1, "FAILED Isolation context command send\n");
	else
		RTE_LOG(INFO, USER1, "PASSED Isolation context test\n");

	/* Get the packet buffer back from the address */
	mbuf = rte_dpaa2_mbuf_from_buf_addr(cmdif_packet_pool,
			data - RTE_PKTMBUF_HEADROOM);
	if (mbuf)
		rte_pktmbuf_free(mbuf);
	else
		RTE_LOG(ERR, USER1, "Unable to fetch and release Packet.\n");

	/* Clean-up */
	RTE_LOG(INFO, USER1, "Executing session close\n");
	ret = cmdif_session_close(&cidesc[CMDIF_DEV_INDEX0],
			auth_id, 50, session_data,
			(void *)(uint64_t)(server_devid));
	if (ret)
		RTE_LOG(ERR, USER1, "FAILED cmdif session close\n");
	else
		RTE_LOG(INFO, USER1, "PASSED cmdif session close\n");

	rte_free(session_data);

	ret = cmdif_unregister_module(CMDIF_TEST_MODULE_NAME);
	if (ret)
		RTE_LOG(ERR, USER1, "Server deregistration failed\n");

	close_for_cmdif(0);

	RTE_LOG(INFO, USER1, "Exiting %s\n", __func__);
	printf("*******************************************\n\n");

	return 0;
}

static int
cmdif_demo_main_thread(__attribute__((unused)) void *dummy)
{
	int ret;

	ret = cmdif_client_test();
	if (ret)
		return ret;

	ret = cmdif_server_test();

	return ret;
}

int
main(int argc, char *argv[])
{
	int ret;
	unsigned int lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	if (rte_lcore_count() > 1) {
		rte_exit(EXIT_FAILURE,
			"Invalid number of cores. Required only single core");
	}

	/* Get the client and the server device */
	client_devid = rte_vdev_init("dpaa2_dpci1", NULL);
	server_devid = rte_vdev_init("dpaa2_dpci2", NULL);

	if (client_devid < 0 || server_devid < 0)
		rte_exit(EXIT_FAILURE, "Not enough Resource to run\n");

	/* Create the memory pool */
	cmdif_memory_pool = rte_mempool_create("cmdif_memory_pool",
		CMDIF_BUF_NUM, CMDIF_BUF_SIZE, CMDIF_BUF_CACHE_SIZE,
		0, NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
	if (cmdif_memory_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init cmdif_memory_pool\n");

	/* Create the buffer pool */
	cmdif_packet_pool = rte_pktmbuf_pool_create("cmdif_packet_pool",
		CMDIF_BUF_NUM, CMDIF_BUF_CACHE_SIZE, 0,
		CMDIF_BUF_SIZE, SOCKET_ID_ANY);
	if (cmdif_packet_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init cmdif_packet_pool\n");

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(cmdif_demo_main_thread, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	printf("Main Finished.. bye!\n");
	return 0;
}
