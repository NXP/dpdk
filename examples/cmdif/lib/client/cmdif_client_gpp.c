/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 NXP
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <rte_log.h>
#include <rte_rawdev.h>
#include <rte_pmd_dpaa2_cmdif.h>

#include <fsl_cmdif_client.h>
#include <fsl_cmdif_flib_c.h>
#include <cmdif.h>

/* Default 10 milli-second wait for CMDIF sync commands */
static uint64_t cmdif_client_sync_wait_interval = 10000;
/* Default max 1000 tries (polls) for CMDIF sync commands */
static uint64_t cmdif_client_sync_num_tries = 1000;

void
cmdif_sync_set_timeout_params(uint64_t wait_interval_us,
			      uint64_t num_tries)
{
	cmdif_client_sync_wait_interval = wait_interval_us;
	cmdif_client_sync_num_tries = num_tries;
}


int
cmdif_open(struct cmdif_desc *cidesc,
	   const char *module_name,
	   uint8_t instance_id,
	   void *data,
	   uint32_t size)
{
	struct rte_dpaa2_cmdif_context cmdif_send_cnxt;
	uint64_t dpci_devid = (uint64_t)(cidesc->regs);
	struct rte_rawdev_buf buf, *send_buf = &buf;
	struct cmdif_fd fd;
	int err = 0;
	uint64_t t = 0;
	int resp = 0;

	err = cmdif_open_cmd(cidesc, module_name, instance_id, data,
			(uint64_t)(data), size, &fd);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif_open_cmd failed with err: %d\n",
			err);
		return err;
	}

	buf.buf_addr = (void *)fd.u_addr.d_addr;
	cmdif_send_cnxt.size = fd.d_size;
	cmdif_send_cnxt.frc = fd.u_frc.frc;
	cmdif_send_cnxt.flc = fd.u_flc.flc;
	cmdif_send_cnxt.priority = CMDIF_PRI_LOW;

	err = rte_rawdev_enqueue_buffers((uint16_t)(dpci_devid),
		&send_buf, 1, &cmdif_send_cnxt);
	if (err <= 0) {
		RTE_LOG(ERR, CMDIF, "enqueue of buffer failed\n");
		return err;
	}

	/* Wait for response from Server */
	do {
		resp = cmdif_sync_ready(cidesc);
		if (resp == 0)
			usleep(cmdif_client_sync_wait_interval);
		t++;
	} while ((resp == 0) && (t < cmdif_client_sync_num_tries));
	if (t == cmdif_client_sync_num_tries) {
		RTE_LOG(ERR, CMDIF, "cmdif_sync_ready reached timeout value\n");
		return -ETIMEDOUT;
	}

	err = cmdif_open_done(cidesc);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif_open_done failed with err: %d\n",
			err);
		return err;
	}

	return 0;
}

int
cmdif_close(struct cmdif_desc *cidesc)
{
	struct rte_dpaa2_cmdif_context cmdif_send_cnxt;
	uint64_t dpci_devid = (uint64_t)(cidesc->regs);
	struct rte_rawdev_buf buf, *send_buf = &buf;
	struct cmdif_fd fd;
	int err = 0;
	uint64_t t = 0;
	int resp = 0;

	err = cmdif_close_cmd(cidesc, &fd);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif_close_cmd failed with err: %d\n",
			err);
		return err;
	}

	buf.buf_addr = (void *)fd.u_addr.d_addr;
	cmdif_send_cnxt.size = fd.d_size;
	cmdif_send_cnxt.frc = fd.u_frc.frc;
	cmdif_send_cnxt.flc = fd.u_flc.flc;
	cmdif_send_cnxt.priority = CMDIF_PRI_LOW;

	err = rte_rawdev_enqueue_buffers((uint16_t)(dpci_devid),
		&send_buf, 1, &cmdif_send_cnxt);
	if (err <= 0) {
		RTE_LOG(ERR, CMDIF, "enqueue of buffer failed\n");
		return err;
	}

	/* Wait for response from Server */
	do {
		resp = cmdif_sync_ready(cidesc);
		if (resp == 0)
			usleep(cmdif_client_sync_wait_interval);
		t++;
	} while ((resp == 0) && (t < cmdif_client_sync_num_tries));
	if (t == cmdif_client_sync_num_tries) {
		RTE_LOG(ERR, CMDIF, "cmdif_sync_ready reached timeout value\n");
		return err;
	}

	err = cmdif_close_done(cidesc);
	if (err)
		RTE_LOG(ERR, CMDIF, "cmdif_close_done failed with err: %d\n",
			err);

	return 0;
}

int
cmdif_send(struct cmdif_desc *cidesc,
	   uint16_t cmd_id,
	   uint32_t size,
	   int priority,
	   uint64_t data,
	   cmdif_cb_t *async_cb,
	   void *async_ctx)
{
	struct rte_dpaa2_cmdif_context cmdif_send_cnxt;
	uint64_t dpci_devid = (uint64_t)(cidesc->regs);
	struct rte_rawdev_buf buf, *send_buf = &buf;
	struct cmdif_fd fd;
	uint64_t t = 0;
	int err = 0;
	int resp = 0;

	err = cmdif_cmd(cidesc, cmd_id, size, data, async_cb, async_ctx, &fd);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif_cmd failed with err: %d\n",
			err);
		return err;
	}

	buf.buf_addr = (void *)fd.u_addr.d_addr;
	cmdif_send_cnxt.size = fd.d_size;
	cmdif_send_cnxt.frc = fd.u_frc.frc;
	cmdif_send_cnxt.flc = fd.u_flc.flc;
	cmdif_send_cnxt.priority = priority;

	err = rte_rawdev_enqueue_buffers((uint16_t)(dpci_devid),
		&send_buf, 1, &cmdif_send_cnxt);
	if (err <= 0) {
		RTE_LOG(ERR, CMDIF, "enqueue of buffer failed\n");
		return err;
	}

	if (cmdif_is_sync_cmd(cmd_id)) {
		/* Wait for response from Server */
		do {
			resp = cmdif_sync_ready(cidesc);
			if (resp == 0)
				usleep(cmdif_client_sync_wait_interval);
			t++;
		} while ((resp == 0) && (t < cmdif_client_sync_num_tries));
		if (t == cmdif_client_sync_num_tries) {
			RTE_LOG(ERR, CMDIF, "cmdif_sync_ready reached timeout value\n");
			return -ETIMEDOUT;
		}
		err = cmdif_sync_cmd_done(cidesc);
		if (err) {
			RTE_LOG(ERR, CMDIF, "cmdif_sync_cmd_done failed with err: %d\n",
				err);
			return err;
		}

	}

	return 0;
}

int
cmdif_resp_read(struct cmdif_desc *cidesc, int priority)
{
	struct rte_dpaa2_cmdif_context cmdif_rcv_cnxt;
	uint64_t dpci_devid = (uint64_t)(cidesc->regs);
	struct rte_rawdev_buf buf, *recv_buf = &buf;
	struct cmdif_fd fd;
	int err = 0, num_pkts;

	if (cidesc == NULL)
		return -EINVAL;

	cmdif_rcv_cnxt.priority = priority;
	num_pkts = rte_rawdev_dequeue_buffers((uint16_t)(dpci_devid),
		&recv_buf, 1, &cmdif_rcv_cnxt);
	if (num_pkts < 0) {
		RTE_LOG(ERR, CMDIF, "Error calling buffer dequeue\n");
		return num_pkts;
	}
	while (num_pkts > 0) {
		fd.u_addr.d_addr = (uint64_t)buf.buf_addr;
		fd.d_size = cmdif_rcv_cnxt.size;
		fd.u_frc.frc = cmdif_rcv_cnxt.frc;
		fd.u_flc.flc = cmdif_rcv_cnxt.flc;

		err = cmdif_async_cb(&fd);
		if (err) {
			RTE_LOG(ERR, CMDIF, "Error calling cmdif_async_cb\n");
			return err;
		}
		num_pkts = rte_rawdev_dequeue_buffers((uint16_t)(dpci_devid),
			&recv_buf, 1, &cmdif_rcv_cnxt);
		if (num_pkts < 0) {
			RTE_LOG(ERR, USER1, "Error calling buffer dequeue\n");
			return num_pkts;
		}
	}

	return 0;
}
