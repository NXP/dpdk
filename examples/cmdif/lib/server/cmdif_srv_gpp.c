/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <rte_atomic.h>
#include <rte_log.h>
#include <rte_rawdev.h>
#include <rte_pmd_dpaa2_cmdif.h>

#include <fsl_cmdif_flib_s.h>
#include <fsl_cmdif_client.h>
#include <cmdif.h>

/*
 * This is server handle. it is set using cmdif_srv_allocate().
 */
static void *srv;
static rte_atomic16_t module_count;

static int
gpp_cmdif_srv_init(void)
{
	srv = cmdif_srv_allocate((void * (*)(int))(malloc),
		(void * (*)(int))(malloc));
	if (srv == NULL)
		return -ENOMEM;

	return 0;
}

static void
gpp_cmdif_srv_free(void)
{
	cmdif_srv_deallocate(srv, free);
	srv = NULL;
}

int
cmdif_register_module(const char *m_name, struct cmdif_module_ops *ops)
{
	int ret;

	/* Place here lock if required */

	if (rte_atomic16_add_return(&module_count, 1) == 1) {
		ret = gpp_cmdif_srv_init();
		if (ret != 0) {
			RTE_LOG(ERR, CMDIF, "CMDIF srv Initalization failed\n");
			return ret;
		}

		ret = cmdif_srv_register(srv, m_name, ops);
		if (ret != 0)
			gpp_cmdif_srv_free();
		return ret;
	}

	return cmdif_srv_register(srv, m_name, ops);
}

int
cmdif_unregister_module(const char *m_name)
{
	int ret;

	/* Place here lock if required */

	ret = cmdif_srv_unregister(srv, m_name);
	if (ret != 0) {
		RTE_LOG(ERR, CMDIF, "cmdif_srv_unregister failed\n");
		return ret;
	}

	if (rte_atomic16_sub_return(&module_count, 1) == 0)
		gpp_cmdif_srv_free();

	return ret;
}

int
cmdif_srv_cb(int pr, void *send_dev)
{
	struct rte_dpaa2_cmdif_context cmdif_rcv_cnxt;
	uint64_t dpci_devid = (uint64_t)(send_dev);
	struct rte_rawdev_buf buf_in, buf_out;
	struct rte_rawdev_buf *recv_buf = &buf_in, *send_buf = &buf_out;
	struct  cmdif_fd cfd_out;
	struct  cmdif_fd cfd;
	uint8_t send_resp = 0;
	int pkt_rcvd;
	int err = 0;

	if (srv == NULL)
		return -ENODEV;

	cmdif_rcv_cnxt.priority = pr;
	pkt_rcvd = rte_rawdev_dequeue_buffers((uint16_t)(dpci_devid),
		&recv_buf, 1, &cmdif_rcv_cnxt);
	if (pkt_rcvd < 0) {
		RTE_LOG(ERR, CMDIF, "Error calling buffer dequeue\n");
		return pkt_rcvd;
	}

	if (pkt_rcvd == 0)
		return -ENODATA;

	cfd.u_addr.d_addr = (uint64_t)buf_in.buf_addr;
	cfd.d_size = cmdif_rcv_cnxt.size;
	cfd.u_frc.frc = cmdif_rcv_cnxt.frc;
	cfd.u_flc.flc = cmdif_rcv_cnxt.flc;

	/* Call ctrl cb; if no perm cfd_out will be invalid */
	err = cmdif_srv_cmd(srv, &cfd, 0, &cfd_out, &send_resp);
	/*
	 * don't bother to send response in order not to overload
	 * response queue, it might be intentional attack
	 */
	if (err) {
		if (err == -EPERM)
			RTE_LOG(ERR, CMDIF, "Got cmd with invalid auth_id\n");
		else if (err == -EINVAL)
			RTE_LOG(ERR, CMDIF, "Inv. parameters for cmdif_srv_cmd\n");
		return err;
	}
	if (send_resp) {
		struct rte_dpaa2_cmdif_context cmdif_send_cnxt;

		buf_out.buf_addr = (void *)cfd_out.u_addr.d_addr;
		cmdif_send_cnxt.size = cfd_out.d_size;
		cmdif_send_cnxt.frc = cfd_out.u_frc.frc;
		cmdif_send_cnxt.flc = cfd_out.u_flc.flc;
		cmdif_send_cnxt.priority = pr;

		err = rte_rawdev_enqueue_buffers((uint16_t)(dpci_devid),
			&send_buf, 1, &cmdif_send_cnxt);
		if (err <= 0) {
			RTE_LOG(ERR, CMDIF, "enqueue of buffer failed\n");
			return err;
		}
	}

	return 0;
}

int
cmdif_session_open(struct cmdif_desc *cidesc,
		   const char *m_name,
		   uint8_t inst_id,
		   uint32_t size,
		   void *v_data,
		   void *send_dev,
		   uint16_t *auth_id)
{
	uint64_t dpci_devid = (uint64_t)(send_dev);
	uint64_t dpci_obj_id;
	int err = 0;

	err = rte_rawdev_get_attr((uint16_t)dpci_devid, NULL, &dpci_obj_id);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif rawdev attribute get failed\n");
		return err;
	}

	/* Place here lock if required */

	/* Call open_cb , Store dev */
	err = cmdif_srv_open(srv, m_name, inst_id, dpci_obj_id, size, v_data,
			auth_id);
	if (err)
		return err;

	/* Send information to AIOP */
	err = cmdif_send(cidesc, CMD_ID_NOTIFY_OPEN, size, CMDIF_PRI_LOW,
			(uint64_t)(v_data), NULL, NULL);

	return err;
}

int
cmdif_session_close(struct cmdif_desc *cidesc,
		    uint16_t auth_id,
		    uint32_t size,
		    void *v_data,
		    void *send_dev)
{
	uint64_t dpci_devid = (uint64_t)(send_dev);
	uint64_t dpci_obj_id;
	int err = 0;

	err = rte_rawdev_get_attr((uint16_t)dpci_devid, NULL, &dpci_obj_id);
	if (err) {
		RTE_LOG(ERR, CMDIF, "cmdif rawdev attribute get failed\n");
		return err;
	}

	/* Place here lock if required */

	/* Call close_cb , place dpci_id, auth_id inside p_data */
	err = cmdif_srv_close(srv, auth_id, dpci_obj_id, size, v_data);
	if (err)
		return err;

	/* Send information to AIOP */
	err = cmdif_send(cidesc, CMD_ID_NOTIFY_CLOSE, size, CMDIF_PRI_LOW,
			(uint64_t)(v_data), NULL, NULL);

	return err;
}
