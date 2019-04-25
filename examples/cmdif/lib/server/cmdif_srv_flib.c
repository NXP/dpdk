/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#include <cmdif.h>
#include <fsl_cmdif_flib_s.h>
#include <fsl_cmdif_client.h>
#include <cmdif_srv_flib.h>

#ifndef ENAVAIL
#define ENAVAIL		119	/*!< Resource not available, or not found */
#endif

#define UNUSED(_x)	((void)(_x))

#define FREE_MODULE    '\0'
#define FREE_INSTANCE  (M_NUM_OF_MODULES)

#define SEND_RESP(CMD)	\
	((!((CMD) & CMDIF_NORESP_CMD)) && ((CMD) != CMD_ID_NOTIFY_CLOSE) && \
		((CMD) != CMD_ID_NOTIFY_OPEN) && ((CMD) & CMDIF_ASYNC_CMD))

#define CTRL_CB(AUTH_ID, CMD_ID, SIZE, DATA) \
	(((struct cmdif_srv *)srv)->ctrl_cb[srv->m_id[AUTH_ID]]\
		(((struct cmdif_srv *)srv)->inst_dev[AUTH_ID], \
	CMD_ID, SIZE, DATA))

#define CLOSE_CB(AUTH_ID) \
	(((struct cmdif_srv *)srv)->close_cb\
		[((struct cmdif_srv *)srv)->m_id[AUTH_ID]] \
		(((struct cmdif_srv *)srv)->inst_dev[AUTH_ID]))

/** Blocking commands don't need response FD */
#define SYNC_CMD(CMD)	\
	((!((CMD) & CMDIF_NORESP_CMD)) && !((CMD) & CMDIF_ASYNC_CMD))

#define IS_VALID_AUTH_ID(ID) \
	((((struct cmdif_srv *)srv)->inst_dev != NULL) && \
		((ID) < M_NUM_OF_INSTANCES) && \
	(((struct cmdif_srv *)srv)->m_id != NULL) && \
	(((struct cmdif_srv *)srv)->m_id[(ID)] < M_NUM_OF_MODULES))

void *
cmdif_srv_allocate(void *(*fast_malloc)(int size),
		   void *(*slow_malloc)(int size))
{
	struct cmdif_srv *srv = fast_malloc(sizeof(struct cmdif_srv));

	if (srv == NULL)
		return NULL;

	/* SHRAM */
	srv->inst_dev  = fast_malloc(sizeof(void *) * M_NUM_OF_INSTANCES);
	srv->m_id      = fast_malloc(M_NUM_OF_INSTANCES);
	srv->ctrl_cb   = fast_malloc(sizeof(ctrl_cb_t *) * M_NUM_OF_MODULES);
	srv->sync_done = fast_malloc(sizeof(uint64_t) * M_NUM_OF_INSTANCES);
	/* DDR */
	srv->m_name    = slow_malloc(sizeof(char[M_NAME_CHARS + 1]) *
				M_NUM_OF_MODULES);
	srv->open_cb   = slow_malloc(sizeof(open_cb_t *) * M_NUM_OF_MODULES);
	srv->close_cb  = slow_malloc(sizeof(close_cb_t *) * M_NUM_OF_MODULES);

	if ((srv->inst_dev == NULL)     || (srv->m_id == NULL)      ||
		(srv->ctrl_cb == NULL)  || (srv->sync_done == NULL) ||
		(srv->m_name == NULL)   || (srv->open_cb == NULL)   ||
		(srv->close_cb == NULL)) {
		return NULL;
	}

	memset((uint8_t *)srv->m_name,
		FREE_MODULE,
		sizeof(srv->m_name[0]) * M_NUM_OF_MODULES);
	memset((uint8_t *)srv->inst_dev,
		0,
		sizeof(srv->inst_dev[0]) * M_NUM_OF_INSTANCES);
	memset(srv->m_id,
		FREE_INSTANCE,
		M_NUM_OF_INSTANCES);

	srv->inst_count = 0;

	return srv;
}

void
cmdif_srv_deallocate(void *_srv, void (*free)(void *ptr))
{
	struct  cmdif_srv *srv = (struct  cmdif_srv *)_srv;

	if (srv != NULL) {
		if (srv->inst_dev)
			free(srv->inst_dev);
		if (srv->m_id)
			free(srv->m_id);
		if (srv->sync_done)
			free(srv->sync_done);
		if (srv->m_name)
			free(srv->m_name);
		if (srv->open_cb)
			free(srv->open_cb);
		if (srv->ctrl_cb)
			free(srv->ctrl_cb);
		if (srv->close_cb)
			free(srv->close_cb);

		free(srv);
	}
}

static int
empty_open_cb(uint8_t instance_id, void **dev)
{
	UNUSED(instance_id);
	UNUSED(dev);
	return -ENODEV; /* Must be error for cmdif_srv_unregister() */
}

static int
empty_close_cb(void *dev)
{
	UNUSED(dev);
	return -ENODEV; /* Must be error for cmdif_srv_unregister() */
}

static int
empty_ctrl_cb(void *dev,
	      uint16_t cmd,
	      uint32_t size,
	      void *data)
{
	UNUSED(cmd);
	UNUSED(dev);
	UNUSED(size);
	UNUSED(data);
	return -ENODEV; /* Must be error for cmdif_srv_unregister() */
}

static int
module_id_alloc(struct cmdif_srv *srv,
		const char *m_name,
		struct cmdif_module_ops *ops)
{
	int i = 0;
	int id = -ENAVAIL;

	if (m_name[0] == FREE_MODULE)
		return -EINVAL;


	for (i = 0; i < M_NUM_OF_MODULES; i++) {
		if ((srv->m_name[i][0] == FREE_MODULE) && (id < 0))
			id = i;
		else if (strncmp(srv->m_name[i], m_name, M_NAME_CHARS) == 0)
			return -EEXIST;
	}
	if (id >= 0) {
		strncpy(srv->m_name[id], m_name, M_NAME_CHARS);
		srv->m_name[id][M_NAME_CHARS] = '\0';

		srv->ctrl_cb[id]  = empty_ctrl_cb;
		srv->open_cb[id]  = empty_open_cb;
		srv->close_cb[id] = empty_close_cb;

		if (ops->ctrl_cb)
			srv->ctrl_cb[id]  = ops->ctrl_cb;
		if (ops->open_cb)
			srv->open_cb[id]  = ops->open_cb;
		if (ops->close_cb)
			srv->close_cb[id] = ops->close_cb;
	}

	return id;
}

static int
module_id_find(struct cmdif_srv *srv, const char *m_name)
{
	int i = 0;

	if (m_name[0] == FREE_MODULE)
		return -EINVAL;

	for (i = 0; i < M_NUM_OF_MODULES; i++) {
		if (strncmp(srv->m_name[i], m_name, M_NAME_CHARS) == 0)
			return i;
	}

	return -ENAVAIL;
}

int
cmdif_srv_register(void *srv,
		   const char *m_name,
		   struct cmdif_module_ops *ops)
{

	int    m_id = 0;

	if ((m_name == NULL) || (ops == NULL) || (srv == NULL))
		return -EINVAL;

	m_id = module_id_alloc((struct cmdif_srv *)srv, m_name, ops);

	if (m_id < 0)
		return m_id;

	return 0;
}

int
cmdif_srv_unregister(void *srv, const char *m_name)
{
	int    m_id = -1;

	if ((m_name == NULL) || (srv == NULL))
		return -EINVAL;

	m_id = module_id_find((struct cmdif_srv *)srv, m_name);
	if (m_id >= 0) {
		((struct cmdif_srv *)srv)->ctrl_cb[m_id]   = empty_ctrl_cb;
		((struct cmdif_srv *)srv)->open_cb[m_id]   = empty_open_cb;
		((struct cmdif_srv *)srv)->close_cb[m_id]  = empty_close_cb;
		((struct cmdif_srv *)srv)->m_name[m_id][0] = FREE_MODULE;
		return 0;
	} else {
		return m_id; /* POSIX error is returned */
	}
}

static int
inst_alloc(struct cmdif_srv *srv, uint8_t m_id)
{
	int r = 0;
	int count = 0;

#ifdef DEBUG
	if (srv == NULL)
		return -EINVAL;
#endif

	r = rand() % M_NUM_OF_INSTANCES;
	while ((srv->m_id[r] != FREE_INSTANCE) &&
		(count < M_NUM_OF_INSTANCES)) {
		r = rand() % M_NUM_OF_INSTANCES;
		count++;
	}

	/* didn't find empty space yet */
	if (srv->m_id[r] != FREE_INSTANCE) {
		count = 0;
		while ((srv->m_id[r] != FREE_INSTANCE) &&
			(count < M_NUM_OF_INSTANCES)) {
			r = r % M_NUM_OF_INSTANCES;
			r++;
			count++;
		}
	}

	/* didn't find empty space */
	if (count >= M_NUM_OF_INSTANCES)
		return -ENAVAIL;

	srv->m_id[r] = m_id;
	srv->inst_count++;
	return r;
}

static void
inst_dealloc(int inst, struct cmdif_srv *srv)
{
	srv->m_id[inst] = FREE_INSTANCE;
	srv->inst_count--;
}

int
cmdif_srv_open(void *_srv,
	       const char *m_name,
	       uint8_t inst_id,
	       uint32_t dpci_id,
	       uint32_t size __rte_unused,
	       void *v_data,
	       uint16_t *auth_id)
{
	int    err = 0;
	int    m_id = 0;
	int    id = 0;
	struct cmdif_srv *srv = (struct cmdif_srv *)_srv;
	struct cmdif_session_data *data = v_data;
	void   *dev = NULL;

#ifdef DEBUG
	if ((uint64_t)v_data & 0x7)
		return -EINVAL;

	if ((v_data != NULL) && (size < CMDIF_SESSION_OPEN_SIZEOF))
		return -EINVAL;

	if (auth_id == NULL)
		return -EINVAL;
#endif

	m_id = module_id_find(srv, m_name);
	if (m_id < 0)
		return m_id;

	err = srv->open_cb[m_id](inst_id, &dev);
	if (err)
		return err;

	id = inst_alloc(srv, (uint8_t)m_id);
	if (id < 0)
		return id;

	srv->inst_dev[id]  = dev;
	srv->sync_done[id] = (uint64_t)v_data;
	*auth_id = (uint16_t)id;

	/* Sending */
	if (data != NULL) {
		data->done    = 0;
		data->err     = 0;
		data->dev_id  = CPU_TO_SRV32(dpci_id);
		data->auth_id = *auth_id;
		data->inst_id = inst_id;
		strncpy(&data->m_name[0], m_name, M_NAME_CHARS);
		data->m_name[M_NAME_CHARS] = '\0';
	}

	return 0;
}

int
cmdif_srv_close(void *srv,
		uint16_t auth_id,
		uint32_t dpci_id,
		uint32_t size __rte_unused,
		void *v_data)
{
	struct cmdif_session_data *data = v_data;

#ifdef DEBUG
	if ((v_data != NULL) && (size < CMDIF_SESSION_OPEN_SIZEOF))
		return -EINVAL;
#endif

	if (!IS_VALID_AUTH_ID(auth_id))
		return -EINVAL;

	CLOSE_CB(auth_id);

	inst_dealloc(auth_id, srv);
	if (data != NULL) {
		data->auth_id = auth_id;
		data->dev_id  = CPU_TO_SRV32(dpci_id); /* 1 DPCI = 1 Server */
	}

	return 0;
}

int
cmdif_srv_cmd(void *_srv,
	      struct cmdif_fd *cfd,
	      void   *v_addr,
	      struct cmdif_fd *cfd_out,
	      uint8_t *send_resp)
{
	int    err = 0;
	struct cmdif_srv *srv = (struct cmdif_srv *)_srv;
	struct cmdif_fd in_cfd;

#ifdef DEBUG
	if ((cfd == NULL) || (srv == NULL) || (send_resp == NULL))
		return -EINVAL;
#endif

	/* This is required because flc is a struct */
	in_cfd.u_flc.flc = CPU_TO_BE64(cfd->u_flc.flc);

	if (!IS_VALID_AUTH_ID(in_cfd.u_flc.cmd.auth_id))
		return -EPERM;

	*send_resp = SEND_RESP(in_cfd.u_flc.cmd.cmid);

	if (*send_resp && (cfd_out == NULL))
		return -EINVAL;

	err = CTRL_CB(in_cfd.u_flc.cmd.auth_id,
		in_cfd.u_flc.cmd.cmid,
		cfd->d_size,
		(void *)((v_addr != NULL) ?
			(uint64_t)(v_addr) : cfd->u_addr.d_addr));

	if (SYNC_CMD(in_cfd.u_flc.cmd.cmid)) {
		if (srv->sync_done[in_cfd.u_flc.cmd.auth_id]) {
			struct cmdif_session_data *sync_done =
				(struct cmdif_session_data *)
				srv->sync_done[in_cfd.u_flc.cmd.auth_id];
			sync_done->err = (int8_t)err;
			sync_done->done = 1;
			sync_done->auth_id = in_cfd.u_flc.cmd.auth_id;
		}

	} else if (*send_resp) {
		*cfd_out = *cfd;
		in_cfd.u_flc.cmd.err = (uint8_t)err;
		cfd_out->u_flc.flc   = CPU_TO_BE64(in_cfd.u_flc.flc);
	}

	return 0;
}
