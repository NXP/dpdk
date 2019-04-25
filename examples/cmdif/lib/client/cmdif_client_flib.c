/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#include <cmdif.h>
#include <fsl_cmdif_flib_c.h>
#include <cmdif_client_flib.h>

#define IS_VLD_OPEN_SIZE(SIZE) \
	((SIZE) >= CMDIF_OPEN_SIZEOF)

/** Server special command indication */
#define SPECIAL_CMD	0xC000

/** Blocking commands don't need response FD */
#define SYNC_CMD(CMD)	\
	(!((CMD) & (CMDIF_NORESP_CMD | CMDIF_ASYNC_CMD)) || (CMD & SPECIAL_CMD))


int
cmdif_is_sync_cmd(uint16_t cmd_id)
{
	return SYNC_CMD(cmd_id);
}

int
cmdif_open_cmd(struct cmdif_desc *cidesc,
	       const char *m_name,
	       uint8_t instance_id,
	       uint8_t *v_data,
	       uint64_t p_data,
	       uint32_t size,
	       struct cmdif_fd *fd)
{
	uint64_t p_addr = 0;
	int      i = 0;
	union  cmdif_data *v_addr = NULL;
	struct cmdif_dev  *dev = NULL;

#ifdef DEBUG
	/*
	 * if cidesc->dev != NULL it's ok,
	 * it's useful to keep it in order to let user to free this buffer
	 */
	if ((m_name == NULL)
		|| (cidesc == NULL)
		|| (v_data == NULL)
		|| (p_data == 0)
		|| (p_data & 0x7) /* must be 8 byte aligned */
		|| ((uint64_t)v_data & 0x7))/* must be 8 byte aligned */
		return -EINVAL;
#endif

	if (!IS_VLD_OPEN_SIZE(size))
		return -ENOMEM;

	memset(v_data, 0, size);

	p_addr = p_data + sizeof(struct cmdif_dev);
	v_addr = (union cmdif_data *)(v_data + sizeof(struct cmdif_dev));

	fd->u_flc.flc          = 0;
	fd->u_flc.open.cmid    = CPU_TO_SRV16(CMD_ID_OPEN);
	fd->u_flc.open.auth_id = CPU_TO_SRV16(OPEN_AUTH_ID);
	fd->u_flc.open.inst_id = instance_id;
	fd->u_flc.open.epid    = CPU_TO_BE16(CMDIF_EPID); /* Used by HW */
	fd->u_frc.frc          = 0;
	fd->u_addr.d_addr      = p_addr;
	fd->d_size             = sizeof(union cmdif_data);

	dev = (struct cmdif_dev *)v_data;
	dev->sync_done = v_addr;
	cidesc->dev    = (void *)dev;

	v_addr->send.done = 0;
	/* 8 characters module name terminated by \0*/
	while ((m_name[i] != '\0') && (i < M_NAME_CHARS)) {
		v_addr->send.m_name[i] = m_name[i];
		i++;
	}
	if (i < M_NAME_CHARS)
		v_addr->send.m_name[i] = '\0';

	/* This is required because flc is a struct */
	fd->u_flc.flc = CPU_TO_BE64(fd->u_flc.flc);

	return 0;
}

int
cmdif_sync_ready(struct cmdif_desc *cidesc)
{
	struct cmdif_dev *dev = NULL;

#ifdef DEBUG
	if ((cidesc == NULL) || (cidesc->dev == NULL) ||
		(((struct cmdif_dev *)cidesc->dev)->sync_done == NULL))
		return 0; /* Don't use POSIX on purpose */
#endif

	dev = (struct cmdif_dev *)cidesc->dev;

	return ((union  cmdif_data *)(dev->sync_done))->resp.done;
}

int
cmdif_sync_cmd_done(struct cmdif_desc *cidesc)
{
	struct cmdif_dev *dev = NULL;
	int    err = 0;

#ifdef DEBUG
	if ((cidesc == NULL) || (cidesc->dev == NULL) ||
		(((struct cmdif_dev *)cidesc->dev)->sync_done == NULL))
		return -EINVAL;
#endif

	dev = (struct cmdif_dev *)cidesc->dev;
	err = ((union  cmdif_data *)(dev->sync_done))->resp.err;
	((union  cmdif_data *)(dev->sync_done))->resp.done = 0;

	return err;
}

int
cmdif_open_done(struct cmdif_desc *cidesc)
{
	struct cmdif_dev *dev = NULL;

#ifdef DEBUG
	if ((cidesc == NULL) || (cidesc->dev == NULL) ||
		(((struct cmdif_dev *)cidesc->dev)->sync_done == NULL))
		return -EINVAL;
#endif

	dev = (struct cmdif_dev *)cidesc->dev;
	dev->auth_id = ((union  cmdif_data *)(dev->sync_done))->resp.auth_id;

	return cmdif_sync_cmd_done(cidesc);
}

int
cmdif_close_cmd(struct cmdif_desc *cidesc, struct cmdif_fd *fd)
{
	struct cmdif_dev *dev = NULL;

#ifdef DEBUG
	if ((cidesc == NULL) || (cidesc->dev == NULL))
		return -EINVAL;
#endif

	dev = (struct cmdif_dev *)cidesc->dev;

	fd->u_addr.d_addr       = 0;
	fd->d_size              = 0;
	fd->u_flc.flc           = 0;
	fd->u_flc.close.cmid    = CPU_TO_SRV16(CMD_ID_CLOSE);
	fd->u_flc.close.auth_id = dev->auth_id;
	fd->u_flc.close.epid    = CPU_TO_BE16(CMDIF_EPID); /* Used by HW */

	/* This is required because flc is a struct */
	fd->u_flc.flc = CPU_TO_BE64(fd->u_flc.flc);

	return 0;
}

int
cmdif_close_done(struct cmdif_desc *cidesc)
{
	return cmdif_sync_cmd_done(cidesc);
}

static inline void
async_cb_get(struct cmdif_fd *fd, cmdif_cb_t **async_cb,
	     void **async_ctx)
{
	void *async_data = (void *)CMDIF_ASYNC_ADDR_GET(fd->u_addr.d_addr,
							fd->d_size);
	struct cmdif_async temp;

	memcpy(&temp, async_data, sizeof(temp));

	*async_cb  = (cmdif_cb_t *)temp.async_cb;
	*async_ctx = (void *)temp.async_ctx;

}

static inline void
async_cb_set(struct cmdif_fd *fd,
	     cmdif_cb_t *async_cb, void *async_ctx)
{
	void *async_data = (void *)CMDIF_ASYNC_ADDR_GET(fd->u_addr.d_addr,
							fd->d_size);
	struct cmdif_async temp;

	temp.async_cb = (uint64_t)async_cb;
	temp.async_ctx = (uint64_t)async_ctx;

	memcpy(async_data, &temp, sizeof(temp));
}

int
cmdif_cmd(struct cmdif_desc *cidesc,
	  uint16_t cmd_id,
	  uint32_t size,
	  uint64_t data,
	  cmdif_cb_t *async_cb,
	  void *async_ctx,
	  struct cmdif_fd *fd)
{
	struct cmdif_dev *dev = NULL;

#ifdef DEBUG
	if ((cidesc == NULL) || (cidesc->dev == NULL))
		return -EINVAL;
	if ((cmd_id & CMDIF_ASYNC_CMD) && (size < sizeof(struct cmdif_async)))
		return -EINVAL;
	if ((data == 0) && (size > 0))
		return -EINVAL;
#endif

	dev = (struct cmdif_dev *)cidesc->dev;

	if (cmd_id & CMDIF_ASYNC_CMD) {
		CMDIF_CMD_FD_SET(fd, dev, data,
			(size - sizeof(struct cmdif_async)), cmd_id);
		async_cb_set(fd, async_cb, async_ctx);
	} else {
		CMDIF_CMD_FD_SET(fd, dev, data, size, cmd_id);
	}

	return 0;
}

int
cmdif_async_cb(struct cmdif_fd *fd)
{
	cmdif_cb_t *async_cb      = NULL;
	void       *async_ctx     = NULL;
	uint16_t   cmd_id         = 0;

#ifdef DEBUG
	if (fd == NULL)
		return -EINVAL;
#endif

	/*
	 * This is required because flc is a struct but HW treats it as
	 * 8 byte LE.
	 * Therefore if CPU is LE which means that swap is not done
	 * by QMAN driver, we need to do it here
	 */
	fd->u_flc.flc = CPU_TO_BE64(fd->u_flc.flc);
	cmd_id = CPU_TO_SRV16(fd->u_flc.cmd.cmid);

#ifdef DEBUG
	if (!(cmd_id & CMDIF_ASYNC_CMD) || (fd->u_addr.d_addr == 0))
		return -EINVAL;
#endif

	async_cb_get(fd, &async_cb, &async_ctx);

	if (async_cb == NULL)
		return -EINVAL;

	return async_cb(async_ctx,
		fd->u_flc.cmd.err,
		cmd_id,
		fd->d_size,
		(fd->d_size ? (void *)fd->u_addr.d_addr : NULL));
}
