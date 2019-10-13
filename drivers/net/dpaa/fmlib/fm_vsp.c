/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "fm_ext.h"
#include "fm_pcd_ext.h"
#include "fm_port_ext.h"
#include "fm_vsp_ext.h"
#include <rte_dpaa_logs.h>

uint32_t FM_PORT_VSPAlloc(t_Handle h_FmPort, t_FmPortVSPAllocParams *p_Params)
{
	t_Device *p_Dev = (t_Device *)h_FmPort;
	ioc_fm_port_vsp_alloc_params_t params;

	_fml_dbg("Calling...\n");
	memset(&params, 0, sizeof(ioc_fm_port_vsp_alloc_params_t));
	memcpy(&params.params, p_Params, sizeof(t_FmPortVSPAllocParams));

	if (ioctl(p_Dev->fd, FM_PORT_IOC_VSP_ALLOC, &params))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Called.\n");

	return E_OK;
}

t_Handle FM_VSP_Config(t_FmVspParams *p_FmVspParams)
{
	t_Device *p_Dev = NULL;
	t_Device *p_VspDev = NULL;
	ioc_fm_vsp_params_t param;

	p_Dev = p_FmVspParams->h_Fm;

	_fml_dbg("Performing VSP Configuration...\n");

	memset(&param, 0, sizeof(ioc_fm_vsp_params_t));
	memcpy(&param, p_FmVspParams, sizeof(t_FmVspParams));
	param.vsp_params.h_Fm = UINT_TO_PTR(p_Dev->id);
	param.id = NULL;

	if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG, &param)) {
		DPAA_PMD_ERR("%s ioctl error\n", __func__);
		return NULL;
	}

	p_VspDev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_VspDev) {
		DPAA_PMD_ERR("FM VSP Params!\n");
		return NULL;
	}
	memset(p_VspDev, 0, sizeof(t_Device));
	p_VspDev->h_UserPriv = (t_Handle)p_Dev;
	p_Dev->owners++;
	p_VspDev->id = PTR_TO_UINT(param.id);

	_fml_dbg("VSP Configuration completed\n");

	return (t_Handle)p_VspDev;
}

uint32_t FM_VSP_Init(t_Handle h_FmVsp)
{
	t_Device *p_Dev = NULL;
	t_Device *p_VspDev = (t_Device *)h_FmVsp;
	ioc_fm_obj_t id;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)p_VspDev->h_UserPriv;
	id.obj = UINT_TO_PTR(p_VspDev->id);

	if (ioctl(p_Dev->fd, FM_IOC_VSP_INIT, &id)) {
		DPAA_PMD_ERR("%s ioctl error\n", __func__);
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
	}

	_fml_dbg("Called.\n");

	return E_OK;
}

uint32_t FM_VSP_Free(t_Handle h_FmVsp)
{
	t_Device *p_Dev = NULL;
	t_Device *p_VspDev = (t_Device *)h_FmVsp;
	ioc_fm_obj_t id;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)p_VspDev->h_UserPriv;
	id.obj = UINT_TO_PTR(p_VspDev->id);

	if (ioctl(p_Dev->fd, FM_IOC_VSP_FREE, &id)) {
		DPAA_PMD_ERR("%s ioctl error\n", __func__);
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
	}

	p_Dev->owners--;
	free(p_VspDev);

	_fml_dbg("Called.\n");

	return E_OK;
}

uint32_t FM_VSP_ConfigBufferPrefixContent(t_Handle h_FmVsp,
		t_FmBufferPrefixContent *p_FmBufferPrefixContent)
{
	t_Device *p_Dev = NULL;
	t_Device *p_VspDev = (t_Device *)h_FmVsp;
	ioc_fm_buffer_prefix_content_params_t params;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)p_VspDev->h_UserPriv;
	params.p_fm_vsp = UINT_TO_PTR(p_VspDev->id);
	memcpy(&params.fm_buffer_prefix_content,
	       p_FmBufferPrefixContent, sizeof(*p_FmBufferPrefixContent));

	if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG_BUFFER_PREFIX_CONTENT,
		  &params)) {
		DPAA_PMD_ERR("%s ioctl error\n", __func__);
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
	}

	_fml_dbg("Called.\n");

	return E_OK;
}
