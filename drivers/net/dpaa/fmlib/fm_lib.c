/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 * Copyright 2017-2019 NXP
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
#include <rte_dpaa_logs.h>

#define DEV_TO_ID(p) \
	do { \
	t_Device *p_Dev = (t_Device *)p; \
	p = UINT_TO_PTR(p_Dev->id); \
	} while (0)

/* Major and minor are in sync with FMD, respin is for fmlib identification */
#define FM_LIB_VERSION_MAJOR	21
#define FM_LIB_VERSION_MINOR	1
#define FM_LIB_VERSION_RESPIN	0

#if (FMD_API_VERSION_MAJOR != FM_LIB_VERSION_MAJOR) || \
	(FMD_API_VERSION_MINOR != FM_LIB_VERSION_MINOR)
#warning FMD and FMLIB version mismatch
#endif

uint32_t FM_GetApiVersion(t_Handle h_Fm, ioc_fm_api_version_t *p_version);

/*******************************************************************************
*  FM FUNCTIONS								*
*******************************************************************************/

t_Handle FM_Open(uint8_t id)
{
	t_Device	*p_Dev;
	int	fd;
	char	devName[20];
	static bool called;
	ioc_fm_api_version_t ver;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(devName, 0, 20);
	sprintf(devName, "%s%s%d", "/dev/", DEV_FM_NAME, id);
	fd = open(devName, O_RDWR);
	if (fd < 0) {
		free(p_Dev);
		return NULL;
	}

	p_Dev->id = id;
	p_Dev->fd = fd;
	if (!called) {
		called = true;
		FM_GetApiVersion((t_Handle)p_Dev, &ver);

		if (FMD_API_VERSION_MAJOR != ver.version.major ||
		    FMD_API_VERSION_MINOR != ver.version.minor ||
			FMD_API_VERSION_RESPIN != ver.version.respin) {
			DPAA_PMD_WARN("Compiled against FMD API ver %u.%u.%u",
				      FMD_API_VERSION_MAJOR,
				FMD_API_VERSION_MINOR, FMD_API_VERSION_RESPIN);
			DPAA_PMD_WARN("Running with FMD API ver %u.%u.%u",
				      ver.version.major, ver.version.minor,
				ver.version.respin);
		}
	}
	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

void FM_Close(t_Handle h_Fm)
{
	t_Device	*p_Dev = (t_Device *)h_Fm;

	_fml_dbg("Calling...\n");

	close(p_Dev->fd);
	free(p_Dev);

	_fml_dbg("Finishing.\n");
}

uint32_t  FM_GetApiVersion(t_Handle h_Fm, ioc_fm_api_version_t *p_version)
{
	t_Device			*p_Dev = (t_Device *)h_Fm;
	int ret;

	_fml_dbg("Calling...\n");

	ret = ioctl(p_Dev->fd, FM_IOC_GET_API_VERSION, p_version);
	if (ret) {
		DPAA_PMD_ERR("cannot get API version, error %i (%s)\n",
			     errno, strerror(errno));
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
	}
	_fml_dbg("Finishing.\n");

	return E_OK;
}

/********************************************************************************************/
/*  FM_PCD FUNCTIONS								*/
/********************************************************************************************/

t_Handle FM_PCD_Open(t_FmPcdParams *p_FmPcdParams)
{
	t_Device	*p_Dev;
	int	fd;
	char	devName[20];

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(devName, 0, 20);
	sprintf(devName, "%s%s%u-pcd", "/dev/", DEV_FM_NAME,
		(uint32_t)((t_Device *)p_FmPcdParams->h_Fm)->id);
	fd = open(devName, O_RDWR);
	if (fd < 0) {
		free(p_Dev);
		return NULL;
	}

	p_Dev->id = ((t_Device *)p_FmPcdParams->h_Fm)->id;
	p_Dev->fd = fd;
	p_Dev->owners = 0;

	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

void FM_PCD_Close(t_Handle h_FmPcd)
{
	t_Device *p_Dev = (t_Device *)h_FmPcd;

	_fml_dbg("Calling...\n");

	close(p_Dev->fd);

	if (p_Dev->owners) {
		printf(
		"\nTrying to delete a previously created pcd handler(owners:%u)!!\n",
		p_Dev->owners);
		return;
	}

	free(p_Dev);

	_fml_dbg("Finishing.\n");
}

uint32_t FM_PCD_Enable(t_Handle h_FmPcd)
{
	t_Device *p_Dev = (t_Device *)h_FmPcd;

	_fml_dbg("Calling...\n");

	if (ioctl(p_Dev->fd, FM_PCD_IOC_ENABLE))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

uint32_t FM_PCD_Disable(t_Handle h_FmPcd)
{
	t_Device	*p_Dev = (t_Device *)h_FmPcd;

	_fml_dbg("Calling...\n");

	if (ioctl(p_Dev->fd, FM_PCD_IOC_DISABLE))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

t_Handle FM_PCD_NetEnvCharacteristicsSet(t_Handle h_FmPcd, ioc_fm_pcd_net_env_params_t *params)
{
	t_Device *p_PcdDev = (t_Device *)h_FmPcd;
	t_Device *p_Dev = NULL;

	_fml_dbg("Calling...\n");

	params->id = NULL;

	if (ioctl(p_PcdDev->fd, FM_PCD_IOC_NET_ENV_CHARACTERISTICS_SET, params))
		return NULL;

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(p_Dev, 0, sizeof(t_Device));
	p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
	p_PcdDev->owners++;
	p_Dev->id = PTR_TO_UINT(params->id);

	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

uint32_t FM_PCD_NetEnvCharacteristicsDelete(t_Handle h_NetEnv)
{
	t_Device *p_Dev = (t_Device *)h_NetEnv;
	t_Device *p_PcdDev = NULL;
	ioc_fm_obj_t id;

	_fml_dbg("Calling...\n");

	p_PcdDev = (t_Device *)p_Dev->h_UserPriv;
	id.obj = UINT_TO_PTR(p_Dev->id);

	if (ioctl(p_PcdDev->fd, FM_PCD_IOC_NET_ENV_CHARACTERISTICS_DELETE, &id))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	p_PcdDev->owners--;
	free(p_Dev);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

t_Handle FM_PCD_KgSchemeSet(t_Handle h_FmPcd, ioc_fm_pcd_kg_scheme_params_t *params)
{
	t_Device *p_PcdDev = (t_Device *)h_FmPcd;
	t_Device *p_Dev = NULL;
	int ret;

	_fml_dbg("Calling...\n");

	params->id = NULL;

	if (params->param.modify) {
		if (params->param.scm_id.scheme_id)
			DEV_TO_ID(params->param.scm_id.scheme_id);
		else
			return NULL;
	}

	/* correct h_NetEnv param from scheme */
	if (params->param.net_env_params.net_env_id)
		DEV_TO_ID(params->param.net_env_params.net_env_id);

	/* correct next engine params handlers: cc*/
	if (params->param.next_engine == e_IOC_FM_PCD_CC &&
	    params->param.kg_next_engine_params.cc.tree_id)
		DEV_TO_ID(params->param.kg_next_engine_params.cc.tree_id);

	ret = ioctl(p_PcdDev->fd, FM_PCD_IOC_KG_SCHEME_SET, params);
	if (ret) {
		DPAA_PMD_ERR("  cannot set kg scheme, error %i (%s)\n",
			     errno, strerror(errno));
		return NULL;
	}

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(p_Dev, 0, sizeof(t_Device));
	p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
	/* increase owners only if a new scheme is created */
	if (params->param.modify == false)
		p_PcdDev->owners++;
	p_Dev->id = PTR_TO_UINT(params->id);

	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

uint32_t FM_PCD_KgSchemeDelete(t_Handle h_Scheme)
{
	t_Device *p_Dev = (t_Device *)h_Scheme;
	t_Device *p_PcdDev = NULL;
	ioc_fm_obj_t id;

	_fml_dbg("Calling...\n");

	p_PcdDev =  (t_Device *)p_Dev->h_UserPriv;
	id.obj = UINT_TO_PTR(p_Dev->id);

	if (ioctl(p_PcdDev->fd, FM_PCD_IOC_KG_SCHEME_DELETE, &id)) {
		DPAA_PMD_WARN("cannot delete kg scheme, error %i (%s)\n",
			      errno, strerror(errno));
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
	}

	p_PcdDev->owners--;
	free(p_Dev);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

#ifdef FM_CAPWAP_SUPPORT
#error CAPWAP feature not supported
#endif

typedef struct {
	e_FmPortType	portType;	/**< Port type */
	uint8_t		portId;		/**< Port Id - relative to type */
} t_FmPort;

/********************************************************************************************/
/*  FM_PORT FUNCTIONS								*/
/********************************************************************************************/

t_Handle FM_PORT_Open(t_FmPortParams *p_FmPortParams)
{
	t_Device	*p_Dev;
	int	fd;
	char	devName[30];
	t_FmPort	*p_FmPort;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(p_Dev, 0, sizeof(t_Device));

	p_FmPort = (t_FmPort *)malloc(sizeof(t_FmPort));
	if (!p_FmPort) {
		free(p_Dev);
		return NULL;
	}
	memset(p_FmPort, 0, sizeof(t_FmPort));
	memset(devName, 0, sizeof(devName));
	switch (p_FmPortParams->portType) {
	case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
		sprintf(devName, "%s%s%u-port-oh%d", "/dev/", DEV_FM_NAME,
			(uint32_t)((t_Device *)p_FmPortParams->h_Fm)->id,
			p_FmPortParams->portId);
		break;
	case e_FM_PORT_TYPE_RX:
		sprintf(devName, "%s%s%u-port-rx%d", "/dev/", DEV_FM_NAME,
			(uint32_t)((t_Device *)p_FmPortParams->h_Fm)->id,
			p_FmPortParams->portId);
		break;
	case e_FM_PORT_TYPE_RX_10G:
		sprintf(devName, "%s%s%u-port-rx%d", "/dev/", DEV_FM_NAME,
			(uint32_t)((t_Device *)p_FmPortParams->h_Fm)->id,
			FM_MAX_NUM_OF_1G_RX_PORTS + p_FmPortParams->portId);
		break;
	case e_FM_PORT_TYPE_TX:
		sprintf(devName, "%s%s%u-port-tx%d", "/dev/", DEV_FM_NAME,
			(uint32_t)((t_Device *)p_FmPortParams->h_Fm)->id,
			p_FmPortParams->portId);
		break;
	case e_FM_PORT_TYPE_TX_10G:
		sprintf(devName, "%s%s%u-port-tx%d", "/dev/", DEV_FM_NAME,
			(uint32_t)((t_Device *)p_FmPortParams->h_Fm)->id,
			FM_MAX_NUM_OF_1G_TX_PORTS + p_FmPortParams->portId);
		break;
	default:
		free(p_FmPort);
		free(p_Dev);
		return NULL;
	}

	fd = open(devName, O_RDWR);
	if (fd < 0) {
		free(p_FmPort);
		free(p_Dev);
		return NULL;
	}

	p_FmPort->portType = p_FmPortParams->portType;
	p_FmPort->portId = p_FmPortParams->portId;
	p_Dev->id = p_FmPortParams->portId;
	p_Dev->fd = fd;
	p_Dev->h_UserPriv = (t_Handle)p_FmPort;

	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

void FM_PORT_Close(t_Handle h_FmPort)
{
	t_Device	*p_Dev = (t_Device *)h_FmPort;

	_fml_dbg("Calling...\n");

	close(p_Dev->fd);
	if (p_Dev->h_UserPriv)
		free(p_Dev->h_UserPriv);
	free(p_Dev);

	_fml_dbg("Finishing.\n");
}

uint32_t FM_PORT_Disable(t_Handle h_FmPort)
{
	t_Device	*p_Dev = (t_Device *)h_FmPort;

	_fml_dbg("Calling...\n");

	if (ioctl(p_Dev->fd, FM_PORT_IOC_DISABLE))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

uint32_t FM_PORT_Enable(t_Handle h_FmPort)
{
	t_Device	*p_Dev = (t_Device *)h_FmPort;

	_fml_dbg("Calling...\n");

	if (ioctl(p_Dev->fd, FM_PORT_IOC_ENABLE))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

uint32_t FM_PORT_SetPCD(t_Handle h_FmPort, ioc_fm_port_pcd_params_t *params)
{
	t_Device *p_Dev = (t_Device *)h_FmPort;

	_fml_dbg("Calling...\n");

	/* correct h_NetEnv param from t_FmPortPcdParams */
	DEV_TO_ID(params->net_env_id);

	/* correct pcd structures according to what support was set */
	if (params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_CC) {
		if (params->p_cc_params && params->p_cc_params->cc_tree_id)
			DEV_TO_ID(params->p_cc_params->cc_tree_id);
		else
			DPAA_PMD_WARN("Coarse Clasification not set !");
	}

	if (params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR){
		if (params->p_kg_params) {
			uint32_t i;

			for (i = 0; i < params->p_kg_params->num_of_schemes; i++)
				if (params->p_kg_params->scheme_ids[i])
					DEV_TO_ID(params->p_kg_params->scheme_ids[i]);
				else
					DPAA_PMD_WARN("Scheme:%u not set!!", i);

			if (params->p_kg_params && params->p_kg_params->direct_scheme)
				DEV_TO_ID(params->p_kg_params->direct_scheme_id);
		} else {
			DPAA_PMD_WARN("KeyGen not set !");
		}
	}

	if (params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PLCR_ONLY ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
		params->pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR) {
		if (params->p_plcr_params) {
			if (params->p_plcr_params->plcr_profile_id)
				DEV_TO_ID(params->p_plcr_params->plcr_profile_id);
			else
				DPAA_PMD_WARN("Policer not set !");
		}
	}

	if (params->p_ip_reassembly_manip)
		DEV_TO_ID(params->p_ip_reassembly_manip);

#if (DPAA_VERSION >= 11)
	if (params->p_capwap_reassembly_manip)
		DEV_TO_ID(params->p_capwap_reassembly_manip);
#endif

	if (ioctl(p_Dev->fd, FM_PORT_IOC_SET_PCD, params))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

uint32_t FM_PORT_DeletePCD(t_Handle h_FmPort)
{
	t_Device *p_Dev = (t_Device *)h_FmPort;

	_fml_dbg("Calling...\n");

	if (ioctl(p_Dev->fd, FM_PORT_IOC_DELETE_PCD))
		RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

	_fml_dbg("Finishing.\n");

	return E_OK;
}

t_Handle CreateDevice(t_Handle h_UserPriv, t_Handle h_DevId)
{
	t_Device *p_UserPrivDev = (t_Device *)h_UserPriv;
	t_Device *p_Dev = NULL;

	_fml_dbg("Calling...\n");

	p_Dev = (t_Device *)malloc(sizeof(t_Device));
	if (!p_Dev)
		return NULL;

	memset(p_Dev, 0, sizeof(t_Device));
	p_Dev->h_UserPriv = h_UserPriv;
	p_UserPrivDev->owners++;
	p_Dev->id = PTR_TO_UINT(h_DevId);

	_fml_dbg("Finishing.\n");

	return (t_Handle)p_Dev;
}

t_Handle GetDeviceId(t_Handle h_Dev)
{
	t_Device *p_Dev = (t_Device *)h_Dev;

	return (t_Handle)p_Dev->id;
}

#if defined FMAN_V3H
void Platform_is_FMAN_V3H(void)
{
}
#elif defined FMAN_V3L
void Platform_is_FMAN_V3L(void)
{
}
#endif
