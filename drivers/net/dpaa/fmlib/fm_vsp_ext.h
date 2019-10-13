/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright 2008-2012 Freescale Semiconductor, Inc
 * Copyright 2019 NXP
 *
 */

/**************************************************************************//**
 @File          fm_vsp_ext.h

 @Description   FM Virtual Storage-Profile ...
*//***************************************************************************/
#ifndef __FM_VSP_EXT_H
#define __FM_VSP_EXT_H
#include "ncsw_ext.h"
#include "fm_ext.h"
#include "net_ext.h"

typedef struct t_FmVspParams {
	t_Handle	h_Fm;	/**< A handle to the FM object this VSP related to */
	t_FmExtPools	extBufPools;	/**< Which external buffer pools are used
								(up to FM_PORT_MAX_NUM_OF_EXT_POOLS), and their sizes.
								parameter associated with Rx / OP port */
	uint16_t	liodnOffset;	/**< VSP's LIODN offset */
	struct {
		e_FmPortType	portType;           /**< Port type */
		uint8_t	portId;             /**< Port Id - relative to type */
	} portParams;
	uint8_t	relativeProfileId;  /**< VSP Id - relative to VSP's range
								defined in relevant FM object */
} t_FmVspParams;

typedef struct ioc_fm_vsp_params_t {
	struct t_FmVspParams vsp_params;
	void		*id;		/**< return value */
} ioc_fm_vsp_params_t;

typedef struct t_FmPortVSPAllocParams {
	uint8_t     numOfProfiles;	/**< Number of Virtual Storage Profiles; must be a power of 2 */
	uint8_t     dfltRelativeId;		/**< The default Virtual-Storage-Profile-id dedicated to Rx/OP port
								The same default Virtual-Storage-Profile-id will be for coupled Tx port
								if relevant function called for Rx port */
} t_FmPortVSPAllocParams;

typedef struct ioc_fm_port_vsp_alloc_params_t {
	struct t_FmPortVSPAllocParams params;
	void	*p_fm_tx_port;		/**< Handle to coupled Tx Port; not relevant for OP port. */
} ioc_fm_port_vsp_alloc_params_t;

typedef struct ioc_fm_buffer_prefix_content_t {
	uint16_t priv_data_size; /**< Number of bytes to be left at the beginning
							of the external buffer; Note that the private-area will
							start from the base of the buffer address. */
	bool pass_prs_result; /**< TRUE to pass the parse result to/from the FM;
							User may use FM_PORT_GetBufferPrsResult() in order to
							get the parser-result from a buffer. */
	bool pass_time_stamp; /**< TRUE to pass the timeStamp to/from the FM
							User may use FM_PORT_GetBufferTimeStamp() in order to
							get the parser-result from a buffer. */
	bool pass_hash_result; /**< TRUE to pass the KG hash result to/from the FM
							User may use FM_PORT_GetBufferHashResult() in order to
							get the parser-result from a buffer. */
	bool pass_all_other_pcd_info; /**< Add all other Internal-Context information:
								AD, hash-result, key, etc. */
	uint16_t data_align; /**< 0 to use driver's default alignment [64],
						other value for selecting a data alignment (must be a power of 2);
						if write optimization is used, must be >= 16. */
	uint8_t manip_extra_space; /**< Maximum extra size needed (insertion-size minus removal-size);
								Note that this field impacts the size of the buffer-prefix
								(i.e. it pushes the data offset);
								This field is irrelevant if DPAA_VERSION==10 */
} ioc_fm_buffer_prefix_content_t;

typedef struct ioc_fm_buffer_prefix_content_params_t {
	void    *p_fm_vsp;
	ioc_fm_buffer_prefix_content_t fm_buffer_prefix_content;
} ioc_fm_buffer_prefix_content_params_t;

uint32_t FM_PORT_VSPAlloc(
		t_Handle h_FmPort,
		t_FmPortVSPAllocParams *p_Params);

t_Handle FM_VSP_Config(t_FmVspParams *p_FmVspParams);

uint32_t FM_VSP_Init(t_Handle h_FmVsp);

uint32_t FM_VSP_Free(t_Handle h_FmVsp);

uint32_t FM_VSP_ConfigBufferPrefixContent(t_Handle h_FmVsp,
		t_FmBufferPrefixContent *p_FmBufferPrefixContent);

#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_VSP_ALLOC_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(38), ioc_compat_fm_port_vsp_alloc_params_t)
#endif
#define FM_PORT_IOC_VSP_ALLOC _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(38), ioc_fm_port_vsp_alloc_params_t)

#if defined(CONFIG_COMPAT)
#define FM_IOC_VSP_CONFIG_COMPAT	_IOWR(FM_IOC_TYPE_BASE, FM_IOC_NUM(8), ioc_compat_fm_vsp_params_t)
#endif
#define FM_IOC_VSP_CONFIG	_IOWR(FM_IOC_TYPE_BASE, FM_IOC_NUM(8), ioc_fm_vsp_params_t)

#if defined(CONFIG_COMPAT)
#define FM_IOC_VSP_INIT_COMPAT	_IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(9), ioc_compat_fm_obj_t)
#endif
#define FM_IOC_VSP_INIT	_IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(9), ioc_fm_obj_t)

#if defined(CONFIG_COMPAT)
#define FM_IOC_VSP_FREE_COMPAT	_IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(10), ioc_compat_fm_obj_t)
#endif
#define FM_IOC_VSP_FREE	_IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(10), ioc_fm_obj_t)

#if defined(CONFIG_COMPAT)
#define FM_IOC_VSP_CONFIG_BUFFER_PREFIX_CONTENT_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(12), ioc_compat_fm_buffer_prefix_content_params_t)
#endif
#define FM_IOC_VSP_CONFIG_BUFFER_PREFIX_CONTENT _IOW(FM_IOC_TYPE_BASE, FM_IOC_NUM(12), ioc_fm_buffer_prefix_content_params_t)

#endif /* __FM_VSP_EXT_H */
