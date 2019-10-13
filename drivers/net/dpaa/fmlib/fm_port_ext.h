/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 * Copyright 2017-2019 NXP
 */

#ifndef __FM_PORT_EXT_H
#define __FM_PORT_EXT_H

#include <errno.h>
#include "ncsw_ext.h"
#include "fm_pcd_ext.h"
#include "fm_ext.h"
#include "net_ext.h"
#include "dpaa_integration.h"

/******************************************************************************
 @Description   FM Port routines
*//***************************************************************************/

/**************************************************************************//**

 @Group	lnx_ioctl_FM_grp Frame Manager Linux IOCTL API

 @Description   FM Linux ioctls definitions and enums

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group	lnx_ioctl_FM_PORT_grp FM Port

 @Description   FM Port API

	The FM uses a general module called "port" to represent a Tx port
	(MAC), an Rx port (MAC), offline parsing flow or host command
	flow. There may be up to 17 (may change) ports in an FM - 5 Tx
	ports (4 for the 1G MACs, 1 for the 10G MAC), 5 Rx Ports, and 7
	Host command/Offline parsing ports. The SW driver manages these
	ports as sub-modules of the FM, i.e. after an FM is initialized,
	its ports may be initialized and operated upon.

	The port is initialized aware of its type, but other functions on
	a port may be indifferent to its type. When necessary, the driver
	verifies coherency and returns error if applicable.

	On initialization, user specifies the port type and it's index
	(relative to the port's type). Host command and Offline parsing
	ports share the same id range, I.e user may not initialized host
	command port 0 and offline parsing port 0.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   An enum for defining port PCD modes.
	(Must match enum e_FmPortPcdSupport defined in fm_port_ext.h)

	This enum defines the superset of PCD engines support - i.e. not
	all engines have to be used, but all have to be enabled. The real
	flow of a specific frame depends on the PCD configuration and the
	frame headers and payload.
	Note: the first engine and the first engine after the parser (if
	exists) should be in order, the order is important as it will
	define the flow of the port. However, as for the rest engines
	(the ones that follows), the order is not important anymore as
	it is defined by the PCD graph itself.
*//***************************************************************************/
typedef enum ioc_fm_port_pcd_support {
	e_IOC_FM_PORT_PCD_SUPPORT_NONE = 0	/**< BMI to BMI, PCD is not used */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_ONLY	/**< Use only Parser */
	, e_IOC_FM_PORT_PCD_SUPPORT_PLCR_ONLY	/**< Use only Policer */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR	/**< Use Parser and Policer */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG	/**< Use Parser and Keygen */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC	/**< Use Parser, Keygen and Coarse Classification */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR
			/**< Use all PCD engines */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR	/**< Use Parser, Keygen and Policer */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_CC	/**< Use Parser and Coarse Classification */
	, e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_CC_AND_PLCR	/**< Use Parser and Coarse Classification and Policer */
	, e_IOC_FM_PORT_PCD_SUPPORT_CC_ONLY	/**< Use only Coarse Classification */
#if (defined(FM_CAPWAP_SUPPORT) && (DPAA_VERSION == 10))
	, e_IOC_FM_PORT_PCD_SUPPORT_CC_AND_KG	/**< Use Coarse Classification,and Keygen */
	, e_IOC_FM_PORT_PCD_SUPPORT_CC_AND_KG_AND_PLCR	/**< Use Coarse Classification, Keygen and Policer */
#endif /* FM_CAPWAP_SUPPORT */
} ioc_fm_port_pcd_support;

/**************************************************************************//**
 @Collection   FM Frame error
*//***************************************************************************/
typedef uint32_t	ioc_fm_port_frame_err_select_t;
	/**< typedef for defining Frame Descriptor errors */

/* @} */

/**************************************************************************//**
 @Description   An enum for defining Dual Tx rate limiting scale.
	(Must match e_FmPortDualRateLimiterScaleDown defined in fm_port_ext.h)
*//***************************************************************************/
typedef enum ioc_fm_port_dual_rate_limiter_scale_down {
	e_IOC_FM_PORT_DUAL_RATE_LIMITER_NONE = 0,	/**< Use only single rate limiter  */
	e_IOC_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_2,/**< Divide high rate limiter by 2 */
	e_IOC_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_4,/**< Divide high rate limiter by 4 */
	e_IOC_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_8	/**< Divide high rate limiter by 8 */
} ioc_fm_port_dual_rate_limiter_scale_down;

/**************************************************************************//**
 @Description   A structure for defining Tx rate limiting
	(Must match struct t_FmPortRateLimit defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_rate_limit_t {
	uint16_t	max_burst_size;/**< in KBytes for Tx ports, in frames
			for offline parsing ports. (note that
			for early chips burst size is
			rounded up to a multiply of 1000 frames).*/
	uint32_t	rate_limit;/**< in Kb/sec for Tx ports, in frame/sec for
				offline parsing ports. Rate limit refers to
				data rate (rather than line rate). */
	ioc_fm_port_dual_rate_limiter_scale_down rate_limit_divider;
		/**< For offline parsing ports only. Not-valid
		for some earlier chip revisions */
} ioc_fm_port_rate_limit_t;


/**************************************************************************//**
 @Group	lnx_ioctl_FM_PORT_runtime_control_grp FM Port Runtime Control Unit

 @Description FM Port Runtime control unit API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   An enum for defining FM Port counters.
		(Must match enum e_FmPortCounters defined in fm_port_ext.h)
*//***************************************************************************/
typedef enum ioc_fm_port_counters {
	e_IOC_FM_PORT_COUNTERS_CYCLE,	/**< BMI performance counter */
	e_IOC_FM_PORT_COUNTERS_TASK_UTIL,	/**< BMI performance counter */
	e_IOC_FM_PORT_COUNTERS_QUEUE_UTIL,	/**< BMI performance counter */
	e_IOC_FM_PORT_COUNTERS_DMA_UTIL,	/**< BMI performance counter */
	e_IOC_FM_PORT_COUNTERS_FIFO_UTIL,	/**< BMI performance counter */
	e_IOC_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION,/**< BMI Rx only performance counter */
	e_IOC_FM_PORT_COUNTERS_FRAME,		/**< BMI statistics counter */
	e_IOC_FM_PORT_COUNTERS_DISCARD_FRAME,	/**< BMI statistics counter */
	e_IOC_FM_PORT_COUNTERS_DEALLOC_BUF,	/**< BMI deallocate buffer statistics counter */
	e_IOC_FM_PORT_COUNTERS_RX_BAD_FRAME,	/**< BMI Rx only statistics counter */
	e_IOC_FM_PORT_COUNTERS_RX_LARGE_FRAME,	/**< BMI Rx only statistics counter */
	e_IOC_FM_PORT_COUNTERS_RX_FILTER_FRAME,	/**< BMI Rx & OP only statistics counter */
	e_IOC_FM_PORT_COUNTERS_RX_LIST_DMA_ERR,	/**< BMI Rx, OP & HC only statistics counter */
	e_IOC_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD,/**< BMI Rx, OP & HC statistics counter */
	e_IOC_FM_PORT_COUNTERS_PREPARE_TO_ENQUEUE_COUNTER,/**< BMI Rx, OP & HC only statistics counter */
	e_IOC_FM_PORT_COUNTERS_WRED_DISCARD,	/**< BMI OP & HC only statistics counter */
	e_IOC_FM_PORT_COUNTERS_LENGTH_ERR,	/**< BMI non-Rx statistics counter */
	e_IOC_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT,	/**< BMI non-Rx statistics counter */
	e_IOC_FM_PORT_COUNTERS_DEQ_TOTAL,	/**< QMI total QM dequeues counter */
	e_IOC_FM_PORT_COUNTERS_ENQ_TOTAL,	/**< QMI total QM enqueues counter */
	e_IOC_FM_PORT_COUNTERS_DEQ_FROM_DEFAULT,/**< QMI counter */
	e_IOC_FM_PORT_COUNTERS_DEQ_CONFIRM	/**< QMI counter */
} ioc_fm_port_counters;

typedef struct ioc_fm_port_bmi_stats_t {
	uint32_t cnt_cycle;
	uint32_t cnt_task_util;
	uint32_t cnt_queue_util;
	uint32_t cnt_dma_util;
	uint32_t cnt_fifo_util;
	uint32_t cnt_rx_pause_activation;
	uint32_t cnt_frame;
	uint32_t cnt_discard_frame;
	uint32_t cnt_dealloc_buf;
	uint32_t cnt_rx_bad_frame;
	uint32_t cnt_rx_large_frame;
	uint32_t cnt_rx_filter_frame;
	uint32_t cnt_rx_list_dma_err;
	uint32_t cnt_rx_out_of_buffers_discard;
	uint32_t cnt_wred_discard;
	uint32_t cnt_length_err;
	uint32_t cnt_unsupported_format;
} ioc_fm_port_bmi_stats_t;

/**************************************************************************//**
 @Description   Structure for Port id parameters.
		(Description may be inaccurate;
		must match struct t_FmPortCongestionGrps defined in fm_port_ext.h)

		Fields commented 'IN' are passed by the port module to be used
		by the FM module.
		Fields commented 'OUT' will be filled by FM before returning to port.
*//***************************************************************************/
typedef struct ioc_fm_port_congestion_groups_t {
	uint16_t	num_of_congestion_grps_to_consider;
			/**< The number of required congestion groups
			to define the size of the following array */
	uint8_t	congestion_grps_to_consider [FM_PORT_NUM_OF_CONGESTION_GRPS];
		/**< An array of CG indexes;
		Note that the size of the array should be
		'num_of_congestion_grps_to_consider'. */
#if DPAA_VERSION >= 11
	bool	pfc_priorities_enable[FM_PORT_NUM_OF_CONGESTION_GRPS][FM_MAX_NUM_OF_PFC_PRIORITIES];
		/**< A matrix that represents the map between the CG ids
		defined in 'congestion_grps_to_consider' to the priorities
		mapping array. */
#endif /* DPAA_VERSION >= 11 */
} ioc_fm_port_congestion_groups_t;


/**************************************************************************//**
 @Function	FM_PORT_Disable

 @Description   Gracefully disable an FM port. The port will not start new
		tasks after all tasks associated with the port are terminated.

 @Return	0 on success; error code otherwise.

 @Cautions	This is a blocking routine, it returns after port is
		gracefully stopped, i.e. the port will not except new frames,
		but it will finish all frames or tasks which were already began
*//***************************************************************************/
#define FM_PORT_IOC_DISABLE   _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(1))

/**************************************************************************//**
 @Function	FM_PORT_Enable

 @Description   A runtime routine provided to allow disable/enable of port.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_ENABLE   _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(2))

/**************************************************************************//**
 @Function	FM_PORT_SetRateLimit

 @Description   Calling this routine enables rate limit algorithm.
		By default, this functionality is disabled.

		Note that rate - limit mechanism uses the FM time stamp.
		The selected rate limit specified here would be
		rounded DOWN to the nearest 16M.

		May be used for Tx and offline parsing ports only

 @Param[in]	ioc_fm_port_rate_limit A structure of rate limit parameters

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_SET_RATE_LIMIT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(3), ioc_fm_port_rate_limit_t)

/**************************************************************************//**
 @Function	FM_PORT_DeleteRateLimit

 @Description   Calling this routine disables the previously enabled rate limit.

		May be used for Tx and offline parsing ports only

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_DELETE_RATE_LIMIT   _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(5))
#define FM_PORT_IOC_REMOVE_RATE_LIMIT   FM_PORT_IOC_DELETE_RATE_LIMIT

/**************************************************************************//**
 @Function	FM_PORT_AddCongestionGrps

 @Description   This routine effects the corresponding Tx port.
		It should be called in order to enable pause
		frame transmission in case of congestion in one or more
		of the congestion groups relevant to this port.
		Each call to this routine may add one or more congestion
		groups to be considered relevant to this port.

		May be used for Rx, or RX+OP ports only (depending on chip)

 @Param[in]	ioc_fm_port_congestion_groups_t - A pointer to an array of
					congestion group ids to consider.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_ADD_CONGESTION_GRPS	_IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(34), ioc_fm_port_congestion_groups_t)

/**************************************************************************//**
 @Function	FM_PORT_RemoveCongestionGrps

 @Description   This routine effects the corresponding Tx port. It should be
		called when congestion groups were
		defined for this port and are no longer relevant, or pause
		frames transmitting is not required on their behalf.
		Each call to this routine may remove one or more congestion
		groups to be considered relevant to this port.

		May be used for Rx, or RX+OP ports only (depending on chip)

 @Param[in]	ioc_fm_port_congestion_groups_t - A pointer to an array of
					congestion group ids to consider.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_REMOVE_CONGESTION_GRPS	_IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(35), ioc_fm_port_congestion_groups_t)

/**************************************************************************//**
 @Function	FM_PORT_SetErrorsRoute

 @Description   Errors selected for this routine will cause a frame with that error
		to be enqueued to error queue.
		Errors not selected for this routine will cause a frame with that error
		to be enqueued to the one of the other port queues.
		By default all errors are defined to be enqueued to error queue.
		Errors that were configured to be discarded (at initialization)
		may not be selected here.

		May be used for Rx and offline parsing ports only

 @Param[in]	ioc_fm_port_frame_err_select_t  A list of errors to enqueue to error queue

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		(szbs001: How is it possible to have one function that needs to be
			called BEFORE FM_PORT_Init() implemented as an ioctl,
			which will ALWAYS be called AFTER the FM_PORT_Init()
			for that port!?!?!?!???!?!??!?!?)
*//***************************************************************************/
#define FM_PORT_IOC_SET_ERRORS_ROUTE   _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(4), ioc_fm_port_frame_err_select_t)

/**************************************************************************//**
 @Group	lnx_ioctl_FM_PORT_pcd_runtime_control_grp FM Port PCD Runtime Control Unit

 @Description   FM Port PCD Runtime control unit API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   A structure defining the KG scheme after the parser.
		(Must match struct ioc_fm_pcd_kg_scheme_select_t defined in fm_port_ext.h)

		This is relevant only to change scheme selection mode - from
		direct to indirect and vice versa, or when the scheme is selected directly,
		to select the scheme id.

*//***************************************************************************/
typedef struct ioc_fm_pcd_kg_scheme_select_t {
	bool	direct;	/**< TRUE to use 'scheme_id' directly, FALSE to use LCV.*/
	void	*scheme_id;/**< Relevant for 'direct'=TRUE only.
			'scheme_id' selects the scheme after parser. */
} ioc_fm_pcd_kg_scheme_select_t;

/**************************************************************************//**
 @Description   Scheme IDs structure
		(Must match struct ioc_fm_pcd_port_schemes_params_t defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_pcd_port_schemes_params_t {
	uint8_t	num_of_schemes;	/**< Number of schemes for port to be bound to. */
	void	*scheme_ids[FM_PCD_KG_NUM_OF_SCHEMES];
	/**< Array of 'num_of_schemes' schemes for the port to be bound to */
} ioc_fm_pcd_port_schemes_params_t;

/**************************************************************************//**
 @Description   A union for defining port protocol parameters for parser
		(Must match union u_FmPcdHdrPrsOpts defined in fm_port_ext.h)
*//***************************************************************************/
typedef union ioc_fm_pcd_hdr_prs_opts_u {
	/* MPLS */
	struct {
	bool label_interpretation_enable;/**< When this bit is set, the last MPLS label will be
			interpreted as described in HW spec table. When the bit
			is cleared, the parser will advance to MPLS next parse */
	ioc_net_header_type next_parse;/**< must be equal or higher than IPv4 */
	} mpls_prs_options;

	/* VLAN */
	struct {
	uint16_t	tag_protocol_id1;
			/**< User defined Tag Protocol Identifier, to be recognized
			on VLAN TAG on top of 0x8100 and 0x88A8 */
	uint16_t	tag_protocol_id2;
			/**< User defined Tag Protocol Identifier, to be recognized
			on VLAN TAG on top of 0x8100 and 0x88A8 */
	} vlan_prs_options;

	/* PPP */
	struct{
	bool		enable_mtu_check;	/**< Check validity of MTU according to RFC2516 */
	} pppoe_prs_options;

	/* IPV6 */
	struct {
	bool		routing_hdr_disable;	/**< Disable routing header */
	} ipv6_prs_options;

	/* UDP */
	struct {
	bool		pad_ignore_checksum;	/**< TRUE to ignore pad in checksum */
	} udp_prs_options;

	/* TCP */
	struct {
	bool		pad_ignore_checksum;	/**< TRUE to ignore pad in checksum */
	} tcp_prs_options;
} ioc_fm_pcd_hdr_prs_opts_u;

/**************************************************************************//**
 @Description   A structure for defining each header for the parser
		(must match struct t_FmPcdPrsAdditionalHdrParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_pcd_prs_additional_hdr_params_t {
	ioc_net_header_type	hdr; /**< Selected header */
	bool	err_disable; /**< TRUE to disable error indication */
	bool	soft_prs_enable;/**< Enable jump to SW parser when this
				header is recognized by the HW parser. */
	uint8_t	index_per_hdr;	/**< Normally 0, if more than one sw parser
				attachments exists for the same header,
				(in the main sw parser code) use this
				index to distinguish between them. */
	bool	use_prs_opts;	/**< TRUE to use parser options. */
	ioc_fm_pcd_hdr_prs_opts_u prs_opts;/**< A unuion according to header type,
				defining the parser options selected.*/
} ioc_fm_pcd_prs_additional_hdr_params_t;

/**************************************************************************//**
 @Description   A structure for defining port PCD parameters
		(Must match t_FmPortPcdPrsParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_prs_params_t {
	uint8_t			prs_res_priv_info;	/**< The private info provides a method of inserting
				port information into the parser result. This information
				may be extracted by KeyGen and be used for frames
				distribution when a per-port distinction is required,
				it may also be used as a port logical id for analyzing
				incoming frames. */
	uint8_t			parsing_offset;	/**< Number of bytes from begining of packet to start parsing */
	ioc_net_header_type		first_prs_hdr;	/**< The type of the first header axpected at 'parsing_offset' */
	bool				include_in_prs_statistics; /**< TRUE to include this port in the parser statistics */
	uint8_t			num_of_hdrs_with_additional_params;
				/**< Normally 0, some headers may get special parameters */
	ioc_fm_pcd_prs_additional_hdr_params_t  additional_params[IOC_FM_PCD_PRS_NUM_OF_HDRS];
				/**< 'num_of_hdrs_with_additional_params' structures
				additional parameters for each header that requires them */
	bool				set_vlan_tpid1;	/**< TRUE to configure user selection of Ethertype to
				indicate a VLAN tag (in addition to the TPID values
				0x8100 and 0x88A8). */
	uint16_t			vlan_tpid1;		/**< extra tag to use if set_vlan_tpid1=TRUE. */
	bool				set_vlan_tpid2;	/**< TRUE to configure user selection of Ethertype to
				indicate a VLAN tag (in addition to the TPID values
				0x8100 and 0x88A8). */
	uint16_t			vlan_tpid2;		/**< extra tag to use if set_vlan_tpid1=TRUE. */
} ioc_fm_port_pcd_prs_params_t;

/**************************************************************************//**
 @Description   A structure for defining coarse alassification parameters
		(Must match t_FmPortPcdCcParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_cc_params_t {
	void		*cc_tree_id; /**< CC tree id */
} ioc_fm_port_pcd_cc_params_t;

/**************************************************************************//**
 @Description   A structure for defining keygen parameters
		(Must match t_FmPortPcdKgParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_kg_params_t {
	uint8_t		num_of_schemes;		/**< Number of schemes for port to be bound to. */
	void		*scheme_ids[FM_PCD_KG_NUM_OF_SCHEMES];
				/**< Array of 'num_of_schemes' schemes for the
				port to be bound to */
	bool		direct_scheme;		/**< TRUE for going from parser to a specific scheme,
				regardless of parser result */
	void		*direct_scheme_id;		/**< Scheme id, as returned by FM_PCD_KgSetScheme;
				relevant only if direct=TRUE. */
} ioc_fm_port_pcd_kg_params_t;

/**************************************************************************//**
 @Description   A structure for defining policer parameters
		(Must match t_FmPortPcdPlcrParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_plcr_params_t {
	void		*plcr_profile_id;		/**< Selected profile handle;
				relevant in one of the following cases:
				e_IOC_FM_PORT_PCD_SUPPORT_PLCR_ONLY or
				e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR were selected,
				or if any flow uses a KG scheme where policer
				profile is not generated (bypass_plcr_profile_generation selected) */
} ioc_fm_port_pcd_plcr_params_t;

/**************************************************************************//**
 @Description   A structure for defining port PCD parameters
		(Must match struct t_FmPortPcdParams defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_params_t {
	ioc_fm_port_pcd_support	pcd_support;	/**< Relevant for Rx and offline ports only.
				Describes the active PCD engines for this port. */
	void		*net_env_id;	/**< HL Unused in PLCR only mode */
	ioc_fm_port_pcd_prs_params_t	*p_prs_params;  /**< Parser parameters for this port */
	ioc_fm_port_pcd_cc_params_t	*p_cc_params;   /**< Coarse classification parameters for this port */
	ioc_fm_port_pcd_kg_params_t	*p_kg_params;   /**< Keygen parameters for this port */
	ioc_fm_port_pcd_plcr_params_t	*p_plcr_params; /**< Policer parameters for this port */
	void		*p_ip_reassembly_manip;/**< IP Reassembly manipulation */
#if (DPAA_VERSION >= 11)
	void		*p_capwap_reassembly_manip;/**< CAPWAP Reassembly manipulation */
#endif /* (DPAA_VERSION >= 11) */
} ioc_fm_port_pcd_params_t;

/**************************************************************************//**
 @Description   A structure for defining the Parser starting point
		(Must match struct ioc_fm_pcd_prs_start_t defined in fm_port_ext.h)
*//***************************************************************************/
typedef struct ioc_fm_pcd_prs_start_t {
	uint8_t		parsing_offset; /**< Number of bytes from begining of packet to
				start parsing */
	ioc_net_header_type first_prs_hdr;  /**< The type of the first header axpected at
				'parsing_offset' */
} ioc_fm_pcd_prs_start_t;

/**************************************************************************//**
 @Description   FQID parameters structure
*//***************************************************************************/
typedef struct ioc_fm_port_pcd_fqids_params_t {
	uint32_t		num_fqids;  /**< Number of fqids to be allocated for the port */
	uint8_t		alignment;  /**< Alignment required for this port */
	uint32_t		base_fqid;  /**< output parameter - the base fqid */
} ioc_fm_port_pcd_fqids_params_t;

/**************************************************************************//**
 @Function	FM_PORT_IOC_ALLOC_PCD_FQIDS

 @Description   Allocates FQID's

		May be used for Rx and offline parsing ports only

 @Param[in,out] ioc_fm_port_pcd_fqids_params_t  Parameters for allocating FQID's

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_ALLOC_PCD_FQIDS   _IOWR(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(19), ioc_fm_port_pcd_fqids_params_t)

/**************************************************************************//**
 @Function	FM_PORT_IOC_FREE_PCD_FQIDS

 @Description   Frees previously-allocated FQIDs

		May be used for Rx and offline parsing ports only

 @Param[in]	uint32_t	Base FQID of previously allocated range.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_FREE_PCD_FQIDS   _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(19), uint32_t)

/**************************************************************************//**
 @Function	FM_PORT_SetPCD

 @Description   Calling this routine defines the port's PCD configuration.
		It changes it from its default configuration which is PCD
		disabled (BMI to BMI) and configures it according to the passed
		parameters.

		May be used for Rx and offline parsing ports only

 @Param[in]	ioc_fm_port_pcd_params_t	A Structure of parameters defining the port's PCD
				configuration.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_SET_PCD_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(20), ioc_compat_fm_port_pcd_params_t)
#endif
#define FM_PORT_IOC_SET_PCD _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(20), ioc_fm_port_pcd_params_t)

/**************************************************************************//**
 @Function	FM_PORT_DeletePCD

 @Description   Calling this routine releases the port's PCD configuration.
		The port returns to its default configuration which is PCD
		disabled (BMI to BMI) and all PCD configuration is removed.

		May be used for Rx and offline parsing ports which are
		in PCD mode only

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_DELETE_PCD _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(21))

/**************************************************************************//**
 @Function	FM_PORT_AttachPCD

 @Description   This routine may be called after FM_PORT_DetachPCD was called,
		to return to the originally configured PCD support flow.
		The couple of routines are used to allow PCD configuration changes
		that demand that PCD will not be used while changes take place.

		May be used for Rx and offline parsing ports which are
		in PCD mode only

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_ATTACH_PCD _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(23))

/**************************************************************************//**
 @Function	FM_PORT_DetachPCD

 @Description   Calling this routine detaches the port from its PCD functionality.
		The port returns to its default flow which is BMI to BMI.

		May be used for Rx and offline parsing ports which are
		in PCD mode only

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#define FM_PORT_IOC_DETACH_PCD _IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(22))

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrAllocProfiles

 @Description   This routine may be called only for ports that use the Policer in
		order to allocate private policer profiles.

 @Param[in]	uint16_t	The number of required policer profiles

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed before FM_PORT_SetPCD() only.
*//***************************************************************************/
#define FM_PORT_IOC_PCD_PLCR_ALLOC_PROFILES	_IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(24), uint16_t)

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrFreeProfiles

 @Description   This routine should be called for freeing private policer profiles.

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed before FM_PORT_SetPCD() only.
*//***************************************************************************/
#define FM_PORT_IOC_PCD_PLCR_FREE_PROFILES	_IO(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(25))

/**************************************************************************//**
 @Function	FM_PORT_PcdKgModifyInitialScheme

 @Description   This routine may be called only for ports that use the keygen in
		order to change the initial scheme frame should be routed to.
		The change may be of a scheme id (in case of direct mode),
		from direct to indirect, or from indirect to direct - specifying the scheme id.

 @Param[in]	ioc_fm_pcd_kg_scheme_select_t   A structure of parameters for defining whether
					a scheme is direct/indirect, and if direct - scheme id.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_PCD_KG_MODIFY_INITIAL_SCHEME_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(26), ioc_compat_fm_pcd_kg_scheme_select_t)
#endif
#define FM_PORT_IOC_PCD_KG_MODIFY_INITIAL_SCHEME _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(26), ioc_fm_pcd_kg_scheme_select_t)

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrModifyInitialProfile

 @Description   This routine may be called for ports with flows
		e_IOC_FM_PCD_SUPPORT_PLCR_ONLY or e_IOC_FM_PCD_SUPPORT_PRS_AND_PLCR  only,
		to change the initial Policer profile frame should be routed to.
		The change may be of a profile and / or absolute / direct mode selection.

 @Param[in]	ioc_fm_obj_t	Policer profile Id as returned from FM_PCD_PlcrSetProfile.

 @Return	0 on success; error code otherwise.
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_PCD_PLCR_MODIFY_INITIAL_PROFILE_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(27), ioc_compat_fm_obj_t)
#endif
#define FM_PORT_IOC_PCD_PLCR_MODIFY_INITIAL_PROFILE _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(27), ioc_fm_obj_t)

/**************************************************************************//**
 @Function	FM_PORT_PcdCcModifyTree

 @Description   This routine may be called to change this port connection to
		a pre - initializes coarse classification Tree.

 @Param[in]	ioc_fm_obj_t	Id of new coarse classification tree selected for this port.

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed only following FM_PORT_SetPCD() and FM_PORT_DetachPCD()
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_PCD_CC_MODIFY_TREE_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(28), ioc_compat_fm_obj_t)
#endif
#define FM_PORT_IOC_PCD_CC_MODIFY_TREE _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(28), ioc_fm_obj_t)

/**************************************************************************//**
 @Function	FM_PORT_PcdKgBindSchemes

 @Description   These routines may be called for modifying the binding of ports
		to schemes. The scheme itself is not added,
		just this specific port starts using it.

 @Param[in]	ioc_fm_pcd_port_schemes_params_t	Schemes parameters structre

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed only following FM_PORT_SetPCD().
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_PCD_KG_BIND_SCHEMES_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(30), ioc_compat_fm_pcd_port_schemes_params_t)
#endif
#define FM_PORT_IOC_PCD_KG_BIND_SCHEMES _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(30), ioc_fm_pcd_port_schemes_params_t)

/**************************************************************************//**
 @Function	FM_PORT_PcdKgUnbindSchemes

 @Description   These routines may be called for modifying the binding of ports
		to schemes. The scheme itself is not removed or invalidated,
		just this specific port stops using it.

 @Param[in]	ioc_fm_pcd_port_schemes_params_t	Schemes parameters structre

 @Return	0 on success; error code otherwise.

 @Cautions	Allowed only following FM_PORT_SetPCD().
*//***************************************************************************/
#if defined(CONFIG_COMPAT)
#define FM_PORT_IOC_PCD_KG_UNBIND_SCHEMES_COMPAT _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(31), ioc_compat_fm_pcd_port_schemes_params_t)
#endif
#define FM_PORT_IOC_PCD_KG_UNBIND_SCHEMES _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(31), ioc_fm_pcd_port_schemes_params_t)

#define ENET_NUM_OCTETS_PER_ADDRESS 6	/**< Number of octets (8-bit bytes) in an ethernet address */
typedef struct ioc_fm_port_mac_addr_params_t {
	uint8_t addr[ENET_NUM_OCTETS_PER_ADDRESS];
} ioc_fm_port_mac_addr_params_t;

/**************************************************************************//**
 @Function	FM_MAC_AddHashMacAddr

 @Description   Add an Address to the hash table. This is for filter purpose only.

 @Param[in]	ioc_fm_port_mac_addr_params_t - Ethernet Mac address

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_MAC_Init(). It is a filter only address.
 @Cautions	Some address need to be filtered out in upper FM blocks.
*//***************************************************************************/
#define FM_PORT_IOC_ADD_RX_HASH_MAC_ADDR   _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(36), ioc_fm_port_mac_addr_params_t)

/**************************************************************************//**
 @Function	FM_MAC_RemoveHashMacAddr

 @Description   Delete an Address to the hash table. This is for filter purpose only.

 @Param[in]	ioc_fm_port_mac_addr_params_t - Ethernet Mac address

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_MAC_Init().
*//***************************************************************************/
#define FM_PORT_IOC_REMOVE_RX_HASH_MAC_ADDR   _IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(37), ioc_fm_port_mac_addr_params_t)

typedef struct ioc_fm_port_tx_pause_frames_params_t {
	uint8_t  priority;
	uint16_t pause_time;
	uint16_t thresh_time;
} ioc_fm_port_tx_pause_frames_params_t;

/**************************************************************************//**
 @Function	FM_MAC_SetTxPauseFrames

 @Description   Enable/Disable transmission of Pause-Frames.
		The routine changes the default configuration:
		pause-time - [0xf000]
		threshold-time - [0]

 @Param[in]	ioc_fm_port_tx_pause_frames_params_t A structure holding the required parameters.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_MAC_Init().
		PFC is supported only on new mEMAC; i.e. in MACs that don't have
		PFC support (10G-MAC and dTSEC), user should use 'FM_MAC_NO_PFC'
		in the 'priority' field.
*//***************************************************************************/
#define FM_PORT_IOC_SET_TX_PAUSE_FRAMES	_IOW(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(40), ioc_fm_port_tx_pause_frames_params_t)

typedef struct ioc_fm_port_mac_statistics_t {
	/* RMON */
	uint64_t  e_stat_pkts_64;		/**< r-10G tr-DT 64 byte frame counter */
	uint64_t  e_stat_pkts_65_to_127;	/**< r-10G 65 to 127 byte frame counter */
	uint64_t  e_stat_pkts_128_to_255;	/**< r-10G 128 to 255 byte frame counter */
	uint64_t  e_stat_pkts_256_to_511;	/**< r-10G 256 to 511 byte frame counter */
	uint64_t  e_stat_pkts_512_to_1023;   /**< r-10G 512 to 1023 byte frame counter */
	uint64_t  e_stat_pkts_1024_to_1518;  /**< r-10G 1024 to 1518 byte frame counter */
	uint64_t  e_stat_pkts_1519_to_1522;  /**< r-10G 1519 to 1522 byte good frame count */
	/* */
	uint64_t  e_stat_fragments;	/**< Total number of packets that were less than 64 octets long with a wrong CRC.*/
	uint64_t  e_stat_jabbers;		/**< Total number of packets longer than valid maximum length octets */
	uint64_t  e_stat_drop_events;	/**< number of dropped packets due to internal errors of the MAC Client (during recieve). */
	uint64_t  e_stat_CRC_align_errors;   /**< Incremented when frames of correct length but with CRC error are received.*/
	uint64_t  e_stat_undersize_pkts;	/**< Incremented for frames under 64 bytes with a valid FCS and otherwise well formed;
					This count does not include range length errors */
	uint64_t  e_stat_oversize_pkts;	/**< Incremented for frames which exceed 1518 (non VLAN) or 1522 (VLAN) and contains
					a valid FCS and otherwise well formed */
	/* Pause */
	uint64_t  te_stat_pause;		/**< Pause MAC Control received */
	uint64_t  re_stat_pause;		/**< Pause MAC Control sent */
	/* MIB II */
	uint64_t  if_in_octets;		/**< Total number of byte received. */
	uint64_t  if_in_pkts;		/**< Total number of packets received.*/
	uint64_t  if_in_ucast_pkts;	/**< Total number of unicast frame received;
				NOTE: this counter is not supported on dTSEC MAC */
	uint64_t  if_in_mcast_pkts;	/**< Total number of multicast frame received*/
	uint64_t  if_in_bcast_pkts;	/**< Total number of broadcast frame received */
	uint64_t  if_in_discards;		/**< Frames received, but discarded due to problems within the MAC RX. */
	uint64_t  if_in_errors;		/**< Number of frames received with error:
					- FIFO Overflow Error
					- CRC Error
					- Frame Too Long Error
					- Alignment Error
					- The dedicated Error Code (0xfe, not a code error) was received */
	uint64_t  if_out_octets;		/**< Total number of byte sent. */
	uint64_t  if_out_pkts;		/**< Total number of packets sent .*/
	uint64_t  if_out_ucast_pkts;	/**< Total number of unicast frame sent;
				NOTE: this counter is not supported on dTSEC MAC */
	uint64_t  if_out_mcast_pkts;	/**< Total number of multicast frame sent */
	uint64_t  if_out_bcast_pkts;	/**< Total number of multicast frame sent */
	uint64_t  if_out_discards;	/**< Frames received, but discarded due to problems within the MAC TX N/A!.*/
	uint64_t  if_out_errors;		/**< Number of frames transmitted with error:
					- FIFO Overflow Error
					- FIFO Underflow Error
					- Other */
} ioc_fm_port_mac_statistics_t;

/**************************************************************************//**
 @Function	FM_MAC_GetStatistics

 @Description   get all MAC statistics counters

 @Param[out]	ioc_fm_port_mac_statistics_t	A structure holding the statistics

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_Init().
*//***************************************************************************/
#define FM_PORT_IOC_GET_MAC_STATISTICS	_IOR(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(41), ioc_fm_port_mac_statistics_t)

/**************************************************************************//**
 @Function	FM_PORT_GetBmiCounters

 @Description   Read port's BMI stat counters and place them into
		a designated structure of counters.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[out]	p_BmiStats  counters structure

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/

#define FM_PORT_IOC_GET_BMI_COUNTERS _IOR(FM_IOC_TYPE_BASE, FM_PORT_IOC_NUM(42), ioc_fm_port_bmi_stats_t)

/** @} */ /* end of lnx_ioctl_FM_PORT_pcd_runtime_control_grp group */
/** @} */ /* end of lnx_ioctl_FM_PORT_runtime_control_grp group */

/** @} */ /* end of lnx_ioctl_FM_PORT_grp group */
/** @} */ /* end of lnx_ioctl_FM_grp group */


/**************************************************************************//**
 @Group	gen_id  General Drivers Utilities

 @Description   External routines.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group	gen_error_id  Errors, Events and Debug

 @Description   External routines.

 @{
*//***************************************************************************/

/******************************************************************************
The scheme below provides the bits description for error codes:

 0	1	2	3	4	5	6	7	8	9	10   11   12   13   14   15
|	Reserved (should be zero)	|		Module ID		|

 16   17   18   19   20   21   22   23   24   25   26   27   28   29   30   31
|				Error Type				|
******************************************************************************/

#define ERROR_CODE(_err)		((((uint32_t)_err) & 0x0000FFFF) | __ERR_MODULE__)

#define GET_ERROR_TYPE(_errcode)	((_errcode) & 0x0000FFFF)
				/**< Extract module code from error code (#uint32_t) */

#define GET_ERROR_MODULE(_errcode)  ((_errcode) & 0x00FF0000)
				/**< Extract error type (#e_ErrorType) from
				error code (#uint32_t) */

#define RETURN_ERROR(_level, _err, _vmsg) \
	return ERROR_CODE(_err)

/**************************************************************************//**
 @Description	Error Type Enumeration
*//***************************************************************************/
typedef enum e_ErrorType	/*   Comments / Associated Message Strings			*/
{			/* ------------------------------------------------------------ */
	E_OK = 0		/*   Never use "RETURN_ERROR" with E_OK; Use "return E_OK;"	*/
	, E_WRITE_FAILED = EIO   /**< Write access failed on memory/device.			*/
				/*   String: none, or device name.				*/
	, E_NO_DEVICE = ENXIO	/**< The associated device is not initialized.		*/
				/*   String: none.				*/
	, E_NOT_AVAILABLE = EAGAIN
				/**< Resource is unavailable.				*/
				/*   String: none, unless the operation is not the main goal
				of the function (in this case add resource description).   */
	, E_NO_MEMORY = ENOMEM   /**< External memory allocation failed.			*/
				/*   String: description of item for which allocation failed.   */
	, E_INVALID_ADDRESS = EFAULT
				/**< Invalid address.				*/
				/*   String: description of the specific violation.		*/
	, E_BUSY = EBUSY	/**< Resource or module is busy.				*/
				/*   String: none, unless the operation is not the main goal
				of the function (in this case add resource description).   */
	, E_ALREADY_EXISTS = EEXIST
				/**< Requested resource or item already exists.		*/
				/*   Use when resource duplication or sharing are not allowed.
				String: none, unless the operation is not the main goal
				of the function (in this case add item description).	*/
	, E_INVALID_OPERATION = ENODEV
				/**< The operation/command is invalid (unrecognized).	*/
				/*   String: none.				*/
	, E_INVALID_VALUE = EDOM /**< Invalid value.				*/
				/*   Use for non-enumeration parameters, and
				only when other error types are not suitable.
				String: parameter description + "(should be <attribute>)",
				e.g: "Maximum Rx buffer length (should be divisible by 8)",
				"Channel number (should be even)".			*/
	, E_NOT_IN_RANGE = ERANGE/**< Parameter value is out of range.			*/
				/*   Don't use this error for enumeration parameters.
				String: parameter description + "(should be %d-%d)",
				e.g: "Number of pad characters (should be 0-15)".	*/
	, E_NOT_SUPPORTED = ENOSYS
				/**< The function is not supported or not implemented.	*/
				/*   String: none.				*/
	, E_INVALID_STATE	/**< The operation is not allowed in current module state.	*/
				/*   String: none.				*/
	, E_INVALID_HANDLE	/**< Invalid handle of module or object.			*/
				/*   String: none, unless the function takes in more than one
				handle (in this case add the handle description)	*/
	, E_INVALID_ID	/**< Invalid module ID (usually enumeration or index).	*/
				/*   String: none, unless the function takes in more than one
				ID (in this case add the ID description)		*/
	, E_NULL_POINTER	/**< Unexpected NULL pointer.				*/
				/*   String: pointer description.				*/
	, E_INVALID_SELECTION	/**< Invalid selection or mode.				*/
				/*   Use for enumeration values, only when other error types
				are not suitable.
				String: parameter description.				*/
	, E_INVALID_COMM_MODE	/**< Invalid communication mode.				*/
				/*   String: none, unless the function takes in more than one
				communication mode indications (in this case add
				parameter description).				*/
	, E_INVALID_MEMORY_TYPE  /**< Invalid memory type.				*/
				/*   String: none, unless the function takes in more than one
				memory types (in this case add memory description,
				e.g: "Data memory", "Buffer descriptors memory").	*/
	, E_INVALID_CLOCK	/**< Invalid clock.				*/
				/*   String: none, unless the function takes in more than one
				clocks (in this case add clock description,
				e.g: "Rx clock", "Tx clock").				*/
	, E_CONFLICT		/**< Some setting conflicts with another setting.		*/
				/*   String: description of the conflicting settings.	*/
	, E_NOT_ALIGNED	/**< Non-aligned address.				*/
				/*   String: parameter description + "(should be %d-bytes aligned)",
				e.g: "Rx data buffer (should be 32-bytes aligned)".	*/
	, E_NOT_FOUND		/**< Requested resource or item was not found.		*/
				/*   Use only when the resource/item is uniquely identified.
				String: none, unless the operation is not the main goal
				of the function (in this case add item description).	*/
	, E_FULL		/**< Resource is full.				*/
				/*   String: none, unless the operation is not the main goal
				of the function (in this case add resource description).   */
	, E_EMPTY		/**< Resource is empty.				*/
				/*   String: none, unless the operation is not the main goal
				of the function (in this case add resource description).   */
	, E_ALREADY_FREE	/**< Specified resource or item is already free or deleted.	*/
				/*   String: none, unless the operation is not the main goal
				of the function (in this case add item description).	*/
	, E_READ_FAILED	/**< Read access failed on memory/device.			*/
				/*   String: none, or device name.				*/
	, E_INVALID_FRAME	/**< Invalid frame object (NULL handle or missing buffers).	*/
				/*   String: none.				*/
	, E_SEND_FAILED	/**< Send operation failed on device.			*/
				/*   String: none, or device name.				*/
	, E_RECEIVE_FAILED	/**< Receive operation failed on device.			*/
				/*   String: none, or device name.				*/
	, E_TIMEOUT/* = ETIMEDOUT*/  /**< The operation timed out.				*/
				/*   String: none.				*/

	, E_DUMMY_LAST	/* NEVER USED */

} e_ErrorType;

/**************************************************************************//**

 @Group	FM_grp Frame Manager API

 @Description   FM API functions, definitions and enums

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group	FM_PORT_grp FM Port

 @Description   FM Port API

		The FM uses a general module called "port" to represent a Tx port
		(MAC), an Rx port (MAC) or Offline Parsing port.
		The number of ports in an FM varies between SOCs.
		The SW driver manages these ports as sub-modules of the FM, i.e.
		after an FM is initialized, its ports may be initialized and
		operated upon.

		The port is initialized aware of its type, but other functions on
		a port may be indifferent to its type. When necessary, the driver
		verifies coherence and returns error if applicable.

		On initialization, user specifies the port type and it's index
		(relative to the port's type) - always starting at 0.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   An enum for defining port PCD modes.
		This enum defines the superset of PCD engines support - i.e. not
		all engines have to be used, but all have to be enabled. The real
		flow of a specific frame depends on the PCD configuration and the
		frame headers and payload.
		Note: the first engine and the first engine after the parser (if
		exists) should be in order, the order is important as it will
		define the flow of the port. However, as for the rest engines
		(the ones that follows), the order is not important anymore as
		it is defined by the PCD graph itself.
*//***************************************************************************/
typedef enum e_FmPortPcdSupport {
	e_FM_PORT_PCD_SUPPORT_NONE = 0		/**< BMI to BMI, PCD is not used */
	, e_FM_PORT_PCD_SUPPORT_PRS_ONLY		/**< Use only Parser */
	, e_FM_PORT_PCD_SUPPORT_PLCR_ONLY		/**< Use only Policer */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR		/**< Use Parser and Policer */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_KG		/**< Use Parser and Keygen */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC	/**< Use Parser, Keygen and Coarse Classification */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR
					/**< Use all PCD engines */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR	/**< Use Parser, Keygen and Policer */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_CC		/**< Use Parser and Coarse Classification */
	, e_FM_PORT_PCD_SUPPORT_PRS_AND_CC_AND_PLCR	/**< Use Parser and Coarse Classification and Policer */
	, e_FM_PORT_PCD_SUPPORT_CC_ONLY		/**< Use only Coarse Classification */
#ifdef FM_CAPWAP_SUPPORT
	, e_FM_PORT_PCD_SUPPORT_CC_AND_KG		/**< Use Coarse Classification,and Keygen */
	, e_FM_PORT_PCD_SUPPORT_CC_AND_KG_AND_PLCR	/**< Use Coarse Classification, Keygen and Policer */
#endif /* FM_CAPWAP_SUPPORT */
} e_FmPortPcdSupport;

/**************************************************************************//**
 @Description   Port interrupts
*//***************************************************************************/
typedef enum e_FmPortExceptions {
	e_FM_PORT_EXCEPTION_IM_BUSY		/**< Independent-Mode Rx-BUSY */
} e_FmPortExceptions;

/**************************************************************************//**
 @Collection	General FM Port defines
*//***************************************************************************/
#define FM_PORT_PRS_RESULT_NUM_OF_WORDS	8   /**< Number of 4 bytes words in parser result */
/* @} */

/**************************************************************************//**
 @Collection   FM Frame error
*//***************************************************************************/
typedef uint32_t	fmPortFrameErrSelect_t;			/**< typedef for defining Frame Descriptor errors */

#define FM_PORT_FRM_ERR_UNSUPPORTED_FORMAT	FM_FD_ERR_UNSUPPORTED_FORMAT	/**< Not for Rx-Port! Unsupported Format */
#define FM_PORT_FRM_ERR_LENGTH		FM_FD_ERR_LENGTH		/**< Not for Rx-Port! Length Error */
#define FM_PORT_FRM_ERR_DMA			FM_FD_ERR_DMA		/**< DMA Data error */
#define FM_PORT_FRM_ERR_NON_FM		FM_FD_RX_STATUS_ERR_NON_FM	/**< non Frame-Manager error; probably come from SEC that
						was chained to FM */

#define FM_PORT_FRM_ERR_IPRE			(FM_FD_ERR_IPR & ~FM_FD_IPR)	/**< IPR error */
#define FM_PORT_FRM_ERR_IPR_NCSP		(FM_FD_ERR_IPR_NCSP & ~FM_FD_IPR)   /**< IPR non-consistent-sp */

#define FM_PORT_FRM_ERR_IPFE			0				/**< Obsolete; will be removed in the future */

#ifdef FM_CAPWAP_SUPPORT
#define FM_PORT_FRM_ERR_CRE			FM_FD_ERR_CRE
#define FM_PORT_FRM_ERR_CHE			FM_FD_ERR_CHE
#endif /* FM_CAPWAP_SUPPORT */

#define FM_PORT_FRM_ERR_PHYSICAL		FM_FD_ERR_PHYSICAL		/**< Rx FIFO overflow, FCS error, code error, running disparity
						error (SGMII and TBI modes), FIFO parity error. PHY
						Sequence error, PHY error control character detected. */
#define FM_PORT_FRM_ERR_SIZE			FM_FD_ERR_SIZE		/**< Frame too long OR Frame size exceeds max_length_frame  */
#define FM_PORT_FRM_ERR_CLS_DISCARD		FM_FD_ERR_CLS_DISCARD	/**< indicates a classifier "drop" operation */
#define FM_PORT_FRM_ERR_EXTRACTION		FM_FD_ERR_EXTRACTION		/**< Extract Out of Frame */
#define FM_PORT_FRM_ERR_NO_SCHEME		FM_FD_ERR_NO_SCHEME		/**< No Scheme Selected */
#define FM_PORT_FRM_ERR_KEYSIZE_OVERFLOW	FM_FD_ERR_KEYSIZE_OVERFLOW	/**< Keysize Overflow */
#define FM_PORT_FRM_ERR_COLOR_RED		FM_FD_ERR_COLOR_RED		/**< Frame color is red */
#define FM_PORT_FRM_ERR_COLOR_YELLOW		FM_FD_ERR_COLOR_YELLOW	/**< Frame color is yellow */
#define FM_PORT_FRM_ERR_ILL_PLCR		FM_FD_ERR_ILL_PLCR		/**< Illegal Policer Profile selected */
#define FM_PORT_FRM_ERR_PLCR_FRAME_LEN	FM_FD_ERR_PLCR_FRAME_LEN	/**< Policer frame length error */
#define FM_PORT_FRM_ERR_PRS_TIMEOUT		FM_FD_ERR_PRS_TIMEOUT	/**< Parser Time out Exceed */
#define FM_PORT_FRM_ERR_PRS_ILL_INSTRUCT	FM_FD_ERR_PRS_ILL_INSTRUCT	/**< Invalid Soft Parser instruction */
#define FM_PORT_FRM_ERR_PRS_HDR_ERR		FM_FD_ERR_PRS_HDR_ERR	/**< Header error was identified during parsing */
#define FM_PORT_FRM_ERR_BLOCK_LIMIT_EXCEEDED	FM_FD_ERR_BLOCK_LIMIT_EXCEEDED  /**< Frame parsed beyind 256 first bytes */
#define FM_PORT_FRM_ERR_PROCESS_TIMEOUT	0x00000001			/**< FPM Frame Processing Timeout Exceeded */
/* @} */


/**************************************************************************//**
 @Group	FM_PORT_init_grp FM Port Initialization Unit

 @Description   FM Port Initialization Unit

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   Exceptions user callback routine, will be called upon an
		exception passing the exception identification.

 @Param[in]	h_App	- User's application descriptor.
 @Param[in]	exception  - The exception.
  *//***************************************************************************/
typedef void (t_FmPortExceptionCallback) (t_Handle h_App, e_FmPortExceptions exception);

/**************************************************************************//**
 @Description   User callback function called by driver with received data.

		User provides this function. Driver invokes it.

 @Param[in]	h_App	Application's handle originally specified to
				the API Config function
 @Param[in]	p_Data	A pointer to data received
 @Param[in]	length	length of received data
 @Param[in]	status	receive status and errors
 @Param[in]	position	position of buffer in frame
 @Param[in]	h_BufContext	A handle of the user acossiated with this buffer

 @Retval	e_RX_STORE_RESPONSE_CONTINUE - order the driver to continue Rx
				operation for all ready data.
 @Retval	e_RX_STORE_RESPONSE_PAUSE	- order the driver to stop Rx operation.
*//***************************************************************************/
typedef e_RxStoreResponse(t_FmPortImRxStoreCallback) (t_Handle h_App,
					uint8_t  *p_Data,
					uint16_t length,
					uint16_t status,
					uint8_t  position,
					t_Handle h_BufContext);

/**************************************************************************//**
 @Description   User callback function called by driver when transmit completed.

		User provides this function. Driver invokes it.

 @Param[in]	h_App	Application's handle originally specified to
				the API Config function
 @Param[in]	p_Data	A pointer to data received
 @Param[in]	status	transmit status and errors
 @Param[in]	lastBuffer	is last buffer in frame
 @Param[in]	h_BufContext	A handle of the user acossiated with this buffer
 *//***************************************************************************/
typedef void (t_FmPortImTxConfCallback) (t_Handle   h_App,
				uint8_t	*p_Data,
				uint16_t   status,
				t_Handle   h_BufContext);

/**************************************************************************//**
 @Description   A structure for additional Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortRxParams {
	uint32_t		errFqid;		/**< Error Queue Id. */
	uint32_t		dfltFqid;	/**< Default Queue Id.  */
	uint16_t		liodnOffset;	/**< Port's LIODN offset. */
	t_FmExtPools		extBufPools;	/**< Which external buffer pools are used
					(up to FM_PORT_MAX_NUM_OF_EXT_POOLS), and their sizes. */
} t_FmPortRxParams;

/**************************************************************************//**
 @Description   A structure for additional non-Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortNonRxParams {
	uint32_t		errFqid;		/**< Error Queue Id. */
	uint32_t		dfltFqid;	/**< For Tx - Default Confirmation queue,
					0 means no Tx confirmation for processed
					frames. For OP port - default Rx queue. */
	uint32_t		qmChannel;	/**< QM-channel dedicated to this port; will be used
					by the FM for dequeue. */
} t_FmPortNonRxParams;

/**************************************************************************//**
 @Description   A structure for additional Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortImRxTxParams {
	t_Handle			h_FmMuram;	/**< A handle of the FM-MURAM partition */
	uint16_t			liodnOffset;	/**< For Rx ports only. Port's LIODN Offset. */
	uint8_t			dataMemId;	/**< Memory partition ID for data buffers */
	uint32_t			dataMemAttributes;  /**< Memory attributes for data buffers */
	t_BufferPoolInfo		rxPoolParams;	/**< For Rx ports only. */
	t_FmPortImRxStoreCallback   *f_RxStore;	/**< For Rx ports only. */
	t_FmPortImTxConfCallback	*f_TxConf;	/**< For Tx ports only. */
} t_FmPortImRxTxParams;

/**************************************************************************//**
 @Description   A union for additional parameters depending on port type
*//***************************************************************************/
typedef union u_FmPortSpecificParams {
	t_FmPortImRxTxParams	imRxTxParams;	/**< Rx/Tx Independent-Mode port parameter structure */
	t_FmPortRxParams		rxParams;	/**< Rx port parameters structure */
	t_FmPortNonRxParams	nonRxParams;	/**< Non-Rx port parameters structure */
} u_FmPortSpecificParams;

/**************************************************************************//**
 @Description   A structure representing FM initialization parameters
*//***************************************************************************/
typedef struct t_FmPortParams {
	uintptr_t	baseAddr;	/**< Virtual Address of memory mapped FM Port registers.*/
	t_Handle	h_Fm;		/**< A handle to the FM object this port related to */
	e_FmPortType	portType;	/**< Port type */
	uint8_t		portId;		/**< Port Id - relative to type;
				NOTE: When configuring Offline Parsing port for
				FMANv3 devices (DPAA_VERSION 11 and higher),
				it is highly recommended NOT to use portId=0 due to lack
				of HW resources on portId=0. */
	bool		independentModeEnable;
				/**< This port is Independent-Mode - Used for Rx/Tx ports only! */
	uint16_t			liodnBase;	/**< Irrelevant for P4080 rev 1. LIODN base for this port, to be
				used together with LIODN offset. */
	u_FmPortSpecificParams	specificParams;	/**< Additional parameters depending on port
				type. */

	t_FmPortExceptionCallback   *f_Exception;	/**< Relevant for IM only Callback routine to be called on BUSY exception */
	t_Handle			h_App;		/**< A handle to an application layer object; This handle will
				be passed by the driver upon calling the above callbacks */
} t_FmPortParams;

/**************************************************************************//**
 @Function	FM_PORT_Config

 @Description   Creates a descriptor for the FM PORT module.

		The routine returns a handle(descriptor) to the FM PORT object.
		This descriptor must be passed as first parameter to all other
		FM PORT function calls.

		No actual initialization or configuration of FM hardware is
		done by this routine.

 @Param[in]	p_FmPortParams   - Pointer to data structure of parameters

 @Retval	Handle to FM object, or NULL for Failure.
*//***************************************************************************/
t_Handle FM_PORT_Config(t_FmPortParams *p_FmPortParams);

/**************************************************************************//**
 @Function	FM_PORT_Init

 @Description   Initializes the FM PORT module by defining the software structure
		and configuring the hardware registers.

 @Param[in]	h_FmPort - FM PORT module descriptor

 @Return	E_OK on success; Error code otherwise.
*//***************************************************************************/
uint32_t FM_PORT_Init(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_Free

 @Description   Frees all resources that were assigned to FM PORT module.

		Calling this routine invalidates the descriptor.

 @Param[in]	h_FmPort - FM PORT module descriptor

 @Return	E_OK on success; Error code otherwise.
*//***************************************************************************/
uint32_t FM_PORT_Free(t_Handle h_FmPort);

t_Handle FM_PORT_Open(t_FmPortParams *p_FmPortParams);
void FM_PORT_Close(t_Handle h_FmPort);


/**************************************************************************//**
 @Group	FM_PORT_advanced_init_grp	FM Port Advanced Configuration Unit

 @Description   Configuration functions used to change default values.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   enum for defining QM frame dequeue
*//***************************************************************************/
typedef enum e_FmPortDeqType {
   e_FM_PORT_DEQ_TYPE1,		/**< Dequeue from the SP channel - with priority precedence,
				and Intra-Class Scheduling respected. */
   e_FM_PORT_DEQ_TYPE2,		/**< Dequeue from the SP channel - with active FQ precedence,
				and Intra-Class Scheduling respected. */
   e_FM_PORT_DEQ_TYPE3		/**< Dequeue from the SP channel - with active FQ precedence,
				and override Intra-Class Scheduling */
} e_FmPortDeqType;

/**************************************************************************//**
 @Description   enum for defining QM frame dequeue
*//***************************************************************************/
typedef enum e_FmPortDeqPrefetchOption {
   e_FM_PORT_DEQ_NO_PREFETCH,	/**< QMI preforms a dequeue action for a single frame
				only when a dedicated portID Tnum is waiting. */
   e_FM_PORT_DEQ_PARTIAL_PREFETCH,  /**< QMI preforms a dequeue action for 3 frames when
				one dedicated portId tnum is waiting. */
   e_FM_PORT_DEQ_FULL_PREFETCH	/**< QMI preforms a dequeue action for 3 frames when
				no dedicated portId tnums are waiting. */

} e_FmPortDeqPrefetchOption;

/**************************************************************************//**
 @Description   enum for defining port default color
*//***************************************************************************/
typedef enum e_FmPortColor {
	e_FM_PORT_COLOR_GREEN,	/**< Default port color is green */
	e_FM_PORT_COLOR_YELLOW,	/**< Default port color is yellow */
	e_FM_PORT_COLOR_RED,		/**< Default port color is red */
	e_FM_PORT_COLOR_OVERRIDE	/**< Ignore color */
} e_FmPortColor;

/**************************************************************************//**
 @Description   A structure for defining Dual Tx rate limiting scale
*//***************************************************************************/
typedef enum e_FmPortDualRateLimiterScaleDown {
	e_FM_PORT_DUAL_RATE_LIMITER_NONE = 0,	/**< Use only single rate limiter  */
	e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_2,	/**< Divide high rate limiter by 2 */
	e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_4,	/**< Divide high rate limiter by 4 */
	e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_8	/**< Divide high rate limiter by 8 */
} e_FmPortDualRateLimiterScaleDown;

/**************************************************************************//**
 @Description   A structure for defining FM port resources
*//***************************************************************************/
typedef struct t_FmPortRsrc {
	uint32_t	num;		/**< Committed required resource */
	uint32_t	extra;		/**< Extra (not committed) required resource */
} t_FmPortRsrc;

/**************************************************************************//**
 @Description   A structure for defining observed pool depletion
*//***************************************************************************/
typedef struct t_FmPortObservedBufPoolDepletion {
	t_FmBufPoolDepletion	poolDepletionParams;/**< parameters to define pool depletion */
	t_FmExtPools		poolsParams;	/**< Which external buffer pools are observed
					(up to FM_PORT_MAX_NUM_OF_OBSERVED_EXT_POOLS),
					and their sizes. */
} t_FmPortObservedBufPoolDepletion;

/**************************************************************************//**
 @Description   A structure for defining Tx rate limiting
*//***************************************************************************/
typedef struct t_FmPortRateLimit {
	uint16_t				maxBurstSize;	/**< in KBytes for Tx ports, in frames
				for OP ports. (note that
				for early chips burst size is
				rounded up to a multiply of 1000 frames).*/
	uint32_t				rateLimit;		/**< in Kb/sec for Tx ports, in frame/sec for
				OP ports. Rate limit refers to
				data rate (rather than line rate). */
	e_FmPortDualRateLimiterScaleDown	rateLimitDivider;	/**< For OP ports only. Not-valid
				for some earlier chip revisions */
} t_FmPortRateLimit;

/**************************************************************************//**
 @Description   A structure for defining the parameters of
		the Rx port performance counters
*//***************************************************************************/
typedef struct t_FmPortPerformanceCnt {
	uint8_t	taskCompVal;		/**< Task compare value */
	uint8_t	queueCompVal;	/**< Rx queue/Tx confirm queue compare
				value (unused for H/O) */
	uint8_t	dmaCompVal;		/**< Dma compare value */
	uint32_t	fifoCompVal;		/**< Fifo compare value (in bytes) */
} t_FmPortPerformanceCnt;

/**************************************************************************//**
 @Description   A structure for defining the sizes of the Deep Sleep
		the Auto Response tables
*//***************************************************************************/
typedef struct t_FmPortDsarTablesSizes {
	uint16_t   maxNumOfArpEntries;
	uint16_t   maxNumOfEchoIpv4Entries;
	uint16_t   maxNumOfNdpEntries;
	uint16_t   maxNumOfEchoIpv6Entries;
	uint16_t   maxNumOfSnmpIPV4Entries;
	uint16_t   maxNumOfSnmpIPV6Entries;
	uint16_t   maxNumOfSnmpOidEntries;
	uint16_t   maxNumOfSnmpOidChar; /* total amount of character needed for the snmp table */

	uint16_t   maxNumOfIpProtFiltering;
	uint16_t   maxNumOfTcpPortFiltering;
	uint16_t   maxNumOfUdpPortFiltering;
} t_FmPortDsarTablesSizes;

/**************************************************************************//**
 @Function	FM_PORT_ConfigDsarSupport

 @Description   This function will allocate the amount of MURAM needed for
		this max number of entries for Deep Sleep Auto Response.
		it will calculate all needed MURAM for autoresponse including
		necessary common stuff.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	params	A pointer to a structure containing the maximum
				sizes of the auto response tables

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDsarSupport(t_Handle h_FmPortRx, t_FmPortDsarTablesSizes *params);

/**************************************************************************//**
 @Function	FM_PORT_ConfigNumOfOpenDmas

 @Description   Calling this routine changes the max number of open DMA's
		available for this port. It changes this parameter in the
		internal driver data base from its default configuration
		[OP: 1]
		[1G-RX, 1G-TX: 1 (+1)]
		[10G-RX, 10G-TX: 8 (+8)]

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_OpenDmas  A pointer to a structure of parameters defining
				the open DMA allocation.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigNumOfOpenDmas(t_Handle h_FmPort, t_FmPortRsrc *p_OpenDmas);

/**************************************************************************//**
 @Function	FM_PORT_ConfigNumOfTasks

 @Description   Calling this routine changes the max number of tasks
		available for this port. It changes this parameter in the
		internal driver data base from its default configuration
		[OP : 1]
		[1G - RX, 1G - TX : 3 ( + 2)]
		[10G - RX, 10G - TX : 16 ( + 8)]

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_NumOfTasks	A pointer to a structure of parameters defining
				the tasks allocation.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigNumOfTasks(t_Handle h_FmPort, t_FmPortRsrc *p_NumOfTasks);

/**************************************************************************//**
 @Function	FM_PORT_ConfigSizeOfFifo

 @Description   Calling this routine changes the max FIFO size configured for this port.

		This function changes the internal driver data base from its
		default configuration. Please refer to the driver's User Guide for
		information on default FIFO sizes in the various devices.
		[OP: 2KB]
		[1G-RX, 1G-TX: 11KB]
		[10G-RX, 10G-TX: 12KB]

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_SizeOfFifo	A pointer to a structure of parameters defining
				the FIFO allocation.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigSizeOfFifo(t_Handle h_FmPort, t_FmPortRsrc *p_SizeOfFifo);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDeqHighPriority

 @Description   Calling this routine changes the dequeue priority in the
		internal driver data base from its default configuration
		1G: [DEFAULT_PORT_deqHighPriority_1G]
		10G: [DEFAULT_PORT_deqHighPriority_10G]

		May be used for Non - Rx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	highPri	TRUE to select high priority, FALSE for normal operation.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDeqHighPriority(t_Handle h_FmPort, bool highPri);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDeqType

 @Description   Calling this routine changes the dequeue type parameter in the
		internal driver data base from its default configuration
		[DEFAULT_PORT_deqType].

		May be used for Non - Rx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	deqType	According to QM definition.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDeqType(t_Handle h_FmPort, e_FmPortDeqType deqType);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDeqPrefetchOption

 @Description   Calling this routine changes the dequeue prefetch option parameter in the
		internal driver data base from its default configuration
		[DEFAULT_PORT_deqPrefetchOption]
		Note: Available for some chips only

		May be used for Non - Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	deqPrefetchOption   New option

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDeqPrefetchOption(t_Handle h_FmPort, e_FmPortDeqPrefetchOption deqPrefetchOption);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDeqByteCnt

 @Description   Calling this routine changes the dequeue byte count parameter in
		the internal driver data base from its default configuration
		1G:[DEFAULT_PORT_deqByteCnt_1G].
		10G:[DEFAULT_PORT_deqByteCnt_10G].

		May be used for Non - Rx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	deqByteCnt	New byte count

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDeqByteCnt(t_Handle h_FmPort, uint16_t deqByteCnt);

/**************************************************************************//**
 @Function	FM_PORT_ConfigBufferPrefixContent

 @Description   Defines the structure, size and content of the application buffer.
		The prefix will
		In Tx ports, if 'passPrsResult', the application
		should set a value to their offsets in the prefix of
		the FM will save the first 'privDataSize', than,
		depending on 'passPrsResult' and 'passTimeStamp', copy parse result
		and timeStamp, and the packet itself (in this order), to the
		application buffer, and to offset.
		Calling this routine changes the buffer margins definitions
		in the internal driver data base from its default
		configuration: Data size:  [DEFAULT_PORT_bufferPrefixContent_privDataSize]
				Pass Parser result: [DEFAULT_PORT_bufferPrefixContent_passPrsResult].
				Pass timestamp: [DEFAULT_PORT_bufferPrefixContent_passTimeStamp].

		May be used for all ports

 @Param[in]	h_FmPort			A handle to a FM Port module.
 @Param[in,out] p_FmBufferPrefixContent	A structure of parameters describing the
					structure of the buffer.
					Out parameter: Start margin - offset
					of data from start of external buffer.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigBufferPrefixContent(t_Handle			h_FmPort,
					   t_FmBufferPrefixContent	*p_FmBufferPrefixContent);

/**************************************************************************//**
 @Function	FM_PORT_ConfigCheksumLastBytesIgnore

 @Description   Calling this routine changes the number of checksum bytes to ignore
		parameter in the internal driver data base from its default configuration
		[DEFAULT_PORT_cheksumLastBytesIgnore]

		May be used by Tx & Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	cheksumLastBytesIgnore  New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigCheksumLastBytesIgnore(t_Handle h_FmPort, uint8_t cheksumLastBytesIgnore);

/**************************************************************************//**
 @Function	FM_PORT_ConfigCutBytesFromEnd

 @Description   Calling this routine changes the number of bytes to cut from a
		frame's end parameter in the internal driver data base
		from its default configuration [DEFAULT_PORT_cutBytesFromEnd]
		Note that if the result of (frame length before chop - cutBytesFromEnd) is
		less than 14 bytes, the chop operation is not executed.

		May be used for Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	cutBytesFromEnd	New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigCutBytesFromEnd(t_Handle h_FmPort, uint8_t cutBytesFromEnd);

/**************************************************************************//**
 @Function	FM_PORT_ConfigPoolDepletion

 @Description   Calling this routine enables pause frame generation depending on the
		depletion status of BM pools. It also defines the conditions to activate
		this functionality. By default, this functionality is disabled.

		May be used for Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_BufPoolDepletion	A structure of pool depletion parameters

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigPoolDepletion(t_Handle h_FmPort, t_FmBufPoolDepletion *p_BufPoolDepletion);

/**************************************************************************//**
 @Function	FM_PORT_ConfigObservedPoolDepletion

 @Description   Calling this routine enables a mechanism to stop port enqueue
		depending on the depletion status of selected BM pools.
		It also defines the conditions to activate
		this functionality. By default, this functionality is disabled.

		Note: Available for some chips only

		May be used for OP ports only

 @Param[in]	h_FmPort				A handle to a FM Port module.
 @Param[in]	p_FmPortObservedBufPoolDepletion	A structure of parameters for pool depletion.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigObservedPoolDepletion(t_Handle				h_FmPort,
				t_FmPortObservedBufPoolDepletion	*p_FmPortObservedBufPoolDepletion);

/**************************************************************************//**
 @Function	FM_PORT_ConfigExtBufPools

 @Description   This routine should be called for OP ports
		that internally use BM buffer pools. In such cases, e.g. for fragmentation and
		re-assembly, the FM needs new BM buffers. By calling this routine the user
		specifies the BM buffer pools that should be used.

		Note: Available for some chips only

		May be used for OP ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_FmExtPools	A structure of parameters for the external pools.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigExtBufPools(t_Handle h_FmPort, t_FmExtPools *p_FmExtPools);

/**************************************************************************//**
 @Function	FM_PORT_ConfigBackupPools

 @Description   Calling this routine allows the configuration of some of the BM pools
		defined for this port as backup pools.
		A pool configured to be a backup pool will be used only if all other
		enabled non - backup pools are depleted.

		May be used for Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_FmPortBackupBmPools   An array of pool id's. All pools specified here will
				be defined as backup pools.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigBackupPools(t_Handle h_FmPort, t_FmBackupBmPools *p_FmPortBackupBmPools);

/**************************************************************************//**
 @Function	FM_PORT_ConfigFrmDiscardOverride

 @Description   Calling this routine changes the error frames destination parameter
		in the internal driver data base from its default configuration :
		override =[DEFAULT_PORT_frmDiscardOverride]

		May be used for Rx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	override	TRUE to override discarding of error frames and
				enqueueing them to error queue.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigFrmDiscardOverride(t_Handle h_FmPort, bool override);

/**************************************************************************//**
 @Function	FM_PORT_ConfigErrorsToDiscard

 @Description   Calling this routine changes the behaviour on error parameter
		in the internal driver data base from its default configuration :
		[DEFAULT_PORT_errorsToDiscard].
		If a requested error was previously defined as "ErrorsToEnqueue" it's
		definition will change and the frame will be discarded.
		Errors that were not defined either as "ErrorsToEnqueue" nor as
		"ErrorsToDiscard", will be forwarded to CPU.

		May be used for Rx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	errs	A list of errors to discard

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigErrorsToDiscard(t_Handle h_FmPort, fmPortFrameErrSelect_t errs);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDmaSwapData

 @Description   Calling this routine changes the DMA swap data aparameter
		in the internal driver data base from its default
		configuration[DEFAULT_PORT_dmaSwapData]

		May be used for all port types

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	swapData	New selection

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDmaSwapData(t_Handle h_FmPort, e_FmDmaSwapOption swapData);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDmaIcCacheAttr

 @Description   Calling this routine changes the internal context cache
		attribute parameter in the internal driver data base
		from its default configuration[DEFAULT_PORT_dmaIntContextCacheAttr]

		May be used for all port types

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	intContextCacheAttr	New selection

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDmaIcCacheAttr(t_Handle h_FmPort, e_FmDmaCacheOption intContextCacheAttr);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDmaHdrAttr

 @Description   Calling this routine changes the header cache
		attribute parameter in the internal driver data base
		from its default configuration[DEFAULT_PORT_dmaHeaderCacheAttr]

		May be used for all port types

 @Param[in]	h_FmPort			A handle to a FM Port module.
 @Param[in]	headerCacheAttr		New selection

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDmaHdrAttr(t_Handle h_FmPort, e_FmDmaCacheOption headerCacheAttr);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDmaScatterGatherAttr

 @Description   Calling this routine changes the scatter gather cache
		attribute parameter in the internal driver data base
		from its default configuration[DEFAULT_PORT_dmaScatterGatherCacheAttr]

		May be used for all port types

 @Param[in]	h_FmPort			A handle to a FM Port module.
 @Param[in]	scatterGatherCacheAttr	New selection

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDmaScatterGatherAttr(t_Handle h_FmPort, e_FmDmaCacheOption scatterGatherCacheAttr);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDmaWriteOptimize

 @Description   Calling this routine changes the write optimization
		parameter in the internal driver data base
		from its default configuration : By default optimize = [DEFAULT_PORT_dmaWriteOptimize].
		Note:

		1. For head optimization, data alignment must be >= 16 (supported by default).

		3. For tail optimization, note that the optimization is performed by extending the write transaction
		of the frame payload at the tail as needed to achieve optimal bus transfers, so that the last write
		is extended to be on 16 / 64 bytes aligned block (chip dependent).

		Relevant for non - Tx port types

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	optimize	TRUE to enable optimization, FALSE for normal operation

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDmaWriteOptimize(t_Handle h_FmPort, bool optimize);

/**************************************************************************//**
 @Function	FM_PORT_ConfigNoScatherGather

 @Description	Calling this routine changes the noScatherGather parameter in internal driver data base
		from its default configuration.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	noScatherGather (TRUE - frame is discarded if can not be stored in single buffer,
				FALSE - frame can be stored in scatter gather (S / G) format).

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigNoScatherGather(t_Handle h_FmPort, bool noScatherGather);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDfltColor

 @Description   Calling this routine changes the internal default color parameter
		in the internal driver data base
		from its default configuration[DEFAULT_PORT_color]

		May be used for all port types

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	color	New selection

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDfltColor(t_Handle h_FmPort, e_FmPortColor color);

/**************************************************************************//**
 @Function	FM_PORT_ConfigSyncReq

 @Description   Calling this routine changes the synchronization attribute parameter
		in the internal driver data base from its default configuration :
		syncReq =[DEFAULT_PORT_syncReq]

		May be used for all port types

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	syncReq	TRUE to request synchronization, FALSE otherwize.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigSyncReq(t_Handle h_FmPort, bool syncReq);

/**************************************************************************//**
 @Function	FM_PORT_ConfigForwardReuseIntContext

 @Description   This routine is relevant for Rx ports that are routed to OP port.
		It changes the internal context reuse option in the internal
		driver data base from its default configuration :
		reuse =[DEFAULT_PORT_forwardIntContextReuse]

		May be used for Rx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	reuse	TRUE to reuse internal context on frames
				forwarded to OP port.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigForwardReuseIntContext(t_Handle h_FmPort, bool reuse);

/**************************************************************************//**
 @Function	FM_PORT_ConfigDontReleaseTxBufToBM

 @Description   This routine should be called if no Tx confirmation
		is done, and yet buffers should not be released to the BM.

		Normally, buffers are returned using the Tx confirmation
		process. When Tx confirmation is not used (defFqid = 0),
		buffers are typically released to the BM. This routine
		may be called to avoid this behavior and not release the
		buffers.

		May be used for Tx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigDontReleaseTxBufToBM(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_ConfigIMMaxRxBufLength

 @Description   Changes the maximum receive buffer length from its default
		configuration: Closest rounded down power of 2 value of the
		data buffer size.

		The maximum receive buffer length directly affects the structure
		of received frames (single- or multi-buffered) and the performance
		of both the FM and the driver.

		The selection between single- or multi-buffered frames should be
		done according to the characteristics of the specific application.
		The recommended mode is to use a single data buffer per packet,
		as this mode provides the best performance. However, the user can
		select to use multiple data buffers per packet.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	newVal	Maximum receive buffer length (in bytes).

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
uint32_t FM_PORT_ConfigIMMaxRxBufLength(t_Handle h_FmPort, uint16_t newVal);

/**************************************************************************//**
 @Function	FM_PORT_ConfigIMRxBdRingLength

 @Description   Changes the receive BD ring length from its default
		configuration:[DEFAULT_PORT_rxBdRingLength]

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	newVal	The desired BD ring length.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
uint32_t FM_PORT_ConfigIMRxBdRingLength(t_Handle h_FmPort, uint16_t newVal);

/**************************************************************************//**
 @Function	FM_PORT_ConfigIMTxBdRingLength

 @Description   Changes the transmit BD ring length from its default
		configuration:[DEFAULT_PORT_txBdRingLength]

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	newVal	The desired BD ring length.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
uint32_t FM_PORT_ConfigIMTxBdRingLength(t_Handle h_FmPort, uint16_t newVal);

/**************************************************************************//**
 @Function	FM_PORT_ConfigIMFmanCtrlExternalStructsMemory

 @Description   Configures memory partition and attributes for FMan-Controller
		data structures (e.g. BD rings).
		Calling this routine changes the internal driver data base
		from its default configuration
		[DEFAULT_PORT_ImfwExtStructsMemId, DEFAULT_PORT_ImfwExtStructsMemAttr].

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	memId	Memory partition ID.
 @Param[in]	memAttributes   Memory attributes mask (a combination of MEMORY_ATTR_x flags).

 @Return	E_OK on success; Error code otherwise.
*//***************************************************************************/
uint32_t  FM_PORT_ConfigIMFmanCtrlExternalStructsMemory(t_Handle h_FmPort,
					uint8_t  memId,
					uint32_t memAttributes);

/**************************************************************************//**
 @Function	FM_PORT_ConfigIMPolling

 @Description   Changes the Rx flow from interrupt driven (default) to polling.

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
uint32_t FM_PORT_ConfigIMPolling(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_ConfigMaxFrameLength

 @Description   Changes the definition of the max size of frame that should be
		transmitted/received on this port from its default value [DEFAULT_PORT_maxFrameLength].
		This parameter is used for confirmation of the minimum Fifo
		size calculations and only for Tx ports or ports working in
		independent mode. This should be larger than the maximum possible
		MTU that will be used for this port (i.e. its MAC).

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	length	Max size of frame

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
		This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
uint32_t FM_PORT_ConfigMaxFrameLength(t_Handle h_FmPort, uint16_t length);

/**************************************************************************//*
 @Function	FM_PORT_ConfigTxFifoMinFillLevel

 @Description   Calling this routine changes the fifo minimum
		fill level parameter in the internal driver data base
		from its default configuration[DEFAULT_PORT_txFifoMinFillLevel]

		May be used for Tx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	minFillLevel	New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigTxFifoMinFillLevel(t_Handle h_FmPort, uint32_t minFillLevel);

/**************************************************************************//*
 @Function	FM_PORT_ConfigFifoDeqPipelineDepth

 @Description   Calling this routine changes the fifo dequeue
		pipeline depth parameter in the internal driver data base

		from its default configuration : 1G ports : [DEFAULT_PORT_fifoDeqPipelineDepth_1G],
		10G port : [DEFAULT_PORT_fifoDeqPipelineDepth_10G],
		OP port : [DEFAULT_PORT_fifoDeqPipelineDepth_OH]

		May be used for Tx / OP ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	deqPipelineDepth	New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigFifoDeqPipelineDepth(t_Handle h_FmPort, uint8_t deqPipelineDepth);

/**************************************************************************//*
 @Function	FM_PORT_ConfigTxFifoLowComfLevel

 @Description   Calling this routine changes the fifo low comfort level
		parameter in internal driver data base
		from its default configuration[DEFAULT_PORT_txFifoLowComfLevel]

		May be used for Tx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	fifoLowComfLevel	New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigTxFifoLowComfLevel(t_Handle h_FmPort, uint32_t fifoLowComfLevel);

/**************************************************************************//*
 @Function	FM_PORT_ConfigRxFifoThreshold

 @Description   Calling this routine changes the threshold of the FIFO
		fill level parameter in the internal driver data base
		from its default configuration[DEFAULT_PORT_rxFifoThreshold]

		If the total number of buffers which are
		currently in use and associated with the
		specific RX port exceed this threshold, the
		BMI will signal the MAC to send a pause frame
		over the link.

		May be used for Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	fifoThreshold	New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigRxFifoThreshold(t_Handle h_FmPort, uint32_t fifoThreshold);

/**************************************************************************//*
 @Function	FM_PORT_ConfigRxFifoPriElevationLevel

 @Description   Calling this routine changes the priority elevation level
		parameter in the internal driver data base from its default
		configuration[DEFAULT_PORT_rxFifoPriElevationLevel]

		If the total number of buffers which are currently in use and
		associated with the specific RX port exceed the amount specified
		in priElevationLevel, BMI will signal the main FM's DMA to

		elevate the FM priority on the system bus.

		May be used for Rx ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	priElevationLevel   New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigRxFifoPriElevationLevel(t_Handle h_FmPort, uint32_t priElevationLevel);

#ifdef FM_HEAVY_TRAFFIC_HANG_ERRATA_FMAN_A005669
/**************************************************************************//*
 @Function	FM_PORT_ConfigBCBWorkaround

 @Description   Configures BCB errata workaround.

		When BCB errata is applicable, the workaround is always
		performed by FM Controller. Thus, this functions doesn't
		actually enable errata workaround but rather allows driver
		to perform adjustments required due to errata workaround
		execution in FM controller.

		Applying BCB workaround also configures FM_PORT_FRM_ERR_PHYSICAL
		errors to be discarded. Thus FM_PORT_FRM_ERR_PHYSICAL can't be
		set by FM_PORT_SetErrorsRoute() function.

 @Param[in]	h_FmPort		A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigBCBWorkaround(t_Handle h_FmPort);
#endif /* FM_HEAVY_TRAFFIC_HANG_ERRATA_FMAN_A005669 */

#if (DPAA_VERSION >= 11)
/**************************************************************************//*
 @Function	FM_PORT_ConfigInternalBuffOffset

 @Description   Configures internal buffer offset.

		May be used for Rx and OP ports only

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	val		New value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ConfigInternalBuffOffset(t_Handle h_FmPort, uint8_t val);
#endif /* (DPAA_VERSION >= 11) */

/** @} */ /* end of FM_PORT_advanced_init_grp group */
/** @} */ /* end of FM_PORT_init_grp group */

/**************************************************************************//**
 @Group	FM_PORT_runtime_control_grp FM Port Runtime Control Unit

 @Description   FM Port Runtime control unit API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   enum for defining FM Port counters
*//***************************************************************************/
typedef enum e_FmPortCounters {
	e_FM_PORT_COUNTERS_CYCLE,			/**< BMI performance counter */
	e_FM_PORT_COUNTERS_TASK_UTIL,		/**< BMI performance counter */
	e_FM_PORT_COUNTERS_QUEUE_UTIL,		/**< BMI performance counter */
	e_FM_PORT_COUNTERS_DMA_UTIL,			/**< BMI performance counter */
	e_FM_PORT_COUNTERS_FIFO_UTIL,		/**< BMI performance counter */
	e_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION,	/**< BMI Rx only performance counter */
	e_FM_PORT_COUNTERS_FRAME,			/**< BMI statistics counter */
	e_FM_PORT_COUNTERS_DISCARD_FRAME,		/**< BMI statistics counter */
	e_FM_PORT_COUNTERS_DEALLOC_BUF,		/**< BMI deallocate buffer statistics counter */
	e_FM_PORT_COUNTERS_RX_BAD_FRAME,		/**< BMI Rx only statistics counter */
	e_FM_PORT_COUNTERS_RX_LARGE_FRAME,		/**< BMI Rx only statistics counter */
	e_FM_PORT_COUNTERS_RX_FILTER_FRAME,		/**< BMI Rx & OP only statistics counter */
	e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR,		/**< BMI Rx, OP & HC only statistics counter */
	e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD,   /**< BMI Rx, OP & HC statistics counter */
	e_FM_PORT_COUNTERS_PREPARE_TO_ENQUEUE_COUNTER,  /**< BMI Rx, OP & HC only statistics counter */
	e_FM_PORT_COUNTERS_WRED_DISCARD,		/**< BMI OP & HC only statistics counter */
	e_FM_PORT_COUNTERS_LENGTH_ERR,		/**< BMI non-Rx statistics counter */
	e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT,	/**< BMI non-Rx statistics counter */
	e_FM_PORT_COUNTERS_DEQ_TOTAL,		/**< QMI total QM dequeues counter */
	e_FM_PORT_COUNTERS_ENQ_TOTAL,		/**< QMI total QM enqueues counter */
	e_FM_PORT_COUNTERS_DEQ_FROM_DEFAULT,		/**< QMI counter */
	e_FM_PORT_COUNTERS_DEQ_CONFIRM		/**< QMI counter */
} e_FmPortCounters;

typedef struct t_FmPortBmiStats {
	uint32_t cntCycle;
	uint32_t cntTaskUtil;
	uint32_t cntQueueUtil;
	uint32_t cntDmaUtil;
	uint32_t cntFifoUtil;
	uint32_t cntRxPauseActivation;
	uint32_t cntFrame;
	uint32_t cntDiscardFrame;
	uint32_t cntDeallocBuf;
	uint32_t cntRxBadFrame;
	uint32_t cntRxLargeFrame;
	uint32_t cntRxFilterFrame;
	uint32_t cntRxListDmaErr;
	uint32_t cntRxOutOfBuffersDiscard;
	uint32_t cntWredDiscard;
	uint32_t cntLengthErr;
	uint32_t cntUnsupportedFormat;
} t_FmPortBmiStats;

/**************************************************************************//**
 @Description   Structure for Port id parameters.
		Fields commented 'IN' are passed by the port module to be used
		by the FM module.
		Fields commented 'OUT' will be filled by FM before returning to port.
*//***************************************************************************/
typedef struct t_FmPortCongestionGrps {
	uint16_t	numOfCongestionGrpsToConsider;	/**< The number of required CGs
				to define the size of the following array */
	uint8_t	congestionGrpsToConsider[FM_PORT_NUM_OF_CONGESTION_GRPS];
				/**< An array of CG indexes;
				Note that the size of the array should be
				'numOfCongestionGrpsToConsider'. */
#if (DPAA_VERSION >= 11)
	bool	pfcPrioritiesEn[FM_PORT_NUM_OF_CONGESTION_GRPS][FM_MAX_NUM_OF_PFC_PRIORITIES];
				/**< a matrix that represents the map between the CG ids
				defined in 'congestionGrpsToConsider' to the priorties
				mapping array. */
#endif /* (DPAA_VERSION >= 11) */
} t_FmPortCongestionGrps;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response ARP Entry
*//***************************************************************************/
typedef struct t_FmPortDsarArpEntry {
	uint32_t  ipAddress;
	uint8_t   mac[6];
	bool	isVlan;
	uint16_t  vid;
} t_FmPortDsarArpEntry;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response ARP info
*//***************************************************************************/
typedef struct t_FmPortDsarArpInfo {
	uint8_t	tableSize;
	t_FmPortDsarArpEntry *p_AutoResTable;
	bool		enableConflictDetection; /* when TRUE Conflict Detection will be checked and wake the host if needed */
} t_FmPortDsarArpInfo;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response NDP Entry
*//***************************************************************************/
typedef struct t_FmPortDsarNdpEntry {
	uint32_t  ipAddress[4];
	uint8_t   mac[6];
	bool	isVlan;
	uint16_t  vid;
} t_FmPortDsarNdpEntry;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response NDP info
*//***************************************************************************/
typedef struct t_FmPortDsarNdpInfo
{
	uint32_t		multicastGroup;

	uint8_t		tableSizeAssigned;
	t_FmPortDsarNdpEntry  *p_AutoResTableAssigned; /* This list refer to solicitation IP addresses.
				Note that all IP addresses must be from the same multicast group.
				This will be checked and if not operation will fail. */
	uint8_t		tableSizeTmp;
	t_FmPortDsarNdpEntry  *p_AutoResTableTmp;	/* This list refer to temp IP addresses.
				Note that all temp IP addresses must be from the same multicast group.
				This will be checked and if not operation will fail. */

	bool		enableConflictDetection; /* when TRUE Conflict Detection will be checked and wake the host if needed */

} t_FmPortDsarNdpInfo;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response ICMPV4 info
*//***************************************************************************/
typedef struct t_FmPortDsarEchoIpv4Info {
	uint8_t		tableSize;
	t_FmPortDsarArpEntry  *p_AutoResTable;
} t_FmPortDsarEchoIpv4Info;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response ICMPV6 info
*//***************************************************************************/
typedef struct t_FmPortDsarEchoIpv6Info {
	uint8_t		tableSize;
	t_FmPortDsarNdpEntry  *p_AutoResTable;
} t_FmPortDsarEchoIpv6Info;

/**************************************************************************//**
@Description	Deep Sleep Auto Response SNMP OIDs table entry

*//***************************************************************************/
typedef struct {
	uint16_t	oidSize;
	uint8_t	*oidVal; /* only the oid string */
	uint16_t	resSize;
	uint8_t	*resVal; /* resVal will be the entire reply,
		i.e. "Type|Length|Value" */
} t_FmPortDsarOidsEntry;

/**************************************************************************//**
 @Description   Deep Sleep Auto Response SNMP IPv4 Addresses Table Entry
		Refer to the FMan Controller spec for more details.
*//***************************************************************************/
typedef struct
{
	uint32_t ipv4Addr; /*!< 32 bit IPv4 Address. */
	bool	isVlan;
	uint16_t vid;   /*!< 12 bits VLAN ID. The 4 left-most bits should be cleared			*/
			/*!< This field should be 0x0000 for an entry with no VLAN tag or a null VLAN ID. */
} t_FmPortDsarSnmpIpv4AddrTblEntry;

/**************************************************************************//**
 @Description   Deep Sleep Auto Response SNMP IPv6 Addresses Table Entry
		Refer to the FMan Controller spec for more details.
*//***************************************************************************/
typedef struct
{
	uint32_t ipv6Addr[4];  /*!< 4 * 32 bit IPv6 Address.					*/
	bool	isVlan;
	uint16_t vid;	/*!< 12 bits VLAN ID. The 4 left-most bits should be cleared			*/
			/*!< This field should be 0x0000 for an entry with no VLAN tag or a null VLAN ID. */
} t_FmPortDsarSnmpIpv6AddrTblEntry;

/**************************************************************************//**
 @Description   Deep Sleep Auto Response SNMP Descriptor

*//***************************************************************************/
typedef struct
{
	uint16_t control;			/**< Control bits [0-15]. */
	uint16_t maxSnmpMsgLength;		/**< Maximal allowed SNMP message length. */
	uint16_t numOfIpv4Addresses;		/**< Number of entries in IPv4 addresses table. */
	uint16_t numOfIpv6Addresses;		/**< Number of entries in IPv6 addresses table. */
	t_FmPortDsarSnmpIpv4AddrTblEntry *p_Ipv4AddrTbl; /**< Pointer to IPv4 addresses table. */
	t_FmPortDsarSnmpIpv6AddrTblEntry *p_Ipv6AddrTbl; /**< Pointer to IPv6 addresses table. */
	uint8_t *p_RdOnlyCommunityStr;		/**< Pointer to the Read Only Community String. */
	uint8_t *p_RdWrCommunityStr;		/**< Pointer to the Read Write Community String. */
	t_FmPortDsarOidsEntry *p_OidsTbl;		/**< Pointer to OIDs table. */
	uint32_t oidsTblSize;			/**< Number of entries in OIDs table. */
} t_FmPortDsarSnmpInfo;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response filtering Entry
*//***************************************************************************/
typedef struct t_FmPortDsarFilteringEntry
{
	uint16_t	srcPort;
	uint16_t	dstPort;
	uint16_t	srcPortMask;
	uint16_t	dstPortMask;
} t_FmPortDsarFilteringEntry;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response filtering info
*//***************************************************************************/
typedef struct t_FmPortDsarFilteringInfo
{
	/* IP protocol filtering parameters */
	uint8_t	ipProtTableSize;
	uint8_t	*p_IpProtTablePtr;
	bool	ipProtPassOnHit;  /* when TRUE, miss in the table will cause the packet to be droped,
				hit will pass the packet to UDP/TCP filters if needed and if not
				to the classification tree. If the classification tree will pass
				the packet to a queue it will cause a wake interupt.
				When FALSE it the other way around. */
	/* UDP port filtering parameters */
	uint8_t	udpPortsTableSize;
	t_FmPortDsarFilteringEntry *p_UdpPortsTablePtr;
	bool	udpPortPassOnHit; /* when TRUE, miss in the table will cause the packet to be droped,
				hit will pass the packet to classification tree.
				If the classification tree will pass the packet to a queue it
				will cause a wake interupt.
				When FALSE it the other way around. */
	/* TCP port filtering parameters */
	uint16_t	tcpFlagsMask;
	uint8_t	tcpPortsTableSize;
	t_FmPortDsarFilteringEntry *p_TcpPortsTablePtr;
	bool	tcpPortPassOnHit; /* when TRUE, miss in the table will cause the packet to be droped,
				hit will pass the packet to classification tree.
				If the classification tree will pass the packet to a queue it
				will cause a wake interupt.
				When FALSE it the other way around. */
} t_FmPortDsarFilteringInfo;

/**************************************************************************//**
 @Description   Structure for Deep Sleep Auto Response parameters
*//***************************************************************************/
typedef struct t_FmPortDsarParams
{
	t_Handle		h_FmPortTx;
	t_FmPortDsarArpInfo	*p_AutoResArpInfo;
	t_FmPortDsarEchoIpv4Info  *p_AutoResEchoIpv4Info;
	t_FmPortDsarNdpInfo	*p_AutoResNdpInfo;
	t_FmPortDsarEchoIpv6Info  *p_AutoResEchoIpv6Info;
	t_FmPortDsarSnmpInfo	*p_AutoResSnmpInfo;
	t_FmPortDsarFilteringInfo *p_AutoResFilteringInfo;
} t_FmPortDsarParams;

/**************************************************************************//**
 @Function	FM_PORT_EnterDsar

 @Description   Enter Deep Sleep Auto Response mode.
		This function write the appropriate values to in the relevant
		tables in the MURAM.

 @Param[in]	h_FmPortRx - FM PORT module descriptor
 @Param[in]	params - Auto Response parameters

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_EnterDsar(t_Handle h_FmPortRx, t_FmPortDsarParams *params);

/**************************************************************************//**
 @Function	FM_PORT_EnterDsarFinal

 @Description   Enter Deep Sleep Auto Response mode.
		This function sets the Tx port in independent mode as needed
		and redirect the receive flow to go through the
		Dsar Fman-ctrl code

 @Param[in]	h_DsarRxPort - FM Rx PORT module descriptor
 @Param[in]	h_DsarTxPort - FM Tx PORT module descriptor

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_EnterDsarFinal(t_Handle h_DsarRxPort, t_Handle h_DsarTxPort);

/**************************************************************************//**
 @Function	FM_PORT_ExitDsar

 @Description   Exit Deep Sleep Auto Response mode.
		This function reverse the AR mode and put the ports back into
		their original wake mode

 @Param[in]	h_FmPortRx - FM PORT Rx module descriptor
 @Param[in]	h_FmPortTx - FM PORT Tx module descriptor

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_EnterDsar().
*//***************************************************************************/
void FM_PORT_ExitDsar(t_Handle h_FmPortRx, t_Handle h_FmPortTx);

/**************************************************************************//**
 @Function	FM_PORT_IsInDsar

 @Description   This function returns TRUE if the port was set as Auto Response
		and FALSE if not. Once Exit AR mode it will return FALSE as well
		until re-enabled once more.

 @Param[in]	h_FmPort - FM PORT module descriptor

 @Return	E_OK on success; Error code otherwise.
*//***************************************************************************/
bool FM_PORT_IsInDsar(t_Handle h_FmPort);

typedef struct t_FmPortDsarStats
{
	uint32_t arpArCnt;
	uint32_t echoIcmpv4ArCnt;
	uint32_t ndpArCnt;
	uint32_t echoIcmpv6ArCnt;
	uint32_t snmpGetCnt;
	uint32_t snmpGetNextCnt;
} t_FmPortDsarStats;

/**************************************************************************//**
 @Function	FM_PORT_GetDsarStats

 @Description   Return statistics for Deep Sleep Auto Response

 @Param[in]	h_FmPortRx - FM PORT module descriptor
 @Param[out]	stats - structure containing the statistics counters

 @Return	E_OK on success; Error code otherwise.
*//***************************************************************************/
uint32_t FM_PORT_GetDsarStats(t_Handle h_FmPortRx, t_FmPortDsarStats *stats);

#if (defined(DEBUG_ERRORS) && (DEBUG_ERRORS > 0))
/**************************************************************************//**
 @Function	FM_PORT_DumpRegs

 @Description   Dump all regs.

		Calling this routine invalidates the descriptor.

 @Param[in]	h_FmPort - FM PORT module descriptor

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_DumpRegs(t_Handle h_FmPort);
#endif /* (defined(DEBUG_ERRORS) && ... */

/**************************************************************************//**
 @Function	FM_PORT_GetBufferDataOffset

 @Description   Relevant for Rx ports.
		Returns the data offset from the beginning of the data buffer

 @Param[in]	h_FmPort - FM PORT module descriptor

 @Return	data offset.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_GetBufferDataOffset(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_GetBufferICInfo

 @Description   Returns the Internal Context offset from the beginning of the data buffer

 @Param[in]	h_FmPort - FM PORT module descriptor
 @Param[in]	p_Data   - A pointer to the data buffer.

 @Return	Internal context info pointer on success, NULL if 'allOtherInfo' was not
		configured for this port.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint8_t *FM_PORT_GetBufferICInfo(t_Handle h_FmPort, char *p_Data);

/**************************************************************************//**
 @Function	FM_PORT_GetBufferPrsResult

 @Description   Returns the pointer to the parse result in the data buffer.
		In Rx ports this is relevant after reception, if parse
		result is configured to be part of the data passed to the
		application. For non Rx ports it may be used to get the pointer
		of the area in the buffer where parse result should be
		initialized - if so configured.
		See FM_PORT_ConfigBufferPrefixContent for data buffer prefix
		configuration.

 @Param[in]	h_FmPort	- FM PORT module descriptor
 @Param[in]	p_Data	- A pointer to the data buffer.

 @Return	Parse result pointer on success, NULL if parse result was not
		configured for this port.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_FmPrsResult *FM_PORT_GetBufferPrsResult(t_Handle h_FmPort, char *p_Data);

/**************************************************************************//**
 @Function	FM_PORT_GetBufferTimeStamp

 @Description   Returns the time stamp in the data buffer.
		Relevant for Rx ports for getting the buffer time stamp.
		See FM_PORT_ConfigBufferPrefixContent for data buffer prefix
		configuration.

 @Param[in]	h_FmPort	- FM PORT module descriptor
 @Param[in]	p_Data	- A pointer to the data buffer.

 @Return	A pointer to the hash result on success, NULL otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint64_t *FM_PORT_GetBufferTimeStamp(t_Handle h_FmPort, char *p_Data);

/**************************************************************************//**
 @Function	FM_PORT_GetBufferHashResult

 @Description   Given a data buffer, on the condition that hash result was defined
		as a part of the buffer content(see FM_PORT_ConfigBufferPrefixContent)
		this routine will return the pointer to the hash result location in the
		buffer prefix.

 @Param[in]	h_FmPort	- FM PORT module descriptor
 @Param[in]	p_Data	- A pointer to the data buffer.

 @Return	A pointer to the hash result on success, NULL otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint8_t *FM_PORT_GetBufferHashResult(t_Handle h_FmPort, char *p_Data);

/**************************************************************************//**
 @Function	FM_PORT_Disable

 @Description   Gracefully disable an FM port. The port will not start new tasks after all
		tasks associated with the port are terminated.

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
		This is a blocking routine, it returns after port is
		gracefully stopped, i.e. the port will not except new frames,
		but it will finish all frames or tasks which were already began
*//***************************************************************************/
uint32_t FM_PORT_Disable(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_Enable

 @Description   A runtime routine provided to allow disable/enable of port.

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_Enable(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_SetRateLimit

 @Description   Calling this routine enables rate limit algorithm.
		By default, this functionality is disabled.

		Note that rate - limit mechanism uses the FM time stamp.
		The selected rate limit specified here would be
		rounded DOWN to the nearest 16M.

		May be used for Tx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_RateLimit	A structure of rate limit parameters

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
		If rate limit is set on a port that need to send PFC frames,
		it might violate the stop transmit timing.
*//***************************************************************************/
uint32_t FM_PORT_SetRateLimit(t_Handle h_FmPort, t_FmPortRateLimit *p_RateLimit);

/**************************************************************************//**
 @Function	FM_PORT_DeleteRateLimit

 @Description   Calling this routine disables and clears rate limit
		initialization.

		May be used for Tx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_DeleteRateLimit(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_SetPfcPrioritiesMappingToQmanWQ

 @Description   Calling this routine maps each PFC received priority to the transmit WQ.
		This WQ will be blocked upon receiving a PFC frame with this priority.

		May be used for Tx ports only.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	prio		PFC priority (0 - 7).
 @Param[in]	wq		Work Queue (0 - 7).

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetPfcPrioritiesMappingToQmanWQ(t_Handle h_FmPort, uint8_t prio, uint8_t wq);

/**************************************************************************//**
 @Function	FM_PORT_SetStatisticsCounters

 @Description   Calling this routine enables/disables port's statistics counters.
		By default, counters are enabled.

		May be used for all port types

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	enable	TRUE to enable, FALSE to disable.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetStatisticsCounters(t_Handle h_FmPort, bool enable);

/**************************************************************************//**
 @Function	FM_PORT_SetFrameQueueCounters

 @Description   Calling this routine enables/disables port's enqueue/dequeue counters.
		By default, counters are enabled.

		May be used for all ports

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	enable	TRUE to enable, FALSE to disable.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetFrameQueueCounters(t_Handle h_FmPort, bool enable);

/**************************************************************************//**
 @Function	FM_PORT_AnalyzePerformanceParams

 @Description   User may call this routine to so the driver will analyze if the
		basic performance parameters are correct and also the driver may
		suggest of improvements; The basic parameters are FIFO sizes, number
		of DMAs and number of TNUMs for the port.

		May be used for all port types

 @Param[in]	h_FmPort		A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_AnalyzePerformanceParams(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_SetAllocBufCounter

 @Description   Calling this routine enables/disables BM pool allocate
		buffer counters.
		By default, counters are enabled.

		May be used for Rx ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	poolId	BM pool id.
 @Param[in]	enable	TRUE to enable, FALSE to disable.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetAllocBufCounter(t_Handle h_FmPort, uint8_t poolId, bool enable);

/**************************************************************************//**
 @Function	FM_PORT_GetBmiCounters

 @Description   Read port's BMI stat counters and place them into
		a designated structure of counters.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[out]	p_BmiStats  counters structure

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_GetBmiCounters(t_Handle h_FmPort, t_FmPortBmiStats *p_BmiStats);

/**************************************************************************//**
 @Function	FM_PORT_GetCounter

 @Description   Reads one of the FM PORT counters.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	fmPortCounter	The requested counter.

 @Return	Counter's current value.

 @Cautions	Allowed only following FM_PORT_Init().
		Note that it is user's responsibility to call this routine only
		for enabled counters, and there will be no indication if a
		disabled counter is accessed.
*//***************************************************************************/
uint32_t FM_PORT_GetCounter(t_Handle h_FmPort, e_FmPortCounters fmPortCounter);

/**************************************************************************//**
 @Function	FM_PORT_ModifyCounter

 @Description   Sets a value to an enabled counter. Use "0" to reset the counter.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	fmPortCounter	The requested counter.
 @Param[in]	value		The requested value to be written into the counter.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ModifyCounter(t_Handle h_FmPort, e_FmPortCounters fmPortCounter, uint32_t value);

/**************************************************************************//**
 @Function	FM_PORT_GetAllocBufCounter

 @Description   Reads one of the FM PORT buffer counters.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	poolId		The requested pool.

 @Return	Counter's current value.

 @Cautions	Allowed only following FM_PORT_Init().
		Note that it is user's responsibility to call this routine only
		for enabled counters, and there will be no indication if a
		disabled counter is accessed.
*//***************************************************************************/
uint32_t FM_PORT_GetAllocBufCounter(t_Handle h_FmPort, uint8_t poolId);

/**************************************************************************//**
 @Function	FM_PORT_ModifyAllocBufCounter

 @Description   Sets a value to an enabled counter. Use "0" to reset the counter.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	poolId		The requested pool.
 @Param[in]	value		The requested value to be written into the counter.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ModifyAllocBufCounter(t_Handle h_FmPort,  uint8_t poolId, uint32_t value);

/**************************************************************************//**
 @Function	FM_PORT_AddCongestionGrps

 @Description   This routine effects the corresponding Tx port.
		It should be called in order to enable pause
		frame transmission in case of congestion in one or more
		of the congestion groups relevant to this port.
		Each call to this routine may add one or more congestion
		groups to be considered relevant to this port.

		May be used for Rx, or RX + OP ports only (depending on chip)

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_CongestionGrps	A pointer to an array of congestion groups
				id's to consider.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_AddCongestionGrps(t_Handle h_FmPort, t_FmPortCongestionGrps *p_CongestionGrps);

/**************************************************************************//**
 @Function	FM_PORT_RemoveCongestionGrps

 @Description   This routine effects the corresponding Tx port. It should be
		called when congestion groups were
		defined for this port and are no longer relevant, or pause
		frames transmitting is not required on their behalf.
		Each call to this routine may remove one or more congestion
		groups to be considered relevant to this port.

		May be used for Rx, or RX + OP ports only (depending on chip)

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_CongestionGrps	A pointer to an array of congestion groups
				id's to consider.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_RemoveCongestionGrps(t_Handle h_FmPort, t_FmPortCongestionGrps *p_CongestionGrps);

/**************************************************************************//**
 @Function	FM_PORT_IsStalled

 @Description   A routine for checking whether the specified port is stalled.

 @Param[in]	h_FmPort		A handle to a FM Port module.

 @Return	TRUE if port is stalled, FALSE otherwize

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
bool FM_PORT_IsStalled(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_ReleaseStalled

 @Description   This routine may be called in case the port was stalled and may
		now be released.
		Note that this routine is available only on older FMan revisions
		(FMan v2, DPAA v1.0 only).

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_ReleaseStalled(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_SetRxL4ChecksumVerify

 @Description   This routine is relevant for Rx ports (1G and 10G). The routine
		set / clear the L3 / L4 checksum verification (on RX side).
		Note that this takes affect only if hw - parser is enabled !

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	l4Checksum	boolean indicates whether to do L3/L4 checksum
				on frames or not.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetRxL4ChecksumVerify(t_Handle h_FmPort, bool l4Checksum);

/**************************************************************************//**
 @Function	FM_PORT_SetErrorsRoute

 @Description   Errors selected for this routine will cause a frame with that error
		to be enqueued to error queue.
		Errors not selected for this routine will cause a frame with that error
		to be enqueued to the one of the other port queues.
		By default all errors are defined to be enqueued to error queue.
		Errors that were configured to be discarded(at initialization)
		may not be selected here.

		May be used for Rx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	errs	A list of errors to enqueue to error queue

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetErrorsRoute(t_Handle h_FmPort, fmPortFrameErrSelect_t errs);

/**************************************************************************//**
 @Function	FM_PORT_SetIMExceptions

 @Description   Calling this routine enables/disables FM PORT interrupts.

 @Param[in]	h_FmPort	FM PORT module descriptor.
 @Param[in]	exception	The exception to be selected.
 @Param[in]	enable	TRUE to enable interrupt, FALSE to mask it.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
		This routine should NOT be called from guest-partition
		(i.e. guestId != NCSW_MASTER_ID)
*//***************************************************************************/
uint32_t FM_PORT_SetIMExceptions(t_Handle h_FmPort, e_FmPortExceptions exception, bool enable);

/**************************************************************************//*
 @Function	FM_PORT_SetPerformanceCounters

 @Description   Calling this routine enables/disables port's performance counters.
		By default, counters are enabled.

		May be used for all port types

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	enable		TRUE to enable, FALSE to disable.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetPerformanceCounters(t_Handle h_FmPort, bool enable);

/**************************************************************************//*
 @Function	FM_PORT_SetPerformanceCountersParams

 @Description   Calling this routine defines port's performance
		counters parameters.

		May be used for all port types

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_FmPortPerformanceCnt  A pointer to a structure of performance
				counters parameters.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetPerformanceCountersParams(t_Handle h_FmPort, t_FmPortPerformanceCnt *p_FmPortPerformanceCnt);

/**************************************************************************//**
 @Group	FM_PORT_pcd_runtime_control_grp FM Port PCD Runtime Control Unit

 @Description   FM Port PCD Runtime control unit API functions, definitions and enums.

 @Function	FM_PORT_SetPCD

 @Description   Calling this routine defines the port's PCD configuration.
		It changes it from its default configuration which is PCD
		disabled (BMI to BMI) and configures it according to the passed
		parameters.

		May be used for Rx and OP ports only

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_FmPortPcd	A Structure of parameters defining the port's PCD
				configuration.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_SetPCD(t_Handle h_FmPort, ioc_fm_port_pcd_params_t *p_FmPortPcd);

/**************************************************************************//**
 @Function	FM_PORT_DeletePCD

 @Description   Calling this routine releases the port's PCD configuration.
		The port returns to its default configuration which is PCD
		disabled (BMI to BMI) and all PCD configuration is removed.

		May be used for Rx and OP ports which are
		in PCD mode  only

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_DeletePCD(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_AttachPCD

 @Description   This routine may be called after FM_PORT_DetachPCD was called,
		to return to the originally configured PCD support flow.
		The couple of routines are used to allow PCD configuration changes
		that demand that PCD will not be used while changes take place.

		May be used for Rx and OP ports which are
		in PCD mode only

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint32_t FM_PORT_AttachPCD(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_DetachPCD

 @Description   Calling this routine detaches the port from its PCD functionality.
		The port returns to its default flow which is BMI to BMI.

		May be used for Rx and OP ports which are
		in PCD mode only

 @Param[in]	h_FmPort	A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_AttachPCD().
*//***************************************************************************/
uint32_t FM_PORT_DetachPCD(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrAllocProfiles

 @Description   This routine may be called only for ports that use the Policer in
		order to allocate private policer profiles.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	numOfProfiles	The number of required policer profiles

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PCD_Init(),
		and before FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdPlcrAllocProfiles(t_Handle h_FmPort, uint16_t numOfProfiles);

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrFreeProfiles

 @Description   This routine should be called for freeing private policer profiles.

 @Param[in]	h_FmPort		A handle to a FM Port module.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PCD_Init(),
		and before FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdPlcrFreeProfiles(t_Handle h_FmPort);

/**************************************************************************//**
 @Function	FM_PORT_PcdKgModifyInitialScheme

 @Description   This routine may be called only for ports that use the keygen in
		order to change the initial scheme frame should be routed to.
		The change may be of a scheme id(in case of direct mode),
		from direct to indirect, or from indirect to direct - specifying the scheme id.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	p_FmPcdKgScheme	A structure of parameters for defining whether
				a scheme is direct / indirect, and if direct - scheme id.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdKgModifyInitialScheme(t_Handle h_FmPort, ioc_fm_pcd_kg_scheme_select_t *p_FmPcdKgScheme);

/**************************************************************************//**
 @Function	FM_PORT_PcdPlcrModifyInitialProfile

 @Description   This routine may be called for ports with flows
		e_FM_PORT_PCD_SUPPORT_PLCR_ONLY or e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR
		only, to change the initial Policer profile frame should be
		routed to. The change may be of a profile and / or absolute / direct
		mode selection.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	h_Profile		Policer profile handle

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdPlcrModifyInitialProfile(t_Handle h_FmPort, t_Handle h_Profile);

/**************************************************************************//**
 @Function	FM_PORT_PcdCcModifyTree

 @Description   This routine may be called for ports that use coarse classification tree
		if the user wishes to replace the tree. The routine may not be called while port
		receives packets using the PCD functionalities, therefor port must be first detached
		from the PCD, only than the routine may be called, and than port be attached to PCD again.

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[in]	h_CcTree		A CC tree that was already built. The tree id as returned from
				the BuildTree routine.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init(), FM_PORT_SetPCD() and FM_PORT_DetachPCD()
*//***************************************************************************/
uint32_t FM_PORT_PcdCcModifyTree(t_Handle h_FmPort, t_Handle h_CcTree);

/**************************************************************************//**
 @Function	FM_PORT_PcdKgBindSchemes

 @Description   These routines may be called for adding more schemes for the
		port to be bound to. The selected schemes are not added,
		just this specific port starts using them.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_PortScheme	A structure defining the list of schemes to be added.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdKgBindSchemes(t_Handle h_FmPort, ioc_fm_pcd_port_schemes_params_t *p_PortScheme);

/**************************************************************************//**
 @Function	FM_PORT_PcdKgUnbindSchemes

 @Description   These routines may be called for adding more schemes for the
		port to be bound to. The selected schemes are not removed or invalidated,
		just this specific port stops using them.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_PortScheme	A structure defining the list of schemes to be added.

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init() and FM_PORT_SetPCD().
*//***************************************************************************/
uint32_t FM_PORT_PcdKgUnbindSchemes(t_Handle h_FmPort, ioc_fm_pcd_port_schemes_params_t *p_PortScheme);

/**************************************************************************//**
 @Function	FM_PORT_GetIPv4OptionsCount

 @Description   TODO

 @Param[in]	h_FmPort		A handle to a FM Port module.
 @Param[out]	p_Ipv4OptionsCount  will hold the counter value

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init()
*//***************************************************************************/
uint32_t FM_PORT_GetIPv4OptionsCount(t_Handle h_FmPort, uint32_t *p_Ipv4OptionsCount);

/** @} */ /* end of FM_PORT_pcd_runtime_control_grp group */
/** @} */ /* end of FM_PORT_runtime_control_grp group */

/**************************************************************************//**
 @Group	FM_PORT_runtime_data_grp FM Port Runtime Data-path Unit

 @Description   FM Port Runtime data unit API functions, definitions and enums.
		This API is valid only if working in Independent-Mode.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Function	FM_PORT_ImTx

 @Description   Tx function, called to transmit a data buffer on the port.

 @Param[in]	h_FmPort	A handle to a FM Port module.
 @Param[in]	p_Data	A pointer to an LCP data buffer.
 @Param[in]	length	Size of data for transmission.
 @Param[in]	lastBuffer  Buffer position - TRUE for the last buffer
				of a frame, including a single buffer frame
 @Param[in]	h_BufContext  A handle of the user acossiated with this buffer

 @Return	E_OK on success; Error code otherwise.

 @Cautions	Allowed only following FM_PORT_Init().
		NOTE - This routine can be used only when working in
		Independent-Mode mode.
*//***************************************************************************/
uint32_t  FM_PORT_ImTx(t_Handle		h_FmPort,
			uint8_t		*p_Data,
			uint16_t		length,
			bool		lastBuffer,
			t_Handle		h_BufContext);

/**************************************************************************//**
 @Function	FM_PORT_ImTxConf

 @Description   Tx port confirmation routine, optional, may be called to verify
		transmission of all frames. The procedure performed by this
		routine will be performed automatically on next buffer transmission,
		but if desired, calling this routine will invoke this action on
		demand.

 @Param[in]	h_FmPort		A handle to a FM Port module.

 @Cautions	Allowed only following FM_PORT_Init().
		NOTE - This routine can be used only when working in
		Independent-Mode mode.
*//***************************************************************************/
void FM_PORT_ImTxConf(t_Handle h_FmPort);

uint32_t  FM_PORT_ImRx(t_Handle h_FmPort);

/** @} */ /* end of FM_PORT_runtime_data_grp group */
/** @} */ /* end of FM_PORT_grp group */
/** @} */ /* end of FM_grp group */
#endif /* __FM_PORT_EXT_H */
