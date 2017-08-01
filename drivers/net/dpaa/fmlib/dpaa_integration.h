/*-
 * This file is provided under a dual BSD/GPLv2 license. When using or
 * redistributing this file, you may do so under either license.
 *
 *   BSD LICENSE
 *
 * Copyright 2009-2012 Freescale Semiconductor Inc.
 * Copyright 2017 NXP.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *   GPL LICENSE SUMMARY
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DPAA_INTEGRATION_H
#define __DPAA_INTEGRATION_H

#include "ncsw_ext.h"

#define DPAA_VERSION	11

/*****************************************************************************
 BMan INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define BM_MAX_NUM_OF_POOLS	64	/**< Number of buffers pools */

/*****************************************************************************
 FM INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define INTG_MAX_NUM_OF_FM	2

/* Ports defines */
#define FM_MAX_NUM_OF_1G_MACS	6
#define FM_MAX_NUM_OF_10G_MACS	2
#define FM_MAX_NUM_OF_MACS	(FM_MAX_NUM_OF_1G_MACS + FM_MAX_NUM_OF_10G_MACS)
#define FM_MAX_NUM_OF_OH_PORTS	6

#define FM_MAX_NUM_OF_1G_RX_PORTS   FM_MAX_NUM_OF_1G_MACS
#define FM_MAX_NUM_OF_10G_RX_PORTS  FM_MAX_NUM_OF_10G_MACS
#define FM_MAX_NUM_OF_RX_PORTS	(FM_MAX_NUM_OF_10G_RX_PORTS + FM_MAX_NUM_OF_1G_RX_PORTS)

#define FM_MAX_NUM_OF_1G_TX_PORTS   FM_MAX_NUM_OF_1G_MACS
#define FM_MAX_NUM_OF_10G_TX_PORTS  FM_MAX_NUM_OF_10G_MACS
#define FM_MAX_NUM_OF_TX_PORTS	(FM_MAX_NUM_OF_10G_TX_PORTS + FM_MAX_NUM_OF_1G_TX_PORTS)

#define FM_PORT_MAX_NUM_OF_EXT_POOLS		4	/**< Number of external BM pools per Rx port */
#define FM_PORT_NUM_OF_CONGESTION_GRPS		256	/**< Total number of congestion groups in QM */
#define FM_MAX_NUM_OF_SUB_PORTALS		16
#define FM_PORT_MAX_NUM_OF_OBSERVED_EXT_POOLS   0

/* PCD defines */
#define FM_PCD_PLCR_NUM_ENTRIES		256	/**< Total number of policer profiles */
#define FM_PCD_KG_NUM_OF_SCHEMES	32	/**< Total number of KG schemes */
#define FM_PCD_MAX_NUM_OF_CLS_PLANS	256	/**< Number of classification plan entries. */

#define FM_MAX_NUM_OF_PFC_PRIORITIES		8

#endif /* __DPAA_INTEGRATION_H */
