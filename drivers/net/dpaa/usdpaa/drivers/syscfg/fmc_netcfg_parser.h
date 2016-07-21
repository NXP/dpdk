/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __FMC_NETCFG_PARSER_H
#define	__FMC_NETCFG_PARSER_H

#include <usdpaa/fsl_usd.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/compat.h>
#include <libxml/parser.h>

/* Range of frame queues specified for PCD and Default RX */
struct fmc_netcfg_fqs {
	struct list_head *list; /* List of "struct fm_eth_port_fqrange" */
};

/* pcd_file@ : netpcd file (XML). which have a PCD information.
 * cfg_file@ : cfgdata file (XML).  Which have net config data
 *		This is further linked to netpcd file.
 *
 * Parse the FMC configuration files (XML) and extract the required
 * configuration information in a data structure.
 * */
int fmc_netcfg_parser_init(const char *pcd_file, const char *cfg_file);

/* Free the resources used by FMC NETCFG driver layer */
int fmc_netcfg_parser_exit(void);

/* port_id@:	Port id for which the configuration information is requested.
 * *cfg@:	structure pointer in which the information will be returned.
 *
 * This function returns the configuration information extracted from file
 * FMC configuration file (XML as of now) for the requested port id.
 * */
int fmc_netcfg_get_info(uint8_t fman, bool is_offline, uint8_t p_num,
			struct fmc_netcfg_fqs *cfg);

#endif
