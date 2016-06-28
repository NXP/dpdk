/* Copyright (c) 2010-2012 Freescale Semiconductor, Inc.
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

#ifndef USDPAA_NETCFG_H
#define USDPAA_NETCFG_H

#include <usdpaa/fman.h>
#include <argp.h>
/* Represents a contiguous range of FQIDs (to be linked into a per-port list) */
struct fm_eth_port_fqrange {
	struct list_head list;
	uint32_t start;
	uint32_t count;
};

/* Configuration information related to a specific ethernet port */
struct fm_eth_port_cfg {
	/* A list of PCD FQ ranges, obtained from FMC configuration */
	struct list_head *list;
	/* The "Rx default" FQID, obtained from FMC configuration */
	uint32_t rx_def;
	/* Other interface details are in the fman driver interface */
	struct fman_if *fman_if;
};


/* This structure contains the configuration information for the USDPAA app. */
struct usdpaa_netcfg_info {
	uint8_t num_ethports;	/* Number of ports */
	struct fm_eth_port_cfg port_cfg[0]; /* variable structure array of size
					num_ethports. */
};

/* pcd_file: FMC netpcd XML ("policy") file, that contains PCD information.
 * cfg_file: FMC config XML file
 * Returns the configuration information in newly allocated memory.
 */
struct usdpaa_netcfg_info *usdpaa_netcfg_acquire(const char *pcd_file,
					const char *cfg_file);

/* cfg_ptr: configuration information pointer.
 * Frees the resources allocated by the configuration layer.
 */
void usdpaa_netcfg_release(struct usdpaa_netcfg_info *cfg_ptr);

/* cfg_ptr: configuration information pointer.
 * This function dumps configuration data to stdout.
 */
void dump_usdpaa_netcfg(struct usdpaa_netcfg_info *cfg_ptr);

/* fif: FMAN interface
 * flag_up: flag to make this interface enable/disable
 */
void usdpaa_netcfg_enable_disable_shared_rx(const struct fman_if *fif,
					int flag_up);

/* vname : macless interface name
 * src_mac : source MAC address
 */
int get_mac_addr(const char *vname, struct ether_addr *src_mac);

/* ifname : macless interface name
 * addr : MAC address to be set
 */
int set_mac_addr(const char *vname, struct ether_addr *mac);

extern const struct argp netcfg_argp;
#endif
