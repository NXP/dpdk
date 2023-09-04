/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#ifndef _XFRM_KM_H
#define _XFRM_KM_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sys/msg.h>
#include <linux/pfkeyv2.h>

#include "ipsec_ike.h"

#ifndef bool
#define bool int
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif /* unlikely */

enum {
	XFRMA_AUTH_PRESENT = 1,
	XFRMA_AUTH_TRUNC_PRESENT = 2
};

struct xfrm_algo_param {
	char alg_name[64];
	uint32_t alg_key_len; /* in bytes */
	uint8_t alg_key[MAX_KEY_SIZE];
};

struct xfrm_algo_trunc_param {
	char alg_name[64];
	uint32_t alg_key_len; /* in bytes */
	uint32_t alg_trunc_len; /* icv trunc in bytes */
	uint8_t alg_key[MAX_KEY_SIZE];
};

union xfrm_auth_algo_param {
	struct xfrm_algo_param alg;
	struct xfrm_algo_trunc_param alg_trunc;
};

struct xfm_ipsec_sa_params {
	int auth_present;
	int ciph_present;
	int encp_present;
	struct xfrm_algo_param ciph_alg;
	union xfrm_auth_algo_param auth_alg;
	struct xfrm_encap_tmpl encp;
};

int setup_xfrm_msgloop(void);

struct ipsec_ike_sa_entry *
xfm_sp_entry_lookup_sa(union ipsec_ike_addr *src,
	union ipsec_ike_addr *dst, rte_be32_t spi,
	uint16_t family, int is_in, int sa_idx);

int
do_spdget(int spid, xfrm_address_t *saddr,
	xfrm_address_t *daddr, int *sa_af);

int
do_spddel(int spid);

int
do_saddel(int spi);

int
pfkey_align(struct sadb_msg *msg, caddr_t *mhp);

int pfkey_recv_sadbmsg(int so, u_int msg_type, u_int32_t seq_num,
	struct sadb_msg **newmsg);

void kdebug_sadb(struct sadb_msg *base);

int pfkey_open(void);

void pfkey_close(int so);

int pfkey_send(int so, struct sadb_msg *msg, int len);

#endif
