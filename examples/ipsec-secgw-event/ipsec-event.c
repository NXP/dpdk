/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Copyright 2018 NXP
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_crypto.h>
#include <rte_security.h>
#include <rte_cryptodev.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_hash.h>

#include "ipsec.h"
#include "esp.h"

static inline int
create_session(struct ipsec_ctx *ipsec_ctx, struct ipsec_sa *sa)
{
	struct rte_cryptodev_info cdev_info;
	int32_t ret = 0;
	struct cdev_qp_index *cdev_qp;

	cdev_qp = get_next_cdev_qp();
	RTE_LOG_DP(DEBUG, IPSEC, "Create session for SA spi %u on cryptodev "
			"%u qp %u\n", sa->spi,
			cdev_qp->cdev_id,
			cdev_qp->queue_id);

	if (sa->type == RTE_SECURITY_ACTION_TYPE_NONE) {
		sa->crypto_session = rte_cryptodev_sym_session_create(
				ipsec_ctx->session_pool);
		rte_cryptodev_sym_session_init(cdev_qp->cdev_id,
				sa->crypto_session, sa->xforms,
				ipsec_ctx->session_pool);

		rte_cryptodev_info_get(sa->cdev_qp_id->cdev_id,
				&cdev_info);
		if (cdev_info.sym.max_nb_sessions_per_qp > 0) {
			ret = rte_cryptodev_queue_pair_attach_sym_session(
					cdev_qp->cdev_id,
					cdev_qp->queue_id,
					sa->crypto_session);
			if (ret < 0) {
				RTE_LOG(ERR, IPSEC,
					"Session cannot be attached to cdev: %u, qp %u\n",
					cdev_qp->cdev_id, cdev_qp->queue_id);
				return -1;
			}
		}
	} else {
		struct rte_security_session_conf sess_conf = {
			.action_type = sa->type,
			.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
			{.ipsec = {
				.spi = sa->spi,
				.salt = sa->salt,
				.options = { 0 },
				.direction = sa->direction,
				.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
				.mode = (sa->flags == IP4_TUNNEL ||
						sa->flags == IP6_TUNNEL) ?
					RTE_SECURITY_IPSEC_SA_MODE_TUNNEL :
					RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT,
			} },
			.crypto_xform = sa->xforms

		};

		struct rte_security_ctx *ctx = (struct rte_security_ctx *)
						rte_cryptodev_get_sec_ctx(
						cdev_qp->cdev_id);

		if (sess_conf.ipsec.mode ==
				RTE_SECURITY_IPSEC_SA_MODE_TUNNEL) {
			struct rte_security_ipsec_tunnel_param *tunnel =
					&sess_conf.ipsec.tunnel;
			if (sa->flags == IP4_TUNNEL) {
				tunnel->type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
				tunnel->ipv4.ttl = IPDEFTTL;

				memcpy((uint8_t *)&tunnel->ipv4.src_ip,
					(uint8_t *)&sa->src.ip.ip4, 4);

				memcpy((uint8_t *)&tunnel->ipv4.dst_ip,
					(uint8_t *)&sa->dst.ip.ip4, 4);
			}
			/* TODO support for Transport and IPV6 tunnel */
		}

		sa->sec_session = rte_security_session_create(ctx,
				&sess_conf, ipsec_ctx->session_pool);
		if (sa->sec_session == NULL) {
			RTE_LOG(ERR, IPSEC,
			"SEC Session init failed: err: %d\n", ret);
			return -1;
		}
	}
// TODO: Add inline offload support if required
	sa->cdev_qp_id = cdev_qp;

	return 0;
}

static inline void
enqueue_cop(struct ipsec_sa *sa,
	    struct ipsec_ctx *ipsec_ctx,
	    struct rte_crypto_op *cop,
	    uint8_t is_last)
{
	struct buf_list *buf_list = &ipsec_ctx->tbl[sa->cdev_qp_id->id];
	int ret, i, current_num_cdev_qp, cdev_qp_index;

	if (!buf_list->len) {
		current_num_cdev_qp = ipsec_ctx->current_num_cdev_qp;
		ipsec_ctx->current_cdev_qp[current_num_cdev_qp] =
				sa->cdev_qp_id->id;
		ipsec_ctx->current_num_cdev_qp++;
	}
	buf_list->buf[buf_list->len++] = cop;

	if (!is_last)
		return;

	for (i = 0; i < ipsec_ctx->current_num_cdev_qp; i++) {
		cdev_qp_index = ipsec_ctx->current_cdev_qp[i];
		buf_list = &ipsec_ctx->tbl[cdev_qp_index];
		ret = rte_cryptodev_enqueue_burst(sa->cdev_qp_id->cdev_id,
				sa->cdev_qp_id->queue_id,
				buf_list->buf, buf_list->len);
		if (ret < buf_list->len) {
			RTE_LOG_DP(DEBUG, IPSEC, "Cryptodev %u queue %u:"
					" enqueued %u crypto ops out of %u\n",
					 sa->cdev_qp_id->cdev_id,
					 sa->cdev_qp_id->queue_id,
					 ret, buf_list->len);
			for (i = ret; i < buf_list->len; i++)
				rte_pktmbuf_free(buf_list->buf[i]->sym->m_src);
		}
		buf_list->len = 0;
	}
	ipsec_ctx->current_num_cdev_qp = 0;
}

static inline void
ipsec_enqueue(ipsec_xform_fn xform_func, struct ipsec_ctx *ipsec_ctx,
		struct rte_mbuf *pkts[], struct ipsec_sa *sas[],
		uint16_t nb_pkts)
{
	int32_t ret = 0, i;
	struct ipsec_mbuf_metadata *priv;
	struct rte_crypto_sym_op *sym_cop;
	struct ipsec_sa *sa;
	uint8_t is_last = 0;

	for (i = 0; i < nb_pkts; i++) {
		if (unlikely(sas[i] == NULL)) {
			rte_pktmbuf_free(pkts[i]);
			continue;
		}

		rte_prefetch0(sas[i]);
		rte_prefetch0(pkts[i]);

		priv = get_priv(pkts[i]);
		sa = sas[i];
		priv->sa = sa;

		switch (sa->type) {
		case RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL:
			priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
			priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

			rte_prefetch0(&priv->sym_cop);

			if (unlikely(sa->sec_session == NULL)) {
				pthread_mutex_lock(&sa_lock);
				/* Recheck in case sec session is allocated
				 * by another core
				 */
				if ((sa->sec_session == NULL) &&
				    create_session(ipsec_ctx, sa)) {
					rte_pktmbuf_free(pkts[i]);
					pthread_mutex_unlock(&sa_lock);
					continue;
				}
				pthread_mutex_unlock(&sa_lock);
			}

			sym_cop = get_sym_cop(&priv->cop);
			sym_cop->m_src = pkts[i];

			rte_security_attach_session(&priv->cop,
					sa->sec_session);
			break;
		case RTE_SECURITY_ACTION_TYPE_NONE:

			priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
			priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

			rte_prefetch0(&priv->sym_cop);

			if (unlikely(sa->crypto_session == NULL)) {
				pthread_mutex_lock(&sa_lock);
				/* Recheck in case crypto session is allocated
				 * by another core
				 */
				if ((sa->crypto_session == NULL) &&
					create_session(ipsec_ctx, sa)) {
					rte_pktmbuf_free(pkts[i]);
					pthread_mutex_unlock(&sa_lock);
					continue;
				}
				pthread_mutex_unlock(&sa_lock);
			}

			rte_crypto_op_attach_sym_session(&priv->cop,
					sa->crypto_session);

			ret = xform_func(pkts[i], sa, &priv->cop);
			if (unlikely(ret)) {
				rte_pktmbuf_free(pkts[i]);
				continue;
			}
			break;
		default:
			RTE_LOG(ERR, IPSEC, "Unsupported sa type: %d\n",
				sa->type);
		}

		if (i == nb_pkts - 1)
			is_last = 1;

		enqueue_cop(sa, ipsec_ctx, &priv->cop, is_last);
	}
}

void
ipsec_inbound(struct ipsec_ctx *ctx, struct rte_mbuf *pkts[],
		uint16_t nb_pkts)
{
	struct ipsec_sa *sas[nb_pkts];

	inbound_sa_lookup(ctx->sa_ctx, pkts, sas, nb_pkts);

	ipsec_enqueue(esp_inbound, ctx, pkts, sas, nb_pkts);
}

void
ipsec_outbound(struct ipsec_ctx *ctx, struct rte_mbuf *pkts[],
		uint32_t sa_idx[], uint16_t nb_pkts)
{
	struct ipsec_sa *sas[nb_pkts];

	outbound_sa_lookup(ctx->sa_ctx, sa_idx, sas, nb_pkts);

	ipsec_enqueue(esp_outbound, ctx, pkts, sas, nb_pkts);
}
