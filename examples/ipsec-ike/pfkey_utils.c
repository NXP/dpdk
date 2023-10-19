/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2011-2013 Freescale Semiconductor, Inc.
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ipsec.h>
#include <linux/pfkeyv2.h>

#include <stdbool.h>
#include "xfrm_km.h"

#define PFKEY_UNUNIT64(a) ((a) << 3)
#define PFKEY_UNIT64(a) ((a) >> 3)

#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PFKEY_EXTLEN(msg) \
	PFKEY_UNUNIT64(((struct sadb_ext *)(msg))->sadb_ext_len)
#define PFKEY_ADDR_PREFIX(ext) \
	(((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
	(((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
	((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))

static uint32_t xfrm_msg_seq_num;

void kdebug_sadb(struct sadb_msg *base)
{
	struct sadb_ext *ext;
	int tlen, extlen;

	if (!base) {
		RTE_LOG(ERR, IPSEC_IKE, "%s: NULL pointer was passed\n",
			__func__);
		return;
	}

	RTE_LOG(INFO, IPSEC_IKE,
		"%s: version=%u type=%u errno=%u satype=%u\n",
		__func__, base->sadb_msg_version,
		base->sadb_msg_type, base->sadb_msg_errno,
		base->sadb_msg_satype);
	RTE_LOG(INFO, IPSEC_IKE,
		"len=%u reserved=%u seq=%u pid=%u\n",
		base->sadb_msg_len, base->sadb_msg_reserved,
		base->sadb_msg_seq, base->sadb_msg_pid);

	tlen = PFKEY_UNUNIT64(base->sadb_msg_len) -
		sizeof(struct sadb_msg);
	ext = (void *)((caddr_t)(void *)base +
		sizeof(struct sadb_msg));

	while (tlen > 0) {
		RTE_LOG(INFO, IPSEC_IKE,
			"sadb_ext: len=%u type=%u\n",
			ext->sadb_ext_len, ext->sadb_ext_type);

		if (!ext->sadb_ext_len) {
			RTE_LOG(ERR, IPSEC_IKE,
				"%s: invalid ext_len=0 was passed.\n",
				__func__);
			return;
		}
		if (ext->sadb_ext_len > tlen) {
			RTE_LOG(ERR, IPSEC_IKE,
				"%s: ext_len exceeds end of buffer.\n",
				__func__);
			return;
		}
		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);
		tlen -= extlen;
		ext = (void *)((caddr_t)(void *)ext + extlen);
	}
}

int pfkey_open(void)
{
	return socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
}

void pfkey_close(int so)
{
	close(so);
}

int pfkey_send(int so, struct sadb_msg *msg, int len)
{
	len = send(so, (void *)msg, (socklen_t)len, 0);
	if (len < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"%s ret len(%d)\n", strerror(errno), len);
	}
	return len;
}

static inline u_int8_t sysdep_sa_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	}
	return sizeof(struct sockaddr_in);
}

static inline void sa_getaddr(const struct sockaddr *sa,
		xfrm_address_t *xaddr)
{
	switch (sa->sa_family) {
	case AF_INET:
		rte_memcpy(&xaddr->a4,
			&((const struct sockaddr_in *)sa)->sin_addr.s_addr,
			sizeof(uint32_t));
		return;
	case AF_INET6:
		rte_memcpy(&xaddr->a6,
			&((const struct sockaddr_in6 *)sa)->sin6_addr,
			sizeof(struct in6_addr));
		return;
	}
}

static caddr_t
pfkey_setsadbmsg(caddr_t buf, caddr_t lim, uint32_t type,
	uint32_t tlen, u_int satype, u_int32_t seq,
	pid_t pid)
{
	struct sadb_msg *p;
	uint32_t len;

	p = (void *)buf;
	len = sizeof(struct sadb_msg);

	if (buf + len > lim)
		return NULL;

	memset(p, 0, len);
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	p->sadb_msg_satype = satype;
	p->sadb_msg_len = PFKEY_UNIT64(tlen);
	p->sadb_msg_reserved = 0;
	p->sadb_msg_seq = seq;
	p->sadb_msg_pid = (u_int32_t)pid;

	return buf + len;
}

/* sending SADB_X_SPDGET */
static int pfkey_send_spdget(int so, uint32_t request_seq_num,
	uint32_t spid, uint32_t type)
{
	struct sadb_msg *newmsg;
	struct sadb_x_policy xpl;
	int len;
	caddr_t p;
	caddr_t ep;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg) + sizeof(xpl);
	newmsg = calloc(1, (size_t)len);
	if (!newmsg)
		return -ENOMEM;
	ep = ((caddr_t)(void *)newmsg) + len;

	p = pfkey_setsadbmsg((void *)newmsg, ep, type,
		(uint32_t)len, SADB_SATYPE_UNSPEC,
		request_seq_num, getpid());
	if (!p) {
		free(newmsg);
		return -ENOMEM;
	}

	if (p + sizeof(xpl) != ep) {
		free(newmsg);
		return -ENOMEM;
	}
	memset(&xpl, 0, sizeof(xpl));
	xpl.sadb_x_policy_len = PFKEY_UNIT64(sizeof(xpl));
	xpl.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl.sadb_x_policy_id = spid;
	memcpy(p, &xpl, sizeof(xpl));

	/* send message */
	len = pfkey_send(so, newmsg, len);
	free(newmsg);

	if (len < 0)
		return len;

	return len;
}

static int pfkey_send_sadget(int so, uint32_t request_seq_num,
	uint32_t spi, uint32_t type)
{
	struct sadb_msg *newmsg;
	struct sadb_sa sa;
	int len;
	caddr_t p;
	caddr_t ep;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg) + sizeof(sa);
	newmsg = calloc(1, (size_t)len);
	if (!newmsg)
		return -ENOMEM;
	ep = ((caddr_t)(void *)newmsg) + len;

	p = pfkey_setsadbmsg((void *)newmsg, ep, type,
		(uint32_t)len, SADB_SATYPE_UNSPEC,
		request_seq_num, getpid());
	if (!p) {
		free(newmsg);
		return -ENOMEM;
	}

	if (p + sizeof(sa) != ep) {
		free(newmsg);
		return -ENOMEM;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sadb_sa_len = PFKEY_UNIT64(sizeof(sa));
	sa.sadb_sa_exttype = SADB_EXT_SA;
	sa.sadb_sa_spi = rte_cpu_to_be_32(spi);
	memcpy(p, &sa, sizeof(sa));

	/* send message */
	len = pfkey_send(so, newmsg, len);
	free(newmsg);

	if (len < 0)
		return len;

	return len;
}

int pfkey_recv_sadbmsg(int so, u_int msg_type, u_int32_t seq_num,
	struct sadb_msg **newmsg)
{
	struct sadb_msg buf;
	struct sadb_msg *tmp = NULL;
	int len, reallen;

	do {
		/* Get next SADB message header: */
		while ((len = recv(so, (void *)&buf, sizeof(buf),
			MSG_PEEK)) < 0) {
			if (errno == EINTR)
				continue;
			return len;
		}

		if (len < (int)sizeof(buf)) {
			/* Corrupted message. Just read it and discard it. */
			recv(so, (void *)&buf, sizeof(buf), 0);
			return -EINVAL;
		}

		/* read real message */
		reallen = PFKEY_UNUNIT64(buf.sadb_msg_len);
		tmp = (struct sadb_msg *)realloc(*newmsg, reallen);
		if (!tmp)
			return -ENOMEM;
		*newmsg = tmp;

		while ((len = recv(so, (void *)tmp, (socklen_t)reallen,
					0)) < 0) {
			if (errno == EINTR)
				continue;
			return len;
		}

		/* Expecting to read a full message: */
		if (len != reallen)
			return -EINVAL;

		/* don't trust what the kernel says, validate! */
		if (PFKEY_UNUNIT64(tmp->sadb_msg_len) != len)
			return -EINVAL;
	} while ((tmp->sadb_msg_type != msg_type) ||
			(tmp->sadb_msg_seq != seq_num) ||
			(tmp->sadb_msg_pid != (u_int32_t)getpid()));

	return 0;
}

int
pfkey_align(struct sadb_msg *msg, caddr_t *mhp)
{
	struct sadb_ext *ext;
	int i;
	caddr_t p;
	caddr_t ep;

	/* validity check */
	if (!msg || !mhp)
		return -EINVAL;

	/* initialize */
	for (i = 0; i < SADB_EXT_MAX + 1; i++)
		mhp[i] = NULL;

	mhp[0] = (void *)msg;

	/* initialize */
	p = (void *) msg;
	ep = p + PFKEY_UNUNIT64(msg->sadb_msg_len);

	/* skip base header */
	p += sizeof(struct sadb_msg);

	while (p < ep) {
		ext = (void *)p;
		if (ep < p + sizeof(*ext) ||
			(uint64_t)PFKEY_EXTLEN(ext) < (uint64_t)sizeof(*ext) ||
			ep < p + PFKEY_EXTLEN(ext)) {
			/* invalid format */
			break;
		}

		/* duplicate check */
		/* XXX Are there duplication either KEY_AUTH or KEY_ENCRYPT ?*/
		if (mhp[ext->sadb_ext_type])
			return -EINVAL;

		mhp[ext->sadb_ext_type] = (void *)ext;

		/* sadb_ext_type is one of:
		 *switch (ext->sadb_ext_type) {
		 *case SADB_EXT_SA:
		 *case SADB_EXT_LIFETIME_CURRENT:
		 *case SADB_EXT_LIFETIME_HARD:
		 *case SADB_EXT_LIFETIME_SOFT:
		 *case SADB_EXT_ADDRESS_SRC:
		 *case SADB_EXT_ADDRESS_DST:
		 *case SADB_EXT_ADDRESS_PROXY:
		 *case SADB_EXT_KEY_AUTH:
		 *case SADB_EXT_KEY_ENCRYPT:
		 *case SADB_EXT_IDENTITY_SRC:
		 *case SADB_EXT_IDENTITY_DST:
		 *case SADB_EXT_SENSITIVITY:
		 *case SADB_EXT_PROPOSAL:
		 *case SADB_EXT_SUPPORTED_AUTH:
		 *case SADB_EXT_SUPPORTED_ENCRYPT:
		 *case SADB_EXT_SPIRANGE:
		 *case SADB_X_EXT_POLICY:
		 *case SADB_X_EXT_SA2:
		 *case SADB_X_EXT_NAT_T_TYPE:
		 *case SADB_X_EXT_NAT_T_SPORT:
		 *case SADB_X_EXT_NAT_T_DPORT:
		 *case SADB_X_EXT_NAT_T_OA:

		 *case SADB_X_EXT_TAG:

		 *case SADB_X_EXT_PACKET:

		 *case SADB_X_EXT_KMADDRESS:

		 *case SADB_X_EXT_SEC_CTX:
		 *	mhp[ext->sadb_ext_type] = (void *)ext;
		 *	break;
		 *default:
		 *	return -EINVAL;
		 *}
		 */
		p += PFKEY_EXTLEN(ext);
	}

	if (p != ep)
		return -EINVAL;

	return 0;
}

static int
ipsec_dump_ipsecrequest(struct sadb_x_ipsecrequest *xisr,
	int bound,
	xfrm_address_t *saddr, xfrm_address_t *daddr,
	int *sa_af)
{
	int ret;

	if (xisr->sadb_x_ipsecrequest_len > bound)
		return -EINVAL;

	switch (xisr->sadb_x_ipsecrequest_proto) {
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_COMP:
		break;
	default:
		return -EINVAL;
	}

	switch (xisr->sadb_x_ipsecrequest_mode) {
	case IPSEC_MODE_ANY:
	case IPSEC_MODE_TRANSPORT:
	case IPSEC_MODE_TUNNEL:
		break;
	default:
		return -EINVAL;
	}

	switch (xisr->sadb_x_ipsecrequest_level) {
	case IPSEC_LEVEL_DEFAULT:
	case IPSEC_LEVEL_USE:
	case IPSEC_LEVEL_REQUIRE:
	case IPSEC_LEVEL_UNIQUE:
		break;
	default:
		return -EINVAL;
	}

	if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
		struct sockaddr *sa1, *sa2;
		caddr_t p;
		const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
		char host1[NI_MAXHOST], host2[NI_MAXHOST];
		char serv1[NI_MAXSERV], serv2[NI_MAXHOST];

		p = (void *)(xisr + 1);
		sa1 = (void *)p;
		sa2 = (void *)(p + sysdep_sa_len(sa1));
		if (sizeof(*xisr) + sysdep_sa_len(sa1) + sysdep_sa_len(sa2) !=
		    xisr->sadb_x_ipsecrequest_len)
			return -EINVAL;

		ret = getnameinfo(sa1, (socklen_t)sysdep_sa_len(sa1),
			host1, sizeof(host1),
			serv1, sizeof(serv1), niflags);
		if (ret)
			return ret;

		ret = getnameinfo(sa2, (socklen_t)sysdep_sa_len(sa2),
			host2, sizeof(host2),
			serv2, sizeof(serv2), niflags);

		if (ret)
			return ret;
		sa_getaddr(sa1, saddr);
		sa_getaddr(sa2, daddr);
		*sa_af = sa1->sa_family;
	}

	return 0;
}

static int
ipsec_dump_policy(void *policy,
	xfrm_address_t *saddr, xfrm_address_t *daddr,
	int *sa_af)
{
	struct sadb_x_policy *xpl = policy;
	struct sadb_x_ipsecrequest *xisr;
	size_t off;
	int ret;

	/* count length of buffer for use */
	off = sizeof(*xpl);
	while (off < (size_t)PFKEY_EXTLEN(xpl)) {
		xisr = (void *)((caddr_t)(void *)xpl + off);
		off += xisr->sadb_x_ipsecrequest_len;
	}

	/* validity check */
	if (off != (size_t)PFKEY_EXTLEN(xpl))
		return -EINVAL;
	off = sizeof(*xpl);
	while (off < (size_t)PFKEY_EXTLEN(xpl)) {
		xisr = (void *)((caddr_t)(void *)xpl + off);

		ret = ipsec_dump_ipsecrequest(xisr,
		    PFKEY_EXTLEN(xpl) - off, saddr, daddr, sa_af);
		if (ret < 0)
			return ret;

		off += xisr->sadb_x_ipsecrequest_len;
	}
	return 0;
}

static int
pfkey_spdump(struct sadb_msg *m,
	xfrm_address_t *saddr, xfrm_address_t *daddr,
	int *sa_af)
{
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_x_policy *m_xpl;
	int ret;

	ret = pfkey_align(m, mhp);
	if (ret)
		return ret;

	m_xpl = (void *)mhp[SADB_X_EXT_POLICY];
	/* policy */
	if (!m_xpl)
		return -EINVAL;

	return ipsec_dump_policy(m_xpl, saddr, daddr, sa_af);
}

int
do_spdget(int spid, xfrm_address_t *saddr, xfrm_address_t *daddr,
	int *sa_af)
{
	int ret, so;
	struct sadb_msg *m = NULL;

	so = pfkey_open();
	if (so < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to open PF_KEY socket(%d)\n", so);

		return so;
	}
	ret = pfkey_send_spdget(so, xfrm_msg_seq_num, spid, SADB_X_SPDGET);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to send SADB_X_SPDGET(%d)\n", ret);
		return ret;
	}
	ret = pfkey_recv_sadbmsg(so, SADB_X_SPDGET, xfrm_msg_seq_num++, &m);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to receive from PF_KEY socket(%d)\n", ret);

		free(m);
		pfkey_close(so);
		return ret;
	}
	pfkey_close(so);
	ret = pfkey_spdump(m, saddr, daddr, sa_af);
	free(m);
	return ret;
}

int
do_spddel(int spid)
{
	int ret, so;
	struct sadb_msg *m = NULL;

	so = pfkey_open();
	if (so < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to open PF_KEY socket(%d)\n", so);

		return so;
	}
	ret = pfkey_send_spdget(so, xfrm_msg_seq_num, spid, SADB_X_SPDDELETE);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to send SADB_X_SPDDELETE(%d)\n", ret);
		return ret;
	}
	ret = pfkey_recv_sadbmsg(so, SADB_X_SPDDELETE, xfrm_msg_seq_num++, &m);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to receive from PF_KEY socket(%d)\n", ret);

		free(m);
		pfkey_close(so);
		return ret;
	}
	pfkey_close(so);
	free(m);
	return ret;
}

int
do_saddel(int spi)
{
	int ret, so;
	struct sadb_msg *m = NULL;

	so = pfkey_open();
	if (so < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to open PF_KEY socket(%d)\n", so);

		return so;
	}
	ret = pfkey_send_sadget(so, xfrm_msg_seq_num, spi, SADB_DELETE);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to send SADB_DELETE(%d)\n", ret);
		return ret;
	}
	ret = pfkey_recv_sadbmsg(so, SADB_DELETE, xfrm_msg_seq_num++, &m);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Failed to receive from PF_KEY socket(%d)\n", ret);

		free(m);
		pfkey_close(so);
		return ret;
	}
	pfkey_close(so);
	free(m);
	return ret;
}
