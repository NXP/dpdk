/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <fcntl.h>

#include <signal.h>
#include <rte_common.h>
#include <cryptodev_pmd.h>
#include <bus_vdev_driver.h>
#include <rte_malloc.h>
#include <common/dpaax/compat.h>

#include "v2x_fce_pvt.h"
#include "v2x_fce_uio.h"
#include "v2x_fce_api.h"

#define FCE_CRYPTO_PMD_NAME	v2x_fce
#define FCE_CRYPTO_DISPATCHER_CORE "dispatcher_core_id"
#define PLAT_DIR		"/sys/firmware/devicetree/base/compatible"

static uint8_t cryptodev_driver_id;
volatile struct fce_crypto_qp *fce_qp;

void *dispatcher(__rte_unused void *arg);

/* contains fixed information */
struct v2x_fce_info {
	const char *plat_name;
	int num_device;
};

struct v2x_fce_info fce_info[] = {
	{ .plat_name = "imx943-evk", .num_device = 1 },
	{},
};

static void
fce_complete_buf(uint8_t *buf, uint32_t len)
{
	uint32_t i;

	for (i = 0; i <= len; i += RTE_CACHE_LINE_SIZE)
		dccivac(buf + i);
}

static void
fce_complete_op(struct rte_crypto_op *op)
{
	struct fce_crypto_session *sess;
	struct rte_mbuf *mbuf;

	sess = CRYPTODEV_GET_SYM_SESS_PRIV(op->sym->session);

	if (is_auth_cipher(sess)) {
		if (op->sym->m_dst)
			mbuf = op->sym->m_dst;
		else
			mbuf = op->sym->m_src;

		fce_complete_buf(rte_pktmbuf_mtod(mbuf, void *),
				 rte_pktmbuf_pkt_len(mbuf));
		fce_complete_buf(op->sym->auth.digest.data,
				 sess->auth.digest_len);
	} else if (is_cipher_only(sess)) {
		if (op->sym->m_dst)
			mbuf = op->sym->m_dst;
		else
			mbuf = op->sym->m_src;

		fce_complete_buf(rte_pktmbuf_mtod(mbuf, void *),
				 rte_pktmbuf_pkt_len(mbuf));
	} else if (is_auth_only(sess)) {
		fce_complete_buf(op->sym->auth.digest.data,
				 sess->auth.digest_len);
	} else if (is_aead(sess)) {
		if (op->sym->m_dst)
			mbuf = op->sym->m_dst;
		else
			mbuf = op->sym->m_src;

		fce_complete_buf(rte_pktmbuf_mtod(mbuf, void *),
				 rte_pktmbuf_pkt_len(mbuf));

	}
}

static uint16_t
fce_dequeue_burst(void *queue_pair,
		  struct rte_crypto_op **ops,
		  uint16_t nb_ops)
{
	struct fce_crypto_qp *qp = queue_pair;
	uint32_t num_dequeue = 0;
	uint16_t i = 0;

	if (!rte_ring_count(qp->out_ring))
		return 0;

	num_dequeue = rte_ring_dequeue_burst(qp->out_ring, (void **)ops,
					     nb_ops, NULL);
	qp->stats.dequeued_count += num_dequeue;

	for (i = 0; i < num_dequeue; i++)
		fce_complete_op(ops[i]);

	return num_dequeue;
}

static void
fce_set_status(struct rte_crypto_op **ops,
	       int *enq_id, uint16_t nb_ops,
	       int req_id, int status)
{
	int i;

	for (i = 0; i < nb_ops; i++) {
		if (enq_id[i] == req_id) {
			if (status == REQ_VERIFY_FAIL)
				ops[i]->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
			else
				ops[i]->status = RTE_CRYPTO_OP_STATUS_ERROR;

			break;
		}
	}
}

static void
fce_process_ops(struct rte_crypto_op **ops,
		uint16_t nb_ops,
		int *enq_id)
{
	struct fce_crypto_session *sess;
	uint32_t req_id;
	int status;

	sess = CRYPTODEV_GET_SYM_SESS_PRIV(ops[0]->sym->session);

	if (!fce_read_clear_gsr(sess->fce_mu_base))
		return;

	/* Error signal is set, clear the FCE qeuue by reading error job */
	do {
		req_id = sess->req_id;
		status = fce_get_request_status(sess->fce_mu_base, &req_id);
		fce_set_status(ops, enq_id, nb_ops, req_id, status);

	} while (req_id < sess->req_id);
}

static int
fce_build_op(struct rte_crypto_op *op,
	     uint8_t buf_off,
	     uint8_t flag)
{
	struct fce_crypto_session *sess;
	int ret = -1;

	switch (op->sess_type) {
	case RTE_CRYPTO_OP_WITH_SESSION:
		sess = CRYPTODEV_GET_SYM_SESS_PRIV(op->sym->session);
		break;
	case RTE_CRYPTO_OP_SECURITY_SESSION:
	default:
		FCE_ERR("sessionless crypto op not supported");
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return ret;
	}

	if (rte_pktmbuf_is_contiguous(op->sym->m_src)) {
		if (is_auth_cipher(sess) || is_cipher_only(sess))
			ret = fce_cipher_build(op, buf_off, flag);
		else if (is_auth_only(sess))
			ret = fce_auth_build(op, buf_off, flag);
		else if (is_aead(sess))
			ret = fce_aead_build(op, buf_off);
	}

	if (ret)
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;

	return ret;
}

static int
fce_push_ops(struct rte_crypto_op **ops,
	     uint16_t nb_ops,
	     int *enq_id,
	     uint8_t flag)
{
	struct fce_crypto_session *sess;
	uint8_t slot = 0, jobs = 0, buf_off = 64;
	int i, ret, req_id;

	/* Push Request: MU Slot */
	for (i = 0; i < nb_ops; i++) {
		if (flag && (i + 1 == nb_ops))
			ret = fce_build_op(ops[i], buf_off * i, FCE_SIG_POP_REQ);
		else
			ret = fce_build_op(ops[i], buf_off * i, FCE_POP_REQ);

		if (ret < 0) {
			enq_id[i] = -1;
			continue;
		}

		slot = slot | (1 << i);
		jobs++;
	}

	if (slot) {
		sess = CRYPTODEV_GET_SYM_SESS_PRIV(ops[0]->sym->session);
		req_id = fce_push(sess->fce_mu_base, slot);
		if (req_id < 0) {
			for (i = 0; i < nb_ops; i++) {
				enq_id[i] = -1;
				ops[i]->status = RTE_CRYPTO_OP_STATUS_ERROR;
			}

			return 0;
		}

		/* save the last successful pushed req id */
		sess->req_id = req_id;

		/* save the request id for each op and set the status */
		for (i = nb_ops - 1; i >= 0; i--) {
			if (slot & (1 << i)) {
				enq_id[i] = req_id;
				req_id = req_id - FCE_REQ_ID_DIFF;
				ops[i]->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
			}
		}
	}

	return jobs;
}

static uint16_t
fce_enqueue_burst(void *queue_pair,
		  struct rte_crypto_op **ops,
		  uint16_t nb_ops)
{
	uint32_t num_enqueue = 0;

	if (nb_ops == 0)
		return 0;

	if (fce_qp != queue_pair) {
		FCE_ERR("invalid queue pair");
		return 0;
	}

	num_enqueue = rte_ring_enqueue_burst(fce_qp->in_ring, (void *)ops, nb_ops, NULL);
	fce_qp->stats.enqueued_count += num_enqueue;

	return num_enqueue;
}

#ifdef __GNUC__
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif
void *
dispatcher(void *arg)
{
	struct rte_crypto_op *ops[FCE_MAX_OPS];
	int enq_id[FCE_MAX_OPS];
	uint16_t nb_ops, ops_cnt, i;
	uint8_t flag;
	int ops_pushed;
	dispatcher_args_t *args = (dispatcher_args_t *)arg;

	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(args->core_id, &cpuset);

	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

	while (1) {
		while (!fce_qp || !(rte_ring_count(fce_qp->in_ring)))
			;

		nb_ops = rte_ring_dequeue_burst(fce_qp->in_ring, (void **)ops,
						FCE_MAX_OPS, NULL);
		i = 0;
		while (i < nb_ops) {
			if ((nb_ops - i) > 4) {
				ops_cnt = 4;
				flag = 0;
			} else {
				ops_cnt = nb_ops - i;
				flag = 1;
			}
			ops_pushed = fce_push_ops(&ops[i], ops_cnt,
						  &enq_id[i], flag);
			fce_qp->stats.enqueue_err_count += ops_cnt - ops_pushed;
			i += ops_cnt;
		}

		fce_process_ops(ops, i, enq_id);
		rte_ring_enqueue_burst(fce_qp->out_ring, (void *)ops, i, NULL);
	}

	return NULL;
}
#ifdef __GNUC__
#pragma GCC pop_options
#endif

static int
check_compatible_plat(void)
{
	char plat_str[ARR_LEN] = {0};
	ssize_t bytes;
	int i, fd;

	fd = open(PLAT_DIR, O_RDONLY);
	if (fd < 0)
		return -errno;

	bytes = read(fd, plat_str, sizeof(plat_str) - 1);
	if (bytes <= 0) {
		close(fd);
		return -errno;
	}
	plat_str[bytes] = '\0';

	for (i = 0; fce_info[i].plat_name != NULL; i++) {
		if (strstr(plat_str, fce_info[i].plat_name) != NULL) {
			fce_info[i].num_device--;
			close(fd);
			return fce_info[i].num_device;
		}
	}

	close(fd);

	return -1;
}

static int
fce_cryptodev_create(const char *name,
		     struct rte_vdev_device *vdev,
		     struct rte_cryptodev_pmd_init_params *init_params,
		     int dispatcher_core)
{
	struct rte_cryptodev *dev;
	struct uio_fce_mu *fce_mu;
	struct fce_crypto_private *internals;

	dev = rte_cryptodev_pmd_create(name, &vdev->device, init_params);
	if (dev == NULL) {
		FCE_ERR("failed to create cryptodev vdev");
		return -ENODEV;
	}

	dev->driver_id = cryptodev_driver_id;
	dev->dev_ops = fce_get_cryptodev_ops();

	/* register rx/tx burst functions for data path */
	dev->dequeue_burst = fce_dequeue_burst;
	dev->enqueue_burst = fce_enqueue_burst;
	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_HW_ACCELERATED;

	/* map fce mu */
	fce_mu = fce_mu_open();
	if (fce_mu == NULL) {
		rte_cryptodev_pmd_release_device(dev);
		return -EFAULT;
	}

	internals = dev->data->dev_private;
	internals->fce_mu_fd = fce_mu->fd;
	internals->fce_mu_base = fce_mu->base;
	internals->fce_mu_offset = fce_mu->offset;
	internals->num_cipher_keyslot = FCE_MAX_KEYSLOT;
	internals->num_auth_keyslot = FCE_MAX_KEYSLOT;
	internals->max_nb_queue_pairs = init_params->max_nb_queue_pairs;

	/* create dispatcher thread */
	internals->args = malloc(sizeof(dispatcher_args_t));
	internals->args->core_id = dispatcher_core;
	pthread_create(&internals->dispatcher_tid, NULL, dispatcher, (void *)internals->args);

	rte_cryptodev_pmd_probing_finish(dev);

	RTE_LOG(INFO, PMD, "%s cryptodev init\n", dev->data->name);

	return 0;
}

static int
fce_crypto_parse_args(const char *args)
{
	struct rte_kvargs *kvlist;
	const char *val;
	int core_id = 0;

	kvlist = rte_kvargs_parse(args, NULL);
	if (!kvlist)
		return -EINVAL;

	val = rte_kvargs_get(kvlist, FCE_CRYPTO_DISPATCHER_CORE);
	if (val)
		core_id = atoi(val);

	rte_kvargs_free(kvlist);

	return core_id;
}

static int
fce_cryptodev_probe(struct rte_vdev_device *vdev)
{
	if (check_compatible_plat() < 0) {
		FCE_ERR("platform or device not supported");
		return -ENOTSUP;
	}

	struct rte_cryptodev_pmd_init_params init_params = {
		"",
		sizeof(struct fce_crypto_private),
		rte_socket_id(),
		1
	};
	const char *name;
	const char *input_args;
	int core_id;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	input_args = rte_vdev_device_args(vdev);

	rte_cryptodev_pmd_parse_input_args(&init_params, input_args);

	/* parse dispatcher core id */
	core_id = fce_crypto_parse_args(input_args);
	if (core_id < 0)
		core_id = 0;

	return fce_cryptodev_create(name, vdev, &init_params, core_id);
}

static void
fce_cryptodev_destroy(struct rte_cryptodev *dev)
{
	struct fce_crypto_private *internals;

	internals = dev->data->dev_private;
	if (internals) {
		pthread_kill(internals->dispatcher_tid, SIGTERM);
		free(internals->args);
		fce_mu_close(internals->fce_mu_fd);
	}
}

static int
fce_cryptodev_remove(struct rte_vdev_device *vdev)
{
	struct rte_cryptodev *cryptodev;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	cryptodev = rte_cryptodev_pmd_get_named_dev(name);
	if (cryptodev == NULL)
		return -ENODEV;

	fce_cryptodev_destroy(cryptodev);

	return rte_cryptodev_pmd_destroy(cryptodev);
}

static struct rte_vdev_driver fce_crypto_pmd = {
	.probe = fce_cryptodev_probe,
	.remove = fce_cryptodev_remove
};

static struct cryptodev_driver fce_cryptodev_drv;

RTE_PMD_REGISTER_VDEV(FCE_CRYPTO_PMD_NAME, fce_crypto_pmd);
RTE_PMD_REGISTER_PARAM_STRING(FCE_CRYPTO_PMD_NAME,
			      "dispatcher_core_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(fce_cryptodev_drv, fce_crypto_pmd.driver,
			       cryptodev_driver_id);
RTE_LOG_REGISTER_DEFAULT(fce_logtype, ERR);
