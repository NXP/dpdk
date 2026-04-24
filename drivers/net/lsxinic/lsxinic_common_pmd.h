/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2026 NXP
 */

#ifndef _LSINIC_COMMON_PMD_H_
#define _LSINIC_COMMON_PMD_H_

#include <rte_io.h>
#include "rte_tm.h"
#include <rte_pci.h>
#include <ethdev_driver.h>

#include "lsxinic_common_logs.h"

#define LSINIC_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define LSINIC_ETH_OVERHEAD_SIZE RTE_TM_ETH_FRAMING_OVERHEAD_FCS

static inline int
is_valid_ether_addr(uint8_t *addr)
{
	const char zaddr[6] = { 0,  };

	return !(addr[0] & 1) && memcmp(addr, zaddr, 6);
}

static inline int
lsxinic_common_link_update(struct rte_eth_dev *dev, int up)
{
	if (up) {
		dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
		dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_25G;
	} else {
		dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
		dev->data->dev_link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
		dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_NONE;
	}

	return 0;
}

#define lsxinic_common_get_ipackets(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_rx_queues; i++) { \
		q = _dev->data->rx_queues[i]; \
		total += q->packets; \
	} \
	total; \
})

#define lsxinic_common_get_ibytes(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_rx_queues; i++) { \
		q = _dev->data->rx_queues[i]; \
		total += q->bytes; \
	} \
	total; \
})

#define lsxinic_common_get_epackets(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_tx_queues; i++) { \
		q = _dev->data->tx_queues[i]; \
		total += q->packets; \
	} \
	total; \
})

#define lsxinic_common_get_ebytes(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_tx_queues; i++) { \
		q = _dev->data->tx_queues[i]; \
		total += q->bytes; \
	} \
	total; \
})

#define lsxinic_common_get_ierrs(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_rx_queues; i++) { \
		q = _dev->data->rx_queues[i]; \
		total += q->errors; \
	} \
	total; \
})

#define lsxinic_common_get_eerrs(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_tx_queues; i++) { \
		q = _dev->data->tx_queues[i]; \
		total += q->errors; \
	} \
	total; \
})

#define lsxinic_common_get_ibd_errs(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_rx_queues; i++) { \
		q = _dev->data->rx_queues[i]; \
		total += q->align_err; \
	} \
	total; \
})

#define lsxinic_common_get_efulls(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_tx_queues; i++) { \
		q = _dev->data->tx_queues[i]; \
		total += q->ring_full; \
	} \
	total; \
})

#define lsxinic_common_get_edrops(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint32_t i; \
	qtype q; \
	uint64_t total = 0; \
	\
	for (i = 0; i < _dev->data->nb_tx_queues; i++) { \
		q = _dev->data->tx_queues[i]; \
		total += q->drop_packet_num; \
	} \
	total; \
})

#define lsxinic_common_q_reset(dev, qtype) \
({ \
	struct rte_eth_dev *_dev = (dev); \
	uint16_t i, nb, loop = 0; \
	void **qs; \
	qtype q; \
	\
	while (1) { \
		if (loop > 1) \
			break; \
		if (loop == 1) { \
			nb = _dev->data->nb_tx_queues; \
			qs = _dev->data->tx_queues; \
		} else { \
			nb = _dev->data->nb_rx_queues; \
			qs = _dev->data->rx_queues; \
		} \
		loop++; \
		for (i = 0; i < nb; i++) { \
			q = qs[i]; \
			q->packets = 0; \
			q->bytes = 0; \
			q->bytes_fcs = 0; \
			q->bytes_overhead = 0; \
			q->bytes_overhead_old = 0; \
			q->errors = 0; \
			q->drop_packet_num = 0; \
			q->ring_full = 0; \
			q->align_err = 0; \
		} \
	} \
})

typedef uint64_t (*lsxinic_common_xstats_count)(struct rte_eth_dev *dev);

struct lsxinic_common_xstats_desc {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint16_t param; /* param to get statistics */
	lsxinic_common_xstats_count cb;
};

enum lsxinic_common_xstats_type {
	LSXINIC_COMMON_XSTATS_INGRESS_PACKETS,
	LSXINIC_COMMON_XSTATS_INGRESS_BYTES,
	LSXINIC_COMMON_XSTATS_EGRESS_PACKETS,
	LSXINIC_COMMON_XSTATS_EGRESS_BYTES,
	LSXINIC_COMMON_XSTATS_INGRESS_ERRORS,
	LSXINIC_COMMON_XSTATS_EGRESS_ERRORS,
	LSXINIC_COMMON_XSTATS_INGRESS_BD_ERRS,
	LSXINIC_COMMON_XSTATS_EGRESS_FULLS,
	LSXINIC_COMMON_XSTATS_EGRESS_DROPS
};

static struct lsxinic_common_xstats_desc s_lsxinic_xstats[] = {
	{"ingress_packets", LSXINIC_COMMON_XSTATS_INGRESS_PACKETS},
	{"ingress_bytes", LSXINIC_COMMON_XSTATS_INGRESS_BYTES},
	{"egress_packets", LSXINIC_COMMON_XSTATS_EGRESS_PACKETS},
	{"egress_bytes", LSXINIC_COMMON_XSTATS_EGRESS_BYTES},
	{"ingress_errs", LSXINIC_COMMON_XSTATS_INGRESS_ERRORS},
	{"egress_errs", LSXINIC_COMMON_XSTATS_EGRESS_ERRORS},
	{"ingress_bd_errs", LSXINIC_COMMON_XSTATS_INGRESS_BD_ERRS},
	{"egress_fulls", LSXINIC_COMMON_XSTATS_EGRESS_FULLS},
	{"egress_drops", LSXINIC_COMMON_XSTATS_EGRESS_DROPS}
};

/** Callbacks to be added must be in order of enum lsxinic_common_xstats_type*/
static inline void
lsxinic_common_xstats_add_cb(const lsxinic_common_xstats_count *cbs)
{
	uint64_t i;
	struct lsxinic_common_xstats_desc *desc;

	for (i = 0; i < RTE_DIM(s_lsxinic_xstats); i++) {
		desc = &s_lsxinic_xstats[i];
		desc->cb = cbs[i];
	}
}

static inline int
lsxinic_common_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n)
{
	const struct lsxinic_common_xstats_desc *desc;
	uint16_t i;

	if (n > RTE_DIM(s_lsxinic_xstats)) {
		LSXINIC_PMD_ERR("%s: Expected number(%d) > max number(%ld)",
			__func__, n, RTE_DIM(s_lsxinic_xstats));
		return -EINVAL;
	}

	if (!xstats)
		return 0;

	for (i = 0; i < n; i++) {
		desc = &s_lsxinic_xstats[i];
		xstats[i].id = i;
		xstats[i].value = desc->cb(dev);
	}

	return i;
}

static inline int
lsxinic_common_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, uint32_t limit)
{
	uint16_t i, stat_cnt = RTE_DIM(s_lsxinic_xstats);

	RTE_SET_USED(dev);

	if (!limit)
		return stat_cnt;

	if (limit < stat_cnt)
		stat_cnt = limit;

	if (!xstats_names)
		return stat_cnt;

	for (i = 0; i < stat_cnt; i++) {
		rte_strscpy(xstats_names[i].name, s_lsxinic_xstats[i].name,
			RTE_ETH_XSTATS_NAME_SIZE);
	}

	return stat_cnt;
}

static inline int
lsinic_common_xstats_get_by_id(struct rte_eth_dev *dev, const uint64_t *ids,
	uint64_t *values, uint32_t n)
{
	uint16_t i, id, stat_cnt = RTE_DIM(s_lsxinic_xstats);
	const struct lsxinic_common_xstats_desc *desc;

	for (i = 0; i < n; i++) {
		if (ids && ids[i] >= stat_cnt) {
			LSXINIC_PMD_ERR("xstats id value isn't valid");
			return -EINVAL;
		}
		id = ids ? ids[i] : i;
		desc = &s_lsxinic_xstats[id];
		values[i] = desc->cb(dev);
	}

	return n;
}

static inline int
lsinic_common_xstats_get_names_by_id(struct rte_eth_dev *dev,
	const uint64_t *ids, struct rte_eth_xstat_name *xstats_names,
	uint32_t limit)
{
	uint16_t i, stat_cnt = RTE_DIM(s_lsxinic_xstats);

	if (!ids)
		return lsxinic_common_xstats_get_names(dev, xstats_names, limit);

	for (i = 0; i < limit; i++) {
		if (ids[i] >= stat_cnt) {
			LSXINIC_PMD_ERR("xstats id[%d] value(%ld) >= max count(%d)",
				i, ids[i], stat_cnt);
			return -EINVAL;
		}
		rte_strscpy(xstats_names[i].name, s_lsxinic_xstats[ids[i]].name,
			RTE_ETH_XSTATS_NAME_SIZE);
	}
	return limit;
}

#endif /*  _LSINIC_COMMON_PMD_H_ */
