/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef _RTE_DPAA2_QDMA_H_
#define _RTE_DPAA2_QDMA_H_

/** States if the source addresses is physical. */
#define RTE_QDMA_JOB_SRC_PHY		(1ULL << 30)

/** States if the destination addresses is physical. */
#define RTE_QDMA_JOB_DEST_PHY		(1ULL << 31)

struct rte_dpaa2_qdma_rbp {
	uint32_t use_ultrashort:1;
	uint32_t enable:1;
	/**
	 * dportid:
	 * 0000 PCI-Express 1
	 * 0001 PCI-Express 2
	 * 0010 PCI-Express 3
	 * 0011 PCI-Express 4
	 * 0100 PCI-Express 5
	 * 0101 PCI-Express 6
	 */
	uint32_t dportid:4;
	uint32_t dpfid:2;
	uint32_t dvfid:6;
	/*using route by port for destination */
	uint32_t drbp:1;
	/**
	 * sportid:
	 * 0000 PCI-Express 1
	 * 0001 PCI-Express 2
	 * 0010 PCI-Express 3
	 * 0011 PCI-Express 4
	 * 0100 PCI-Express 5
	 * 0101 PCI-Express 6
	 */
	uint32_t sportid:4;
	uint32_t spfid:2;
	uint32_t svfid:6;
	/* using route by port for source */
	uint32_t srbp:1;
	uint32_t rsv:4;
};

/* Enable FD in long format. To be called before 'rte_dma_vchan_setup()' API. */
void rte_dpaa2_qdma_vchan_fd_lf_enable(struct rte_dma_dev *dev,
		uint16_t vchan);

/* Enable internal SG processing. To be called before 'rte_dma_vchan_setup()' API. */
void rte_dpaa2_qdma_vchan_internal_sg_enable(struct rte_dma_dev *dev,
		uint16_t vchan);

/* Enable RBP */
void rte_dpaa2_qdma_vchan_rbp_enable(struct rte_dma_dev *dev,
		uint16_t vchan, struct rte_dpaa2_qdma_rbp *rbp_config);

#endif /* _RTE_DPAA2_QDMA_H_ */
