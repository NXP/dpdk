/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSINIC_COMMON_H_
#define _LSINIC_COMMON_H_

#define NXP_PCI_VENDOR_ID (0x1957)
#define NXP_PCI_DEV_ID_LX2160A (0x8d80)
#define NXP_PCI_DEV_ID_LS2088A (0x8240)
#define NXP_PCI_DEV_ID_NULL (0)
#define NXP_PCI_CLASS_ID (0x0200)

#define LSINIC_MERGE_DEFAULT_THRESHOLD		(600) /* bytes */

#define LSINIC_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define LSINIC_ETH_OVERHEAD_SIZE \
	RTE_TM_ETH_FRAMING_OVERHEAD_FCS

#define LSINIC_QDMA_TEST_PKT_MAX_LEN (4 * 1024)

static inline __attribute__((always_inline))
void mem_cp128b_atomic(uint8_t *dst, const uint8_t *src)
{
	__uint128_t *dst128 = (__uint128_t *)dst;
	const __uint128_t *src128 = (const __uint128_t *)src;
	*dst128 = *src128;
}

#undef LSXINIC_ASSERT_PKT_SIZE

#endif /*  _LSINIC_VDEV_H_ */
