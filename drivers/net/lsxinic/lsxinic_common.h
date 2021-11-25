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

#ifndef RTE_VERIFY
#define RTE_VERIFY(exp) do {} while (0)
#endif

static inline __attribute__((always_inline))
void mem_cp128b_atomic(uint8_t *dst, const uint8_t *src)
{
	__uint128_t *dst128 = (__uint128_t *)dst;
	const __uint128_t *src128 = (const __uint128_t *)src;
	*dst128 = *src128;
}

static inline int is_align_16(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x1)
		return 0;

	return 1;
}

static inline int is_align_32(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x3)
		return 0;

	return 1;
}

static inline int is_align_64(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x7)
		return 0;

	return 1;
}

static inline int is_align_128(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0xf)
		return 0;

	return 1;
}

static inline void
lsinic_pcie_memset_align(uint8_t *dst,
	uint8_t data, uint16_t size)
{
	uint64_t src64[2];
	__uint128_t *src128 = (__uint128_t *)src64;
	uint32_t *src32 = (uint32_t *)src64;
	uint16_t *src16 = (uint16_t *)src64;

	memset(src64, data, sizeof(src64));

	if (!is_align_16(dst) && size > 0) {
		*dst = data;
		dst++;
		size--;
	}

	if (!is_align_32(dst) &&
		size >= sizeof(uint16_t)) {
		*((uint16_t *)dst) = src16[0];
		dst += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (!is_align_64(dst) &&
		size >= sizeof(uint32_t)) {
		*((uint32_t *)dst) = src32[0];
		dst += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	if (!is_align_128(dst) &&
		size >= sizeof(uint64_t)) {
		*((uint64_t *)dst) = src64[0];
		dst += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(__uint128_t)) {
		RTE_VERIFY(is_align_128(dst));
		*((__uint128_t *)dst) = *src128;
		dst += sizeof(__uint128_t);
		size -= sizeof(__uint128_t);
	}

	while (size >= sizeof(uint64_t)) {
		RTE_VERIFY(is_align_64(dst));
		*((uint64_t *)dst) = src64[0];
		dst += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) {
		RTE_VERIFY(is_align_32(dst));
		*((uint32_t *)dst) = src32[0];
		dst += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) {
		RTE_VERIFY(is_align_16(dst));
		*((uint16_t *)dst) = src16[0];
		dst += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	while (size > 0) {
		*dst = data;
		dst++;
		size--;
	}
}

static inline void
lsinic_pcie_memcp_align(uint8_t *dst,
	uint8_t *src, uint32_t size)
{
	if (!is_align_16(dst) && size > 0) {
		*dst = *src;
		dst++;
		src++;
		size--;
	}

	if (!is_align_32(dst) &&
		size >= sizeof(uint16_t)) {
		*((uint16_t *)dst) = *((uint16_t *)src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (!is_align_64(dst) &&
		size >= sizeof(uint32_t)) {
		*((uint32_t *)dst) = *((uint32_t *)src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	if (!is_align_128(dst) &&
		size >= sizeof(uint64_t)) {
		*((uint64_t *)dst) = *((uint64_t *)src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(__uint128_t)) {
		RTE_VERIFY(is_align_128(dst));
		*((__uint128_t *)dst) = *((__uint128_t *)src);
		dst += sizeof(__uint128_t);
		src += sizeof(__uint128_t);
		size -= sizeof(__uint128_t);
	}

	while (size >= sizeof(uint64_t)) {
		RTE_VERIFY(is_align_64(dst));
		*((uint64_t *)dst) = *((uint64_t *)src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) {
		RTE_VERIFY(is_align_32(dst));
		*((uint32_t *)dst) = *((uint32_t *)src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) {
		RTE_VERIFY(is_align_16(dst));
		*((uint16_t *)dst) = *((uint16_t *)src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	while (size > 0) {
		*dst = *src;
		dst++;
		src++;
		size--;
	}
}

#undef LSXINIC_ASSERT_PKT_SIZE

#endif /*  _LSINIC_VDEV_H_ */
