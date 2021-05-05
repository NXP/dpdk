/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2021 NXP
 *
 */
#ifndef __LA93XX_IPC_H__
#define __LA93XX_IPC_H__

#include <stdint.h>
#include "la93xx_ipc_ioctl.h"
#include "la93xx_bbdev_ipc.h"

typedef void *ipc_t;

/** No. of max IPC instance possible */
#define IPC_MAX_INSTANCE_COUNT	(1)

/** No. of max channel per instance */
#define IPC_MAX_CHANNEL_COUNT	(4)

/** Channel Depth */
#define IPC_MAX_DEPTH	(4)

/* IPC PI/CI index & flag manipulation helpers */
#define IPC_PI_CI_FLAG_MASK	0x80000000 /*  (1<<31) */
#define IPC_PI_CI_INDEX_MASK	0x7FFFFFFF /* ~(1<<31) */

#define IPC_SET_PI_FLAG(x)	(x |= IPC_PI_CI_FLAG_MASK)
#define IPC_RESET_PI_FLAG(x)	(x &= IPC_PI_CI_INDEX_MASK)
#define IPC_GET_PI_FLAG(x)	(x >> 31)
#define IPC_GET_PI_INDEX(x)	(x & IPC_PI_CI_INDEX_MASK)

#define IPC_SET_CI_FLAG(x)	(x |= IPC_PI_CI_FLAG_MASK)
#define IPC_RESET_CI_FLAG(x)	(x &= IPC_PI_CI_INDEX_MASK)
#define IPC_GET_CI_FLAG(x)	(x >> 31)
#define IPC_GET_CI_INDEX(x)	(x & IPC_PI_CI_INDEX_MASK)

/** Error codes */
#define IPC_SUCCESS		(0)	/** IPC operation success */
#define IPC_INPUT_INVALID	(-1)	/** Invalid input to API */
#define IPC_CH_INVALID		(-2)	/** Channel no is invalid */
#define IPC_INSTANCE_INVALID	(-3)	/** Instance no is invalid */
#define IPC_MEM_INVALID		(-4)	/** Insufficient memory */
#define IPC_CH_FULL		(-5)	/** Channel is full */
#define IPC_CH_EMPTY		(-6)	/** Channel is empty */
#define IPC_BL_EMPTY		(-7)	/** Free buffer list is empty */
#define IPC_BL_FULL		(-8)	/** Free buffer list is full */
#define IPC_HOST_BUF_ALLOC_FAIL	(-9)	/** DPDK malloc fail */
#define IPC_MD_SZ_MISS_MATCH	(-10) /** META DATA size in mhif miss matched */
#define IPC_MALLOC_FAIL		(-11) /** system malloc fail */
#define IPC_IOCTL_FAIL		(-12) /** IOCTL call failed */
#define IPC_MMAP_FAIL		(-14) /** MMAP fail */
#define IPC_OPEN_FAIL		(-15) /** OPEN fail */
#define IPC_EVENTFD_FAIL	(-16) /** eventfd initalization failed */
#define IPC_NOT_IMPLEMENTED	(-17)	/** IPC feature is not implemented yet */

#define IPC_HOST_SIGNATURE	(0x02020202) /* IPC host signature */
#define IPC_MODEM_SIGNATURE	(0x01010101) /* IPC modem signature */

/* This shared memory would be on the host side which have copy of some
 * of the parameters which are also part of Shared BD ring. Read access
 * of these parameters from the host side would not be over PCI.
 */
typedef struct host_ipc_params {
	volatile uint32_t pi;
	volatile uint32_t ci;
	volatile uint32_t bd_m_modem_ptr[IPC_MAX_DEPTH];
} __attribute__((packed)) host_ipc_params_t;

typedef struct {
	uint64_t host_phys;
	uint32_t modem_phys;
	void    *host_vaddr;
	uint32_t size;
} mem_range_t;

/** buffer ring common metadata */
typedef struct ipc_bd_ring_md {
	volatile uint32_t pi;		/**< Producer index and flag (MSB)
					  * which flip for each Ring wrapping */
	volatile uint32_t ci;		/**< Consumer index and flag (MSB)
					  * which flip for each Ring wrapping */
	uint32_t ring_size;	/**< depth (Used to roll-over pi/ci) */
	uint32_t msg_size;	/**< Size of the each buffer */
} __attribute__((packed)) ipc_br_md_t;

/** IPC buffer descriptor */
typedef struct ipc_buffer_desc {
	union {
		uint64_t host_virt;	/**< msg's host virtual address */
		struct {
			uint32_t host_virt_l;
			uint32_t host_virt_h;
		};
	};
	uint32_t modem_ptr;	/**< msg's modem physical address */
	uint32_t len;		/**< msg len */
} __attribute__((packed)) ipc_bd_t;

typedef struct ipc_channel {
	uint32_t ch_id;		/**< Channel id */
	ipc_br_md_t md;			/**< Metadata for BD ring */
	ipc_bd_t bd_h[IPC_MAX_DEPTH];	/**< Buffer Descriptor on Host */
	ipc_bd_t bd_m[IPC_MAX_DEPTH];	/**< Buffer Descriptor on Modem */
	uint32_t op_type;		/**< Type of the BBDEV operation supported on this channel */
	uint32_t depth;			/**< Channel depth */
	uint32_t host_ipc_params;	/**< Address for host IPC parameters */
	uint32_t is_host_to_modem;	/**< Direction of operation */
	uint32_t conf_enable;		/**< Confirmation mode enabled/disabled */
} __attribute__((packed)) ipc_ch_t;

typedef struct ipc_instance {
	uint32_t instance_id;		/**< instance id, use to init this instance by ipc_init API */
	uint32_t initialized;		/**< Set in ipc_init */
	ipc_ch_t ch_list[IPC_MAX_CHANNEL_COUNT];	/**< Channel descriptors in this instance */
} __attribute__((packed)) ipc_instance_t;

typedef struct ipc_metadata {
	uint32_t ipc_host_signature;		/**< IPC host signature, Set by host/L2 */
	uint32_t ipc_modem_signature;	/**< IPC modem signature, Set by modem */
	ipc_instance_t instance_list[IPC_MAX_INSTANCE_COUNT];
} __attribute__((packed)) ipc_metadata_t;

typedef struct ipc_channel_us_priv {
	int32_t		eventfd;
	uint32_t	channel_id;
} ipc_channel_us_t;

typedef struct ipc_priv_t {
	int instance_id;
	int dev_ipc;
	int dev_mem;
	sys_map_t sys_map;
	mem_range_t modem_ccsrbar;
	mem_range_t tcml_start;
	mem_range_t mhif_start;
	mem_range_t hugepg_start;
	ipc_channel_us_t *channels[IPC_MAX_CHANNEL_COUNT];
	ipc_instance_t	*instance;
	ipc_instance_t	*instance_bk;
} ipc_userspace_t;

#define MODEM_PHY2VIRT(A, ipcu) \
	((uint64_t) ((unsigned long) (A) \
			+ (unsigned long)(ipcu->tcml_start.host_vaddr)))

#endif /* __LA93XX_IPC_H__ */
