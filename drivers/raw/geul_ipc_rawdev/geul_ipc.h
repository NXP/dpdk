/*
 * Copyright 2019 NXP
 */

#ifndef __GEUL_IPC_H__
#define __GEUL_IPC_H__

#include <stdint.h>
#include "geul_ipc_errorcodes.h"
#include "geul_ipc_api.h"

/** Count the bits in (v), for e.g. short 2 * 8 = 16 */
#define bitcount(v)	(sizeof(v) * 8)

/** No. of max IPC instance possible */
#define IPC_MAX_INSTANCE_COUNT	( 1 )

/** No. of max channel per instance */
#define IPC_MAX_CHANNEL_COUNT	( 64 )

/** No. of max channel per instance */
#define IPC_MAX_DEPTH	( 4 )

/** Channel config bitmask array size */
#define IPC_BITMASK_ARRAY_SIZE		(((IPC_MAX_CHANNEL_COUNT - 1) / bitcount(ipc_bitmask_t)) + 1)
#define IPC_BUF_ALLOC_POOL_SIZE	(1024 * 512)

/** buffer ring common metadata */
typedef struct ipc_bd_ring_md {
	uint32_t pi;		/**< Producer index */
	uint32_t ci;		/**< Consumer index */
	uint32_t ring_size;	/**< depth (Used to roll-over pi/ci) */
	uint32_t pc;		/**< Produced counter */
	uint32_t cc;		/**< Consumed counter */
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
	uint64_t host_phy;	/**< msg's host physical address */
	uint32_t modem_ptr;	/**< msg's modem physical address */
	uint32_t len;		/**< msg len */
	uint64_t crc;		/**< crc */
} __attribute__((packed)) ipc_bd_t;

/** ipc msg bd ring */
typedef struct ipc_bd_ring_msg {
	ipc_br_md_t md;
	ipc_bd_t bd[IPC_MAX_DEPTH];	/** < Add comment */
} __attribute__((packed)) ipc_bd_ring_msg_t;


typedef struct ipc_bd_ring_buf_list {
	ipc_br_md_t md;
	ipc_sh_buf_t bd[IPC_MAX_DEPTH];
} __attribute__((packed)) ipc_bd_ring_bl_t;

typedef struct ipc_channel {
	uint32_t ch_id;		/**< Channel id */
	uint32_t bl_initialized;	/**< Set when buffer list is initialized */
	ipc_cbfunc_t event_cb;		/**< IPC channel callback for async design */
#if MODEM || (HOST & !HOST_IS_64BIT)
	uint32_t pad;	/**< Padding to align 64 bit ptr size on host to 32 bit ptr size of modem */
#endif
	ipc_ch_type_t ch_type;
	ipc_bd_ring_msg_t br_msg_desc;
	ipc_bd_ring_bl_t br_bl_desc;
} __attribute__((packed)) ipc_ch_t;

typedef struct ipc_instance {
	uint32_t instance_id;		/**< instance id, use to init this instance by ipc_init API */
	uint32_t initialized;		/**< Set in ipc_init */
	ipc_ch_t ch_list[IPC_MAX_CHANNEL_COUNT];	/**< Channel descriptors in this instance */
	ipc_mem_pool_t mem_pool[IPC_MAX_MEMPOOL_COUNT];		/**< Use to allocate space in PEB/WSRAM memory by MODEM*/
	ipc_bitmask_t ch_data_rdy_msk[IPC_BITMASK_ARRAY_SIZE];	/**< Maintain bitmask of produced data channels */
	ipc_bitmask_t cfgmask[IPC_BITMASK_ARRAY_SIZE];	/**< Maintain bitmask of configured channels also set in ipc_configure_channel() */
} __attribute__((packed)) ipc_instance_t;

typedef struct ipc_metadata {
	uint32_t ipc_host_signature;		/**< IPC host signature, Set by host/L2 */
	uint32_t ipc_geul_signature;	/**< IPC geul signature, Set by modem */
	ipc_instance_t instance_list[IPC_MAX_INSTANCE_COUNT];
} __attribute__((packed)) ipc_metadata_t;

#endif /* __GEUL_IPC_H__ */
