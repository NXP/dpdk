/*
 * @ geul_ipc_api
 *
 * Copyright 2019 NXP
 *
 * Author: Ashish kumar
 * Author: Jagdish Gediya
 *
 * This software is available to you under the BSD-3-Clause
 * license mentioned below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 */

#ifndef __GEUL_IPC_API_H__
#define __GEUL_IPC_API_H__
#ifndef HOST
#define HOST 1
#define MODEM 0
#define HOST_IS_64BIT 1
#endif

#if HOST
#include <rte_mempool.h>
#include <geul_ipc_types.h>
#include <gul_ipc_ioctl.h>
#endif
#include <stdint.h>
#include <geul_ipc_errorcodes.h>

#if HOST
typedef uint64_t phys_addr_t;
typedef uint64_t addr_t;
#define SIZE_2K (1024 * 2)
#define SIZE_16K (1024 * 16)
#define SIZE_128K (1024 * 128)
#else
typedef uint32_t phys_addr_t;
typedef uint32_t addr_t;
#endif

typedef uint64_t ipc_bitmask_t;
typedef void *ipc_t;

/** ipc callback function for async channels */
/*****************************************************************************
 * @ipc_cbfunc_t
 *
 * Consumer callback function data type.
 *
 * channel_id - [IN][M] unique id of the channel
 *
 * context - [IN][M] This parameter has different meaning based on
 * channel type:
 * On a IPC_MSG_CH - the context is the ipc buffer pointer
 * from which the consumer should copy in local buffer
 *
 * On a IPC_PTR_CH - the context may be a buffer pointer
 *
 * len - [IN][M] usually contains the length of the context
 *
 * Return Value:
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 *****************************************************************************/
typedef int (*ipc_cbfunc_t)(uint32_t channel_id, void *context,
		uint32_t msg_len);

typedef enum ipc_mempool_type {
	IPC_MODEM_BUF_ALLOC_POOL,	/**< Modem allocate memory from peb for buffers */
	IPC_MAX_MEMPOOL_COUNT	/**< MAX mempool possible */
} ipc_mempool_type_t;

#if HOST
typedef enum ipc_mempool_size {
	IPC_HOST_BUF_POOLSZ_2K,		/**< HOST allocate memory from hugepg for 2K buffers as consumer */
	IPC_HOST_BUF_POOLSZ_16K,	/**< HOST allocate memory from hugepg for 16K buffers as consumer*/
	IPC_HOST_BUF_POOLSZ_128K,	/**< HOST allocate memory from hugepg for 128K buffers as consumer*/
	IPC_HOST_BUF_POOLSZ_SH_BUF,		/**< HOST allocate memory of size ipc_sh_buf_t(32 bytes as of) for consumer of PTR channel*/
	IPC_HOST_BUF_POOLSZ_R2,		/**< HOST allocate memory from hugepg for future use as consumer*/
	IPC_HOST_BUF_MAX_COUNT		/**< HOST allocate memory from hugepg for future use as consumer*/
} ipc_mempool_size_t;
#endif

typedef enum ipc_ch_type {
	IPC_CH_MSG = 1,
	IPC_CH_PTR = 2,
} ipc_ch_type_t;

/** Shared buffer descriptor */
typedef struct ipc_sh_buf {
	uint32_t mod_phys;	/**< modem address of the buffer */
	uint32_t buf_size;	/**< length of this buffer */
	uint32_t data_size;	/**< actual size of the data in this buffer */
	uint32_t cookie;	/**< Useful to free the buf */
	uint64_t host_phys;	/**< host physcal address of the buffer */
	uint64_t host_virt;	/**< host virtual address of the buffer */
} __attribute__((packed)) ipc_sh_buf_t;

/** IPC memory pool */
/** Modem only USED */
typedef struct ipc_mem_pool {
	uint32_t mod_phys;	/**< modem address of the buffer */
	uint32_t modem_cptr;	/**< Points to the start of the freespace in mem pool */
	uint32_t size;	/**< size of the memory pool */
} __attribute__((packed)) ipc_mem_pool_t;

#if MODEM
/** mempool should be initialized */
/*****************************************************************************
 * @ipc_modem_init
 *
 * Init function to initialize the IPC subsystem.
 *
 * instance_id - [IN][M]  IPC instance ID. For Geul cases only 0 (i.e single IPC instance)
 * is supported
 *
 * mem_pools – [IN][M] Pointer to PEB memory pools for
 * CTRL messages, SG List
 *
 * err - [OUT][O] Error code filled by API if any
 *
 * Return Value -
 * ipc_t handle.
 * This has to be provided in all subsequent calls to ipc
 *
 *****************************************************************************/
ipc_t ipc_modem_init(uint32_t instance_id, ipc_mem_pool_t *mem_pools[], int *err);
#endif

#if HOST
/*****************************************************************************
 * @ipc_host_init
 *
 * Init function to initialize the IPC subsystem.
 *
 * instance_id - [IN][M]  IPC instance ID. For Geul cases only 0 (i.e single IPC instance)
 * is supported
 *
 * rte_mempool – [IN][M] Pointer to DPDK memory pools for
 * CTRL messages, SG List
 *
 * err - [OUT][O] Error code filled by API if any
 *
 * Return Value -
 * ipc_t handle of the instance
 * This has to be provided in all subsequent calls to ipc's API
 *
 *****************************************************************************/
ipc_t ipc_host_init(uint32_t instance_id, struct rte_mempool *rte_mempool1[], mem_range_t hugepg_start, int *err);

int ipc_shutdown(void *);
#endif

/** for PTR channel, msg_size == sizeof (ipc_sh_buf_t)
 * for PTR channel, depth == size of free buffer list
 * For MSG channel where Modem is consumer it need to attach PEB memory in channel
 * To be used by both Host & Modem. This API configures consumer end of a IPC channel,
 * it also allocates the buffers for the channel close to the consumer.
 * For example, for channel where Modem is consumer, it is preferable to allocate
 * buffers in PEBM, and for channels where MAC is consumer it is preferable to
 * allocate buffers in Host DDR. This ensures no PCIe overheads are incurred when
 * consumer accesses the channel buffers. */
/*****************************************************************************
 * @ipc_configure_channel
 *
 * To be called one time per channel by the consumer.
 *
 * channel_id - [IN][M]unique id of the channel
 *
 * depth - [IN][M]user configurable number of entries in the ring.
 * depth <= max depth
 *
 * channel_type - [IN][M]either of IPC_PTR_CH/IPC_MSG_CH
 *
 * msg_size - [IN]max size of each message.
 * For PTR_CH, msg_ring_vaddr, msg_ring_paddr, msg_size
 * are all NULL. Required only for IPC_MSG_CH
 *
 * cbfunc - [IN]The callback function called on receiving interrupt
 * from the producer. If cbfunc is NULL, channel does not
 * support notifications.
 *
 * The channel supports the notification using interrupts
 * The ipc layer will find a free rt signal for process
 * and attach the signal with the interrupt.
 *
 * The kernel mode component of ipc will find a free irq
 * and attach to the channel structure in the shared ctrl
 * area which can be read by the producer.
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value:
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 *****************************************************************************/
int ipc_configure_channel(uint32_t channel_id,
		uint32_t depth,
		ipc_ch_type_t channel_type,
		uint32_t msg_size,
		ipc_cbfunc_t cbfunc,
		ipc_t instance);

/** This is called to attach the buffers from DPDK to IPC PTR channel
 *  Only HOST will call this
 *  Based on size, Pool indentification is done
 *
 * *************************************************************************/
int ipc_init_ptr_buf_list(uint32_t channel_id,
		uint32_t depth, uint32_t size, ipc_t instance);

/*****************************************************************************
 * @ipc_put_buf called to free buffer IPC channel attach to ipc_sh_buf_t
 * Consumer API.
 * channel_id - [IN][M]unique id of the channel
 *
 * buf_to_free - [IN][M] Pointer to ipc_sh_buf_t
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 *
 ****************************************************************************/
int ipc_put_buf(uint32_t channel_id, ipc_sh_buf_t *buf_to_free, ipc_t instance);

/*****************************************************************************
 * @ipc_get_buf called to get buffer IPC channel attach to ipc_sh_buf_t
 * Producer API.
 * channel_id - [IN][M]unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * err - [OUT][O] Error code filled by API if any
 *
 * Return Value - Pointer to ipc_sh_buf_t
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 *
 ****************************************************************************/
ipc_sh_buf_t* ipc_get_buf(uint32_t channel_id, ipc_t instance, int *err);

/** get buffer using ipc_get_buf API and then call this API */
/*****************************************************************************
 * @ipc_send_ptr
 *
 * Producer API.
 * channel_id - [IN][M]unique id of the channel
 *
 * buf - [IN][M] Pointer to ipc_sh_buf_t
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_send_ptr(uint32_t channel_id, ipc_sh_buf_t *buf, ipc_t instance);

/** Not to implement right now */
int ipc_get_prod_buf_ptr(uint32_t channel_id, void **buf_ptr, ipc_t instance);

/** This API should have algo to decide QDMA or Memcpy */
/** Memcpy initially, copy to IPC MSG channel buffer */
/*****************************************************************************
 * @ipc_send_msg
 *
 * Producer API.
 * channel_id - [IN][M]unique id of the channel
 *
 * src_buf_addr - [IN][M]source address of data buffer
 *
 * len - [IN][M]size of data buffer
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_send_msg(uint32_t channel_id, void *src_buf_addr,
		uint32_t len, ipc_t instance);

/*****************************************************************************
 * @ipc_recv_ptr
 *
 * Consumer API, called when the consumer is polling
 * channel_id - [IN][M]unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * err - [OUT][O] Error code filled by API if any
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
ipc_sh_buf_t* ipc_recv_ptr(uint32_t channel_id,	ipc_t instance, int *err);

/***************************************************************************
 * @ipc_recv_msg
 *
 * Consumer API, called when the consumer is polling
 *
 * dst_buffer - [IN][M]
 * IPC copies from the message ring into the buffer pointer provided
 * by the consumer, and increments the consumer index.
 *
 * len - [IN][M]
 * length of the copied buffer
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_recv_msg(uint32_t channel_id, void *dst_buffer,
		uint32_t *len, ipc_t instance);

/*****************************************************************************
 * @ipc_recv_msg_ptr
 *
 * Consumer API, called when the consumer is polling, and when the
 * consumer is using the buffer in the message ring(which is PEB memory) without
 * copying in the local buffer. (Zero Copy)
 * When consumed fully the API ipc_set_consumed_status should be
 * called, this would increment the consumer index.
 *
 * channel_id - [IN][M] unique id of the channel
 *
 * dst_buffer - [OUT][M] IPC copies the virtual address of message buffer
 *
 * len - [IN][M] length of the copied buffer
 *
 * instance - [IN][M] - ipc handle
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_recv_msg_ptr(uint32_t channel_id, void **dst_buffer,
		uint32_t *len, ipc_t instance);

/**This API is mainly for Modem.
 * L1C calls this API when it receives Interrupt from FECA that RX TB
 * is copied to the Host DDR. */
/*****************************************************************************
 * @ipc_set_produced_status
 *
 * channel_id - [IN][M] unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * Increments producer index for channel
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_set_produced_status(uint32_t channel_id, ipc_t instance);

/***************************************************************************
 * @ipc_set_consumed_status
 *
 * channel_id - [IN][M] unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * Called along with ipc_recv_msg_ptr to increment the consumer index
 * on that channel
 * OR
 * Called after ipc_recv_msg()
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_set_consumed_status(uint32_t channel_id, ipc_t instance);

/*****************************************************************************
 * @ipc_chk_recv_status
 *
 * The api checks all the consumer channels owned by the _calling process_ to
 * find out which has a msg/ptr received.
 *
 * bmask - [OUT][M] There can be a max of 64 channels. Each bit set
 * represents a channel has recieved a message/ptr.
 * Bit 0 MSB - Bit 64 LSB
 * (Bit = Channel id)
 *
 * instance - [IN][M] - ipc handle
 *
 * It can only find if there is any outstanding consume
 *
 * Return Value -
 * IPC_SUCCESS - no error
 * Non zero value - error (check ipc_errorcodes.h)
 ****************************************************************************/
int ipc_chk_recv_status(uint64_t *bmask, ipc_t instance);


/*****************************************************************************
 * @ipc_is_channel_configured
 * channel_id - [IN][M] unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * Should be called from Producer side for consumer channels only
 *
 * Return Value -
 * IPC_SUCCESS - no errr
 * Non zero value - error (check ipc_errorcodes.h)
 *****************************************************************************/
int ipc_is_channel_configured(uint32_t channel_id, ipc_t instance);

/*****************************************************************************
 * @ipc_get_list_of_configured_channel
 * list[] [OUT][M] unique id of the channel
 *
 * instance - [IN][M] - ipc handle
 *
 * Should be called from Producer side for consumer channels only
 *
 * Return Value -
 * IPC_SUCCESS - no errr
 * Non zero value - error (check ipc_errorcodes.h)
 *****************************************************************************/
int ipc_get_list_of_configured_channel(ipc_bitmask_t list[], ipc_t instance);

/** Generic comments for Guel
 * MPU Configuration as per below
 * : IPC metadata : Cache inhabitate, Gaurded
 * : IPC data: Cacheable, Non-Gaurded
 */
#endif	/* __GEUL_IPC_API_H__ */
