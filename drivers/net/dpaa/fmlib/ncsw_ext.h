/*-
 * This file is provided under a dual BSD/GPLv2 license. When using or
 * redistributing this file, you may do so under either license.
 *
 *   BSD LICENSE
 *
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *   GPL LICENSE SUMMARY
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __NCSW_EXT_H
#define __NCSW_EXT_H

#include <stdint.h>

#define PTR_TO_UINT(_ptr)	((uintptr_t)(_ptr))
#define UINT_TO_PTR(_val)	((void *)(uintptr_t)(_val))

/* physAddress_t should be uintptr_t */
typedef uint64_t physAddress_t;

/**************************************************************************//**
 @Description   Possible RxStore callback responses.
*//***************************************************************************/
typedef enum e_RxStoreResponse {
	e_RX_STORE_RESPONSE_PAUSE
		/**< Pause invoking callback with received data;
		in polling mode, start again invoking callback
		only next time user invokes the receive routine;
		in interrupt mode, start again invoking callback
		only next time a receive event triggers an interrupt;
		in all cases, received data that are pending are not
		lost, rather, their processing is temporarily deferred;
		in all cases, received data are processed in the order
		in which they were received. */
	, e_RX_STORE_RESPONSE_CONTINUE
	/**< Continue invoking callback with received data. */
} e_RxStoreResponse;


/**************************************************************************//**
 @Description   General Handle
*//***************************************************************************/
typedef void *t_Handle;   /**< handle, used as object's descriptor */

/* @} */

/**************************************************************************//**
 @Function	t_GetBufFunction

 @Description   User callback function called by driver to get data buffer.

		User provides this function. Driver invokes it.

 @Param[in]	h_BufferPool	- A handle to buffer pool manager
 @Param[out]	p_BufContextHandle  - Returns the user's private context that
					should be associated with the buffer

 @Return	Pointer to data buffer, NULL if error
 *//***************************************************************************/
typedef uint8_t * (t_GetBufFunction)(t_Handle   h_BufferPool,
					t_Handle * p_BufContextHandle);

/**************************************************************************//**
 @Function	t_PutBufFunction

 @Description   User callback function called by driver to return data buffer.

		User provides this function. Driver invokes it.

 @Param[in]	h_BufferPool	- A handle to buffer pool manager
 @Param[in]	p_Buffer	- A pointer to buffer to return
 @Param[in]	h_BufContext	- The user's private context associated with
				the returned buffer

 @Return	E_OK on success; Error code otherwise
 *//***************************************************************************/
typedef uint32_t (t_PutBufFunction)(t_Handle h_BufferPool,
				uint8_t  *p_Buffer,
				t_Handle h_BufContext);

/**************************************************************************//**
 @Function	t_PhysToVirt

 @Description   Translates a physical address to the matching virtual address.

 @Param[in]	addr - The physical address to translate.

 @Return	Virtual address.
*//***************************************************************************/
typedef void *t_PhysToVirt(physAddress_t addr);

/**************************************************************************//**
 @Function	t_VirtToPhys

 @Description   Translates a virtual address to the matching physical address.

 @Param[in]	addr - The virtual address to translate.

 @Return	Physical address.
*//***************************************************************************/
typedef physAddress_t t_VirtToPhys(void *addr);

/**************************************************************************//**
 @Description   Buffer Pool Information Structure.
*//***************************************************************************/
typedef struct t_BufferPoolInfo {
	t_Handle		h_BufferPool;   /**< A handle to the buffer pool manager */
	t_GetBufFunction	*f_GetBuf;	/**< User callback to get a free buffer */
	t_PutBufFunction	*f_PutBuf;	/**< User callback to return a buffer */
	uint16_t		bufferSize;	/**< Buffer size (in bytes) */

	t_PhysToVirt	*f_PhysToVirt;  /**< User callback to translate pool buffers
						physical addresses to virtual addresses  */
	t_VirtToPhys	*f_VirtToPhys;  /**< User callback to translate pool buffers
						virtual addresses to physical addresses */
} t_BufferPoolInfo;

/**************************************************************************//**
 @Description   User callback function called by driver with receive data.

		User provides this function. Driver invokes it.

 @Param[in]	h_App	- Application's handle, as was provided to the
				driver by the user
 @Param[in]	queueId	- Receive queue ID
 @Param[in]	p_Data	- Pointer to the buffer with received data
 @Param[in]	h_BufContext	- The user's private context associated with
				the given data buffer
 @Param[in]	length	- Length of received data
 @Param[in]	status	- Receive status and errors
 @Param[in]	position	- Position of buffer in frame
 @Param[in]	flags	- Driver-dependent information

 @Retval	e_RX_STORE_RESPONSE_CONTINUE - order the driver to continue Rx
						operation for all ready data.
 @Retval	e_RX_STORE_RESPONSE_PAUSE- order the driver to stop Rx ops.
 *//***************************************************************************/
typedef e_RxStoreResponse(t_RxStoreFunction)(t_Handle  h_App,
						uint32_t  queueId,
						uint8_t   *p_Data,
						t_Handle  h_BufContext,
						uint32_t  length,
						uint16_t  status,
						uint8_t   position,
						uint32_t  flags);

typedef struct t_Device {
	uintptr_t   id;	/**< the device id */
	int	fd;	/**< the device file descriptor */
	t_Handle	h_UserPriv;
	uint32_t	owners;
} t_Device;

t_Handle CreateDevice(t_Handle h_UserPriv, t_Handle h_DevId);
t_Handle GetDeviceId(t_Handle h_Dev);

#endif /* __NCSW_EXT_H */
