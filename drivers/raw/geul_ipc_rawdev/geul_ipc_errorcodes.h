/*
 * @ ipc_errorcodes
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


#ifndef __IPC_ERRCODES_H__
#define __IPC_ERRCODES_H__

/** Error codes */
#define IPC_SUCCESS			( 0  )	/** IPC operation success */
#define IPC_INPUT_INVALID		( -1 )	/** Invalid input to API */
#define IPC_CH_INVALID			( -2 )	/** Channel no is invalid */
#define IPC_INSTANCE_INVALID		( -3 )	/** Instance no is invalid */
#define IPC_MEM_INVALID			( -4 )	/** Insufficient memory */
#define IPC_CH_FULL			( -5 )	/** Channel is full */
#define IPC_CH_EMPTY			( -6 )	/** Channel is empty */
#define IPC_BL_EMPTY			( -7 )	/** Free buffer list is empty */
#define IPC_BL_FULL			( -8 )	/** Free buffer list is full */
#define IPC_HOST_BUF_ALLOC_FAIL		( -9 )	/** DPDK malloc fail */
#define IPC_MD_SZ_MISS_MATCH		( -10 ) /** META DATA size in mhif miss matched */
#define IPC_MALLOC_FAIL			( -11 ) /** system malloc fail */
#define IPC_IOCTL_FAIL			( -12 ) /** IOCTL call failed */
#define IPC_MMAP_FAIL			( -14 ) /** MMAP fail */
#define IPC_NOT_IMPLEMENTED		( -15 )	/** IPC feature is not implemented yet */

#endif	/* __IPC_ERRCODES_H__ */
