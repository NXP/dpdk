/*
 * Copyright 2019 NXP
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree or part of the
 * FreeRTOS distribution.
 *
 * FreeRTOS is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License (version 2) as published by
 * the Free Software Foundation >>!AND MODIFIED BY!<< the FreeRTOS exception.
 * >>! NOTE: The modification to the GPL is included to allow you to
 * >>! distribute a combined work that includes FreeRTOS without being obliged to
 * >>! provide the source code for proprietary components outside of the FreeRTOS
 * >>! kernel.
 *
 * FreeRTOS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  Full license text is available from the
 * following link: http://www.freertos.org/a00114.htmlor the BSD-3-Clause
 *
 */
#ifndef __GUL_IPC_IF_H__
#define __GUL_IPC_IF_H__

/* Number of IPC channels to create at run time */
#define NUM_IPC_CHANNELS	(64)

/* Maximum size of data transfer supported in IPC CP */
/* Should be multiple of 4 */
#define IPC_MSG_SIZE		(0x100)		/* 256B */

#endif	/* __GUL_IPC_IF_H__ */
