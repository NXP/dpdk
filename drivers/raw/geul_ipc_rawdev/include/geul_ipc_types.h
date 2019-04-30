/*
 * @ geul_ipc_types
 *
 * Copyright 2019 NXP
 *
 * Author: Ashish kumar
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


#ifndef __GEUL_IPC_TYPES_H__
#define __GEUL_IPC_TYPES_H__
#include "gul_ipc_ioctl.h"

typedef struct {
        uint64_t host_phys;
        uint32_t modem_phys;
        void    *host_vaddr;
        uint32_t size;
} mem_range_t;

#endif	/* __GEUL_IPC_TYPES_H__ */
