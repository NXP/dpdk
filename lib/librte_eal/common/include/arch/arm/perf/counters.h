/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of  Freescale Semiconductor, Inc nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__

#include <stdint.h>

/*Common EVENTS for ARMv7 and ARMv8*/
#define L1I_CACHE_REFILL          0x01
#define L1I_TLB_REFILL            0x02
#define L1D_CACHE_REFILL          0x03
#define L1D_CACHE_ACCESS          0x04
#define L1D_TLB_REFILL            0x05
#define LD_INST_EXEC              0x06
#define ST_INST_EXEC              0x07
#define INST_EXEC                 0x08
#define EXCP_TAKEN                0x09
#define EXCP_RETURN               0x0A
#define CID_WRITE_EXEC            0x0B
#define PC_WRITE_EXEC             0x0C
#define BR_IMMED_EXEC             0x0D
#define BR_RETURN_EXEC            0x0E
#define UNALIGNED_LDST_EXEC       0x0F
#define BR_MIS_PRED               0x10
#define CPU_CYCLES                0x11
#define BR_PRED                   0x12
#define MEM_ACCESS                0x13
#define L1I_CACHE_ACCESS          0x14
#define L1D_CACHE_WB              0x15
#define L2D_CACHE_ACCESS          0x16
#define L2D_CACHE_REFILL          0x17
#define L2D_CACHE_WB              0x18
#define BUS_ACCESS                0x19
#define BUS_CYCLES                0x1D
#define BUS_ACCESS_LD             0x60
#define BUS_ACCESS_ST             0x61
#define IRQ_EXCP                  0x86
#define FIQ_EXCP                  0x87

/*COUNTERS*/
#define PM_COUNTER_1              0
#define PM_COUNTER_2              1
#define PM_COUNTER_3              2
#define PM_COUNTER_4              3

#if defined(__GNUC__) && defined(__ARM_ARCH_7A__)
#include "counters_v7.h"
#endif
#if defined(__GNUC__) && defined(__aarch64__)
#define PM_COUNTER_5              4
#define PM_COUNTER_6              5
#include "counters_v8.h"
#endif
#endif
