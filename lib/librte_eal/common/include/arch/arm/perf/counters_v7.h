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

#ifndef __COUNTERS_H_V7__
#define __COUNTERS_H_V7__

#include <stdint.h>



static inline void arm_enable_counter(int counter)
{
         asm volatile("mcr p15, 0, %0, c9, c12, 1" : : "r" (1UL << counter) );
}


static inline void arm_enable_cycle_counter()
{
         asm volatile("mcr p15, 0, %0, c9, c12, 1" : : "r" (1UL << 31) );
}

static inline void arm_disable_counter(counter)
{
         asm volatile("mcr p15, 0, %0, c9, c12, 2" : : "r" (1UL << counter) );
}

static inline void arm_disable_cycle_counter()
{
         asm volatile("mcr p15, 0, %0, c9, c12, 2" : : "r" (1UL << 31) );
}

static inline void arm_connect_counter_to_event(int counter, uint32_t event)
{
         asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (counter));
         asm volatile("mcr p15, 0, %0, c9, c13, 1" : : "r" (event));
}



static inline uint32_t arm_read_counter(int counter)
{
         uint32_t value ;
         asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (counter));
         asm volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (value));
         return value;
}


static inline uint32_t arm_read_cycle_counter(void)
{
        uint32_t value;
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(value) );
        return value;
}


#endif

