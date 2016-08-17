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

#ifndef __COUNTERS_H_V8__
#define __COUNTERS_H_V8___

#include <stdint.h>


static inline uint32_t arm_read_counter(int counter)
{
	 uint32_t value;
 	 asm volatile("msr pmselr_el0,%0"  ::  "r" (counter));
	 /* We have possible race condition here: 
	    if someone is trying to read/write
	 different counter */
         asm volatile("mrs %0,pmxevcntr_el0" : "=r" (value));

         return value;
}

static inline void arm_write_counter(int counter, uint32_t value)
{
	asm volatile("msr pmselr_el0,%0"  ::  "r" (counter));
        asm volatile("msr pmxevcntr_el0,%0" :: "r" (value));
}

static inline void arm_connect_counter_to_event(int counter, uint32_t event)
{
	asm volatile("msr pmselr_el0,%0"  ::  "r" (counter));
        asm volatile("msr pmxevtyper_el0,%0" :: "r" (event));
}


static inline void arm_enable_counter(int counter)
{
        asm volatile("msr pmcntenset_el0,%0" :: "r" (1UL<<counter) );
}

static inline void arm_enable_cycle_counter(void)
{
        asm volatile("msr pmcntenset_el0,%0" :: "r" (1UL<<31) );	
}

static inline void arm_disable_counter(int counter)
{
	asm volatile("msr pmcntenclr_el0,%0" :: "r" (1UL<<counter) );
}


static inline void arm_disable_cycle_counter(void)
{
	asm volatile("msr pmcntenclr_el0,%0" :: "r" (1UL<<31) );
}

static inline uint64_t arm_read_cycle_counter(void)
{
  uint64_t val = 0;

  asm volatile("mrs %0, pmccntr_el0" : "=r" (val));
  
  return val;
}
 
#endif
