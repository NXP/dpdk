This package provides source code for accessing performance counters from linux userspace. 

It comes with two kernel modules one for each architecture(ARMv7 & ARMv8) which enable the access to the hardware performance counters from userspace. Please edit the makefile appropriately to compile the module for the desired architecture. Once compiled insmod the kernel module.

In the source code where you would like to access the performance counters include "counters.h" header file. This file will inturn include the required header file for the architecture. 

We have to enable the counters with a specific event(cycles, cache misses etc) to start counting that event. We can do that using below sequence of function calls.
  
  	arm_write_evtype(PM_COUNTER_1, L1D_CACHE_REFILL);
  	arm_pmu_enable_counter(PM_COUNTER_1);

Here we first select an event which we want to monitor and the counter where we want the event to be counted. After which we enable that counter to start counting.

All the counters are 32 bits in length so when we read that counter, it returns an unsigned 32 bit integer value. We can read the counter using the below function.
	
	uint32_t read;
	read = arm_read_counter(PM_COUNTER_1);

We can disable the counters by calling the below function.
	
	arm_pmu_disable_counter(PM_COUNTER_1);

64 Bit Cycle counter:
We can Enable the 64 bit cycle counter using
	
	arm_enable_cycle_counter();

reading the cycle counter:

	uint64_t read;
	read = arm_read_cycle_counter();

Disalbe cycle counter:

	arm_disable_cycle_counter();

See the test_program.c for reference on how an event is monitored.

Example code:

#include <stdio.h>
#include <stdint.h>
#include "counters.h"

int main(void)
{
  uint64_t read1=0, read2=0;
  uint64_t cyc_read1=0, cyc_read2=0;
  int i,x=0;
  /*selecting PM_COUNTER_1 to count "INST_EXEC" event*/
  arm_connect_counter_to_event(PM_COUNTER_1, INST_EXEC);

  /*enable PM_COUNTER_1  counter*/
  arm_enable_counter(PM_COUNTER_1);

  /*Enable the 64bit cycle counter*/
  arm_enable_cycle_counter();

  /*Get an initial reading of PM_COUNTER_1*/
  read1 = arm_read_counter(PM_COUNTER_1);

  /*Get an initial reading of 64 bit cycle counter*/
  cyc_read1 = arm_read_cycle_counter();

  for(i=0;i<1000;i++)
    x++;

  /*Get an final reading of 64 bit cycle counter*/
  cyc_read2 = arm_read_cycle_counter();

  /*Get an final reading of PM_COUNTER_1*/
  read2 = arm_read_counter(PM_COUNTER_1);

  /*disable counters*/
  arm_disable_counter(PM_COUNTER_1);
  arm_disable_cycle_counter();

  printf("x = %d, INST = %lu, CYC = %lu\n", x, read2-read1, cyc_read2-cyc_read1);
  return 0;
}

