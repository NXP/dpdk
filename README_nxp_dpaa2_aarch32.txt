===============================================================================
NXP DPDK README FOR LS-DPAA2 aarch32 PLATFORM e.g LS208x, LS108x
===============================================================================

NXP DPDK provides a set of data plane libraries and network interface
controller driver for Layerscape platforms
This README provides information about building and executing DPDK based
applications for LS-DPAA2 platform

===============================================================================

Components for Build & Execution Environment
--------------------------------------------

To successfully build and execute DPDK based applications for LS2 platform,
following components are required:

1. DPDK source code
2. Cross compiled toolchain for ARM platform
3. Linux kernel for LS2 platform
4. LS208x board or LS1088 board

Following information can be used to obtain these components:

     DPDK code for LS2 platform
     ==========================
     Use following command to get the DPDK code

       # git clone ssh://git@sw-stash.freescale.net/gitam/dpdk.git
       # git checkout -b 16.07-qoriq remotes/origin/16.07-qoriq


     Linux kernel code for LS2 platform
     ==================================
     Use following command to get the linux code

       # install SDK released by NXP(previously freescale) for ls208x or ls108x
       # find the source for linux


     Cross compiled toolchain For ARM
     ==================================
    get the linaro gcc-5.1 or later toolchain from:
    https://releases.linaro.org/components/toolchain/binaries/5.1-2015.08/armv8l-linux-gnueabihf/

set the CROSS path e.g
export CROSS=/opt/gcc-linaro-5.1-2015.08-x86_64_armv8l-linux-gnueabihf/bin/armv8l-linux-gnueabihf-

===============================================================================

How to Build DPDK Applications
------------------------------
1. Execute following commands from Linux(Host) shell prompt for generating
   DPDK libraries, which are required for compiling DPDK examples and
   applications:

     make install T=arm-dpaa2-linuxapp-gcc
     - If installation is required in a specific directory, use following:
     make install T=arm-dpaa2-linuxapp-gcc DESTDIR=<Path to install dir>

2. Steps for compiling the DPDK examples
	The basic testpmd application is compiled by default. It should be available in build/app
	or install directory.

     1. set other export variables (execute these from the DPDK directory):
	   # export RTE_TARGET=arm-dpaa2-linuxapp-gcc
	   # export RTE_SDK=`pwd`

     2. Compilation of L3FWD example
           # make -C examples/l3fwd

===============================================================================

How to run DPDK Applications
----------------------------
1. Bring up the board with the LS2 images with proper DPNI-DPMAC configurations
   in the DPL file.

2. Get the dpdk applications binaries and dynamic_dpl.sh on the LS2 board.
 It may already be present in your rootfs

   Run the following on the board:
      1. source /usr/bin/dpdk-example/extras/dynamic_dpl.sh dpmac.1 dpmac.2 dpmac.3 dpmac.4
      2. export DPRC=<dprc_container_created_by_dynamic_DPL>

3. Running DPDK testpmd Application
   ==============================

   Execute following commands to run DPDK testpmd on LS2 board

   #./testpmd -c 0xF -n 4 -- -i --portmask=0x3 --nb-cores=2
   - this will run test_pmd on dpni.0 and dpni.2 w.r.t dpmac.3 and dpmac.3
   - you can change the number of cores.

   This would start the testpmd application in interactive mode, starting a
   shell for accepting further commands. For e.g:

   testpmd> show port info all

   Above command can be used to view all the ports which the framework has
   identified, with their detailed information.

4. Running DPDK L3FWD Application
   ==============================

   Execute following commands to run DPDK L3FWD on LS2 board

	1 core - 1 Port, 1 queue per port =>
	./l3fwd -c 0x1 -n 1 -- -p 0x1 --config="(0,0,0)"

	4 core - 2 Port, 2 queue per port =>
	./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)"

	4 core - 2 Port with dest mac =>
	./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)" --eth-dest=0,11:11:11:11:11:11 --eth-dest=1,00:00:00:11:11:11

	8 core - 4 Port with 4 queue per port =>
	./l3fwd -c 0xFF -n 1 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3),(2,0,4),(2,1,5),(3,0,6),(3,1,7)"

       Now pump traffic from the Spirent to the enabled ports as per the given streams
		Traffic to port 1: 1.1.1.0/24
		Traffic to port 2: 2.1.1.0/24
		Traffic to port 3: 3.1.1.0/24
		Traffic to port 4: 4.1.1.0/24

=============================================================================
Applications validated on DPDK-DPAA2
 1. l3fwd

Features:
-	Support for LS2-BUS in DPDK VFIO support function
-	Addition of WRIOP-MC based poll mode driver (pmd) in DPDK.
-	Able to run DPDK on single core and multiple cores.

Code Location: stash
Branch: 16.07-qoriq
Tag:

DPDK base version used: Release 16.07
More info on DPDK :  www.dpdk.org

LS2 Release - SDK2.0
NXP contact: hemant.agrawal@nxp.com
