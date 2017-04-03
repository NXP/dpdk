===============================================================================
NXP DPDK README FOR LS-DPAA2 PLATFORM e.g LS208x, LS108x
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
2. Cross compiled toolchain for ARM64 platform
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


     Cross compiled toolchain For ARM64
     ==================================
    get the linaro gcc-4.9 or later toolchain from:
    https://releases.linaro.org/components/toolchain/binaries/4.9-2016.02/aarch64-linux-gnu/

set the CROSS_COMPILE path e.g
export CROSS_COMPILE=/opt/gcc-linaro-4.9-2016.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-

===============================================================================

How to Build DPDK Applications
------------------------------
1. Script "standalone-dpaa2" is present in DPDK code. Open it and check the
   CROSS_PATH.

     --> export CROSS_PATH=/opt/gcc-linaro-4.9-2016.02-x86_64_aarch64-linux-gnu/bin/

     NOTE: if toolchain is installed at location other than "/opt" then above
     lines needs to be modified appropriately.

2. OpenSSL cross compilation (for ARM CE - crypto support)

   Cross compilation requires cross compiling the individual libraries.  In order for
   a cross compiled executable to run on a target system, one must build the same
   version as that which is installed on the target rootfs.

   # Clone openssl repository
   $ git clone git://git.openssl.org/openssl.git
   $ cd openssl

   # Checkout the specific tag to match openssl library in your target rootfs
   $ git checkout OpenSSL_1_0_2h


   # Build and install 64 bit version of openssl
   $ ./Configure linux-aarch64  --prefix=<OpenSSL library path> shared
   $ make depend
   $ make
   $ make install
   $ export OPENSSL_PATH=<OpenSSL library path>

  NOTE: ARMCE is enabled by default and OpenSSL PATH is needed.
	If ARMCE (crypto) is not needed,
		modify config/defconfig_arm64-dpaa2-linuxapp-gcc
		CONFIG_RTE_LIBRTE_PMD_ARMCE=n

3. Execute following commands from Linux(Host) shell prompt for generating
   DPDK libraries, which are required for compiling DPDK examples and
   applications:

     1. export KERNEL_PATH=<path to LS2 Linux kernel code - prebuild>
	if you don't have kernel sources, you may disable KNI
		modify config/defconfig_arm64-dpaa2-linuxapp-gcc
		CONFIG_RTE_KNI_KMOD=n	
     2. export CROSS_COMPILE=/opt/gcc-linaro-4.9-2016.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
     3. export OPENSSL_PATH=<path to OpenSSL library>
     4. source standalone-dpaa2
     5. make install T=arm64-dpaa2-linuxapp-gcc
        - If installation is required in a specific directory, use following:
        make install T=arm64-dpaa2-linuxapp-gcc DESTDIR=<Path to install dir>

4. Steps for compiling the DPDK examples
	The basic testpmd application is compiled by default. It should be available in build/app
	or install directory.
     1. Before executing following step, all the steps mentioned in point no. "3"
        above must have been executed. export the RTE_TARGET
	export RTE_TARGET=arm64-dpaa2-linuxapp-gcc
     2. compilation of KNI example
           # make -C examples/kni
     3. Compilation of L2FWD example
           # make -C examples/l2fwd
     4. Compilation of L3FWD example
           # make -C examples/l3fwd
     5. Compilation of L2FWD-Crypto example
           # make -C examples/l2fwd-crypto
     6. Compilation of Test example
           # make -C app/test

===============================================================================

How to run DPDK Applications
----------------------------
1. Bring up the board with the LS2 images with proper DPNI-DPMAC configurations
   in the DPL file.

2. Get the dpdk applications binaries and dynamic_dpl.sh on the LS2 board.
 It may already be present in your rootfs

	#if you plan to run pktgen, please also increase the number of buffer pool available
	export DPBP_COUNT=16

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

4. Running DPDK L2FWD Application
   ==============================

   Execute following commands to run DPDK L2FWD on LS2 board

       # ./l2fwd -c 0x1 -n 1 -- -p 0x1 -q 1
                        OR
       # ./l2fwd -c 0x3 -n 1 -- -p 0x3 -q 1

       Now pump traffic from the Spirent to the enabled ports

7. Running DPDK L3FWD Application
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

6. Running DPDK L2FWD-CRYPTO Application
   ==============================

   Execute following commands to run DPDK L2FWD-CRYPTO on LS2 board

   Case: Encrypt then Authenticate
       # ./l2fwd-crypto -c 0x1 -n 1 -- -p 0x3 -q 1 -s --chain CIPHER_HASH  \
		--cipher_algo AES_CBC --cipher_op ENCRYPT --cipher_key 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10 \
		--auth_algo SHA1_HMAC --auth_op GENERATE
   Case: Encrypt only
       # ./l2fwd-crypto -c 0x1 -n 1 -- -p 0x3 -q 1 -s --chain CIPHER_ONLY --cipher_algo AES_CBC --cipher_op ENCRYPT --cipher_key 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10
   Case: Authenticate only
       # ./l2fwd-crypto -c 0x1 -n 1 -- -p 0x3 -q 1 -s --chain HASH_ONLY --auth_algo SHA1_HMAC --auth_op GENERATE
   Case: Authenticate then Encrypt
       # To be supported in future.

       Now pump traffic from the Spirent to the enabled ports

7. Running DPDK TEST application for Crypto tests
   ==============================

   Transfer the test utility to board
   Execute following commands to run DPDK test on LS2 board
       # ./test
   Execute following commands to run Crypto tests on RTE command line
       # RTE>>cryptodev_dpaa2_sec_autotest
	This is for functional verification of Encrypt+Hash Generate and then Decrypt+Hash Verify for AES-CBC-HMAC-SHA1. More test cases will be added in future.

       # RTE>>cryptodev_dpaa2_sec_perftest
	This is for taking performance numbers of Crypto operations.

8. Running DPDK test Application for ARM-CE:
   ==============================

       1. To launch regression tests:
           # ./test
           RTE>>cryptodev_armce_autotest

       2. To launch performance/benchmark tests:
           # ./test
           RTE>>cryptodev_armce_perftest


9. Running DPDK KNI Application
   ============================

   Execute following commands to run DPDK KNI

         loadable module "rte_kni.ko" from Host machine to target machine

            # scp <user>@192.168.1.1:$(RTE_SDK)/examples/kni/build/kni .
            # scp <user>@192.168.1.1:$(RTE_SDK)/arm64-dpaa2-linuxapp-gcc/kmod/rte_kni.ko .


      4. Now execute following commands to run KNI

            #insmod rte_kni.ko
	    # ./kni -c 0x3 -n 1 -- -P -p 0x1 --config "(0,0,1)" &

                   Above command will start the execution
                   of "kni" in background. This is required
                   so to further execute following commands
                   shell prompt:

            # ifconfig vEth0 hw ether 00:00:00:00:00:09
            # ifconfig vEth0 9.9.9.10

       On Host Machine
       ---------------
       1. Now execute "ping" command from HOST Machine so to get "ping response"
          from KNI application running on Target Machine

            # ping 9.9.9.10

          Similarly, execute "ping" command from Target Machine shell prompt so
          to get "ping response" from Host Machine

            # ping 9.9.9.1

10. Building and Use PKTGEN with DPDK
   ============================

	Get the code from: git://dpdk.org/apps/pktgen-dpdk
	- DPDK 16.07 works upto pktgen 3.1.2

	#do the make install in DPDK.
	source <DPDK Source DIR>/standalone_dpaa
	export RTE_SDK=<DPDK Source DIR>
	make

	Note: you may need pcap library installed in your toolchain (compiled for ARM64)

	Copy "Pktgen.lua" and "pktgen" 	to the board.
	(available at: app/app/arm64-dpaa2-linuxapp-gcc/pktgen)

	example Command to run:

	#3 port - 1 core each
	./pktgen -l 0-3 -n 3 --proc-type auto --file-prefix pg --log-level 8 -- -T -P -m "[1].0, [2].1, [3].2"

	#2 port - 2 core each
	./pktgen -l 0-7 -n 3 --proc-type auto --file-prefix pg --log-level 8 -- -T -P -m "[2:3].0, [4:5].1"

	#To start traffic on specific port:
	start 0
	stop 0

	#To start on all ports
	str
	stp

=============================================================================
11.Applications validated on DPDK-DPAA2
 1. l2fwd
 2. l3fwd
 3. l2fwd-crypto
 4. link_status_interrupt (link_status_interrupt -c 0xf -n 1  --log-level=8  -- -p 0x30 -q 1 -T 30)
 5. ip_fragmentation
 6. ip_reassembly
 7. kni
 8. cmdline
 9. timer

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
