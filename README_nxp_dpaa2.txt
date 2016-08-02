===============================================================================
NXP DPDK README FOR LS-DPAA2 PLATFORM
===============================================================================

NXP DPDK provides a set of data plane libraries and network interface
controller driver for LS2 and QorIQ platforms.
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
4. LS208x board

Following information can be used to obtain these components:

     DPDK code for LS2 platform
     ==========================
     Use following command to get the DPDK code

       # git clone ssh://git@sw-stash.freescale.net/gitam/dpdk.git
       # git checkout -b 16.07-qoriq remotes/origin/16.07-qoriq


     Linux kernel code for LS2 platform
     ==================================
     Use following command to get the DPDK code

       # git clone ssh://git@sw-stash.freescale.net/dnnpi/ls2-linux.git


     Cross compiled toolchain For ARM64
     ==================================
	get the linaro gcc-4.9 toolchain.
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

2. Execute following commands from Linux(Host) shell prompt for generating
   DPDK libraries, which are required for compiling DPDK examples and
   applications:

     1. export KERNEL_PATH=<path to LS2 Linux kernel code>
     2. source standalone-dpaa2
     3. make install T=arm64-dpaa2-linuxapp-gcc
        - If installation is required in a specific directory, use following:
        make install T=arm64-dpaa2-linuxapp-gcc DESTDIR=<Path to install dir>

3. Steps for compiling the DPDK examples
	The basic testpmd application is compiled by default. It should be available in build/app
	or install directory.
     1. Before executing following step, all the steps mentioned in point no. "2"
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
 If you are planning to run l3fwd or any other multiple TX Queue based application please export
 following parameters for resourcing
	export MAX_TCS=8
	export MAX_DIST_PER_TC=8,1,1,1,1,1,1,1

	#if you plan to run pktgen, please also increase the number of buffer pool available
	export DPBP_COUNT=16

   Run the following on the board:
      1. /usr/odp/scripts/dynamic_dpl.sh dpmac.1 dpmac.2 dpmac.3 dpmac.4
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

       # ./l2fwd -c 0x1 -n 1 -- -p 0x1 -q 1 -R
                        OR
       # ./l2fwd -c 0x3 -n 1 -- -p 0x3 -q 1 -R

       Now pump traffic from the Spirent to the enabled ports

5. Running DPDK L2FWD-CRYPTO Application
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

6. Running DPDK TEST application for Crypto tests
   Execute following commands to run DPDK test on LS2 board
       # ./test
   Execute following commands to run Crypto tests on RTE command line
       # RTE>>cryptodev_dpaa2_sec_autotest
	This is for functional verification of Encrypt+Hash Generate and then Decrypt+Hash Verify for AES-CBC-HMAC-SHA1. More test cases will be added in future.

       # RTE>>cryptodev_dpaa2_sec_perftest
	This is for taking performance numbers of Crypto operations.

7. Running DPDK L3FWD Application
   ==============================
   NOTE: enabled multiple tx queue i.e. TC support for the ports during restool config using dynamicdpl
   Execute following commands to run DPDK L2FWD on LS2 board

	./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)"
			OR
	./l3fwd -c 0x1 -n 1 -- -p 0x1 --config="(0,0,0)"
			OR
	./l3fwd -c 0xFF -n 1 -- -p 0x3 --config="(0,0,0),(0,1,1),(0,2,2),(0,3,3),(1,0,4),(1,1,5),(1,2,6),(1,3,7)"

./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)" --eth-dest=0,11:11:11:11:11:11 --eth-dest=1,00:00:00:11:11:11

       Now pump traffic from the Spirent to the enabled ports as per the given streams
Traffic to port 1: 1.1.1.0/24
Traffic to port 2: 2.1.1.0/24
Traffic to port 3: 3.1.1.0/24
Traffic to port 4: 4.1.1.0/24

8. Running DPDK KNI Application
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


===============================================================================
Building and Use PKTGEN with DPDK

 Get the code from:
git clone https://github.com/qoriq-open-source/pktgen-dpdk.git
#do the make install in DPDK.
source <DPDK Source DIR>/standalone_dpaa2
export RTE_SDK=<DPDK Source DIR>
make -j8 EXTRA_CFLAGS="-std=gnu99"

Note: you may need pcap library installed in your toolchain (compiled for ARM64)

Copy "Pktgen.lua" and "pktgen" (available at: app/app/arm64-dpaa2-linuxapp-gcc/pktgen) to the board.

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
Applications:
-	Able to run L2FWD, L3FWD, Kernel Network Interface (KNI) demo unmodified.

Features:
-	Support for LS2-BUS in DPDK VFIO support function
-	Addition of WRIOP-MC as a poll mode driver (pmd) in DPDK.
-	Able to run DPDK on single core and multiple cores.

NXP platform support:
-	The code is not optimized for the performance.

Code Location: stash
Branch: 16.07-qoriq
Tag:

DPDK base version used: Release 16.07-rc3
More info on DPDK :  www.dpdk.org

LS2 Release - EAR6 & SDK2.0
NXP contact: hemant.agrawal@nxp.com
