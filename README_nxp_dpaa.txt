===============================================================================
NXP DPDK README FOR LS-DPAA1 PLATFORM
===============================================================================

NXP DPDK provides a set of data plane libraries and network interface
controller driver for LS1 platforms.
This README provides information about building and executing DPDK based
applications for LS-DPAA1 platform

===============================================================================

Components for Build & Execution Environment
--------------------------------------------

To sucessfully build and execute DPDK based applications for LS1 platform, 
following components are required:

1. DPDK source code
2. Cross compiled toolchain for ARM64 platform
3. Linux kernel for LS1 platform
4. LS104x board

Following information can be used to obtain these components:

     DPDK code for LS1 platform
     ==========================
     Use following command to get the DPDK code

       # git clone ssh://git@sw-stash.freescale.net/gitam/dpdk.git
       # git checkout -b 16.07-qoriq remotes/origin/16.07-qoriq


     Linux kernel code for LS1 platform
     ==================================
     Use following command to get the linux code

       # install SDK released by NXP(previously freescale) for ls1043ardb
       # find the source for linux


     Cross compiled toolchain For ARM64
     ==================================
    get the linaro gcc-4.9 toolchain from:
https://releases.linaro.org/components/toolchain/binaries/4.9-2016.02/aarch64-linux-gnu/

set the CROSS_COMPILE path e.g
export CROSS_COMPILE=/opt/gcc-linaro-4.9-2016.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-

===============================================================================

How to Build DPDK Applications
------------------------------
1. Script "standalone-dpaa" is present in DPDK code. Open it and check the
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
		modify config/defconfig_arm64-dpaa-linuxapp-gcc
		CONFIG_RTE_LIBRTE_PMD_ARMCE=n

3. Execute following commands from Linux(Host) shell prompt for generating
   DPDK libraries, which are required for compiling DPDK examples and
   applications:

     0. compile libxml2.a and libz.a or copy these two libraries from SDK release
        into a folder, such as usdpaa_lib; set env XML_LIBZ_PATH to this folder in
	the below standalone-dpaa
     1. export KERNEL_PATH=<path to LS1043 Linux kernel code>
     2. export CROSS_COMPILE=/opt/gcc-linaro-aarch64-linux-gnu-4.9-2014.09_linux/bin/aarch64-linux-gnu-
     3. export OPENSSL_PATH=<path to OpenSSL library>
     4. source standalone-dpaa
     5. make install T=arm64-dpaa-linuxapp-gcc

4. Steps for compiling the DPDK examples
	The basic testpmd application is compiled by default. It should be available in build/app
	or install directory.
     1. Before executing following step, all the steps mentioned in point no. "4."
        above must have been executed. export the RTE_TARGET
	export RTE_TARGET=arm64-dpaa-linuxapp-gcc
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
1. Bring up the board with the LS1 images with proper kernel/usdpaa configurations
   in the dtb file.

2. Upload the dpdk applications binaries and below setup files to the LS1 board.
   the configuration files includes:
   3. usdpaa_config_ls1043.xml;    dpdk/ext
   4. usdpaa_policy_hash_ipv4_*queue.xml; dpdk/ext  #(* = 1/2/4)
	# mount hugetlb file system
   	if [ ! -d /mnt/hugetlbfs ]; then
	        mkdir /mnt/hugetlbfs
	fi

	echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	mount -t hugetlbfs nodev /mnt/hugetlbfs/

	#set config and policy file for fman
	#Use the respective policy file to support only the number of queues per
	#DPDK port which the application needs to run. You can select either
	#from 1 or 2 or 3 queue policy files.
	#Anyone of the below one policy file should be used along
	#with configuration file while running the fmc script based
	#on the number of queues to be used per port in the application.
	#1. ext/usdpaa_policy_hash_ipv4_1queue.xml
	#2. ext/usdpaa_policy_hash_ipv4_2queue.xml
	#3. ext/usdpaa_policy_hash_ipv4_4queue.xml

	fmc -c usdpaa_config_ls1043.xml -p usdpaa_policy_hash_ipv4_*queue.xml -a
		(* = 1/2/4)

   NOTE: fmc should be availabe in rootfs.

3. Running DPDK testpmd Application
   ============================== 

   Execute following commands to run DPDK testpmd on LS1 board

   #./testpmd -c 0xF -n 4 -- -i --portmask=0x3 --nb-cores=2 
   - you can change the number of cores.

   This would start the testpmd application in interactive mode, starting a
   shell for accepting further commands. For e.g:

   testpmd> show port info all

   Above command can be used to view all the ports which the framework has
   identified, with their detailed information.

4. Running DPDK L2FWD Application
   ============================== 

   Execute following commands to run DPDK L2FWD on LS1 board

       # ./l2fwd -c 0x1 -n 1 -- -p 0x1 -q 1
                        OR
       # ./l2fwd -c 0x3 -n 1 -- -p 0x3 -q 1

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
   Execute following commands to run DPDK L3FWD on LS1 board

	2Port => ./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)"
			OR
	1Port => ./l3fwd -c 0x1 -n 1 -- -p 0x1 --config="(0,0,0)"

	2Port with dest mac=> ./l3fwd -c 0xF -n 4 -- -p 0x3 -P --config="(0,0,0),(0,1,1),(1,0,2),(1,1,3)" --eth-dest=0,11:11:11:11:11:11 --eth-dest=1,00:00:00:11:11:11

	4Port=> ./l3fwd -c 0xf -n 4 -- -p 0xf -P --config="(0,0,0),(1,0,1),(2,0,2),(3,0,3)"
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
            # scp <user>@192.168.1.1:$(RTE_SDK)/arm64-dpaa-linuxapp-gcc/kmod/rte_kni.ko .


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
7. Running DPDK test Application for ARM-CE:

       1. To launch regression tests:
           # ./test
           RTE>>cryptodev_armce_autotest

       2. To launch performance/benchmark tests:
           # ./test
           RTE>>cryptodev_armce_perftest

===============================================================================
Building and Use PKTGEN with DPDK

 Get the code from: git://dpdk.org/apps/pktgen-dpdk
#do the make install in DPDK. 
source <DPDK Source DIR>/standalone_dpaa
export RTE_SDK=<DPDK Source DIR>
make

Note: you may need pcap library installed in your toolchain (compiled for ARM64)

Copy "Pktgen.lua" and "pktgen" (available at: app/app/arm64-dpaa-linuxapp-gcc/pktgen) to the board.

example Command to run: 

#3 port - 1 core each
./pktgen -l 0-3 -n 3 --proc-type auto --file-prefix pg --log-level 8 -- -T -P -m "[1].0, [2].1, [3].2"

#2 port - 2 core each
./pktgen -l 0-3 -n 3 --proc-type auto --file-prefix pg --log-level 8 -- -T -P -m "[0:1].0, [2:3].1"

#To start traffic on specific port:
start 0
stop 0

#To start on all ports
str
stp
=============================================================================
Applications:
-	Able to run L2FWD, L3FWD, Kernel Network Interface (KNI) demo unmodified. 

NXP platform support:
-	The code is not optimized for the performance. 

Code Location: stash
Branch: 16.07-qoriq
Tag:

DPDK base version used: Release 16.07
More info on DPDK :  www.dpdk.org

LS2 Release - SDK2.0
NXP contact: hemant.agrawal@nxp.com
