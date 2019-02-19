#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2016-2020 NXP.
#

help() {
	echo
	echo "USAGE: . ./loopback_l2fwd_crypto.sh <options>
The Options are:
	-a		Auto mode		Enabling the Auto mode. Default is manual
						mode.

	-p=\"num\"	Ping packets numbers	'num' is number of ping packets which will be used
						for sanity testing. Default is 10.

	-d		Developer help		This option is only for developers. It will
						print the help for developers, which describes
						how to add a test case in the script.

	-h		Help			Prints script help.

Example:
	source ./loopback_l2fwd-crypto.sh -a

Options and Sanity script running behaviour:

	OPTIONS					SCRIPT BEHAVIOUR



	* only -a				If only this option specified, then script will run
						all the DPDK example applications automatically and at the
						end an option will be given to the user which specify whether
						to test the Cunit or not. If user press 'y' then script will
						run all the Cunit test cases automatically also.



	* without any option  If none of these options is there, then script will run in manual
						mode and user input  'y' require for procedding testcase one by one


Assumptions:
	* dynamic_dpl.sh, destroy_dynamic_dpl.sh and loopback_sanity_test.sh all these three scripts are present in the 'usr/local/dpdk/dpaa2/' directory.
	* All DPDK example binaries are present in the '/usr/local/bin/ or /usr/local/dpdk/dpaa2/' directory.
	* There are sufficient resources available to create two DPDK conatiners and 2 kernel interfaces.
	* There is sufficient memory to run two DPDK applications concurrently. Script is verified with following bootargs:
	  (bootargs=console=ttyS1,115200 root=/dev/ram0 earlycon=uart8250,mmio,0x21c0600,115200 ramdisk_size=2000000 default_hugepagesz=1024m hugepagesz=1024m hugepages=8)

Note: Minimum running time of script for all test cases is 30 mins.
"
}

developer_help() {
	echo
	echo -e "\tDeveloper's Help:

	###############################################################################
	############ Sanity script will have following Resources ######################
	###############################################################################
	2 kernel interfaces and 2 containers will be created for the testing, having
	following number of DPNIs objects:

	KERNEL => NI1, NI2
	FDPRC => FDPNI0, FDPNI1
	SDPRC => SDPNI0, SDPNI1

	These DPNIs will be connected as:
		______________________________________________
		| FDPNI1					| SDPNI1
		==================		===================
		|	FDPRC		|	|	SDPRC		|
		|			|	|			|
		==================		===================
		|FDPNI0						|SDPNI0
		|						|
		|						|
		|						|
		|NI1						|NI2
		============================================
		|			kernel				|
		|							|
		============================================

	MAC addresses to these DPNIs will be as:

	NI1 = 00:16:3e:7e:94:9a
	NI2 = 00:16:3e:7e:94:9a

	FDPNI0 = 00:00:00:00:5:1
	FDPNI1 = 00:00:00:00:5:2

	SDPNI0 = 00:00:00:00:6:1
	SDPNI1 = 00:00:00:00:6:2

	Namespaces and kernel interfaces:

	* Interface NI1 will be in the default namespace having IP address 192.168.101.1
	* Interface NI2 will be in sanity_port2 namespace having IP address 192.168.1.1

DPDK EXAMPLE APPLICATIONS: Method to add an DPDk example application as test case:

Test case command syntax:
	run_command <arguments ...>

Mandatory arguments:
	argument1	Test module	First argument should be Test Module, which is predefined
					Macro for each DPDK application as:
					PKT_IPSEC_SECGW	=> ipsec-secgw

	argument2	command		Actual command to run.

Process of testing:
	* l2fwd-crypto:
		---- two instances of l2fwd-crypto, one in ENCRYPT/GENERATE and other in DECRYPT/VERIFY.
		---- ping from 192.168.101.1 to 192.168.1.1. If ping request reaches other end successfully, test is PASSED. else FAILED.

Example:
	run_command PKT_L2FWD_CRYPTO_CIPHER_ONLY_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask'

All these commands should be added only in run_dpdk function.

Note:
* For OPENSSL test, l2fwd-crypto application should be compiled by openssl.
"
}

#/* Function to append new lines into sanity_log file*/
append_newline() {
	num=0
	while [[ $num -lt $1 ]]
	do
		echo >> sanity_log
		num=`expr $num + 1`
	done
}

#Checking if resources are already available
check_resources () {

	if [[ -z $NI1 || -z $NI2 ]]
	then
		return 1;
	fi

	#checking sanity script containers
	if [[ -z $FDPRC || -z $FDPNI0 || -z $FDPNI1 ]]
	then
		return 1;
	fi
	if [[ -z $SDPRC || -z $SDPNI0 || -z $SDPNI1 ]]
	then
		return 1;
	fi

	return 0;

}

#creating the required resources
get_resources() {

	#/*Creating the required linux interfaces and connecting them to the required DPNIs*/
	if [[ -z $KDPNI1 ]]
	then
		ls-addni -n | tee linux_iflog
		export NI1=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI1=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi

	if [[ -z $KDPNI2 ]]
	then
		ls-addni -n | tee linux_iflog
		export NI2=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI2=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi

	rm linux_iflog

	#/*
	# * creating the container "FDPRC" with 3 DPNIs which will not be connected to
	# * any object.
	# */
	export DPIO_COUNT=10;
	source ${DPDK_EXTRAS_PATH}/dynamic_dpl.sh $KDPNI1 dpni
	FDPRC=$DPRC
	FDPNI0=$DPNI1
	FDPNI1=$DPNI2
	#/*
	# * creating the 2nd container "SDPRC" with 2 DPNIs in which one will be connected to
	# * the first DPNI of first conatiner and 2nd DPNI will remain unconnected.
	# */
	sleep 5
	source ${DPDK_EXTRAS_PATH}/dynamic_dpl.sh $KDPNI2 $FDPNI1 -b 00:00:00:00:06:00
	SDPRC=$DPRC
	SDPNI0=$DPNI1
	SDPNI1=$DPNI2
	#/*Creating the required linux interfaces and connecting them to the reaquired DPNIs*/
	sleep 5
}

# Function to print results of the most of test cases.
print_result() {
	if [[ -z "$1" ]]
	then
		echo -e $RED "\tUnable to capture Results"$NC
		echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
		SEMI_TEST_UNKNOWN_RESULTS=`expr $SEMI_TEST_UNKNOWN_RESULTS + 1`
	elif [[ "$1" -lt "0" ]]
	then
		echo -e $RED "\t$2"" packet loss"$NC
		echo -e "\t packet-size "$2"Bytes\t""$2"" packet loss  ----- FAILED" >> sanity_tested_apps
		SEMI_TEST_FAILED=`expr $SEMI_TEST_FAILED + 1`
	else
		echo -e $GREEN "\t$1"" packet loss"$NC
		echo -e "\t packet-size "$2"Bytes\t""$1"" packet loss  ----- PASSED" >> sanity_tested_apps
		SEMI_TEST_PASSED=`expr $SEMI_TEST_PASSED + 1`
	fi
}

#/* Function to run the DPDK l2fwd crypto  test cases*/
run_l2fwd_crypto() {
echo -e " #$test_no)\tTest case:$1  \n  \t\tCommand:($2)  \n \t\tCommand:($3)"
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\t$1\t\tcommand ($3) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1  \n  \t\tCommand:($2)  \n \t\tCommand:($3) " >> sanity_tested_apps
	append_newline 1
	echo
	export DPRC=$FDPRC
	eval "nohup $2 >> sanity_log 2>&1 &"

	sleep 5
	export DPRC=$SDPRC
	eval "nohup $3 >> sanity_log 3>&1 &"

	echo
	sleep 10
	append_newline 3

	TOTAL_SEMI_TEST=`echo "$pkt_list" | wc -w`
	SEMI_TEST_PASSED=0
	SEMI_TEST_FAILED=0
	SEMI_TEST_UNKNOWN_RESULTS=0
        for pkt_size in $pkt_list
        do
		if [ -f sanity_log_2 ] ; then
			rm sanity_log_2
		fi

		ip netns exec sanity_port2 tcpdump -nt -v -i $NI2 >> sanity_log_2 &
                sleep 5
		echo " Starting the ping test ..."
		echo " Sending $ping_packets Packets and size of each packet is $pkt_size "
                ping 192.168.1.1 -i 0.001 -c $ping_packets -s $pkt_size | tee log
		sleep 20
		killall tcpdump
		RESULT=`grep -c "192.168.101.1 > 192.168.1.1: ICMP echo request" sanity_log_2`
		RESULT2=`expr $RESULT - $ping_packets `
		print_result $RESULT2 $ping_packets
		cat log >> sanity_log
		ifconfig $NI1 >> sanity_log
        done

	if [ $SEMI_TEST_PASSED -eq $TOTAL_SEMI_TEST ] ; then
		passed=`expr $passed + 1`
	elif [ $SEMI_TEST_PASSED -gt 0 ] ; then
		partial=`expr $partial + 1`
	elif [ $SEMI_TEST_UNKNOWN_RESULTS -eq $TOTAL_SEMI_TEST ] ; then
		na=`expr $na + 1`
	else
		failed=`expr $failed + 1`
	fi

	killall l2fwd-crypto
	sleep 10
	append_newline 5
	rm sanity_log_2
	rm log
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}

#/* Common function to run all test cases*/
run_command() {
case $1 in
	PKT_L2FWD_CRYPTO_CIPHER_ONLY_HW )
		run_l2fwd_crypto $1 "$2" "$3"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_ONLY_OPENSSL )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_ONLY_HW_OPENSSL )
		run_l2fwd_crypto $1 "$2" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_ONLY_OPENSSL_HW )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3"
		;;
	PKT_L2FWD_CRYPTO_HASH_ONLY_HW )
		run_l2fwd_crypto $1 "$2" "$3"
		;;
	PKT_L2FWD_CRYPTO_HASH_ONLY_OPENSSL )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_HASH_ONLY_HW_OPENSSL )
		run_l2fwd_crypto $1 "$2" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_HASH_ONLY_OPENSSL_HW )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_HASH_HW )
		run_l2fwd_crypto $1 "$2" "$3"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_HASH_OPENSSL )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_HASH_HW_OPENSSL )
		run_l2fwd_crypto $1 "$2" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_CIPHER_HASH_OPENSSL_HW )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3"
		;;
	PKT_L2FWD_CRYPTO_AEAD_HW )
		run_l2fwd_crypto $1 "$2" "$3"
		;;
	PKT_L2FWD_CRYPTO_AEAD_OPENSSL )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_AEAD_HW_OPENSSL )
		run_l2fwd_crypto $1 "$2" "$3 $crypto_dev_mask"
		;;
	PKT_L2FWD_CRYPTO_AEAD_OPENSSL_HW )
		run_l2fwd_crypto $1 "$2 $crypto_dev_mask" "$3"
		;;
	*)
		echo "Invalid test case $1"
esac
}

#function to run DPDK example applications
run_dpdk() {

	run_command PKT_L2FWD_CRYPTO_CIPHER_ONLY_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f'
	run_command PKT_L2FWD_CRYPTO_CIPHER_ONLY_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_CIPHER_ONLY_HW_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_CIPHER_ONLY_OPENSSL_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_ONLY --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f'
	run_command PKT_L2FWD_CRYPTO_HASH_ONLY_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
	run_command PKT_L2FWD_CRYPTO_HASH_ONLY_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_HASH_ONLY_HW_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_HASH_ONLY_OPENSSL_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_ONLY --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
	run_command PKT_L2FWD_CRYPTO_CIPHER_HASH_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_HASH --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_CIPHER --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
	run_command PKT_L2FWD_CRYPTO_CIPHER_HASH_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_HASH --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_CIPHER --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_CIPHER_HASH_HW_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain CIPHER_HASH --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain HASH_CIPHER --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_CIPHER_HASH_OPENSSL_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain CIPHER_HASH --cipher_algo aes-cbc --cipher_op ENCRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op GENERATE --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain HASH_CIPHER --cipher_algo aes-cbc --cipher_op DECRYPT --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --auth_algo sha1-hmac --auth_op VERIFY --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
	run_command PKT_L2FWD_CRYPTO_AEAD_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op ENCRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op DECRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f'
	run_command PKT_L2FWD_CRYPTO_AEAD_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op ENCRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op DECRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_AEAD_HW_OPENSSL './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain AEAD  --aead_algo aes-gcm --aead_op ENCRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op DECRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask'
	run_command PKT_L2FWD_CRYPTO_AEAD_OPENSSL_HW './l2fwd-crypto -c 0xf -n 1 --file-prefix=p1 --socket-mem=1024 --vdev "crypto_openssl0" --vdev "crypto_openssl1" -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op ENCRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f --cryptodev_mask' './l2fwd-crypto -c 0xf -n 1 --file-prefix=p2 --socket-mem=1024 -- --no-mac-updating -p 0x3 --chain AEAD --aead_algo aes-gcm --aead_op DECRYPT --aead_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f'
}

#/* configuring the interfaces*/
configure_ethif() {

	ifconfig $NI1 192.168.101.1
	ifconfig $NI1 hw ether 00:16:3e:7e:94:9a
	ip route add 192.168.1.0/24 via 192.168.101.2
	arp -s 192.168.101.2 00:00:00:00:00:10

	ip netns add sanity_port2
	ip link set $NI2 netns sanity_port2
	ip netns exec sanity_port2 ifconfig $NI2 192.168.1.1
	ip netns exec sanity_port2 ifconfig $NI2 hw ether 00:16:3e:7e:94:9a
	ip netns exec sanity_port2 ip route add 192.168.101.0/24 via 192.168.1.2
	ip netns exec sanity_port2 arp -s 192.168.1.2 00:00:00:00:00:20

	cd ${DPDK_EXAMPLE_PATH}
	echo
	echo
	echo
}

unconfigure_ethif() {

	ip netns del sanity_port2
	ifconfig $NI1 down
	source ${DPDK_EXTRAS_PATH}/destroy_dynamic_dpl.sh $FDPRC
	source ${DPDK_EXTRAS_PATH}/destroy_dynamic_dpl.sh $SDPRC

	cd -
}

main() {

	export DPRC=$FDPRC
	if [ ! -v ALL_TEST ]
	then
		echo "############################################## TEST CASES ###############################################" >> sanity_tested_apps
		echo >> sanity_tested_apps
	fi

	if [[ $board_type == "2160" ]]
	then
		crypto_dev_mask=0x30000
	elif [[ $board_type == "2088" ]]
	then
		crypto_dev_mask=0x300
	fi

	run_dpdk

	unconfigure_ethif

	if [ ! -v ALL_TEST ]
	then
		echo "############################################## TEST REPORT ################################################" >> result
		echo >> result
		echo >> result
		echo -e "\tDPDK EXAMPLE APPLICATIONS:" >> result
		echo >> result
		echo -e "\tNo. of passed DPDK examples test cases                \t\t= $passed" >> result
		echo -e "\tNo. of failed DPDK examples test cases                \t\t= $failed" >> result
		echo -e "\tNo. of partial passed DPDK examples test cases        \t\t= $partial" >> result
		echo -e "\tNo. of DPDK examples test cases with unknown results  \t\t= $na" >> result
		echo -e "\tNo. of untested DPDK example test cases              \t\t= $not_tested" >> result
		echo -e "\tTotal number of DPDK example test cases	              \t\t= `expr $test_no - 1`" >> result
		echo >> result
		mv ${DPDK_EXAMPLE_PATH}/sanity_log ${DPDK_SANITY_RESULT}/sanity_log
		mv ${DPDK_EXAMPLE_PATH}/sanity_tested_apps ${DPDK_SANITY_RESULT}/sanity_tested_apps
		if [[ -e "${DPDK_EXAMPLE_PATH}/sanity_untested_apps " ]]
		then
			mv ${DPDK_EXAMPLE_PATH}/sanity_untested_apps ${DPDK_SANITY_RESULT}/sanity_untested_apps
		fi
		echo
		cat result
		echo
		echo >> result
		echo -e "NOTE:  Test results are based on applications logs, If there is change in any application log, results may go wrong.
	\tSo it is always better to see console log and sanity_log to verify the results." >> result
		echo >> result
		cat result > ${DPDK_SANITY_RESULT}/sanity_test_report
		rm result
		echo
		echo
		echo -e " COMPLETE LOG			=> $GREEN${DPDK_SANITY_RESULT}/sanity_log $NC"
		echo
		echo -e " SANITY TESTED APPS REPORT	=> "$GREEN"${DPDK_SANITY_RESULT}/sanity_tested_apps"$NC
		echo
		echo -e " SANITY UNTESTED APPS		=> "$GREEN"${DPDK_SANITY_RESULT}/sanity_untested_apps"$NC
		echo
		echo -e " SANITY REPORT			=> "$GREEN"${DPDK_SANITY_RESULT}/sanity_test_report"$NC
		echo
		echo " Sanity testing is Done."
		echo

	fi
}

# script's starting point

if [ -v DPDK_EXTRAS_PATH ] && [ -v DPDK_EXAMPLE_PATH ]; then
	echo "dpdk extras path $DPDK_EXTRAS_PATH"
	echo "dpdk example app path $DPDK_EXAMPLE_PATH"
elif [ -d "/usr/bin/dpdk-example/extras/dpaa2" ]; then
	export DPDK_EXTRAS_PATH=/usr/bin/dpdk-example/extras/dpaa2
	export DPDK_EXAMPLE_PATH=/usr/bin/dpdk-example
	echo "dpdk script path on SDK  $DPDK_EXTRAS_PATH"
elif [ -d "/usr/local/dpdk/dpaa2" ];then
	export DPDK_EXTRAS_PATH=/usr/local/dpdk/dpaa2
	export DPDK_EXAMPLE_PATH=/usr/local/bin
	echo "dpdk script path on flexbuild $DPDK_EXTRAS_PATH"
else
	echo "DPDK script folder does not exists...."
	exit
fi

export DPDK_SANITY_RESULT=$(pwd)
echo "Result path is $DPDK_SANITY_RESULT"

set -m
ping_packets=320
pkt_list="64 380 1410"
if [ ! -v ALL_TEST ]
then
	test_no=1
	not_tested=0
	passed=0
	failed=0
	partial=0
fi
na=0
input=

#/*
# * Parsing the arguments.
# */
if [[ $1 ]]
then
	for i in "$@"
	do
		case $i in
			-h)
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-d)
				developer_help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-p=*)
				ping_packets="${i#*=}"
				;;
			-a)
				PRINT_MSG=
				READ=
				input=y
				;;

			*)
				echo "Invalid option $i"
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
		esac
	done
fi

if [[ $input != "y" ]]
then
	PRINT_MSG="echo -e \"\tEnter 'y' to execute the test case\""
	READ="read input"
fi

if [[ -e "${DPDK_SANITY_RESULT}/sanity_log" ]]
then
	rm ${DPDK_SANITY_RESULT}/sanity_log
fi

if [[ -e "${DPDK_SANITY_RESULT}/sanity_tested_apps" ]]
then
	rm ${DPDK_SANITY_RESULT}/sanity_tested_apps
fi

if [[ -e "${DPDK_SANITY_RESULT}/sanity_untested_apps" ]]
then
	rm ${DPDK_SANITY_RESULT}/sanity_untested_apps
fi

if [[ -e "${DPDK_SANITY_RESULT}/sanity_test_report" ]]
then
	rm ${DPDK_SANITY_RESULT}/sanity_test_report
fi

#/* Variables represent colors */
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_resources
RET=$?

if [[ $RET == 1 ]]
then
	get_resources
else
	source ${DPDK_EXTRAS_PATH}/destroy_dynamic_dpl.sh $FDPRC
	source ${DPDK_EXTRAS_PATH}/destroy_dynamic_dpl.sh $SDPRC
	get_resources
fi

configure_ethif
x=101
y=1
main

set +m
