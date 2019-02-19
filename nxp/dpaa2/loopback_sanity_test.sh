#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2016-2019 NXP.
#

help() {
	echo
	echo "USAGE: . ./loopback_sanity_test.sh <options>
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
	. ./loopback_sanity_test.sh -a        OR     source ./loopback_sanity_test.sh -a

Options and Sanity script running behaviour:

	OPTIONS					SCRIPT BEHAVIOUR

	* Both -a and -c			If both options -a and -c are given, then script will
						run all the test cases automatically including Cunit
						test cases.

	* only -a				If only this option specified, then script will run
						all the DPDK example applications automatically and at the
						end an option will be given to the user which specify whether
						to test the Cunit or not. If user press 'y' then script will
						run all the Cunit test cases automatically also.



	* neither -c nor -a			If none of these options is there, then script will run in manual
						mode even for Cunit test cases.


Assumptions:
	* dynamic_dpl.sh and loopback_sanity_test.sh all these three scripts
	  are present in the 'usr/bin/dpdk-example/extras' directory.
	* All DPDK example binaries are present in the '/usr/local/bin/ or /usr/local/dpdk/dpaa2/' directory.
	* There are sufficient resources available to create two DPDK conatiners and 4 kernel interfaces.
	* There is sufficient memory to run two DPDK applications concurrently. Script is verified with
	  following bootargs:
	  (bootargs=console=ttyS1,115200 root=/dev/ram0 earlycon=uart8250,mmio,0x21c0600,115200
	   ramdisk_size=2000000 default_hugepagesz=1024m hugepagesz=1024m hugepages=8)
Note:	Minimum running time of script for all test cases is 30 mins.
	"

}

developer_help() {
	echo
	echo -e "\tDeveloper's Help:

	###############################################################################
	############ Sanity script will have following Resources ######################
	###############################################################################
	4 kernel interfaces and 1 containers will be created for the testing, having
	following number of DPNIs objects:

	KERNEL => NI1, NI2, NI3,NI4
	FDPRC => FDPNI0, FDPNI1, FDPNI2,FDPNI3


	These DPNIs will be connected as:


			      ===================================================
			     |   		FDPRC				|
			     |	     					       	|
			      ===================================================
				 FDPNI0  	|FDPNI1		|FDPNI2	     |FDPNI3
				 | 	 	|		|	     |
				 | 	 	|		|	     |
				 | 	 	|		|	     |
				 | 	 	|		|	     |
				 | 	 	|		|	     |
				 |NI1	 	|NI2		|NI3	     |NI4
				=================================================
				|   		kernel   			|
				|	     					|
				=================================================

	MAC addresses to these DPNIs will be as:

	NI1 = 02:00:00:00:00:00
	NI2 = 02:00:00:00:00:01
	NI3 = 02:00:00:00:00:02
	NI4 = 02:00:00:00:00:03

	FDPNI0 = 00:00:00:00:5:1
	FDPNI1 = 00:00:00:00:5:2
	FDPNI2 = 00:00:00:00:5:3
	FDPNI3 = 00:00:00:00:5:4


	Namespaces and kernel interfaces:

	* Interface NI1 will be in the default namespace having  IP address 1.1.1.10
	* Interface NI2 will be in sanity_port2 namespace having IP address 2.1.1.10
	* Interface NI3 will be in sanity_port3 namespace having IP address 3.1.1.10
	* Interface NI4 will be in sanity_port4 namespace having IP address 4.1.1.10

DPDK EXAMPLE APPLICATIONS: Method to add an DPDk example application as test case:

Test case command syntax:
	run_command <arguments ...>

Mandatory arguments:
	argument1	Test module	First argument should be Test Module, which is predefined
					Macro for each DPDK application as:
					PKT_TESTPMD	=> testpmd
					PKT_L2FWD  	=> l2fwd
					PKT_L3FWD	=> l3fwd

	argument2	command		Actual command to run.

Process of testing:
	* l2fwd:
		---- l2fwd application ping verification for 1,2 and 4port configuration .

	* l3fwd
		---- l3fwd application ping verification for 1,2 and 4port configuration .


Example:
	run_command PKT_l2FWD "./l2fwd -c 0x3 -n 1 -- -p 0x5 -q 1"

	All these commands should be added only in run_dpdk() function.


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

  #checking kernel interfaces are available or not.
        if [[ -z $NI1 || -z $NI2 || -z $NI3 || -z $NI4 ]]
        then
                return 1;
        fi

        #checking sanity script containers
        if [[ -z $FDPRC || -z $FDPNI0 || -z $FDPNI1 || -z $FDPNI2 ||  -z $FDPNI3 ]]
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
		NI1=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI1=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi

        if [[ -z $KDPNI2 ]]
        then
		ls-addni -n | tee linux_iflog
		export NI2=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI2=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi

        if [[ -z $KDPNI3 ]]
        then
		ls-addni -n | tee linux_iflog
		export NI3=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI3=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi

        if [[ -z $KDPNI4 ]]
        then
		ls-addni -n | tee linux_iflog
		export NI4=`grep -o "interface: eth\w*" linux_iflog | sed -e 's/interface: //g'`
		export KDPNI4=`grep -o "object:dpni.\w*" linux_iflog | sed -e 's/object://g'`
	fi
	rm linux_iflog

	#/* creating the container "FDPRC" with 4 DPNIs connected to kernel DPNIs
	# */
#	DPCON_COUNT=3
#	DPSEC_COUNT=4
#	DPDMAI_COUNT=0
#	DPBP_COUNT=4
#	DPIO_COUNT=4
#	DPCI_COUNT=2
	source ${DPDK_EXTRAS_PATH}/dynamic_dpl.sh $KDPNI1 $KDPNI2 $KDPNI3 $KDPNI4 -b 00:00:00:00:05:00
	FDPRC=$DPRC
	FDPNI0=$DPNI1
	FDPNI1=$DPNI2
	FDPNI2=$DPNI3
	FDPNI3=$DPNI4

	sleep 5
}


# Function to print results of the most of test cases.
print_result_pkt() {
	echo "Received $1 packets"
	if [[ "$1" == "$2" ]]
	then
		echo -e $GREEN "\tno packet loss"$NC
		echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
		passed=`expr $passed + 1`
	elif [[ "$1" -lt "$2" ]]
	then
		echo -e $RED "\t$((1-2))"" packets loss"$NC
		echo -e "\t""$1"" packets loss  ----- FAILED" >> sanity_tested_apps
		failed=`expr $failed + 1`
	elif [[ -z "$1" ]]
	then
		echo -e $RED "\tUnable to capture Results"$NC
		echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
		na=`expr $na + 1`
	else
		echo -e $GREEN "\t"" All packets received"$NC
		echo -e "\t""$1""All packets rcvd  ----- PARTIAL PASSED" >> sanity_tested_apps
		partial=`expr $partial + 1`
	fi
}


print_result() {
	if [[ "$1" == "0%" ]]
	then
		echo -e $GREEN "\tno packet loss"$NC
		echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
		passed=`expr $passed + 1`
	elif [[ "$1" == "100%" ]]
	then
		echo -e $RED "\t$1"" packets loss"$NC
		echo -e "\t""$1"" packets loss  ----- FAILED" >> sanity_tested_apps
		failed=`expr $failed + 1`
	elif [[ -z "$1" ]]
	then
		echo -e $RED "\tUnable to capture Results"$NC
		echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
		na=`expr $na + 1`
	else
		echo -e $RED "\t$1"" packets loss"$NC
		echo -e "\t""$1"" packets loss  ----- PARTIAL PASSED" >> sanity_tested_apps
		partial=`expr $partial + 1`
	fi
}


#/* Function to run the DPDK Testpmd test cases*/
run_pkt_testpmd() {
echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo
	tcpdump -nt -i $NI1 >> log3 &
	ip netns exec sanity_ns tcpdump -nt -i $NI2 | tee log1 &
	timeout -k 9 9 $2
	#eval "$2 >> sanity_log 2>&1 &"
	echo
	sleep 5
	append_newline 3
	#ip netns exec sanity_ns tcpdump -nt -i $NI2 | tee log1 &
	sleep 6
	append_newline 3
	echo " Starting the ping test ..."
	#tcpdump -nt -i $NI | tee log3 &
	#ping 192.168.111.1 -c $ping_packets | tee log
	sleep 2
	#ip netns exec sanity_ns killall tcpdump
	#killall tcpdump
	#RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	#RESULT=`grep -c "IP 192.168.111.2 > 192.168.111.1: ICMP echo request" log1`
	echo
	cat log >> sanity_log
	print_result "$RESULT" "$ping_packets"
	pid=`ps | pgrep testpmd`
	if [[ -z "$pid" ]]
	then
		pid=`ps | pgrep testpmd`
	fi
	kill -2 $pid
	append_newline 5
	rm log
	rm log1
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
#/* Function to run the DPDK L2fwd test cases*/
run_pkt_l2fwd() {
echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2)  \t\tUsecase:($3) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) \t\tUsecase:($3) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) \t\tUsecase:($3) " >> sanity_tested_apps
	append_newline 1
	echo
	eval "$2 >> sanity_log 2>&1 &"
	echo
	sleep 5
	append_newline 3

	if [[ "$3" == "1PORT" ]]
	then
	    if [ -f log3 ] ; then
		rm log3
		fi

	    tcpdump -nt -i $NI1 >> log3 &
		sleep 5

		ping -f 1.1.1.1 -c $ping_packets -s $pkt_size | tee log
                sleep 20
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		killall tcpdump
                sleep 5
		RESULT=`grep -c "IP 1.1.1.10 > 1.1.1.1: ICMP echo request" log3`
		RESULT1=`expr $RESULT - $ping_packets `

		print_result_pkt $RESULT1 $ping_packets

		cat log >> sanity_log
		ifconfig $NI1 >> sanity_log

	elif [[ "$3" == "2PORT" ]]
	then
		ping -f 2.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port2 ping -f 1.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

	elif [[ "$3" == "4PORT" ]]
	then

		ping -f 2.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port2 ping -f 1.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

		append_newline 3


		ip netns exec sanity_port3 ping -f 4.1.1.10 -c $ping_packets -s $pkt_size | tee log

		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port4 ping -f 3.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

	else
		echo -e $RED "\t$3"" Wrong No of Port Configure"
		echo -e "\t""$3"" Wrong No of Port Configure" >> sanity_tested_apps

	fi

	killall l2fwd
	sleep 10
	append_newline 5
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

#/* Function to run the DPDK L3fwd test cases*/
run_pkt_l3fwd() {
echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2)  \t\tUsecase:($3) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) \t\tUsecase:($3) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) \t\tUsecase:($3) " >> sanity_tested_apps
	append_newline 1
	echo
	eval "$2 >> sanity_log 2>&1 &"
	echo
	sleep 5
	append_newline 3
	if [[ "$3" == "1PORT" ]]
	then
	    if [ -f log3 ] ; then
		rm log3
		fi


	        tcpdump -nt -i $NI1 >> log3 &
		sleep 5

                ping -f 1.1.1.1 -c $ping_packets -s $pkt_size | tee log
                sleep 20
                RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
                killall tcpdump
                sleep 5
                RESULT=`grep -c "IP 1.1.1.10 > 1.1.1.1: ICMP echo request" log3`
                RESULT1=`expr $RESULT - $ping_packets `

		print_result_pkt $RESULT1 $ping_packets

		cat log >> sanity_log
		ifconfig $NI1 >> sanity_log

	elif [[ "$3" == "2PORT" ]]
	then
		ping -f 2.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port2 ping -f 1.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

	elif [[ "$3" == "4PORT" ]]
	then

		ping -f 2.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port2 ping -f 1.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

		append_newline 3


		ip netns exec sanity_port3 ping -f 4.1.1.10 -c $ping_packets -s $pkt_size | tee log

		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"
		sleep 5
		cat log >> sanity_log
		append_newline 3
		ip netns exec sanity_port4 ping -f 3.1.1.10 -c $ping_packets -s $pkt_size | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		print_result "$RESULT"

	else
		echo -e $RED "\t$3"" Wrong No of Port Configure"
		echo -e "\t""$3"" Wrong No of Port Configure" >> sanity_tested_apps

	fi

	killall l3fwd
	sleep 10
	append_newline 5

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
	PKT_TESTPMD )
		run_pkt_testpmd $1 "$2"
		;;
	PKT_l2FWD )
		run_pkt_l2fwd $1 "$2" "$3"
		;;
	PKT_l3FWD )
		run_pkt_l3fwd $1 "$2" "$3"
		;;
	*)
		echo "Invalid test case $1"
esac
}

#function to run DPDK example applications
run_dpdk() {

	#/* DPDK L2FWD App
	# */
	run_command PKT_l2FWD "./l2fwd -c 0xf -n 1 -- -p 0x1 -q 1  --mac-updating"  "1PORT"
	run_command PKT_l2FWD "./l2fwd -c 0xf -n 1 -- -p 0x3 -q 1  --mac-updating"  "2PORT"
	run_command PKT_l2FWD "./l2fwd -c 0xf -n 1 -- -p 0xf -q 1  --mac-updating"  "4PORT"

	#/* DPDK L3FWD App
	# */
	run_command PKT_l3FWD './l3fwd -c 0xFF -n 1 -- -p 0x1 --config="(0,0,0)"  -P'  "1PORT"
	run_command PKT_l3FWD './l3fwd -c 0xFF -n 1 -- -p 0x3 --config="(0,0,0),(0,1,1),(0,2,2),(0,3,3),(1,0,4),(1,1,5),(1,2,6),(1,3,7)"  -P'  "2PORT"
	run_command PKT_l3FWD './l3fwd -c 0xFF -n 1 -- -p 0x3 --config="(0,0,0),(0,1,1),(0,2,2),(0,3,3),(0,4,4),(0,5,5),(0,6,6),(0,7,7),(1,0,0),(1,1,1),(1,2,2),(1,3,3),(1,4,4),(1,5,5),(1,6,6),(1,7,7)"  -P'  "2PORT"
	run_command PKT_l3FWD './l3fwd -c 0xFF -n 1 -- -p 0xf --config="(0,0,1),(1,0,2),(2,0,3),(3,0,4),(0,1,5),(1,1,6),(2,1,7),(3,1,0)"  -P'  "4PORT"


	#/* DPDK TESTPMD App
	# */
	#run_command PKT_TESTPMD "./testpmd -c 3 -n 1 -- -i --nb-cores=1 --nb-ports=4 --total-num-mbufs=1025 --forward-mode=txonly --port-topology=chained --no-flush-rx -a"

}

#/* configuring the interfaces*/

configure_ethif() {

	ifconfig $NI1 1.1.1.10
	ifconfig $NI1 hw ether 02:00:00:00:00:00
	ip route add 2.1.1.0/24 via 1.1.1.1
	arp -s 1.1.1.1 000000000501

	ip netns add sanity_port2
	ip link set $NI2 netns sanity_port2
	ip netns exec sanity_port2 ifconfig $NI2 2.1.1.10
	ip netns exec sanity_port2 ifconfig $NI2 hw ether 02:00:00:00:00:01
	ip netns exec sanity_port2 ip route add 1.1.1.0/24 via 2.1.1.1
	ip netns exec sanity_port2 arp -s 2.1.1.1 000000000502

	ip netns add sanity_port3
	ip link set $NI3 netns sanity_port3
	ip netns exec sanity_port3 ifconfig $NI3 3.1.1.10
	ip netns exec sanity_port3 ifconfig $NI3 hw ether 02:00:00:00:00:02
	ip netns exec sanity_port3 ip route add 4.1.1.0/24 via 3.1.1.1
	ip netns exec sanity_port3 arp -s 3.1.1.1 000000000503

	ip netns add sanity_port4
	ip link set $NI4 netns sanity_port4
	ip netns exec sanity_port4 ifconfig $NI4 4.1.1.10
	ip netns exec sanity_port4 ifconfig $NI4 hw ether 02:00:00:00:00:03
	ip netns exec sanity_port4 ip route add 3.1.1.0/24 via 4.1.1.1
	ip netns exec sanity_port4 arp -s 4.1.1.1 000000000504


	cd ${DPDK_EXAMPLE_PATH}
	echo
	echo
	echo


}

unconfigure_ethif() {

	ip netns del sanity_port2
	ip netns del sanity_port3
	ip netns del sanity_port4
	ifconfig $NI1 down
	source ${DPDK_EXTRAS_PATH}/destroy_dynamic_dpl.sh $FDPRC

	cd -
}

main() {

	export DPRC=$FDPRC
	if [ ! -v ALL_TEST ]
	then
		echo "############################################## TEST CASES ###############################################" >> sanity_tested_apps
		echo >> sanity_tested_apps
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
ping_packets=1000
pkt_size=64
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

get_resources
fi
configure_ethif
main

set +m
