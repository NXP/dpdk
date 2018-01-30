#!/usr/bin/env bash

cat > script_help << EOF


script help :----->

	Run this script as
	". ./dynamic_dpl.sh dpmac.1 dpmac.2 -b ab:cd:ef:gh:ij:kl dpni-dpni dpni-self..."

	Acceptable arguments are dpni-dpni, dpni-self, dpmac.x and -b

    -b [optional] = Specify the MAC base address and must be followed by
		    a valid MAC base address. If this option is there in
		    command line then MAC addresses to DPNIs will be given as:

		    Base address = ab:cd:ef:gh:ij:kl
				 + 00:00:00:00:00:0I
		                  -------------------
				   Actual MAC address

		    where I is the index of the argument

	dpni-dpni = This specify that 2 DPNIs object will be created,
		    which will be connected back to back.
		    dpni.x <-------connected----->dpni.y

		    If -b option is not given then MAC addresses will be like:

		    dpni.x = 00:00:00:00:02:I
		    dpni.y = 00:00:00:00:03:I
		    where I is the index of the argument "dpni-dpni".

	dpni-self = This specify that 1 DPNI object will be created,
		    which will be connected to itself.
		    dpni.x <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:04:I
		    where I is the index of the argument "dpni-self".

	     dpni = This specify that 1 DPNI object will be created,
		    which will be unconnect.
		    dpni.x ------------- UNCONNECTED

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:05:I
		    where I is the index of the argument "dpni".

	   dpni.x = This specify that 1 DPNI (dpni.y) object will be created,
		    which will be connected to dpni.x
		    dpni.y <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:06:I
		    where I is the index of the argument "dpni.y".

	  dpmac.x = This specify that 1 DPNI  (dpni.y) object will be created,
		    which will be connected to dpmac.x.
		    dpmac.x <-------connected----->dpni.y

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:00:x
		    where x is the ID of the dpmac.x

	By default, this script will create 16 DPBP, 10 DPIOs, 2 DPCIs, 8 DPCON, 8 DPSEC
	device and DPNIs depend upon the arguments given during command line.

	Note: Please refer to dynamic_dpl_logs file for script logs

     Optional configuration parameters:

	Below "ENVIRONMENT VARIABLES" are exported to get user defined
	configuration"
	/**DPNI**:-->
		MAX_QUEUES         = max number of Rx/Tx Queues on DPNI.
					Set the parameter using below command:
					'export MAX_QUEUES=<Number of Queues>'
					where "Number of Queues" is an integer
					value "e.g export MAX_QUEUES=8"

		MAX_TCS             = maximum traffic classes for Rx/Tx both.
					Set the parameter using below command:
					'export MAX_TCS=<Num of traffic class>'
					where "Number of traffic classes" is an
					integer value. "e.g export MAX_TCS=8"

		MAX_QOS             = maximum QoS Entries.
					Set the parameter using below command:
					'export MAX_QOS=<Num of QoS entries>'
					where "Number of QoS entries" is an
					integer value. "e.g export MAX_QOS=1"
					Default is set to 1.

		DPNI_NORMAL_BUF    = Change the mode to use normal buf mode.
					The default mode is high performance buffer mode.
					However there are limitation w.r.t total outstanding packets
					in queue with that mode (i.e. ~10K)
					So, it may be desired to disable the high performance mode.

		DPNI_OPTIONS        = DPNI related options.
					Set the parameter using below command:
					'export DPNI_OPTIONS="opt-1,opt-2,..."'
					e.g export DPNI_OPTIONS="DPNI_OPT_TX_FRM_RELEASE,DPNI_OPT_HAS_KEY_MASKING"

	/**DPCON**:-->
		DPCON_COUNT	    = DPCONC objects count
					Set the parameter using below command:
					'export DPCON_COUNT=<Num of dpconc objects>'
					where "Number of dpconc objects" is an
					integer value and greater than 2.
					e.g export DPCON_COUNT=10"

		DPCON_PRIORITIES    = number of priorities 1-8.
					Set the parameter using below command:
					'export DPCON_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					e.g export DPCON_PRIORITIES=8."


	/**DPSECI**:-->
		DPSECI_COUNT        = DPSECI objects count
					Set the parameter using below command:
					'export DPSECI_COUNT=<Num of dpseci objects>'
					where "Number of dpseci objects" is an
					integer value.
					e.g export DPSECI_COUNT=4"

		DPSECI_QUEUES       = number of rx/tx queues.
					Set the parameter using below command:
					'export DPSECI_QUEUES=<Num of Queues>'
					where "Number of Queues" is an integer
					value "e.g export DPSECI_QUEUES=8".

		DPSECI_PRIORITIES   = num-queues priorities.
					Set the parameter using below command:
                                        'export DPSECI_PRIORITIES="Prio-1,Prio-2,..."'
                                        e.g export DPSECI_PRIORITIES="2,2,2,2,2,2,2,2"

	/**DPIO**:-->
		DPIO_COUNT	    = DPIO objects count
					Set the parameter using below command:
					'export DPIO_COUNT=<Num of dpio objects>'
					where "Number of dpio objects" is an
					integer value.
					e.g export DPIO_COUNT=10"

		DPIO_PRIORITIES     = number of  priority from 1-8.
					Set the parameter using below command:
                                        'export DPIO_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					"e.g export DPIO_PRIORITIES=8"

	/**DPBP**:-->
		DPBP_COUNT	    = DPBP objects count
					Set the parameter using below command:
					'export DPBP_COUNT=<Num of dpbp objects>'
					where "Number of dpbp objects" is an
					integer value.
					e.g export DPBP_COUNT=4"

	/**DPCI**:-->
		DPCI_COUNT	    = DPCI objects count for software queues
					Set the parameter using below command:
					'export DPCI_COUNT=<Num of dpci objects>'
					e.g export DPCI_COUNT=12"

		DPCI_PRIORITIES     = number of  priority from 1-2.
					Set the parameter using below command:
                                        'export DPCI_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					"e.g export DPCI_PRIORITIES=1"
EOF


#/* Function, to intialize the DPNI related parameters
#*/
get_dpni_parameters() {
	if [[ -z "$BOARD_TYPE" ]]
	then
		if [ -e /sys/firmware/devicetree/base/compatible ]
		then
			board_type=`grep -ao '1088\|2088\|2080\|2085\|2160' /sys/firmware/devicetree/base/compatible | head -1`
		fi
		if [ -z "$board_type" ]
		then
			echo "Unable to find the board type!"
			echo "Please enter the board type! (Accepted board type keywords: 1088/2088/2085/2080/2160)"
			read board_type
		fi
	else
		board_type=${BOARD_TYPE}
	fi

	if [ \
	     $board_type != "1088" -a $board_type != "2080" -a \
	     $board_type != "2085" -a $board_type != "2088" -a \
	     $board_type != "2160" \
	   ]
	then
		echo "  Invalid board type ${board_type} specified."
		echo -n "  Only supported values are "
		echo "  1088|2080|2085|2088|2160."
		echo "  Not continuing ahead."
		return 1;
	fi

	echo "Using board type as ${board_type}"
	if [[ -z "$MAX_QUEUES" ]]
	then
		MAX_QUEUES=8
	fi
	if [[ -z "$MAX_TCS" ]]
	then
		MAX_TCS=8
	fi
	if [[ -z "$MAX_QOS" ]]
	then
		if [[ $board_type == "1088" || $board_type == "2080" || $board_type == "2085" ]]
		then
			MAX_QOS=1
		elif [[ $board_type == "2088" || $board_type == "2160" ]]
		then
			# Setting MAX_QOS to default value on LS2088 = 64, as per restool v1.5
			MAX_QOS=64
		fi
	fi
	if [[ -z "$DPNI_OPTIONS" ]]
	then
		if [[ $board_type != "1088" ]]
		then
			DPNI_OPTIONS="DPNI_OPT_HAS_KEY_MASKING"
		fi
	fi
	if [[ -z "$DPNI_NORMAL_BUF" ]]
	then
		if [[ $board_type != "1088" ]]
		then
			DPNI_OPTIONS=$DPNI_OPTIONS,0x80000000
			echo "Using High Performance Buffers"
		fi
	else
		echo "Using Normal Performance Buffers"
	fi
	if [[ -z "$MAX_DIST_KEY_SIZE" ]]
	then
		MAX_DIST_KEY_SIZE=8
	fi
	if [[ -z "$FS_ENTRIES" ]]
	then
		FS_ENTRIES=1
	fi
	if [[ -z "$DPSECI_OPTIONS" ]]
	then
		DPSECI_OPTIONS=DPSECI_OPT_HAS_CG
	fi
	echo >> dynamic_dpl_logs
	echo  "DPNI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tMAX_QUEUES = "$MAX_QUEUES >> dynamic_dpl_logs
	echo -e "\tMAX_TCS = "$MAX_TCS >> dynamic_dpl_logs
	echo -e "\tDPNI_OPTIONS = "$DPNI_OPTIONS >> dynamic_dpl_logs
	echo -e "\tDPSECI_OPTIONS = "$DPSECI_OPTIONS >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs

}

#/* Function, to intialize the DPCON related parameters
#*/
get_dpcon_parameters() {
	if [[ "$DPCON_COUNT" ]]
	then
		if [[ $DPCON_COUNT -lt 3 ]]
		then
			echo -e "\tDPCON_COUNT value should be greater than 2" >> dynamic_dpl_logs
			echo -e $RED"\tDPCON_COUNT value should be greater than 2"$NC
			return 1;
		fi

	else
		DPCON_COUNT=8
	fi
	if [[ -z "$DPCON_PRIORITIES" ]]
	then
		DPCON_PRIORITIES=2
	fi
	echo "DPCON parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPCON_PRIORITIES	= "$DPCON_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPCON_COUNT		= "$DPCON_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPBP related parameters
#*/
get_dpbp_parameters() {
	if [[ -z "$DPBP_COUNT" ]]
	then
		DPBP_COUNT=16
	fi
	echo "DPBP parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPBP_COUNT = "$DPBP_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPSECI related parameters
#*/
get_dpseci_parameters() {
	if [[ -z "$DPSECI_COUNT" ]]
	then
		DPSECI_COUNT=8
	fi
	if [[ -z "$DPSECI_QUEUES" ]]
	then
		DPSECI_QUEUES=1
	fi
	if [[ -z "$DPSECI_PRIORITIES" ]]
	then
		DPSECI_PRIORITIES="2"
	fi
	echo "DPSECI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPSECI_COUNT = "$DPSECI_COUNT >> dynamic_dpl_logs
	echo -e "\tDPSECI_QUEUES = "$DPSECI_QUEUES >> dynamic_dpl_logs
	echo -e "\tDPSECI_PRIORITIES = "$DPSECI_PRIORITIES >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPIO related parameters
#*/
get_dpio_parameters() {
	if [[ -z "$DPIO_COUNT" ]]
	then
		if [[ $board_type == "2160" ]]
		then
			DPIO_COUNT=24
		else
			DPIO_COUNT=10
		fi
	fi
	if [[ -z "$DPIO_PRIORITIES" ]]
	then
		DPIO_PRIORITIES=2
	fi
	echo "DPIO parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPIO_PRIORITIES = "$DPIO_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPIO_COUNT = "$DPIO_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPCI related parameters
#*/
get_dpci_parameters() {
	if [[ -z "$DPCI_COUNT" ]]
	then
		DPCI_COUNT=2
	fi
	if [[ -z "$DPCI_PRIORITIES" ]]
	then
		DPCI_PRIORITIES=2
	fi
	echo "DPCI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPCI_PRIORITIES = "$DPCI_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPCI_COUNT = "$DPCI_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* function, to create the actual MAC address from the base address
#*/
create_actual_mac() {
	last_octet=$(echo $2 | head -1 | cut -f6 -d ':')
	last_octet=$(printf "%d" 0x$last_octet)
	last_octet=$(expr $last_octet + $1)
	last_octet=$(printf "%0.2x" $last_octet)
	if [[ 0x$last_octet -gt 0xFF ]]
        then
		last_octet=$(printf "%d" 0x$last_octet)
		last_octet=`expr $last_octet - 255`
		last_octet=$(printf "%0.2x" $last_octet)
	fi
	ACTUAL_MAC=$(echo $2 | sed -e 's/..$/'$last_octet'/g')
}


#/* script's actual starting point
#*/
rm dynamic_dpl_logs > /dev/null 2>&1
rm dynamic_results > /dev/null 2>&1
unset BASE_ADDR
printf "%-21s %-21s %-25s\n" "Interface Name" "Endpoint" "Mac Address" > dynamic_results
printf "%-21s %-21s %-25s\n" "==============" "========" "==================" >> dynamic_results
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
if [[ $1 ]]
then
	echo "Available DPRCs" >> dynamic_dpl_logs
	restool dprc list >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	#/* Creation of DPRC*/
	export DPRC=$(restool -s dprc create dprc.1 --label="DPDK Container" --options=DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED,DPRC_CFG_OPT_OBJ_CREATE_ALLOWED)

	DPRC_LOC=/sys/bus/fsl-mc/devices/$DPRC
	echo $DPRC "Created" >> dynamic_dpl_logs

	#/*Validating the arguments*/
	echo >> dynamic_dpl_logs
	echo "Validating the arguments....." >> dynamic_dpl_logs
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 1`
			BASE_ADDR=$(echo ${!num} | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
			if [[ $BASE_ADDR ]]
			then
				echo >> dynamic_dpl_logs
				echo -e '\t'$BASE_ADDR" will be used as MAC's base address" >> dynamic_dpl_logs
				num=`expr $num + 1`
			else
				echo >> dynamic_dpl_logs
				echo -e "\tInvalid MAC base address" >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				echo
				echo -e $RED"\tInvalid MAC base address"$NC
				echo
				restool dprc destroy $DPRC >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
			fi
			continue;
		fi
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} != "dpni-dpni" && ${!num} != "dpni-self" && $TYPE != "dpmac" && $TYPE != "dpni" ]]
		then
			echo >> dynamic_dpl_logs
			echo -e "\tInvalid Argument \""${!num}"\"" >> dynamic_dpl_logs
			echo >> dynamic_dpl_logs
			echo
			echo -e $RED"\tInvalid Argument \""${!num}"\"" $NC
			echo
			restool dprc destroy $DPRC >> dynamic_dpl_logs
			cat script_help
			rm script_help
			echo
			[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
		fi
		num=`expr $num + 1`
	done

	#/* Getting parameters*/
	get_dpni_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	get_dpcon_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	get_dpbp_parameters
	get_dpseci_parameters
	get_dpio_parameters
	get_dpci_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	#/* Objects creation*/
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		echo >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		echo "####### Parsing argument number "$num" ("${!num}") #######" >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		MAC_OCTET2=0
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} == "dpni-dpni" ]]
		then
			if [[ $BASE_ADDR ]]
			then
				mac_no=`expr $# + $num`
				create_actual_mac $mac_no $BASE_ADDR
			else
				ACTUAL_MAC="00:00:00:00:02:"$num
			fi
			OBJ=$(restool -s dpni create --options=$DPNI_OPTIONS --num-tcs=$MAX_TCS --num-queues=$MAX_QUEUES --fs-entries=$FS_ENTRIES --vlan-entries=16 --qos-entries=$MAX_QOS --container=$DPRC)
			restool dprc sync
			restool dpni update $OBJ --mac-addr=$ACTUAL_MAC
			echo $OBJ "created with MAC addr = "$ACTUAL_MAC >> dynamic_dpl_logs
			MAC_ADDR1=$ACTUAL_MAC
			MAC_OCTET2=3
			MAC_OCTET1=$num
		elif [[ ${!num} == "dpni-self" ]]
		then
			MAC_OCTET2=4
			MAC_OCTET1=$num;
		elif [[ ${!num} == "dpni" ]]
		then
			MAC_OCTET2=5
			MAC_OCTET1=$num;
		elif [[ $TYPE == "dpni" ]]
		then
			MAC_OCTET2=6
			MAC_OCTET1=$num;
		else
			OBJ=${!num}
			MAC_OCTET1=$(echo $OBJ | head -1 | cut -f2 -d '.');
		fi
		if [[ $BASE_ADDR ]]
		then
			create_actual_mac $num $BASE_ADDR
		else
			ACTUAL_MAC="00:00:00:00:"$MAC_OCTET2":"$MAC_OCTET1
		fi
		DPNI=$(restool -s dpni create --options=$DPNI_OPTIONS --num-tcs=$MAX_TCS --num-queues=$MAX_QUEUES --fs-entries=$FS_ENTRIES --vlan-entries=16 --qos-entries=$MAX_QOS --container=$DPRC)
		restool dprc sync
		restool dpni update $DPNI --mac-addr=$ACTUAL_MAC
		echo -e '\t'$DPNI "created with MAC addr = "$ACTUAL_MAC >> dynamic_dpl_logs
		export DPNI$num=$DPNI
		MAC_ADDR2=$ACTUAL_MAC
		if [[ $TYPE == "dpmac" ]]
		then
			echo -e "\tDisconnecting the" $OBJ", if already connected" >> dynamic_dpl_logs
			TEMP=$(restool dprc disconnect dprc.1 --endpoint=$OBJ > /dev/null 2>&1)
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ 2>&1)
			CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
			if [[ $CHECK == "error:" ]]
			then
				echo -e "\tGetting error, trying to create the "$OBJ >> dynamic_dpl_logs
				OBJ_ID=$(echo $OBJ | head -1 | cut -f2 -d '.')
				TEMP=$(restool dpmac create --mac-id=$OBJ_ID 2>&1)
				CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
				if [[ $CHECK == "error:" ]]
				then
					echo -e "\tERROR: unable to create "$OBJ $NC >> dynamic_dpl_logs
					echo -e "\tDestroying container "$DPRC >> dynamic_dpl_logs
					echo -e $RED"\tERROR: unable to create "$OBJ $NC
					./destroy_dynamic_dpl.sh $DPRC >> dynamic_dpl_logs
					echo
					rm script_help
					[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				fi
				restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ
			fi
			MAC_ADDR1=
			echo -e '\t'$OBJ" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state " >> dynamic_dpl_logs
		elif [[ ${!num} == "dpni" ]]
		then
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			MAC_ADDR1=
			OBJ=
		elif [[ $TYPE == "dpni" ]]
		then
			echo " printing the dpni ="${!num} >> dynamic_dpl_logs
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=${!num})
			echo -e '\t'$DPNI" Linked with "${!num} >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			MAC_ADDR1=
			OBJ=${!num}
		elif [[ ${!num} == "dpni-self" ]]
		then
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$DPNI)
			echo -e '\t'$DPNI" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			OBJ=$DPNI
			MAC_ADDR1=$MAC_ADDR2
			unset MAC_ADDR2
		else
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ)
			echo -e '\t'$OBJ" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$OBJ --child=$DPRC --plugged=1)
			echo -e '\t'$OBJ "moved to plugged state" >> dynamic_dpl_logs
		fi
		if [[ $MAC_ADDR1 ]]
		then
			if [[ $MAC_ADDR2 ]]
			then
				printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
			fi
			printf "%-21s %-21s %-25s\n" $OBJ $DPNI $MAC_ADDR1 >> dynamic_results
		elif [[ $OBJ ]]
		then
			printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
		else
			printf "%-21s %-21s %-25s\n" $DPNI "UNCONNECTED" $MAC_ADDR2 >> dynamic_results
		fi
		OBJ=
		num=`expr $num + 1`
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 2`
			continue;
		fi
	done
	echo >> dynamic_dpl_logs
	echo "******* End of parsing ARGS *******" >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs

	restool dprc sync

	#/* DPMCP objects creation*/
	DPMCP=$(restool -s dpmcp create --container=$DPRC)
	echo $DPMCP "Created" >> dynamic_dpl_logs
	restool dprc sync
	TEMP=$(restool dprc assign $DPRC --object=$DPMCP --child=$DPRC --plugged=1)
	echo $DPMCP "moved to plugged state" >> dynamic_dpl_logs
	restool dprc sync

	#/* DPBP objects creation*/
	for i in $(seq 1 ${DPBP_COUNT}); do
		DPBP=$(restool -s dpbp create --container=$DPRC)
		echo $DPBP "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPBP --child=$DPRC --plugged=1)
		echo $DPBP "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	#/* DPCON objects creation*/
	for i in $(seq 1 ${DPCON_COUNT}); do
		DPCON=$(restool -s dpcon create --num-priorities=$DPCON_PRIORITIES --container=$DPRC)
		echo $DPCON "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPCON --child=$DPRC --plugged=1)
		echo $DPCON "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	#/* DPSECI objects creation*/
	for i in $(seq 1 ${DPSECI_COUNT}); do
		DPSEC=$(restool -s dpseci create --num-queues=$DPSECI_QUEUES --priorities=$DPSECI_PRIORITIES --options=$DPSECI_OPTIONS --container=$DPRC)
		echo $DPSEC "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPSEC --child=$DPRC --plugged=1)
		echo $DPSEC "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	#/* DPIO objects creation*/
	for i in $(seq 1 ${DPIO_COUNT}); do
		DPIO=$(restool -s dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES --container=$DPRC)
		echo $DPIO "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPIO --child=$DPRC --plugged=1)
		echo $DPIO "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	# Create DPCI's for software queues
	unset DPCI
	for i in $(seq 1 ${DPCI_COUNT}); do
		DPCI=$(restool -s dpci create --num-priorities=$DPCI_PRIORITIES --container=$DPRC)
		echo $DPCI "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPCI --child=$DPRC --plugged=1)
		echo $DPCI "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	dmesg -D
	# Mount HUGETLB Pages first
	HUGE=$(grep -E '/mnt/\<hugepages\>.*hugetlbfs' /proc/mounts)
	if [[ -z $HUGE ]]
	then
		mkdir /mnt/hugepages
		mount -t hugetlbfs none /mnt/hugepages
	else
		echo >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		echo "Already mounted :  " $HUGE >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
	fi
	echo
	if [ -e /sys/module/vfio_iommu_type1 ];
	then
	        echo -e "\tAllow unsafe interrupts" >> dynamic_dpl_logs
	        echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
	else
	        echo -e " Can't Run DPAA2 without VFIO support" >> dynamic_dpl_logs
	        echo -e $RED" Can't Run DPAA2 without VFIO support"$NC
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi
	if [ -e $DPRC_LOC ];
	then
		echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/$DPRC/driver_override
		echo -e "\tBind "$DPRC" to VFIO driver" >> dynamic_dpl_logs
		echo $DPRC > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
		echo -e "Binding to VFIO driver is done" >> dynamic_dpl_logs
	fi
	dmesg -E

	echo -e "##################### Container $GREEN $DPRC $NC is created ####################"
	echo
	echo -e "Container $DPRC have following resources :=>"
	echo
	count=$(restool dprc show $DPRC | grep -c dpbp.*)
	echo -e " * $count DPBP"
	count=$(restool dprc show $DPRC | grep -c dpcon.*)
	echo -e " * $count DPCON"
	count=$(restool dprc show $DPRC | grep -c dpseci.*)
	echo -e " * $count DPSECI"
	count=$(restool dprc show $DPRC | grep -c dpni.*)
	echo -e " * $count DPNI"
	count=$(restool dprc show $DPRC | grep -c dpio.*)
	echo -e " * $count DPIO"
	count=$(restool dprc show $DPRC | grep -c dpci.*)
	echo -e " * $count DPCI"
	echo
	echo
	unset count
	echo -e "######################### Configured Interfaces #########################"
	echo
	cat dynamic_results
	echo >> dynamic_dpl_logs
	echo -e "USE " $DPRC " FOR YOUR APPLICATIONS" >> dynamic_dpl_logs
	rm script_help
	echo

else
	echo >> dynamic_dpl_logs
	echo -e "\tArguments missing" >> dynamic_dpl_logs
	echo
	echo -e '\t'$RED"Arguments missing"$NC
	cat script_help
	rm script_help
fi
