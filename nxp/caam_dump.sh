#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 NXP

# commands:
# reset counters:
# echo "0x0" | ./caam_dump.sh 3
# dump counters and status registers:
# ./caam_dump.sh 2
# or
# watch -d ./caam_dump.sh 2
# dump counters:
# ./caam_dump.sh 1
# dump full QI, common, DECOs blocks
# ./caam_dump.sh

CAAM_BASE=0x1700000
CAAM_QI_BASE=0x70000
CAAM_DECO0_BASE=0x80000
CAAM_DECO1_BASE=0x90000
CAAM_DECO2_BASE=0xA0000

DEVMEM=./devmem5

if [[ "$1" == "3" ]]
then
	CAAM_QI_PC_BASE=0xF00
	echo "resetting counters..."
	for i in {0..13}
	do
		$DEVMEM w $(($CAAM_BASE + $CAAM_QI_BASE + $CAAM_QI_PC_BASE + ($i * 4))) w
	done
	exit
fi
if [[ -z "$1" || "$1" == "1" || "$1" == "2" ]]
then
	echo "Performance counters:"
	echo "============================"
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF00)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF07)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_REQ_DEQ:   " $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF08)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF0F)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -2 | head -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_OB_ENC_REQ:" $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF10)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF17)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_IB_DEC_REQ:" $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF18)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF1F)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -2 | head -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_OB_ENCRYPT:" $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF20)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF27)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_OB_PROTECT:" $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF28)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF2F)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -2 | head -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_IB_DECRYPT:" $((16#${C}))
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xF30)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xF37)) w)
	B=$(echo "$A" | awk '{print  $(NF-1) $NF}' | tail -1)
	C=$(echo ${B:6:2}${B:4:2}${B:2:2}${B:0:2}${B:14:2}${B:12:2}${B:10:2}${B:8:2})
	echo "PC_IB_VALIDATED" $((16#${C}))
	echo
	if [[ "$1" == "1" ]]
	then
		exit
	fi
fi
if [[ -z "$1" || "$1" == "2" ]]
then
	echo "CAAM GENERAL REGISTERS:"
	echo "============================"
	A=$($DEVMEM r $(($CAAM_BASE + 0x04)) $(($CAAM_BASE + 0x07)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "MCFGR:   " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + 0x58)) $(($CAAM_BASE + 0x5B)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "DEBUGCTL:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + 0x5C)) $(($CAAM_BASE + 0x5F)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -2 | head -1)
	echo "JRSTARTR:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + 0x120)) $(($CAAM_BASE + 0x123)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "DAR:     " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + 0x504)) $(($CAAM_BASE + 0x507)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "DMA_CTRL:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + 0x50C)) $(($CAAM_BASE + 0x50F)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -2 | head -1)
	echo "DMA_STA: " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	echo
	echo "QI STATUS REGISTERS:"
	echo "============================"
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0x04)) $(($CAAM_BASE + $CAAM_QI_BASE + 0x07)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "QICTL_LS:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0x0C)) $(($CAAM_BASE + $CAAM_QI_BASE + 0x0F)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -2 | head -1)
	echo "QISTA:   " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0x10)) $(($CAAM_BASE + $CAAM_QI_BASE + 0x13)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "QIDQC_MS:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0x14)) $(($CAAM_BASE + $CAAM_QI_BASE + 0x17)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "QIDQC_LS:" ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0x700)) $(($CAAM_BASE + $CAAM_QI_BASE + 0x703)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "REIR0QI: " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	A=$($DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE + 0xFD4)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xFD7)) w)
	B=$(echo "$A" | awk '{print $NF}' | tail -1)
	echo "SSTA:    " ${B:6:2}${B:4:2}${B:2:2}${B:0:2}
	echo
	if [[ "$1" == "2" ]]
	then
		exit
	fi
fi
echo "###########################################"
echo "Dumping CAAM general register space in BIG endian"
$DEVMEM r $(($CAAM_BASE)) $(($CAAM_BASE + 0xFFC)) w
echo
echo "###########################################"
echo "Dumping CAAM QI register space in BIG endian"
$DEVMEM r $(($CAAM_BASE + $CAAM_QI_BASE)) $(($CAAM_BASE + $CAAM_QI_BASE + 0xFFC)) w
echo
echo "###########################################"
echo "Dumping CAAM DECO0 register space in BIG endian"
$DEVMEM r $(($CAAM_BASE + $CAAM_DECO0_BASE)) $(($CAAM_BASE + $CAAM_DECO0_BASE + 0xFFC)) w
echo
echo "###########################################"
echo "Dumping CAAM DECO1 register space in BIG endian"
$DEVMEM r $(($CAAM_BASE + $CAAM_DECO1_BASE)) $(($CAAM_BASE + $CAAM_DECO1_BASE + 0xFFC)) w
echo
echo "###########################################"
echo "Dumping CAAM DECO2 register space in BIG endian"
$DEVMEM r $(($CAAM_BASE + $CAAM_DECO2_BASE)) $(($CAAM_BASE + $CAAM_DECO2_BASE + 0xFFC)) w
