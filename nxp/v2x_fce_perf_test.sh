#!/bin/bash -i
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025-2026 NXP

#usages are:
#./v2x_fce_perf_test.sh v2x_fce

#########  Tunable parameters

ops_num=100000
test_type=throughput
#test_type=latency

cores=0xc
burst=252

buffer_size=32
max_buffer_sz=16384

#logs=--log-level=8
logs=--log-level=6

silent=--silent
#csv_format=--csv-friendly
#others=--out-of-place
#segment=--segment-sz 200
extra_flags=$silent $csv_format

#default for dpaa_sec
vdev_string="--vdev v2x_fce"
dev_string=v2x_fce

count=0
failed=0

shaonly=1
hmaconly=1
aesonly=1

logoutput="dpdk_${dev_string}_report.txt"
#logoutput="${logoutput}_"`date +%d%m%Y_%H%M%S`".txt"

function mycmd() {
	$@ | tee -a ${logoutput}
	if [ $? -ne 0 ]; then
		failed=$((failed+1))
	fi
	count=$((count+1))
}

if [ -v DPDK_EXAMPLE_PATH ]; then
	echo "dpdk example app path $DPDK_EXAMPLE_PATH"
#elif [ -d "/usr/local/bin" ];then
#	export DPDK_EXAMPLE_PATH=/usr/local/bin
#	echo "dpdk example app path $DPDK_EXAMPLE_PATH"
else
	export DPDK_EXAMPLE_PATH=$(pwd)
fi

if [ ! -e $DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf ]; then
	echo -e "${DPDK_EXAMPLE_PATH}/dpdk-test-crypto-perf binary not available"
	echo -e "where DPDK_EXAMPLE_PATH is ${DPDK_EXAMPLE_PATH}"
	exit 1
fi

arg=1
if [[ ${!arg} == "v2x_fce" ]]
then
	logoutput="dpdk_${dev_string}_report.txt"
	shaonly=1
	hmaconly=1
	aesonly=1
	echo -e "=============== running v2x_fce ===============" | tee ${logoutput}
fi

echo ${logoutput}
if [ $shaonly -ne 0 ]; then
	echo -e "\n******************* sha2-256(generate) *******************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-256(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-256 --auth-op generate --auth-key-sz 0 \
		--digest-sz 32 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n******************* sha2-384(generate) *******************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-384(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-384 --auth-op generate --auth-key-sz 0 \
		--digest-sz 48 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n******************* sha2-512(generate) *******************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-512(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-512 --auth-op generate --auth-key-sz 0 \
		--digest-sz 64 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
fi
if [ $hmaconly -ne 0 ]; then
	echo -e "\n**************** sha2-256-hmac(generate) ****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-256-hmac(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-256-hmac --auth-op generate --auth-key-sz 64 \
		--digest-sz 32 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n***************** sha2-256-hmac(verify) *****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-256-hmac(verify) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-256-hmac --auth-op verify --auth-key-sz 64 \
		--digest-sz 32 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size $extra_flags \
		--test-file test$buffer_size.data --test-name sha2_256_hmac"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n**************** sha2-384-hmac(generate) ****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-384-hmac(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-384-hmac --auth-op generate --auth-key-sz 128 \
		--digest-sz 48 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n***************** sha2-384-hmac(verify) *****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-384-hmac(verify) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-384-hmac --auth-op verify --auth-key-sz 64 \
		--digest-sz 48 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags \
		--test-file test$buffer_size.data --test-name sha2_384_hmac"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n**************** sha2-512-hmac(generate) ****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-512-hmac(generate) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-512-hmac --auth-op generate --auth-key-sz 128 \
		--digest-sz 64 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n***************** sha2-512-hmac(verify) *****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "sha2-512-hmac(verify) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
		--optype auth-only --auth-algo sha2-512-hmac --auth-op verify --auth-key-sz 64 \
		--digest-sz 64 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags \
		--test-file test$buffer_size.data --test-name sha2_512_hmac"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
fi

# aes only algos
if [ $aesonly -ne 0 ]; then
	echo -e "\n***************** aes-256-cbc(encrypt) *****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "aes-256-cbc(encrypt) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
		--optype cipher-only --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 32 \
		--cipher-iv-sz 16 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
	echo -e "\n***************** aes-256-ecb(encrypt) *****************" | tee -a ${logoutput}
	buffer_size=32
	while [ $buffer_size -le $max_buffer_sz ]; do
		echo "aes-256-ecb(encrypt) buffer size $buffer_size" | tee -a ${logoutput}
		cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
		--optype cipher-only --cipher-algo aes-ecb --cipher-op encrypt --cipher-key-sz 32 \
		--cipher-iv-sz 0 --ptest $test_type --total-ops $ops_num \
		--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
		mycmd ${cmd}
		buffer_size=$((buffer_size * 2))
	done
fi

echo -e "===========================================" | tee -a ${logoutput}
echo -e "Total testcases run $count : failed $failed" | tee -a ${logoutput}
echo -e "Results available at ${logoutput}" | tee -a ${logoutput}
echo -e "===========================================" | tee -a ${logoutput}
