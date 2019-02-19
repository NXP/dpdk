#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2020 NXP

# tunable parameters

LOCAL_ARCH=$(arch)
echo "Build Platform is $LOCAL_ARCH";
if [ $LOCAL_ARCH != aarch64 ]; then
	# CROSS should be set by user, else exit
	if [ -z "$CROSS" ]; then echo "CROSS is not set; set it first";
	 exit 1;
	fi
else
	# CROSS should be set by user, else default compiler would be picked up
	if [ -z "$CROSS" ]; then echo "CROSS is not set; using default";
	fi
fi

# RTE_KERNELDIR should be set else we disable KNI_KMOD
if [ -z "${RTE_KERNELDIR}" ]; then
	echo "KERNELDIR not set; disabling kernel build";
	kernel_disable="CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n"
else
	kernel_disable=
fi

# OPENSSL should be set else we disable OPENSSL related config
if [ -z "${OPENSSL_PATH}" ]; then
	echo "OPENSSL_PATH not set; disabling OPENSSL related config"
	openssl_disable="CONFIG_RTE_LIBRTE_PMD_OPENSSL=n"
else
	openssl_disable=
fi

RTE_SDK=`pwd`
RTE_TARGET=

# defaults ## Modify then to tune default values

platform="arm64-dpaa" # set to "dpaa" for both platform as default
build="static shared"  # set to "static shared" for 2 builds as default
debug_flag=0
jobs=4          # Parallel jobs
silent=0	# If output is dumped to screen
logoutput=      # File to dump output to, if -s is provided
clean_all=1	# Clean all before starting build
all_build=1     # Whether to build debug and non debug by default

dpaa_config_list="EXTRA_CFLAGS=-g"
dpaa_config_list=${dpaa_config_list}" EXTRA_CFLAGS+=-O0"
dpaa_config_list=${dpaa_config_list}" EXTRA_LDFLAGS=-g"
dpaa_config_list=${dpaa_config_list}" EXTRA_LDFLAGS+=-O0"
dpaa_config_list=${dpaa_config_list}" CONFIG_RTE_LIBRTE_DPAA_HWDEBUG=y"
dpaa_config_list=${dpaa_config_list}" CONFIG_RTE_LOG_LEVEL=RTE_LOG_DEBUG"
dpaa_config_list=${dpaa_config_list}" CONFIG_RTE_LOG_DP_LEVEL=RTE_LOG_DEBUG"

# List of example applications to build
examples_to_build="cmdif l2fwd l3fwd ipsec-secgw l2fwd-crypto ip_fragmentation"
examples_to_build=$examples_to_build + " qdma_demo"

# Some colors

RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

function debug() {
	echo "DEBUG: $@"
}

function error() {
	echo "ERROR: $@"
}

function print() {
	if [ ${silent} -eq 1 ]; then
		echo -e "$@" >> ${logoutput}
	else
		echo -e "$@"
	fi
}

function usage() {
	echo "Usage: $0 [-s <build type>] [-d] [-c] [-j <jobs>]"
	echo "          [--dpaaconfig <comma separated list of configs> [-s] [-a] [-h] [-o <output file>]"
	echo
	echo "           -b <build type>"
	echo "              Optional: shared|static|all"
	echo "              default: static"
	echo
	echo "           -d Enable debugging mode compilation"
	echo "              If provided, toggles all DEBUG* configuration"
	echo "              parameter to \'y\'. It also adds \'-g\' and \'-O0\' to build"
	echo
	echo "           -c Don't cleanup before build"
	echo "              Each platform and build type creates an output folder"
	echo "              If this is not provided, re-compilation is done"
	echo "              If provided, build directory is deleted and compilation done."
	echo
	echo "           -j Number of parallel jobs"
	echo
	echo "           --dpaaconfig"
	echo "              A comma separated list of configuration items to build with"
	echo "              For e.g.: --dpaaconfig CONFIG_RTE_LIBRTE_DPAA_DEBUG_DRIVER=y"
	echo "              This would be passed to DPAA type build"
	echo
	echo "           -a Build with and without debugging"
	echo "              Builds are created separately for non-debug and debug, for each platform"
	echo "              By default, 'all=1'. Set -a for disabling debug build"
	echo
	echo "           -s Silent build. Output would be redirected into a randomly generated file"
	echo
	echo "           -o Output file. if not specified and silent is specified, randomly generated"
	echo "              file is used. This also implies silent mode"
	echo
	echo "           -h This help"
	echo
	echo " Set the environment variable CROSS, RTE_KERNELDIR, OPENSSL_PATH before execution."
	echo " If CROSS is not set, default compiler would be assumed."
	echo " If RTE_KERNELDIR or OPENSSL_PATH are not set, KNI and OPENSSL PMD compilation is disabled"
	echo
}

function dump_configuration() {
	if [ $silent -eq 1 ]; then
		echo "Output redirected to $logoutput"
	fi
	print "============================================"
	print "${BLUE}Using: "
	print "__CROSS         = ${CROSS}"
	print "__RTE_KERNELDIR = ${RTE_KERNELDIR}"
	print "__RTE_SDK       = ${RTE_SDK}"
	print "__OPENSSL_PATH  = ${OPENSSL_PATH}"
	print "__platform(s)   = $platform"
	print "__build(s)      = $build"
	print "__cleanall(s)   = $clean_all"
	print "__debug         = $debug_flag"
	print "__all_build     = $all_build"
	print "__Parallel jobs = ${jobs}"
	print "__DPAA  Config  = $dpaa_config_list"
	print "${NC}"
	print "==========================================="
}

while getopts ":p:b:dcj:-:aso:h" o; do
	case "${o}" in
		p)
			;;
		b)
			# shared or static build
			if [ ${OPTARG} == "static" ]; then
				build="static"
			else
			if [ ${OPTARG} == "shared" ]; then
				build="shared"
			else
			if [ ${OPTARG} ==  "all" ]; then
				build="static shared"
			else
				error "Invalid build type specified: Using default"
				build="static"
			fi;fi;fi
			debug "Build type: $build"
			;;
		d)
			# Debugging enable/disable
			debug_flag=1
			;;
		c)
			# Don't Clean all before building
			clean_all=0
			;;
		j)
			# Number of parallel jobs to run
			jobs=${OPTARG}
			if [ $jobs -lt 1 -o $jobs -gt 8 ]; then
				jobs=4
			fi
			;;
		-)
			# Long options for config options for each platform
			case "${OPTARG}" in
			dpaaconfig)
				val="${!OPTIND}"; OPTIND=$(( $OPTIND + 1 ))
				temp="$val"
				dpaa_config_list=`echo ${temp} | sed -r 's/,/ /g'`
				debug "dpaa config = ${dpaa_config_list}"
				;;
			*)
				usage
				exit 1
				;;
			esac;;
		a)
			all_build=0
			;;
		s)
			# Silent
			silent=1
			logoutput="output_"
			logoutput="${logoutput}_"`date +%d%m%Y_%H%M%S`".txt"
			;;
		o)
			logoutput=${OPTARG}
			if [ ! -e ${logoutput} ]; then
				touch ${logoutput}
			fi
			silent=1
			touch ${logoutput}
			if [ $? -ne 0 ]; then
				print "Unable to create output file; Disabling Output to file"
				silent=0
				logoutput=
			fi
			;;
		h)
			usage
			exit 1
			;;
		*)
			if [ "$OPTERR" != 1 ] || [ "${o:0:1}" = ":" ]; then
				usage
				exit 1
			fi
			;;
		\?)
			echo "Unknown argument"
			usage
			exit 1
			;;
	esac
done

dump_configuration

function build_examples() {
	local TARGET=$1
	local example_name=$2

	if [ $clean_all -eq 1 ]; then
		rm -rf examples/*/arm64-*
		rm -rf examples/*/*/arm64-*
		rm -rf examples/*/*/*/arm64-*
	fi

	unset RTE_TARGET
	export RTE_TARGET=${TARGET}

	# extract the target folder without any "/" and then append "shared" or
	# "static" to create final folder name. This is because the O= param
	# of "make -C examples/" doesn't allow "/"
	local b=`expr index $RTE_TARGET "/"`
	local prefix=
	TARGET=${RTE_TARGET:b}

	case "$RTE_TARGET" in
	*shared*)
		prefix="shared"
		;;
	*static*)
		prefix="static"
		;;
	*)
		prefix="unknown"
		;;
	esac

	TARGET=$prefix"-"$TARGET

	cmd="make -C examples/${example_name} O=${TARGET}"
	print "Executing ${cmd} for TARGET=${TARGET}"
	if [ ${silent} -eq 1 ]; then
		${cmd} >> $logoutput
	else
		${cmd}
	fi
	if [ $? -ne 0 ]; then
		echo -e "Error in ${RED} Building Examples ${NC}"
		return 1
	fi

	return 0
}

function build_x86() {
	# backup the existing CROSS
	CROSS1=${CROSS}
	unset CROSS

	local TARGET="x86_64-native"
	local OUTPUT=build_x86

	cmd="make T=${TARGET}-linuxapp-gcc -j ${jobs} O=${OUTPUT} install"
	cmd="$cmd $kernel_disable $openssl_disable"
	if [ ${debug_flag} -eq 1 ]; then
		rm -rf ${OUTPUT}
		echo -en " and ${BLUE}debugging${NC} enabled"
		varname="CONFIG_RTE_LOG_LEVEL=RTE_LOG_DEBUG CONFIG_RTE_LOG_DP_LEVEL=RTE_LOG_DEBUG"
		cmd="$cmd ${varname}"
	fi
	print "===================================================="
	print "Executing ${cmd}"
	if [ ${silent} -eq 1 ]; then
		${cmd} >> $logoutput
	else
		${cmd}
	fi
	if [ $? -ne 0 ]; then
		echo -e "Error in ${RED}${OUTPUT}${NC}"
		return 1
	fi
	print "===================================================="

	# Build examples
#	for i in $examples_to_build
#	do
#		build_examples ${OUTPUT}/"x86_64-native-linuxapp-gcc" $i
#		if [ $? -ne 0 ]
#		then
#			echo -e "Error in ${RED}${OUTPUT}/${TARGET} $i${NC}"
#			return 1
#		fi
#	done

	# restore CROSS
	export CROSS=${CROSS1}

	return 0
}

function build() {
	for i in ${platform}; do
		OUTPUT_head="build_${i}"
		if [ ${debug_flag} -eq 1 ]; then
			OUTPUT_head="build_debug_${i}"
		fi
		TARGET="$i-linuxapp-gcc"
		for j in ${build}; do
			# Dump what is being done on screen
			echo -en "Building: ${BLUE}${i}${NC} platform "
			echo -en "${BLUE}${j}${NC} mode"
			if [ ${debug_flag} -eq 1 ]; then
				echo -en " and ${BLUE}debugging${NC} enabled"
				#debug build only for static mode.
				if [ "$j" == "shared" ]; then
					return 0
				fi
			fi
			echo -e "${NC}."

			OUTPUT=${OUTPUT_head}"_${j}"
			print "Generating build in ${BLUE}${OUTPUT}${NC} dir"
			cmd="make T=${TARGET} -j ${jobs} O=${OUTPUT} install"
			cmd="$cmd $kernel_disable $openssl_disable"
			if [ "$j" == "shared" ]; then
				cmd="$cmd CONFIG_RTE_BUILD_SHARED_LIB=y"
			fi
			if [ ${debug_flag} -eq 1 ]; then
				local replace=""
				# i contains arm64-dpaa and we need to strip
				# the 'arm64-' part of it.
				local subs=${i/arm64-/$replace}
				varname="${subs}_config_list"
				cmd="$cmd ${!varname}"
			fi
			if [ $clean_all -eq 1 ]; then
				rm -rf ${OUTPUT}
			fi

			print "================================================"
			print "Executing ${cmd}"
			if [ ${silent} -eq 1 ]; then
				${cmd} >> $logoutput
			else
				${cmd}
			fi
			if [ $? -ne 0 ]; then
				echo -e "Error in ${RED}${OUTPUT}${NC}"
				exit 1
			fi
			print "================================================"

			#no need to build examples for debug build
			if [ ${debug_flag} -ne 1 ]; then
				# build examples for this target
				unset RTE_TARGET
				export RTE_TARGET=${OUTPUT}/${TARGET}
				make -C examples O=${OUTPUT}/${TARGET}
				if [ $? -ne 0 ]
				then
					echo -e "Error in ${RED}/${TARGET} ${NC}"
					return 1
				fi
			fi
		done
	done
	print "===================================================="
}

export RTE_SDK=${RTE_SDK}
build
build_x86
if [ ${all_build} -eq 1 ]; then
	debug_flag=1
	build
fi
