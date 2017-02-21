#!/bin/bash

rm -rf arm64*
make install T=arm64-dpaa2-linuxapp-gcc EXTRA_CFLAGS="-DRTE_LIBRTE_DPAA2_USE_PHYS_IOVA=y -DRTE_LIBRTE_DPAA2_DEBUG_INIT=y -DRTE_LIBRTE_DPAA2_DEBUG_DRIVER=y -DRTE_LIBRTE_DPAA2_DEBUG_RX=y -DRTE_LIBRTE_DPAA2_DEBUG_TX=y -DRTE_LIBRTE_DPAA2_DEBUG_TX_FREE=y  -DRTE_LIBRTE_ETHDEV_DEBUG=y -DRTE_LOG_LEVEL=RTE_LOG_DEBUG -DRTE_LIBRTE_DPAA2_SEC_DEBUG_INIT=y -DRTE_LIBRTE_DPAA2_SEC_DEBUG_DRIVER=y -DRTE_LIBRTE_DPAA2_SEC_DEBUG_RX=y" -j4
if [ $? -ne 0 ]
then
	echo "dpaa2 debug build failed"
	exit
fi
rm -rf arm64*
make install T=arm64-dpaa-linuxapp-gcc  EXTRA_CFLAGS="-DRTE_LIBRTE_DPAA_DEBUG_INIT=y -DRTE_LIBRTE_DPAA_DEBUG_DRIVER=y -DRTE_LIBRTE_DPAA_DEBUG_RX=y -DRTE_LIBRTE_DPAA_DEBUG_TX=y -DRTE_LIBRTE_DPAA_DEBUG_TX_FREE=y  -DRTE_LIBRTE_ETHDEV_DEBUG=y -DRTE_LOG_LEVEL=RTE_LOG_DEBUG -DRTE_LIBRTE_DPAA_SEC_DEBUG_INIT=y -DRTE_LIBRTE_DPAA_SEC_DEBUG_DRIVER=y -DRTE_LIBRTE_DPAA_SEC_DEBUG_RX=y" -j4
if [ $? -ne 0 ]
then
	echo "dpaa debug build failed"
	exit
fi
rm -rf arm64*
make install T=arm64-dpaa-linuxapp-gcc -j4
if [ $? -ne 0 ]
then
	echo "dpaa build failed"
	exit
fi
make install T=arm64-dpaa2-linuxapp-gcc -j4
if [ $? -ne 0 ]
then
	echo "dpaa2 build failed"
	exit
fi
