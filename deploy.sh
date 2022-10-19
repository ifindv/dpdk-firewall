# created by Alan at 2022-09-30 15:39

#! /bin/bash

# set variable
WORK_PATH=`pwd`
KMOD_INSTALL_PATH=${WORK_PATH}/build/kmods/
TOOL_PATH=${WORK_PATH}/usertools/

# check shell params
if [ $# -ne 2 ];
then
	echo "[Usage]: ./deploy.sh <NIC1> <NIC2>"
	echo "--------------------NICs--------------------"
	ip link
	echo "--------------------PCIs--------------------"
	python3 ${TOOL_PATH}/dpdk-devbind.py -s | grep '0000'
	exit
fi

# set netcard
NIC1=$1
NIC2=$2

# reserve huge mem
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

# insert kernel mod
sudo modprobe uio
sudo insmod ${KMOD_INSTALL_PATH}/igb_uio.ko 2> /dev/null

# bind nic
ip link set dev $NIC1 down
ip link set dev $NIC2 down
python3 ${TOOL_PATH}/dpdk-devbind.py -b igb_uio $NIC1 $NIC2
python3 ${TOOL_PATH}/dpdk-devbind.py -s | grep 'drv=igb_uio'