# created by Alan at 2022-09-30 15:17

#! /bin/bash

# set variable
WORK_PATH=`pwd`
KMOD_PATH=${WORK_PATH}/kmods/linux/igb_uio/
KMOD_INSTALL_PATH=${WORK_PATH}/build/kmods/
MODULE_PATH=${WORK_PATH}/module

# remove cache
rm -fr build
mkdir build

# build third-party module
for dir in ${MODULE_PATH}/*; do
    if [ -d "$dir" ]; then
        cd "$dir"
        if [ -f "build.sh" ]; then
            chmod 777 build.sh
            source ./build.sh
            if [ $? -ne 0 ]; then
                echo "build terminate !"
                exit -1
            fi
        fi
    fi
done
cd ${WORK_PATH}

# build all examples use -Dexamples=all

if [ $1 == "debug" ]; then
    meson -Dexamples=helloworld -Db_sanitize=address -Db_lundef=false -Dbuildtype=debug build
else
    meson -Dexamples=helloworld build
fi

ninja -C build

# build kernel module
mkdir -p ${KMOD_INSTALL_PATH}
cd ${KMOD_PATH}
make clean
make
cp igb_uio.ko ${KMOD_INSTALL_PATH}
cd ${WORK_PATH}
