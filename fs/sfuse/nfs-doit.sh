#!/bin/bash -norc
set -x
# overlay mount on top of NFS example

PATH=/sbin:.:/usr/local/fist:${PATH}
export PATH

#make module_install
#make module_install_nocheck
#make install
lsmod
insmod ./sfuse.o || exit
lsmod

#read n
#sleep 1

mount -t sfuse -o dir=/mnt/sfuse /mnt/sfuse /mnt/sfuse || exit

#read n
#sleep 1
fist_ioctl -d /mnt/sfuse ${1:-18} || exit
fist_ioctl -f /mnt/sfuse 1 || exit

if test -f fist_setkey ; then
    read n
    echo abrakadabra | ./fist_setkey /mnt/sfuse
    echo
fi
