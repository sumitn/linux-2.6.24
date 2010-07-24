#!/bin/bash -norc
set -x
PATH=/sbin:.:/usr/local/fist:${PATH}
export PATH

function set_default() {
  eval val=\$$1

  if [ -z "$val" ]
  then
    eval $1=$2
  fi
}

set_default LOWERDIR /n/fist/sfuse
set_default MOUNTPOINT /mnt/sfuse
set_default DEBUG 18

if [ -f doitopts ] ; then
	. doitopts
fi
if [ -f doitopts.`uname -n` ] ; then
	. doitopts.`uname -n`
fi

#make module_install
#make module_install_nocheck
#make install
lsmod
insmod ./sfuse.ko || exit
lsmod

#read n
sleep 1

# regular style mount
mount -t sfuse -o dir=${LOWERDIR},debug=${1:-$DEBUG} ${LOWERDIR} ${MOUNTPOINT} || exit

# attach-mode style mount
#mount -t sfuse -o debug=18 none ${MOUNTPOINT} || exit

#read n
#fist_ioctl +a ${MOUNTPOINT} abc /n/fist/sfuse/zadok

#read n
#sleep 1
fist_ioctl -d ${MOUNTPOINT} ${1:-$DEBUG} || exit
#fist_ioctl -f ${MOUNTPOINT} 1 || exit

if test -f fist_setkey ; then
    read n
    echo abrakadabra | ./fist_setkey ${MOUNTPOINT}
    echo
fi
