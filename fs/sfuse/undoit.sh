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

set_default MOUNTPOINT /mnt/sfuse

if [ -f doitopts ] ; then
	. doitopts
fi
if [ -f doitopts.`uname -n` ] ; then
	. doitopts.`uname -n`
fi

fist_ioctl -d ${MOUNTPOINT} ${1:-18}

#/bin/rm /mnt/sfuse/X-*
#cp -p /n/fist/ext2fs/X-* /mnt/sfuse
#cp -p /n/fist/ext2fs/X-26 /mnt/sfuse

umount ${MOUNTPOINT}
lsmod
rmmod sfuse
lsmod
