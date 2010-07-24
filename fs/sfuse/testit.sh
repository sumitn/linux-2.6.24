#!/bin/bash -norc
set -x

#strace -v ./mapper1 /mnt/sfuse/BAR.TXT 0 20

/tmp/fsx-linux -N 1000 /mnt/sfuse/foo.$$

exit 0

# attach a node so /mnt/sfuse/abc -> /n/fist/zadok
./fist_ioctl +a /mnt/sfuse abc /n/fist/zadok
#read n
#./fist_ioctl +a /mnt/sfuse XyZ23q /some/place
exit 1

#ls -l /mnt/sfuse/uname

#read n
file=foo-$RANDOM

## shift inward test
#echo 'abcdefghijklmnopqrstuvwxyz0123456789' > /mnt/sfuse/$file
#read n
#echo 'XXXXXXXXXX' | ~ib42/c/test/write /mnt/sfuse/$file 10

## shift outward test
#echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > /mnt/sfuse/$file
cp /bin/ls /mnt/sfuse/$file
read n
echo '1234567890' | ~ib42/c/test/write /mnt/sfuse/$file 4110

read n
cat <<EOF
aaaaaaaaaa1234567890
aaaaaaaaaaaaaaa
EO>> /mnt/sfuse/G

#  touch /mnt/sfuse/$file
#  ls -l /mnt/sfuse/$file
#  read n
#  #perl -e "print 'a' x 80" >> /mnt/sfuse/$file
#  ~ib42/c/test/truncate /mnt/sfuse/$file 100
#  read n
#  #perl -e "print 'b' x 4900" >> /mnt/sfuse/$file
#  ~ib42/c/test/truncate /mnt/sfuse/$file 5000
#  read n
#  date >> /mnt/sfuse/$file
#  read n
#  hexdump /mnt/sfuse/$file


#echo
#cp /etc/termcap /mnt/sfuse/$file
#read n
#od -Ax -h /n/fist/sfuse/$file
#ls -l /mnt/sfuse/$file
