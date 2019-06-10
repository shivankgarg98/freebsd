#!/bin/sh

dir=`dirname $0`
. ${dir}/ipacl_script.sh

#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair

echo "test for ipv4"
exec_test ok ipv4 epair0a '192.168.12.12' 24 0 #test for host
exec_test ok ipv4 epair0b '192.168.12.13' 24 1 #test for jid=1
exec_test fl ipv4 epair0a '312.041.12.31' 24 0
echo "test for ipv6"
exec_test ok ipv6 epair0a '001:470:1e04:5ea::10' 64 0 #test for host
exec_test ok ipv6 epair0b '001:470:1e01:5ea::11' 64 1 #test of jid=1
