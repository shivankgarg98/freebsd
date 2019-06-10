#!/bin/sh

dir=`dirname $0`
. ${dir}/ipacl_script.sh

#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jls 1
echo "test for ipv4"
exec_test ok ipv4 epair0a '192.168.12.12' 16 0 #1 test for host
exec_test ok ipv4 epair0b '192.168.12.13' 16 1 #2 test for jid=1
exec_test fl ipv4 epair0a '312.41.12.31' 24 0 #3
exec_test ok ipv4 epair0b '198.18.0.12' 15 1 #4 Benchmarking
exec_test ok ipv4 epair0a '198.51.100.108' 24 0 #5 TEST-NET-2
exec_test ok ipv4 epair0b '127.0.0.56' 8 1 #6 loop-back
exec_test fl ipv4 wlp12sa '192.168.41.1' 24 1 #7 interface doesn't exist
exec_test ok ipv4 wlp12sa '192.168.41.1' 24 1 #8 intentionally FAIL
exec_test fl ipv4 epair0a '192.168.41.1' 24 0 #9 intentionally FAIL

echo "test for ipv6"
exec_test ok ipv6 epair0a '001:470:1e04:5ea::10' 64 0 #10 test for host
exec_test ok ipv6 epair0b '001:470:1e01:5ea::11' 64 1 #11 test of jid=1
exec_test fl ipv6 epair0b 'fffff::1' 32 1 #12
exec_test ok ipv6 epair0a '2001:db8::1111' 32 0 #13 Documentation
exec_test fl ipv6 wlp12sa '2001:2::abcd' 48 0 #14 interface doesn't exist
exec_test fl ipv6 epair0b '2001:2::abcd' 48 1 #15 intentionally FAIL  
