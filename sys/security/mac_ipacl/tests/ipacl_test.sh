#!/bin/sh

dir=`dirname $0`
. ${dir}/ipacl_script.sh

#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jls 1

echo "1..30"
#sysctl allow
sysctl security.mac.ipacl.ipv4=1 >/dev/null
sysctl security.mac.ipacl.ipv6=1 >/dev/null

echo "test for ipv4 - ipv4 allow"
exec_test ok ipv4 epair0a '192.168.12.12' 16 0 #1 test for host
exec_test ok ipv4 epair0b '192.168.12.13' 16 1 #2 test for jid=1
exec_test fl ipv4 epair0a '312.41.12.31' 24 0 #3 fl wrong IP
exec_test ok ipv4 epair0b '198.18.0.12' 15 1 #4 Benchmarking
exec_test ok ipv4 epair0a '198.51.100.108' 24 0 #5 TEST-NET-2
exec_test ok ipv4 epair0b '127.0.0.56' 8 1 #6 loop-back
exec_test fl ipv4 wlp12sa '192.168.41.1' 24 1 #7 fl wrong interface

echo "test for ipv6 - ipv6 allow"
exec_test ok ipv6 epair0a '001:470:1e04:5ea::10' 64 0 #8 test for host
exec_test ok ipv6 epair0b '001:470:1e01:5ea::11' 64 1 #9 test of jid=1
exec_test fl ipv6 epair0b 'fffff::1' 32 1 #10
exec_test ok ipv6 epair0a '2001:db8::1111' 32 0 #11 Documentation
exec_test fl ipv6 wlp12sa '2001:2::abcd' 48 0 #12 interface doesn't exist

echo "Next 3 FAIL-intentionally"
exec_test fl ipv6 epair0b '2001:2::abcd' 48 1 #13 intentionally FAIL 
exec_test ok ipv4 wlp12sa '192.168.41.1' 24 1 #14 intentionally FAIL
exec_test fl ipv4 epair0a '192.168.41.1' 24 0 #15 intentionally FAIL


#sysctl disallow
sysctl security.mac.ipacl.ipv4=0 >/dev/null
sysctl security.mac.ipacl.ipv6=0 >/dev/null
echo "test for ipv4 - ipv4 disallow"
exec_test ok ipv4 epair0a '192.168.12.12' 16 0 #16 test for host
exec_test fl ipv4 epair0b '192.168.12.13' 16 1 #17 test for jid=1
exec_test fl ipv4 epair0a '312.41.12.31' 24 0 #18 fl wrong IP
exec_test fl ipv4 epair0b '198.18.0.12' 15 1 #19 Benchmarking
exec_test ok ipv4 epair0a '198.51.100.108' 24 0 #20 TEST-NET-2
exec_test fl ipv4 epair0b '127.0.0.56' 8 1 #21 loop-back
exec_test fl ipv4 wlp12sa '192.168.41.1' 24 1 #22 interface doesn't exist

echo "test for ipv6 - ipv6 disallow"
exec_test ok ipv6 epair0a '001:470:1e04:5ea::10' 64 0 #23 test for host
exec_test fl ipv6 epair0b '001:470:1e01:5ea::11' 64 1 #24 test of jid=1
exec_test fl ipv6 epair0b 'fffff::1' 32 1 #25
exec_test ok ipv6 epair0a '2001:db8::1111' 32 0 #26 Documentation
exec_test fl ipv6 wlp12sa '2001:2::abcd' 48 0 #27 interface doesn't exist

echo "Next 3 FAIL-intentionally"
exec_test ok ipv6 epair0b '2001:2::abcd' 48 1 #28 intentionally FAIL 
exec_test ok ipv4 epair0b '192.168.41.1' 24 1 #29 intentionally FAIL
exec_test fl ipv4 epair0a '192.168.41.1' 24 0 #30 intentionally FAIL



