#!/bin/sh
# $FreeBSD$

dir=`dirname $0`
. ${dir}/ipacl_script.sh

echo "1..32"
jid1=1
jid2=3

if1_host="epair0a"
if1_jail1="epair0b"
if2_jail1="lo0"
if1_jail2="epair1b"
if2_jail2="lo0"

#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jail 1
# make sure to create second jail(jid=2) with epair1b

#this script also tests that host remain unaffected in all cases

# Verify effect of changing security.mac.ipacl.ipv4
sysctl security.mac.ipacl.ipv6=0 >/dev/null
exec_test ok ipv6 ${if1_host} '2001:db8::1111' 32 0
exec_test ok ipv6 ${if1_jail1} '2001:db8::1112' 64 1
exec_test ok ipv6 ${if1_host} '2001:2::abcd' 24 0
exec_test ok ipv6 ${if1_jail1} '001:470:1e01:5ea::11' 48 1

sysctl security.mac.ipacl.ipv6=1 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null

exec_test ok ipv6 ${if1_host} '2001:db8::1111' 32 0
exec_test fl ipv6 ${if1_jail1} '2001:db8::1112' 64 1
exec_test ok ipv6 ${if1_host} '2001:2::abcd' 24 0
exec_test fl ipv6 ${if1_jail1} '001:470:1e01:5ea::11' 48 1

# rule: jid@allow@interface_name@addr_family@ip_addr@subnet_mask
sysctl security.mac.ipacl.rules=${jid1}@1@epair0b@AF_INET6@2001:db8::1111@-1,${jid2}@1@epair1b@AF_INET6@2001:2::1234:1234@-1,${jid2}@1@@AF_INET6@fe80::@32,${jid2}@0@@AF_INET6@fe80::abcd@-1 >/dev/null

# Verify if security.mac.ipacl.rules allow jail to set certain IPv4 address
exec_test ok ipv6 ${if1_jail1} '2001:db8::1111' 16 ${jid1}
exec_test fl ipv6 ${if1_jail1} '2001:db8::1112' 16 ${jid1}
exec_test ok ipv6 ${if1_jail2} '2001:2::1234:1234' 48 ${jid2}
exec_test fl ipv6 ${if1_jail1} '2001:2::1234:1234' 48 ${jid1}

# Verify if scurity.mac.ipacl.rules allow jail to set any address in subnet
exec_test ok ipv6 ${if1_jail2} 'FE80::1101:1221' 15 ${jid2}
exec_test ok ipv6 ${if1_jail2} 'FE80::abab' 15 ${jid2}
exec_test ok ipv6 ${if1_jail2} 'FE80::1' 64 ${jid2}
exec_test fl ipv6 ${if1_jail2} 'FE80::abcd' 15 ${jid2} #last rule disllow the ip in that subnet

# Verify if security.mac.ipacl.rules (interface wildcard) allow jail to set certain IPv4 address
exec_test ok ipv6 ${if2_jail2} 'FE80::1101:1221' 15 ${jid2}
exec_test ok ipv6 ${if2_jail2} 'FE80::abab' 32 ${jid2}
exec_test fl ipv6 ${if2_jail2} 'FE81::1' 64 ${jid2}
exec_test fl ipv6 ${if2_jail2} 'FE80::abcd' 32 ${jid2} #last rule disllow the ip in that subnet

#add more tests of ULA address space
#allow subnet fc00::/7 except subnet fc00::1111:22xx but allow fc00::1111:2281
sysctl security.mac.ipacl.rules=${jid1}@1@@AF_INET6@fc00::@7,${jid1}@0@@AF_INET6@fc00::1111:2200@120,${jid1}@1@@AF_INET6@fc00::1111:2299@-1,${jid1}@1@@AF_INET6@2001:db8::@32,${jid1}@0@@AF_INET6@2001:db8::abcd@-1 >/dev/null
exec_test ok ipv6 ${if1_jail1} 'fc00::0000:1234' 48 ${jid1}
exec_test ok ipv6 ${if1_jail1} 'fc00::1112:1234' 48 ${jid1}
exec_test fl ipv6 ${if1_jail1} 'f800::2222:2200' 48 ${jid1}
exec_test fl ipv6 ${if1_jail1} 'f800::2222:22ff' 48 ${jid1}

exec_test ok ipv6 ${if1_jail1} 'fc00::1111:2111' 64 ${jid1}
exec_test fl ipv6 ${if1_jail1} 'fc00::1111:2211' 64 ${jid1}
exec_test fl ipv6 ${if1_jail1} 'fc00::1111:22aa' 48 ${jid1}
exec_test ok ipv6 ${if1_jail1} 'fc00::1111:2299' 48 ${jid1}

#add more tests of documentation range IPV6
exec_test ok ipv6 ${if1_jail1} '2001:db8:abcd:bcde:cdef:def1:ef12:f123' 32 ${jid1}
exec_test ok ipv6 ${if1_jail1} '2001:db8:1111:2222:3333:4444:5555:6666' 32 ${jid1}
exec_test fl ipv6 ${if1_jail1} '2000:db9:1111:2222:3333:4444:5555:6666' 32 ${jid1}
exec_test fl ipv6 ${if2_jail1} '2001:db8::abcd' 32 ${jid1}

sysctl security.mac.ipacl.ipv6=0 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null
