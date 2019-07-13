#!/bin/sh

dir=`dirname $0`
. ${dir}/ipacl_script.sh

echo "1..21"
jid2=5
#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jail 1
# make sure to create second jail(jid=2) with epair1b

#this script also tests that host remain unaffected in all cases

# Verify effect of changing security.mac.ipacl.ipv4
sysctl security.mac.ipacl.ipv6=0 >/dev/null
exec_test ok ipv6 epair0a '2001:db8::1111' 32 0
exec_test ok ipv6 epair0b '2001:db8::1112' 64 1
exec_test ok ipv6 epair0a '2001:2::abcd' 24 0
exec_test ok ipv6 epair0b '001:470:1e01:5ea::11' 48 1

sysctl security.mac.ipacl.ipv6=1 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null

exec_test ok ipv6 epair0a '2001:db8::1111' 32 0
exec_test fl ipv6 epair0b '2001:db8::1112' 64 1
exec_test ok ipv6 epair0a '2001:2::abcd' 24 0
exec_test fl ipv6 epair0b '001:470:1e01:5ea::11' 48 1

# rule: jid@allow@interface_name@addr_family@ip_addr@subnet_mask
sysctl security.mac.ipacl.rules=1@1@epair0b@AF_INET6@2001:db8::1111@-1,${jid2}@1@epair1b@AF_INET6@2001:2::1234:1234@-1,${jid2}@1@@AF_INET6@fe80::@32,${jid2}@0@@AF_INET6@fe80::abcd@-1 >/dev/null

# Verify if security.mac.ipacl.rules allow jail to set certain IPv4 address
exec_test ok ipv6 epair0b '2001:db8::1111' 16 1
exec_test fl ipv6 epair0b '2001:db8::1112' 16 1
exec_test ok ipv6 epair1b '2001:2::1234:1234' 48 ${jid2}
exec_test fl ipv6 epair0b '2001:2::1234:1234' 48 1

# Verify if scurity.mac.ipacl.rules allow jail to set any address in subnet
exec_test ok ipv6 epair1b 'FE80::1101:1221' 15 ${jid2}
exec_test ok ipv6 epair1b 'FE80::abab' 15 ${jid2}
exec_test ok ipv6 epair1b 'FE80::1' 64 ${jid2}
exec_test fl ipv6 epair1b 'FE80::abcd' 15 ${jid2} #last rule disllow the ip in that subnet

# Verify if secutiy.mac.ipacl.rules (interface wildcard) allow jail to set certain IPv4 address
exec_test ok ipv6 lo0 'FE80::1101:1221' 15 ${jid2}
exec_test ok ipv6 lo0 'FE80::abab' 32 ${jid2}
exec_test ok ipv6 lo0 'FE80::1' 64 ${jid2}
exec_test fl ipv6 lo0 'FE81::1' 64 ${jid2}
exec_test fl ipv6 lo0 'FE80::abcd' 32 ${jid2} #last rule disllow the ip in that subnet

sysctl security.mac.ipacl.ipv6=0 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null
