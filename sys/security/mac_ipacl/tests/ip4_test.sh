#!/bin/sh
# $FreeBSD$

dir=`dirname $0`
. ${dir}/ipacl_script.sh

echo "1..28" 
jid1=1
jid2=3
#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jail 1
# make sure to create second jail(jid=2) with epair1b

#this script also tests that host remain unaffected in all cases
if1_host="epair0a"
if1_jail1="epair0b"
if2_jail1="lo0"
if1_jail2="epair1b"
if2_jail2="lo0"

# Verify effect of changing security.mac.ipacl.ipv4
sysctl security.mac.ipacl.ipv4=0 >/dev/null
exec_test ok ipv4 ${if1_host} '192.168.43.26' 16 0
exec_test ok ipv4 ${if1_jail1} '192.168.43.26' 16 1
exec_test ok ipv4 ${if1_host} '127.1.32.31' 24 0
exec_test ok ipv4 ${if1_jail1} '198.18.0.12' 15 1

sysctl security.mac.ipacl.ipv4=1 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null

exec_test ok ipv4 ${if1_host} '192.168.43.26' 16 0
exec_test fl ipv4 ${if1_jail1} '192.168.43.26' 16 1
exec_test ok ipv4 ${if1_host} '127.1.32.31' 24 0
exec_test fl ipv4 ${if1_jail1} '198.18.0.12' 15 1

# rule: jid@allow@interface_name@addr_family@ip_addr@subnet_mask
sysctl security.mac.ipacl.rules=${jid1}@1@${if1_jail1}@AF_INET@192.168.42.2@-1,${jid2}@1@${if1_jail2}@AF_INET@127.1.32.1@-1,${jid2}@1@@AF_INET@198.18.0.1@15,${jid2}@0@@AF_INET@198.18.0.12@-1 >/dev/null

# Verify if security.mac.ipacl.rules allow jail to set certain IPv4 address
exec_test ok ipv4 ${if1_jail1} '192.168.42.2' 16 ${jid1}
exec_test fl ipv4 ${if1_jail1} '192.168.42.3' 16 ${jid1}
exec_test ok ipv4 ${if1_jail2} '127.1.32.1' 24 ${jid2}
exec_test fl ipv4 ${if2_jail2} '127.1.32.1' 24 ${jid2}

# Verify if scurity.mac.ipacl.rules allow jail to set any address in subnet
exec_test ok ipv4 ${if1_jail2} '198.18.0.192' 15 ${jid2}
exec_test ok ipv4 ${if1_jail2} '198.18.132.121' 15 ${jid2}
exec_test fl ipv4 ${if1_jail2} '197.1.123.123' 15 ${jid2}
exec_test fl ipv4 ${if1_jail2} '198.18.0.12' 15 ${jid2} #last rule disllow the ip in that subnet

# Verify if security.mac.ipacl.rules (interface wildcard) allow jail to set certain IPv4 address
exec_test ok ipv4 ${if2_jail2} '198.18.0.192' 15 ${jid2}
exec_test ok ipv4 ${if2_jail2} '198.18.132.121' 15 ${jid2}
exec_test fl ipv4 ${if2_jail2} '197.1.123.123' 15 ${jid2}
exec_test fl ipv4 ${if2_jail2} '198.18.0.12' 15 ${jid2} #last rule disllow the ip in that subnet

sysctl security.mac.ipacl.rules=${jid1}@1@@AF_INET@169.254.0.0@16,${jid1}@0@@AF_INET@169.254.123.0@24,${jid1}@1@@AF_INET@169.254.123.123@-1,${jid1}@1@@AF_INET@198.51.100.0@24,${jid1}@0@@AF_INET@198.51.100.100@-1 >/dev/null
# Add more tests from Link-Local space and Documentation(TEST-NET-3)
exec_test ok ipv4 ${if1_jail1} '169.254.121.121' 16 ${jid1}
exec_test fl ipv4 ${if1_jail1} '169.254.123.121' 16 ${jid1}
exec_test ok ipv4 ${if1_jail1} '169.254.123.123' 16 ${jid1}
exec_test fl ipv4 ${if1_jail1} '169.253.121.121' 16 ${jid1}

exec_test ok ipv4 ${if2_jail1} '198.51.100.001' 24 ${jid1}
exec_test ok ipv4 ${if2_jail1} '198.51.100.254' 24 ${jid1}
exec_test fl ipv4 ${if1_jail1} '198.51.100.100' 24 ${jid1}
exec_test fl ipv4 ${if1_jail1} '198.151.100.100' 24 ${jid1}

sysctl security.mac.ipacl.ipv4=0 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null
