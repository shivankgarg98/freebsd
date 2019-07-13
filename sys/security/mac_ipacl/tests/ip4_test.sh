#!/bin/sh

dir=`dirname $0`
. ${dir}/ipacl_script.sh

echo "1..20" 
jid2=5
#run this script for epair0a and epair0b as of now
#use ifconfig epair create to generate epair
#epair0a = host #epair0b = jail 1
# make sure to create second jail(jid=2) with epair1b

#this script also tests that host remain unaffected in all cases

# Verify effect of changing security.mac.ipacl.ipv4
sysctl security.mac.ipacl.ipv4=0 >/dev/null
exec_test ok ipv4 epair0a '192.168.43.26' 16 0
exec_test ok ipv4 epair0b '192.168.43.26' 16 1
exec_test ok ipv4 epair0a '127.1.32.31' 24 0
exec_test ok ipv4 epair0b '198.18.0.12' 15 1

sysctl security.mac.ipacl.ipv4=1 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null

exec_test ok ipv4 epair0a '192.168.43.26' 16 0
exec_test fl ipv4 epair0b '192.168.43.26' 16 1
exec_test ok ipv4 epair0a '127.1.32.31' 24 0
exec_test fl ipv4 epair0b '198.18.0.12' 15 1

# rule: jid@allow@interface_name@addr_family@ip_addr@subnet_mask
sysctl security.mac.ipacl.rules=1@1@epair0b@AF_INET@192.168.42.2@-1,${jid2}@1@epair1b@AF_INET@127.1.32.1@-1,${jid2}@1@@AF_INET@198.18.0.1@15,${jid2}@0@@AF_INET@198.18.0.12@-1 >/dev/null

# Verify if security.mac.ipacl.rule=TODO allow jail to set certain IPv4 address
exec_test ok ipv4 epair0b '192.168.42.2' 16 1
exec_test fl ipv4 epair0b '192.168.43.3' 16 1
exec_test ok ipv4 epair1b '127.1.32.1' 24 ${jid2}
exec_test fl ipv4 epair0b '127.1.32.1' 24 ${jid2}

# Verify if scurity.mac.ipacl.rule allow jail to set any address in subnet
exec_test ok ipv4 epair1b '198.18.0.192' 15 ${jid2}
exec_test ok ipv4 epair1b '198.18.132.121' 15 ${jid2}
exec_test fl ipv4 epair1b '197.1.123.123' 15 ${jid2}
exec_test fl ipv4 epair1b '198.18.0.12' 15 ${jid2} #last rule disllow the ip in that subnet

# Verify if secutiy.mac.ipacl.rule=TODO(interface wildcard) allow jail to set certain IPv4 address
exec_test ok ipv4 lo0 '198.18.0.192' 15 ${jid2}
exec_test ok ipv4 lo0 '198.18.132.121' 15 ${jid2}
exec_test fl ipv4 lo0 '197.1.123.123' 15 ${jid2}
exec_test fl ipv4 lo0 '198.18.0.12' 15 ${jid2} #last rule disllow the ip in that subnet

sysctl security.mac.ipacl.ipv4=0 >/dev/null
sysctl security.mac.ipacl.rules= >/dev/null
