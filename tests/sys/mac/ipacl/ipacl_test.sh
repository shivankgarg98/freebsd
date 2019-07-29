#! /usr/libexec/atf-sh
# $FreeBSD$

. $(atf_get_srcdir)/utils.subr

atf_test_case "ipacl_v4" "cleanup"

ipacl_v4_head()
{
	atf_set descr 'basic test for ipacl on IPv4 addresses'
	atf_set require.user root
}

ipacl_v4_body()
{
	ipacl_test_init
	
	epairA=$(vnet_mkepair)
	epairB=$(vnet_mkepair)
	epairC=$(vnet_mkepair)

	vnet_mkjail A ${epairA}b
	vnet_mkjail B ${epairB}b ${epairC}b

	jidA=$(jls -j A -s jid | grep -o -E '[0-9]+')
	jidB=$(jls -j B -s jid | grep -o -E '[0-9]+')
	
	sysctl security.mac.ipacl.ipv4=0
	# The ipacl policy module is not enforced for IPv4.
	
	atf_check -s exit:0 -e ignore ifconfig ${epairA}a 192.0.2.1/24 up
	atf_check -s exit:0 -e ignore ifconfig ${epairA}a 198.18.0.12/15 up
	atf_check -s exit:0 -e ignore jexec A \
	    ifconfig ${epairA}b 192.0.2.2/24 up
	atf_check -s exit:0 -e ignore jexec A \
	    ifconfig ${epairA}b 203.0.113.254/24 up

	sysctl security.mac.ipacl.ipv4=1
	sysctl security.mac.ipacl.rules=
	# The ipacl policy module is enforced for IPv4 and prevent all
	# jails from setting their IPv4 address
	
	atf_check -s exit:0 -e ignore ifconfig ${epairA}a 192.0.2.1/24 up
	atf_check -s exit:0 -e ignore ifconfig ${epairA}a 198.18.0.12/15 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 192.0.2.2/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 203.0.113.254/24 up

	sysctl security.mac.ipacl.rules=${jidA}@1@${epairA}b@AF_INET@192.168.42.2@-1,${jidB}@1@${epairB}b@AF_INET@127.1.32.1@-1,${jidB}@1@@AF_INET@198.18.0.1@15,${jidB}@0@@AF_INET@198.18.0.12@-1

	# Verify if it allows jail to set only certain IPv4 address.
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 192.168.42.2/16 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 198.168.42.3/16 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b 127.1.32.1/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b 127.1.32.1/24 up

	# Verify if the module allow jail to set any address in subnet.
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b 198.18.0.192/15 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b 198.18.132.121/15 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b 197.1.123.123/15 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b 198.18.0.12/15 up

	# Check wildcard for interfaces.
	atf_check -s exit:0 -e ignore jexec B ifconfig ${epairC}b 198.18.0.192/15 up
	atf_check -s exit:0 -e ignore jexec B ifconfig ${epairC}b 198.18.132.121/15 up
	atf_check -s not-exit:0 -e ignore jexec B ifconfig ${epairC}b 197.1.123.123/15 up
	atf_check -s not-exit:0 -e ignore jexec B ifconfig ${epairC}b 198.18.0.12/15 up

	# Tests when subnet is allowed.
	sysctl security.mac.ipacl.rules=${jidB}@1@@AF_INET@10.0.0.0@16,${jidB}@1@@AF_INET@10.12.0.0@16

	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b 10.1.0.0/16 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b 10.0.10.10/16 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b 10.13.0.0/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b 10.11.0.10/24 up

	sysctl security.mac.ipacl.rules=${jidA}@1@@AF_INET@169.254.0.0@16,${jidA}@0@@AF_INET@169.254.123.0@24,${jidA}@1@@AF_INET@169.254.123.123@-1,${jidA}@1@@AF_INET@198.51.100.0@24,${jidA}@0@@AF_INET@198.51.100.100@-1
	
	# Tests from Link-Local space and Documentation(TEST-NET-3).
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 169.254.121.121/16 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 169.254.123.121/16 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 169.254.123.123/16 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 169.253.121.121/16 up

	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 198.51.100.001/24 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 198.51.100.254/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 198.51.100.100/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b 198.151.100.254/24 up

	# Reset rules.
	sysctl security.mac.ipacl.rules=
}

ipacl_v4_cleanup()
{
	ipacl_test_cleanup
}

atf_test_case "ipacl_v6" "cleanup"

ipacl_v6_head()
{
	atf_set descr 'basic test for ipacl on IPv6 addresses'
	atf_set require.user root
}

ipacl_v6_body()
{
	ipacl_test_init
	
	epairA=$(vnet_mkepair)
	epairB=$(vnet_mkepair)
	epairC=$(vnet_mkepair)

	vnet_mkjail A ${epairA}b
	vnet_mkjail B ${epairB}b ${epairC}b

	jidA=$(jls -j A -s jid | grep -o -E '[0-9]+')
	jidB=$(jls -j B -s jid | grep -o -E '[0-9]+')
	
	sysctl security.mac.ipacl.ipv6=0
	# The ipacl policy module is not enforced for IPv6
	
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:2::abcd/24 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 001:470:1e01:5ea::11/48 up

	sysctl security.mac.ipacl.ipv6=1
	sysctl security.mac.ipacl.rules=
	# The ipacl policy module is enforced for IPv6 and prevent all
	# jails from setting their IPv6 address
	
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:2::abcd/24 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 001:470:1e01:5ea::11/48 up

	sysctl security.mac.ipacl.rules="${jidA}@1@${epairA}b@AF_INET6@2001:db8::1111@-1,${jidB}@1@${epairB}b@AF_INET6@2001:2::1234:1234@-1,${jidB}@1@@AF_INET6@fe80::@32,${jidB}@0@@AF_INET6@fe80::abcd@-1"
	
	# Verify if it allows jail to set only certain IPv6 address
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:db8::1111/16 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:db8::1112/16 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b inet6 2001:2::1234:1234/48 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:2::1234:1234/48 up

	# Verify if the module allow jail set any address in subnet
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b inet6 FE80::1101:1221/15 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b inet6 FE80::abab/15 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b inet6 FE80::1/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairB}b inet6 FE80::abcd/15 up

	# Check wildcard for interfaces. 
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 FE80::1101:1221/15 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 FE80::abab/32 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 FE81::1/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 FE80::abcd/32 up

	# Tests when subnet is allowed.
	sysctl security.mac.ipacl.rules=${jidB}@1@@AF_INET6@2001:2::@48,${jidB}@1@@AF_INET6@2001:3::@32

	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 2001:2:0001::1/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 2001:2:1000::1/32 up
	atf_check -s exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 2001:3:0001::1/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec B ifconfig ${epairC}b inet6 2001:4::1/64 up
	
	# More tests of ULA address space.
	sysctl security.mac.ipacl.rules=${jidA}@1@@AF_INET6@fc00::@7,${jidA}@0@@AF_INET6@fc00::1111:2200@120,${jidA}@1@@AF_INET6@fc00::1111:2299@-1,${jidA}@1@@AF_INET6@2001:db8::@32,${jidA}@0@@AF_INET6@2001:db8::abcd@-1

	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::0000:1234/48 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::0000:1234/48 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 f800::2222:2200/48 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 f800::2222:22ff/48 up

	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::1111:2111/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::1111:2211/64 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::1111:22aa/48 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 fc00::1111:2299/48 up

	# More tests from IPv6 documentation range.
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:db8:abcd:bcde:cdef:def1:ef12:f123/32 up
	atf_check -s exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:db8:1111:2222:3333:4444:5555:6666/32 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2000:db9:1111:2222:3333:4444:5555:6666/32 up
	atf_check -s not-exit:0 -e ignore \
	    jexec A ifconfig ${epairA}b inet6 2001:db8::abcd/32 up

	# Reset sysctl
	sysctl security.mac.ipacl.rules=
}

ipacl_v6_cleanup()
{
	ipacl_test_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "ipacl_v4"
	atf_add_test_case "ipacl_v6"
}
