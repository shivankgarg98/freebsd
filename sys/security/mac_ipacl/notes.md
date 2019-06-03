R0ugh N0tes-
1. write parsing rules to parse the command string
2. implement those rules using system calls(ioctl) and SIOCAIFADDR(for IPv4) and SIOCAIFADDR_IN6(for IPv6) - https://groups.google.com/forum/#!topic/fa.freebsd.hackers/LWIW5SYtjY8
3. implementing checks according to above rules to prevent jail from setting the particular IP address.
...
...
...



--------------------------------------------------------------------------
R3s0urc3s-
1. using TrustedBSD- http://www.drdobbs.com/using-trustedbsd/199101621
2. MAC framework intro - https://www.nixd.org/en/freebsd/freebsd-mac-framework-intro
3. KLD intro - http://beefchunk.com/documentation/sys-programming/os-freebsd/Dynamic_Kernel_Linker_KLD_Facility_Programming_Tutorial.html
4.




--------------------------------------------------------------------------
Commands-
1. kld
	* kldstat
	* kldload /usr/obj/usr/home/shivank/freebsd/amd64.amd64/sys/security/mac_ipacl/mac_ipacl.ko
	* kldunload mac_ipacl 
