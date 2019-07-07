TODO-
2. label an IP address for the jail which does not give EPERM error


--------------------------------------------------------------------------
Rough Notes-
1. if(subnet == subnet & IP) then IP is present in that particular subnet.
   Now, I'm thinking about changing the bool allow in struct ipacl_rule to
   int allow. and host can give the policy as allow=0 reject, allow=1 for IP
   address and allow=2 for whole subnet(allow all ip in that subnet)




-------------------------------------------------------------------------
Issues -
1. ifconfig commands first delete the ip address and then adds the new one. So,
if "add" is not given in parameters then the old one get lost and new one is not
alloted, leaving the jail without IP.

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
2. make
	* make obj depend all install #create obj in /boot/modules, can be loaded and unloaded by just names
	* make -j 4 KERNCONF=VIMAGE kernel -DKERNFAST
