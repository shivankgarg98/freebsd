TODO-
1. prevent jails from configuring their IP address only when mac_ipacl is loaded
   currently it prevent jails everytime.
2. label an IP address for the jail which does not give EPERM error


--------------------------------------------------------------------------
Rough Notes-
1. 




-------------------------------------------------------------------------
Issues -
2. iocage jail doesn't start due to "Configuring VNET Failed"


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
