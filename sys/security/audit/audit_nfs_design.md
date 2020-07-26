## **audit(4) support to NFS: idea and design document**

#### BUGS
1. first(after system boot) NFS RPC event cannot make upto the audit log. Subsequent audit RPC events are logged successfully. This causes 1st test case to fail if it is made to run after the system restart.

2. some problem with vnode locking.

This I found while running libnfs/tests with auditd running with intention to find such bugs.
textdump
```
panic: Lock ufs not locked @ /usr/home/shivank/freebsd/sys/kern/kern_lock.c:1178

cpuid = 1
time = 1595316652
KDB: stack backtrace:
db_trace_self_wrapper() at db_trace_self_wrapper+0x2b/frame 0xfffffe001d3c9500
vpanic() at vpanic+0x182/frame 0xfffffe001d3c9550
panic() at panic+0x43/frame 0xfffffe001d3c95b0
lockmgr_unlock() at lockmgr_unlock+0x222/frame 0xfffffe001d3c95d0
vop_stdvptocnp() at vop_stdvptocnp+0xf2/frame 0xfffffe001d3c9920
vn_vptocnp() at vn_vptocnp+0x119/frame 0xfffffe001d3c99a0
vn_fullpath_dir() at vn_fullpath_dir+0x12d/frame 0xfffffe001d3c9a10
vn_fullpath_any() at vn_fullpath_any+0x94/frame 0xfffffe001d3c9a90
sys___getcwd() at sys___getcwd+0x77/frame 0xfffffe001d3c9ad0
amd64_syscall() at amd64_syscall+0x73d/frame 0xfffffe001d3c9bf0
fast_syscall_common() at fast_syscall_common+0x101/frame 0xfffffe001d3c9bf0
--- syscall (326, FreeBSD ELF64, sys___getcwd), rip = 0x8003880aa, rsp = 0x7fffffffe328, rbp = 0x7fffffffe480 ---
KDB: enter: panic

__curthread () at /usr/home/shivank/freebsd/sys/amd64/include/pcpu_aux.h:55
55		__asm("movq %%gs:%P1,%0" : "=r" (td) : "n" (offsetof(struct pcpu,
(kgdb) #0  __curthread ()
    at /usr/home/shivank/freebsd/sys/amd64/include/pcpu_aux.h:55
#1  doadump (textdump=0)
    at /usr/home/shivank/freebsd/sys/kern/kern_shutdown.c:394
#2  0xffffffff804a044a in db_dump (dummy=<optimized out>, 
    dummy2=<unavailable>, dummy3=<unavailable>, dummy4=<unavailable>)
    at /usr/home/shivank/freebsd/sys/ddb/db_command.c:575
#3  0xffffffff804a020c in db_command (last_cmdp=<optimized out>, 
    cmd_table=<optimized out>, dopager=1)
    at /usr/home/shivank/freebsd/sys/ddb/db_command.c:482
#4  0xffffffff8049ff7d in db_command_loop ()
    at /usr/home/shivank/freebsd/sys/ddb/db_command.c:535
#5  0xffffffff804a31e8 in db_trap (type=<optimized out>, code=<optimized out>)
    at /usr/home/shivank/freebsd/sys/ddb/db_main.c:253
#6  0xffffffff80c113b4 in kdb_trap (type=3, code=0, tf=<optimized out>)
    at /usr/home/shivank/freebsd/sys/kern/subr_kdb.c:699
#7  0xffffffff8106b5b8 in trap (frame=0xfffffe001d3c9430)
    at /usr/home/shivank/freebsd/sys/amd64/amd64/trap.c:578
#8  <signal handler called>
#9  kdb_enter (why=0xffffffff81237e07 "panic", msg=<optimized out>)
    at /usr/home/shivank/freebsd/sys/kern/subr_kdb.c:486
#10 0xffffffff80bc6a5e in vpanic (fmt=<optimized out>, ap=<optimized out>)
    at /usr/home/shivank/freebsd/sys/kern/kern_shutdown.c:902
#11 0xffffffff80bc67f3 in panic (
    fmt=0xffffffff81c8e5e8 <cnputs_mtx> "J\237\037\201\377\377\377\377")
    at /usr/home/shivank/freebsd/sys/kern/kern_shutdown.c:839
#12 0xffffffff80b99822 in _lockmgr_assert (lk=0xfffff80013200068, 
    what=<error reading variable: Cannot access memory at address 0x1>, 
    file=<optimized out>,
```





1. **Where should the audit hooks be added to  efficiently audit the NFS RPC from server?**

I chose to add `AUDIT_NFSRPC_ENTER` and `AUDIT_NFSRPC_EXIT` macros in `nfs_proc()` function defined in `sys/fs/nfsserver/nfs_nfsdkrpc.c` The reason being it call the the `nfsrvd_dorpc` whenever their is some request. These macros are useful to for event preselection(TBD) and allocating/committing the new record.

When the thread will be servicing the RPC, the desirable RPC arguments can audited using the AUDIT_ARG_* macros.

2. **What all information has to be audited and recorded in log files?**

- Each RPC has to be audited and various desired argument in it should be audited. 

- To clarify above point: The client(subject) information, the NFS RPC request made by it and files etc, it accessed or modified.

- This all information that would have appeared in client's audit record if it'd be audit(4) runs on client.

  | NFSv3 RPC Service                                            | Argument | Status |
  | ------------------------------------------------------------ | -------- | ------ |
  | nfsrvd_getattr                                               |          |        |
  | nfsrvd_setattr                                               |          |        |
  | nfsrvd_lookup                                                |          |        |
  | nfsrvd_access                                                |          |        |
  | nfsrvd_readlink                                              |          |        |
  | nfsrvd_read                                                  |          |        |
  | nfsrvd_write                                                 |          |        |
  | nfsrvd_create                                                |          |        |
  | nfsrvd_mkdir                                                 |          |        |
  | nfsrvd_symlink                                               |          |        |
  | nfsrvd_mknod                                                 |          |        |
  | nfsrvd_remove                                                |          |        |
  | nfsrvd_rmdir                                                 |          |        |
  | nfsrvd_rename                                                |          |        |
  | nfsrvd_link                                                  |          |        |
  | nfsrvd_readdir                                               |          |        |
  | nfsrvd_readdirplus                                           |          |        |
  | nfsrvd_statfs                                                |          |        |
  | nfsrvd_fsinfo                                                |          |        |
  | nfsrvd_pathconf                                              |          |        |
  | nfsrvd_commit                                                |          |        |
  
  

3. **How would the audit(4) would be interpret the NFS records and show it ?**

New cases for handling NFS RPC evennts will have to be defined in kaudit_to_bsm.

The new event can be mentioned here: contrib/openbsm/etc/audit_event. This will install them as default files when compiling from source.

4. **Do we need to define new audit event type, audit token for this new support? or Use currently defined?**

We will need to create new AUE_ events for each NFS RPC, since there is no 1:1 relationship between syscalls and RPCs.

5. **How would the NFS audit record look like?**

a. HEADER_TOKEN - can we use **Expanded Header Token** here and the Machine Address field to store client info?? See `struct auditinfo_addr`
b. SUBJECT TOKEN - information of the subject: some token describing subect info. The subject/process token for syscall audit have cred of the thread. In case  of NFS audit, do I need to overwrite it to reflect creds of the client. struct au_tid_addr can be used to reflect those info. Code place: kaudit_to_bsm, audit_record_ctor.
If this the process token (audit_arg_process) or subject token, which of these?
c. information of the object affected by event. (that is some token describing file)
d. event-specific information: some token depending on RPC. for instance, it can describing a file, some attr, or some text, or IP address etc. See bsm_token.c and audit.log(5) for all such possibilty.
e. return token

Can I add a new token(NFS RPC) for the associating the already defined events(AUE_OPEN, etc.) and this wil differentiate the NFS server audit records when a client access the NFS shared dir v/s when some user on server access the NFS shared dir

If not above solution, then Do I need the define new audit events that are associated with RPC calls(and not on sycalls)?

Is there some other way?

6. **Where the NFS process will keep the record?**

We can't use td_ar field of struct thread for storing the audit record. Therefore, I chose struct nfsrv_descript for that purpose.



#### Doubts while deploying the above design-
*DONE* difference b/w socket addr - nd_nam and return socket addr - nd_nam2
  nd.nd_nam = svc_getrpccaller(rqst);
	nd.nd_nam2 = rqst->rq_addr; comment is reply address or NULL if connected
for logging the client info which should I choose?
2. *TODO* audit_bsm: /* XXX Need to handle ARG_SADDRINET6 */
Why it's not handled in audit? Is there any challenge in handling the case similiar to IPv4.
*DONE* NFS RPC Service extracts the info(that interests us, example- path) at some later point in the function and do error checking in initial stage. This make is difficult to log the complete info, as the flow may be sent to out/return if there is an error at initial stage. It may cause the loss of info, we may want to log.

#### References and Study material
1. Oracle Docs: https://docs.oracle.com/cd/E19683-01/806-4078/6jd6cjs6k/index.html, https://docs.oracle.com/cd/E19109-01/tsolaris8/816-1049/index.html
2. man pages: audit(4), audit.log(5), audit_class(5), audit_control(5), audit_event(5), audit_user(5)
3. https://wiki.freebsd.org/AddingAuditEvents
4. FreeBSD Book: 5.11 SECURITY EVENT AUDITING: https://learning.oreilly.com/library/view/the-design-and/9780133761825/ch05.html
5. FreeBSD Book: 11 NETWORK FILE SYSTEM: https://learning.oreilly.com/library/view/the-design-and/9780133761825/ch11.html
6. FreeBSD Handbook Chapter 16 and 29.3: https://www.freebsd.org/doc/handbook/audit.html, https://www.freebsd.org/doc/handbook/network-nfs.html
7. http://www.watson.org/~robert/freebsd/2006ukuuglisa/20060323-ukuug2006lisa-audit.pdf
8. NFS Specification: https://tools.ietf.org/html/rfc1813#page-32
