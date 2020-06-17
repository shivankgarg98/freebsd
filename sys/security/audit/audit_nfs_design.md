## **audit(4) support to NFS: idea and design document**



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
b. information of the subject: some token describing subect info. 
c. information of the object affected by event. (that is some token describing file)
c. event-specific information: some token depending on RPC. for instance, it can describing a file, some attr, or some text, or IP address etc. See bsm_token.c and audit.log(5) for all such possibilty.
d. return token

Can I add a new token(NFS RPC) for the associating the already defined events(AUE_OPEN, etc.) and this wil differentiate the NFS server audit records when a client access the NFS shared dir v/s when some user on server access the NFS shared dir

If not above solution, then Do I need the define new audit events that are associated with RPC calls(and not on sycalls)?

Is there some other way?

6. **Where the NFS process will keep the record?**

We can't use td_ar field of struct thread for storing the audit record. Therefore, I chose struct nfsrv_descript for that purpose.



#### Doubts while deploying the above design-


#### References and Study material
1. Oracle Docs: https://docs.oracle.com/cd/E19683-01/806-4078/6jd6cjs6k/index.html, https://docs.oracle.com/cd/E19109-01/tsolaris8/816-1049/index.html
2. man pages: audit(4), audit.log(5), audit_class(5), audit_control(5), audit_event(5), audit_user(5)
3. https://wiki.freebsd.org/AddingAuditEvents
4. FreeBSD Book: 5.11 SECURITY EVENT AUDITING: https://learning.oreilly.com/library/view/the-design-and/9780133761825/ch05.html
5. FreeBSD Book: 11 NETWORK FILE SYSTEM: https://learning.oreilly.com/library/view/the-design-and/9780133761825/ch11.html
6. FreeBSD Handbook Chapter 16 and 29.3: https://www.freebsd.org/doc/handbook/audit.html, https://www.freebsd.org/doc/handbook/network-nfs.html
7. http://www.watson.org/~robert/freebsd/2006ukuuglisa/20060323-ukuug2006lisa-audit.pdf
