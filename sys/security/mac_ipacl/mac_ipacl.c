/* MAC policy module for limiting IP address to a VNET enabled jail */

/*
 * KLD Skeleton
 * Inspired by Andrew Reiter's Daemonnews article
 */

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/kernel.h> /* types used in module initialization */
/*
 * Load handler that deals with the loading and unloading of a KLD.
 */

static int mac_ipacl_loader(struct module *m, int what, void *arg)
{
  int err = 0;

  switch (what) {
  case MOD_LOAD:                /* kldload */
    uprintf("-> mac_ipacl loaded.\n");
    break;
  case MOD_UNLOAD:
    uprintf("-> mac_ipacl unloaded.\n");
    break;
  default:
    err = EOPNOTSUPP;
    break;
  }
  return(err);
}

/* Declare this module to the rest of the kernel */

static moduledata_t skel_mod = {
  "MAC IP ACL",
  mac_ipacl_loader,
  NULL
};

DECLARE_MODULE(mac_ipacl, skel_mod, SI_SUB_KLD, SI_ORDER_ANY);
