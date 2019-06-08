/* MAC policy module for limiting IP address to a VNET enabled jail */


#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/priv.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

SYSCTL_DECL(_security_mac);
static SYSCTL_NODE(_security_mac, OID_AUTO, ipacl, CTLFLAG_RW, 0,
    "TrustedBSD mac_ipacl controls");

static int ipacl_enabled = 1;

SYSCTL_INT(_security_mac_ipacl, OID_AUTO, enabled, CTLFLAG_RWTUN,
    &ipacl_enabled, 0, "Enforce mac_ipacl policy");

/*
 *
 */

/*
 * enforce this policy only on jail
 */


static void ipacl_init(struct mac_policy_conf *conf)
{
	uprintf("\t INIT: macip_acl loaded\n");
}

static void ipacl_destroy(struct mac_policy_conf *conf)
{
	uprintf("\t DESTROY: mac_ipacl unloaded\n");
}


static int ipacl_priv_grant(struct ucred *cred, int priv)
{
	uprintf("\t ipacl_priv_grant +\n ");
/*
 *
 *
 */
	return 0;
}
static int ip4_check_jail(struct ucred *cred, struct label *mlabel,
                   struct in_addr *ia)
{
	/*
	 * label an IPv4 address
	 * 
	 */
	return 0;
}

static int ip6_check_jail(struct ucred *cred, struct label *mlabel,
                   struct in6_addr *ia6)
{
	/*
	 * label an IPv6 address
	 * 
	 */
	return 0;
}

/* Declare this module to the rest of the kernel */

/*
 * adding checks  here
 */

static struct mac_policy_ops ipacl_ops =
{
	.mpo_priv_grant = ipacl_priv_grant,
	.mpo_init = ipacl_init,
	.mpo_destroy = ipacl_destroy,
	.mpo_ip4_check_jail = ip4_check_jail,
	.mpo_ip6_check_jail = ip6_check_jail,
	
	/*
	 *
	 */
};

MAC_POLICY_SET(&ipacl_ops, mac_ipacl, "TrustedBSD MAC/ipacl",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);

