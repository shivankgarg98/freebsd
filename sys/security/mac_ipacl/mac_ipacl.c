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
#include <sys/jail.h>

#include <security/mac/mac_policy.h>

SYSCTL_DECL(_security_mac);
static SYSCTL_NODE(_security_mac, OID_AUTO, ipacl, CTLFLAG_RW, 0,
    "TrustedBSD mac_ipacl policy controls");

static int ipacl_enabled = 1;

SYSCTL_INT(_security_mac_ipacl, OID_AUTO, enabled, CTLFLAG_RWTUN,
    &ipacl_enabled, 0, "Enforce mac_ipacl policy");

/*
 * enforce this policy only on jail for now
 * sysctl ipv4 and ipv6 to allow/disallow jail
 */

static int ipacl_ipv4 = 1;

SYSCTL_INT(_security_mac_ipacl, OID_AUTO, ipv4, CTLFLAG_RWTUN,
    &ipacl_ipv4, 0, "allow IPv4 address for interfaces");

static int ipacl_ipv6 = 1;

SYSCTL_INT(_security_mac_ipacl, OID_AUTO, ipv6, CTLFLAG_RWTUN,
    &ipacl_ipv6, 0, "allow IPv6 address for interfaces");

static void ipacl_init(struct mac_policy_conf *conf)
{
	printf("\t INIT: macip_acl loaded\n");
}

static void ipacl_destroy(struct mac_policy_conf *conf)
{
	printf("\t DESTROY: mac_ipacl unloaded\n");
}

static int ipacl_ip4_check_jail(struct ucred *cred, const struct in_addr *ia)
{
	/*function only when ipacl is enabled and it is a jail*/
	if(!ipacl_enabled || !jailed(cred))
		return 0;
	
	if(ipacl_ipv4)
		return 0;

	return (EPERM);
}

static int ipacl_ip6_check_jail(struct ucred *cred, const struct in6_addr *ia6)
{
	/*function only when ipacl is enabled and it is a jail*/
	if(!ipacl_enabled || !jailed(cred))
		return 0;
	
	if(ipacl_ipv6)
		return 0;

	return (EPERM);
}

static struct mac_policy_ops ipacl_ops =
{

	.mpo_init = ipacl_init,
	.mpo_destroy = ipacl_destroy,
	.mpo_ip4_check_jail = ipacl_ip4_check_jail,
	.mpo_ip6_check_jail = ipacl_ip6_check_jail,
	
	/*
	 *
	 */
};

MAC_POLICY_SET(&ipacl_ops, mac_ipacl, "TrustedBSD MAC/ipacl",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);

