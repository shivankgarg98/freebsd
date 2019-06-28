/* MAC policy module for limiting IP address to a VNET enabled jail */


#include <sys/param.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/jail.h>

#include <netinet/in.h>

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

static MALLOC_DEFINE(M_IPACL, "ipacl_rule", "Rules for mac_ipacl");

#define	MAC_RULE_STRING_LEN	1024

struct ipacl_addr {
	union {
		struct in_addr	ipv4;
		struct in6_addr	ipv6;
		u_int8_t	addr8[16];
		u_int16_t	addr16[8];
		u_int32_t	addr32[4];
	} ipa; /* 128 bit address*/
/*inspired from pf_var.h*/	
#define v4	ipa.ipv4
#define v6	ipa.ipv6
#define addr8	ipa.addr8
#define addr16	ipa.addr16
#define addr32	ipa.addr32
};


struct ip_rule {
	int			jid; /* or name it int pr_id?*/
	bool			allow; /*allow or deny */
	struct			ifnet *ifp; /*network interface*/
	struct			ipacl_addr addr;
	struct			ipacl_addr mask;
	/* currently I am thinking if user gives some special value
	 * to addr, then rule applies for whole subnet/prefix
	 */

	TAILQ_ENTRY(ip_rule)	r_entries; /* queue */ 
				  
};
/* This is copy paste from mac_portacl, the rules and queue will 
 * be same as that of port_acl, can be modified if felt need
 */
static struct mtx			rule_mtx;
static TAILQ_HEAD(rulehead, ip_rule)	rule_head;
//static char				rule_string[MAC_RULE_STRING_LEN];

static void
toast_rules(struct rulehead *head)
{
	struct ip_rule *rule;

	while ((rule = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, rule, r_entries);
		free(rule, M_IPACL);
	}
}

static void
ipacl_init(struct mac_policy_conf *conf)
{
	printf("\t INIT: macip_acl loaded\n");
	mtx_init(&rule_mtx, "rule_mtx", NULL, MTX_DEF);
	TAILQ_INIT(&rule_head);
}

static void
ipacl_destroy(struct mac_policy_conf *conf)
{
	printf("\t DESTROY: mac_ipacl unloaded\n");
	mtx_destroy(&rule_mtx);
	toast_rules(&rule_head);
}

/*
 * to add rule parser, exact format is yet to decide
 * It can be jid:allow:ifp:ipaddr:mask.
 * to see if mask can be given in both way(like 255.0.0.0
 * or /8 as user wish
 */

/*
 * Note: parsing routines are destructive on the passed string.
 */

static int
parse_rule_element(char *element, struct ip_rule **rule)
{
	char *jid, *allow, *ifp, *ipaddr, *mask, *p;
	struct ip_rule *new;
	int error;

	error = 0;
	new = malloc(sizeof(*new), M_IPACL, M_ZERO | M_WAITOK);

	jid = strsep(&element, ":"); /*specifying the jail_name instead
				       of jid will be done later*/
	if (jid == NULL) {
		error = EINVAL;
		goto out;
	}
	new->jid = strtol(jid, &p, 10);
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}
	allow = strsep(&element, ":");
	if (allow == NULL) {
		error = EINVAL;
		goto out;
	}
	new->allow=strtol(allow, &p, 10);
	ifp = strsep(&element, ":");
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}
	if (ifp == NULL) {
		error = EINVAL;
		goto out;
	}
	/*
	 * TO_SEE-HOW TO FIND THE INTERFACE FROM ITS NAME
	 */
	ipaddr = strsep(&element, ":");
	if (ipaddr == NULL) {
		error = EINVAL;
		goto out;
	}
	/*convert string to ip_addr.*/
	mask = element;
	if (mask == NULL) {
		error = EINVAL;
		goto out;
	}
	/*mask can be given as ip_addr or number*/






out:
	if (error != 0) {
		free(new, M_IPACL);
		*rule = NULL;
	} else
		*rule = new;
	return (error);
}

static int
parse_rules(char *string, struct rulehead *head)
{
	struct ip_rule *new;
	char *element;
	int error;

	error = 0;
	while ((element = strsep(&string, ",")) != NULL) {
		if (strlen(element) == 0)
			continue;
		error = parse_rule_element(element, &new);
		if (error)
			goto out;
		TAILQ_INSERT_TAIL(head, new, r_entries);
	}
out:
	if (error != 0)
		toast_rules(head);
	return (error);
}

static int
ipacl_ip4_check_jail(struct ucred *cred,
    const struct in_addr *ia, struct ifnet *ifp)
{
	/*function only when ipacl is enabled and it is a jail*/
	if (!ipacl_enabled || !jailed(cred))
		return 0;
	
	if (ipacl_ipv4)
		return 0;

	return (EPERM);
}

static int
ipacl_ip6_check_jail(struct ucred *cred,
    const struct in6_addr *ia6, struct ifnet *ifp)
{
	/*function only when ipacl is enabled and it is a jail*/
	if (!ipacl_enabled || !jailed(cred))
		return 0;
	
	if (ipacl_ipv6)
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

