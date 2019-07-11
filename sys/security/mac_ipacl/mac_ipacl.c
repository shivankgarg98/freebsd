/* MAC policy module for limiting IP address to a VNET enabled jail */


#include <sys/param.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/jail.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet6/scope6_var.h>

#include <security/mac/mac_policy.h>

SYSCTL_DECL(_security_mac);

static SYSCTL_NODE(_security_mac, OID_AUTO, ipacl, CTLFLAG_RW, 0,
    "TrustedBSD mac_ipacl policy controls");

static int ipacl_enabled = 1;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, enabled, CTLFLAG_RWTUN,
    &ipacl_enabled, 0, "Enforce mac_ipacl policy");
/*
 * sysctl enabled has became obsolete, though used in module
 * it can be removed with minor changes
 */

static int ipacl_ipv4 = 1;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, ipv4, CTLFLAG_RWTUN,
    &ipacl_ipv4, 0, "Enforce mac_ipacl for IPv4 addresses");

static int ipacl_ipv6 = 1;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, ipv6, CTLFLAG_RWTUN,
    &ipacl_ipv6, 0, "Enforce mac_ipacl for IPv6 addresses");

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
/*inspired from struct pf_addr*/	
#define v4	ipa.ipv4
#define v6	ipa.ipv6
#define addr8	ipa.addr8
#define addr16	ipa.addr16
#define addr32	ipa.addr32
};


struct ip_rule {
	int			jid; /* or name it int pr_id?*/
	bool			allow; /*allow or deny */
	char			if_name[IFNAMSIZ]; /*network interface name*/
	int			af; /*address family, can be ipv4, ipv6 or hw_addr(later)*/	
	struct	ipacl_addr	addr;
	struct	ipacl_addr	mask;
	TAILQ_ENTRY(ip_rule)	r_entries; /* queue */ 
				  
};
/* This is copy paste from mac_portacl, the rules and queue will 
 * be same as that of port_acl, can be modified if felt need
 */
static struct mtx			rule_mtx;
static TAILQ_HEAD(rulehead, ip_rule)	rule_head;
static char				rule_string[MAC_RULE_STRING_LEN];

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
 * Note: parsing routines are destructive on the passed string.
 */

static int
parse_rule_element(char *element, struct ip_rule **rule)
{
	char *jid, *allow, *if_name, *fam, *ip_addr, *mask, *p;
	struct ip_rule *new;
	int error, prefix, i, j;

	error = 0;
	new = malloc(sizeof(*new), M_IPACL, M_ZERO | M_WAITOK);

	jid = strsep(&element, "@"); /*specifying the jail_name/jid instead
				       of only jid will be done later*/
	if (jid == NULL) {
		error = EINVAL;
		goto out;
	}/*jail wildcard?*/
	new->jid = strtol(jid, &p, 10);
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}
	allow = strsep(&element, "@");
	if (allow == NULL) {
		error = EINVAL;
		goto out;
	}
	new->allow=strtol(allow, &p, 10);
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}
	if_name = strsep(&element, "@");/*add len restriction=IF_NAMESIZE for name*/
	if (sizeof(if_name) > IF_NAMESIZE) {
		error = EINVAL;
		goto out;
	}
	/* empty = wildcard to all interfaces*/
	bzero(new->if_name, IF_NAMESIZE);
	bcopy(if_name, new->if_name, strlen(if_name));
	fam = strsep(&element, "@");
	if (fam == NULL) {
		error = EINVAL;
		goto out;
	}

	new->af = (strcmp(fam, "AF_INET") == 0) ? AF_INET : 
             (strcmp(fam, "AF_INET6") == 0) ? AF_INET6 : -1;
	if (new->af == -1) {
		error = EINVAL;
		goto out;
	}	

	ip_addr = strsep(&element, "@");
	if (ip_addr == NULL) {
		error = EINVAL;
		goto out;
	}
	if (inet_pton(new->af, ip_addr, new->addr.addr32) != 1) {
		error = EINVAL;
		goto out;
	}
	mask = element;
	if (mask == NULL) {
		error = EINVAL;
		goto out;
	}
	prefix = strtol(mask, &p, 10);
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}
	if (new->af == AF_INET) {
		if (prefix < 0 || prefix > 32) {
			error = EINVAL;
			goto out;
		}
		if (prefix == 0)
			new->mask.addr32[0] = htonl(0);

		else
			new->mask.addr32[0] = htonl(~((1 << (32 - prefix)) - 1));
	}
	else {
		if (prefix < 0 || prefix > 128) {
			error = EINVAL;
			goto out;
		}
		for (i = prefix, j = 0; i > 0; i -= 8, ++j)
  			new->mask.addr8[j] = i >= 8 ? 0xff
				: (unsigned long)((0xffU << (8 - i)) & 0xffU);
	}

out:
	if (error != 0) {
		free(new, M_IPACL);
		*rule = NULL;
	} else
		*rule = new;
	return (error);
}

/* parsing rule- jid@allow@interface_name@addr_family@ip_addr@subnet_mask
 * Eg:sysctl security.mac.ipacl.rules=1@1@epair0b@AF_INET@192.168.42.2@24,0@0@epair0b@AF_INET6@FE80::0202:B3FF:FE1E:8329@64
 */

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
sysctl_rules(SYSCTL_HANDLER_ARGS)
{
	char *string, *copy_string, *new_string;
	struct rulehead head, save_head;
	int error;

	new_string = NULL;
	if (req->newptr != NULL) {
		new_string = malloc(MAC_RULE_STRING_LEN, M_IPACL,
		    M_WAITOK | M_ZERO);
		mtx_lock(&rule_mtx);
		strcpy(new_string, rule_string);
		mtx_unlock(&rule_mtx);
		string = new_string;
	} else
		string = rule_string;

	error = sysctl_handle_string(oidp, string, MAC_RULE_STRING_LEN, req);
	if (error)
		goto out;

	if (req->newptr != NULL) {
		copy_string = strdup(string, M_IPACL);
		TAILQ_INIT(&head);
		error = parse_rules(copy_string, &head);
		free(copy_string, M_IPACL);
		if (error)
			goto out;

		TAILQ_INIT(&save_head);
		mtx_lock(&rule_mtx);
		TAILQ_CONCAT(&save_head, &rule_head, r_entries);
		TAILQ_CONCAT(&rule_head, &head, r_entries);
		strcpy(rule_string, string);
		mtx_unlock(&rule_mtx);
		toast_rules(&save_head);
	}
out:
	if (new_string != NULL)
		free(new_string, M_IPACL);
	return (error);
}

SYSCTL_PROC(_security_mac_ipacl, OID_AUTO, rules,
       CTLTYPE_STRING|CTLFLAG_RW, 0, 0, sysctl_rules, "A", "IP ACL Rules");

/*
 * rough printing rules for debugging purposes
 */
static int
rule_printf(){
	struct ip_rule *rule;
	char buf[32];
	char buf6[128];

	for (rule = TAILQ_FIRST(&rule_head);
	    rule != NULL;
	    rule = TAILQ_NEXT(rule, r_entries)) {
		printf("jid=%d allow=%d family=%d\n",rule->jid, rule->allow, rule->af);
		if (rule->af == AF_INET) {
			if (inet_ntop(AF_INET, &(rule->addr.v4), buf, sizeof(buf)) != NULL)
				printf("inet addr: %s\n", buf);
			if (inet_ntop(AF_INET, &(rule->mask.v4), buf, sizeof(buf)) != NULL)
				printf("mask addr: %s\n", buf);
		}
		else if (rule->af == AF_INET6) {
			if (inet_ntop(AF_INET6, &(rule->addr.v6), buf6, sizeof(buf6)) != NULL)
				printf("inet6 addr: %s\n", buf6);
			if (inet_ntop(AF_INET6, &(rule->mask.v6), buf6, sizeof(buf6)) != NULL)
				printf("mask addr: %s\n", buf6);
		}
	}
	return 0; 
}

static int
rules_check(struct ucred *cred,
   struct ipacl_addr *ip_addr, struct ifnet *ifp)
{
	struct ip_rule *rule;
	int error;
	char buf[INET_ADDRSTRLEN];
	char buf6[INET6_ADDRSTRLEN];	

	error = EPERM;
	
	mtx_lock(&rule_mtx);
	
	for (rule = TAILQ_FIRST(&rule_head);
	    rule != NULL;
	    rule = TAILQ_NEXT(rule, r_entries)) {
		
		/*skip if current rule is for different jail*/
		if(cred->cr_prison->pr_id != rule->jid)
			continue;
		if (strcmp(rule->if_name, "\0") && strcmp(rule->if_name, ifp->if_xname))
			continue;

		switch (rule->af) {
			case AF_INET:
				if (inet_ntop(AF_INET, &(ip_addr->addr32), buf, sizeof(buf)) != NULL)
					printf("to check ipv4: %s\n", buf);
				if (ip_addr->v4.s_addr != rule->addr.v4.s_addr)
					continue;
				break;
			case AF_INET6:
				if (inet_ntop(AF_INET6, &(ip_addr->addr32), buf6, sizeof(buf6)) != NULL)
					printf("to  check ipv6: %s\n", buf6);
				if (bcmp(&rule->addr, ip_addr, sizeof(*ip_addr))) /*as called in pf.c:685*/
					continue;
				break;
			default:
				error = EINVAL;
		}
		if (rule->allow)
			error = 0;
		/*subnet check is remaining*/
	}

	mtx_unlock(&rule_mtx);

	return (error);
}

static int
ipacl_ip4_check_jail(struct ucred *cred,
    const struct in_addr *ia, struct ifnet *ifp)
{
	struct ipacl_addr ip4_addr;
	ip4_addr.v4 = *ia;
	/*function only when ipacl is enabled and it is a jail*/
	if (!ipacl_enabled || !jailed(cred))
		return 0;
	rule_printf();

	/*if policy is enforced for ip4 address then check with rules
	 * else return 0
	 */
	if (ipacl_ipv4)
		return rules_check(cred, &ip4_addr, ifp);

	return 0;
}

static int
ipacl_ip6_check_jail(struct ucred *cred,
    const struct in6_addr *ia6, struct ifnet *ifp)
{
	struct ipacl_addr ip6_addr;
	ip6_addr.v6 = *ia6; /*make copy to not alter the original*/
	in6_clearscope(&ip6_addr.v6);/* clear scope id*/
	
	char buf6[INET6_ADDRSTRLEN];	
	printf("\nIPV6_SPRINTF = %s\n",ip6_sprintf(buf6, ia6));
	printf("\nIPV6_SPRINTF COPIED= %s\n",ip6_sprintf(buf6, &ip6_addr.v6));

	rule_printf();
	/*function only when ipacl is enabled and it is a jail*/
	if (!ipacl_enabled || !jailed(cred))
		return 0;
	
	/*if policy is enforced for ip6 address then check with rules
	 * else return 0
	 */

	if (ipacl_ipv6)
		return rules_check(cred, &ip6_addr, ifp);
	
	return 0;
}

static struct mac_policy_ops ipacl_ops =
{
	.mpo_init = ipacl_init,
	.mpo_destroy = ipacl_destroy,
	.mpo_ip4_check_jail = ipacl_ip4_check_jail,
	.mpo_ip6_check_jail = ipacl_ip6_check_jail,
};

MAC_POLICY_SET(&ipacl_ops, mac_ipacl, "TrustedBSD MAC/ipacl",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
