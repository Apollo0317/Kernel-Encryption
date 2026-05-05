/**
 * @Author: Mark Hong, Apollo
*/

//Moudle reference
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/list.h>
//Network Reference
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <net/genetlink.h>

#include "nl4_entry.h"
#include <nl4_netlink.h>

static int nl4_debug = 0;
static int nl4_perf = 0;

module_param(nl4_debug, int, 0644);
MODULE_PARM_DESC(nl4_debug, "Enable nl4 debug logging");
module_param(nl4_perf, int, 0644);
MODULE_PARM_DESC(nl4_perf, "Enable nl4 performance counters");

struct nl4_perf_stats {
	atomic64_t packets;
	atomic64_t bytes;
	atomic64_t hook_ns;
	atomic64_t prepare_ns;
	atomic64_t crypto_ns;
	atomic64_t checksum_ns;
	atomic64_t gso_seen;
	atomic64_t gso_encrypt_ok;
	atomic64_t gso_bad_csum_mode;
	atomic64_t gso_prepare_fail;
	atomic64_t gso_drop;
	atomic64_t nonlinear_count;
	atomic64_t ensure_writable_fail_count;
	atomic64_t port_mismatch;
};

static struct nl4_perf_stats nl4_perf_in;
static struct nl4_perf_stats nl4_perf_out;

struct nl4_rule {
	struct list_head list;
	struct rcu_head rcu;
	__be32 remote_ip;
	__be16 service_port;
	u8 service_side;
	u32 shared_key_words[NL4_SHARED_KEY_WORDS];
};

static LIST_HEAD(nl4_rule_list);
static DEFINE_MUTEX(nl4_rule_lock);

static struct genl_family nl4_genl_family;

static const struct nla_policy nl4_genl_policy[NL4_ATTR_MAX + 1] = {
	[NL4_ATTR_REMOTE_IPV4] = { .type = NLA_U32 },
	[NL4_ATTR_SERVICE_SIDE] = { .type = NLA_U8 },
	[NL4_ATTR_SERVICE_PORT] = { .type = NLA_U16 },
	[NL4_ATTR_SHARED_KEY] = { .type = NLA_BINARY, .len = NL4_SHARED_KEY_LEN },
};

static inline u64 nl4_perf_now(void)
{
	return nl4_perf ? ktime_get_ns() : 0;
}

static inline void nl4_perf_add_ns(atomic64_t *counter, u64 start)
{
	if (nl4_perf)
		atomic64_add(ktime_get_ns() - start, counter);
}

static inline void nl4_perf_inc(atomic64_t *counter)
{
	if (nl4_perf)
		atomic64_inc(counter);
}

static inline void nl4_perf_add_count(atomic64_t *counter, u64 value)
{
	if (nl4_perf)
		atomic64_add(value, counter);
}

static void nl4_perf_print_one(const char *tag, struct nl4_perf_stats *stats)
{
	printk(KERN_LOG " PERF %s packets=%llu bytes=%llu hook_ns=%llu "
	       "prepare_ns=%llu crypto_ns=%llu checksum_ns=%llu "
	       "gso_seen=%llu gso_encrypt_ok=%llu gso_bad_csum_mode=%llu "
	       "gso_prepare_fail=%llu gso_drop=%llu nonlinear=%llu "
	       "writable_fail=%llu port_mismatch=%llu\n",
	       tag,
	       atomic64_read(&stats->packets),
	       atomic64_read(&stats->bytes),
	       atomic64_read(&stats->hook_ns),
	       atomic64_read(&stats->prepare_ns),
	       atomic64_read(&stats->crypto_ns),
	       atomic64_read(&stats->checksum_ns),
	       atomic64_read(&stats->gso_seen),
	       atomic64_read(&stats->gso_encrypt_ok),
	       atomic64_read(&stats->gso_bad_csum_mode),
	       atomic64_read(&stats->gso_prepare_fail),
	       atomic64_read(&stats->gso_drop),
	       atomic64_read(&stats->nonlinear_count),
	       atomic64_read(&stats->ensure_writable_fail_count),
	       atomic64_read(&stats->port_mismatch));
}

static int nl4_rule_matches_tcp(const struct nl4_rule *rule,
				const struct tcphdr *tcph, int bound)
{
	if (rule->service_side == NL4_SERVICE_ALL_PORTS)
		return 1;

	switch (rule->service_side) {
	case NL4_SERVICE_REMOTE:
		return bound == OUTBOUND ? tcph->dest == rule->service_port :
					   tcph->source == rule->service_port;
	case NL4_SERVICE_LOCAL:
		return bound == OUTBOUND ? tcph->source == rule->service_port :
					   tcph->dest == rule->service_port;
	default:
		return 0;
	}
}

static struct nl4_rule *nl4_find_rule(__be32 remote_ip,
				      const struct tcphdr *tcph, int bound,
				      struct nl4_perf_stats *stats)
{
	struct nl4_rule *rule;
	int ip_match = 0;

	list_for_each_entry_rcu(rule, &nl4_rule_list, list) {
		if (rule->remote_ip != remote_ip)
			continue;

		ip_match = 1;
		if (nl4_rule_matches_tcp(rule, tcph, bound))
			return rule;
	}

	if (ip_match)
		nl4_perf_inc(&stats->port_mismatch);

	return NULL;
}

static struct nl4_rule *nl4_lookup_rule_skb(struct sk_buff *skb,
					    struct iphdr *iph, int bound,
					    struct nl4_perf_stats *stats)
{
	unsigned int total_len;
	unsigned int ip_hdr_len;
	struct tcphdr _tcph;
	struct tcphdr *tcph = NULL;
	__be32 remote_ip = (bound == INBOUND) ? iph->saddr : iph->daddr;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;

	total_len = ntohs(iph->tot_len);
	ip_hdr_len = iph->ihl * 4;
	if (iph->ihl < 5 || total_len < ip_hdr_len + sizeof(struct tcphdr))
		return NULL;

	tcph = skb_header_pointer(skb, skb_network_offset(skb) + ip_hdr_len,
				  sizeof(_tcph), &_tcph);
	if (!tcph)
		return NULL;

	return nl4_find_rule(remote_ip, tcph, bound, stats);
}

static struct nl4_rule *nl4_find_rule_exact(__be32 remote_ip, u8 service_side,
					    __be16 service_port)
{
	struct nl4_rule *rule;

	list_for_each_entry(rule, &nl4_rule_list, list) {
		if (rule->remote_ip == remote_ip &&
		    rule->service_side == service_side &&
		    rule->service_port == service_port)
			return rule;
	}

	return NULL;
}

static void nl4_free_rule_rcu(struct rcu_head *rcu)
{
	struct nl4_rule *rule = container_of(rcu, struct nl4_rule, rcu);

	kfree(rule);
}

static void nl4_delete_rule_locked(struct nl4_rule *rule)
{
	list_del_rcu(&rule->list);
	call_rcu(&rule->rcu, nl4_free_rule_rcu);
}

static void nl4_flush_rules(void)
{
	struct nl4_rule *rule;
	struct nl4_rule *tmp;

	mutex_lock(&nl4_rule_lock);
	list_for_each_entry_safe(rule, tmp, &nl4_rule_list, list)
		nl4_delete_rule_locked(rule);
	mutex_unlock(&nl4_rule_lock);
}

static int nl4_fill_rule_msg(struct sk_buff *skb, u32 portid, u32 seq,
			     int flags, const struct nl4_rule *rule)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &nl4_genl_family, flags,
			  NL4_CMD_LIST_RULES);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(skb, NL4_ATTR_REMOTE_IPV4, (__force u32)rule->remote_ip) ||
	    nla_put_u8(skb, NL4_ATTR_SERVICE_SIDE, rule->service_side) ||
	    nla_put_u16(skb, NL4_ATTR_SERVICE_PORT, ntohs(rule->service_port)))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int nl4_genl_add_rule(struct sk_buff *skb, struct genl_info *info)
{
	struct nl4_rule *rule;
	__be32 remote_ip;
	__be16 service_port;
	u8 service_side;

	if (!info->attrs[NL4_ATTR_REMOTE_IPV4] ||
	    !info->attrs[NL4_ATTR_SERVICE_SIDE] ||
	    !info->attrs[NL4_ATTR_SERVICE_PORT] ||
	    !info->attrs[NL4_ATTR_SHARED_KEY])
		return -EINVAL;

	remote_ip = (__force __be32)nla_get_u32(info->attrs[NL4_ATTR_REMOTE_IPV4]);
	service_side = nla_get_u8(info->attrs[NL4_ATTR_SERVICE_SIDE]);
	service_port = htons(nla_get_u16(info->attrs[NL4_ATTR_SERVICE_PORT]));
	if (service_side < NL4_SERVICE_REMOTE ||
	    service_side > NL4_SERVICE_SIDE_MAX)
		return -EINVAL;
	if (service_side != NL4_SERVICE_ALL_PORTS && service_port == 0)
		return -EINVAL;
	if (service_side == NL4_SERVICE_ALL_PORTS)
		service_port = 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	rule->remote_ip = remote_ip;
	rule->service_side = service_side;
	rule->service_port = service_port;
	memcpy(rule->shared_key_words, nla_data(info->attrs[NL4_ATTR_SHARED_KEY]),
	       sizeof(rule->shared_key_words));

	mutex_lock(&nl4_rule_lock);
	if (nl4_find_rule_exact(remote_ip, service_side, service_port)) {
		mutex_unlock(&nl4_rule_lock);
		kfree(rule);
		return -EEXIST;
	}
	list_add_tail_rcu(&rule->list, &nl4_rule_list);
	mutex_unlock(&nl4_rule_lock);

	return 0;
}

static int nl4_genl_delete_rule(struct sk_buff *skb, struct genl_info *info)
{
	struct nl4_rule *rule;
	__be32 remote_ip;
	__be16 service_port;
	u8 service_side;
	int ret = -ENOENT;

	if (!info->attrs[NL4_ATTR_REMOTE_IPV4] ||
	    !info->attrs[NL4_ATTR_SERVICE_SIDE] ||
	    !info->attrs[NL4_ATTR_SERVICE_PORT])
		return -EINVAL;

	remote_ip = (__force __be32)nla_get_u32(info->attrs[NL4_ATTR_REMOTE_IPV4]);
	service_side = nla_get_u8(info->attrs[NL4_ATTR_SERVICE_SIDE]);
	service_port = htons(nla_get_u16(info->attrs[NL4_ATTR_SERVICE_PORT]));
	if (service_side < NL4_SERVICE_REMOTE ||
	    service_side > NL4_SERVICE_SIDE_MAX)
		return -EINVAL;
	if (service_side != NL4_SERVICE_ALL_PORTS && service_port == 0)
		return -EINVAL;
	if (service_side == NL4_SERVICE_ALL_PORTS)
		service_port = 0;

	mutex_lock(&nl4_rule_lock);
	rule = nl4_find_rule_exact(remote_ip, service_side, service_port);
	if (rule) {
		nl4_delete_rule_locked(rule);
		ret = 0;
	}
	mutex_unlock(&nl4_rule_lock);

	return ret;
}

static int nl4_genl_flush_rules(struct sk_buff *skb, struct genl_info *info)
{
	nl4_flush_rules();
	return 0;
}

static int nl4_genl_dump_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nl4_rule *rule;
	unsigned long idx = 0;
	unsigned long start = cb->args[0];

	rcu_read_lock();
	list_for_each_entry_rcu(rule, &nl4_rule_list, list) {
		if (idx++ < start)
			continue;
		if (nl4_fill_rule_msg(skb, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, NLM_F_MULTI,
				      rule) < 0)
			break;
		cb->args[0] = idx;
	}
	rcu_read_unlock();

	return skb->len;
}

static const struct genl_ops nl4_genl_ops[] = {
	{
		.cmd = NL4_CMD_ADD_RULE,
		.flags = GENL_ADMIN_PERM,
		.doit = nl4_genl_add_rule,
	},
	{
		.cmd = NL4_CMD_DELETE_RULE,
		.flags = GENL_ADMIN_PERM,
		.doit = nl4_genl_delete_rule,
	},
	{
		.cmd = NL4_CMD_LIST_RULES,
		.dumpit = nl4_genl_dump_rules,
	},
	{
		.cmd = NL4_CMD_FLUSH_RULES,
		.flags = GENL_ADMIN_PERM,
		.doit = nl4_genl_flush_rules,
	},
};

static struct genl_family nl4_genl_family = {
	.name = NL4_GENL_NAME,
	.version = NL4_GENL_VERSION,
	.maxattr = NL4_ATTR_MAX,
	.policy = nl4_genl_policy,
	.module = THIS_MODULE,
	.ops = nl4_genl_ops,
	.n_ops = ARRAY_SIZE(nl4_genl_ops),
};

static void nl4_log_tcp(const char *tag, struct iphdr *iph,
	struct tcphdr *tcph, unsigned int total_len,
			 unsigned int ip_hdr_len, unsigned int tcp_hdr_len,
			 unsigned int payload_len, int padding_len,
			 int tailroom, struct sk_buff *skb)
{
	u32 seq = ntohl(tcph->seq);
	u32 block_index = seq / NL4_TCP_STREAM_BLOCK_SIZE;
	unsigned int skip = seq % NL4_TCP_STREAM_BLOCK_SIZE;

	if (!nl4_debug)
		return;
	printk(KERN_LOG " %s TCP %pI4:%u -> %pI4:%u seq=%u ack=%u "
	       "flags=S%dA%dF%dR%dP%d tot=%u ihl=%u thl=%u pay=%u pad=%d "
	       "block=%u skip=%u skb_len=%u tailroom=%d summed=%u gso=%u "
	       "checksum=recompute\n",
	       tag,
	       &iph->saddr, ntohs(tcph->source),
	       &iph->daddr, ntohs(tcph->dest),
	       seq, ntohl(tcph->ack_seq),
	       tcph->syn, tcph->ack, tcph->fin, tcph->rst, tcph->psh,
	       total_len, ip_hdr_len, tcp_hdr_len, payload_len, padding_len,
	       block_index, skip, skb->len, tailroom, skb->ip_summed,
	       skb_is_gso(skb));
}

static void nl4_log_tcp_skip(const char *tag, const char *reason,
			      struct iphdr *iph, struct tcphdr *tcph,
			      unsigned int total_len, unsigned int ip_hdr_len,
			      unsigned int tcp_hdr_len, unsigned int payload_len,
			      struct sk_buff *skb)
{
	if (!nl4_debug)
		return;
	printk(KERN_LOG " %s TCP skip=%s %pI4:%u -> %pI4:%u seq=%u ack=%u "
	       "tot=%u ihl=%u thl=%u pay=%u skb_len=%u summed=%u gso=%u\n",
	       tag, reason,
	       &iph->saddr, ntohs(tcph->source),
	       &iph->daddr, ntohs(tcph->dest),
	       ntohl(tcph->seq), ntohl(tcph->ack_seq),
	       total_len, ip_hdr_len, tcp_hdr_len, payload_len,
	       skb->len, skb->ip_summed, skb_is_gso(skb));
}

static int get_l4_info(struct iphdr *iph, unsigned int total_len,
				void **l4_hdr, unsigned int *l4_hdr_len)
{
	unsigned int ip_hdr_len = iph->ihl * 4;

	if (iph->ihl < 5 || total_len < ip_hdr_len)
		return -EINVAL;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph;
		unsigned int tcp_hdr_len;

		if (total_len < ip_hdr_len + sizeof(struct tcphdr))
			return -EINVAL;
		tcph = (struct tcphdr *)((u8 *)iph + ip_hdr_len);
		tcp_hdr_len = tcph->doff * 4;
		if (tcp_hdr_len < sizeof(struct tcphdr))
			return -EINVAL;
		if (total_len < ip_hdr_len + tcp_hdr_len)
			return -EINVAL;
		*l4_hdr = tcph;
		*l4_hdr_len = tcp_hdr_len;
		break;
	}
	case IPPROTO_UDP:
		if (total_len < ip_hdr_len + sizeof(struct udphdr))
			return -EINVAL;
		*l4_hdr = (u8 *)iph + ip_hdr_len;
		*l4_hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		if (total_len < ip_hdr_len + sizeof(struct icmphdr))
			return -EINVAL;
		*l4_hdr = (u8 *)iph + ip_hdr_len;
		*l4_hdr_len = sizeof(struct icmphdr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static void update_l4_checksum(struct iphdr *iph, void *l4_hdr,
				      unsigned int l4_len)
{
	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = l4_hdr;

		if (l4_len < sizeof(struct tcphdr))
			return;
		tcph->check = 0;
		tcph->check = tcp_v4_check(l4_len, iph->saddr, iph->daddr,
					 csum_partial((char *)tcph, l4_len, 0));
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = l4_hdr;

		if (l4_len < sizeof(struct udphdr))
			return;
		udph->check = 0;
		udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					 l4_len, IPPROTO_UDP,
					 csum_partial((char *)udph, l4_len, 0));
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmph = l4_hdr;

		if (l4_len < sizeof(struct icmphdr))
			return;
		icmph->checksum = 0;
		icmph->checksum = ip_compute_csum((unsigned char *)icmph,
						 l4_len);
		break;
	}
	default:
		break;
	}
}

static int nl4_prepare_skb(struct sk_buff *skb, struct nl4_perf_stats *stats)
{
	unsigned int total_len;
	struct iphdr *iph;

	if (skb_is_nonlinear(skb)) {
		nl4_perf_inc(&stats->nonlinear_count);
		if (unlikely(skb_linearize(skb) != 0))
			return -ENOMEM;
	}

	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	total_len = ntohs(iph->tot_len);
	if (unlikely(skb_ensure_writable(skb, total_len) != 0)) {
		nl4_perf_inc(&stats->ensure_writable_fail_count);
		return -ENOMEM;
	}

	return 0;
}

static int nl4_tcp_gso_fast_path(struct sk_buff *skb,
				 struct nl4_perf_stats *stats,
				 const u32 key_words[NL4_SHARED_KEY_WORDS],
				 int enc, const char *tag)
{
	unsigned int total_len;
	unsigned int ip_hdr_len;
	unsigned int tcp_hdr_len;
	unsigned int payload_len;
	struct iphdr *iph;
	struct tcphdr *tcph;
	char *payload;
	int ret;

	nl4_perf_inc(&stats->gso_seen);

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		nl4_perf_inc(&stats->gso_bad_csum_mode);
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_TCP) {
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	total_len = ntohs(iph->tot_len);
	ip_hdr_len = iph->ihl * 4;
	if (iph->ihl < 5 || total_len < ip_hdr_len + sizeof(struct tcphdr)) {
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	if (skb_is_nonlinear(skb)) {
		nl4_perf_inc(&stats->nonlinear_count);
		if (unlikely(skb_linearize(skb) != 0)) {
			nl4_perf_inc(&stats->gso_prepare_fail);
			nl4_perf_inc(&stats->gso_drop);
			return -ENOMEM;
		}
	}

	if (unlikely(skb_ensure_writable(skb, total_len) != 0)) {
		nl4_perf_inc(&stats->ensure_writable_fail_count);
		nl4_perf_inc(&stats->gso_prepare_fail);
		nl4_perf_inc(&stats->gso_drop);
		return -ENOMEM;
	}

	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_TCP) {
		nl4_perf_inc(&stats->gso_prepare_fail);
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	total_len = ntohs(iph->tot_len);
	ip_hdr_len = iph->ihl * 4;
	if (iph->ihl < 5 || total_len < ip_hdr_len + sizeof(struct tcphdr)) {
		nl4_perf_inc(&stats->gso_prepare_fail);
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	tcph = (struct tcphdr *)((u8 *)iph + ip_hdr_len);
	tcp_hdr_len = tcph->doff * 4;
	if (tcp_hdr_len < sizeof(struct tcphdr) ||
	    total_len < ip_hdr_len + tcp_hdr_len) {
		nl4_perf_inc(&stats->gso_prepare_fail);
		nl4_perf_inc(&stats->gso_drop);
		return -EINVAL;
	}

	payload_len = total_len - ip_hdr_len - tcp_hdr_len;
	if (payload_len == 0) {
		nl4_log_tcp_skip(tag, "gso-no-payload", iph, tcph, total_len,
				 ip_hdr_len, tcp_hdr_len, payload_len, skb);
		nl4_perf_inc(&stats->gso_encrypt_ok);
		return 0;
	}

	payload = (char *)tcph + tcp_hdr_len;
	nl4_perf_inc(&stats->packets);
	nl4_perf_add_count(&stats->bytes, payload_len);
	ret = nl4_tcp_crypto_cipher(payload, payload_len, iph, tcph,
				    key_words, enc);
	if (ret != 0) {
		nl4_perf_inc(&stats->gso_drop);
		return ret;
	}

	nl4_perf_inc(&stats->gso_encrypt_ok);
	nl4_log_tcp(tag, iph, tcph, total_len, ip_hdr_len, tcp_hdr_len,
		    payload_len, 0, skb_tailroom(skb), skb);
	return 0;
}

static struct nf_hook_ops nfhk_local_in = 
{
	.hook = nf_hookfn_in,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfhk_local_out =
{
	.hook = nf_hookfn_out,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};

unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	unsigned int total_len;
	unsigned int ip_hdr_len;
	unsigned int l4_hdr_len;
	unsigned int data_len;
	char* payload;
	struct iphdr *iph = NULL;
	void *l4_hdr = NULL;
	struct nl4_rule *rule;
	u32 key_words[NL4_SHARED_KEY_WORDS];
	u8 proto;
	int ret;
	u64 hook_start = nl4_perf_now();
	u64 step_start;
    // struct tcphdr *tcph = NULL;

	iph = ip_hdr(skb);
	if (iph == NULL)
		goto out_accept;
	proto = iph->protocol;
	rcu_read_lock();
	rule = nl4_lookup_rule_skb(skb, iph, INBOUND, &nl4_perf_in);
	if (!rule) {
		rcu_read_unlock();
		goto out_accept;
	}
	memcpy(key_words, rule->shared_key_words, sizeof(key_words));
	rcu_read_unlock();

	if (proto == IPPROTO_TCP && skb_is_gso(skb)) {
		step_start = nl4_perf_now();
		ret = nl4_tcp_gso_fast_path(skb, &nl4_perf_in, key_words, DECRYPTION,
					    "in gso stream");
		nl4_perf_add_ns(&nl4_perf_in.crypto_ns, step_start);
		if (ret != 0) {
			printk_ratelimited(KERN_LOG
					   " in TCP GSO fast path failed ret=%d, drop\n",
					   ret);
			nl4_perf_add_ns(&nl4_perf_in.hook_ns, hook_start);
			return NF_DROP;
		}
		goto out_accept;
	}

	step_start = nl4_perf_now();
	ret = nl4_prepare_skb(skb, &nl4_perf_in);
	nl4_perf_add_ns(&nl4_perf_in.prepare_ns, step_start);
	if (ret != 0) {
		if (proto == IPPROTO_TCP) {
			printk_ratelimited(KERN_LOG
					   " in TCP skb prepare failed ret=%d, drop\n",
					   ret);
			nl4_perf_add_ns(&nl4_perf_in.hook_ns, hook_start);
			return NF_DROP;
		}
		goto out_accept;
	}

	iph = ip_hdr(skb);
	if (iph != NULL) {
		total_len = ntohs(iph->tot_len);
		ip_hdr_len = iph->ihl * 4;
		if (total_len < ip_hdr_len)
			goto out_accept;
		if (get_l4_info(iph, total_len, &l4_hdr, &l4_hdr_len) != 0)
			goto out_accept;
		if (total_len < ip_hdr_len + l4_hdr_len)
			goto out_accept;

		//a. extract cipher payload (exclude L4 header)
		data_len = total_len - ip_hdr_len - l4_hdr_len;
		if (data_len == 0) {
			if (iph->protocol == IPPROTO_TCP)
				nl4_log_tcp_skip("in", "no-payload", iph, l4_hdr,
						 total_len, ip_hdr_len, l4_hdr_len,
						 data_len, skb);
			goto out_accept;
		}
		payload = (char *)l4_hdr + l4_hdr_len;

		/* Stream cipher decrypts in place without changing payload length. */
		if (iph->protocol == IPPROTO_TCP) {
			nl4_perf_inc(&nl4_perf_in.packets);
			nl4_perf_add_count(&nl4_perf_in.bytes, data_len);
			step_start = nl4_perf_now();
			ret = nl4_tcp_crypto_cipher(payload, data_len, iph, l4_hdr,
						    key_words, DECRYPTION);
			nl4_perf_add_ns(&nl4_perf_in.crypto_ns, step_start);
			if (ret != 0) {
				printk_ratelimited(KERN_LOG
						   " in TCP crypto failed ret=%d, drop\n",
						   ret);
				nl4_perf_add_ns(&nl4_perf_in.hook_ns, hook_start);
				return NF_DROP;
			}
			nl4_log_tcp("in stream", iph, l4_hdr, total_len, ip_hdr_len,
				    l4_hdr_len, data_len, 0, -1, skb);
		} else {
			ret = nl4_crypto_cipher(payload, data_len, DECRYPTION);
			if (ret != 0)
				goto out_accept;
		}

		//c. re-checksum for L4 and IP
		step_start = nl4_perf_now();
		update_l4_checksum(iph, l4_hdr, total_len - ip_hdr_len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		nl4_perf_add_ns(&nl4_perf_in.checksum_ns, step_start);
	}

out_accept:
	nl4_perf_add_ns(&nl4_perf_in.hook_ns, hook_start);
	return NF_ACCEPT;
}

unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	unsigned int total_len;
	unsigned int ip_hdr_len;
	unsigned int l4_hdr_len;
	unsigned int payload_len;
	char* payload;
	struct iphdr *iph = NULL;
	void *l4_hdr = NULL;
	struct nl4_rule *rule;
	u32 key_words[NL4_SHARED_KEY_WORDS];
	u8 proto;
	int ret;
	u64 hook_start = nl4_perf_now();
	u64 step_start;
	// struct tcphdr *tcph = NULL;

	iph = ip_hdr(skb);
	if (iph == NULL)
		goto out_accept;
	proto = iph->protocol;
	rcu_read_lock();
	rule = nl4_lookup_rule_skb(skb, iph, OUTBOUND, &nl4_perf_out);
	if (!rule) {
		rcu_read_unlock();
		goto out_accept;
	}
	memcpy(key_words, rule->shared_key_words, sizeof(key_words));
	rcu_read_unlock();

	if (proto == IPPROTO_TCP && skb_is_gso(skb)) {
		step_start = nl4_perf_now();
		ret = nl4_tcp_gso_fast_path(skb, &nl4_perf_out, key_words, ENCRYPTION,
					    "out gso stream");
		nl4_perf_add_ns(&nl4_perf_out.crypto_ns, step_start);
		if (ret != 0) {
			printk_ratelimited(KERN_LOG
					   " out TCP GSO fast path failed ret=%d, drop\n",
					   ret);
			nl4_perf_add_ns(&nl4_perf_out.hook_ns, hook_start);
			return NF_DROP;
		}
		goto out_accept;
	}

	step_start = nl4_perf_now();
	ret = nl4_prepare_skb(skb, &nl4_perf_out);
	nl4_perf_add_ns(&nl4_perf_out.prepare_ns, step_start);
	if (ret != 0) {
		if (proto == IPPROTO_TCP) {
			printk_ratelimited(KERN_LOG
					   " out TCP skb prepare failed ret=%d, drop\n",
					   ret);
			nl4_perf_add_ns(&nl4_perf_out.hook_ns, hook_start);
			return NF_DROP;
		}
		goto out_accept;
	}

	iph = ip_hdr(skb);
	if (iph != NULL) {
		total_len = ntohs(iph->tot_len);
		ip_hdr_len = iph->ihl * 4;
		if (total_len < ip_hdr_len)
			goto out_accept;
		if (get_l4_info(iph, total_len, &l4_hdr, &l4_hdr_len) != 0)
			goto out_accept;
		if (total_len < ip_hdr_len + l4_hdr_len)
			goto out_accept;

		//a. encrypt payload in place without resizing skb
		payload_len = total_len - ip_hdr_len - l4_hdr_len;
		if (payload_len == 0) {
			if (iph->protocol == IPPROTO_TCP)
				nl4_log_tcp_skip("out", "no-payload", iph, l4_hdr,
						 total_len, ip_hdr_len, l4_hdr_len,
						 payload_len, skb);
			goto out_accept;
		}
		if (iph->protocol == IPPROTO_TCP)
			nl4_log_tcp("out stream", iph, l4_hdr, total_len, ip_hdr_len,
				    l4_hdr_len, payload_len, 0,
				    skb_tailroom(skb), skb);

		/* Stream cipher keeps total_len and iph->tot_len unchanged. */
		payload = (char *)l4_hdr + l4_hdr_len;
		if (iph->protocol == IPPROTO_TCP) {
			nl4_perf_inc(&nl4_perf_out.packets);
			nl4_perf_add_count(&nl4_perf_out.bytes, payload_len);
			step_start = nl4_perf_now();
			ret = nl4_tcp_crypto_cipher(payload, payload_len, iph,
						    l4_hdr, key_words,
						    ENCRYPTION);
			nl4_perf_add_ns(&nl4_perf_out.crypto_ns, step_start);
			if (ret != 0) {
				printk_ratelimited(KERN_LOG
						   " out TCP crypto failed ret=%d, drop\n",
						   ret);
				nl4_perf_add_ns(&nl4_perf_out.hook_ns, hook_start);
				return NF_DROP;
			}
		} else {
			ret = nl4_crypto_cipher(payload, payload_len, ENCRYPTION);
			if (ret != 0)
				goto out_accept;
		}

		//c. re-checksum for L4 and IP
		step_start = nl4_perf_now();
		update_l4_checksum(iph, l4_hdr, total_len - ip_hdr_len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		nl4_perf_add_ns(&nl4_perf_out.checksum_ns, step_start);
	}

out_accept:
	nl4_perf_add_ns(&nl4_perf_out.hook_ns, hook_start);
	return NF_ACCEPT;
}

static int nl4_init(void)
{
	unsigned int ret;

	ret = nl4_crypto_init();
	if (ret < 0) {
		printk(KERN_LOG "Crypto Init Error.\n");
		return ret;
	}

	ret = genl_register_family(&nl4_genl_family);
	if (ret < 0) {
		printk(KERN_LOG "Generic Netlink Register Error.\n");
		nl4_crypto_exit();
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nfhk_local_in);
	if (ret < 0) {
        printk("INBOUND Module Register Error.\n");
		genl_unregister_family(&nl4_genl_family);
		nl4_crypto_exit();
        return ret;
    }

	ret = nf_register_net_hook(&init_net, &nfhk_local_out);
	if (ret < 0) {
        printk("OUTBOUND Module Register Error.\n");
		nf_unregister_net_hook(&init_net, &nfhk_local_in);
		genl_unregister_family(&nl4_genl_family);
		nl4_crypto_exit();
        return ret;
    }

    printh("NL4 Suite Init ...\n");
	return 0;
}

static void nl4_fini(void)
{
	nf_unregister_net_hook(&init_net, &nfhk_local_in);
	nf_unregister_net_hook(&init_net, &nfhk_local_out);
	genl_unregister_family(&nl4_genl_family);
	nl4_flush_rules();
	if (nl4_perf) {
		nl4_perf_print_one("OUT", &nl4_perf_out);
		nl4_perf_print_one("IN", &nl4_perf_in);
	}
	nl4_crypto_exit();
	printh("NL4 Suite Exit ...\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Apollo");
module_init(nl4_init);
module_exit(nl4_fini);
