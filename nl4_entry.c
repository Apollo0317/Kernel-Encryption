/**
 * @Author: Mark Hong
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

#include "nl4_entry.h"

static u32 remote_addr = 0;
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
	atomic64_t gso_count;
	atomic64_t nonlinear_count;
	atomic64_t ensure_writable_fail_count;
};

static struct nl4_perf_stats nl4_perf_in;
static struct nl4_perf_stats nl4_perf_out;

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
	       "prepare_ns=%llu crypto_ns=%llu checksum_ns=%llu gso=%llu "
	       "nonlinear=%llu writable_fail=%llu\n",
	       tag,
	       atomic64_read(&stats->packets),
	       atomic64_read(&stats->bytes),
	       atomic64_read(&stats->hook_ns),
	       atomic64_read(&stats->prepare_ns),
	       atomic64_read(&stats->crypto_ns),
	       atomic64_read(&stats->checksum_ns),
	       atomic64_read(&stats->gso_count),
	       atomic64_read(&stats->nonlinear_count),
	       atomic64_read(&stats->ensure_writable_fail_count));
}

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

	if (skb_is_gso(skb)) {
		nl4_perf_inc(&stats->gso_count);
		return -EOPNOTSUPP;
	}

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

int remoteAllowed(struct iphdr *iph, int bound)
{
	u32 tmp_addr = (bound==INBOUND)?iph->saddr:iph->daddr;
	if (tmp_addr==remote_addr)
		return 1;
	else
		return 0;
}

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
	u8 proto;
	int ret;
	u64 hook_start = nl4_perf_now();
	u64 step_start;
    // struct tcphdr *tcph = NULL;

	iph = ip_hdr(skb);
	if (iph == NULL || !remoteAllowed(iph, INBOUND))
		goto out_accept;
	proto = iph->protocol;

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
						    DECRYPTION);
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
				return NF_ACCEPT;
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
	u8 proto;
	int ret;
	u64 hook_start = nl4_perf_now();
	u64 step_start;
	// struct tcphdr *tcph = NULL;

	iph = ip_hdr(skb);
	if (iph == NULL || !remoteAllowed(iph, OUTBOUND))
		goto out_accept;
	proto = iph->protocol;

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
						    l4_hdr, ENCRYPTION);
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
				return NF_ACCEPT;
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

	remote_addr = IP2NUM(REMOTE_IP);

	ret = nl4_crypto_init();
	if (ret < 0) {
		printk(KERN_LOG "Crypto Init Error.\n");
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nfhk_local_in);
	if (ret < 0) {
        printk("INBOUND Module Register Error.\n");
		nl4_crypto_exit();
        return ret;
    }

	ret = nf_register_net_hook(&init_net, &nfhk_local_out);
	if (ret < 0) {
        printk("OUTBOUND Module Register Error.\n");
		nf_unregister_net_hook(&init_net, &nfhk_local_in);
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
