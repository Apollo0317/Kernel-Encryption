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

module_param(nl4_debug, int, 0644);
MODULE_PARM_DESC(nl4_debug, "Enable nl4 debug logging");

static void nl4_log_tcp(const char *tag, struct iphdr *iph,
			 struct tcphdr *tcph, unsigned int total_len,
			 unsigned int ip_hdr_len, unsigned int tcp_hdr_len,
			 unsigned int payload_len, int padding_len,
			 int tailroom, struct sk_buff *skb)
{
	if (!nl4_debug)
		return;
	printk(KERN_LOG " %s TCP %pI4:%u -> %pI4:%u seq=%u ack=%u "
	       "flags=S%dA%dF%dR%dP%d tot=%u ihl=%u thl=%u pay=%u pad=%d "
	       "skb_len=%u tailroom=%d summed=%u gso=%u\n",
	       tag,
	       &iph->saddr, ntohs(tcph->source),
	       &iph->daddr, ntohs(tcph->dest),
	       ntohl(tcph->seq), ntohl(tcph->ack_seq),
	       tcph->syn, tcph->ack, tcph->fin, tcph->rst, tcph->psh,
	       total_len, ip_hdr_len, tcp_hdr_len, payload_len, padding_len,
	       skb->len, tailroom, skb->ip_summed, skb_is_gso(skb));
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
	int ret;
    // struct tcphdr *tcph = NULL;

	/* Only linearize when the skb payload is fragmented. */
	if (skb_is_nonlinear(skb) && unlikely(skb_linearize(skb) != 0))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, INBOUND))
	{
		total_len = ntohs(iph->tot_len);
		ip_hdr_len = iph->ihl * 4;
		if (total_len < ip_hdr_len)
			return NF_ACCEPT;
		if (get_l4_info(iph, total_len, &l4_hdr, &l4_hdr_len) != 0)
			return NF_ACCEPT;
		if (total_len < ip_hdr_len + l4_hdr_len)
			return NF_ACCEPT;

		//a. extract cipher payload (exclude L4 header)
		data_len = total_len - ip_hdr_len - l4_hdr_len;
		if (data_len == 0) {
			if (iph->protocol == IPPROTO_TCP)
				nl4_log_tcp_skip("in", "no-payload", iph, l4_hdr,
						 total_len, ip_hdr_len, l4_hdr_len,
						 data_len, skb);
			return NF_ACCEPT;
		}
		payload = (char *)l4_hdr + l4_hdr_len;

		/* Stream cipher decrypts in place without changing payload length. */
		ret = nl4_crypto_cipher(payload, data_len, DECRYPTION);
		if (ret != 0)
			return NF_ACCEPT;
		if (iph->protocol == IPPROTO_TCP)
			nl4_log_tcp("in stream", iph, l4_hdr, total_len, ip_hdr_len,
				    l4_hdr_len, data_len, 0, -1, skb);

		//c. re-checksum for L4 and IP
		update_l4_checksum(iph, l4_hdr, total_len - ip_hdr_len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
	}

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
	int ret;
	// struct tcphdr *tcph = NULL;

	/* Only linearize when the skb payload is fragmented. */
	if (skb_is_nonlinear(skb) && unlikely(skb_linearize(skb) != 0))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, OUTBOUND))
	{
		total_len = ntohs(iph->tot_len);
		ip_hdr_len = iph->ihl * 4;
		if (total_len < ip_hdr_len)
			return NF_ACCEPT;
		if (get_l4_info(iph, total_len, &l4_hdr, &l4_hdr_len) != 0)
			return NF_ACCEPT;
		if (total_len < ip_hdr_len + l4_hdr_len)
			return NF_ACCEPT;

		//a. encrypt payload in place without resizing skb
		payload_len = total_len - ip_hdr_len - l4_hdr_len;
		if (payload_len == 0) {
			if (iph->protocol == IPPROTO_TCP)
				nl4_log_tcp_skip("out", "no-payload", iph, l4_hdr,
						 total_len, ip_hdr_len, l4_hdr_len,
						 payload_len, skb);
			return NF_ACCEPT;
		}
		if (iph->protocol == IPPROTO_TCP)
			nl4_log_tcp("out stream", iph, l4_hdr, total_len, ip_hdr_len,
				    l4_hdr_len, payload_len, 0,
				    skb_tailroom(skb), skb);

		/* Stream cipher keeps total_len and iph->tot_len unchanged. */
		payload = (char *)l4_hdr + l4_hdr_len;
		ret = nl4_crypto_cipher(payload, payload_len, ENCRYPTION);
		if (ret != 0)
			return NF_ACCEPT;

		//c. re-checksum for L4 and IP
		update_l4_checksum(iph, l4_hdr, total_len - ip_hdr_len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
	}

	return NF_ACCEPT;
}

static int nl4_init(void)
{
	unsigned int ret;

	remote_addr = IP2NUM(REMOTE_IP);

	ret = nf_register_net_hook(&init_net, &nfhk_local_in);
	if (ret < 0) {
        printk("INBOUND Module Register Error.\n");
        return ret;
    }

	ret = nf_register_net_hook(&init_net, &nfhk_local_out);
	if (ret < 0) {
        printk("OUTBOUND Module Register Error.\n");
        return ret;
    }

    printh("NL4 Suite Init ...\n");
	return 0;
}

static void nl4_fini(void)
{
	nf_unregister_net_hook(&init_net, &nfhk_local_in);
	nf_unregister_net_hook(&init_net, &nfhk_local_out);
	printh("NL4 Suite Exit ...\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Apollo");
module_init(nl4_init);
module_exit(nl4_fini);
