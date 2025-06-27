#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} drop_count SEC(".maps");

SEC("xdp")
int drop_icmp(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;
	struct iphdr *ip;
	int *count;
	int key=0;
	__u8 protocol;

	if (eth + 1 > data_end)
		return XDP_DROP;

	switch (eth->h_proto) {
		case bpf_htons(ETH_P_IP):
			ip = data+sizeof(struct ethhdr);
			if (ip + 1 > data_end)
				return XDP_DROP;
			if (ip->protocol != IPPROTO_ICMP)
				return XDP_PASS;
			break;
		case bpf_htons(ETH_P_IPV6):
			ip6 = data+sizeof(struct ethhdr);
			if (ip6 + 1 > data_end)
				return XDP_DROP;
			if (ip6->nexthdr != IPPROTO_ICMPV6)
				return XDP_PASS;
			break;
		default:
			return XDP_PASS;
	}

	char fmt[] = "Dropping ICMP packet !";
	bpf_trace_printk(fmt, sizeof(fmt));
	count = bpf_map_lookup_elem(&drop_count, &key);
	if (count)
		*count+=1;

	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
