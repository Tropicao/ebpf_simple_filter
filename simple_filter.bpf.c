#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
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
	struct iphdr *ip;
	int *count;
	int key=0;

	if (eth + 1 > data_end)
		return XDP_DROP;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = data+sizeof(struct ethhdr);

	if (ip + 1 > data_end)
		return XDP_DROP;

	if (ip->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	char fmt[] = "Dropping ICMP packet !";
	bpf_trace_printk(fmt, sizeof(fmt));
	count = bpf_map_lookup_elem(&drop_count, &key);
	if (count)
		*count+=1;

	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
