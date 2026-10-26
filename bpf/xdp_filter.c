#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

char LICENSE[] SEC("license") = "GPL";

struct vlan_hdr {
    __be16 tci;
    __be16 proto;
};

static __always_inline struct iphdr *ipv4_header(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return NULL;
    }
    __u16 proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    if (proto == ETH_P_8021Q) {
        struct vlan_hdr *vh = nh;

        if ((void *)(vh + 1) > data_end) {
            return NULL;
        }
        proto = bpf_ntohs(vh->proto);
        nh = (void *)(vh + 1);
    }

    if (proto != ETH_P_IP) {
        return NULL;
    }

    struct iphdr *ip = nh;

    if ((void *)(ip + 1) > data_end) {
        return NULL;
    }
    if (ip->version != 4 || ip->ihl != 5) {
        return NULL;
    }
    return ip;

}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    struct iphdr *ip = ipv4_header(ctx);

    if (ip) {
        asm volatile("" :: "r"(ip->saddr));
    }
    return XDP_PASS;
}