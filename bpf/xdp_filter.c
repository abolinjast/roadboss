#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>


char LICENSE[] SEC("license") = "GPL";

struct vlan_hdr {
    __be16 tci;
    __be16 proto;
};

enum {
    STAT_PASS = 0,
    STAT_DROP_BLOCKLIST,
    STAT_DROP_SYN,
    STAT_DROP_UDP,
    STAT_DROP_FULL,
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct limits_cfg {
    __u32 syn_pps;
    __u32 udp_pps;
};
struct source_rate {
    __u64 window_ns;
    __u32 syn;
    __u32 udp;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct limits_cfg);
} limits SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);
    __type(value, struct source_rate);
} sources SEC(".maps");

static __always_inline void add_stat(__u32 slot)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &slot);
    if (value)
        *value += 1;
}

static __always_inline int account(__u32 src, __u32 limit, int is_udp)
{
    struct source_rate *rate;
    struct source_rate init = {};
    __u64 now;
    if (limit == 0)
        return 0;
    now = bpf_ktime_get_ns();
    rate = bpf_map_lookup_elem(&sources, &src);
    if (!rate) {
        init.window_ns = now;
        if (is_udp)
            init.udp = 1;
        else
            init.syn = 1;
        if (bpf_map_update_elem(&sources, &src, &init, BPF_ANY) < 0)
            return 2;
        return 0;
    }
    if (now - rate->window_ns >= 1000000000ULL) {
        rate->window_ns = now;
        rate->syn = 0;
        rate->udp = 0;
    }
    if (is_udp) {
        if (rate->udp >= limit)
            return 1;
        rate->udp += 1;
    } else {
        if (rate->syn >= limit)
            return 1;
        rate->syn += 1;
    }
    return 0;
}

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
    void *data_end = (void *)(long)ctx->data_end;

    
    struct iphdr *ip = ipv4_header(ctx);

    __u32 src;
    __u32 zero = 0;
    struct limits_cfg *lim;
    __u8 *l4;
    int verdict;

    if (!ip) {
        goto pass;
    }


    src = ip->saddr;
    if (bpf_map_lookup_elem(&blocklist, &src)) {
        add_stat(STAT_DROP_BLOCKLIST);
        return XDP_DROP;
    }
    lim = bpf_map_lookup_elem(&limits, &zero);
    if (!lim) {
        goto pass;
    }
    l4 = (void *)(ip + 1);
    if (ip->protocol == IPPROTO_TCP) {
        if ((void *)(l4 + 20) > data_end) {
            goto pass;
        }
        if ((l4[13] & 0x12) != 0x02) {
            goto pass;
        }
        verdict = account(src, lim->syn_pps, 0);
        if (verdict == 1) {
            add_stat(STAT_DROP_SYN);
        } else if (verdict == 2) {
            add_stat(STAT_DROP_FULL);
        } else {
            goto pass;
        }
        return XDP_DROP;
    }
    if (ip->protocol == IPPROTO_UDP) {
        if ((void *)(l4 + 8) > data_end) {
            goto pass;
        }
        verdict = account(src, lim->udp_pps, 1);
        if (verdict == 1) {
            add_stat(STAT_DROP_UDP);
        } else if (verdict == 2) {
            add_stat(STAT_DROP_FULL);
        } else {
            goto pass;
        }
        return XDP_DROP;
    }
    

pass:
    add_stat(STAT_PASS);
    return XDP_PASS;
}