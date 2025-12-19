// tc_flow_log.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};

static __always_inline int load_bytes(struct __sk_buff *skb, int off, void *to, int len)
{
    return bpf_skb_load_bytes(skb, off, to, len);
}

static __always_inline __u64 pack_u64(__u32 gid, __u32 v)
{
    return ((__u64)gid << 32) | (__u64)v;
}

static __always_inline int parse_and_emit(struct __sk_buff *skb, __u32 dir /*1 ingress,2 egress*/)
{
    int off = 0;

    __u32 gid = skb->hash;
    if (!gid)
        gid = bpf_get_prandom_u32();

    __u32 ifidx = skb->ifindex;

    struct ethhdr eth;
    if (load_bytes(skb, off, &eth, sizeof(eth)) < 0)
        return TC_ACT_UNSPEC;
    off += sizeof(eth);

    __u16 h_proto = bpf_ntohs(eth.h_proto);

    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr vh;
        if (load_bytes(skb, off, &vh, sizeof(vh)) < 0)
            return TC_ACT_UNSPEC;
        h_proto = bpf_ntohs(vh.encap_proto);
        off += sizeof(vh);
    }

    // Common fields (each: literal fmt + one arg)
    bpf_printk("I=%llx", pack_u64(gid, ifidx)); // ifindex
    bpf_printk("R=%llx", pack_u64(gid, dir));   // direction

    if (h_proto == ETH_P_IP) {
        struct iphdr iph;
        if (load_bytes(skb, off, &iph, sizeof(iph)) < 0)
            return TC_ACT_UNSPEC;

        __u8 vihl;
        if (load_bytes(skb, off, &vihl, 1) < 0)
            return TC_ACT_UNSPEC;
        __u32 ihl = (vihl & 0x0F) * 4;
        if (ihl < 20 || ihl > 60)
            return TC_ACT_UNSPEC;

        __u8 proto = iph.protocol;
        int l4_off = off + (int)ihl;

        __u16 sport = 0, dport = 0;
        if (proto == IPPROTO_TCP) {
            struct tcphdr th;
            if (load_bytes(skb, l4_off, &th, sizeof(th)) < 0)
                return TC_ACT_UNSPEC;
            sport = bpf_ntohs(th.source);
            dport = bpf_ntohs(th.dest);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr uh;
            if (load_bytes(skb, l4_off, &uh, sizeof(uh)) < 0)
                return TC_ACT_UNSPEC;
            sport = bpf_ntohs(uh.source);
            dport = bpf_ntohs(uh.dest);
        }

        bpf_printk("V=%llx",  pack_u64(gid, 4));
        bpf_printk("P=%llx",  pack_u64(gid, proto));          // L4 proto number
        bpf_printk("SP=%llx", pack_u64(gid, sport));
        bpf_printk("DP=%llx", pack_u64(gid, dport));
        bpf_printk("S4=%llx", pack_u64(gid, iph.saddr));      // BE u32
        bpf_printk("D4=%llx", pack_u64(gid, iph.daddr));      // BE u32

        return TC_ACT_UNSPEC;
    }

    if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (load_bytes(skb, off, &ip6h, sizeof(ip6h)) < 0)
            return TC_ACT_UNSPEC;

        __u8 proto = ip6h.nexthdr;
        int l4_off = off + (int)sizeof(ip6h);

        __u16 sport = 0, dport = 0;
        if (proto == IPPROTO_TCP) {
            struct tcphdr th;
            if (load_bytes(skb, l4_off, &th, sizeof(th)) < 0)
                return TC_ACT_UNSPEC;
            sport = bpf_ntohs(th.source);
            dport = bpf_ntohs(th.dest);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr uh;
            if (load_bytes(skb, l4_off, &uh, sizeof(uh)) < 0)
                return TC_ACT_UNSPEC;
            sport = bpf_ntohs(uh.source);
            dport = bpf_ntohs(uh.dest);
        }

        bpf_printk("V=%llx",  pack_u64(gid, 6));
        bpf_printk("P=%llx",  pack_u64(gid, proto));
        bpf_printk("SP=%llx", pack_u64(gid, sport));
        bpf_printk("DP=%llx", pack_u64(gid, dport));

        bpf_printk("S0=%llx", pack_u64(gid, ip6h.saddr.in6_u.u6_addr32[0]));
        bpf_printk("S1=%llx", pack_u64(gid, ip6h.saddr.in6_u.u6_addr32[1]));
        bpf_printk("S2=%llx", pack_u64(gid, ip6h.saddr.in6_u.u6_addr32[2]));
        bpf_printk("S3=%llx", pack_u64(gid, ip6h.saddr.in6_u.u6_addr32[3]));

        bpf_printk("D0=%llx", pack_u64(gid, ip6h.daddr.in6_u.u6_addr32[0]));
        bpf_printk("D1=%llx", pack_u64(gid, ip6h.daddr.in6_u.u6_addr32[1]));
        bpf_printk("D2=%llx", pack_u64(gid, ip6h.daddr.in6_u.u6_addr32[2]));
        bpf_printk("D3=%llx", pack_u64(gid, ip6h.daddr.in6_u.u6_addr32[3]));

        return TC_ACT_UNSPEC;
    }

    return TC_ACT_UNSPEC;
}

SEC("classifier/ingress")
int tc_flow_log_ingress(struct __sk_buff *skb)
{
    return parse_and_emit(skb, 1);
}

SEC("classifier/egress")
int tc_flow_log_egress(struct __sk_buff *skb)
{
    return parse_and_emit(skb, 2);
}

char LICENSE[] SEC("license") = "GPL";

