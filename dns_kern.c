#include <linux/byteorder/little_endian.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <sys/types.h>

// #include "./libbpf/src/bpf_helpers.h"

/*
 * Macros
 *
 */
// !!! The following definitions should correspond to
// user space program
#define MAX_CPUS 64
#define SAMPLE_SIZE 512ul
/* struct to define the value size of the perf_event map*/
struct S {
    __u16 cookies; // kind of key used to retrieve data
    __u16 pkt_len; // the length of the packet
    __u16 nh_off;  // offset of the UDP payload
} __packed;

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/*
 * This macro is only used to help with non const size data copy
 * use with discern with other stuff
 * */
#define min(x, y) ((x) < (y) ? (x) : (y))

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} dns_map SEC(".maps");

/*
 * defining xdp program
 * */
SEC("xdp_dns") int xdp_dnshook_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data; // ethernet header
    __u16 nh_off = sizeof(*eth);
    // check if the data boundary is correct,
    if (data + nh_off > data_end) {
        // return XDP_ABORTED; // trigger trace point
        return XDP_DROP;
    }

    // check if ethernet frame has IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // check ipv4 packet
    struct iphdr *iph = (void *)data + nh_off;
    if ((void *)iph + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }
    // check if datagrams are correct
    // check if it's udp and port 53
    // assuming it's UDP, though in some rare cases it's going to be TCP
    if (iph->protocol != (IPPROTO_UDP)) {
        return XDP_PASS;
    }

    // /* src address could also be check to filter a specific upstream
    // nameserver
    //  */
    //
    nh_off += iph->ihl * 4;
    struct udphdr *udp = (void *)data + nh_off;
    // check boundary before accessing the fileds
    if ((void *)udp + sizeof(struct udphdr) > data_end) {
        return XDP_DROP;
    }

    // // check port, if src port is not 53, ignore
    // // force using the default port
    if (bpf_ntohs(udp->source) != 53) {
        return XDP_PASS;
    }

    // nh_off += sizeof(*udp);

    bpf_printk("Got some udp packets here! Packet len: %d,  src ip: %pI4, src "
               "port: %ld, dst "
               "port: %ld\n",
               bpf_htons(udp->len), &iph->saddr, bpf_ntohs(udp->source),
               bpf_ntohs(udp->dest));

    // __u16 sample_size = bpf_ntohs(udp->len);
    // void *payload = (void *)data + nh_off;

    // now write to maps
    __u16 sample_size = (__u16)(data_end - data);

    // test payload size
    // bpf_printk("Buffer: %s\n", buffer);
    // bpf_printk("Size calculated: %ld\n", size);
    __u64 flags = BPF_F_CURRENT_CPU;
    int ret;
    struct S meta;
    meta.cookies = 0xdead; // name used for user space program
    meta.pkt_len = min(sample_size, SAMPLE_SIZE);
    meta.nh_off = nh_off; // staring at the UDP header

    /* The XDP perf_event_output handler will use the upper 32 bits of flags, as
     * the number of bytes to include of the packet payload in the event data,
     * reading directly from ctx, the following bit operation will combine
     * both the flag and size within a 64bit
     * */
    flags |= (__u64)sample_size << 32;

    // write to map
    ret = bpf_perf_event_output(ctx, &dns_map, flags, &meta, sizeof(meta));
    if (0 != ret) {
        bpf_printk("perf_event_output failed: %d\n", ret);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
        // (Note: type __u32 is NOT the real-type)
        __u32 data;
        __u32 data_end;
        __u32 data_meta;
        // Below access go through struct xdp_rxq_info
        __u32 ingress_ifindex; // rxq->dev->ifindex
        __u32 rx_queue_index;  // rxq->queue_index
};
*/
