#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <sys/types.h>

#include "./libbpf/src/bpf_helpers.h"

/*
 * Macros
 * */
#define XDP_MAX_DNS_ENTRIES                                                    \
    64 // results maybe deleted after read from user space
       // therefore, as long as it's big enough for concurrent requests?
#define XDP_MAX_IP_RESULT 32 // the number of ips returned in a dns response

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

/*
 * define maps to store dns records
 * */
struct ip_list {
    __u32 ip_addr[XDP_MAX_IP_RESULT];
};
struct dns_payload {
    char payload[512];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_payload);
    __uint(max_entries, XDP_MAX_DNS_ENTRIES);
} dns_map SEC(".maps");

/******************* DNS Structure Definition *********************/
/*
 * Total 12 bytes, DNS header, divided into 6 16-bits double word
 * the second one is flags, consists of 8 fields:
 *		1. QR:		Query Response			1 bit
 *		2. OPCODE:	Operation Code			4 bits
 *		3. AA:		Authoritative answer	1 bit
 *		4. TC:		Truncated Message		1 bit
 *		5. RD:		Recursion Desired		1 bit
 *		6. RA:		Recursion Available		1 bit
 *		7. Z:		Reserved				3 bits
 *		8. RCODE	Response Code			4 bits
 *
 *		use __bexx type, which means big endian type
 */
struct dnshdr {
    __be16 id;      // id
    __be16 flags;   // flags, see above
    __be16 qdcount; // question count
    __be16 ancount; // answer count
    __be16 nscount; // authority count
    __be16 arcount; // additional count
};

struct dnsquest {
    __u16 type;  // record type
    __u16 class; // class, always set to 1
};

struct dnsrec {
    __u16 type;  // record type
    __u16 class; // same above
    __u32 ttl;   // time to live
    __u16 len;   // length of record type specific data
};

struct iprec {
    __u32 ip; // ip address encoded as a four byte integer
};

/******************* DNS Structure Definition *********************/

/*
 * defining xdp program
 * */
SEC("xdp_dns") int xdp_dnshook_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // check if the data boundary is correct,
    if (data + 1 > data_end) {
        // return XDP_ABORTED; // trigger trace point
        // return XDP_DROP;
        return XDP_PASS;
    }

    struct ethhdr *eth = (struct ethhdr *)data; // ethernet header

    // bpf_printk("Got some  packets\n");

    // check boundary first?
    if (eth + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    // check if ethernet frame has IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // bpf_printk("Got some IP packets\n");

    struct iphdr *ip = (void *)eth + ETH_HLEN;
    if (ip + 1 > data_end) {
        return XDP_PASS;
    }
    // check if datagrams are correct
    // check if it's udp and port 53
    // assuming it's UDP, though in some rare cases it's going to be TCP
    if (ip->protocol != (IPPROTO_UDP)) {
        return XDP_PASS;
    }

    bpf_printk("Got some udp packets here! src ip: %pI4\n", &ip->saddr);

    // /* src address could also be check to filter a specific upstream
    // nameserver
    //  */
    //
    __u32 hdrsize = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + hdrsize;
    // check boundary before accessing the fileds
    if (udp + 1 > data_end) {
        return XDP_PASS;
    }
    // bpf_printk("I was here\n src port: %ld, dst port: %ld\n",
    // bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
    bpf_printk("I was here\n src port: %ld, dst port: %ld\n", (udp->source),
               (udp->dest));

    // // check port, if src port is not 53, ignore
    // // force using the default port
    if (udp->source != bpf_htons(53)) {
        return XDP_PASS;
    }
    // // pass it to dns response checker
    // // trying to print packet info to see if it's correct
    bpf_printk("packet recvd: %d\n", bpf_ntohs(udp->source));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/* xdp_md: is the metadata for xdp hook
 * In the following case "xdp_abort" is the ELF section name,
 * and "xdp_abort_func" is the BPF program name, both could
 * used to specify which function to be loaded into the kernel, and only one is
 *needed to be specified.

 SEC("xdp_abort")
 int xdp_abort_func(struct xdp_md *ctx) { return XDP_ABORTED; }

 */

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
