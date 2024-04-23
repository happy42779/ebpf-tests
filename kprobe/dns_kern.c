#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netdb.h>
#include <sys/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

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

/*
 * defining xdp program
 * */
SEC("kretsyscall/getaddrinfo")
int BPF_KRETSYSCALL(const char *node, const char *service,
                    const struct addrinfo *hints, struct addrinfo **res) {

    return 0;
}
