#include <errno.h>
#include <linux/if_link.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <xdp/libxdp.h>

#include "dns.h"

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define SAMPLE_SIZE 512ul
#define MAX_CPUS 64

// static variables
const char *file_name = "dns.o";
const char *prog_name = "xdp_dnshook_func";
static struct xdp_program *prog;
static struct perf_buffer *pb;
static int ifindex = -1;

// returns the ifindex
int parse_cmd_args(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Not enough args!, only got %d\n", argc);
        printf("Usage: %s ifname filename progname \n", argv[0]);
        return -1;
    }
    // check ifname
    if (strlen(argv[1]) > IF_NAMESIZE) {
        fprintf(stderr, "ERR: dev name too long\n");
        return -1;
    }
    int ifidx = if_nametoindex(argv[1]);
    if (0 == ifidx) {
        fprintf(stderr, "ERR: unknown dev name\n");
        return -1;
    }
    return ifidx;
}

static void sig_handler(int signo) {
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);

    enum xdp_attach_mode attach_mode = xdp_multiprog__attach_mode(mp);

    printf("Cleaning up...");

    xdp_program__detach(prog, ifindex, attach_mode, 0);
    perf_buffer__free(pb);

    exit(0);
}

/*
 * This is the callback function of a perf event
 * @ctx, extra user-provided extra context
 * @cpu, ?
 * @data, this contains the metadata
 * @size, this is the size of metadata
 * */

static void perf_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    struct {
        __u16 cookie;
        __u16 pkt_len;
        __u16 nh_off;
        __u8 pkt_data[SAMPLE_SIZE];
    } __packed *e = data; // ctx data is in e now

    if (e->cookie != 0xdead) {
        printf("BUG cookie: %x sized %d\n", e->cookie, size);
    }

    // read
    printf("nh_off: %d\n", e->nh_off);

    struct udphdr *udp = (void *)e->pkt_data + e->nh_off;
    printf("src port: %d, udp packet len: %d\n", bpf_ntohs(udp->source),
           bpf_ntohs(udp->len));

    print_dns_message(e->pkt_data + e->nh_off + sizeof(struct udphdr),
                      e->pkt_len - e->nh_off - sizeof(struct udphdr));
}

int main(int argc, char *argv[]) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    char errmsg[1024];
    struct bpf_map *map;

    /* // creates a bpf_object by opening the BPF ELF
        // struct bpf_object *obj;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    obj = bpf_object__open_file(file_name, &bpf_opts);
    // check error
    if (NULL == obj) {
        libxdp_strerror(errno, errmsg, sizeof(errmsg));
        fprintf(stderr, "Couldn't open BPF object file %s: %s\n", file_name,
                errmsg);
        return -1;
    } */

    ifindex = parse_cmd_args(argc, argv);
    if (-1 == ifindex) {
        exit(EXIT_FAILURE);
    }
    // load the xdp program from bpf object
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    xdp_opts.open_filename = file_name;
    xdp_opts.prog_name = prog_name;
    xdp_opts.opts = &bpf_opts;

    // set resource limit
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAILURE;
    }

    // create xdp program
    prog = xdp_program__create(&xdp_opts);
    int err = libxdp_get_error(prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "ERR: loading program %s: %s\n", prog_name, errmsg);
        exit(EXIT_FAILURE);
    }

    // attach
    err = xdp_program__attach(prog, ifindex, XDP_ATTACHED_SKB, 0);
    if (err) {
        fprintf(stderr, "ERR: failed to attach program\n");
        exit(EXIT_FAILURE);
    }

    int prog_fd = xdp_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERR: xdp_program__fd failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // int map_fd;
    // const char *mapname = "dns_map";
    // open map
    // struct bpf_map *map =
    //     bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), mapname);
    // if (NULL == map) {
    //     fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
    // }
    // map_fd =
    //     bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), mapname);

    // retrieve the map
    map = bpf_object__next_map(xdp_program__bpf_obj(prog), NULL);
    if (NULL == map) {
        fprintf(stderr, "finding a map in obj file failed\n");
        exit(EXIT_FAILURE);
    }
    // retrieve fd to the map
    int map_fd = bpf_map__fd(map);

    // set up the sig_handler
    // because, at the point, we have opened some stuff,
    // and we want these stuff to be closed safely
    if (signal(SIGINT, sig_handler) || signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        return -1;
    }

    // allocate buffer
    pb = perf_buffer__new(map_fd, 8, perf_event_cb, NULL, NULL, NULL);
    if (NULL == pb) {
        perror("perf_buffer setup failed");
        return 1;
    }

    // keep polling for new events
    while ((err = perf_buffer__poll(pb, 300)) >= 0) {
    }

    xdp_program__detach(prog, ifindex, XDP_ATTACHED_SKB, 0);

    return 0;
}
