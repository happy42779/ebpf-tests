#include <error.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/time_types.h>
#include <net/if.h>

#include "./libbpf/src/bpf_helpers.h"

static const char *__doc__ =
    "XDP loader\n"
    "- Specify BPF-object --filename to load \n"
    " - and select BPF program --progname name to XDP-attach to --dev\n";

static const char *default_filename = "dnshook_k.o";
static const char *default_progname = "dhshook_fuc";

static void list_avail_progs(struct bpf_object *obj) {
    struct bpf_program *pos;

    printf("BPF object (%s) listing available XDP functions\n",
           bpf_object__name(obj));

    bpf_object__for_each_program(pos, obj) {
        if (bpf_program__type(pos) == BPF_PROG_TYPE_XDP)
            printf(" %s\n", bpf_program__name(pos));
    }
}

int main(int argc, char *argv[]) { return EXIT_SUCCESS; }
