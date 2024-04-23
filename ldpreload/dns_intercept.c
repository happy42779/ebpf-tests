#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    static int (*original_getaddrinfo)(const char *, const char *,
                                       const struct addrinfo *,
                                       struct addrinfo **) = NULL;

    if (!original_getaddrinfo) {
        original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    }

    // hook post call by calling the original
    int ret = original_getaddrinfo(node, service, hints, res);

    printf("Intercepted getaddrinfo() call for hostname: %s\n", node);
    // now examine the data
    char address_buffer[100] = {0};
    struct addrinfo *addr = *res;
    do {
        getnameinfo(addr->ai_addr, addr->ai_addrlen, address_buffer,
                    sizeof(address_buffer), 0, 0, NI_NUMERICHOST);
        printf("\t%s\n", address_buffer);
    } while ((addr = addr->ai_next));

    // return the original return value
    return ret;
}
