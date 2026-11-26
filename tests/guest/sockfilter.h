#ifndef APPINE_TEST_SOCKFILTER_H
#define APPINE_TEST_SOCKFILTER_H

#include <stdint.h>
#include <sys/socket.h>

#define TEST_SYSCALL 0xa991
#define HOOK_REFUSE_TCP_FILTERS 14

/* Classic BPF socket filter ABI for musl-gcc, which has no linux/filter.h */
struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_LEN 0x80
#define BPF_RET 0x06
#define BPF_K 0x00
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
#ifndef SO_DETACH_FILTER
#define SO_DETACH_FILTER 27
#endif
#ifndef SO_GET_FILTER
#define SO_GET_FILTER SO_ATTACH_FILTER
#endif
#ifndef SO_LOCK_FILTER
#define SO_LOCK_FILTER 44
#endif

#endif
