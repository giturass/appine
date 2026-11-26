/*
 * Guest regression suite for kernel/net, kernel/netns, kernel/netlink, kernel/rawicmp and
 * kernel/nft fixes. Built with musl-gcc -static and run under both Tier 0 and Tier 1.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sockfilter.h"

/* Self-contained Linux UAPI definitions (musl-gcc has no linux UAPI headers). */
#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif
#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

enum {
    NETLINK_ROUTE = 0,
    NETLINK_NETFILTER = 12,
};

struct sockaddr_nl {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};

struct ifinfomsg {
    uint8_t ifi_family;
    uint8_t __ifi_pad;
    uint16_t ifi_type;
    int32_t ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
};

struct ifaddrmsg {
    uint8_t ifa_family;
    uint8_t ifa_prefixlen;
    uint8_t ifa_flags;
    uint8_t ifa_scope;
    uint32_t ifa_index;
};

struct rtmsg {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
};

struct ndmsg {
    uint8_t ndm_family;
    uint8_t ndm_pad1;
    uint16_t ndm_pad2;
    int32_t ndm_ifindex;
    uint16_t ndm_state;
    uint8_t ndm_flags;
    uint8_t ndm_type;
};

enum {
    NLMSG_HDRLEN = 16,
    NLMSG_ERROR = 2,
    NLMSG_DONE = 3,
    NLM_F_REQUEST = 0x01,
    NLM_F_MULTI = 0x02,
    NLM_F_ACK = 0x04,
    NLM_F_REPLACE = 0x100,
    NLM_F_NONREC = 0x100,
    NLM_F_EXCL = 0x200,
    NLM_F_DUMP = 0x300,
    NLM_F_CREATE = 0x400,
    NLA_HDRLEN = 4,
    NLA_F_NESTED = 0x8000,
    NLA_TYPE_MASK = 0x3fff,

    RTM_NEWLINK = 16,
    RTM_DELLINK = 17,
    RTM_GETLINK = 18,
    RTM_NEWADDR = 20,
    RTM_NEWROUTE = 24,
    RTM_DELROUTE = 25,
    RTM_GETNEIGH = 30,

    IFLA_IFNAME = 3,
    IFLA_LINKINFO = 18,
    IFLA_NET_NS_PID = 19,
    IFLA_INFO_KIND = 1,
    IFLA_INFO_DATA = 2,

    IFA_ADDRESS = 1,
    IFA_LOCAL = 2,

    RT_TABLE_MAIN = 254,
    RTPROT_BOOT = 3,
    RT_SCOPE_UNIVERSE = 0,
    RT_SCOPE_LINK = 253,
    RT_SCOPE_NOWHERE = 255,
    RTN_UNICAST = 1,
    RTA_DST = 1,
    RTA_OIF = 4,
    RTA_GATEWAY = 5,

    NDA_DST = 1,

    NFPROTO_IPV4 = 2,
    NF_DROP = 0,
    NF_ACCEPT = 1,
    NF_INET_PRE_ROUTING = 0,
    NF_INET_LOCAL_OUT = 3,

    NFNL_MSG_BATCH_BEGIN = 0x10,
    NFNL_MSG_BATCH_END = 0x11,
    NFNL_SUBSYS_NFTABLES = 10,

    NFT_MSG_NEWTABLE = 0,
    NFT_MSG_DELTABLE = 2,
    NFT_MSG_NEWCHAIN = 3,
    NFT_MSG_GETCHAIN = 4,
    NFT_MSG_DELCHAIN = 5,
    NFT_MSG_NEWRULE = 6,
    NFT_MSG_GETRULE = 7,
    NFT_MSG_NEWSET = 9,
    NFT_MSG_DELSET = 11,
    NFT_MSG_NEWSETELEM = 12,

    NFTA_TABLE_NAME = 1,
    NFTA_CHAIN_TABLE = 1,
    NFTA_CHAIN_HANDLE = 2,
    NFTA_CHAIN_NAME = 3,
    NFTA_CHAIN_HOOK = 4,
    NFTA_CHAIN_POLICY = 5,
    NFTA_CHAIN_TYPE = 7,
    NFTA_HOOK_HOOKNUM = 1,
    NFTA_HOOK_PRIORITY = 2,
    NFTA_RULE_TABLE = 1,
    NFTA_RULE_CHAIN = 2,
    NFTA_RULE_HANDLE = 3,
    NFTA_RULE_EXPRESSIONS = 4,
    NFTA_SET_TABLE = 1,
    NFTA_SET_NAME = 2,
    NFTA_SET_FLAGS = 3,
    NFTA_SET_KEY_LEN = 5,
    NFTA_SET_DATA_TYPE = 6,
    NFT_SET_MAP = 0x08,
    NFTA_SET_ELEM_LIST_TABLE = 1,
    NFTA_SET_ELEM_LIST_SET = 2,
    NFTA_SET_ELEM_LIST_ELEMENTS = 3,
    NFTA_LIST_ELEM = 1,
    NFTA_SET_ELEM_KEY = 1,
    NFTA_SET_ELEM_DATA = 2,
    NFTA_DATA_VALUE = 1,
    NFTA_DATA_VERDICT = 2,
    NFTA_VERDICT_CODE = 1,
    NFTA_VERDICT_CHAIN = 2,
    NFTA_EXPR_NAME = 1,
    NFTA_EXPR_DATA = 2,
};

#define NFT_DATA_VERDICT 0xffffff00U
#define NFT_JUMP (-3)

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: ", __func__, __LINE__);                                            \
            printf(__VA_ARGS__);                                                                   \
            printf(" (errno %d)\n", errno);                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void ok(const char *name)
{
    printf("ok %s\n", name);
    fflush(stdout);
}

static int run_in_child(void (*fn)(void))
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        fn();
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid, "waitpid");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* ---- Netlink / rtnetlink helpers ---- */

struct nlbuf {
    uint8_t data[4096];
    size_t len;
};

static void nl_init(struct nlbuf *b, uint16_t type, uint16_t flags, uint32_t seq)
{
    memset(b, 0, sizeof *b);
    struct nlmsghdr h = {
        .nlmsg_len = NLMSG_HDRLEN,
        .nlmsg_type = type,
        .nlmsg_flags = flags,
        .nlmsg_seq = seq,
    };
    memcpy(b->data, &h, sizeof h);
    b->len = NLMSG_HDRLEN;
}

static void nl_put_raw(struct nlbuf *b, const void *p, size_t n)
{
    CHECK(b->len + n <= sizeof b->data, "nlbuf overflow");
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static size_t nl_attr_start(struct nlbuf *b, uint16_t type)
{
    size_t off = b->len;
    struct nlattr a = {.nla_len = NLA_HDRLEN, .nla_type = type};
    nl_put_raw(b, &a, sizeof a);
    return off;
}

static void nl_attr_end(struct nlbuf *b, size_t off)
{
    uint16_t len = (uint16_t)(b->len - off);
    memcpy(b->data + off, &len, sizeof len);
    while (b->len & 3)
        b->data[b->len++] = 0;
}

static void nl_attr(struct nlbuf *b, uint16_t type, const void *p, size_t n)
{
    size_t off = nl_attr_start(b, type);
    nl_put_raw(b, p, n);
    nl_attr_end(b, off);
}

static void nl_attr_str(struct nlbuf *b, uint16_t type, const char *s)
{
    nl_attr(b, type, s, strlen(s) + 1);
}

static void nl_attr_u32(struct nlbuf *b, uint16_t type, uint32_t v)
{
    nl_attr(b, type, &v, sizeof v);
}

static void nl_attr_be32(struct nlbuf *b, uint16_t type, uint32_t v)
{
    uint32_t be = htonl(v);
    nl_attr(b, type, &be, sizeof be);
}

static void nl_attr_be64(struct nlbuf *b, uint16_t type, uint64_t v)
{
    uint64_t be = __builtin_bswap64(v);
    nl_attr(b, type, &be, sizeof be);
}

static void nl_finish(struct nlbuf *b)
{
    uint32_t len = (uint32_t)b->len;
    memcpy(b->data, &len, sizeof len);
}

static int nl_send_ack(int fd, struct nlbuf *b)
{
    nl_finish(b);
    CHECK(send(fd, b->data, b->len, 0) == (ssize_t)b->len, "nl send");
    uint8_t resp[4096];
    ssize_t n = recv(fd, resp, sizeof resp, 0);
    CHECK(n >= (ssize_t)(NLMSG_HDRLEN + 4), "nl recv %zd", n);
    struct nlmsghdr h;
    memcpy(&h, resp, sizeof h);
    CHECK(h.nlmsg_type == NLMSG_ERROR, "expected NLMSG_ERROR got %u", h.nlmsg_type);
    int32_t err = 0;
    memcpy(&err, resp + NLMSG_HDRLEN, 4);
    return -err;
}

static void set_link_up(int rtnl, int ifindex)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 1);
    struct ifinfomsg ifi = {.ifi_index = ifindex, .ifi_flags = IFF_UP, .ifi_change = IFF_UP};
    nl_put_raw(&b, &ifi, sizeof ifi);
    CHECK(nl_send_ack(rtnl, &b) == 0, "link up %d", ifindex);
}

static void create_dummy(int rtnl, const char *name)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 2);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr_str(&b, IFLA_IFNAME, name);
    size_t li = nl_attr_start(&b, IFLA_LINKINFO);
    nl_attr_str(&b, IFLA_INFO_KIND, "dummy");
    nl_attr_end(&b, li);
    CHECK(nl_send_ack(rtnl, &b) == 0, "create dummy %s", name);
}

static void create_veth(int rtnl, const char *name, const char *peer_name, pid_t peer_ns_pid)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 3);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr_str(&b, IFLA_IFNAME, name);
    size_t li = nl_attr_start(&b, IFLA_LINKINFO);
    nl_attr_str(&b, IFLA_INFO_KIND, "veth");
    size_t ld = nl_attr_start(&b, IFLA_INFO_DATA);
    size_t pr = nl_attr_start(&b, 1 /* VETH_INFO_PEER */);
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr_str(&b, IFLA_IFNAME, peer_name);
    if (peer_ns_pid > 0)
        nl_attr_u32(&b, IFLA_NET_NS_PID, (uint32_t)peer_ns_pid);
    nl_attr_end(&b, pr);
    nl_attr_end(&b, ld);
    nl_attr_end(&b, li);
    CHECK(nl_send_ack(rtnl, &b) == 0, "create veth %s/%s", name, peer_name);
}

static void add_v4_addr(int rtnl, int ifindex, const char *ip, uint8_t prefix)
{
    struct in_addr a;
    CHECK(inet_pton(AF_INET, ip, &a) == 1, "inet_pton");
    struct nlbuf b;
    nl_init(&b, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 4);
    struct ifaddrmsg ifa = {.ifa_family = AF_INET, .ifa_prefixlen = prefix, .ifa_index = ifindex};
    nl_put_raw(&b, &ifa, sizeof ifa);
    nl_attr(&b, IFA_LOCAL, &a, 4);
    nl_attr(&b, IFA_ADDRESS, &a, 4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "add addr %s", ip);
}

/* ---- 1. kernel/net: SO_ATTACH_BPF ---- */

static void test_so_attach_bpf_child_unpriv(void)
{
    CHECK(setresuid(65534, 65534, 65534) == 0, "drop privs");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0, "tcp socket");
    int bad = 9999;
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &bad, sizeof bad) == -1 && errno == EPERM,
          "unpriv tcp SO_ATTACH_BPF should be EPERM");
    close(s);
}

static void test_so_attach_bpf(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0, "udp socket");
    int bad = 9999;
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &bad, sizeof bad) == -1 && errno == EBADF,
          "bad fd SO_ATTACH_BPF");
    int neg = -1;
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &neg, sizeof neg) == -1 && errno == EBADF,
          "neg fd SO_ATTACH_BPF");
    /* Valid guest fd that is not a BPF socket-filter program -> EINVAL, never sent to host */
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &s, sizeof s) == -1 && errno == EINVAL,
          "non-bpf fd SO_ATTACH_BPF");
    /* Short optlen -> EINVAL */
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &s, 2) == -1 && errno == EINVAL,
          "short optlen SO_ATTACH_BPF");
    /* SO_ATTACH_REUSEPORT_EBPF checks the same guest fd table */
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &bad, sizeof bad) == -1 &&
              errno == EBADF,
          "bad fd SO_ATTACH_REUSEPORT_EBPF");
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &s, sizeof s) == -1 &&
              errno == EINVAL,
          "non-bpf fd SO_ATTACH_REUSEPORT_EBPF");
    close(s);
    CHECK(run_in_child(test_so_attach_bpf_child_unpriv) == 0, "unpriv SO_ATTACH_BPF");
    ok("so_attach_bpf");
}

/* ---- 2. kernel/net: MSG_WAITALL partial read preserves error ---- */

static void test_waitall_preserves_error(void)
{
    for (int mode = 0; mode < 2; mode++) {
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(srv >= 0, "srv");
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        CHECK(bind(srv, (struct sockaddr *)&sa, sizeof sa) == 0, "bind");
        socklen_t slen = sizeof sa;
        CHECK(getsockname(srv, (struct sockaddr *)&sa, &slen) == 0, "getsockname");
        CHECK(listen(srv, 4) == 0, "listen");

        int cli = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(cli >= 0, "cli");
        CHECK(connect(cli, (struct sockaddr *)&sa, sizeof sa) == 0, "connect");
        int acc = accept(srv, NULL, NULL);
        CHECK(acc >= 0, "accept");

        /* Send 5 bytes, then force TCP RST via SO_LINGER(1, 0) */
        CHECK(send(acc, "hello", 5, 0) == 5, "send");
        struct linger lg = {.l_onoff = 1, .l_linger = 0};
        CHECK(setsockopt(acc, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0, "SO_LINGER");
        close(acc);
        close(srv);

        /* Give loopback stack a moment to deliver RST behind data */
        usleep(20000);

        char buf[16];
        ssize_t n = recv(cli, buf, sizeof buf, MSG_WAITALL);
        CHECK(n == 5 && memcmp(buf, "hello", 5) == 0, "partial MSG_WAITALL got %zd", n);

        if (mode == 0) {
            errno = 0;
            ssize_t n2 = recv(cli, buf, sizeof buf, 0);
            CHECK(n2 == -1 && errno == ECONNRESET,
                  "next recv after partial MSG_WAITALL got %zd", n2);
        } else {
            int err = 0;
            socklen_t elen = sizeof err;
            CHECK(getsockopt(cli, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == ECONNRESET,
                  "SO_ERROR after partial MSG_WAITALL got %d", err);
            CHECK(recv(cli, buf, sizeof buf, 0) == 0, "EOF after consuming SO_ERROR");
        }
        close(cli);
    }
    ok("waitall_preserves_error");
}

/* ---- 3. kernel/net: sendto destination validation ---- */

static void test_sendto_validation(void)
{
    int u6 = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(u6 >= 0, "u6");
    struct sockaddr_in6 bogus6 = {0};
    bogus6.sin6_family = 99;
    errno = 0;
    CHECK(sendto(u6, "x", 1, 0, (struct sockaddr *)&bogus6, sizeof bogus6) == -1 && errno == EINVAL,
          "AF_INET6 UDP bogus family should be EINVAL");
    struct sockaddr_in6 short6 = {.sin6_family = AF_INET6};
    errno = 0;
    CHECK(sendto(u6, "x", 1, 0, (struct sockaddr *)&short6, 12) == -1 && errno == EINVAL,
          "AF_INET6 UDP short sockaddr");
    uint8_t tiny = 0;
    errno = 0;
    CHECK(sendto(u6, "x", 1, 0, (struct sockaddr *)&tiny, 1) == -1 && errno == EINVAL,
          "AF_INET6 UDP 1-byte sockaddr");
    close(u6);

    int u4 = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(u4 >= 0, "u4");
    struct sockaddr_in bogus4 = {0};
    bogus4.sin_family = 99;
    errno = 0;
    CHECK(sendto(u4, "x", 1, 0, (struct sockaddr *)&bogus4, sizeof bogus4) == -1 &&
              errno == EAFNOSUPPORT,
          "AF_INET UDP bogus family should be EAFNOSUPPORT");
    errno = 0;
    CHECK(sendto(u4, "x", 1, 0, (struct sockaddr *)&bogus4, 8) == -1 && errno == EINVAL,
          "AF_INET UDP short sockaddr");
    close(u4);
    ok("sendto_validation");
}

/* ---- 4. kernel/net: wildcard connect from bound IPv4 socket ---- */

static void test_wildcard_connect_bound_v4(void)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(srv >= 0, "srv");
    struct sockaddr_in sa = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, "127.0.0.2", &sa.sin_addr) == 1, "pton");
    CHECK(bind(srv, (struct sockaddr *)&sa, sizeof sa) == 0, "bind 127.0.0.2");
    socklen_t slen = sizeof sa;
    CHECK(getsockname(srv, (struct sockaddr *)&sa, &slen) == 0, "getsockname");
    CHECK(listen(srv, 4) == 0, "listen");

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(cli >= 0, "cli");
    struct sockaddr_in local = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, "127.0.0.2", &local.sin_addr) == 1, "pton");
    CHECK(bind(cli, (struct sockaddr *)&local, sizeof local) == 0, "bind cli 127.0.0.2");

    struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = sa.sin_port};
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    CHECK(connect(cli, (struct sockaddr *)&any, sizeof any) == 0, "connect 0.0.0.0");

    struct sockaddr_in peer = {0};
    socklen_t plen = sizeof peer;
    CHECK(getpeername(cli, (struct sockaddr *)&peer, &plen) == 0, "getpeername");
    CHECK(peer.sin_addr.s_addr == sa.sin_addr.s_addr && peer.sin_port == sa.sin_port,
          "expected peer 127.0.0.2 got 0x%x", ntohl(peer.sin_addr.s_addr));
    close(cli);
    close(srv);
    ok("wildcard_connect_bound_v4");
}

/* ---- 5. kernel/netns: connected UDP listener & filter checks, ephemeral port aliasing ---- */

static void nft_batch_send(int fd, struct nlbuf *msgs, size_t nmsgs, int *errs, size_t nerrs)
{
    uint8_t buf[16384];
    size_t off = 0;

    struct nlbuf begin;
    nl_init(&begin, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    uint8_t gen_b[4] = {0, 0, 0, NFNL_SUBSYS_NFTABLES};
    nl_put_raw(&begin, gen_b, 4);
    nl_finish(&begin);
    memcpy(buf + off, begin.data, begin.len);
    off += (begin.len + 3) & ~3u;

    for (size_t i = 0; i < nmsgs; i++) {
        nl_finish(&msgs[i]);
        memcpy(buf + off, msgs[i].data, msgs[i].len);
        off += (msgs[i].len + 3) & ~3u;
    }

    struct nlbuf end;
    nl_init(&end, NFNL_MSG_BATCH_END, NLM_F_REQUEST, 999);
    nl_put_raw(&end, gen_b, 4);
    nl_finish(&end);
    memcpy(buf + off, end.data, end.len);
    off += (end.len + 3) & ~3u;

    CHECK(send(fd, buf, off, 0) == (ssize_t)off, "nft batch send");
    for (size_t i = 0; i < nerrs; i++) {
        uint8_t resp[4096];
        ssize_t n = recv(fd, resp, sizeof resp, 0);
        CHECK(n >= (ssize_t)(NLMSG_HDRLEN + 4), "nft ack recv %zu", i);
        int32_t e = 0;
        memcpy(&e, resp + NLMSG_HDRLEN, 4);
        errs[i] = -e;
    }
}

static int nft_batch_one(int fd, struct nlbuf *msg)
{
    int err = -1;
    nft_batch_send(fd, msg, 1, &err, 1);
    return err;
}

static void nft_msg_init(struct nlbuf *b, uint8_t msg, uint16_t flags, uint32_t seq, uint8_t fam)
{
    nl_init(b, (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | msg), NLM_F_REQUEST | flags, seq);
    uint8_t g[4] = {fam, 0, 0, 0};
    nl_put_raw(b, g, 4);
}

static void nft_table_msg(struct nlbuf *b, uint8_t msg, uint16_t flags, uint32_t seq,
                          const char *table)
{
    nft_msg_init(b, msg, flags, seq, NFPROTO_IPV4);
    nl_attr_str(b, NFTA_TABLE_NAME, table);
}

static void nft_chain_msg(struct nlbuf *b, uint8_t msg, uint16_t flags, uint32_t seq,
                          const char *table, const char *chain)
{
    nft_msg_init(b, msg, flags, seq, NFPROTO_IPV4);
    nl_attr_str(b, NFTA_CHAIN_TABLE, table);
    nl_attr_str(b, NFTA_CHAIN_NAME, chain);
}

static void nft_base_chain_msg(struct nlbuf *b, uint32_t seq, const char *table, const char *chain,
                               uint32_t hooknum, int32_t prio, uint32_t policy, const char *type)
{
    nft_chain_msg(b, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, seq, table, chain);
    size_t hk = nl_attr_start(b, NFTA_CHAIN_HOOK);
    nl_attr_be32(b, NFTA_HOOK_HOOKNUM, hooknum);
    nl_attr_be32(b, NFTA_HOOK_PRIORITY, (uint32_t)prio);
    nl_attr_end(b, hk);
    nl_attr_be32(b, NFTA_CHAIN_POLICY, policy);
    nl_attr_str(b, NFTA_CHAIN_TYPE, type);
}

static void nft_rule_msg(struct nlbuf *b, uint16_t flags, uint32_t seq, const char *table,
                         const char *chain)
{
    nft_msg_init(b, NFT_MSG_NEWRULE, flags, seq, NFPROTO_IPV4);
    nl_attr_str(b, NFTA_RULE_TABLE, table);
    nl_attr_str(b, NFTA_RULE_CHAIN, chain);
}

static void nft_put_data_val(struct nlbuf *b, uint16_t outer_attr, const void *val, size_t len)
{
    size_t dv = nl_attr_start(b, outer_attr | NLA_F_NESTED);
    nl_attr(b, NFTA_DATA_VALUE, val, len);
    nl_attr_end(b, dv);
}

static void test_netns_udp_and_ephemeral_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    close(rtnl);

    /* Ephemeral port vs explicit bind aliasing (TCP, UDP, wide UDP) */
    int t1 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(t1, (struct sockaddr *)&sa, sizeof sa) == 0, "tcp bind(0)");
    socklen_t slen = sizeof sa;
    CHECK(getsockname(t1, (struct sockaddr *)&sa, &slen) == 0 && sa.sin_port != 0, "tcp getsockname");

    int t2 = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0;
    CHECK(bind(t2, (struct sockaddr *)&sa, sizeof sa) == -1 && errno == EADDRINUSE,
          "explicit TCP bind onto active ephemeral port must EADDRINUSE");
    close(t1);
    CHECK(bind(t2, (struct sockaddr *)&sa, sizeof sa) == 0, "bind after ephemeral closed");
    close(t2);

    /* Wide UDP bind(0.0.0.0:0) vs explicit bind of same port */
    int w1 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in wsa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
    CHECK(bind(w1, (struct sockaddr *)&wsa, sizeof wsa) == 0, "wide udp bind(0)");
    slen = sizeof wsa;
    CHECK(getsockname(w1, (struct sockaddr *)&wsa, &slen) == 0 && wsa.sin_port != 0, "wide getsockname");

    int w2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in lo_same = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = wsa.sin_port,
    };
    errno = 0;
    CHECK(bind(w2, (struct sockaddr *)&lo_same, sizeof lo_same) == -1 && errno == EADDRINUSE,
          "explicit UDP bind onto active wide ephemeral port must EADDRINUSE");
    close(w1);
    close(w2);

    /* Connected UDP address-less send must check target listeners in new netns */
    int srv = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in s2 = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, "127.0.0.2", &s2.sin_addr) == 1, "pton");
    CHECK(bind(srv, (struct sockaddr *)&s2, sizeof s2) == 0, "bind 127.0.0.2");
    slen = sizeof s2;
    CHECK(getsockname(srv, (struct sockaddr *)&s2, &slen) == 0, "getsockname srv");

    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst_lo1 = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = s2.sin_port,
    };
    CHECK(connect(cli, (struct sockaddr *)&dst_lo1, sizeof dst_lo1) == 0, "connect udp 127.0.0.1");
    CHECK(send(cli, "nope", 4, 0) == 4, "send to unbound address");
    char tmp[8];
    errno = 0;
    CHECK(recv(srv, tmp, sizeof tmp, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "srv bound to 127.0.0.2 must not receive send to 127.0.0.1");
    close(cli);

    /* Wide UDP socket connecting to a namespace target must record nftables OUTPUT drop verdict */
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf socket");
    struct nlbuf msgs[2];
    nft_table_msg(&msgs[0], NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, 1, "flt");
    nft_base_chain_msg(&msgs[1], 2, "flt", "out", NF_INET_LOCAL_OUT, 0, NF_DROP, "filter");

    int errs[2] = {-1, -1};
    nft_batch_send(nf, msgs, 2, errs, 2);
    CHECK(errs[0] == 0 && errs[1] == 0, "install drop policy %d %d", errs[0], errs[1]);

    int wide_cli = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in any0 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
    CHECK(bind(wide_cli, (struct sockaddr *)&any0, sizeof any0) == 0, "bind wide");
    CHECK(connect(wide_cli, (struct sockaddr *)&s2, sizeof s2) == 0, "wide connect");
    errno = 0;
    CHECK(send(wide_cli, "blocked", 7, 0) == -1 && errno == EPERM,
          "wide connected UDP send must obey OUTPUT DROP (EPERM)");
    errno = 0;
    CHECK(recv(srv, tmp, sizeof tmp, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "dropped datagram must not arrive");
    close(wide_cli);
    close(srv);
    close(nf);
}

static void test_netns_udp_and_ephemeral(void)
{
    CHECK(run_in_child(test_netns_udp_and_ephemeral_child) == 0, "netns udp & ephemeral");
    ok("netns_udp_and_ephemeral");
}

/* ---- 6. kernel/netns: route gateway & next-hop checks ---- */

static void test_netns_routes_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    create_dummy(rtnl, "d0");
    create_dummy(rtnl, "d1");
    int i0 = (int)if_nametoindex("d0");
    int i1 = (int)if_nametoindex("d1");
    CHECK(i0 > 0 && i1 > i0, "indices %d %d", i0, i1);
    set_link_up(rtnl, i0);
    set_link_up(rtnl, i1);
    add_v4_addr(rtnl, i0, "10.77.0.1", 24);
    add_v4_addr(rtnl, i1, "10.77.0.2", 24);

    /* Gateway without device must resolve to lowest-index matching subnet (d0, not d1) */
    struct in_addr dst, gw;
    CHECK(inet_pton(AF_INET, "10.88.0.0", &dst) == 1, "pton");
    CHECK(inet_pton(AF_INET, "10.77.0.254", &gw) == 1, "pton");
    struct nlbuf b;
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 10);
    struct rtmsg rtm = {
        .rtm_family = AF_INET,
        .rtm_dst_len = 24,
        .rtm_table = RT_TABLE_MAIN,
        .rtm_protocol = RTPROT_BOOT,
        .rtm_scope = RT_SCOPE_UNIVERSE,
        .rtm_type = RTN_UNICAST,
    };
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr(&b, RTA_GATEWAY, &gw, 4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "add gw route");

    /* Re-adding with explicit d0 must fail EEXIST (proving it landed on d0, not d1) */
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 11);
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr(&b, RTA_GATEWAY, &gw, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == EEXIST, "duplicate on d0 must be EEXIST");

    /* All-zero RTA_GATEWAY counts as no gateway */
    CHECK(inet_pton(AF_INET, "10.89.0.0", &dst) == 1, "pton");
    uint8_t zero4[4] = {0, 0, 0, 0};
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 12);
    struct rtmsg rtm_link = rtm;
    rtm_link.rtm_scope = RT_SCOPE_LINK;
    nl_put_raw(&b, &rtm_link, sizeof rtm_link);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr(&b, RTA_GATEWAY, zero4, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == 0, "all-zero gateway route");

    /* Create veth v0 (up) + v1 (down) so v0 has NO carrier; IPv6 link-local gw with dev succeeds */
    create_veth(rtnl, "v0", "v1", 0);
    int iv0 = (int)if_nametoindex("v0");
    CHECK(iv0 > 0, "v0 index");
    set_link_up(rtnl, iv0);

    struct in6_addr dst6, ll_gw, far_gw;
    CHECK(inet_pton(AF_INET6, "2001:db8:1::", &dst6) == 1, "pton6");
    CHECK(inet_pton(AF_INET6, "fe80::1", &ll_gw) == 1, "pton6");
    CHECK(inet_pton(AF_INET6, "2001:db8:99::1", &far_gw) == 1, "pton6");
    struct rtmsg rtm6 = {
        .rtm_family = AF_INET6,
        .rtm_dst_len = 64,
        .rtm_table = RT_TABLE_MAIN,
        .rtm_protocol = RTPROT_BOOT,
        .rtm_scope = RT_SCOPE_UNIVERSE,
        .rtm_type = RTN_UNICAST,
    };
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 14);
    nl_put_raw(&b, &rtm6, sizeof rtm6);
    nl_attr(&b, RTA_DST, &dst6, 16);
    nl_attr(&b, RTA_GATEWAY, &ll_gw, 16);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)iv0);
    CHECK(nl_send_ack(rtnl, &b) == 0, "IPv6 link-local gw on no-carrier veth");

    /* Unreachable IPv6 gateway must return EHOSTUNREACH (not ENETUNREACH) */
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 15);
    nl_put_raw(&b, &rtm6, sizeof rtm6);
    nl_attr(&b, RTA_DST, &dst6, 16);
    nl_attr(&b, RTA_GATEWAY, &far_gw, 16);
    CHECK(nl_send_ack(rtnl, &b) == EHOSTUNREACH, "unreachable IPv6 gw must be EHOSTUNREACH");

    close(rtnl);
}

static void test_netns_routes(void)
{
    CHECK(run_in_child(test_netns_routes_child) == 0, "netns routes");
    ok("netns_routes");
}

/* ---- 7. kernel/netlink: unique IDs, RCVBUF cap, msg_name, NLM_F_REQUEST, shutdown, getpeername, RTM_GETNEIGH ---- */

static void test_netlink_unpriv_child(void)
{
    CHECK(setresuid(65534, 65534, 65534) == 0, "drop privs");
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(nl >= 0, "nl");
    struct sockaddr_nl dst = {.nl_family = AF_NETLINK, .nl_pid = 1, .nl_groups = 0};
    struct nlbuf b;
    nl_init(&b, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_finish(&b);
    errno = 0;
    CHECK(sendto(nl, b.data, b.len, 0, (struct sockaddr *)&dst, sizeof dst) == -1 && errno == EPERM,
          "unpriv sendto non-kernel port must EPERM");
    dst.nl_pid = 0;
    dst.nl_groups = 1;
    errno = 0;
    CHECK(sendto(nl, b.data, b.len, 0, (struct sockaddr *)&dst, sizeof dst) == -1 && errno == EPERM,
          "unpriv sendto group must EPERM");
    close(nl);
}

static int getneigh_err(int nl, uint32_t seq, uint8_t fam, int32_t ifindex, const void *dst,
                        size_t dst_len)
{
    struct nlbuf nb;
    nl_init(&nb, RTM_GETNEIGH, NLM_F_REQUEST, seq);
    struct ndmsg ndm = {.ndm_family = fam, .ndm_ifindex = ifindex};
    nl_put_raw(&nb, &ndm, sizeof ndm);
    if (dst)
        nl_attr(&nb, NDA_DST, dst, dst_len);
    return nl_send_ack(nl, &nb);
}

static void test_netlink(void)
{
    /* Unique port IDs */
    int nl1 = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int nl2 = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int nl3 = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(nl1 >= 0 && nl2 >= 0 && nl3 >= 0, "nl sockets");

    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    CHECK(bind(nl1, (struct sockaddr *)&sa, sizeof sa) == 0, "bind nl1");
    socklen_t len = sizeof sa;
    CHECK(getsockname(nl1, (struct sockaddr *)&sa, &len) == 0 && sa.nl_pid == (uint32_t)getpid(),
          "nl1 pid %u", sa.nl_pid);
    uint32_t pid1 = sa.nl_pid;

    struct sockaddr_nl sa2 = {.nl_family = AF_NETLINK};
    CHECK(bind(nl2, (struct sockaddr *)&sa2, sizeof sa2) == 0, "bind nl2");
    len = sizeof sa2;
    CHECK(getsockname(nl2, (struct sockaddr *)&sa2, &len) == 0 && sa2.nl_pid != 0 &&
              sa2.nl_pid != pid1,
          "nl2 distinct pid %u vs %u", sa2.nl_pid, pid1);

    struct sockaddr_nl dup = {.nl_family = AF_NETLINK, .nl_pid = pid1};
    errno = 0;
    CHECK(bind(nl3, (struct sockaddr *)&dup, sizeof dup) == -1 && errno == EADDRINUSE,
          "duplicate explicit nl_pid must EADDRINUSE");
    close(nl1);
    CHECK(bind(nl3, (struct sockaddr *)&dup, sizeof dup) == 0, "rebind after close");
    close(nl2);

    /* shutdown returns EOPNOTSUPP */
    errno = 0;
    CHECK(shutdown(nl3, SHUT_RDWR) == -1 && errno == EOPNOTSUPP, "netlink shutdown EOPNOTSUPP");

    /* getpeername reflects connected port and group */
    struct sockaddr_nl peer = {0};
    len = sizeof peer;
    CHECK(getpeername(nl3, (struct sockaddr *)&peer, &len) == 0 && peer.nl_family == AF_NETLINK &&
              peer.nl_pid == 0 && peer.nl_groups == 0,
          "initial getpeername");
    struct sockaddr_nl target = {.nl_family = AF_NETLINK, .nl_pid = 12345, .nl_groups = 0x5};
    CHECK(connect(nl3, (struct sockaddr *)&target, sizeof target) == 0, "connect nl");
    len = sizeof peer;
    CHECK(getpeername(nl3, (struct sockaddr *)&peer, &len) == 0 && peer.nl_pid == 12345 &&
              peer.nl_groups == 0x1,
          "connected getpeername pid=%u grp=0x%x", peer.nl_pid, peer.nl_groups);
    struct sockaddr unspec = {.sa_family = AF_UNSPEC};
    CHECK(connect(nl3, &unspec, sizeof unspec) == 0, "disconnect nl");
    len = sizeof peer;
    CHECK(getpeername(nl3, (struct sockaddr *)&peer, &len) == 0 && peer.nl_pid == 0 &&
              peer.nl_groups == 0,
          "disconnected getpeername");

    /* msg_name validation in sendto */
    struct nlbuf req;
    nl_init(&req, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&req, &ifi, sizeof ifi);
    nl_finish(&req);
    errno = 0;
    CHECK(sendto(nl3, req.data, req.len, 0, (struct sockaddr *)&target, 4) == -1 && errno == EINVAL,
          "short msg_name EINVAL");
    struct sockaddr_in wrong_fam = {.sin_family = AF_INET};
    errno = 0;
    CHECK(sendto(nl3, req.data, req.len, 0, (struct sockaddr *)&wrong_fam, sizeof wrong_fam) == -1 &&
              errno == EINVAL,
          "non-AF_NETLINK msg_name EINVAL");
    CHECK(run_in_child(test_netlink_unpriv_child) == 0, "unpriv netlink sendto");

    /* NLM_F_REQUEST required on handled rtnetlink types */
    struct nlbuf noreq;
    nl_init(&noreq, RTM_GETLINK, NLM_F_DUMP, 2);
    nl_put_raw(&noreq, &ifi, sizeof ifi);
    nl_finish(&noreq);
    CHECK(send(nl3, noreq.data, noreq.len, 0) == (ssize_t)noreq.len, "send without REQUEST");
    uint8_t rbuf[4096];
    errno = 0;
    CHECK(recv(nl3, rbuf, sizeof rbuf, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "no reply without NLM_F_REQUEST");
    nl_init(&noreq, RTM_GETLINK, NLM_F_ACK, 3);
    nl_put_raw(&noreq, &ifi, sizeof ifi);
    CHECK(nl_send_ack(nl3, &noreq) == 0, "NLM_F_ACK without NLM_F_REQUEST acks 0");

    /* Single RTM_GETNEIGH validation */
    struct nlbuf nb;
    nl_init(&nb, RTM_GETNEIGH, NLM_F_REQUEST, 10);
    CHECK(nl_send_ack(nl3, &nb) == EINVAL, "short GETNEIGH EINVAL");
    uint8_t ip4[4] = {127, 0, 0, 1};
    CHECK(getneigh_err(nl3, 11, AF_INET, 1, NULL, 0) == EINVAL, "missing NDA_DST EINVAL");
    CHECK(getneigh_err(nl3, 12, 99, 1, ip4, 4) == EAFNOSUPPORT, "bad family EAFNOSUPPORT");
    CHECK(getneigh_err(nl3, 13, AF_INET, 1, ip4, 2) == EINVAL, "short NDA_DST EINVAL");
    CHECK(getneigh_err(nl3, 14, AF_INET, 99999, ip4, 4) == ENODEV, "bad ifindex ENODEV");
    CHECK(getneigh_err(nl3, 15, AF_INET, 1, ip4, 4) == ENOENT, "valid GETNEIGH ENOENT");

    /* Queue capped against SO_RCVBUF -> ENOBUFS */
    int small = 2048;
    CHECK(setsockopt(nl3, SOL_SOCKET, SO_RCVBUF, &small, sizeof small) == 0, "SO_RCVBUF");
    for (int i = 0; i < 64; i++) {
        CHECK(send(nl3, req.data, req.len, 0) == (ssize_t)req.len, "flood dump");
    }
    errno = 0;
    CHECK(recv(nl3, rbuf, sizeof rbuf, MSG_DONTWAIT) == -1 && errno == ENOBUFS,
          "overflowed netlink reply queue must report ENOBUFS");
    close(nl3);
    ok("netlink");
}

/* ---- 8. kernel/rawicmp: SHUT_RD wakes waiting recv and returns 0 ---- */

struct raw_wait {
    int fd;
    ssize_t res;
    int err;
};

static void *raw_reader(void *arg)
{
    struct raw_wait *w = arg;
    char buf[64];
    errno = 0;
    w->res = recv(w->fd, buf, sizeof buf, 0);
    w->err = errno;
    return NULL;
}

static void test_rawicmp_shut_rd(void)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    CHECK(s >= 0, "raw icmp socket");
    struct raw_wait w = {.fd = s, .res = -99, .err = -1};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, raw_reader, &w) == 0, "pthread_create");
    usleep(30000);
    int sr = shutdown(s, SHUT_RD);
    CHECK(sr == 0 || (sr == -1 && errno == ENOTCONN), "shutdown SHUT_RD %d", sr);
    CHECK(pthread_join(th, NULL) == 0, "pthread_join");
    CHECK(w.res == 0, "blocked raw icmp recv after SHUT_RD returned %zd (errno %d)", w.res, w.err);

    /* Subsequent blocking recv returns 0 immediately; nonblocking stays EAGAIN */
    char buf[16];
    CHECK(recv(s, buf, sizeof buf, 0) == 0, "immediate 0 after SHUT_RD");
    errno = 0;
    CHECK(recv(s, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "nonblocking raw icmp recv stays EAGAIN");
    close(s);
    ok("rawicmp_shut_rd");
}

/* ---- 9. kernel/nft: verdict-map chain refs, rule replace handle, chain rename, DELTABLE NONREC ---- */

static uint64_t find_be64_attr(const uint8_t *buf, size_t len, uint16_t want)
{
    size_t off = 0;
    while (off + NLA_HDRLEN <= len) {
        struct nlattr a;
        memcpy(&a, buf + off, sizeof a);
        if (a.nla_len < NLA_HDRLEN || off + a.nla_len > len)
            break;
        if ((a.nla_type & NLA_TYPE_MASK) == want && a.nla_len >= NLA_HDRLEN + 8) {
            uint64_t v = 0;
            memcpy(&v, buf + off + NLA_HDRLEN, 8);
            return __builtin_bswap64(v);
        }
        off += (a.nla_len + 3) & ~3u;
    }
    return 0;
}

static uint64_t get_chain_handle(int nf, const char *table, const char *chain)
{
    struct nlbuf b;
    nft_chain_msg(&b, NFT_MSG_GETCHAIN, 0, 100, table, chain);
    nl_finish(&b);
    CHECK(send(nf, b.data, b.len, 0) == (ssize_t)b.len, "getchain send");
    uint8_t resp[4096];
    ssize_t n = recv(nf, resp, sizeof resp, 0);
    CHECK(n >= (ssize_t)(NLMSG_HDRLEN + 4), "getchain recv");
    return find_be64_attr(resp + NLMSG_HDRLEN + 4, (size_t)n - NLMSG_HDRLEN - 4, NFTA_CHAIN_HANDLE);
}

static uint64_t get_first_rule_handle(int nf, const char *table, const char *chain)
{
    struct nlbuf b;
    nft_msg_init(&b, NFT_MSG_GETRULE, NLM_F_DUMP, 101, NFPROTO_IPV4);
    nl_attr_str(&b, NFTA_RULE_TABLE, table);
    nl_attr_str(&b, NFTA_RULE_CHAIN, chain);
    nl_finish(&b);
    CHECK(send(nf, b.data, b.len, 0) == (ssize_t)b.len, "getrule send");
    uint64_t handle = 0;
    for (;;) {
        uint8_t resp[8192];
        ssize_t n = recv(nf, resp, sizeof resp, 0);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN, "getrule recv");
        size_t off = 0;
        int done = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, resp + off, sizeof h);
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            if ((h.nlmsg_type & 0xff) == NFT_MSG_NEWRULE && handle == 0) {
                handle = find_be64_attr(resp + off + NLMSG_HDRLEN + 4,
                                        h.nlmsg_len - NLMSG_HDRLEN - 4, NFTA_RULE_HANDLE);
            }
            off += (h.nlmsg_len + 3) & ~3u;
        }
        if (done)
            break;
    }
    return handle;
}

static void test_nft_control_plane_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf");

    /* Create table t, chain c1, chain target, verdict map vm with element jumping to target */
    struct nlbuf m[5];
    nft_table_msg(&m[0], NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, 1, "t");
    nft_chain_msg(&m[1], NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, 2, "t", "c1");
    nft_chain_msg(&m[2], NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, 3, "t", "target");

    nft_msg_init(&m[3], NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK, 4, NFPROTO_IPV4);
    nl_attr_str(&m[3], NFTA_SET_TABLE, "t");
    nl_attr_str(&m[3], NFTA_SET_NAME, "vm");
    nl_attr_be32(&m[3], NFTA_SET_FLAGS, NFT_SET_MAP);
    nl_attr_be32(&m[3], NFTA_SET_KEY_LEN, 2);
    nl_attr_be32(&m[3], NFTA_SET_DATA_TYPE, NFT_DATA_VERDICT);

    nft_msg_init(&m[4], NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK, 5, NFPROTO_IPV4);
    nl_attr_str(&m[4], NFTA_SET_ELEM_LIST_TABLE, "t");
    nl_attr_str(&m[4], NFTA_SET_ELEM_LIST_SET, "vm");
    size_t els = nl_attr_start(&m[4], NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED);
    size_t el = nl_attr_start(&m[4], NFTA_LIST_ELEM | NLA_F_NESTED);
    uint16_t port80 = htons(80);
    nft_put_data_val(&m[4], NFTA_SET_ELEM_KEY, &port80, 2);
    size_t dat = nl_attr_start(&m[4], NFTA_SET_ELEM_DATA | NLA_F_NESTED);
    size_t verd = nl_attr_start(&m[4], NFTA_DATA_VERDICT | NLA_F_NESTED);
    nl_attr_be32(&m[4], NFTA_VERDICT_CODE, (uint32_t)NFT_JUMP);
    nl_attr_str(&m[4], NFTA_VERDICT_CHAIN, "target");
    nl_attr_end(&m[4], verd);
    nl_attr_end(&m[4], dat);
    nl_attr_end(&m[4], el);
    nl_attr_end(&m[4], els);

    int errs[5];
    nft_batch_send(nf, m, 5, errs, 5);
    for (int i = 0; i < 5; i++)
        CHECK(errs[i] == 0, "setup batch[%d] err %d", i, errs[i]);

    /* Deleting chain referenced by verdict map must fail with EBUSY */
    struct nlbuf b;
    nft_chain_msg(&b, NFT_MSG_DELCHAIN, NLM_F_ACK, 6, "t", "target");
    int e = nft_batch_one(nf, &b);
    CHECK(e == EBUSY, "delchain referenced by vmap must be EBUSY, got %d", e);

    /* Rename chain target -> renamed by handle */
    uint64_t th = get_chain_handle(nf, "t", "target");
    CHECK(th != 0, "target handle");
    nft_chain_msg(&b, NFT_MSG_NEWCHAIN, NLM_F_ACK, 7, "t", "renamed");
    nl_attr_be64(&b, NFTA_CHAIN_HANDLE, th);
    e = nft_batch_one(nf, &b);
    CHECK(e == 0, "rename chain err %d", e);
    CHECK(get_chain_handle(nf, "t", "renamed") == th, "renamed chain keeps handle");

    /* Verdict map reference must now point to renamed -> still EBUSY */
    nft_chain_msg(&b, NFT_MSG_DELCHAIN, NLM_F_ACK, 8, "t", "renamed");
    e = nft_batch_one(nf, &b);
    CHECK(e == EBUSY, "renamed chain still referenced by vmap -> EBUSY, got %d", e);

    /* Add a rule to c1, replace it with NLM_F_REPLACE, and verify its handle is preserved */
    nft_rule_msg(&b, NLM_F_CREATE | NLM_F_ACK, 9, "t", "c1");
    e = nft_batch_one(nf, &b);
    CHECK(e == 0, "add rule err %d", e);
    uint64_t rh = get_first_rule_handle(nf, "t", "c1");
    CHECK(rh != 0, "rule handle");

    nft_rule_msg(&b, NLM_F_REPLACE | NLM_F_ACK, 10, "t", "c1");
    nl_attr_be64(&b, NFTA_RULE_HANDLE, rh);
    e = nft_batch_one(nf, &b);
    CHECK(e == 0, "replace rule err %d", e);
    uint64_t rh2 = get_first_rule_handle(nf, "t", "c1");
    CHECK(rh2 == rh, "replaced rule handle changed %llu -> %llu", (unsigned long long)rh,
          (unsigned long long)rh2);

    /* DELTABLE with NLM_F_NONREC on non-empty table must fail with EBUSY */
    nft_table_msg(&b, NFT_MSG_DELTABLE, NLM_F_NONREC | NLM_F_ACK, 11, "t");
    e = nft_batch_one(nf, &b);
    CHECK(e == EBUSY, "DELTABLE NONREC on non-empty table must EBUSY, got %d", e);

    /* Delete set, chains, then DELTABLE with NLM_F_NONREC succeeds */
    struct nlbuf cleanup[4];
    nft_msg_init(&cleanup[0], NFT_MSG_DELSET, NLM_F_ACK, 12, NFPROTO_IPV4);
    nl_attr_str(&cleanup[0], NFTA_SET_TABLE, "t");
    nl_attr_str(&cleanup[0], NFTA_SET_NAME, "vm");
    nft_chain_msg(&cleanup[1], NFT_MSG_DELCHAIN, NLM_F_ACK, 13, "t", "renamed");
    nft_chain_msg(&cleanup[2], NFT_MSG_DELCHAIN, NLM_F_ACK, 14, "t", "c1");
    nft_table_msg(&cleanup[3], NFT_MSG_DELTABLE, NLM_F_NONREC | NLM_F_ACK, 15, "t");
    int cerrs[4];
    nft_batch_send(nf, cleanup, 4, cerrs, 4);
    for (int i = 0; i < 4; i++)
        CHECK(cerrs[i] == 0, "cleanup[%d] err %d", i, cerrs[i]);

    close(nf);
}

static void test_nft_control_plane(void)
{
    CHECK(run_in_child(test_nft_control_plane_child) == 0, "nft control plane");
    ok("nft_control_plane");
}

/* ---- 10. kernel/netns: dual-stack AF_INET6 wildcard DNAT & CLOSE_WAIT forwarded peer ---- */

static int find_non_lo_ipv4(struct in_addr *out)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    struct ifreq reqs[32];
    struct ifconf ifc = {.ifc_len = (int)sizeof reqs, .ifc_req = reqs};
    int ok_found = 0;
    if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
        int n = ifc.ifc_len / (int)sizeof reqs[0];
        for (int i = 0; i < n; i++) {
            if (reqs[i].ifr_addr.sa_family != AF_INET)
                continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)&reqs[i].ifr_addr;
            if ((ntohl(sin->sin_addr.s_addr) >> 24) != 127 && sin->sin_addr.s_addr != 0) {
                *out = sin->sin_addr;
                ok_found = 1;
                break;
            }
        }
    }
    close(s);
    return ok_found;
}

static void nft_put_expr(struct nlbuf *b, const char *name, const uint8_t *data, size_t dlen)
{
    size_t el = nl_attr_start(b, NFTA_LIST_ELEM | NLA_F_NESTED);
    nl_attr(b, NFTA_EXPR_NAME, name, strlen(name) + 1);
    nl_attr(b, NFTA_EXPR_DATA | NLA_F_NESTED, data, dlen);
    nl_attr_end(b, el);
}

static void test_dualstack_dnat_and_close_wait_peer(int filtered)
{
    struct in_addr host_ip = {0};
    if (!find_non_lo_ipv4(&host_ip)) {
        ok("dualstack_dnat_and_close_wait_peer (skipped: no non-lo ipv4)");
        return;
    }

    if (filtered)
        alarm(30);
    int p2c[2], c2p[2];
    CHECK(pipe(p2c) == 0 && pipe(c2p) == 0, "pipe");
    pid_t child = fork();
    CHECK(child >= 0, "fork");

    if (child == 0) {
        if (filtered)
            alarm(30);
        close(p2c[1]);
        close(c2p[0]);
        CHECK(unshare(CLONE_NEWNET) == 0, "child unshare");
        char b = 1;
        CHECK(write(c2p[1], &b, 1) == 1, "notify unshared");
        CHECK(read(p2c[0], &b, 1) == 1, "wait veth");

        int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        CHECK(rtnl >= 0, "child rtnl");
        set_link_up(rtnl, 1);
        int if1 = (int)if_nametoindex("fw1");
        CHECK(if1 > 0, "fw1 index");
        set_link_up(rtnl, if1);
        add_v4_addr(rtnl, if1, "10.91.0.2", 24);
        /* Default route via 10.91.0.1 */
        struct in_addr gw;
        CHECK(inet_pton(AF_INET, "10.91.0.1", &gw) == 1, "pton gw");
        struct nlbuf rb;
        nl_init(&rb, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 20);
        struct rtmsg rtm = {
            .rtm_family = AF_INET,
            .rtm_table = RT_TABLE_MAIN,
            .rtm_protocol = RTPROT_BOOT,
            .rtm_scope = RT_SCOPE_UNIVERSE,
            .rtm_type = RTN_UNICAST,
        };
        nl_put_raw(&rb, &rtm, sizeof rtm);
        nl_attr(&rb, RTA_GATEWAY, &gw, 4);
        CHECK(nl_send_ack(rtnl, &rb) == 0, "child default route");
        close(rtnl);

        int srv = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(srv >= 0, "child srv");
        int one = 1;
        CHECK(setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "reuseaddr");
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(18080)};
        CHECK(inet_pton(AF_INET, "10.91.0.2", &sa.sin_addr) == 1, "pton srv");
        CHECK(bind(srv, (struct sockaddr *)&sa, sizeof sa) == 0, "child bind");
        CHECK(listen(srv, 4) == 0, "child listen");

        CHECK(write(c2p[1], &b, 1) == 1, "notify listening");

        /* Read expected client port from parent */
        uint16_t cli_port = 0;
        CHECK(read(p2c[0], &cli_port, sizeof cli_port) == (ssize_t)sizeof cli_port, "read cli_port");

        int acc = accept(srv, NULL, NULL);
        CHECK(acc >= 0, "child accept");

        struct sockaddr_in peer = {0};
        socklen_t plen = sizeof peer;
        CHECK(getpeername(acc, (struct sockaddr *)&peer, &plen) == 0, "getpeername established");
        CHECK(peer.sin_addr.s_addr == host_ip.s_addr && peer.sin_port == cli_port,
              "established peer mismatch: got 0x%x:%u want 0x%x:%u", ntohl(peer.sin_addr.s_addr),
              ntohs(peer.sin_port), ntohl(host_ip.s_addr), ntohs(cli_port));

        char buf[16];
        CHECK(recv(acc, buf, 4, MSG_WAITALL) == 4 && memcmp(buf, "ping", 4) == 0, "recv ping");
        /* Tell parent to tear down client side so forwarder closes & forgets OUTSIDE entry */
        CHECK(write(c2p[1], &b, 1) == 1, "notify close");
        /* Wait for EOF (acc enters CLOSE_WAIT after forwarder closes upstream) */
        ssize_t eof = recv(acc, buf, sizeof buf, 0);
        CHECK(eof == 0, "expected EOF into CLOSE_WAIT got %zd", eof);
        usleep(30000);

        memset(&peer, 0, sizeof peer);
        plen = sizeof peer;
        CHECK(getpeername(acc, (struct sockaddr *)&peer, &plen) == 0, "getpeername CLOSE_WAIT");
        CHECK(peer.sin_addr.s_addr == host_ip.s_addr && peer.sin_port == cli_port,
              "CLOSE_WAIT peer reverted: got 0x%x:%u want 0x%x:%u", ntohl(peer.sin_addr.s_addr),
              ntohs(peer.sin_port), ntohl(host_ip.s_addr), ntohs(cli_port));

        close(acc);
        close(srv);
        _exit(0);
    }

    close(p2c[0]);
    close(c2p[1]);
    char b = 0;
    CHECK(read(c2p[0], &b, 1) == 1, "wait child unshare");

    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "parent rtnl");
    /* Create veth fw0 (init_ns) <-> fw1 (child netns) */
    create_veth(rtnl, "fw0", "fw1", child);

    int if0 = (int)if_nametoindex("fw0");
    CHECK(if0 > 0, "fw0 index");
    set_link_up(rtnl, if0);
    add_v4_addr(rtnl, if0, "10.91.0.1", 24);
    CHECK(write(p2c[1], &b, 1) == 1, "notify veth ready");
    CHECK(read(c2p[0], &b, 1) == 1, "wait child listening");

    /* Dual-stack AF_INET6 wildcard listener in init_ns (!IPV6_V6ONLY) */
    int srv6 = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(srv6 >= 0, "srv6");
    int zero = 0;
    CHECK(setsockopt(srv6, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == 0, "IPV6_V6ONLY=0");
    struct sockaddr_in6 sin6 = {.sin6_family = AF_INET6};
    CHECK(bind(srv6, (struct sockaddr *)&sin6, sizeof sin6) == 0, "bind [::]:0");
    socklen_t s6len = sizeof sin6;
    CHECK(getsockname(srv6, (struct sockaddr *)&sin6, &s6len) == 0 && sin6.sin6_port != 0,
          "getsockname srv6");
    if (filtered) {
        /* One classic BPF RET 0, on a host that refuses attachment to TCP. */
        struct sock_filter drop = {.code = BPF_RET | BPF_K};
        struct sock_fprog prog = {1, &drop};
        CHECK(syscall(TEST_SYSCALL, HOOK_REFUSE_TCP_FILTERS, 1) == 0, "force host refusal");
        CHECK(setsockopt(srv6, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) == 0,
              "attach RET 0");
        CHECK(fcntl(srv6, F_SETFL, O_NONBLOCK) == 0, "nonblocking filtered listener");
    }
    CHECK(listen(srv6, 4) == 0, "listen srv6");

    /* Install IPv4 PREROUTING DNAT matching TCP dport == sin6.sin6_port -> 10.91.0.2:18080 */
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf init");
    struct nlbuf m[3];
    nft_table_msg(&m[0], NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, 1, "fwdt");
    nft_base_chain_msg(&m[1], 2, "fwdt", "pre", NF_INET_PRE_ROUTING, -100, NF_ACCEPT, "nat");
    nft_rule_msg(&m[2], NLM_F_CREATE | NLM_F_ACK, 3, "fwdt", "pre");
    size_t exs = nl_attr_start(&m[2], NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);

    struct nlbuf ed;
    /* meta l4proto -> reg1 */
    ed.len = 0;
    nl_attr_be32(&ed, 2 /* NFTA_META_KEY */, 16);
    nl_attr_be32(&ed, 1 /* NFTA_META_DREG */, 1);
    nft_put_expr(&m[2], "meta", ed.data, ed.len);
    /* cmp reg1 == IPPROTO_TCP (6) */
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* NFTA_CMP_SREG */, 1);
    nl_attr_be32(&ed, 2 /* NFTA_CMP_OP */, 0);
    uint8_t tcp_p = IPPROTO_TCP;
    nft_put_data_val(&ed, 3, &tcp_p, 1);
    nft_put_expr(&m[2], "cmp", ed.data, ed.len);
    /* payload th@2,2 -> reg1 */
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* DREG */, 1);
    nl_attr_be32(&ed, 2 /* BASE */, 2);
    nl_attr_be32(&ed, 3 /* OFFSET */, 2);
    nl_attr_be32(&ed, 4 /* LEN */, 2);
    nft_put_expr(&m[2], "payload", ed.data, ed.len);
    /* cmp reg1 == sin6.sin6_port */
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    nft_put_data_val(&ed, 3, &sin6.sin6_port, 2);
    nft_put_expr(&m[2], "cmp", ed.data, ed.len);
    /* immediate 10.91.0.2 -> reg1 */
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    uint8_t dst_ip[4] = {10, 91, 0, 2};
    nft_put_data_val(&ed, 2, dst_ip, 4);
    nft_put_expr(&m[2], "immediate", ed.data, ed.len);
    /* immediate 18080 -> reg2 */
    ed.len = 0;
    nl_attr_be32(&ed, 1, 2);
    uint16_t dst_port = htons(18080);
    nft_put_data_val(&ed, 2, &dst_port, 2);
    nft_put_expr(&m[2], "immediate", ed.data, ed.len);
    /* nat dnat ipv4 reg1:reg2 */
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* TYPE */, 1);
    nl_attr_be32(&ed, 2 /* FAMILY */, NFPROTO_IPV4);
    nl_attr_be32(&ed, 3 /* REG_ADDR_MIN */, 1);
    nl_attr_be32(&ed, 5 /* REG_PROTO_MIN */, 2);
    nft_put_expr(&m[2], "nat", ed.data, ed.len);
    nl_attr_end(&m[2], exs);

    int errs[3] = {-1, -1, -1};
    nft_batch_send(nf, m, 3, errs, 3);
    CHECK(errs[0] == 0 && errs[1] == 0 && errs[2] == 0, "install dnat %d %d %d", errs[0], errs[1],
          errs[2]);

    /* Connect via IPv4 to host_ip:P -> must be forwarded through dual-stack srv6 to 10.91.0.2:18080 */
    int cli = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(cli >= 0, "cli");
    struct sockaddr_in cbind = {.sin_family = AF_INET, .sin_addr = host_ip};
    CHECK(bind(cli, (struct sockaddr *)&cbind, sizeof cbind) == 0, "bind cli");
    socklen_t clen = sizeof cbind;
    CHECK(getsockname(cli, (struct sockaddr *)&cbind, &clen) == 0, "getsockname cli");
    CHECK(write(p2c[1], &cbind.sin_port, sizeof cbind.sin_port) == (ssize_t)sizeof cbind.sin_port,
          "send cli_port");

    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_addr = host_ip, .sin_port = sin6.sin6_port};
    CHECK(connect(cli, (struct sockaddr *)&dst, sizeof dst) == 0, "connect dual-stack dnat");
    CHECK(send(cli, "ping", 4, 0) == 4, "send ping");
    CHECK(read(c2p[0], &b, 1) == 1, "wait child accepted");

    if (filtered) {
        CHECK(accept(srv6, NULL, NULL) < 0 && errno == EAGAIN, "private forwarding queue");
        int other = socket(AF_INET6, SOCK_STREAM, 0);
        CHECK(other >= 0 && setsockopt(other, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) == 0,
              "reuseport");
        CHECK(bind(other, (struct sockaddr *)&sin6, sizeof sin6) < 0 && errno == EADDRINUSE,
              "exclusive DNAT listener");
        close(other);
    }

    /* Close cli with RST so forwarder aborts relay and removes OUTSIDE entry while child is in CLOSE_WAIT */
    struct linger lg = {.l_onoff = 1, .l_linger = 0};
    CHECK(setsockopt(cli, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0, "cli SO_LINGER");
    close(cli);

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child, "waitpid child");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed status %d", status);

    /* Clean up init_ns table and veth */
    struct nlbuf delt;
    nft_table_msg(&delt, NFT_MSG_DELTABLE, NLM_F_ACK, 4, "fwdt");
    CHECK(nft_batch_one(nf, &delt) == 0, "delete fwdt");

    if (filtered) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(c >= 0 && connect(c, (struct sockaddr *)&dst, sizeof dst) < 0 && errno == ECONNREFUSED,
              "withdrawn DNAT closed");
        close(c);
        CHECK(setsockopt(srv6, SOL_SOCKET, SO_DETACH_FILTER, &zero, sizeof zero) == 0,
              "detach after withdrawal");
        CHECK(accept(srv6, NULL, NULL) < 0 && errno == EAGAIN, "empty queue after withdrawal");
        c = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(c >= 0 && connect(c, (struct sockaddr *)&dst, sizeof dst) == 0,
              "original port after detach");
        int accepted = accept(srv6, NULL, NULL);
        CHECK(accepted >= 0, "guest accepts on original port");
        close(accepted);
        close(c);
    }

    struct nlbuf vb;
    nl_init(&vb, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 31);
    struct ifinfomsg dfi = {.ifi_index = if0};
    nl_put_raw(&vb, &dfi, sizeof dfi);
    int dl = nl_send_ack(rtnl, &vb);
    CHECK(dl == 0 || dl == ENODEV, "delete fw0 err %d", dl);

    close(srv6);
    close(nf);
    close(rtnl);
    close(p2c[1]);
    close(c2p[0]);
    ok("dualstack_dnat_and_close_wait_peer");
}

/* ---- 11. kernel/netlink: rtnetlink notification seq/port/flags and NLM_F_ECHO ---- */

static void test_rtnl_notify_echo_child(void)
{
    enum {
        SOL_NETLINK_ = 270,
        NETLINK_PKTINFO_ = 3,
        NLM_F_ECHO_ = 0x08,
        RTM_DELADDR_ = 21,
        RTM_DELROUTE_ = 25,
        RTMGRP_LINK_ = 0x1,
        RTMGRP_IPV4_IFADDR_ = 0x10,
        RTMGRP_IPV4_ROUTE_ = 0x40,
        RTMGRP_IPV6_ROUTE_ = 0x400,
    };
    struct nl_pktinfo_ {
        uint32_t group;
    };

    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int setup = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(setup >= 0, "setup rtnl");
    set_link_up(setup, 1);
    create_dummy(setup, "d0");
    int d0 = (int)if_nametoindex("d0");
    CHECK(d0 > 1, "d0 index");
    set_link_up(setup, d0);
    close(setup);

    uint32_t all_groups = RTMGRP_LINK_ | RTMGRP_IPV4_IFADDR_ | RTMGRP_IPV4_ROUTE_ | RTMGRP_IPV6_ROUTE_;
    int mon = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int tx = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int txs = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(mon >= 0 && tx >= 0 && txs >= 0, "nl sockets");
    struct sockaddr_nl sa_mon = {.nl_family = AF_NETLINK, .nl_groups = all_groups};
    struct sockaddr_nl sa_tx = {.nl_family = AF_NETLINK, .nl_groups = 0};
    struct sockaddr_nl sa_txs = {.nl_family = AF_NETLINK, .nl_groups = all_groups};
    CHECK(bind(mon, (struct sockaddr *)&sa_mon, sizeof sa_mon) == 0, "bind mon");
    CHECK(bind(tx, (struct sockaddr *)&sa_tx, sizeof sa_tx) == 0, "bind tx");
    CHECK(bind(txs, (struct sockaddr *)&sa_txs, sizeof sa_txs) == 0, "bind txs");
    int one = 1;
    CHECK(setsockopt(tx, SOL_NETLINK_, NETLINK_PKTINFO_, &one, sizeof one) == 0, "pktinfo tx");
    CHECK(setsockopt(txs, SOL_NETLINK_, NETLINK_PKTINFO_, &one, sizeof one) == 0, "pktinfo txs");
    CHECK(setsockopt(mon, SOL_NETLINK_, NETLINK_PKTINFO_, &one, sizeof one) == 0, "pktinfo mon");

    socklen_t sl = sizeof sa_tx;
    CHECK(getsockname(tx, (struct sockaddr *)&sa_tx, &sl) == 0, "getsockname tx");
    CHECK(getsockname(txs, (struct sockaddr *)&sa_txs, &sl) == 0, "getsockname txs");
    uint32_t tx_pid = sa_tx.nl_pid;
    uint32_t txs_pid = sa_txs.nl_pid;
    CHECK(tx_pid != 0 && txs_pid != 0 && tx_pid != txs_pid, "distinct pids");

    /* Helper macro to read one message header + pktinfo group */
#define RECV_ONE(fd_, hdr_, grp_)                                                                  \
    do {                                                                                           \
        uint8_t _buf[4096], _ctl[64];                                                              \
        struct sockaddr_nl _from = {0};                                                            \
        struct iovec _v = {_buf, sizeof _buf};                                                     \
        struct msghdr _m = {.msg_name = &_from,                                                    \
                            .msg_namelen = sizeof _from,                                           \
                            .msg_iov = &_v,                                                        \
                            .msg_iovlen = 1,                                                       \
                            .msg_control = _ctl,                                                   \
                            .msg_controllen = sizeof _ctl};                                        \
        ssize_t _n = recvmsg((fd_), &_m, MSG_DONTWAIT);                                            \
        CHECK(_n >= (ssize_t)sizeof(struct nlmsghdr), "recvmsg %zd", _n);                          \
        memcpy(&(hdr_), _buf, sizeof(hdr_));                                                       \
        (grp_) = 0;                                                                                \
        for (struct cmsghdr *_c = CMSG_FIRSTHDR(&_m); _c; _c = CMSG_NXTHDR(&_m, _c))               \
            if (_c->cmsg_level == SOL_NETLINK_ && _c->cmsg_type == NETLINK_PKTINFO_)               \
                (grp_) = ((struct nl_pktinfo_ *)CMSG_DATA(_c))->group;                             \
    } while (0)

    /* 1. IPv4 RTM_NEWADDR with NLM_F_ECHO|NLM_F_ACK on unsubscribed tx:
     *    tx gets echoed RTM_NEWADDR before ACK with seq/pid/group=5;
     *    mon gets RTM_NEWADDR with seq/pid plus auto-routes with CREATE|EXCL and seq/pid=0. */
    struct in_addr ip;
    CHECK(inet_pton(AF_INET, "10.66.0.1", &ip) == 1, "pton");
    struct nlbuf b;
    nl_init(&b, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK | NLM_F_ECHO_, 501);
    struct ifaddrmsg ifa = {.ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_index = (uint32_t)d0};
    nl_put_raw(&b, &ifa, sizeof ifa);
    nl_attr(&b, IFA_LOCAL, &ip, 4);
    nl_attr(&b, IFA_ADDRESS, &ip, 4);
    nl_finish(&b);
    CHECK(send(tx, b.data, b.len, 0) == (ssize_t)b.len, "send NEWADDR");

    struct nlmsghdr h;
    uint32_t grp;
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == RTM_NEWADDR && h.nlmsg_flags == 0 && h.nlmsg_seq == 501 &&
              h.nlmsg_pid == tx_pid && grp == 5,
          "tx echo NEWADDR got ty=%u fl=%#x seq=%u pid=%u grp=%u", h.nlmsg_type, h.nlmsg_flags,
          h.nlmsg_seq, h.nlmsg_pid, grp);
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == 501 && grp == 0, "tx ACK after echo");

    int saw_addr = 0, saw_auto_rt = 0;
    for (;;) {
        uint8_t tmp[4096];
        ssize_t n = recv(mon, tmp, sizeof tmp, MSG_DONTWAIT);
        if (n < 0 && errno == EAGAIN)
            break;
        CHECK(n >= (ssize_t)sizeof h, "mon recv");
        memcpy(&h, tmp, sizeof h);
        if (h.nlmsg_type == RTM_NEWADDR) {
            CHECK(h.nlmsg_seq == 501 && h.nlmsg_pid == tx_pid && h.nlmsg_flags == 0,
                  "mon NEWADDR seq=%u pid=%u fl=%#x", h.nlmsg_seq, h.nlmsg_pid, h.nlmsg_flags);
            saw_addr = 1;
        } else if (h.nlmsg_type == RTM_NEWROUTE) {
            CHECK(h.nlmsg_seq == 0 && h.nlmsg_pid == 0 &&
                      h.nlmsg_flags == (NLM_F_CREATE | NLM_F_EXCL),
                  "mon auto NEWROUTE seq=%u pid=%u fl=%#x", h.nlmsg_seq, h.nlmsg_pid, h.nlmsg_flags);
            saw_auto_rt = 1;
        }
    }
    CHECK(saw_addr && saw_auto_rt, "mon saw addr=%d rt=%d", saw_addr, saw_auto_rt);
    /* Drain txs from step 1 */
    while (recv(txs, b.data, sizeof b.data, MSG_DONTWAIT) > 0)
        ;

    /* 2. IPv4 RTM_NEWROUTE CREATE|ACK|ECHO (even without EXCL -> notifies CREATE|EXCL) */
    struct in_addr dst;
    CHECK(inet_pton(AF_INET, "10.67.0.0", &dst) == 1, "pton");
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_ECHO_, 502);
    struct rtmsg rtm = {.rtm_family = AF_INET,
                        .rtm_dst_len = 24,
                        .rtm_table = RT_TABLE_MAIN,
                        .rtm_protocol = RTPROT_BOOT,
                        .rtm_scope = RT_SCOPE_LINK,
                        .rtm_type = RTN_UNICAST};
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)d0);
    nl_finish(&b);
    CHECK(send(tx, b.data, b.len, 0) == (ssize_t)b.len, "send NEWROUTE");

    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == RTM_NEWROUTE && h.nlmsg_flags == (NLM_F_CREATE | NLM_F_EXCL) &&
              h.nlmsg_seq == 502 && h.nlmsg_pid == tx_pid && grp == 7,
          "tx echo NEWROUTE ty=%u fl=%#x seq=%u pid=%u grp=%u", h.nlmsg_type, h.nlmsg_flags,
          h.nlmsg_seq, h.nlmsg_pid, grp);
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == 502, "tx ACK NEWROUTE");
    RECV_ONE(mon, h, grp);
    CHECK(h.nlmsg_type == RTM_NEWROUTE && h.nlmsg_flags == (NLM_F_CREATE | NLM_F_EXCL) &&
              h.nlmsg_seq == 502 && h.nlmsg_pid == tx_pid && grp == 7,
          "mon NEWROUTE");
    while (recv(txs, b.data, sizeof b.data, MSG_DONTWAIT) > 0)
        ;

    /* 3. Subscribed sender txs sends RTM_NEWROUTE REPLACE|CREATE|ACK|ECHO:
     *    must receive ONLY ONE RTM_NEWROUTE (before ACK, no duplicate!), with NLM_F_REPLACE. */
    nl_init(&b, RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK | NLM_F_ECHO_, 503);
    rtm.rtm_protocol = 4; /* RTPROT_STATIC */
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)d0);
    nl_finish(&b);
    CHECK(send(txs, b.data, b.len, 0) == (ssize_t)b.len, "send replace");

    RECV_ONE(txs, h, grp);
    CHECK(h.nlmsg_type == RTM_NEWROUTE && h.nlmsg_flags == NLM_F_REPLACE && h.nlmsg_seq == 503 &&
              h.nlmsg_pid == txs_pid && grp == 7,
          "txs echo REPLACE ty=%u fl=%#x seq=%u pid=%u grp=%u", h.nlmsg_type, h.nlmsg_flags,
          h.nlmsg_seq, h.nlmsg_pid, grp);
    RECV_ONE(txs, h, grp);
    CHECK(h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == 503, "txs ACK REPLACE");
    errno = 0;
    CHECK(recv(txs, b.data, sizeof b.data, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "subscribed sender with NLM_F_ECHO must not get duplicate");
    RECV_ONE(mon, h, grp);
    CHECK(h.nlmsg_type == RTM_NEWROUTE && h.nlmsg_flags == NLM_F_REPLACE && h.nlmsg_seq == 503 &&
              h.nlmsg_pid == txs_pid,
          "mon REPLACE");

    /* 4. DELROUTE with ECHO|ACK */
    nl_init(&b, RTM_DELROUTE_, NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO_, 504);
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)d0);
    nl_finish(&b);
    CHECK(send(tx, b.data, b.len, 0) == (ssize_t)b.len, "send DELROUTE");
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == RTM_DELROUTE_ && h.nlmsg_flags == 0 && h.nlmsg_seq == 504 &&
              h.nlmsg_pid == tx_pid && grp == 7,
          "tx echo DELROUTE");
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == 504, "tx ACK DELROUTE");

    /* 5. DELADDR with ECHO|ACK */
    nl_init(&b, RTM_DELADDR_, NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO_, 505);
    nl_put_raw(&b, &ifa, sizeof ifa);
    nl_attr(&b, IFA_LOCAL, &ip, 4);
    nl_attr(&b, IFA_ADDRESS, &ip, 4);
    nl_finish(&b);
    CHECK(send(tx, b.data, b.len, 0) == (ssize_t)b.len, "send DELADDR");
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == RTM_DELADDR_ && h.nlmsg_flags == 0 && h.nlmsg_seq == 505 &&
              h.nlmsg_pid == tx_pid && grp == 5,
          "tx echo DELADDR");
    RECV_ONE(tx, h, grp);
    CHECK(h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == 505, "tx ACK DELADDR");

#undef RECV_ONE
    close(mon);
    close(tx);
    close(txs);
}

static void test_rtnl_notify_echo(void)
{
    CHECK(run_in_child(test_rtnl_notify_echo_child) == 0, "rtnl notify & echo");
    ok("rtnl_notify_echo");
}

/* ---- 12. kernel/route: ip route get with RTA_IIF ---- */

static void test_route_get_iif_child(void)
{
    enum {
        RTM_GETROUTE_ = 26,
        RTA_SRC_ = 2,
        RTA_IIF_ = 3,
        RTA_PREFSRC_ = 7,
        RTA_UID_ = 25,
        RTN_LOCAL_ = 2,
    };
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    create_dummy(rtnl, "d0");
    create_dummy(rtnl, "d1");
    create_dummy(rtnl, "d2");
    int d0 = (int)if_nametoindex("d0");
    int d1 = (int)if_nametoindex("d1");
    int d2 = (int)if_nametoindex("d2");
    set_link_up(rtnl, d0);
    set_link_up(rtnl, d1);
    /* d2 stays down */
    add_v4_addr(rtnl, d0, "10.1.0.1", 24);
    add_v4_addr(rtnl, d1, "10.2.0.1", 24);

    /* Add route 10.9.0.0/16 dev d1 */
    struct in_addr dst9;
    CHECK(inet_pton(AF_INET, "10.9.0.0", &dst9) == 1, "pton");
    struct nlbuf b;
    nl_init(&b, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 10);
    struct rtmsg rtm = {.rtm_family = AF_INET,
                        .rtm_dst_len = 16,
                        .rtm_table = RT_TABLE_MAIN,
                        .rtm_protocol = RTPROT_BOOT,
                        .rtm_scope = RT_SCOPE_LINK,
                        .rtm_type = RTN_UNICAST};
    nl_put_raw(&b, &rtm, sizeof rtm);
    nl_attr(&b, RTA_DST, &dst9, 4);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)d1);
    CHECK(nl_send_ack(rtnl, &b) == 0, "add 10.9.0.0/16");

    /* When procfs is mounted, toggle ip_forward explicitly; otherwise accept whichever default
     * forwarding state the new netns inherited from the initial namespace. */
    int has_proc = access("/proc/sys/net/ipv4/ip_forward", W_OK) == 0;
    if (has_proc) {
        int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
        CHECK(fd >= 0 && write(fd, "0\n", 2) == 2, "ip_forward=0");
        close(fd);
    }

    uint8_t resp[4096];
    struct in_addr ip_dst, ip_src;

    /* Helper: send RTM_GETROUTE with iif and optional src */
#define GET_RT_V4(dst_s_, src_s_, iif_)                                                            \
    ({                                                                                             \
        nl_init(&b, RTM_GETROUTE_, NLM_F_REQUEST, 20);                                             \
        struct rtmsg _r = {.rtm_family = AF_INET, .rtm_dst_len = 32};                              \
        nl_put_raw(&b, &_r, sizeof _r);                                                            \
        CHECK(inet_pton(AF_INET, (dst_s_), &ip_dst) == 1, "pton dst");                             \
        nl_attr(&b, RTA_DST, &ip_dst, 4);                                                          \
        if ((src_s_) != NULL) {                                                                    \
            CHECK(inet_pton(AF_INET, (src_s_), &ip_src) == 1, "pton src");                         \
            nl_attr(&b, RTA_SRC_, &ip_src, 4);                                                     \
        }                                                                                          \
        int32_t _iif = (iif_);                                                                     \
        nl_attr(&b, RTA_IIF_, &_iif, 4);                                                           \
        nl_finish(&b);                                                                             \
        CHECK(send(rtnl, b.data, b.len, 0) == (ssize_t)b.len, "send getroute");                    \
        ssize_t _n = recv(rtnl, resp, sizeof resp, 0);                                             \
        CHECK(_n >= 20, "recv getroute");                                                          \
        struct nlmsghdr _h;                                                                        \
        memcpy(&_h, resp, sizeof _h);                                                              \
        int _rc = 0;                                                                               \
        if (_h.nlmsg_type == NLMSG_ERROR) {                                                        \
            int32_t _e;                                                                            \
            memcpy(&_e, resp + 16, 4);                                                             \
            _rc = -_e;                                                                             \
        } else {                                                                                   \
            CHECK(_h.nlmsg_type == RTM_NEWROUTE, "got ty=%u", _h.nlmsg_type);                      \
            _rc = 0;                                                                               \
        }                                                                                          \
        _rc;                                                                                       \
    })

    CHECK(GET_RT_V4("10.1.0.1", "10.1.0.5", 999) == ENODEV, "bad iif ENODEV");
    CHECK(GET_RT_V4("10.1.0.1", NULL, d0) == EINVAL, "no src EINVAL");
    CHECK(GET_RT_V4("10.1.0.1", "10.1.0.5", d2) == EXDEV, "down iif EXDEV");
    if (has_proc)
        CHECK(GET_RT_V4("10.9.0.5", "10.1.0.5", d0) == EHOSTUNREACH, "fwd disabled EHOSTUNREACH");

    /* Local input route succeeds with ip_forward=0 and carries RTA_IIF without RTA_PREFSRC/UID */
    CHECK(GET_RT_V4("10.1.0.1", "10.1.0.5", d0) == 0, "local iif ok");
    struct rtmsg got_rt;
    memcpy(&got_rt, resp + 16, sizeof got_rt);
    CHECK(got_rt.rtm_type == RTN_LOCAL_, "local type");
    int saw_iif = 0, saw_oif = 0;
    struct nlmsghdr rh;
    memcpy(&rh, resp, sizeof rh);
    for (size_t off = 16 + sizeof got_rt; off + 4 <= rh.nlmsg_len;) {
        struct nlattr a;
        memcpy(&a, resp + off, 4);
        if (a.nla_len < 4 || off + a.nla_len > rh.nlmsg_len)
            break;
        uint16_t t = a.nla_type & NLA_TYPE_MASK;
        CHECK(t != RTA_PREFSRC_ && t != RTA_UID_, "no prefsrc/uid on iif reply");
        if (t == RTA_IIF_) {
            int32_t v;
            memcpy(&v, resp + off + 4, 4);
            CHECK(v == d0, "iif=%d", v);
            saw_iif = 1;
        }
        if (t == RTA_OIF) {
            int32_t v;
            memcpy(&v, resp + off + 4, 4);
            CHECK(v == 1, "local oif=%d", v);
            saw_oif = 1;
        }
        off += (a.nla_len + 3) & ~3u;
    }
    CHECK(saw_iif && saw_oif, "local iif/oif attrs");

    /* Forwarding lookup: enable ip_forward=1 when procfs is mounted, else check valid result */
    if (has_proc) {
        int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
        CHECK(fd >= 0 && write(fd, "1\n", 2) == 2, "ip_forward=1");
        close(fd);
        CHECK(GET_RT_V4("10.9.0.5", "10.1.0.5", d0) == 0, "fwd enabled ok");
        memcpy(&got_rt, resp + 16, sizeof got_rt);
        CHECK(got_rt.rtm_type == RTN_UNICAST, "fwd type unicast");
    } else {
        int frc = GET_RT_V4("10.9.0.5", "10.1.0.5", d0);
        CHECK(frc == 0 || frc == EHOSTUNREACH, "fwd iif got %d", frc);
        if (frc == 0) {
            memcpy(&got_rt, resp + 16, sizeof got_rt);
            CHECK(got_rt.rtm_type == RTN_UNICAST, "fwd type unicast");
        }
    }

#undef GET_RT_V4
    close(rtnl);
}

static void test_route_get_iif(void)
{
    CHECK(run_in_child(test_route_get_iif_child) == 0, "route get iif");
    ok("route_get_iif");
}

/* ---- 13. kernel/net: SO_BINDTODEVICE / SO_BINDTOIFINDEX against guest netns devices ---- */

static void test_so_bindtodevice_unpriv_child(void)
{
    CHECK(setresgid(65534, 65534, 65534) == 0 && setresuid(65534, 65534, 65534) == 0, "drop privs");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0, "udp");
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "d1", 3) == 0, "unpriv initial bind d1");
    /* Nonexistent device still returns ENODEV before EPERM */
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "nosuch", 7) == -1 && errno == ENODEV,
          "unpriv rebind nosuch -> ENODEV");
    /* Rebinding or unbinding an already-bound socket without CAP_NET_RAW -> EPERM */
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == -1 && errno == EPERM,
          "unpriv rebind lo -> EPERM");
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "", 0) == -1 && errno == EPERM,
          "unpriv unbind -> EPERM");
    close(s);
}

static void test_so_bindtodevice_netns_child(void)
{
    enum { SO_BINDTOIFINDEX_ = 62 };
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    create_dummy(rtnl, "d0");
    create_dummy(rtnl, "d1");
    int i0 = (int)if_nametoindex("d0");
    int i1 = (int)if_nametoindex("d1");
    CHECK(i0 > 1 && i1 > i0, "dummy indices");
    set_link_up(rtnl, i0);
    set_link_up(rtnl, i1);
    add_v4_addr(rtnl, i0, "10.31.0.1", 24);
    add_v4_addr(rtnl, i1, "10.32.0.1", 24);

    /* Host-only interface name (not present in this new netns) must return ENODEV */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0, "udp");
    errno = 0;
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5) == -1 && errno == ENODEV,
          "absent host iface in new netns must be ENODEV");

    /* Bind to virtual device d0 by name; verify getsockopt len rules and SO_BINDTOIFINDEX */
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "d0", 3) == 0, "bind d0");
    char buf[32];
    socklen_t blen = 3;
    errno = 0;
    CHECK(getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, buf, &blen) == -1 && errno == EINVAL,
          "getsockopt SO_BINDTODEVICE with len < 16 must be EINVAL");
    blen = sizeof buf;
    CHECK(getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, buf, &blen) == 0 && blen == 3 &&
              strcmp(buf, "d0") == 0,
          "getsockopt SO_BINDTODEVICE -> d0");
    int idx = -1;
    socklen_t ilen = sizeof idx;
    CHECK(getsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &idx, &ilen) == 0 && idx == i0,
          "getsockopt SO_BINDTOIFINDEX -> %d", idx);

    /* Unbind with empty string */
    CHECK(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "", 0) == 0, "unbind");
    blen = 4;
    CHECK(getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, buf, &blen) == 0 && blen == 0,
          "unbound getsockopt len=0");
    close(s);

    /* Two TCP listeners on 0.0.0.0:19200 bound to d0 and d1 coexist and route by device;
     * accepted socket inherits SO_BINDTODEVICE. */
    int l0 = socket(AF_INET, SOCK_STREAM, 0);
    int l1 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(setsockopt(l0, SOL_SOCKET, SO_BINDTODEVICE, "d0", 3) == 0, "l0 bind dev d0");
    CHECK(setsockopt(l1, SOL_SOCKET, SO_BINDTODEVICE, "d1", 3) == 0, "l1 bind dev d1");
    struct sockaddr_in any = {
        .sin_family = AF_INET, .sin_port = htons(19200), .sin_addr.s_addr = htonl(INADDR_ANY)};
    CHECK(bind(l0, (struct sockaddr *)&any, sizeof any) == 0, "bind l0");
    CHECK(bind(l1, (struct sockaddr *)&any, sizeof any) == 0, "bind l1 (distinct dev)");
    CHECK(listen(l0, 4) == 0 && listen(l1, 4) == 0, "listen l0/l1");

    int c0 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dst0 = {.sin_family = AF_INET, .sin_port = htons(19200)};
    CHECK(inet_pton(AF_INET, "10.31.0.1", &dst0.sin_addr) == 1, "pton");
    CHECK(connect(c0, (struct sockaddr *)&dst0, sizeof dst0) == 0, "connect 10.31.0.1");
    int a0 = accept(l0, NULL, NULL);
    CHECK(a0 >= 0, "accept on l0");
    blen = sizeof buf;
    CHECK(getsockopt(a0, SOL_SOCKET, SO_BINDTODEVICE, buf, &blen) == 0 && strcmp(buf, "d0") == 0,
          "accepted socket inherits SO_BINDTODEVICE");
    close(a0);
    close(c0);

    int c1 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dst1 = {.sin_family = AF_INET, .sin_port = htons(19200)};
    CHECK(inet_pton(AF_INET, "10.32.0.1", &dst1.sin_addr) == 1, "pton");
    CHECK(connect(c1, (struct sockaddr *)&dst1, sizeof dst1) == 0, "connect 10.32.0.1");
    int a1 = accept(l1, NULL, NULL);
    CHECK(a1 >= 0, "accept on l1");
    close(a1);
    close(c1);
    close(l1);

    /* Delete d0 while l0 is bound -> SO_BINDTODEVICE returns ENODEV, SO_BINDTOIFINDEX keeps i0 */
    struct nlbuf db;
    nl_init(&db, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 30);
    struct ifinfomsg dfi = {.ifi_index = i0};
    nl_put_raw(&db, &dfi, sizeof dfi);
    CHECK(nl_send_ack(rtnl, &db) == 0, "delete d0");
    blen = sizeof buf;
    errno = 0;
    CHECK(getsockopt(l0, SOL_SOCKET, SO_BINDTODEVICE, buf, &blen) == -1 && errno == ENODEV,
          "deleted bound dev -> ENODEV");
    ilen = sizeof idx;
    CHECK(getsockopt(l0, SOL_SOCKET, SO_BINDTOIFINDEX_, &idx, &ilen) == 0 && idx == i0,
          "deleted bound dev keeps ifindex");
    close(l0);
    close(rtnl);

    CHECK(run_in_child(test_so_bindtodevice_unpriv_child) == 0, "unpriv SO_BINDTODEVICE");
}

static void test_so_bindtodevice_netns(void)
{
    CHECK(run_in_child(test_so_bindtodevice_netns_child) == 0, "SO_BINDTODEVICE netns");
    ok("so_bindtodevice_netns");
}

/* ---- 14. kernel/netns: nat-chain drop/reject semantics ---- */

static void test_nat_drop_reject_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    close(rtnl);

    /* Start TCP and UDP servers on 127.0.0.1:19301 (dropped) and 19302 (rejected) */
    int st1 = socket(AF_INET, SOCK_STREAM, 0), st2 = socket(AF_INET, SOCK_STREAM, 0);
    int su1 = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int one = 1;
    setsockopt(st1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(st2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a1 = {
        .sin_family = AF_INET, .sin_port = htons(19301), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in a2 = {
        .sin_family = AF_INET, .sin_port = htons(19302), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(st1, (struct sockaddr *)&a1, sizeof a1) == 0 && listen(st1, 4) == 0, "st1");
    CHECK(bind(st2, (struct sockaddr *)&a2, sizeof a2) == 0 && listen(st2, 4) == 0, "st2");
    CHECK(bind(su1, (struct sockaddr *)&a1, sizeof a1) == 0, "su1");

    /* Install OUTPUT nat chain: dport 19301 -> drop, dport 19302 -> reject (ICMP port unreach) */
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf");
    struct nlbuf m[4];
    nft_table_msg(&m[0], NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, 1, "natdrop");
    nft_base_chain_msg(&m[1], 2, "natdrop", "out", NF_INET_LOCAL_OUT, -100, NF_ACCEPT, "nat");

    /* Rule 1: th dport 19301 drop */
    nft_rule_msg(&m[2], NLM_F_CREATE | NLM_F_ACK, 3, "natdrop", "out");
    size_t exs = nl_attr_start(&m[2], NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
    struct nlbuf ed;
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* DREG */, 1);
    nl_attr_be32(&ed, 2 /* BASE=TH */, 2);
    nl_attr_be32(&ed, 3 /* OFFSET */, 2);
    nl_attr_be32(&ed, 4 /* LEN */, 2);
    nft_put_expr(&m[2], "payload", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    nft_put_data_val(&ed, 3, &a1.sin_port, 2);
    nft_put_expr(&m[2], "cmp", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* DREG=VERDICT */, 0);
    size_t dv = nl_attr_start(&ed, 2 /* DATA */ | NLA_F_NESTED);
    size_t vr = nl_attr_start(&ed, NFTA_DATA_VERDICT | NLA_F_NESTED);
    nl_attr_be32(&ed, NFTA_VERDICT_CODE, NF_DROP);
    nl_attr_end(&ed, vr);
    nl_attr_end(&ed, dv);
    nft_put_expr(&m[2], "immediate", ed.data, ed.len);
    nl_attr_end(&m[2], exs);

    /* Rule 2: th dport 19302 reject (ICMP port unreachable -> ECONNREFUSED) */
    nft_rule_msg(&m[3], NLM_F_CREATE | NLM_F_ACK, 4, "natdrop", "out");
    exs = nl_attr_start(&m[3], NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 2);
    nl_attr_be32(&ed, 3, 2);
    nl_attr_be32(&ed, 4, 2);
    nft_put_expr(&m[3], "payload", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    nft_put_data_val(&ed, 3, &a2.sin_port, 2);
    nft_put_expr(&m[3], "cmp", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* TYPE=ICMP_UNREACH */, 0);
    uint8_t code = 3; /* ICMP_PORT_UNREACH */
    nl_attr(&ed, 2 /* CODE */, &code, 1);
    nft_put_expr(&m[3], "reject", ed.data, ed.len);
    nl_attr_end(&m[3], exs);

    int errs[4] = {-1, -1, -1, -1};
    nft_batch_send(nf, m, 4, errs, 4);
    CHECK(errs[0] == 0 && errs[1] == 0 && errs[2] == 0 && errs[3] == 0,
          "install nat drop/reject %d %d %d %d", errs[0], errs[1], errs[2], errs[3]);

    /* 1. TCP connect to nat-dropped port must NOT return EPERM: blocking times out (SO_SNDTIMEO
     *    -> EINPROGRESS), nonblocking stays in progress. */
    int ct1 = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
    CHECK(setsockopt(ct1, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0, "SO_SNDTIMEO");
    errno = 0;
    CHECK(connect(ct1, (struct sockaddr *)&a1, sizeof a1) == -1 && errno == EINPROGRESS,
          "TCP nat drop must time out (EINPROGRESS), not EPERM (got %d)", errno);
    close(ct1);

    /* 2. TCP connect to nat-rejected port returns ECONNREFUSED immediately (not EPERM). */
    int ct2 = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0;
    CHECK(connect(ct2, (struct sockaddr *)&a2, sizeof a2) == -1 && errno == ECONNREFUSED,
          "TCP nat reject must return ECONNREFUSED (got %d)", errno);
    close(ct2);

    /* 3. UDP connect to nat-dropped port MUST succeed (not EPERM), and subsequent OUTPUT send
     *    returns EPERM without delivering to server. */
    int cu1 = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(connect(cu1, (struct sockaddr *)&a1, sizeof a1) == 0,
          "UDP connect must not be filtered by nat-chain drop");
    errno = 0;
    CHECK(send(cu1, "blocked", 7, 0) == -1 && errno == EPERM,
          "UDP connected send on OUTPUT nat drop must be EPERM");
    char tmp[16];
    errno = 0;
    CHECK(recv(su1, tmp, sizeof tmp, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "dropped UDP datagram must not arrive");
    close(cu1);

    /* 4. Unconnected UDP sendto on OUTPUT nat drop returns EPERM. */
    int cu2 = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0;
    CHECK(sendto(cu2, "blocked", 7, 0, (struct sockaddr *)&a1, sizeof a1) == -1 && errno == EPERM,
          "UDP sendto on OUTPUT nat drop must be EPERM");
    close(cu2);

    close(nf);
    close(su1);
    close(st2);
    close(st1);
}

static void test_nat_drop_reject(void)
{
    CHECK(run_in_child(test_nat_drop_reject_child) == 0, "nat drop/reject");
    ok("nat_drop_reject");
}

/* ---- 15. kernel/netns: full 127.0.0.0/8 loopback range ---- */

static struct sockaddr_in addr4(const char *ip, uint16_t port)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, ip, &addr.sin_addr) == 1, "invalid IPv4 address %s", ip);
    return addr;
}

static void check_local4(int fd, const char *ip, uint16_t port)
{
    struct sockaddr_in want = addr4(ip, port), got = {0};
    socklen_t len = sizeof got;
    CHECK(getsockname(fd, (struct sockaddr *)&got, &len) == 0, "getsockname %s:%u", ip, port);
    CHECK(len == sizeof got && got.sin_family == AF_INET &&
              got.sin_addr.s_addr == want.sin_addr.s_addr && got.sin_port == want.sin_port,
          "getsockname wanted %s:%u, got %s:%u", ip, port, inet_ntoa(got.sin_addr),
          ntohs(got.sin_port));
}

static void test_netns_full_loopback_slash8_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    create_dummy(rtnl, "eth0");
    int eth0 = (int)if_nametoindex("eth0");
    CHECK(eth0 > 0, "eth0 index");
    set_link_up(rtnl, eth0);
    add_v4_addr(rtnl, eth0, "10.99.0.2", 24);
    close(rtnl);

    const char *ips[] = {"127.0.0.1", "127.0.1.1", "127.1.2.3", "127.0.0.254"};
    enum { n = sizeof ips / sizeof ips[0], port = 19401 };
    int srvs[n];
    for (int i = 0; i < n; i++) {
        srvs[i] = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(srvs[i] >= 0, "srv socket %s", ips[i]);
        struct sockaddr_in a = addr4(ips[i], port);
        CHECK(bind(srvs[i], (struct sockaddr *)&a, sizeof a) == 0, "bind %s", ips[i]);
        CHECK(listen(srvs[i], 4) == 0, "listen %s", ips[i]);
        check_local4(srvs[i], ips[i], port);
    }

    for (int i = 0; i < n; i++) {
        int cli = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(cli >= 0, "cli");
        struct sockaddr_in ca = addr4("127.2.3.4", 0);
        CHECK(bind(cli, (struct sockaddr *)&ca, sizeof ca) == 0, "bind cli 127.2.3.4");
        struct sockaddr_in dst = addr4(ips[i], port);
        CHECK(connect(cli, (struct sockaddr *)&dst, sizeof dst) == 0, "connect %s", ips[i]);

        struct sockaddr_in peer = {0};
        socklen_t pl = sizeof peer;
        int acc = accept(srvs[i], (struct sockaddr *)&peer, &pl);
        CHECK(acc >= 0, "accept %s", ips[i]);
        CHECK(peer.sin_addr.s_addr == ca.sin_addr.s_addr, "accept peer %s", inet_ntoa(peer.sin_addr));
        check_local4(acc, ips[i], port);

        char msg[8] = "ping!";
        CHECK(send(cli, msg, 5, 0) == 5, "send");
        char rbuf[8] = {0};
        CHECK(recv(acc, rbuf, 5, MSG_WAITALL) == 5 && memcmp(rbuf, "ping!", 5) == 0, "recv");
        close(acc);
        close(cli);
    }
    for (int i = 0; i < n; i++)
        close(srvs[i]);

    /* UDP between 127.0.1.1 and 127.1.2.3 on the same port */
    int u1 = socket(AF_INET, SOCK_DGRAM, 0), u2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua1 = addr4("127.0.1.1", 19402), ua2 = addr4("127.1.2.3", 19402);
    CHECK(bind(u1, (struct sockaddr *)&ua1, sizeof ua1) == 0, "bind u1");
    CHECK(bind(u2, (struct sockaddr *)&ua2, sizeof ua2) == 0, "bind u2");
    CHECK(sendto(u1, "hi", 2, 0, (struct sockaddr *)&ua2, sizeof ua2) == 2, "sendto u2");
    char ubuf[8] = {0};
    struct sockaddr_in from = {0};
    socklen_t fl = sizeof from;
    CHECK(recvfrom(u2, ubuf, sizeof ubuf, 0, (struct sockaddr *)&from, &fl) == 2, "recvfrom u2");
    CHECK(from.sin_addr.s_addr == ua1.sin_addr.s_addr && from.sin_port == ua1.sin_port,
          "unexpected UDP peer %s:%u", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    CHECK(memcmp(ubuf, "hi", 2) == 0, "UDP payload");
    close(u1);
    close(u2);
}

static void test_netns_full_loopback_slash8(void)
{
    CHECK(run_in_child(test_netns_full_loopback_slash8_child) == 0, "netns 127/8");
    ok("netns_full_loopback_slash8");
}

/* ---- 16. kernel/rawicmp: rebind to another address & SO_RCVBUF ---- */

static void test_rawicmp_rebind_and_rcvbuf_child(void)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0 && (errno == EACCES || errno == EPERM))
        return; /* host disallows unprivileged ping sockets */
    CHECK(s >= 0, "raw icmp socket");

    int rcv = 8192, ttl = 42, one = 1;
    uint32_t filt = 0x10;
    CHECK(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv) == 0, "SO_RCVBUF");
    CHECK(setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) == 0, "IP_TTL");
    CHECK(setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof one) == 0, "IP_RECVTTL");
    CHECK(setsockopt(s, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == 0, "ICMP_FILTER");
    int want_rcv = 0;
    socklen_t optl = sizeof want_rcv;
    CHECK(getsockopt(s, SOL_SOCKET, SO_RCVBUF, &want_rcv, &optl) == 0 && want_rcv >= 2304,
          "get SO_RCVBUF");

    struct sockaddr_in a1 = addr4("127.0.0.1", 0), a2 = addr4("127.0.0.2", 0);
    struct sockaddr_in a3 = addr4("127.0.0.3", 0), bogus = addr4("203.0.113.9", 0);
    struct sockaddr_in any = addr4("0.0.0.0", 0);
    CHECK(bind(s, (struct sockaddr *)&a1, sizeof a1) == 0, "bind 127.0.0.1");
    CHECK(bind(s, (struct sockaddr *)&a2, sizeof a2) == 0, "rebind 127.0.0.2");

    check_local4(s, "127.0.0.2", IPPROTO_ICMP);

    /* Options survive host ping socket replacement. */
    int got_rcv = 0, got_ttl = 0, got_recvttl = 0;
    uint32_t got_filt = 0;
    optl = sizeof got_rcv;
    CHECK(getsockopt(s, SOL_SOCKET, SO_RCVBUF, &got_rcv, &optl) == 0 && got_rcv == want_rcv,
          "SO_RCVBUF preserved %d != %d", got_rcv, want_rcv);
    optl = sizeof got_ttl;
    CHECK(getsockopt(s, IPPROTO_IP, IP_TTL, &got_ttl, &optl) == 0 && got_ttl == 42,
          "IP_TTL preserved %d", got_ttl);
    optl = sizeof got_recvttl;
    CHECK(getsockopt(s, IPPROTO_IP, IP_RECVTTL, &got_recvttl, &optl) == 0 && got_recvttl == 1,
          "IP_RECVTTL preserved");
    optl = sizeof got_filt;
    CHECK(getsockopt(s, SOL_RAW, ICMP_FILTER, &got_filt, &optl) == 0 && got_filt == filt,
          "ICMP_FILTER preserved");

    /* Invalid rebind fails atomically without disturbing existing bind. */
    errno = 0;
    CHECK(bind(s, (struct sockaddr *)&bogus, sizeof bogus) == -1 && errno == EADDRNOTAVAIL,
          "bogus rebind -> EADDRNOTAVAIL");
    check_local4(s, "127.0.0.2", IPPROTO_ICMP);

    /* Connected raw socket refuses rebind with EINVAL; disconnect restores rebindability. */
    CHECK(connect(s, (struct sockaddr *)&a1, sizeof a1) == 0, "connect raw");
    errno = 0;
    CHECK(bind(s, (struct sockaddr *)&a3, sizeof a3) == -1 && errno == EINVAL,
          "connected raw rebind -> EINVAL");
    struct sockaddr unspec = {.sa_family = AF_UNSPEC};
    CHECK(connect(s, &unspec, sizeof unspec) == 0, "disconnect raw");
    CHECK(bind(s, (struct sockaddr *)&any, sizeof any) == 0, "rebind wildcard after disconnect");
    check_local4(s, "0.0.0.0", IPPROTO_ICMP);
    close(s);

    /* The replacement host ICMPv6 ping socket can default to IPV6_V6ONLY=1. */
    int s6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (s6 >= 0) {
        struct sockaddr_in6 lo6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        struct sockaddr_in6 any6 = {.sin6_family = AF_INET6};
        int only = 0;
        CHECK(setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof only) == 0, "clear V6ONLY");
        CHECK(bind(s6, (struct sockaddr *)&lo6, sizeof lo6) == 0, "bind ::1");
        CHECK(bind(s6, (struct sockaddr *)&any6, sizeof any6) == 0, "rebind ::");
        optl = sizeof only;
        CHECK(getsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &only, &optl) == 0 && only == 0,
              "IPV6_V6ONLY after rebind: %d", only);
        close(s6);
    } else {
        CHECK(errno == EACCES || errno == EPERM || errno == EAFNOSUPPORT ||
                  errno == EPROTONOSUPPORT, "raw icmpv6 socket");
    }

    /* New netns: rebind across 127.0.0.1, 127.0.1.1, 127.0.0.2, and 0.0.0.0 */
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net raw");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    set_link_up(rtnl, 1);
    close(rtnl);
    int ns = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    CHECK(ns >= 0, "netns raw icmp");
    const char *ips[] = {"127.0.0.1", "127.0.1.1", "127.0.0.2", "0.0.0.0"};
    for (size_t i = 0; i < sizeof ips / sizeof ips[0]; i++) {
        struct sockaddr_in addr = addr4(ips[i], 0);
        CHECK(bind(ns, (struct sockaddr *)&addr, sizeof addr) == 0, "netns raw bind %s", ips[i]);
        check_local4(ns, ips[i], IPPROTO_ICMP);
    }
    CHECK(connect(ns, (struct sockaddr *)&a1, sizeof a1) == 0, "connect netns raw");
    CHECK(bind(ns, (struct sockaddr *)&bogus, sizeof bogus) == -1 && errno == EINVAL,
          "connected raw bind checks state before the namespace address");
    close(ns);
}

static void test_rawicmp_rebind_and_rcvbuf(void)
{
    CHECK(run_in_child(test_rawicmp_rebind_and_rcvbuf_child) == 0, "rawicmp rebind/rcvbuf");
    ok("rawicmp_rebind_and_rcvbuf");
}

/* ---- 17. kernel/netns: Linux 6.1 route attribute lengths ---- */

static void route_msg(struct nlbuf *b, uint16_t type, uint32_t seq, const struct rtmsg *route)
{
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    if (type == RTM_NEWROUTE)
        flags |= NLM_F_CREATE | NLM_F_EXCL;
    nl_init(b, type, flags, seq);
    nl_put_raw(b, route, sizeof *route);
}

static void test_route_attr_lengths_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    create_dummy(rtnl, "d0");
    int i0 = (int)if_nametoindex("d0");
    CHECK(i0 > 0, "d0 idx");
    set_link_up(rtnl, i0);
    add_v4_addr(rtnl, i0, "10.72.0.1", 24);

    /* Short IPv4 RTA_DST -> ERANGE */
    struct nlbuf b;
    struct rtmsg r4 = {.rtm_family = AF_INET,
                       .rtm_dst_len = 24,
                       .rtm_table = RT_TABLE_MAIN,
                       .rtm_protocol = RTPROT_BOOT,
                       .rtm_scope = RT_SCOPE_UNIVERSE,
                       .rtm_type = RTN_UNICAST};
    route_msg(&b, RTM_NEWROUTE, 10, &r4);
    uint8_t short2[2] = {10, 73};
    nl_attr(&b, RTA_DST, short2, sizeof short2);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == ERANGE, "short IPv4 RTA_DST -> ERANGE");

    /* Oversized IPv4 RTA_DST & RTA_GATEWAY -> first 4 bytes accepted on add & del */
    uint8_t long_dst4[6] = {10, 73, 0, 0, 0xaa, 0xbb};
    uint8_t long_gw4[6] = {10, 72, 0, 254, 0x11, 0x22};
    route_msg(&b, RTM_NEWROUTE, 11, &r4);
    nl_attr(&b, RTA_DST, long_dst4, sizeof long_dst4);
    nl_attr(&b, RTA_GATEWAY, long_gw4, sizeof long_gw4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "long IPv4 route add");

    r4.rtm_scope = RT_SCOPE_NOWHERE;
    route_msg(&b, RTM_DELROUTE, 12, &r4);
    nl_attr(&b, RTA_DST, long_dst4, sizeof long_dst4);
    nl_attr(&b, RTA_GATEWAY, long_gw4, sizeof long_gw4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "long IPv4 route del");

    /* Short IPv6 RTA_GATEWAY -> ERANGE; 8-byte IPv6 RTA_DST for /64 -> OK; 7-byte -> EINVAL */
    struct rtmsg r6 = r4;
    r6.rtm_family = AF_INET6;
    r6.rtm_dst_len = 64;
    r6.rtm_scope = RT_SCOPE_UNIVERSE;
    route_msg(&b, RTM_NEWROUTE, 13, &r6);
    uint8_t short_gw6[4] = {0xfe, 0x80, 0, 0};
    nl_attr(&b, RTA_GATEWAY, short_gw6, sizeof short_gw6);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == ERANGE, "short IPv6 RTA_GATEWAY -> ERANGE");

    uint8_t dst6[8] = {0x20, 0x01, 0x0d, 0xb8, 0, 0x72, 0, 0};
    route_msg(&b, RTM_NEWROUTE, 14, &r6);
    nl_attr(&b, RTA_DST, dst6, sizeof dst6 - 1);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == EINVAL, "7-byte IPv6 /64 RTA_DST -> EINVAL");

    route_msg(&b, RTM_NEWROUTE, 15, &r6);
    nl_attr(&b, RTA_DST, dst6, sizeof dst6);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == 0, "8-byte IPv6 /64 RTA_DST add");

    route_msg(&b, RTM_DELROUTE, 16, &r6);
    nl_attr(&b, RTA_DST, dst6, sizeof dst6);
    nl_attr_u32(&b, RTA_OIF, (uint32_t)i0);
    CHECK(nl_send_ack(rtnl, &b) == 0, "8-byte IPv6 /64 RTA_DST del");

    close(rtnl);
}

static void test_route_attr_lengths(void)
{
    CHECK(run_in_child(test_route_attr_lengths_child) == 0, "route attr lengths");
    ok("route_attr_lengths");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "filtered-dnat") == 0) {
        test_dualstack_dnat_and_close_wait_peer(1);
        printf("all ok\n");
        return 0;
    }
    test_so_attach_bpf();
    test_waitall_preserves_error();
    test_sendto_validation();
    test_wildcard_connect_bound_v4();
    test_netns_udp_and_ephemeral();
    test_netns_routes();
    test_netlink();
    test_rawicmp_shut_rd();
    test_nft_control_plane();
    test_dualstack_dnat_and_close_wait_peer(0);
    test_rtnl_notify_echo();
    test_route_get_iif();
    test_so_bindtodevice_netns();
    test_nat_drop_reject();
    test_netns_full_loopback_slash8();
    test_rawicmp_rebind_and_rcvbuf();
    test_route_attr_lengths();
    printf("all ok\n");
    return 0;
}
