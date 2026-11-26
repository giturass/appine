/*
 * Guest regression tests for network namespace same-port bind conflict semantics,
 * guest-address host-port separation, TCP/UDP demuxing, getsockname/getpeername,
 * /proc/net/{tcp,udp}, and cross-namespace / DNAT forwarding.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Self-contained Linux UAPI definitions (musl-gcc has no linux UAPI headers). */
#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct nlmsgerr {
    int error;
    struct nlmsghdr msg;
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

struct nfgenmsg {
    uint8_t nfgen_family;
    uint8_t version;
    uint16_t res_id;
};

enum {
    NETLINK_ROUTE = 0,
    NETLINK_NETFILTER = 12,
    NLMSG_HDRLEN = 16,
    NLMSG_ERROR = 2,
    NLM_F_REQUEST = 0x01,
    NLM_F_ACK = 0x04,
    NLM_F_EXCL = 0x200,
    NLM_F_CREATE = 0x400,
    NLA_HDRLEN = 4,
    NLA_F_NESTED = 0x8000,

    RTM_NEWLINK = 16,
    RTM_NEWADDR = 20,
    RTM_NEWROUTE = 24,
    IFLA_IFNAME = 3,
    IFLA_LINKINFO = 18,
    IFLA_NET_NS_PID = 19,
    IFLA_INFO_KIND = 1,
    IFLA_INFO_DATA = 2,
    VETH_INFO_PEER = 1,
    IFA_ADDRESS = 1,
    IFA_LOCAL = 2,
    RT_TABLE_MAIN = 254,
    RTPROT_BOOT = 3,
    RT_SCOPE_UNIVERSE = 0,
    RTN_UNICAST = 1,
    RTA_GATEWAY = 5,

    NFPROTO_IPV4 = 2,
    NF_DROP = 0,
    NF_ACCEPT = 1,
    NF_INET_PRE_ROUTING = 0,
    NF_INET_LOCAL_OUT = 3,
    NFNL_MSG_BATCH_BEGIN = 0x10,
    NFNL_MSG_BATCH_END = 0x11,
    NFNL_SUBSYS_NFTABLES = 10,
    NFT_MSG_NEWTABLE = 0,
    NFT_MSG_NEWCHAIN = 3,
    NFT_MSG_NEWRULE = 6,
    NFTA_TABLE_NAME = 1,
    NFTA_CHAIN_TABLE = 1,
    NFTA_CHAIN_NAME = 3,
    NFTA_CHAIN_HOOK = 4,
    NFTA_CHAIN_POLICY = 5,
    NFTA_CHAIN_TYPE = 7,
    NFTA_HOOK_HOOKNUM = 1,
    NFTA_HOOK_PRIORITY = 2,
    NFTA_RULE_TABLE = 1,
    NFTA_RULE_CHAIN = 2,
    NFTA_RULE_EXPRESSIONS = 4,
    NFTA_LIST_ELEM = 1,
    NFTA_EXPR_NAME = 1,
    NFTA_EXPR_DATA = 2,
    NFTA_DATA_VALUE = 1,
};

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_DATA(nlh) ((void *)((char *)(nlh) + NLMSG_HDRLEN))
#define NLMSG_OK(nlh, len)                                                                         \
    ((len) >= (int)sizeof(struct nlmsghdr) && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) &&       \
     (nlh)->nlmsg_len <= (unsigned)(len))
#define NLMSG_NEXT(nlh, len)                                                                       \
    ((len) -= (int)NLMSG_ALIGN((nlh)->nlmsg_len),                                                  \
     (struct nlmsghdr *)((char *)(nlh) + NLMSG_ALIGN((nlh)->nlmsg_len)))

#define CHECK(cond, fmt, ...)                                                                      \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d: %s)\n", __FILE__, __LINE__,            \
                    ##__VA_ARGS__, errno, strerror(errno));                                        \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void ok(const char *name) { printf("ok %s\n", name); }

/* ---- Minimal netlink helpers ---- */

struct nlbuf {
    uint8_t data[1024];
    size_t len;
};

static void nl_init(struct nlbuf *b, uint16_t type, uint16_t flags, uint32_t seq)
{
    memset(b, 0, sizeof *b);
    struct nlmsghdr *h = (struct nlmsghdr *)b->data;
    h->nlmsg_type = type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = seq;
    b->len = NLMSG_HDRLEN;
}

static void nl_put_raw(struct nlbuf *b, const void *src, size_t n)
{
    CHECK(b->len + n <= sizeof b->data, "nlbuf overflow");
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

static void nl_align4(struct nlbuf *b)
{
    while (b->len & 3)
        b->data[b->len++] = 0;
}

static void nl_attr(struct nlbuf *b, uint16_t type, const void *val, size_t len)
{
    nl_align4(b);
    struct nlattr hdr = {.nla_len = (uint16_t)(NLA_HDRLEN + len), .nla_type = type};
    nl_put_raw(b, &hdr, sizeof hdr);
    if (len)
        nl_put_raw(b, val, len);
    nl_align4(b);
}

static void nl_attr_be32(struct nlbuf *b, uint16_t type, uint32_t val)
{
    uint32_t be = htonl(val);
    nl_attr(b, type, &be, 4);
}

static size_t nl_attr_start(struct nlbuf *b, uint16_t type)
{
    nl_align4(b);
    size_t off = b->len;
    struct nlattr hdr = {.nla_len = NLA_HDRLEN, .nla_type = type};
    nl_put_raw(b, &hdr, sizeof hdr);
    return off;
}

static void nl_attr_end(struct nlbuf *b, size_t off)
{
    nl_align4(b);
    struct nlattr *hdr = (struct nlattr *)(b->data + off);
    hdr->nla_len = (uint16_t)(b->len - off);
}

static int nl_send_ack(int fd, struct nlbuf *b)
{
    struct nlmsghdr *h = (struct nlmsghdr *)b->data;
    h->nlmsg_len = (uint32_t)b->len;
    CHECK(send(fd, b->data, b->len, 0) == (ssize_t)b->len, "nl send");
    uint8_t resp[1024];
    ssize_t n = recv(fd, resp, sizeof resp, 0);
    CHECK(n >= (ssize_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr)), "nl recv ack");
    struct nlmsghdr *rh = (struct nlmsghdr *)resp;
    CHECK(rh->nlmsg_type == NLMSG_ERROR, "expected NLMSG_ERROR got %u", rh->nlmsg_type);
    struct nlmsgerr *err = (struct nlmsgerr *)(resp + NLMSG_HDRLEN);
    return -err->error;
}

static void set_link_up(int rtnl, int ifindex)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 1);
    struct ifinfomsg ifi = {.ifi_index = ifindex, .ifi_flags = IFF_UP, .ifi_change = IFF_UP};
    nl_put_raw(&b, &ifi, sizeof ifi);
    CHECK(nl_send_ack(rtnl, &b) == 0, "set_link_up %d", ifindex);
}

static int create_dummy(int rtnl, const char *name)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 2);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr(&b, IFLA_IFNAME, name, strlen(name) + 1);
    size_t li = nl_attr_start(&b, IFLA_LINKINFO);
    nl_attr(&b, IFLA_INFO_KIND, "dummy", 5);
    nl_attr_end(&b, li);
    CHECK(nl_send_ack(rtnl, &b) == 0, "create_dummy %s", name);
    int idx = (int)if_nametoindex(name);
    CHECK(idx > 0, "if_nametoindex %s", name);
    set_link_up(rtnl, idx);
    return idx;
}

static void add_v4_addr(int rtnl, int ifindex, const char *ip_str, uint8_t prefix)
{
    struct in_addr ip;
    CHECK(inet_pton(AF_INET, ip_str, &ip) == 1, "pton %s", ip_str);
    struct nlbuf b;
    nl_init(&b, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 3);
    struct ifaddrmsg ifa = {
        .ifa_family = AF_INET,
        .ifa_prefixlen = prefix,
        .ifa_index = (uint32_t)ifindex,
    };
    nl_put_raw(&b, &ifa, sizeof ifa);
    nl_attr(&b, IFA_LOCAL, &ip, 4);
    nl_attr(&b, IFA_ADDRESS, &ip, 4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "add_v4_addr %s", ip_str);
}

static void create_veth(int rtnl, const char *n0, const char *n1, pid_t peer_pid)
{
    struct nlbuf b;
    nl_init(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 4);
    struct ifinfomsg ifi = {0};
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr(&b, IFLA_IFNAME, n0, strlen(n0) + 1);
    size_t li = nl_attr_start(&b, IFLA_LINKINFO);
    nl_attr(&b, IFLA_INFO_KIND, "veth", 4);
    size_t ld = nl_attr_start(&b, IFLA_INFO_DATA);
    size_t pi = nl_attr_start(&b, VETH_INFO_PEER);
    nl_put_raw(&b, &ifi, sizeof ifi);
    nl_attr(&b, IFLA_IFNAME, n1, strlen(n1) + 1);
    uint32_t pid = (uint32_t)peer_pid;
    nl_attr(&b, IFLA_NET_NS_PID, &pid, sizeof pid);
    nl_attr_end(&b, pi);
    nl_attr_end(&b, ld);
    nl_attr_end(&b, li);
    CHECK(nl_send_ack(rtnl, &b) == 0, "create_veth %s/%s", n0, n1);
}

/* ---- Socket address helpers ---- */

static struct sockaddr_in addr4(const char *ip, uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    CHECK(inet_pton(AF_INET, ip, &a.sin_addr) == 1, "pton4 %s", ip);
    return a;
}

static struct sockaddr_in6 addr6(const char *ip, uint16_t port)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    CHECK(inet_pton(AF_INET6, ip, &a.sin6_addr) == 1, "pton6 %s", ip);
    return a;
}

static int mk_sock(int fam, int ty, int reuseaddr, int reuseport, int v6only)
{
    int fd = socket(fam, ty, 0);
    CHECK(fd >= 0, "socket fam=%d ty=%d", fam, ty);
    int one = 1;
    if (reuseaddr)
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "SO_REUSEADDR");
    if (reuseport)
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0, "SO_REUSEPORT");
    if (fam == AF_INET6 && v6only >= 0)
        CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) == 0, "IPV6_V6ONLY");
    return fd;
}

static int run_in_child(void (*fn)(void))
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        fn();
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid");
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* ---- 1. 127.0.0.1:P + <vaddr>:P + <vaddr2>:P + [::1]:P TCP & UDP independence ---- */

static void verify_tcp_echo(int srv_fd, int fam, const struct sockaddr *dst, socklen_t dlen,
                            const char *want_ip, uint16_t port, const char *msg)
{
    int cli = socket(fam, SOCK_STREAM, 0);
    CHECK(cli >= 0, "cli tcp");
    CHECK(connect(cli, dst, dlen) == 0, "connect %s:%u", want_ip, port);

    /* Verify client getpeername reports exact guest destination */
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    CHECK(getpeername(cli, (struct sockaddr *)&peer, &plen) == 0, "cli getpeername");
    char got[INET6_ADDRSTRLEN] = {0};
    uint16_t got_port = 0;
    if (peer.ss_family == AF_INET) {
        struct sockaddr_in *p4 = (struct sockaddr_in *)&peer;
        inet_ntop(AF_INET, &p4->sin_addr, got, sizeof got);
        got_port = ntohs(p4->sin_port);
    } else {
        struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&peer;
        inet_ntop(AF_INET6, &p6->sin6_addr, got, sizeof got);
        got_port = ntohs(p6->sin6_port);
    }
    CHECK(strcmp(got, want_ip) == 0 && got_port == port,
          "cli peer got %s:%u want %s:%u", got, got_port, want_ip, port);

    int acc = accept(srv_fd, NULL, NULL);
    CHECK(acc >= 0, "accept on %s:%u", want_ip, port);

    /* Verify accepted getsockname reports exact guest local IP and port */
    struct sockaddr_storage loc;
    socklen_t llen = sizeof loc;
    CHECK(getsockname(acc, (struct sockaddr *)&loc, &llen) == 0, "acc getsockname");
    memset(got, 0, sizeof got);
    if (loc.ss_family == AF_INET) {
        struct sockaddr_in *l4 = (struct sockaddr_in *)&loc;
        inet_ntop(AF_INET, &l4->sin_addr, got, sizeof got);
        got_port = ntohs(l4->sin_port);
    } else {
        struct sockaddr_in6 *l6 = (struct sockaddr_in6 *)&loc;
        inet_ntop(AF_INET6, &l6->sin6_addr, got, sizeof got);
        got_port = ntohs(l6->sin6_port);
    }
    CHECK(strcmp(got, want_ip) == 0 && got_port == port,
          "acc local got %s:%u want %s:%u", got, got_port, want_ip, port);

    size_t mlen = strlen(msg);
    CHECK(send(cli, msg, mlen, 0) == (ssize_t)mlen, "cli send");
    char buf[32] = {0};
    CHECK(recv(acc, buf, mlen, MSG_WAITALL) == (ssize_t)mlen && memcmp(buf, msg, mlen) == 0,
          "acc recv %s", msg);
    CHECK(send(acc, msg, mlen, 0) == (ssize_t)mlen, "acc echo");
    memset(buf, 0, sizeof buf);
    CHECK(recv(cli, buf, mlen, MSG_WAITALL) == (ssize_t)mlen && memcmp(buf, msg, mlen) == 0,
          "cli recv echo %s", msg);

    close(acc);
    close(cli);
}

static void test_same_port_distinct_addrs_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    int d0 = create_dummy(rtnl, "dum0");
    int d1 = create_dummy(rtnl, "dum1");
    add_v4_addr(rtnl, d0, "10.77.0.2", 24);
    add_v4_addr(rtnl, d1, "10.78.0.2", 24);
    close(rtnl);

    const uint16_t port = 18100;
    struct sockaddr_in a_lo = addr4("127.0.0.1", port);
    struct sockaddr_in a_v1 = addr4("10.77.0.2", port);
    struct sockaddr_in a_v2 = addr4("10.78.0.2", port);
    struct sockaddr_in6 a_v6 = addr6("::1", port);

    /* TCP: bind and listen on 127.0.0.1, 10.77.0.2, 10.78.0.2, and ::1 on the same port without reuse */
    int s_lo = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, -1);
    int s_v1 = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, -1);
    int s_v2 = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, -1);
    int s_v6 = mk_sock(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, 0);

    CHECK(bind(s_lo, (struct sockaddr *)&a_lo, sizeof a_lo) == 0, "tcp bind 127.0.0.1:%u", port);
    CHECK(bind(s_v1, (struct sockaddr *)&a_v1, sizeof a_v1) == 0, "tcp bind 10.77.0.2:%u", port);
    CHECK(bind(s_v2, (struct sockaddr *)&a_v2, sizeof a_v2) == 0, "tcp bind 10.78.0.2:%u", port);
    CHECK(bind(s_v6, (struct sockaddr *)&a_v6, sizeof a_v6) == 0, "tcp bind [::1]:%u", port);

    CHECK(listen(s_lo, 4) == 0, "listen lo");
    CHECK(listen(s_v1, 4) == 0, "listen v1");
    CHECK(listen(s_v2, 4) == 0, "listen v2");
    CHECK(listen(s_v6, 4) == 0, "listen v6");

    /* Verify getsockname on listeners */
    struct sockaddr_in check_sa;
    socklen_t clen = sizeof check_sa;
    CHECK(getsockname(s_v1, (struct sockaddr *)&check_sa, &clen) == 0 &&
              check_sa.sin_addr.s_addr == a_v1.sin_addr.s_addr &&
              ntohs(check_sa.sin_port) == port,
          "getsockname s_v1");

    /* Verify /proc/net/tcp lists all three IPv4 listeners with their exact guest addresses */
    int pfd = open("/proc/net/tcp", O_RDONLY);
    CHECK(pfd >= 0, "open /proc/net/tcp");
    char pbuf[4096] = {0};
    ssize_t pn = read(pfd, pbuf, sizeof pbuf - 1);
    close(pfd);
    CHECK(pn > 0, "read /proc/net/tcp");
    /* Little-endian hex: 127.0.0.1 = 0100007F, 10.77.0.2 = 02004D0A, 10.78.0.2 = 02004E0A, 18100 = 46B4 */
    CHECK(strstr(pbuf, "0100007F:46B4") != NULL, "/proc/net/tcp missing 127.0.0.1:18100:\n%s", pbuf);
    CHECK(strstr(pbuf, "02004D0A:46B4") != NULL, "/proc/net/tcp missing 10.77.0.2:18100:\n%s", pbuf);
    CHECK(strstr(pbuf, "02004E0A:46B4") != NULL, "/proc/net/tcp missing 10.78.0.2:18100:\n%s", pbuf);

    /* Independent TCP echo on each address; verify no cross-talk on non-target listeners */
    verify_tcp_echo(s_lo, AF_INET, (struct sockaddr *)&a_lo, sizeof a_lo, "127.0.0.1", port, "from-lo");
    CHECK(accept(s_v1, NULL, NULL) == -1 && errno == EAGAIN, "no crosstalk to v1");
    verify_tcp_echo(s_v1, AF_INET, (struct sockaddr *)&a_v1, sizeof a_v1, "10.77.0.2", port, "from-v1");
    CHECK(accept(s_lo, NULL, NULL) == -1 && errno == EAGAIN, "no crosstalk to lo");
    verify_tcp_echo(s_v2, AF_INET, (struct sockaddr *)&a_v2, sizeof a_v2, "10.78.0.2", port, "from-v2");
    verify_tcp_echo(s_v6, AF_INET6, (struct sockaddr *)&a_v6, sizeof a_v6, "::1", port, "from-v6");

    close(s_lo);
    close(s_v1);
    close(s_v2);
    close(s_v6);

    /* UDP: bind 127.0.0.1:P, 10.77.0.2:P, 10.78.0.2:P on the same port and echo without cross-talk */
    int u_lo = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
    int u_v1 = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
    int u_v2 = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
    CHECK(bind(u_lo, (struct sockaddr *)&a_lo, sizeof a_lo) == 0, "udp bind lo");
    CHECK(bind(u_v1, (struct sockaddr *)&a_v1, sizeof a_v1) == 0, "udp bind v1");
    CHECK(bind(u_v2, (struct sockaddr *)&a_v2, sizeof a_v2) == 0, "udp bind v2");

    /* Also check /proc/net/udp lists all three IPv4 UDP bindings with their exact guest addresses */
    pfd = open("/proc/net/udp", O_RDONLY);
    CHECK(pfd >= 0, "open /proc/net/udp");
    memset(pbuf, 0, sizeof pbuf);
    pn = read(pfd, pbuf, sizeof pbuf - 1);
    close(pfd);
    CHECK(pn > 0, "read /proc/net/udp");
    CHECK(strstr(pbuf, "0100007F:46B4") != NULL, "/proc/net/udp missing 127.0.0.1:18100:\n%s", pbuf);
    CHECK(strstr(pbuf, "02004D0A:46B4") != NULL, "/proc/net/udp missing 10.77.0.2:18100:\n%s", pbuf);
    CHECK(strstr(pbuf, "02004E0A:46B4") != NULL, "/proc/net/udp missing 10.78.0.2:18100:\n%s", pbuf);

    /* Test with a wide UDP client (0.0.0.0:0) sending to all three and checking recvfrom source */
    int ucli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    struct sockaddr_in any0 = addr4("0.0.0.0", 0);
    CHECK(bind(ucli, (struct sockaddr *)&any0, sizeof any0) == 0, "bind wide ucli");

    struct {
        int srv;
        int other;
        struct sockaddr_in dst;
        const char *tag;
    } cases[3] = {
        {u_lo, u_v1, a_lo, "udp-lo"},
        {u_v1, u_lo, a_v1, "udp-v1"},
        {u_v2, u_v1, a_v2, "udp-v2"},
    };
    for (int i = 0; i < 3; i++) {
        size_t tlen = strlen(cases[i].tag);
        CHECK(sendto(ucli, cases[i].tag, tlen, 0, (struct sockaddr *)&cases[i].dst,
                     sizeof cases[i].dst) == (ssize_t)tlen,
              "udp sendto %s", cases[i].tag);
        char rbuf[32] = {0};
        struct sockaddr_in from = {0};
        socklen_t flen = sizeof from;
        CHECK(recvfrom(cases[i].srv, rbuf, sizeof rbuf, 0, (struct sockaddr *)&from, &flen) ==
                  (ssize_t)tlen &&
                  memcmp(rbuf, cases[i].tag, tlen) == 0,
              "udp srv recv %s", cases[i].tag);
        /* Verify other listener did NOT receive anything */
        errno = 0;
        CHECK(recv(cases[i].other, rbuf, sizeof rbuf, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "udp crosstalk for %s", cases[i].tag);
        /* Reply to client and verify client sees the exact server guest IP & port */
        CHECK(sendto(cases[i].srv, cases[i].tag, tlen, 0, (struct sockaddr *)&from, flen) ==
                  (ssize_t)tlen,
              "udp reply %s", cases[i].tag);
        memset(rbuf, 0, sizeof rbuf);
        struct sockaddr_in rfrom = {0};
        socklen_t rflen = sizeof rfrom;
        CHECK(recvfrom(ucli, rbuf, sizeof rbuf, 0, (struct sockaddr *)&rfrom, &rflen) ==
                  (ssize_t)tlen &&
                  memcmp(rbuf, cases[i].tag, tlen) == 0,
              "udp cli recv %s", cases[i].tag);
        CHECK(rfrom.sin_addr.s_addr == cases[i].dst.sin_addr.s_addr &&
                  ntohs(rfrom.sin_port) == port,
              "udp reply src mismatch for %s: got 0x%x:%u want 0x%x:%u", cases[i].tag,
              ntohl(rfrom.sin_addr.s_addr), ntohs(rfrom.sin_port),
              ntohl(cases[i].dst.sin_addr.s_addr), port);
    }

    /* Also test an unbound UDP client talking to 10.77.0.2:P (uses SELF_VIA_VADDR) */
    int ucli2 = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    CHECK(sendto(ucli2, "selfv", 5, 0, (struct sockaddr *)&a_v1, sizeof a_v1) == 5, "udp self send");
    char rbuf[16] = {0};
    struct sockaddr_in from = {0};
    socklen_t flen = sizeof from;
    CHECK(recvfrom(u_v1, rbuf, sizeof rbuf, 0, (struct sockaddr *)&from, &flen) == 5 &&
              memcmp(rbuf, "selfv", 5) == 0,
          "udp self srv recv");
    CHECK(sendto(u_v1, "selfr", 5, 0, (struct sockaddr *)&from, flen) == 5, "udp self reply");
    struct sockaddr_in rfrom = {0};
    socklen_t rflen = sizeof rfrom;
    CHECK(recvfrom(ucli2, rbuf, sizeof rbuf, 0, (struct sockaddr *)&rfrom, &rflen) == 5 &&
              memcmp(rbuf, "selfr", 5) == 0,
          "udp self cli recv");
    CHECK(rfrom.sin_addr.s_addr == a_v1.sin_addr.s_addr && ntohs(rfrom.sin_port) == port,
          "udp self reply src mismatch");

    close(ucli2);
    close(ucli);
    close(u_lo);
    close(u_v1);
    close(u_v2);
}

/* ---- 2. Wildcard + specific conflict matrix & SO_REUSEADDR / SO_REUSEPORT ---- */

static void test_conflict_matrix_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    int d0 = create_dummy(rtnl, "dum0");
    add_v4_addr(rtnl, d0, "10.77.0.2", 24);
    close(rtnl);

    /* 2a. TCP 0.0.0.0:P + 127.0.0.2:P without reuse -> EADDRINUSE (both orders) */
    struct sockaddr_in any = addr4("0.0.0.0", 18200);
    struct sockaddr_in lo2 = addr4("127.0.0.2", 18200);
    int a = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    int b = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == 0, "bind any");
    errno = 0;
    CHECK(bind(b, (struct sockaddr *)&lo2, sizeof lo2) == -1 && errno == EADDRINUSE,
          "0.0.0.0 + 127.0.0.2 must EADDRINUSE");
    close(a);
    CHECK(bind(b, (struct sockaddr *)&lo2, sizeof lo2) == 0, "bind lo2");
    a = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    errno = 0;
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == -1 && errno == EADDRINUSE,
          "127.0.0.2 + 0.0.0.0 must EADDRINUSE");
    close(a);
    close(b);

    /* 2b. TCP SO_REUSEADDR: bind before listen succeeds, second listen fails, bind over listening fails */
    any = addr4("0.0.0.0", 18201);
    lo2 = addr4("127.0.0.2", 18201);
    a = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
    b = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == 0, "reuse bind any");
    CHECK(bind(b, (struct sockaddr *)&lo2, sizeof lo2) == 0, "reuse bind lo2 before listen");
    CHECK(listen(a, 4) == 0, "listen a");
    errno = 0;
    CHECK(listen(b, 4) == -1 && errno == EADDRINUSE, "listen b while a listening must EADDRINUSE");
    int c = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
    errno = 0;
    CHECK(bind(c, (struct sockaddr *)&lo2, sizeof lo2) == -1 && errno == EADDRINUSE,
          "reuse bind lo2 while a listening must EADDRINUSE");
    /* Shutdown a stops listening; then b can listen */
    CHECK(shutdown(a, SHUT_RDWR) == 0, "shutdown a");
    CHECK(listen(b, 4) == 0, "listen b after a shutdown");
    close(c);
    close(b);
    close(a);

    /* 2c. TCP SO_REUSEPORT: 0.0.0.0:P + 127.0.0.2:P both bind & listen, exact beats wildcard */
    any = addr4("0.0.0.0", 18202);
    lo2 = addr4("127.0.0.2", 18202);
    struct sockaddr_in lo1 = addr4("127.0.0.1", 18202);
    a = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 1, -1);
    b = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 1, -1);
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == 0, "rport bind any");
    CHECK(listen(a, 4) == 0, "rport listen any");
    CHECK(bind(b, (struct sockaddr *)&lo2, sizeof lo2) == 0, "rport bind lo2");
    CHECK(listen(b, 4) == 0, "rport listen lo2");
    verify_tcp_echo(b, AF_INET, (struct sockaddr *)&lo2, sizeof lo2, "127.0.0.2", 18202, "exact");
    verify_tcp_echo(a, AF_INET, (struct sockaddr *)&lo1, sizeof lo1, "127.0.0.1", 18202, "wild");
    close(a);
    close(b);

    /* 2d. TCP SO_REUSEPORT on identical guest address shares host port */
    lo1 = addr4("127.0.0.1", 18203);
    a = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 1, -1);
    b = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 1, -1);
    CHECK(bind(a, (struct sockaddr *)&lo1, sizeof lo1) == 0, "rport same1");
    CHECK(bind(b, (struct sockaddr *)&lo1, sizeof lo1) == 0, "rport same2");
    CHECK(listen(a, 4) == 0 && listen(b, 4) == 0, "rport same listen");
    int cli = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    CHECK(connect(cli, (struct sockaddr *)&lo1, sizeof lo1) == 0, "connect rport same");
    int acc = accept(a, NULL, NULL);
    if (acc < 0)
        acc = accept(b, NULL, NULL);
    CHECK(acc >= 0, "one of rport peers must accept");
    close(acc);
    close(cli);
    close(a);
    close(b);

    /* 2e. UDP: 0.0.0.0:P + 127.0.0.2:P fails without reuse; succeeds with SO_REUSEADDR & demuxes */
    any = addr4("0.0.0.0", 18204);
    lo2 = addr4("127.0.0.2", 18204);
    a = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    b = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == 0, "udp bind any");
    errno = 0;
    CHECK(bind(b, (struct sockaddr *)&lo2, sizeof lo2) == -1 && errno == EADDRINUSE,
          "udp 0.0.0.0 + 127.0.0.2 without reuse must EADDRINUSE");
    close(a);
    close(b);

    struct sockaddr_in v1 = addr4("10.77.0.2", 18205);
    any = addr4("0.0.0.0", 18205);
    lo1 = addr4("127.0.0.1", 18205);
    a = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 1, 0, -1);
    b = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 1, 0, -1);
    CHECK(bind(a, (struct sockaddr *)&any, sizeof any) == 0, "udp reuse bind any");
    CHECK(bind(b, (struct sockaddr *)&v1, sizeof v1) == 0, "udp reuse bind v1");
    int ucli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    CHECK(sendto(ucli, "to-v1", 5, 0, (struct sockaddr *)&v1, sizeof v1) == 5, "send v1");
    char buf[16] = {0};
    CHECK(recv(b, buf, sizeof buf, 0) == 5 && memcmp(buf, "to-v1", 5) == 0, "v1 got exact");
    CHECK(recv(a, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "any got nothing");
    CHECK(sendto(ucli, "to-lo", 5, 0, (struct sockaddr *)&lo1, sizeof lo1) == 5, "send lo1");
    memset(buf, 0, sizeof buf);
    CHECK(recv(a, buf, sizeof buf, 0) == 5 && memcmp(buf, "to-lo", 5) == 0, "any got fallback");
    close(ucli);
    close(a);
    close(b);

    /* 2f. Accepted child socket keeps port occupied against non-reuse binds, yields to SO_REUSEADDR */
    lo1 = addr4("127.0.0.1", 18206);
    a = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
    CHECK(bind(a, (struct sockaddr *)&lo1, sizeof lo1) == 0 && listen(a, 4) == 0, "srv 18206");
    cli = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    CHECK(connect(cli, (struct sockaddr *)&lo1, sizeof lo1) == 0, "cli 18206");
    acc = accept(a, NULL, NULL);
    CHECK(acc >= 0, "acc 18206");
    close(a);
    b = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    errno = 0;
    CHECK(bind(b, (struct sockaddr *)&lo1, sizeof lo1) == -1 && errno == EADDRINUSE,
          "non-reuse bind over established accepted socket must EADDRINUSE");
    close(b);
    b = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
    CHECK(bind(b, (struct sockaddr *)&lo1, sizeof lo1) == 0 && listen(b, 4) == 0,
          "reuse bind over established accepted socket must succeed");
    close(b);
    close(acc);
    close(cli);
}

/* ---- 3. IPv6-only vs dual-stack vs IPv4 matrix ---- */

static void test_ipv6_v6only_matrix_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    close(rtnl);

    /* 3a. [::]:P (v6only=1) + [::]:P (v6only=0) -> EADDRINUSE (both directions, TCP and UDP) */
    for (int is_udp = 0; is_udp < 2; is_udp++) {
        int ty = is_udp ? SOCK_DGRAM : SOCK_STREAM;
        uint16_t p = (uint16_t)(18300 + is_udp * 10);
        struct sockaddr_in6 any6 = addr6("::", p);

        int s1 = mk_sock(AF_INET6, ty, 0, 0, 1);
        int s2 = mk_sock(AF_INET6, ty, 0, 0, 0);
        CHECK(bind(s1, (struct sockaddr *)&any6, sizeof any6) == 0, "bind v6only");
        if (!is_udp)
            CHECK(listen(s1, 4) == 0, "listen v6only");
        errno = 0;
        CHECK(bind(s2, (struct sockaddr *)&any6, sizeof any6) == -1 && errno == EADDRINUSE,
              "v6only + dual [::] must EADDRINUSE (udp=%d)", is_udp);
        close(s1);
        close(s2);

        /* Reverse order: dual first, then v6only */
        s1 = mk_sock(AF_INET6, ty, 0, 0, 0);
        s2 = mk_sock(AF_INET6, ty, 0, 0, 1);
        CHECK(bind(s1, (struct sockaddr *)&any6, sizeof any6) == 0, "bind dual");
        errno = 0;
        CHECK(bind(s2, (struct sockaddr *)&any6, sizeof any6) == -1 && errno == EADDRINUSE,
              "dual + v6only [::] must EADDRINUSE (udp=%d)", is_udp);
        close(s1);
        close(s2);

        /* 0.0.0.0:P + dual [::]:P -> EADDRINUSE */
        struct sockaddr_in any4 = addr4("0.0.0.0", p + 1);
        any6 = addr6("::", p + 1);
        s1 = mk_sock(AF_INET, ty, 0, 0, -1);
        s2 = mk_sock(AF_INET6, ty, 0, 0, 0);
        CHECK(bind(s1, (struct sockaddr *)&any4, sizeof any4) == 0, "bind 0.0.0.0");
        errno = 0;
        CHECK(bind(s2, (struct sockaddr *)&any6, sizeof any6) == -1 && errno == EADDRINUSE,
              "0.0.0.0 + dual [::] must EADDRINUSE (udp=%d)", is_udp);
        close(s1);
        close(s2);
    }

    /* 3b. 0.0.0.0:P + [::]:P (v6only=1) succeeds and routes IPv4 and IPv6 independently */
    const uint16_t p = 18320;
    struct sockaddr_in any4 = addr4("0.0.0.0", p);
    struct sockaddr_in6 any6 = addr6("::", p);
    int s4 = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, -1);
    int s6 = mk_sock(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, 1);
    CHECK(bind(s4, (struct sockaddr *)&any4, sizeof any4) == 0 && listen(s4, 4) == 0, "s4");
    CHECK(bind(s6, (struct sockaddr *)&any6, sizeof any6) == 0 && listen(s6, 4) == 0, "s6");

    /* Flipping IPV6_V6ONLY after bind must fail with EINVAL */
    int zero = 0;
    errno = 0;
    CHECK(setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == -1 && errno == EINVAL,
          "IPV6_V6ONLY after bind must EINVAL");

    struct sockaddr_in lo4 = addr4("127.0.0.1", p);
    struct sockaddr_in6 lo6 = addr6("::1", p);
    verify_tcp_echo(s4, AF_INET, (struct sockaddr *)&lo4, sizeof lo4, "127.0.0.1", p, "v4only");
    CHECK(accept(s6, NULL, NULL) == -1 && errno == EAGAIN, "s6 no crosstalk");
    verify_tcp_echo(s6, AF_INET6, (struct sockaddr *)&lo6, sizeof lo6, "::1", p, "v6only");
    CHECK(accept(s4, NULL, NULL) == -1 && errno == EAGAIN, "s4 no crosstalk");
    close(s4);
    close(s6);

    /* 3c. IPV6_V6ONLY=1 binding IPv4-mapped address must EINVAL */
    int sm = mk_sock(AF_INET6, SOCK_STREAM, 0, 0, 1);
    struct sockaddr_in6 mapped = addr6("::ffff:127.0.0.1", 18321);
    errno = 0;
    CHECK(bind(sm, (struct sockaddr *)&mapped, sizeof mapped) == -1 && errno == EINVAL,
          "v6only bind ::ffff:127.0.0.1 must EINVAL");
    close(sm);

    /* 3d. Dual-stack ::ffff:127.0.0.1:P conflicts with AF_INET 127.0.0.1:P and getsockname matches */
    sm = mk_sock(AF_INET6, SOCK_STREAM, 0, 0, 0);
    CHECK(bind(sm, (struct sockaddr *)&mapped, sizeof mapped) == 0, "bind ::ffff:127.0.0.1");
    struct sockaddr_in6 got6 = {0};
    socklen_t g6len = sizeof got6;
    CHECK(getsockname(sm, (struct sockaddr *)&got6, &g6len) == 0 &&
              memcmp(&got6.sin6_addr, &mapped.sin6_addr, 16) == 0 &&
              ntohs(got6.sin6_port) == 18321,
          "getsockname ::ffff:127.0.0.1");
    int s4dup = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    struct sockaddr_in lo_dup = addr4("127.0.0.1", 18321);
    errno = 0;
    CHECK(bind(s4dup, (struct sockaddr *)&lo_dup, sizeof lo_dup) == -1 && errno == EADDRINUSE,
          "::ffff:127.0.0.1 + 127.0.0.1 must EADDRINUSE");
    close(s4dup);
    close(sm);
}

/* ---- 4. Cross-namespace veth + DNAT forwarding with 127.0.0.1:P and <vaddr>:P coexisting ---- */

static int find_non_lo_ipv4(struct in_addr *out)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    struct ifreq reqs[32];
    struct ifconf ifc = {.ifc_len = (int)sizeof reqs, .ifc_req = reqs};
    int found = 0;
    if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
        int n = ifc.ifc_len / (int)sizeof reqs[0];
        for (int i = 0; i < n; i++) {
            if (reqs[i].ifr_addr.sa_family != AF_INET)
                continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)&reqs[i].ifr_addr;
            if ((ntohl(sin->sin_addr.s_addr) >> 24) != 127 && sin->sin_addr.s_addr != 0) {
                *out = sin->sin_addr;
                found = 1;
                break;
            }
        }
    }
    close(s);
    return found;
}

static void nft_put_data_val(struct nlbuf *b, uint16_t type, const void *val, size_t len)
{
    size_t d = nl_attr_start(b, type | NLA_F_NESTED);
    nl_attr(b, NFTA_DATA_VALUE, val, len);
    nl_attr_end(b, d);
}

static void nft_put_expr(struct nlbuf *b, const char *name, const uint8_t *data, size_t dlen)
{
    size_t el = nl_attr_start(b, NFTA_LIST_ELEM | NLA_F_NESTED);
    nl_attr(b, NFTA_EXPR_NAME, name, strlen(name) + 1);
    nl_attr(b, NFTA_EXPR_DATA | NLA_F_NESTED, data, dlen);
    nl_attr_end(b, el);
}

static void install_dnat(int nf, uint16_t ext_port_be, const uint8_t dst_ip[4], uint16_t dst_port_be)
{
    struct nlbuf m[5];
    /* batch begin */
    nl_init(&m[0], NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 10);
    struct nfgenmsg g0 = {.nfgen_family = AF_UNSPEC, .version = 0, .res_id = htons(NFNL_SUBSYS_NFTABLES)};
    nl_put_raw(&m[0], &g0, sizeof g0);

    /* new table */
    nl_init(&m[1], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 11);
    struct nfgenmsg g1 = {.nfgen_family = NFPROTO_IPV4};
    nl_put_raw(&m[1], &g1, sizeof g1);
    nl_attr(&m[1], NFTA_TABLE_NAME, "nb_nat", 7);

    /* new base chain prerouting nat */
    nl_init(&m[2], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 12);
    nl_put_raw(&m[2], &g1, sizeof g1);
    nl_attr(&m[2], NFTA_CHAIN_TABLE, "nb_nat", 7);
    nl_attr(&m[2], NFTA_CHAIN_NAME, "pre", 4);
    nl_attr(&m[2], NFTA_CHAIN_TYPE, "nat", 4);
    size_t hk = nl_attr_start(&m[2], NFTA_CHAIN_HOOK | NLA_F_NESTED);
    nl_attr_be32(&m[2], NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING);
    nl_attr_be32(&m[2], NFTA_HOOK_PRIORITY, (uint32_t)-100);
    nl_attr_end(&m[2], hk);
    nl_attr_be32(&m[2], NFTA_CHAIN_POLICY, NF_ACCEPT);

    /* new rule: tcp dport == ext_port -> dnat to dst_ip:dst_port */
    nl_init(&m[3], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 13);
    nl_put_raw(&m[3], &g1, sizeof g1);
    nl_attr(&m[3], NFTA_RULE_TABLE, "nb_nat", 7);
    nl_attr(&m[3], NFTA_RULE_CHAIN, "pre", 4);
    size_t exs = nl_attr_start(&m[3], NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
    struct nlbuf ed;
    ed.len = 0;
    nl_attr_be32(&ed, 2, 16);
    nl_attr_be32(&ed, 1, 1);
    nft_put_expr(&m[3], "meta", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    uint8_t tcp_p = IPPROTO_TCP;
    nft_put_data_val(&ed, 3, &tcp_p, 1);
    nft_put_expr(&m[3], "cmp", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 2);
    nl_attr_be32(&ed, 3, 2);
    nl_attr_be32(&ed, 4, 2);
    nft_put_expr(&m[3], "payload", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    nft_put_data_val(&ed, 3, &ext_port_be, 2);
    nft_put_expr(&m[3], "cmp", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nft_put_data_val(&ed, 2, dst_ip, 4);
    nft_put_expr(&m[3], "immediate", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 2);
    nft_put_data_val(&ed, 2, &dst_port_be, 2);
    nft_put_expr(&m[3], "immediate", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, NFPROTO_IPV4);
    nl_attr_be32(&ed, 3, 1);
    nl_attr_be32(&ed, 5, 2);
    nft_put_expr(&m[3], "nat", ed.data, ed.len);
    nl_attr_end(&m[3], exs);

    /* batch end */
    nl_init(&m[4], NFNL_MSG_BATCH_END, NLM_F_REQUEST, 14);
    nl_put_raw(&m[4], &g0, sizeof g0);

    uint8_t batch[4096];
    size_t blen = 0;
    for (int i = 0; i < 5; i++) {
        struct nlmsghdr *h = (struct nlmsghdr *)m[i].data;
        h->nlmsg_len = (uint32_t)m[i].len;
        memcpy(batch + blen, m[i].data, m[i].len);
        blen += m[i].len;
    }
    CHECK(send(nf, batch, blen, 0) == (ssize_t)blen, "nft batch send");
    int acks = 0;
    while (acks < 3) {
        uint8_t resp[2048];
        ssize_t n = recv(nf, resp, sizeof resp, 0);
        CHECK(n > 0, "nft recv ack");
        for (struct nlmsghdr *h = (struct nlmsghdr *)resp; NLMSG_OK(h, (unsigned)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
                CHECK(e->error == 0, "nft batch err %d", e->error);
                acks++;
            }
        }
    }
}

static void test_cross_ns_and_dnat(void)
{
    struct in_addr host_ip = {0};
    int has_host_ip = find_non_lo_ipv4(&host_ip);
    const uint16_t port = 19090;

    int p2c[2], c2p[2];
    CHECK(pipe(p2c) == 0 && pipe(c2p) == 0, "pipe");
    pid_t child = fork();
    CHECK(child >= 0, "fork");

    if (child == 0) {
        close(p2c[1]);
        close(c2p[0]);
        CHECK(unshare(CLONE_NEWNET) == 0, "child unshare");
        char b = 1;
        CHECK(write(c2p[1], &b, 1) == 1, "notify unshare");
        CHECK(read(p2c[0], &b, 1) == 1, "wait veth");

        int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        CHECK(rtnl >= 0, "child rtnl");
        set_link_up(rtnl, 1);
        int if1 = (int)if_nametoindex("nb1");
        CHECK(if1 > 0, "nb1 index");
        set_link_up(rtnl, if1);
        add_v4_addr(rtnl, if1, "10.79.0.2", 24);
        /* Default route via 10.79.0.1 */
        struct in_addr gw;
        CHECK(inet_pton(AF_INET, "10.79.0.1", &gw) == 1, "pton gw");
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

        /* Bind 127.0.0.1:19090 FIRST, then 10.79.0.2:19090 SECOND (both TCP and UDP) */
        struct sockaddr_in a_lo = addr4("127.0.0.1", port);
        struct sockaddr_in a_va = addr4("10.79.0.2", port);
        int t_lo = mk_sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, 0, -1);
        int t_va = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
        CHECK(bind(t_lo, (struct sockaddr *)&a_lo, sizeof a_lo) == 0 && listen(t_lo, 4) == 0,
              "child tcp lo");
        CHECK(bind(t_va, (struct sockaddr *)&a_va, sizeof a_va) == 0 && listen(t_va, 4) == 0,
              "child tcp vaddr");

        int u_lo = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
        int u_va = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
        CHECK(bind(u_lo, (struct sockaddr *)&a_lo, sizeof a_lo) == 0, "child udp lo");
        CHECK(bind(u_va, (struct sockaddr *)&a_va, sizeof a_va) == 0, "child udp vaddr");

        CHECK(write(c2p[1], &b, 1) == 1, "notify ready");

        /* 1) Accept direct TCP from init_ns to 10.79.0.2:19090 */
        int acc = accept(t_va, NULL, NULL);
        CHECK(acc >= 0, "child accept direct");
        CHECK(accept(t_lo, NULL, NULL) == -1 && errno == EAGAIN, "lo must not accept veth traffic");
        CHECK(send(acc, "veth-tcp", 8, 0) == 8, "send veth-tcp");
        close(acc);

        /* 2) Receive direct UDP from init_ns to 10.79.0.2:19090 and reply */
        char ubuf[16] = {0};
        struct sockaddr_in ufrom = {0};
        socklen_t ulen = sizeof ufrom;
        CHECK(recvfrom(u_va, ubuf, sizeof ubuf, 0, (struct sockaddr *)&ufrom, &ulen) == 4 &&
                  memcmp(ubuf, "ping", 4) == 0,
              "child udp recv");
        CHECK(recv(u_lo, ubuf, sizeof ubuf, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "udp lo must not receive veth traffic");
        CHECK(sendto(u_va, "veth-udp", 8, 0, (struct sockaddr *)&ufrom, ulen) == 8, "child udp reply");

        /* 3) If DNAT test active, accept forwarded connection on t_va (never t_lo) */
        if (has_host_ip) {
            int acc2 = accept(t_va, NULL, NULL);
            CHECK(acc2 >= 0, "child accept dnat");
            CHECK(accept(t_lo, NULL, NULL) == -1 && errno == EAGAIN,
                  "lo must not accept dnat traffic");
            CHECK(send(acc2, "dnat-tcp", 8, 0) == 8, "send dnat-tcp");
            close(acc2);
        }

        close(u_lo);
        close(u_va);
        close(t_lo);
        close(t_va);
        _exit(0);
    }

    close(p2c[0]);
    close(c2p[1]);
    char b = 0;
    CHECK(read(c2p[0], &b, 1) == 1, "wait child unshare");

    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "parent rtnl");
    create_veth(rtnl, "nb0", "nb1", child);
    int if0 = (int)if_nametoindex("nb0");
    CHECK(if0 > 0, "nb0 index");
    set_link_up(rtnl, if0);
    add_v4_addr(rtnl, if0, "10.79.0.1", 24);
    close(rtnl);

    CHECK(write(p2c[1], &b, 1) == 1, "notify veth");
    CHECK(read(c2p[0], &b, 1) == 1, "wait child ready");

    /* Direct TCP from init_ns to 10.79.0.2:19090 */
    struct sockaddr_in target = addr4("10.79.0.2", port);
    int cli = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
    CHECK(connect(cli, (struct sockaddr *)&target, sizeof target) == 0, "init->child tcp");
    char buf[16] = {0};
    CHECK(recv(cli, buf, 8, MSG_WAITALL) == 8 && memcmp(buf, "veth-tcp", 8) == 0,
          "got '%s' want veth-tcp", buf);
    close(cli);

    /* Direct UDP from init_ns to 10.79.0.2:19090 */
    int ucli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    CHECK(sendto(ucli, "ping", 4, 0, (struct sockaddr *)&target, sizeof target) == 4, "init->child udp");
    struct sockaddr_in rfrom = {0};
    socklen_t rflen = sizeof rfrom;
    memset(buf, 0, sizeof buf);
    CHECK(recvfrom(ucli, buf, sizeof buf, 0, (struct sockaddr *)&rfrom, &rflen) == 8 &&
              memcmp(buf, "veth-udp", 8) == 0,
          "got '%s' want veth-udp", buf);
    CHECK(rfrom.sin_addr.s_addr == target.sin_addr.s_addr && ntohs(rfrom.sin_port) == port,
          "init udp reply src mismatch");
    close(ucli);

    /* Forwarder DNAT test: host_ip:ext -> 10.79.0.2:19090 must hit t_va, not t_lo */
    if (has_host_ip) {
        int ext = mk_sock(AF_INET, SOCK_STREAM, 1, 0, -1);
        struct sockaddr_in ext_sa = addr4("0.0.0.0", 0);
        CHECK(bind(ext, (struct sockaddr *)&ext_sa, sizeof ext_sa) == 0 && listen(ext, 4) == 0,
              "ext listen");
        socklen_t elen = sizeof ext_sa;
        CHECK(getsockname(ext, (struct sockaddr *)&ext_sa, &elen) == 0 && ext_sa.sin_port != 0,
              "ext getsockname");

        int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        CHECK(nf >= 0, "nf");
        const uint8_t dst_ip[4] = {10, 79, 0, 2};
        install_dnat(nf, ext_sa.sin_port, dst_ip, htons(port));

        int dcli = mk_sock(AF_INET, SOCK_STREAM, 0, 0, -1);
        struct sockaddr_in ddst = {.sin_family = AF_INET, .sin_addr = host_ip, .sin_port = ext_sa.sin_port};
        CHECK(connect(dcli, (struct sockaddr *)&ddst, sizeof ddst) == 0, "dnat connect");
        memset(buf, 0, sizeof buf);
        CHECK(recv(dcli, buf, 8, MSG_WAITALL) == 8 && memcmp(buf, "dnat-tcp", 8) == 0,
              "dnat got '%s' want dnat-tcp", buf);
        close(dcli);
        close(ext);
        close(nf);
    }

    int st = 0;
    CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "child status %d", st);
    ok("cross_ns_and_dnat");
}

/* ---- 5. Connected UDP connect-before-bind, server close/rebind & nftables guest sport ---- */

static void install_drop_udp_sport(int nf, uint16_t sport_be)
{
    struct nlbuf m[5];
    nl_init(&m[0], NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 30);
    struct nfgenmsg g0 = {.nfgen_family = AF_UNSPEC, .res_id = htons(NFNL_SUBSYS_NFTABLES)};
    nl_put_raw(&m[0], &g0, sizeof g0);

    nl_init(&m[1], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 31);
    struct nfgenmsg g1 = {.nfgen_family = NFPROTO_IPV4};
    nl_put_raw(&m[1], &g1, sizeof g1);
    nl_attr(&m[1], NFTA_TABLE_NAME, "nb_flt", 7);

    nl_init(&m[2], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 32);
    nl_put_raw(&m[2], &g1, sizeof g1);
    nl_attr(&m[2], NFTA_CHAIN_TABLE, "nb_flt", 7);
    nl_attr(&m[2], NFTA_CHAIN_NAME, "out", 4);
    nl_attr(&m[2], NFTA_CHAIN_TYPE, "filter", 7);
    size_t hk = nl_attr_start(&m[2], NFTA_CHAIN_HOOK | NLA_F_NESTED);
    nl_attr_be32(&m[2], NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
    nl_attr_be32(&m[2], NFTA_HOOK_PRIORITY, 0);
    nl_attr_end(&m[2], hk);
    nl_attr_be32(&m[2], NFTA_CHAIN_POLICY, NF_ACCEPT);

    /* rule: udp sport == sport_be -> drop */
    nl_init(&m[3], (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 33);
    nl_put_raw(&m[3], &g1, sizeof g1);
    nl_attr(&m[3], NFTA_RULE_TABLE, "nb_flt", 7);
    nl_attr(&m[3], NFTA_RULE_CHAIN, "out", 4);
    size_t exs = nl_attr_start(&m[3], NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
    struct nlbuf ed;
    ed.len = 0;
    nl_attr_be32(&ed, 2 /* NFTA_META_KEY */, 16 /* L4PROTO */);
    nl_attr_be32(&ed, 1 /* NFTA_META_DREG */, 1);
    nft_put_expr(&m[3], "meta", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    uint8_t udp_p = IPPROTO_UDP;
    nft_put_data_val(&ed, 3, &udp_p, 1);
    nft_put_expr(&m[3], "cmp", ed.data, ed.len);
    /* payload th@0,2 -> reg1 (sport is offset 0, len 2 in UDP header) */
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 2);
    nl_attr_be32(&ed, 3, 0);
    nl_attr_be32(&ed, 4, 2);
    nft_put_expr(&m[3], "payload", ed.data, ed.len);
    ed.len = 0;
    nl_attr_be32(&ed, 1, 1);
    nl_attr_be32(&ed, 2, 0);
    nft_put_data_val(&ed, 3, &sport_be, 2);
    nft_put_expr(&m[3], "cmp", ed.data, ed.len);
    /* immediate verdict NF_DROP */
    ed.len = 0;
    nl_attr_be32(&ed, 1 /* DREG */, 0 /* VERDICT */);
    size_t vd = nl_attr_start(&ed, 2 /* DATA */ | NLA_F_NESTED);
    size_t vr = nl_attr_start(&ed, 2 /* NFTA_DATA_VERDICT */ | NLA_F_NESTED);
    nl_attr_be32(&ed, 1 /* NFTA_VERDICT_CODE */, NF_DROP);
    nl_attr_end(&ed, vr);
    nl_attr_end(&ed, vd);
    nft_put_expr(&m[3], "immediate", ed.data, ed.len);
    nl_attr_end(&m[3], exs);

    nl_init(&m[4], NFNL_MSG_BATCH_END, NLM_F_REQUEST, 34);
    nl_put_raw(&m[4], &g0, sizeof g0);

    uint8_t batch[4096];
    size_t blen = 0;
    for (int i = 0; i < 5; i++) {
        struct nlmsghdr *h = (struct nlmsghdr *)m[i].data;
        h->nlmsg_len = (uint32_t)m[i].len;
        memcpy(batch + blen, m[i].data, m[i].len);
        blen += m[i].len;
    }
    CHECK(send(nf, batch, blen, 0) == (ssize_t)blen, "nft sport batch send");
    int acks = 0;
    while (acks < 3) {
        uint8_t resp[2048];
        ssize_t n = recv(nf, resp, sizeof resp, 0);
        CHECK(n > 0, "nft sport recv ack");
        for (struct nlmsghdr *h = (struct nlmsghdr *)resp; NLMSG_OK(h, (unsigned)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
                CHECK(e->error == 0, "nft sport batch err %d", e->error);
                acks++;
            }
        }
    }
}

static void test_connected_udp_rebind_and_nft_sport_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);
    int d0 = create_dummy(rtnl, "dum0");
    add_v4_addr(rtnl, d0, "10.77.0.2", 24);
    close(rtnl);

    /* 5a. Normal and wide (0.0.0.0:0) connected UDP clients across connect-before-bind and
     *     server close + rebind (which allocates a fresh host ephemeral port). */
    for (int wide = 0; wide < 2; wide++) {
        uint16_t port = (uint16_t)(18400 + wide);
        struct sockaddr_in dst = addr4("10.77.0.2", port);
        struct sockaddr_in lo_decoy = addr4("127.0.0.1", port);
        int cli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
        if (wide) {
            struct sockaddr_in any0 = addr4("0.0.0.0", 0);
            CHECK(bind(cli, (struct sockaddr *)&any0, sizeof any0) == 0, "wide bind");
        }
        CHECK(connect(cli, (struct sockaddr *)&dst, sizeof dst) == 0, "udp connect before bind");
        /* Decoy listener on 127.0.0.1:port must never capture packets meant for 10.77.0.2:port */
        int decoy = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
        CHECK(bind(decoy, (struct sockaddr *)&lo_decoy, sizeof lo_decoy) == 0, "bind decoy");

        /* Send before target binds: silently dropped */
        CHECK(send(cli, "early", 5, 0) == 5, "send before bind");
        char buf[16] = {0};
        CHECK(recv(decoy, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "decoy silent");

        /* Bind srv1 -> send & receive echo */
        int srv1 = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
        CHECK(bind(srv1, (struct sockaddr *)&dst, sizeof dst) == 0, "bind srv1");
        CHECK(send(cli, "msg1", 4, 0) == 4, "send msg1 (wide=%d)", wide);
        struct sockaddr_in from = {0};
        socklen_t flen = sizeof from;
        memset(buf, 0, sizeof buf);
        CHECK(recvfrom(srv1, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 4 &&
                  memcmp(buf, "msg1", 4) == 0,
              "srv1 recv msg1 (wide=%d)", wide);
        CHECK(sendto(srv1, "rep1", 4, 0, (struct sockaddr *)&from, flen) == 4, "srv1 reply");
        memset(buf, 0, sizeof buf);
        CHECK(recv(cli, buf, sizeof buf, 0) == 4 && memcmp(buf, "rep1", 4) == 0,
              "cli recv rep1 (wide=%d)", wide);
        close(srv1);

        /* Close + rebind srv2 (new host port) -> send & receive echo still works */
        int srv2 = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
        CHECK(bind(srv2, (struct sockaddr *)&dst, sizeof dst) == 0, "bind srv2");
        CHECK(send(cli, "msg2", 4, 0) == 4, "send msg2 (wide=%d)", wide);
        flen = sizeof from;
        memset(buf, 0, sizeof buf);
        CHECK(recvfrom(srv2, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 4 &&
                  memcmp(buf, "msg2", 4) == 0,
              "srv2 recv msg2 (wide=%d)", wide);
        CHECK(sendto(srv2, "rep2", 4, 0, (struct sockaddr *)&from, flen) == 4, "srv2 reply");
        memset(buf, 0, sizeof buf);
        CHECK(recv(cli, buf, sizeof buf, 0) == 4 && memcmp(buf, "rep2", 4) == 0,
              "cli recv rep2 (wide=%d)", wide);

        CHECK(recv(decoy, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "decoy silent2");
        close(srv2);
        close(decoy);
        close(cli);
    }

    /* 5b. nftables OUTPUT filter sees the guest sport (unmapped from host ephemeral port) */
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf");
    install_drop_udp_sport(nf, htons(18410));

    struct sockaddr_in srv_sa = addr4("127.0.0.1", 18411);
    int srv = mk_sock(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0, -1);
    CHECK(bind(srv, (struct sockaddr *)&srv_sa, sizeof srv_sa) == 0, "bind sport srv");

    int blocked_cli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    struct sockaddr_in bsa = addr4("127.0.0.1", 18410);
    CHECK(bind(blocked_cli, (struct sockaddr *)&bsa, sizeof bsa) == 0, "bind blocked sport");
    errno = 0;
    CHECK(sendto(blocked_cli, "drop", 4, 0, (struct sockaddr *)&srv_sa, sizeof srv_sa) == -1 &&
              errno == EPERM,
          "nft OUTPUT rule must match guest sport 18410 (EPERM)");

    int ok_cli = mk_sock(AF_INET, SOCK_DGRAM, 0, 0, -1);
    struct sockaddr_in osa = addr4("127.0.0.1", 18412);
    CHECK(bind(ok_cli, (struct sockaddr *)&osa, sizeof osa) == 0, "bind ok sport");
    CHECK(sendto(ok_cli, "pass", 4, 0, (struct sockaddr *)&srv_sa, sizeof srv_sa) == 4,
          "non-matching sport must pass");
    char buf[8] = {0};
    CHECK(recv(srv, buf, sizeof buf, 0) == 4 && memcmp(buf, "pass", 4) == 0, "srv recv pass");

    close(ok_cli);
    close(blocked_cli);
    close(srv);
    close(nf);
}

int main(void)
{
    alarm(30);
    CHECK(run_in_child(test_same_port_distinct_addrs_child) == 0, "same_port_distinct_addrs");
    ok("same_port_distinct_addrs");
    CHECK(run_in_child(test_conflict_matrix_child) == 0, "conflict_matrix");
    ok("conflict_matrix");
    CHECK(run_in_child(test_ipv6_v6only_matrix_child) == 0, "ipv6_v6only_matrix");
    ok("ipv6_v6only_matrix");
    test_cross_ns_and_dnat();
    CHECK(run_in_child(test_connected_udp_rebind_and_nft_sport_child) == 0,
          "connected_udp_rebind_and_nft_sport");
    ok("connected_udp_rebind_and_nft_sport");
    printf("all ok\n");
    return 0;
}
