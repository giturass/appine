/*
 * Standalone guest regression suite for resumable netlink dumps and chunked nft set-element
 * dumps. Built with musl-gcc -static and run under both Tier 0 and Tier 1.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

enum {
    NETLINK_ROUTE = 0,
    NETLINK_NETFILTER = 12,
    NETLINK_GENERIC = 16,
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

enum {
    NLMSG_HDRLEN = 16,
    NLMSG_ERROR = 2,
    NLMSG_DONE = 3,
    NLM_F_REQUEST = 0x01,
    NLM_F_MULTI = 0x02,
    NLM_F_ACK = 0x04,
    NLM_F_EXCL = 0x200,
    NLM_F_DUMP = 0x300,
    NLM_F_CREATE = 0x400,
    NLA_HDRLEN = 4,
    NLA_F_NESTED = 0x8000,
    NLA_TYPE_MASK = 0x3fff,

    RTM_NEWLINK = 16,
    RTM_GETLINK = 18,
    RTM_NEWADDR = 20,
    RTM_GETADDR = 22,
    RTM_NEWROUTE = 24,
    RTM_GETROUTE = 26,
    RTM_NEWRULE = 32,
    RTM_GETRULE = 34,

    IFLA_IFNAME = 3,
    IFLA_LINKINFO = 18,
    IFLA_INFO_KIND = 1,

    IFA_ADDRESS = 1,
    IFA_LOCAL = 2,

    RTA_DST = 1,

    NFPROTO_IPV4 = 2,
    NFNL_MSG_BATCH_BEGIN = 0x10,
    NFNL_MSG_BATCH_END = 0x11,
    NFNL_SUBSYS_NFTABLES = 10,

    NFT_MSG_NEWTABLE = 0,
    NFT_MSG_NEWSET = 9,
    NFT_MSG_NEWSETELEM = 12,
    NFT_MSG_GETSETELEM = 13,

    NFTA_TABLE_NAME = 1,
    NFTA_SET_TABLE = 1,
    NFTA_SET_NAME = 2,
    NFTA_SET_KEY_LEN = 5,
    NFTA_SET_ELEM_LIST_TABLE = 1,
    NFTA_SET_ELEM_LIST_SET = 2,
    NFTA_SET_ELEM_LIST_ELEMENTS = 3,
    NFTA_LIST_ELEM = 1,
    NFTA_SET_ELEM_KEY = 1,
    NFTA_DATA_VALUE = 1,
};

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

struct nlbuf {
    uint8_t data[16384];
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

static void nl_attr_be32(struct nlbuf *b, uint16_t type, uint32_t v)
{
    uint32_t be = htonl(v);
    nl_attr(b, type, &be, sizeof be);
}

static void nl_finish(struct nlbuf *b)
{
    uint32_t len = (uint32_t)b->len;
    memcpy(b->data, &len, sizeof len);
}

static ssize_t nl_recvmsg(int fd, void *buf, size_t len, int flags, int *out_flags)
{
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    struct sockaddr_nl sa = {0};
    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof sa,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    ssize_t n = recvmsg(fd, &msg, flags);
    if (out_flags)
        *out_flags = msg.msg_flags;
    return n;
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

static const uint8_t *find_attr(const uint8_t *buf, size_t len, uint16_t want, size_t *alen)
{
    size_t off = 0;
    while (off + NLA_HDRLEN <= len) {
        struct nlattr a;
        memcpy(&a, buf + off, sizeof a);
        if (a.nla_len < NLA_HDRLEN || off + a.nla_len > len)
            break;
        if ((a.nla_type & NLA_TYPE_MASK) == want) {
            if (alen)
                *alen = a.nla_len - NLA_HDRLEN;
            return buf + off + NLA_HDRLEN;
        }
        off += (a.nla_len + 3) & ~3u;
    }
    return NULL;
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

static void add_v4_addr(int rtnl, int ifindex, const char *ip, uint8_t prefix)
{
    struct in_addr a;
    CHECK(inet_pton(AF_INET, ip, &a) == 1, "inet_pton");
    struct nlbuf b;
    nl_init(&b, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 3);
    struct ifaddrmsg ifa = {.ifa_family = AF_INET, .ifa_prefixlen = prefix, .ifa_index = ifindex};
    nl_put_raw(&b, &ifa, sizeof ifa);
    nl_attr(&b, IFA_LOCAL, &a, 4);
    nl_attr(&b, IFA_ADDRESS, &a, 4);
    CHECK(nl_send_ack(rtnl, &b) == 0, "add addr %s", ip);
}

/* ---- 1 & 2. rtnetlink resumable dumps with small buffers, MSG_PEEK, MSG_TRUNC ---- */

enum { NUM_DUMMIES = 20 };

static void send_rtnl_dump(int fd, uint16_t ty, uint8_t family, uint32_t seq)
{
    struct nlbuf req;
    nl_init(&req, ty, NLM_F_REQUEST | NLM_F_DUMP, seq);
    uint8_t hdr[16] = {0};
    hdr[0] = family;
    nl_put_raw(&req, hdr, sizeof hdr);
    nl_finish(&req);
    CHECK(send(fd, req.data, req.len, 0) == (ssize_t)req.len, "send dump %u", ty);
}

static void check_link_dump(int fd, size_t bufsz)
{
    send_rtnl_dump(fd, RTM_GETLINK, AF_UNSPEC, 10);
    uint8_t *buf = malloc(bufsz);
    CHECK(buf != NULL, "malloc");
    int seen_lo = 0;
    int seen_dum[NUM_DUMMIES] = {0};
    int recvs = 0;
    int done = 0;
    while (!done) {
        int mflags = 0;
        ssize_t n = nl_recvmsg(fd, buf, bufsz, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (size_t)n <= bufsz, "link recv %zd (bufsz %zu)", n,
              bufsz);
        CHECK((mflags & MSG_TRUNC) == 0, "unexpected MSG_TRUNC on link dump bufsz=%zu", bufsz);
        recvs++;
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            CHECK(h.nlmsg_len >= NLMSG_HDRLEN && off + h.nlmsg_len <= (size_t)n, "bad nlmsg_len");
            CHECK((h.nlmsg_flags & NLM_F_MULTI) != 0, "missing NLM_F_MULTI");
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWLINK, "unexpected type %u", h.nlmsg_type);
            size_t nlen = 0;
            const uint8_t *name = find_attr(buf + off + NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                            h.nlmsg_len - NLMSG_HDRLEN - sizeof(struct ifinfomsg),
                                            IFLA_IFNAME, &nlen);
            CHECK(name != NULL, "missing IFLA_IFNAME");
            if (strcmp((const char *)name, "lo") == 0) {
                seen_lo++;
            } else if (strncmp((const char *)name, "dum", 3) == 0) {
                int idx = atoi((const char *)name + 3);
                CHECK(idx >= 0 && idx < NUM_DUMMIES, "bad dummy idx %d", idx);
                seen_dum[idx]++;
            }
            off += (h.nlmsg_len + 3) & ~3u;
        }
    }
    free(buf);
    CHECK(recvs > 2, "expected multiple recvs for bufsz=%zu, got %d", bufsz, recvs);
    CHECK(seen_lo == 1, "lo seen %d times", seen_lo);
    for (int i = 0; i < NUM_DUMMIES; i++)
        CHECK(seen_dum[i] == 1, "dum%d seen %d times (bufsz=%zu)", i, seen_dum[i], bufsz);
}

static void check_addr_dump(int fd, size_t bufsz)
{
    send_rtnl_dump(fd, RTM_GETADDR, AF_UNSPEC, 11);
    uint8_t *buf = malloc(bufsz);
    CHECK(buf != NULL, "malloc");
    int seen_lo4 = 0;
    int seen_dum[NUM_DUMMIES] = {0};
    int recvs = 0;
    int done = 0;
    while (!done) {
        int mflags = 0;
        ssize_t n = nl_recvmsg(fd, buf, bufsz, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (size_t)n <= bufsz, "addr recv %zd", n);
        CHECK((mflags & MSG_TRUNC) == 0, "unexpected MSG_TRUNC on addr dump bufsz=%zu", bufsz);
        recvs++;
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            CHECK(h.nlmsg_len >= NLMSG_HDRLEN && off + h.nlmsg_len <= (size_t)n, "bad nlmsg_len");
            CHECK((h.nlmsg_flags & NLM_F_MULTI) != 0, "missing NLM_F_MULTI");
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWADDR, "unexpected type %u", h.nlmsg_type);
            struct ifaddrmsg ifa;
            memcpy(&ifa, buf + off + NLMSG_HDRLEN, sizeof ifa);
            if (ifa.ifa_family == AF_INET) {
                size_t alen = 0;
                const uint8_t *ip =
                    find_attr(buf + off + NLMSG_HDRLEN + sizeof(struct ifaddrmsg),
                              h.nlmsg_len - NLMSG_HDRLEN - sizeof(struct ifaddrmsg), IFA_LOCAL,
                              &alen);
                CHECK(ip != NULL && alen == 4, "missing IFA_LOCAL");
                if (ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1) {
                    seen_lo4++;
                } else if (ip[0] == 10 && ip[1] == 10 && ip[3] == 1 && ip[2] >= 1 &&
                           ip[2] <= NUM_DUMMIES) {
                    seen_dum[ip[2] - 1]++;
                }
            }
            off += (h.nlmsg_len + 3) & ~3u;
        }
    }
    free(buf);
    CHECK(recvs > 2, "expected multiple recvs for addr bufsz=%zu, got %d", bufsz, recvs);
    CHECK(seen_lo4 == 1, "lo4 seen %d", seen_lo4);
    for (int i = 0; i < NUM_DUMMIES; i++)
        CHECK(seen_dum[i] == 1, "addr dum%d seen %d (bufsz=%zu)", i, seen_dum[i], bufsz);
}

static void check_route_dump(int fd, size_t bufsz)
{
    send_rtnl_dump(fd, RTM_GETROUTE, AF_UNSPEC, 12);
    uint8_t *buf = malloc(bufsz);
    CHECK(buf != NULL, "malloc");
    int seen_subnet[NUM_DUMMIES] = {0};
    int recvs = 0;
    int done = 0;
    while (!done) {
        int mflags = 0;
        ssize_t n = nl_recvmsg(fd, buf, bufsz, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (size_t)n <= bufsz, "route recv %zd", n);
        CHECK((mflags & MSG_TRUNC) == 0, "unexpected MSG_TRUNC on route dump bufsz=%zu", bufsz);
        recvs++;
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            CHECK(h.nlmsg_len >= NLMSG_HDRLEN && off + h.nlmsg_len <= (size_t)n, "bad nlmsg_len");
            CHECK((h.nlmsg_flags & NLM_F_MULTI) != 0, "missing NLM_F_MULTI");
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWROUTE, "unexpected type %u", h.nlmsg_type);
            struct rtmsg rtm;
            memcpy(&rtm, buf + off + NLMSG_HDRLEN, sizeof rtm);
            if (rtm.rtm_family == AF_INET && rtm.rtm_dst_len == 24) {
                size_t dlen = 0;
                const uint8_t *dst =
                    find_attr(buf + off + NLMSG_HDRLEN + sizeof(struct rtmsg),
                              h.nlmsg_len - NLMSG_HDRLEN - sizeof(struct rtmsg), RTA_DST, &dlen);
                if (dst && dlen == 4 && dst[0] == 10 && dst[1] == 10 && dst[3] == 0 &&
                    dst[2] >= 1 && dst[2] <= NUM_DUMMIES) {
                    seen_subnet[dst[2] - 1]++;
                }
            }
            off += (h.nlmsg_len + 3) & ~3u;
        }
    }
    free(buf);
    CHECK(recvs > 2, "expected multiple recvs for route bufsz=%zu, got %d", bufsz, recvs);
    for (int i = 0; i < NUM_DUMMIES; i++)
        CHECK(seen_subnet[i] == 1, "route 10.10.%d.0/24 seen %d", i + 1, seen_subnet[i]);
}

static void check_rule_dump(int fd, uint8_t family, size_t bufsz, int expect_rules)
{
    send_rtnl_dump(fd, RTM_GETRULE, family, 13);
    uint8_t *buf = malloc(bufsz);
    CHECK(buf != NULL, "malloc");
    int count = 0;
    int recvs = 0;
    int done = 0;
    while (!done) {
        int mflags = 0;
        ssize_t n = nl_recvmsg(fd, buf, bufsz, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (size_t)n <= bufsz, "rule recv %zd", n);
        CHECK((mflags & MSG_TRUNC) == 0, "unexpected MSG_TRUNC on rule dump bufsz=%zu", bufsz);
        recvs++;
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            CHECK(h.nlmsg_len >= NLMSG_HDRLEN && off + h.nlmsg_len <= (size_t)n, "bad nlmsg_len");
            CHECK((h.nlmsg_flags & NLM_F_MULTI) != 0, "missing NLM_F_MULTI");
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWRULE, "unexpected type %u", h.nlmsg_type);
            count++;
            off += (h.nlmsg_len + 3) & ~3u;
        }
    }
    free(buf);
    CHECK(count == expect_rules, "expected %d rules got %d (bufsz=%zu)", expect_rules, count,
          bufsz);
    if (bufsz <= 96)
        CHECK(recvs >= 3, "expected split rule recvs for bufsz=%zu, got %d", bufsz, recvs);
}

static void test_rtnetlink_dumps_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int rtnl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rtnl >= 0, "rtnl");
    set_link_up(rtnl, 1);

    for (int i = 0; i < NUM_DUMMIES; i++) {
        char name[16];
        snprintf(name, sizeof name, "dum%d", i);
        create_dummy(rtnl, name);
        int idx = (int)if_nametoindex(name);
        CHECK(idx > 1, "if_nametoindex %s", name);
        set_link_up(rtnl, idx);
        char ip[32];
        snprintf(ip, sizeof ip, "10.10.%d.1", i + 1);
        add_v4_addr(rtnl, idx, ip, 24);
    }

    /* Small-buffer resumable dumps for links (virtual dummy RTM_NEWLINK is ~540B),
     * addrs, routes and rules */
    check_link_dump(rtnl, 640);
    check_link_dump(rtnl, 1024);
    check_addr_dump(rtnl, 256);
    check_addr_dump(rtnl, 512);
    check_route_dump(rtnl, 256);
    check_route_dump(rtnl, 512);
    check_rule_dump(rtnl, AF_INET, 96, 3);
    check_rule_dump(rtnl, AF_UNSPEC, 96, 7);
    check_rule_dump(rtnl, AF_UNSPEC, 512, 7);

    /* MSG_PEEK | MSG_TRUNC probe-and-allocate loop over full link dump */
    send_rtnl_dump(rtnl, RTM_GETLINK, AF_UNSPEC, 20);
    int seen_links = 0;
    int done = 0;
    while (!done) {
        ssize_t sz1 = recv(rtnl, NULL, 0, MSG_PEEK | MSG_TRUNC);
        ssize_t sz2 = recv(rtnl, NULL, 0, MSG_PEEK | MSG_TRUNC);
        CHECK(sz1 >= (ssize_t)NLMSG_HDRLEN && sz1 == sz2, "peek probe mismatch %zd vs %zd", sz1,
              sz2);
        uint8_t *buf = malloc((size_t)sz1);
        CHECK(buf != NULL, "malloc");
        int mflags = 0;
        ssize_t got = nl_recvmsg(rtnl, buf, (size_t)sz1, 0, &mflags);
        CHECK(got == sz1 && (mflags & MSG_TRUNC) == 0, "exact recv got=%zd want=%zd flags=%#x",
              got, sz1, mflags);
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)got) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWLINK, "peek loop type %u", h.nlmsg_type);
            seen_links++;
            off += (h.nlmsg_len + 3) & ~3u;
        }
        free(buf);
    }
    CHECK(seen_links == 1 + NUM_DUMMIES, "peek loop saw %d links", seen_links);

    /* Oversized single atomic message: 128B buffer truncates only the first link, rest resume */
    send_rtnl_dump(rtnl, RTM_GETLINK, AF_UNSPEC, 21);
    uint8_t tiny[128];
    int mflags = 0;
    ssize_t peek_full = nl_recvmsg(rtnl, tiny, sizeof tiny, MSG_PEEK | MSG_TRUNC, &mflags);
    CHECK(peek_full > (ssize_t)sizeof tiny && (mflags & MSG_TRUNC) != 0,
          "expected oversized peek_full=%zd flags=%#x", peek_full, mflags);
    struct nlmsghdr hdr0;
    memcpy(&hdr0, tiny, sizeof hdr0);
    CHECK(hdr0.nlmsg_type == RTM_NEWLINK && hdr0.nlmsg_len == (uint32_t)peek_full,
          "oversized header type=%u len=%u full=%zd", hdr0.nlmsg_type, hdr0.nlmsg_len, peek_full);

    /* Non-peek 128B recv without MSG_TRUNC returns 128 and sets msg_flags |= MSG_TRUNC */
    mflags = 0;
    ssize_t trunc_n = nl_recvmsg(rtnl, tiny, sizeof tiny, 0, &mflags);
    CHECK(trunc_n == (ssize_t)sizeof tiny && (mflags & MSG_TRUNC) != 0,
          "expected truncated 128B recv got=%zd flags=%#x", trunc_n, mflags);

    /* Remaining 20 links + NLMSG_DONE still arrive cleanly with a 640B buffer */
    uint8_t buf640[640];
    int rem_links = 0;
    done = 0;
    while (!done) {
        mflags = 0;
        ssize_t n = nl_recvmsg(rtnl, buf640, sizeof buf640, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (mflags & MSG_TRUNC) == 0, "resume recv %zd flags=%#x",
              n, mflags);
        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf640 + off, sizeof h);
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == RTM_NEWLINK, "resume type %u", h.nlmsg_type);
            rem_links++;
            off += (h.nlmsg_len + 3) & ~3u;
        }
    }
    CHECK(rem_links == NUM_DUMMIES, "expected %d remaining links after 1 trunc, got %d",
          NUM_DUMMIES, rem_links);
    close(rtnl);
}

/* ---- 3. Large nft set-element dump (600 elements) with small and standard buffers ---- */

enum { NUM_SET_ELEMS = 600 };

static void nft_msg_init(struct nlbuf *b, uint8_t msg, uint16_t flags, uint32_t seq, uint8_t fam)
{
    nl_init(b, (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | msg), NLM_F_REQUEST | flags, seq);
    uint8_t g[4] = {fam, 0, 0, 0};
    nl_put_raw(b, g, 4);
}

static void nft_batch_send(int fd, struct nlbuf *msgs, size_t nmsgs, size_t nacks)
{
    uint8_t buf[32768];
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
        CHECK(off + msgs[i].len + 64 <= sizeof buf, "batch buf overflow");
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
    for (size_t i = 0; i < nacks; i++) {
        uint8_t resp[4096];
        ssize_t n = recv(fd, resp, sizeof resp, 0);
        CHECK(n >= (ssize_t)(NLMSG_HDRLEN + 4), "nft ack recv %zu", i);
        int32_t e = 0;
        memcpy(&e, resp + NLMSG_HDRLEN, 4);
        CHECK(e == 0, "nft batch ack %zu error %d", i, -e);
    }
}

static void send_setelem_dump(int nf, const char *table, const char *set, uint32_t seq)
{
    struct nlbuf q;
    nft_msg_init(&q, NFT_MSG_GETSETELEM, NLM_F_DUMP, seq, NFPROTO_IPV4);
    nl_attr_str(&q, NFTA_SET_ELEM_LIST_TABLE, table);
    nl_attr_str(&q, NFTA_SET_ELEM_LIST_SET, set);
    nl_finish(&q);
    CHECK(send(nf, q.data, q.len, 0) == (ssize_t)q.len, "send getsetelem");
}

static void verify_setelem_dump(int nf, size_t bufsz, int use_peek_probe)
{
    send_setelem_dump(nf, "t", "big", 100);
    uint8_t seen[NUM_SET_ELEMS] = {0};
    int elem_msgs = 0;
    int empty_tail = 0;
    int done = 0;

    while (!done) {
        size_t rsz = bufsz;
        if (use_peek_probe) {
            ssize_t probe = recv(nf, NULL, 0, MSG_PEEK | MSG_TRUNC);
            CHECK(probe >= (ssize_t)NLMSG_HDRLEN, "nft peek probe %zd", probe);
            rsz = (size_t)probe;
        }
        uint8_t *buf = malloc(rsz);
        CHECK(buf != NULL, "malloc");
        int mflags = 0;
        ssize_t n = nl_recvmsg(nf, buf, rsz, 0, &mflags);
        CHECK(n >= (ssize_t)NLMSG_HDRLEN && (size_t)n <= rsz, "nft recv %zd (rsz %zu)", n, rsz);
        CHECK((mflags & MSG_TRUNC) == 0, "unexpected MSG_TRUNC on nft set dump rsz=%zu", rsz);
        if (!use_peek_probe)
            CHECK((size_t)n <= 4096, "setelem chunk %zd exceeded page size", n);

        size_t off = 0;
        while (off + NLMSG_HDRLEN <= (size_t)n) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof h);
            CHECK(h.nlmsg_len >= NLMSG_HDRLEN && off + h.nlmsg_len <= (size_t)n, "bad nlmsg_len");
            CHECK((h.nlmsg_flags & NLM_F_MULTI) != 0, "missing NLM_F_MULTI");
            if (h.nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            CHECK(h.nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM),
                  "unexpected nft type %#x", h.nlmsg_type);
            const uint8_t *attrs = buf + off + NLMSG_HDRLEN + 4;
            size_t attr_len = h.nlmsg_len - NLMSG_HDRLEN - 4;
            size_t elen = 0;
            const uint8_t *elist = find_attr(attrs, attr_len, NFTA_SET_ELEM_LIST_ELEMENTS, &elen);
            CHECK(elist != NULL, "missing NFTA_SET_ELEM_LIST_ELEMENTS");
            if (elen == 0) {
                empty_tail++;
            } else {
                elem_msgs++;
                size_t eoff = 0;
                while (eoff + NLA_HDRLEN <= elen) {
                    struct nlattr ea;
                    memcpy(&ea, elist + eoff, sizeof ea);
                    CHECK(ea.nla_len >= NLA_HDRLEN && eoff + ea.nla_len <= elen, "bad list elem");
                    size_t klen = 0;
                    const uint8_t *kattr = find_attr(elist + eoff + NLA_HDRLEN,
                                                     ea.nla_len - NLA_HDRLEN, NFTA_SET_ELEM_KEY,
                                                     &klen);
                    CHECK(kattr != NULL, "missing SET_ELEM_KEY");
                    size_t vlen = 0;
                    const uint8_t *val = find_attr(kattr, klen, NFTA_DATA_VALUE, &vlen);
                    CHECK(val != NULL && vlen == 4 && val[0] == 10 && val[1] == 20, "bad key val");
                    int idx = ((int)val[2] << 8) | (int)val[3];
                    CHECK(idx >= 0 && idx < NUM_SET_ELEMS, "key idx out of range %d", idx);
                    seen[idx]++;
                    eoff += (ea.nla_len + 3) & ~3u;
                }
            }
            off += (h.nlmsg_len + 3) & ~3u;
        }
        free(buf);
    }

    CHECK(elem_msgs >= 3, "expected >=3 chunked NEWSETELEM msgs (bufsz=%zu probe=%d), got %d",
          bufsz, use_peek_probe, elem_msgs);
    CHECK(empty_tail == 1, "expected 1 empty tail NEWSETELEM, got %d", empty_tail);
    for (int i = 0; i < NUM_SET_ELEMS; i++)
        CHECK(seen[i] == 1, "elem %d seen %u (bufsz=%zu probe=%d)", i, seen[i], bufsz,
              use_peek_probe);
}

static void test_nft_large_set_child(void)
{
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare net");
    int nf = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    CHECK(nf >= 0, "nf socket");

    struct nlbuf setup[3];
    nft_msg_init(&setup[0], NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, 1, NFPROTO_IPV4);
    nl_attr_str(&setup[0], NFTA_TABLE_NAME, "t");

    nft_msg_init(&setup[1], NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK, 2, NFPROTO_IPV4);
    nl_attr_str(&setup[1], NFTA_SET_TABLE, "t");
    nl_attr_str(&setup[1], NFTA_SET_NAME, "big");
    nl_attr_be32(&setup[1], NFTA_SET_KEY_LEN, 4);

    nft_msg_init(&setup[2], NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK, 3, NFPROTO_IPV4);
    nl_attr_str(&setup[2], NFTA_SET_TABLE, "t");
    nl_attr_str(&setup[2], NFTA_SET_NAME, "empty");
    nl_attr_be32(&setup[2], NFTA_SET_KEY_LEN, 4);

    nft_batch_send(nf, setup, 3, 3);

    /* Add 600 distinct IPv4 elements in batches of 50 */
    for (int base = 0; base < NUM_SET_ELEMS; base += 50) {
        struct nlbuf add;
        nft_msg_init(&add, NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK, 10 + (uint32_t)base,
                     NFPROTO_IPV4);
        nl_attr_str(&add, NFTA_SET_ELEM_LIST_TABLE, "t");
        nl_attr_str(&add, NFTA_SET_ELEM_LIST_SET, "big");
        size_t els = nl_attr_start(&add, NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED);
        for (int i = base; i < base + 50; i++) {
            size_t el = nl_attr_start(&add, NFTA_LIST_ELEM | NLA_F_NESTED);
            size_t kv = nl_attr_start(&add, NFTA_SET_ELEM_KEY | NLA_F_NESTED);
            uint8_t ip[4] = {10, 20, (uint8_t)(i >> 8), (uint8_t)(i & 0xff)};
            nl_attr(&add, NFTA_DATA_VALUE, ip, 4);
            nl_attr_end(&add, kv);
            nl_attr_end(&add, el);
        }
        nl_attr_end(&add, els);
        nft_batch_send(nf, &add, 1, 1);
    }

    verify_setelem_dump(nf, 512, 0);
    verify_setelem_dump(nf, 1024, 0);
    verify_setelem_dump(nf, 16384, 0);
    verify_setelem_dump(nf, 0, 1);

    /* Empty set with a tiny 56B buffer splits empty NEWSETELEM and NLMSG_DONE cleanly */
    send_setelem_dump(nf, "t", "empty", 200);
    uint8_t tiny[56];
    int mflags = 0;
    ssize_t n1 = nl_recvmsg(nf, tiny, sizeof tiny, 0, &mflags);
    CHECK(n1 >= (ssize_t)NLMSG_HDRLEN && (mflags & MSG_TRUNC) == 0, "empty set msg1 %zd", n1);
    struct nlmsghdr h1;
    memcpy(&h1, tiny, sizeof h1);
    CHECK(h1.nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM), "empty msg1 type");
    ssize_t n2 = nl_recvmsg(nf, tiny, sizeof tiny, 0, &mflags);
    CHECK(n2 >= (ssize_t)NLMSG_HDRLEN && (mflags & MSG_TRUNC) == 0, "empty set done %zd", n2);
    struct nlmsghdr h2;
    memcpy(&h2, tiny, sizeof h2);
    CHECK(h2.nlmsg_type == NLMSG_DONE, "empty msg2 DONE got %u", h2.nlmsg_type);

    close(nf);
}

int main(void)
{
    CHECK(run_in_child(test_rtnetlink_dumps_child) == 0, "rtnetlink dumps");
    ok("rtnetlink_resumable_dumps_peek_trunc");
    CHECK(run_in_child(test_nft_large_set_child) == 0, "nft large set dump");
    ok("nft_chunked_setelem_dump");
    printf("all ok\n");
    return 0;
}
