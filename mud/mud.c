#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mud.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <sodium.h>
#include "aegis256/aegis256.h"

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if defined __linux__
#define MUD_V4V6 1
#else
#define MUD_V4V6 0
#endif

#if defined __APPLE__
#include <mach/mach_time.h>
#endif

#if defined IP_PKTINFO
#define MUD_PKTINFO IP_PKTINFO
#define MUD_PKTINFO_SRC(X) &((struct in_pktinfo *)(X))->ipi_addr
#define MUD_PKTINFO_DST(X) &((struct in_pktinfo *)(X))->ipi_spec_dst
#define MUD_PKTINFO_IFINDEX(X) (((struct in_pktinfo *)(X))->ipi_ifindex)
#define MUD_PKTINFO_SIZE sizeof(struct in_pktinfo)
#elif defined IP_RECVDSTADDR
#define MUD_PKTINFO IP_RECVDSTADDR
#define MUD_PKTINFO_SRC(X) (X)
#define MUD_PKTINFO_DST(X) (X)
#define MUD_PKTINFO_IFINDEX(X) (0U)
#define MUD_PKTINFO_SIZE sizeof(struct in_addr)
#endif

#if defined IP_MTU_DISCOVER
#define MUD_DFRAG IP_MTU_DISCOVER
#define MUD_DFRAG_OPT IP_PMTUDISC_PROBE
#elif defined IP_DONTFRAG
#define MUD_DFRAG IP_DONTFRAG
#define MUD_DFRAG_OPT 1
#endif

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000 * MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60 * MUD_ONE_SEC)

#define MUD_TIME_SIZE    (6U)
#define MUD_TIME_BITS    (MUD_TIME_SIZE * 8U)
#define MUD_TIME_MASK(X) ((X) & ((UINT64_C(1) << MUD_TIME_BITS) - 2))

#define MUD_KEY_SIZE (32U)
#define MUD_MAC_SIZE (16U)

#define MUD_MSG(X)       ((X) & UINT64_C(1))
#define MUD_MSG_MARK(X)  ((X) | UINT64_C(1))
#define MUD_MSG_SENT_MAX (5)

#define MUD_PKT_MIN_SIZE (MUD_TIME_SIZE + MUD_MAC_SIZE)
#define MUD_PKT_MAX_SIZE MUD_MTU_HARD_MAX

/* No discovery/negotiation: every path uses a single fixed wire size,
 * either configured explicitly (struct mud_path_conf.mtu) or this default
 * -- a conservative size safe under standard PPPoE overhead and typical
 * VPN-in-VPN encapsulation without needing to probe for it. */
#define MUD_MTU_DEFAULT (1400U)

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + \
                       CMSG_SPACE(sizeof(struct in6_pktinfo)))

#define MUD_STORE_MSG(D,S) mud_store((D),(S),sizeof(D))
#define MUD_LOAD_MSG(S)    mud_load((S),sizeof(S))

struct mud_crypto_opt {
    unsigned char *dst;
    const unsigned char *src;
    size_t size;
};

struct mud_crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
    } encrypt, decrypt;
    int aes;
};

struct mud_addr {
    union {
        unsigned char v6[16];
        struct {
            unsigned char zero[10];
            unsigned char ff[2];
            unsigned char v4[4];
        };
    };
    unsigned char port[2];
};

struct mud_msg {
    unsigned char sent_time[MUD_TIME_SIZE];
    unsigned char aes;
    unsigned char pkey[MUD_PUBKEY_SIZE];
    struct {
        unsigned char bytes[sizeof(uint64_t)];
        unsigned char total[sizeof(uint64_t)];
    } tx, rx, fw;
    unsigned char max_rate[sizeof(uint64_t)];
    unsigned char beat[MUD_TIME_SIZE];
    unsigned char mtu[2];
    unsigned char pref;
    unsigned char loss;
    unsigned char fixed_rate;
    unsigned char loss_limit;
    struct mud_addr addr;
};

struct mud_keyx {
    uint64_t time;
    unsigned char secret[crypto_scalarmult_SCALARBYTES];
    unsigned char remote[MUD_PUBKEY_SIZE];
    unsigned char local[MUD_PUBKEY_SIZE];
    struct mud_crypto_key private, last, next, current;
    int use_next;
    int aes;
};

#define MUD_WORKERS_MAX (8U)

/* Bounds the resequencing buffer used when mud_conf.reorder_window is
 * enabled (see mud_reorder_insert()/mud_reorder_flush() below). Fixed,
 * always allocated as part of struct mud -- same no-realloc rationale as
 * mud->paths/mud->sock (see struct mud's own comment): a pointer a worker
 * thread is using can never be invalidated by another thread resizing it.
 * Costs nothing beyond the allocation when reorder_window is 0 (the
 * default), since both functions below short-circuit immediately in that
 * case. A decrypted packet larger than MUD_REORDER_SLOT_SIZE bypasses
 * buffering entirely (delivered immediately, unreordered, same as with the
 * feature off) rather than being rejected -- correctness never depends on
 * this buffer, only the reordering benefit does.
 *
 * MUD_REORDER_MAX bounds how many packets can be held across the whole
 * tunnel at once; how much of a reorder_window that actually covers
 * depends on throughput and packet size -- capacity in packets divided by
 * packets/sec gives the covered duration. At 600Mbit combined and
 * ~1450-byte packets that's ~51,700 pps, so 512 slots (the original sizing
 * here) only covered ~10ms -- fine for a low-RTT link, not enough for a
 * long-haul path: a peer several hundred km away routinely needs a
 * 40-60ms window (see "Picking a window size" in glorytun-notes.html),
 * which at the same throughput needs on the order of 2,000-3,000 slots.
 * Past capacity, mud_reorder_insert() just bypasses buffering for the
 * excess (degrades to unbuffered delivery for those packets, never drops
 * or blocks), so an undersized buffer doesn't break anything -- it just
 * quietly stops helping once the real window needed exceeds what's
 * configured here, which is exactly what happened testing against a
 * ~200ms-RTT path with this constant still at 512. Raised to 4096 (~8.5MB
 * total, trivial on a VPS and still reasonable on any router capable of
 * running this workload at all) for headroom past that case; raise
 * further for a still-longer path or higher throughput. */
#define MUD_REORDER_MAX         (4096U)
#define MUD_REORDER_SLOT_SIZE   (2048U)
#define MUD_REORDER_FLUSH_BATCH (32U)

struct mud_reorder_slot {
    unsigned char data[MUD_REORDER_SLOT_SIZE];
    size_t size;
    uint64_t deadline; /* this side's mud_now() at/after which this packet
                        * is safe to release -- computed once at insert
                        * time as (arrival time + this packet's path's own
                        * reorder_hold), entirely in this side's own clock
                        * domain (never compares against the peer's clock
                        * at all). See mud_reorder_insert(). */
};

/* Tunnel-wide (not per-path, not per-worker-thread): reordering happens
 * because packets from one flow cross different physical paths with
 * different latencies, so sorting has to happen after every path funnels
 * back into the single TUN device, not before. See
 * mud_reorder_insert()/mud_reorder_flush() and mud_conf.reorder_window. */
struct mud_reorder {
    struct mud_reorder_slot slot[MUD_REORDER_MAX];
    unsigned count;
    pthread_mutex_t lock;       /* guards slot[]/count -- plain memory
                                 * access only, never held across a
                                 * syscall, same discipline as state_lock */
    pthread_mutex_t flush_lock; /* serializes the deliver-to-TUN phase
                                 * across worker threads -- see
                                 * mud_reorder_flush() */
};

struct mud {
    /* Fixed-size, allocated as part of this struct rather than grown with
     * realloc() -- so a pointer/index a worker thread is using can never be
     * invalidated by another thread resizing the array underneath it. Both
     * are small enough (sock: 256 ints = 1KB; paths: MUD_PATH_MAX structs,
     * see the size note at struct mud_path's own definition) that
     * pre-allocating the whole thing up front costs nothing that matters.
     * Contents (and sock_count/capacity below) are guarded by state_lock;
     * see mud_worker_loop() for the locking protocol worker threads use. */
    int sock[MUD_SOCK_MAX];
    unsigned int sock_count;
    int sock_v4, sock_v6;
    sa_family_t sock_family;
    struct mud_conf conf;
    struct mud_path paths[MUD_PATH_MAX];
    unsigned pref;
    unsigned capacity;
    struct mud_keyx keyx;
    uint64_t last_recv_time;
    size_t mtu;
    struct mud_errors err;
    uint64_t rate;
    uint64_t window;
    uint64_t window_time;
    uint64_t base_time;
    /* Guards everything above from sock_count down through window_time --
     * path/socket-pool state, rate/window accounting, error counters. Held
     * only around plain memory access (array scans, struct field
     * read/writes), never across a syscall or the AEAD encrypt/decrypt call
     * itself -- see mud_worker_loop(). mud->keyx is guarded separately by
     * keyx_lock below, not by this lock; the one place both are held at
     * once (mud_recv_msg(), via mud_worker_loop()'s RX path) always takes
     * state_lock first, keyx_lock second -- never the other order -- so the
     * two can never deadlock against each other. */
    pthread_mutex_t state_lock;
    pthread_mutex_t keyx_lock;
    struct mud_reorder reorder;
#if defined __APPLE__
    mach_timebase_info_data_t mtid;
#endif
};

static inline int
mud_encrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return aegis256_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            npub,
            k->encrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            NULL,
            npub,
            k->encrypt.key
        );
    }
}

static inline int
mud_decrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return aegis256_decrypt(
            c->dst,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_decrypt(
            c->dst,
            NULL,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    }
}

static inline void
mud_store(unsigned char *dst, uint64_t src, size_t size)
{
    dst[0] = (unsigned char)(src);
    dst[1] = (unsigned char)(src >> 8);
    if (size <= 2) return;
    dst[2] = (unsigned char)(src >> 16);
    dst[3] = (unsigned char)(src >> 24);
    dst[4] = (unsigned char)(src >> 32);
    dst[5] = (unsigned char)(src >> 40);
    if (size <= 6) return;
    dst[6] = (unsigned char)(src >> 48);
    dst[7] = (unsigned char)(src >> 56);
}

static inline uint64_t
mud_load(const unsigned char *src, size_t size)
{
    uint64_t ret = 0;
    ret = src[0];
    ret |= ((uint64_t)src[1]) << 8;
    if (size <= 2) return ret;
    ret |= ((uint64_t)src[2]) << 16;
    ret |= ((uint64_t)src[3]) << 24;
    ret |= ((uint64_t)src[4]) << 32;
    ret |= ((uint64_t)src[5]) << 40;
    if (size <= 6) return ret;
    ret |= ((uint64_t)src[6]) << 48;
    ret |= ((uint64_t)src[7]) << 56;
    return ret;
}

static inline uint64_t
mud_time(void)
{
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_usec);
#endif
}

static inline uint64_t
mud_now(struct mud *mud)
{
#if defined __APPLE__
    return MUD_TIME_MASK(mud->base_time
            + (mach_absolute_time() * mud->mtid.numer / mud->mtid.denom)
            / 1000ULL);
#elif defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return MUD_TIME_MASK(mud->base_time
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    return mud_time();
#endif
}

static inline uint64_t
mud_abs_diff(uint64_t a, uint64_t b)
{
    return (a >= b) ? a - b : b - a;
}

static inline int
mud_timeout(uint64_t now, uint64_t last, uint64_t timeout)
{
    return (!last) || (MUD_TIME_MASK(now - last) >= timeout);
}

static inline void
mud_unmapv4(union mud_sockaddr *addr)
{
    if (addr->sa.sa_family != AF_INET6)
        return;

    if (!IN6_IS_ADDR_V4MAPPED(&addr->sin6.sin6_addr))
        return;

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = addr->sin6.sin6_port,
    };
    memcpy(&sin.sin_addr.s_addr,
           &addr->sin6.sin6_addr.s6_addr[12],
           sizeof(sin.sin_addr.s_addr));

    addr->sin = sin;
}

/* Caller must already hold state_lock. */
static struct mud_path *
mud_select_path(struct mud *mud, uint16_t cursor)
{
    uint64_t k = (cursor * mud->rate) >> 16;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->status != MUD_RUNNING)
            continue;

        if (k < path->select_weight)
            return path;

        k -= path->select_weight;
    }
    return NULL;
}

/* No discovery: the wire size a path sends at is whatever was configured
 * (struct mud_path_conf.mtu), or MUD_MTU_DEFAULT if never configured.
 * MUD_MTU_HARD_MAX is enforced here purely as a last-resort backstop --
 * the CLI is the layer that actually rejects an out-of-range request, this
 * clamp exists only so a value reaching this point some other way can
 * never overrun the fixed packet buffers sized to MUD_MTU_HARD_MAX. */
static void
mud_mtu_apply(struct mud_path *path)
{
    uint64_t mtu = path->conf.mtu ? path->conf.mtu : MUD_MTU_DEFAULT;

    if (mtu > MUD_MTU_HARD_MAX)
        mtu = MUD_MTU_HARD_MAX;

    path->mtu = mtu;
}

/* Builds and sends one wire packet to an explicit destination -- no path
 * lookup or path mutation, and deliberately takes plain parameters instead
 * of a `struct mud_path *` so it can be called with a snapshot copied out
 * under state_lock and then run fully unlocked (see mud_worker_loop()'s TX
 * half) -- sendmsg() itself must never happen while holding that lock, or
 * every worker thread's sends would serialize on it. `sock` only needs to
 * be a valid index that was already open at some point in the past (never
 * re-pointed once opened, only ever grown -- see mud_set_sock_count()), so
 * reading mud->sock[sock] here needs no lock either. */
static ssize_t
mud_sendmsg_to(struct mud *mud, unsigned char sock,
              union mud_sockaddr *local, unsigned int local_ifindex,
              union mud_sockaddr *remote, void *data, size_t size, int flags)
{
    unsigned char ctrl[MUD_CTRL_SIZE];
    memset(ctrl, 0, sizeof(ctrl));

    struct msghdr msg = {
        .msg_iov = &(struct iovec) {
            .iov_base = data,
            .iov_len = size,
        },
        .msg_iovlen = 1,
        .msg_control = ctrl,
    };
    if (remote->sa.sa_family == AF_INET) {
        msg.msg_name = &remote->sin;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = MUD_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);
        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &local->sin.sin_addr,
               sizeof(struct in_addr));
#if defined IP_PKTINFO
        MUD_PKTINFO_IFINDEX(CMSG_DATA(cmsg)) = local_ifindex;
#endif
    } else if (remote->sa.sa_family == AF_INET6) {
        msg.msg_name = &remote->sin6;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &local->sin6.sin6_addr,
               sizeof(struct in6_addr));
        ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex = local_ifindex;
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return sendmsg(mud->sock[sock], &msg, flags);
}

/* Caller must already hold state_lock -- this both reads path->conf and
 * mutates path->tx/mud->window, and (unlike mud_worker_loop()'s TX half)
 * doesn't try to avoid holding the lock across the sendmsg() call itself.
 * That's fine here: every caller of this particular function (mud_send(),
 * mud_send_msg() via mud_recv_msg()'s reply) is a low-frequency, one-off
 * send -- beat/keepalive replies, not the per-packet data path -- so
 * serializing worker threads against each other for the duration of one
 * occasional syscall costs nothing that matters. The hot per-packet TX path
 * in mud_worker_loop() calls mud_sendmsg_to() directly instead, precisely
 * to avoid paying that cost on every packet. */
static int
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              void *data, size_t size, int flags)
{
    if (!size || !path)
        return 0;

    ssize_t ret = mud_sendmsg_to(mud, path->conf.sock, &path->conf.local,
                                 path->conf.local_ifindex, &path->conf.remote,
                                 data, size, flags);

    if (ret == (ssize_t)size) {
        path->tx.total++;
        path->tx.bytes += size;
        path->tx.time = now;

        if (mud->window > size) {
            mud->window -= size;
        } else {
            mud->window = 0;
        }
    }
    /* A failed send (EMSGSIZE or otherwise) is simply not counted as sent
     * above -- there's no MTU to re-probe or correct; the wire size is a
     * fixed, operator-set value (see mud_mtu_apply()). */
    return (int)ret;
}

static int
mud_sso_int(int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static inline int
mud_cmp_addr(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                      sizeof(a->sin.sin_addr));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                      sizeof(a->sin6.sin6_addr));
    return 1;
}

static inline int
mud_cmp_port(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_port, &b->sin.sin_port,
                      sizeof(a->sin.sin_port));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_port, &b->sin6.sin6_port,
                      sizeof(a->sin6.sin6_port));
    return 1;
}

/* Two paths are sub-flows of the same physical link if they share local
 * identity (interface index, or local address for legacy/passive paths
 * where local_ifindex is always 0) and remote *address* -- deliberately not
 * remote port. One side of a sub-flow group varies by local port (distinct
 * mud->sock[] entries, same remote address:port); the other side -- the
 * passive peer, which never opens extra sockets -- instead sees the same
 * local address with N distinct remote ports, one per sub-flow it auto-
 * discovered. Comparing remote address only (never remote port) groups
 * correctly from either side without needing to know which one it is. */
static int
mud_path_same_group(struct mud_path *a, struct mud_path *b)
{
    if (a->conf.local_ifindex || b->conf.local_ifindex) {
        if (a->conf.local_ifindex != b->conf.local_ifindex)
            return 0;
    } else if (mud_cmp_addr(&a->conf.local, &b->conf.local)) {
        return 0;
    }
    return !mud_cmp_addr(&a->conf.remote, &b->conf.remote);
}

int
mud_get_paths(struct mud *mud, struct mud_paths *paths,
              union mud_sockaddr *local, union mud_sockaddr *remote)
{
    if (!paths) {
        errno = EINVAL;
        return -1;
    }
    unsigned count = 0;

    pthread_mutex_lock(&mud->state_lock);

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (local && local->sa.sa_family &&
            mud_cmp_addr(local, &path->conf.local))
            continue;

        if (remote && remote->sa.sa_family &&
            (mud_cmp_addr(remote, &path->conf.remote) ||
             mud_cmp_port(remote, &path->conf.remote)))
            continue;

        if (path->conf.state != MUD_EMPTY)
            paths->path[count++] = *path;
    }
    pthread_mutex_unlock(&mud->state_lock);

    paths->count = count;
    return 0;
}

/* Caller must already hold state_lock -- searches (and, for state >
 * MUD_DOWN, creates) a path in mud->paths, which every worker thread and
 * the housekeeping thread can otherwise be touching at the same moment.
 * mud->paths/capacity are fixed-size (see struct mud), so unlike the
 * original version of this function, "no empty slot found" is a real
 * ENOMEM rather than a trigger to grow the array -- there is nothing left
 * to grow into MUD_PATH_MAX wasn't sized generously for nothing. */
static struct mud_path *
mud_get_path(struct mud *mud,
             union mud_sockaddr *local,
             union mud_sockaddr *remote,
             unsigned int local_ifindex,
             unsigned int sock,
             int allow_legacy,
             enum mud_state state)
{
    if (local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return NULL;
    }
    if (local_ifindex) {
        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            if (path->conf.state == MUD_EMPTY ||
                path->conf.local_ifindex != local_ifindex ||
                path->conf.sock != sock ||
                mud_cmp_addr(remote, &path->conf.remote) ||
                mud_cmp_port(remote, &path->conf.remote))
                continue;

            return path;
        }
    }
    if (!local_ifindex || allow_legacy) {
        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            if (path->conf.state == MUD_EMPTY ||
                path->conf.local_ifindex ||
                path->conf.sock != sock ||
                mud_cmp_addr(local, &path->conf.local) ||
                mud_cmp_addr(remote, &path->conf.remote) ||
                mud_cmp_port(remote, &path->conf.remote))
                continue;

            return path;
        }
    }
    if (state <= MUD_DOWN) {
        errno = ENOENT;
        return NULL;
    }
    struct mud_path *path = NULL;

    for (unsigned i = 0; i < mud->capacity; i++) {
        if (mud->paths[i].conf.state == MUD_EMPTY) {
            path = &mud->paths[i];
            break;
        }
    }
    if (!path) {
        errno = ENOMEM;
        return NULL;
    }
    memset(path, 0, sizeof(struct mud_path));

    path->conf.local      = *local;
    path->conf.remote     = *remote;
    path->conf.local_ifindex = state == MUD_PASSIVE ? 0 : local_ifindex;
    path->conf.sock        = sock;
    path->conf.state      = state;
    path->conf.beat       = 100 * MUD_ONE_MSEC;
    path->conf.fixed_rate = 1;
    path->conf.loss_limit = 255;
    path->status          = MUD_PROBING;
    path->idle            = mud_now(mud);

    return path;
}

int
mud_get_errors(struct mud *mud, struct mud_errors *err)
{
    if (!err) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&mud->state_lock);
    memcpy(err, &mud->err, sizeof(struct mud_errors));
    pthread_mutex_unlock(&mud->state_lock);
    return 0;
}

int
mud_set(struct mud *mud, struct mud_conf *conf)
{
    pthread_mutex_lock(&mud->state_lock);

    struct mud_conf c = mud->conf;

    if (conf->keepalive)      c.keepalive      = conf->keepalive;
    if (conf->timetolerance)  c.timetolerance  = conf->timetolerance;
    if (conf->kxtimeout)      c.kxtimeout      = conf->kxtimeout;
    if (conf->reorder_window) c.reorder_window = conf->reorder_window;

    mud->conf = c;
    pthread_mutex_unlock(&mud->state_lock);

    *conf = c;
    return 0;
}

size_t
mud_get_mtu(struct mud *mud)
{
    pthread_mutex_lock(&mud->state_lock);
    size_t mtu = mud->mtu;
    pthread_mutex_unlock(&mud->state_lock);

    if (!mtu)
        return 0;

    return mtu - MUD_PKT_MIN_SIZE;
}

static int
mud_setup_socket(int fd, int v4, int v6)
{
    if ((mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)) ||
        (v4 && mud_sso_int(fd, IPPROTO_IP, MUD_PKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, !v4)))
        return -1;

#if defined MUD_DFRAG
    if (v4)
        mud_sso_int(fd, IPPROTO_IP, MUD_DFRAG, MUD_DFRAG_OPT);
#endif
    return 0;
}

static void
mud_hash_key(unsigned char *dst, unsigned char *key, unsigned char *secret,
             unsigned char *pk0, unsigned char *pk1)
{
    crypto_generichash_state state;

    crypto_generichash_init(&state, key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pk0, MUD_PUBKEY_SIZE);
    crypto_generichash_update(&state, pk1, MUD_PUBKEY_SIZE);
    crypto_generichash_final(&state, dst, MUD_KEY_SIZE);

    sodium_memzero(&state, sizeof(state));
}

static int
mud_keyx(struct mud_keyx *kx, unsigned char *remote, int aes)
{
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, kx->secret, remote))
        return 1;

    mud_hash_key(kx->next.encrypt.key,
                 kx->private.encrypt.key,
                 secret, remote, kx->local);

    mud_hash_key(kx->next.decrypt.key,
                 kx->private.encrypt.key,
                 secret, kx->local, remote);

    sodium_memzero(secret, sizeof(secret));

    memcpy(kx->remote, remote, MUD_PUBKEY_SIZE);
    kx->next.aes = kx->aes && aes;

    return 0;
}

/* Caller (mud_update()) already holds state_lock; this additionally takes
 * keyx_lock for the whole body below, since nearly everything here is a
 * mud->keyx write and this only runs roughly once per kxtimeout (an hour,
 * by default) -- not remotely hot enough for lock granularity to matter. */
static int
mud_keyx_init(struct mud *mud, uint64_t now)
{
    struct mud_keyx *kx = &mud->keyx;

    if (!mud_timeout(now, kx->time, mud->conf.kxtimeout))
        return 1;

    pthread_mutex_lock(&mud->keyx_lock);

    static const unsigned char test[crypto_scalarmult_BYTES] = {
        0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e,
        0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf,
        0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49
    };
    unsigned char tmp[crypto_scalarmult_BYTES];

    do {
        randombytes_buf(kx->secret, sizeof(kx->secret));
        crypto_scalarmult_base(kx->local, kx->secret);
    } while (crypto_scalarmult(tmp, test, kx->local));

    sodium_memzero(tmp, sizeof(tmp));
    kx->time = now;

    /* Proactively derive what the shared key *will* become once the peer
     * notices this rotation, using its already-known public key -- do not
     * switch to it yet (use_next is untouched, so we keep encrypting with
     * the still-valid current key, decryptable by a peer that hasn't
     * rotated either). By ECDH's commutative property this produces the
     * exact same value the peer will independently derive the moment it
     * sees our new local pubkey (ECDH(my_new_secret, peer_pub) ==
     * ECDH(peer_secret, my_new_pub)), so it's just sitting in kx->next,
     * ready for the existing decrypt fallback chain (current -> next ->
     * last -> private) to find and promote automatically the instant the
     * peer's reply actually arrives encrypted with it.
     *
     * Without this, only the peer derives a matching key on rotation --
     * we never do, since mud_keyx() is otherwise only called reactively
     * from mud_recv_msg() when *their* advertised pubkey changes, and
     * theirs hasn't. We'd be stuck unable to decrypt their replies until
     * our own next independent kxtimeout happened to catch up, possibly
     * much later since the two sides' timers aren't synchronized. This
     * was confirmed live: the tunnel reliably broke exactly at kxtimeout
     * (1h default, reproduced at 2m), one direction only.
     *
     * A failure here (e.g. kx->remote is still all-zero because no peer
     * has ever been seen yet) is harmless and intentionally ignored --
     * mud_keyx() returns before touching any state in that case, and the
     * reactive path in mud_recv_msg() still covers the initial handshake
     * either way. */
    mud_keyx(kx, kx->remote, kx->current.aes);
    pthread_mutex_unlock(&mud->keyx_lock);

    return 0;
}

struct mud *
mud_create(union mud_sockaddr *addr, unsigned char *key, int *aes)
{
    if (!addr || !key || !aes)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    switch (addr->sa.sa_family) {
    case AF_INET:
        addrlen = sizeof(struct sockaddr_in);
        v4 = 1;
        v6 = 0;
        break;
    case AF_INET6:
        addrlen = sizeof(struct sockaddr_in6);
        v4 = MUD_V4V6;
        v6 = 1;
        break;
    default:
        return NULL;
    }
    if (sodium_init() == -1)
        return NULL;

    struct mud *mud = sodium_malloc(sizeof(struct mud));

    if (!mud)
        return NULL;

    memset(mud, 0, sizeof(struct mud));

    if (pthread_mutex_init(&mud->state_lock, NULL)) {
        sodium_free(mud);
        return NULL;
    }
    if (pthread_mutex_init(&mud->keyx_lock, NULL)) {
        pthread_mutex_destroy(&mud->state_lock);
        sodium_free(mud);
        return NULL;
    }
    if (pthread_mutex_init(&mud->reorder.lock, NULL)) {
        pthread_mutex_destroy(&mud->keyx_lock);
        pthread_mutex_destroy(&mud->state_lock);
        sodium_free(mud);
        return NULL;
    }
    if (pthread_mutex_init(&mud->reorder.flush_lock, NULL)) {
        pthread_mutex_destroy(&mud->reorder.lock);
        pthread_mutex_destroy(&mud->keyx_lock);
        pthread_mutex_destroy(&mud->state_lock);
        sodium_free(mud);
        return NULL;
    }
    mud->capacity = MUD_PATH_MAX;

    int fd0 = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if ((fd0 == -1) ||
        (mud_setup_socket(fd0, v4, v6)) ||
        (bind(fd0, &addr->sa, addrlen)) ||
        (getsockname(fd0, &addr->sa, &addrlen))) {
        if (fd0 != -1)
            close(fd0);
        mud_delete(mud);
        return NULL;
    }
    mud->sock[0] = fd0;
    mud->sock_count = 1;
    mud->sock_v4 = v4;
    mud->sock_v6 = v6;
    mud->sock_family = addr->sa.sa_family;

    mud->conf.keepalive     = 25 * MUD_ONE_SEC;
    mud->conf.timetolerance = 10 * MUD_ONE_MIN;
    mud->conf.kxtimeout     = 60 * MUD_ONE_MIN;

#if defined __APPLE__
    mach_timebase_info(&mud->mtid);
#endif

    uint64_t now = mud_now(mud);
    uint64_t base_time = mud_time();

    if (base_time > now)
        mud->base_time = base_time - now;

    memcpy(mud->keyx.private.encrypt.key, key, MUD_KEY_SIZE);
    memcpy(mud->keyx.private.decrypt.key, key, MUD_KEY_SIZE);
    sodium_memzero(key, MUD_KEY_SIZE);

    mud->keyx.current = mud->keyx.private;
    mud->keyx.next = mud->keyx.private;
    mud->keyx.last = mud->keyx.private;

    if (*aes && !aegis256_is_available())
        *aes = 0;

    mud->keyx.aes = *aes;

    return mud;
}

int
mud_get_fd(struct mud *mud, unsigned int sock)
{
    if (!mud)
        return -1;

    pthread_mutex_lock(&mud->state_lock);
    int fd = (sock < mud->sock_count) ? mud->sock[sock] : -1;
    pthread_mutex_unlock(&mud->state_lock);

    return fd;
}

unsigned int
mud_get_sock_count(struct mud *mud)
{
    if (!mud)
        return 0;

    pthread_mutex_lock(&mud->state_lock);
    unsigned int count = mud->sock_count;
    pthread_mutex_unlock(&mud->state_lock);

    return count;
}

int
mud_set_sock_count(struct mud *mud, unsigned int count)
{
    if (!mud || count > MUD_SOCK_MAX) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&mud->state_lock);

    if (count <= mud->sock_count) {
        pthread_mutex_unlock(&mud->state_lock);
        return 0;
    }
    union mud_sockaddr addr = {0};
    addr.sa.sa_family = mud->sock_family;
    socklen_t addrlen = (mud->sock_family == AF_INET)
                       ? sizeof(struct sockaddr_in)
                       : sizeof(struct sockaddr_in6);
    int ret = 0;

    while (mud->sock_count < count) {
        unsigned int i = mud->sock_count;
        int fd = socket(mud->sock_family, SOCK_DGRAM, IPPROTO_UDP);

        if ((fd == -1) ||
            (mud_setup_socket(fd, mud->sock_v4, mud->sock_v6)) ||
            (bind(fd, &addr.sa, addrlen))) {
            if (fd != -1)
                close(fd);
            ret = -1;
            break;
        }
        mud->sock[i] = fd;
        mud->sock_count++;
    }
    pthread_mutex_unlock(&mud->state_lock);
    return ret;
}

void
mud_delete(struct mud *mud)
{
    if (!mud)
        return;

    for (unsigned int i = 0; i < mud->sock_count; i++) {
        if (mud->sock[i] >= 0)
            close(mud->sock[i]);
    }
    pthread_mutex_destroy(&mud->reorder.flush_lock);
    pthread_mutex_destroy(&mud->reorder.lock);
    pthread_mutex_destroy(&mud->keyx_lock);
    pthread_mutex_destroy(&mud->state_lock);

    sodium_free(mud);
}

static size_t
mud_encrypt(struct mud *mud, uint64_t now,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    mud_store(dst, now, MUD_TIME_SIZE);

    /* mud->keyx.{current,next} can be replaced at any moment by another
     * thread's mud_recv_msg() (a real key rotation) -- worker threads no
     * longer run under a shared barrier that guarantees writers and
     * readers never overlap (see mud_worker_loop()), so a plain read here
     * would race. Copy the small, fixed-size key struct under the lock,
     * then do the actual AEAD work against the local copy, fully unlocked
     * -- keeps every thread's encrypt calls running in parallel regardless
     * of how many are in flight, same as before this was a concern. */
    pthread_mutex_lock(&mud->keyx_lock);
    struct mud_crypto_key key = mud->keyx.use_next ? mud->keyx.next
                                                    : mud->keyx.current;
    pthread_mutex_unlock(&mud->keyx_lock);

    mud_encrypt_opt(&key, &opt);
    return size;
}

static size_t
mud_decrypt(struct mud *mud,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    /* Same reasoning as mud_encrypt(): snapshot the two keys that might be
     * rotating (current/next) under the lock, then try them against the
     * local copies unlocked -- multiple worker threads decrypting
     * concurrently, with or without a rotation happening at the same
     * moment, never touch shared state during the actual AEAD call. */
    pthread_mutex_lock(&mud->keyx_lock);
    struct mud_crypto_key k_current = mud->keyx.current;
    struct mud_crypto_key k_next = mud->keyx.next;
    pthread_mutex_unlock(&mud->keyx_lock);

    if (mud_decrypt_opt(&k_current, &opt)) {
        if (!mud_decrypt_opt(&k_next, &opt)) {
            /* This is the one place decrypt writes shared state instead of
             * only reading it -- two threads can both land here around the
             * same real rotation. Re-check against the live mud->keyx.next
             * before promoting: if it no longer matches the snapshot we
             * just decrypted with, another thread (or a newer rotation)
             * already handled it, so skip rather than promote stale state
             * on top of something newer. */
            pthread_mutex_lock(&mud->keyx_lock);
            if (!memcmp(&mud->keyx.next, &k_next, sizeof(k_next))) {
                mud->keyx.last = mud->keyx.current;
                mud->keyx.current = mud->keyx.next;
                mud->keyx.use_next = 0;
            }
            pthread_mutex_unlock(&mud->keyx_lock);
        } else {
            pthread_mutex_lock(&mud->keyx_lock);
            struct mud_crypto_key k_last = mud->keyx.last;
            struct mud_crypto_key k_private = mud->keyx.private;
            pthread_mutex_unlock(&mud->keyx_lock);

            if (mud_decrypt_opt(&k_last, &opt) &&
                mud_decrypt_opt(&k_private, &opt))
                return 0;
        }
    }
    return size;
}

static int
mud_localaddr(union mud_sockaddr *addr, unsigned int *ifindex,
              struct msghdr *msg)
{
    *ifindex = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == MUD_PKTINFO)) {
            addr->sa.sa_family = AF_INET;
            memcpy(&addr->sin.sin_addr,
                   MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
                   sizeof(struct in_addr));
            *ifindex = MUD_PKTINFO_IFINDEX(CMSG_DATA(cmsg));
            return 0;
        }
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            addr->sa.sa_family = AF_INET6;
            memcpy(&addr->sin6.sin6_addr,
                   &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                   sizeof(struct in6_addr));
            *ifindex = ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex;
            mud_unmapv4(addr);
            return 0;
        }
    }
    return 1;
}

static int
mud_addr_is_v6(struct mud_addr *addr)
{
    static const unsigned char v4mapped[] = {
        [10] = 255,
        [11] = 255,
    };
    return memcmp(addr->v6, v4mapped, sizeof(v4mapped));
}

static int
mud_addr_from_sock(struct mud_addr *addr, union mud_sockaddr *sock)
{
    if (sock->sa.sa_family == AF_INET) {
        memset(addr->zero, 0, sizeof(addr->zero));
        memset(addr->ff, 0xFF, sizeof(addr->ff));
        memcpy(addr->v4, &sock->sin.sin_addr, 4);
        memcpy(addr->port, &sock->sin.sin_port, 2);
    } else if (sock->sa.sa_family == AF_INET6) {
        memcpy(addr->v6, &sock->sin6.sin6_addr, 16);
        memcpy(addr->port, &sock->sin6.sin6_port, 2);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}

static void
mud_sock_from_addr(union mud_sockaddr *sock, struct mud_addr *addr)
{
    if (mud_addr_is_v6(addr)) {
        sock->sin6.sin6_family = AF_INET6;
        memcpy(&sock->sin6.sin6_addr, addr->v6, 16);
        memcpy(&sock->sin6.sin6_port, addr->port, 2);
    } else {
        sock->sin.sin_family = AF_INET;
        memcpy(&sock->sin.sin_addr, addr->v4, 4);
        memcpy(&sock->sin.sin_port, addr->port, 2);
    }
}

static int
mud_send_msg(struct mud *mud, struct mud_path *path, uint64_t now,
             uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total,
             size_t size)
{
    unsigned char dst[MUD_PKT_MAX_SIZE];
    unsigned char src[MUD_PKT_MAX_SIZE] = {0};
    struct mud_msg *msg = (struct mud_msg *)src;

    if (size < MUD_PKT_MIN_SIZE + sizeof(struct mud_msg))
        size = MUD_PKT_MIN_SIZE + sizeof(struct mud_msg);

    mud_store(dst, MUD_MSG_MARK(now), MUD_TIME_SIZE);
    MUD_STORE_MSG(msg->sent_time, sent_time);

    if (mud_addr_from_sock(&msg->addr, &path->conf.remote))
        return -1;

    /* keyx.local is written periodically by mud_keyx_init() (housekeeping);
     * everything else this function reads is path state, already safe
     * because every caller holds state_lock across this whole call. */
    pthread_mutex_lock(&mud->keyx_lock);
    memcpy(msg->pkey, mud->keyx.local, sizeof(mud->keyx.local));
    msg->aes = (unsigned char)mud->keyx.aes;
    pthread_mutex_unlock(&mud->keyx_lock);

    MUD_STORE_MSG(msg->mtu, path->mtu);

    MUD_STORE_MSG(msg->tx.bytes, path->tx.bytes);
    MUD_STORE_MSG(msg->rx.bytes, path->rx.bytes);
    MUD_STORE_MSG(msg->tx.total, path->tx.total);
    MUD_STORE_MSG(msg->rx.total, path->rx.total);
    MUD_STORE_MSG(msg->fw.bytes, fw_bytes);
    MUD_STORE_MSG(msg->fw.total, fw_total);
    MUD_STORE_MSG(msg->max_rate, path->conf.rx_max_rate);
    MUD_STORE_MSG(msg->beat, path->conf.beat);

    msg->loss = (unsigned char)path->tx.loss;
    msg->pref = path->conf.pref;
    msg->fixed_rate = path->conf.fixed_rate;
    msg->loss_limit = path->conf.loss_limit;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = size - MUD_PKT_MIN_SIZE,
    };
    mud_encrypt_opt(&mud->keyx.private, &opt);

    return mud_send_path(mud, path, now, dst, size,
                         sent_time ? MSG_CONFIRM : 0);
}

static size_t
mud_decrypt_msg(struct mud *mud,
                unsigned char *dst, size_t dst_size,
                const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(struct mud_msg) || size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    if (mud_decrypt_opt(&mud->keyx.private, &opt))
        return 0;

    return size;
}

/* Feed a freshly observed (sent_pkt, recv_pkt) delta into a per-direction
 * loss tracker. Buckets by 1-second wall-clock boundaries: whichever call
 * happens to land at/after a full second closes the in-progress bucket,
 * publishes it as *loss_live (this second's own ratio -- the real-time
 * status-page value), and folds it into a 60-slot ring so *loss reflects
 * the combined counts of the last (up to) 60 closed buckets -- a true
 * rolling 60-second window, not 60 independently-decaying estimates. This
 * is what loss_limit/MUD_LOSSY reads, so a single bad second cannot flip a
 * path to degraded/lossy on its own; sustained loss across the window can.
 *
 * `traffic_idle` means no real tunneled traffic (only keepalive chatter)
 * has moved on this path in the last second. A quiet link only exchanges
 * one tracking message every `keepalive` (25s default), so a 1-second
 * bucket built from that would almost always hold a single packet -- one
 * dropped keepalive then reads as 100% loss out of nowhere. Rather than
 * publish that noise, we don't touch loss/loss_live at all while idle and
 * discard whatever partial bucket was left over from just before things
 * went quiet, so the next active stretch starts from a clean sample. */
static void
mud_update_loss(struct mud_loss_track *track, uint64_t now, int traffic_idle,
                uint64_t *loss, uint64_t *loss_live,
                uint64_t sent_pkt, uint64_t recv_pkt)
{
    if (traffic_idle) {
        track->bucket_time = 0;
        track->bucket_sent = 0;
        track->bucket_recv = 0;
        return;
    }

    if (!track->bucket_time)
        track->bucket_time = now;

    track->bucket_sent += sent_pkt;
    track->bucket_recv += recv_pkt;

    if (MUD_TIME_MASK(now - track->bucket_time) < MUD_ONE_SEC)
        return;

    if (track->bucket_sent)
        *loss_live = (track->bucket_sent >= track->bucket_recv)
                   ? (track->bucket_sent - track->bucket_recv) * 255U
                        / track->bucket_sent
                   : 0;

    track->sum_sent -= track->sample_sent[track->next];
    track->sum_recv -= track->sample_recv[track->next];
    track->sample_sent[track->next] = track->bucket_sent;
    track->sample_recv[track->next] = track->bucket_recv;
    track->sum_sent += track->bucket_sent;
    track->sum_recv += track->bucket_recv;
    track->next = (track->next + 1) % MUD_LOSS_SAMPLES;

    if (track->sum_sent)
        *loss = (track->sum_sent >= track->sum_recv)
              ? (track->sum_sent - track->sum_recv) * 255U / track->sum_sent
              : 0;

    track->bucket_time = now;
    track->bucket_sent = 0;
    track->bucket_recv = 0;
}

static void
mud_update_rl(struct mud *mud, struct mud_path *path, uint64_t now,
              uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt,
              uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt)
{
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {
        if (!path->conf.fixed_rate)
            path->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
    } else {
        mud_update_loss(&path->msg.tx_loss, now, path->traffic_idle,
                        &path->tx.loss, &path->tx.loss_live,
                        tx_pkt, rx_pkt);

        if (!path->conf.fixed_rate)
            path->tx.rate += path->tx.rate / 10;
    }
    if (path->tx.rate > path->conf.tx_max_rate)
        path->tx.rate = path->conf.tx_max_rate;
}

static void
mud_update_stat(struct mud_stat *stat, const uint64_t val)
{
    if (stat->setup) {
        const uint64_t var = mud_abs_diff(stat->val, val);
        stat->var = ((stat->var << 1) + stat->var + var) >> 2;
        stat->val = ((stat->val << 3) - stat->val + val) >> 3;
    } else {
        stat->setup = 1;
        stat->var = val >> 1;
        stat->val = val;
    }
}

static void
mud_recv_msg(struct mud *mud, struct mud_path *path,
             uint64_t now, uint64_t sent_time,
             unsigned char *data, size_t size)
{
    struct mud_msg *msg = (struct mud_msg *)data;
    const uint64_t tx_time = MUD_LOAD_MSG(msg->sent_time);

    mud_sock_from_addr(&path->remote, &msg->addr);

    if (tx_time) {
        mud_update_stat(&path->rtt, MUD_TIME_MASK(now - tx_time));

        const uint64_t tx_bytes = MUD_LOAD_MSG(msg->fw.bytes);
        const uint64_t tx_total = MUD_LOAD_MSG(msg->fw.total);
        const uint64_t rx_bytes = MUD_LOAD_MSG(msg->rx.bytes);
        const uint64_t rx_total = MUD_LOAD_MSG(msg->rx.total);
        const uint64_t rx_time  = sent_time;

        if ((tx_time > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (rx_time > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes)) {
            if (path->msg.set && path->status > MUD_PROBING) {
                mud_update_rl(mud, path, now,
                        MUD_TIME_MASK(tx_time - path->msg.tx.time),
                        tx_bytes - path->msg.tx.bytes,
                        tx_total - path->msg.tx.total,
                        MUD_TIME_MASK(rx_time - path->msg.rx.time),
                        rx_bytes - path->msg.rx.bytes,
                        rx_total - path->msg.rx.total);
            }
            path->msg.tx.time = tx_time;
            path->msg.rx.time = rx_time;
            path->msg.tx.bytes = tx_bytes;
            path->msg.rx.bytes = rx_bytes;
            path->msg.tx.total = tx_total;
            path->msg.rx.total = rx_total;
            path->msg.set = 1;
        }
        /* rx.loss: derived locally from the peer's own tx counters (sent in
         * every message, no echo needed) against our own real rx counters,
         * the same way tx.loss is derived from the peer's rx counters. Do
         * not just copy msg->loss -- that is the peer's own computation of
         * the same number and may disagree if the peer runs different or
         * buggy loss-accounting logic. */
        const uint64_t peer_tx_bytes = MUD_LOAD_MSG(msg->tx.bytes);
        const uint64_t peer_tx_total = MUD_LOAD_MSG(msg->tx.total);

        if ((peer_tx_total > path->msg.rxloss.peer_total) &&
            (peer_tx_bytes > path->msg.rxloss.peer_bytes)) {
            if (path->msg.rxloss.time && path->status > MUD_PROBING) {
                mud_update_loss(&path->msg.rx_loss, now, path->traffic_idle,
                                &path->rx.loss, &path->rx.loss_live,
                                peer_tx_total - path->msg.rxloss.peer_total,
                                path->rx.total - path->msg.rxloss.own_total);
            }
            path->msg.rxloss.peer_total = peer_tx_total;
            path->msg.rxloss.peer_bytes = peer_tx_bytes;
            path->msg.rxloss.own_total  = path->rx.total;
            path->msg.rxloss.time = now;
        }
        path->msg.sent = 0;

        if (path->conf.state == MUD_PASSIVE)
            return;
    } else {
        path->conf.beat = MUD_LOAD_MSG(msg->beat);

        const uint64_t max_rate = MUD_LOAD_MSG(msg->max_rate);

        /* an operator-pinned tx rate (path up ... rate tx X) must not be
         * silently reset by the peer's own rx advertisement */
        if (!path->conf.tx_pinned) {
            if (path->conf.tx_max_rate != max_rate || msg->fixed_rate)
                path->tx.rate = max_rate;

            path->conf.tx_max_rate = max_rate;
            path->conf.fixed_rate = msg->fixed_rate;
        }
        path->conf.pref = msg->pref;
        path->conf.loss_limit = msg->loss_limit;

        /* An operator-set mtu (path up ... mtu N) always wins locally and
         * is never touched here -- mirrors how tx_pinned protects an
         * explicit rate above. A path that's never had one explicitly
         * configured (conf.mtu == 0, e.g. a passively auto-discovered
         * server path with no matching path up) instead follows whatever
         * the peer advertises for this same path, rather than the flat
         * MUD_MTU_DEFAULT: the same physical link's overhead constraint
         * generally applies in both directions, so this is a more useful
         * default than a one-size-fits-all constant. Re-applied on every
         * beat, so it naturally tracks a later change to the peer's own
         * configured value -- this is a live fallback, not a one-time
         * probe/negotiation, so there's no stale state to go wrong. */
        if (!path->conf.mtu) {
            const uint64_t peer_mtu = MUD_LOAD_MSG(msg->mtu);
            if (peer_mtu)
                path->mtu = peer_mtu > MUD_MTU_HARD_MAX
                          ? MUD_MTU_HARD_MAX : peer_mtu;
        }

        path->msg.sent++;
        path->msg.time = now;
    }
    /* Caller (mud_recv_finish(), via mud_worker_loop()'s RX half, or
     * mud_path_track() via mud_update()) already holds state_lock for this
     * whole call -- mud->keyx itself additionally needs keyx_lock, since
     * that's also read (unlocked, via a snapshot copy) by every concurrent
     * encrypt/decrypt call on any worker thread; see mud_encrypt()/
     * mud_decrypt(). */
    pthread_mutex_lock(&mud->keyx_lock);
    int need_keyx = memcmp(msg->pkey, mud->keyx.remote, MUD_PUBKEY_SIZE) != 0;

    if (need_keyx) {
        if (mud_keyx(&mud->keyx, msg->pkey, msg->aes)) {
            pthread_mutex_unlock(&mud->keyx_lock);
            mud->err.keyx.addr = path->conf.remote;
            mud->err.keyx.time = now;
            mud->err.keyx.count++;
            return;
        }
    } else if (path->conf.state == MUD_UP) {
        mud->keyx.use_next = 1;
    }
    pthread_mutex_unlock(&mud->keyx_lock);
    /* No MTU probing to size this reply for -- minimal padding only
     * (mud_send_msg() still pads up to the message's own minimum size). */
    mud_send_msg(mud, path, now, sent_time,
                 MUD_LOAD_MSG(msg->tx.bytes),
                 MUD_LOAD_MSG(msg->tx.total),
                 0);
}

/* Handles everything after a raw packet has been pulled off the wire:
 * validity/clock checks, decrypt, path lookup/creation, control-message
 * processing or idle-timestamp update, rx stat bookkeeping. Shared by
 * mud_recv() and mud_worker_loop()'s RX half so this locking protocol only
 * needs to be gotten right in one place. `msg` must be the same struct
 * msghdr the packet was just recvmsg()'d into (msg_control/msg_controllen
 * still describing the ancillary data received). state_lock is taken and
 * released internally, in two short sections either side of the decrypt
 * call -- never held across the decrypt itself, which is what lets
 * multiple threads calling this concurrently still decrypt in parallel.
 * Returns what the caller should treat as the received size: 0 if the
 * packet was dropped or was a control message (already fully handled
 * here), otherwise the decrypted payload length now sitting in `data`.
 *
 * `reorder_hold_out`, if non-NULL, is set to the resolved path's current
 * mud_path.reorder_hold for a real data packet (0 for anything else --
 * dropped, control message, or no path resolved). Captured here, while
 * state_lock already covers `path`, instead of making the caller look the
 * path up again -- mud_worker_loop() is the only caller that uses this;
 * mud_recv() passes NULL, since the single-packet API doesn't participate
 * in resequencing at all (see mud_worker_loop()'s doc comment in mud.h). */
static int
mud_recv_finish(struct mud *mud, unsigned int sock, struct msghdr *msg,
                union mud_sockaddr *remote, unsigned char *packet,
                ssize_t packet_size, unsigned char *data, size_t data_cap,
                uint64_t *reorder_hold_out)
{
    if (reorder_hold_out)
        *reorder_hold_out = 0;

    if ((msg->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (packet_size <= (ssize_t)MUD_PKT_MIN_SIZE))
        return 0;

    const uint64_t now = mud_now(mud);
    const uint64_t sent_time = mud_load(packet, MUD_TIME_SIZE);

    mud_unmapv4(remote);

    pthread_mutex_lock(&mud->state_lock);
    const uint64_t timetolerance = mud->conf.timetolerance;

    if ((MUD_TIME_MASK(now - sent_time) > timetolerance) &&
        (MUD_TIME_MASK(sent_time - now) > timetolerance)) {
        mud->err.clocksync.addr = *remote;
        mud->err.clocksync.time = now;
        mud->err.clocksync.count++;
        pthread_mutex_unlock(&mud->state_lock);
        return 0;
    }
    pthread_mutex_unlock(&mud->state_lock);

    const size_t ret = MUD_MSG(sent_time)
                     ? mud_decrypt_msg(mud, data, data_cap, packet, (size_t)packet_size)
                     : mud_decrypt(mud, data, data_cap, packet, (size_t)packet_size);

    pthread_mutex_lock(&mud->state_lock);

    if (!ret) {
        mud->err.decrypt.addr = *remote;
        mud->err.decrypt.time = now;
        mud->err.decrypt.count++;
        pthread_mutex_unlock(&mud->state_lock);
        return 0;
    }
    union mud_sockaddr local = {0};
    unsigned int local_ifindex;

    if (mud_localaddr(&local, &local_ifindex, msg)) {
        pthread_mutex_unlock(&mud->state_lock);
        return 0;
    }
    struct mud_path *path = mud_get_path(mud, &local, remote,
                                         local_ifindex, sock, 1, MUD_PASSIVE);

    if (!path || path->conf.state <= MUD_DOWN) {
        pthread_mutex_unlock(&mud->state_lock);
        return 0;
    }
    if (MUD_MSG(sent_time)) {
        mud_recv_msg(mud, path, now, sent_time, data, (size_t)packet_size);
    } else {
        path->idle = now;
    }
    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += (size_t)packet_size;

    if (reorder_hold_out && !MUD_MSG(sent_time))
        *reorder_hold_out = path->reorder_hold;

    mud->last_recv_time = now;

    pthread_mutex_unlock(&mud->state_lock);

    return MUD_MSG(sent_time) ? 0 : (int)ret;
}

int
mud_recv(struct mud *mud, unsigned int sock, void *data, size_t size)
{
    pthread_mutex_lock(&mud->state_lock);
    const int fd = (sock < mud->sock_count) ? mud->sock[sock] : -1;
    pthread_mutex_unlock(&mud->state_lock);

    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }
    union mud_sockaddr remote;
    unsigned char ctrl[MUD_CTRL_SIZE];
    unsigned char packet[MUD_PKT_MAX_SIZE];
    struct msghdr msg = {
        .msg_name = &remote,
        .msg_namelen = sizeof(remote),
        .msg_iov = &(struct iovec) {
            .iov_base = packet,
            .iov_len = sizeof(packet),
        },
        .msg_iovlen = 1,
        .msg_control = ctrl,
        .msg_controllen = sizeof(ctrl),
    };
    const ssize_t packet_size = recvmsg(fd, &msg, 0);

    if (packet_size == (ssize_t)-1)
        return -1;

    return mud_recv_finish(mud, sock, &msg, &remote, packet, packet_size,
                           data, size, NULL);
}

static int
mud_path_update(struct mud *mud, struct mud_path *path, uint64_t now)
{
    switch (path->conf.state) {
        case MUD_DOWN:
            path->status = MUD_DELETING;
        case MUD_PASSIVE:
            if (mud_timeout(now, path->rx.time, 5 * MUD_ONE_MIN)) {
                memset(path, 0, sizeof(struct mud_path));
                return 0;
            }
        case MUD_UP: break;
        default:     return 0;
    }
    if (path->conf.state == MUD_DOWN)
        return 0;

    if (path->msg.sent >= MUD_MSG_SENT_MAX) {
        path->msg.sent = MUD_MSG_SENT_MAX;
        path->status = MUD_DEGRADED;
        return 0;
    }
    if (path->tx.loss > path->conf.loss_limit ||
        path->rx.loss > path->conf.loss_limit) {
        path->status = MUD_LOSSY;
        return 0;
    }
    if (path->conf.rtt_limit && path->rtt.val > path->conf.rtt_limit) {
        path->status = MUD_LATE;
        return 0;
    }
    if (path->conf.state == MUD_PASSIVE &&
        mud_timeout(mud->last_recv_time, path->rx.time,
                    MUD_MSG_SENT_MAX * path->conf.beat)) {
        path->status = MUD_WAITING;
        return 0;
    }
    if (path->conf.pref > mud->pref) {
        path->status = MUD_READY;
    } else if (path->status != MUD_RUNNING) {
        path->status = MUD_RUNNING;
        path->idle = now;
    }
    return 1;
}

static uint64_t
mud_path_track(struct mud *mud, struct mud_path *path, uint64_t now)
{
    path->traffic_idle = mud_timeout(now, path->idle, MUD_ONE_SEC);

    if (path->conf.state != MUD_UP)
        return now;

    uint64_t timeout = path->conf.beat;

    switch (path->status) {
        case MUD_RUNNING:
            /* Back off an idle path's beat cadence to the slow keepalive --
             * except when this instance has more than one local socket
             * open. With sub-flows, mud_select_path() only sends any given
             * packet to one of several paths sharing a physical link, so
             * any individual sub-flow can look "idle" for a full second
             * purely by chance even while the link overall is busy; backing
             * its beat off would both stale its RTT/loss display (only
             * refreshed when a beat reply is processed) and stop its rate
             * estimate from being reassessed, which is what
             * mud_select_path()'s per-group weighting relies on staying
             * current for every member. A single-socket instance keeps the
             * original behavior unchanged. */
            if (path->traffic_idle && mud->sock_count <= 1)
                timeout = mud->conf.keepalive;
            break;
        case MUD_DEGRADED:
        case MUD_LOSSY:
        case MUD_PROBING:
            break;
        default:
            return now;
    }
    if (mud_timeout(now, path->msg.time, timeout)) {
        path->msg.sent++;
        path->msg.time = now;
        mud_send_msg(mud, path, now, 0, 0, 0, path->mtu);
        now = mud_now(mud);
    }
    return now;
}

static void
mud_update_window(struct mud *mud, const uint64_t now)
{
    uint64_t elapsed = MUD_TIME_MASK(now - mud->window_time);

    if (elapsed > MUD_ONE_MSEC) {
        mud->window += mud->rate * elapsed / MUD_ONE_SEC;
        mud->window_time = now;
    }
    uint64_t window_max = mud->rate * 100 * MUD_ONE_MSEC / MUD_ONE_SEC;

    if (mud->window > window_max)
        mud->window = window_max;
}

int
mud_update(struct mud *mud)
{
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    size_t   mtu = 0;
    uint64_t now = mud_now(mud);

    /* Held for this entire sweep -- mud_update() runs on the housekeeping
     * thread roughly every ~100ms (see bind.c), not per-packet, so there is
     * no meaningful cost to worker threads occasionally waiting behind one
     * full pass over mud->paths rather than something more fine-grained. */
    pthread_mutex_lock(&mud->state_lock);

    if (!mud_keyx_init(mud, now))
        now = mud_now(mud);

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (mud_path_update(mud, path, now)) {
            if (next_pref > path->conf.pref && path->conf.pref > mud->pref)
                next_pref = path->conf.pref;
            if (pref > path->conf.pref)
                pref = path->conf.pref;
            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
        if (path->mtu) {
            if (!mtu || mtu > path->mtu)
                mtu = path->mtu;
        }
        now = mud_path_track(mud, path, now);
        count++;
    }
    if (rate) {
        mud->pref = pref;
    } else {
        mud->pref = next_pref;

        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            if (!mud_path_update(mud, path, now))
                continue;

            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
    }
    mud->mtu = mtu;

    /* Recompute mud->rate from select_weight rather than the raw tx.rate
     * sum above -- rate was only needed to settle mud->pref just now. Every
     * RUNNING path's selection weight becomes its physical-link group's
     * average tx.rate (see mud_path_same_group()), so mud_select_path()'s
     * weighted walk splits packets evenly across sub-flows of one link
     * regardless of which currently measures fastest, while still favoring
     * whichever physical link has more real aggregate capacity. Recomputing
     * the total from select_weight itself (rather than reusing `rate`)
     * keeps the two mutually consistent despite integer-division rounding
     * inside each group -- mud_select_path()'s cursor is scaled against
     * mud->rate, so any drift there risks the walk running past the last
     * path without ever finding a match. */
    uint64_t weighted_rate = 0;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->status != MUD_RUNNING) {
            path->select_weight = 0;
            continue;
        }
        uint64_t group_total = 0;
        unsigned group_count = 0;

        for (unsigned j = 0; j < mud->capacity; j++) {
            struct mud_path *other = &mud->paths[j];

            if (other->status != MUD_RUNNING ||
                !mud_path_same_group(path, other))
                continue;

            group_total += other->tx.rate;
            group_count++;
        }
        path->select_weight = group_count ? group_total / group_count : 0;
        weighted_rate += path->select_weight;
    }
    mud->rate = weighted_rate;

    /* Per-path resequencing hold budget -- see mud_path.reorder_hold's own
     * comment in mud.h, and mud_reorder_insert()/mud_reorder_flush() below.
     * Same cadence as select_weight above; only costs a cheap two-pass
     * scan over an already-small array, so it runs unconditionally rather
     * than being gated on whether reorder_window is actually enabled. */
    uint64_t max_running_rtt = 0;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->status == MUD_RUNNING && path->rtt.val > max_running_rtt)
            max_running_rtt = path->rtt.val;
    }
    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        path->reorder_hold = (path->status == MUD_RUNNING &&
                              max_running_rtt > path->rtt.val)
                            ? (max_running_rtt - path->rtt.val) / 2
                            : 0;
    }
    mud_update_window(mud, now);
    pthread_mutex_unlock(&mud->state_lock);

    if (!count)
        return -1;

    return mud->window < 1500;
}

int
mud_set_path(struct mud *mud, struct mud_path_conf *conf)
{
    if (conf->state < MUD_EMPTY || conf->state >= MUD_LAST) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&mud->state_lock);

    if (conf->sock >= mud->sock_count) {
        pthread_mutex_unlock(&mud->state_lock);
        errno = EINVAL;
        return -1;
    }
    struct mud_path *path = mud_get_path(mud, &conf->local,
                                              &conf->remote,
                                              conf->local_ifindex,
                                              conf->sock,
                                              0,
                                              conf->state);
    if (!path) {
        pthread_mutex_unlock(&mud->state_lock);
        return -1;
    }
    struct mud_path_conf c = path->conf;

    if (conf->state)       c.state       = conf->state;
    if (conf->pref)        c.pref        = conf->pref >> 1;
    if (conf->beat)        c.beat        = conf->beat * MUD_ONE_MSEC;
    if (conf->fixed_rate)  c.fixed_rate  = conf->fixed_rate >> 1;
    if (conf->loss_limit)  c.loss_limit  = conf->loss_limit;
    if (conf->rtt_limit)   c.rtt_limit   = conf->rtt_limit * MUD_ONE_MSEC;
    if (conf->tx_max_rate) {
        c.tx_max_rate = path->tx.rate = conf->tx_max_rate;
        c.tx_pinned = 1;
    }
    if (conf->rx_max_rate) c.rx_max_rate = path->rx.rate = conf->rx_max_rate;
    if (conf->mtu)          c.mtu         = conf->mtu;

    path->conf = c;

    /* No discovery to wait on: apply immediately, every call -- cheap and
     * idempotent, and covers both a newly configured value and a brand
     * new path that has never had one set (falls back to the default). */
    mud_mtu_apply(path);
    pthread_mutex_unlock(&mud->state_lock);

    *conf = c;
    return 0;
}

int
mud_rebind_path(struct mud *mud, unsigned int old_ifindex,
                union mud_sockaddr *remote, unsigned int new_ifindex,
                union mud_sockaddr *new_local, unsigned int sock)
{
    if (!mud || !old_ifindex || !new_ifindex || !remote || !new_local ||
        new_local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&mud->state_lock);

    struct mud_path *path = NULL;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *candidate = &mud->paths[i];

        if (candidate->conf.state == MUD_EMPTY ||
            candidate->conf.local_ifindex != old_ifindex ||
            candidate->conf.sock != sock ||
            mud_cmp_addr(remote, &candidate->conf.remote) ||
            mud_cmp_port(remote, &candidate->conf.remote))
            continue;

        path = candidate;
        break;
    }
    if (!path) {
        pthread_mutex_unlock(&mud->state_lock);
        errno = ENOENT;
        return -1;
    }
    struct mud_path_conf conf = path->conf;
    conf.local = *new_local;
    conf.local_ifindex = new_ifindex;

    memset(path, 0, sizeof(*path));
    path->conf = conf;
    path->status = MUD_PROBING;
    path->idle = mud_now(mud);
    path->tx.rate = conf.tx_max_rate;
    path->rx.rate = conf.rx_max_rate;
    mud_mtu_apply(path);
    pthread_mutex_unlock(&mud->state_lock);
    return 0;
}

int
mud_send_wait(struct mud *mud)
{
    pthread_mutex_lock(&mud->state_lock);
    int wait = mud->window < 1500;
    pthread_mutex_unlock(&mud->state_lock);
    return wait;
}

int
mud_send(struct mud *mud, const void *data, size_t size)
{
    if (!size)
        return 0;

    /* Unlocked, optimistic early-out -- worst case (a rotation flips this
     * moments before or after) is one wasted encrypt attempt or one skipped
     * send this call, harmless for a single-packet, non-hot-path API. */
    if (mud->window < 1500) {
        errno = EAGAIN;
        return -1;
    }
    unsigned char packet[MUD_PKT_MAX_SIZE];
    const uint64_t now = mud_now(mud);
    const size_t packet_size = mud_encrypt(mud, now,
                                           packet, sizeof(packet),
                                           data, size);
    if (!packet_size) {
        errno = EMSGSIZE;
        return -1;
    }
    uint16_t k;
    memcpy(&k, &packet[packet_size - sizeof(k)], sizeof(k));

    pthread_mutex_lock(&mud->state_lock);

    struct mud_path *path = mud_select_path(mud, k);

    if (!path) {
        pthread_mutex_unlock(&mud->state_lock);
        errno = EAGAIN;
        return -1;
    }
    path->idle = now;

    int ret = mud_send_path(mud, path, now, packet, packet_size, 0);
    pthread_mutex_unlock(&mud->state_lock);
    return ret;
}

unsigned int
mud_worker_count(void)
{
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    /* Floor of 1, not 0 -- unlike the old shared-pool design, where a
     * calling thread with no workers still processed everything itself,
     * here the worker threads are the only thing that ever processes a
     * packet, so a single-core box still needs exactly one. */
    unsigned want = (ncpu > 1) ? (unsigned)(ncpu - 1) : 1;

    if (want > MUD_WORKERS_MAX)
        want = MUD_WORKERS_MAX;

    return want;
}

/* Worker threads used to all poll() the same tun_fd plus every socket in
 * the pool, which meant every readiness event woke every thread -- only
 * one of them ever did useful work per wakeup (recvmsg()/tun_read()), the
 * rest paid a wasted syscall (EAGAIN) each time. Splitting the socket set
 * so each worker only polls sock indices where (i % worker_count ==
 * worker_index) removes that thundering herd entirely: a given socket now
 * has exactly one thread ever polling it. Recomputed from mud->sock_count
 * every iteration (not cached), so it stays correct as mud_set_sock_count()
 * grows the pool. tun_fd itself is still shared -- it is a single fd, not
 * a set that can be partitioned -- so its own wakeup is still shared across
 * threads; that residual herd is at most worker_count wide (small) rather
 * than worker_count x sock_count, and the batching below makes losing that
 * race a rare event under load rather than one that recurs per packet. */
#define MUD_BATCH_MAX (16U)

struct mud_rx_slot {
    union mud_sockaddr remote;
    unsigned char ctrl[MUD_CTRL_SIZE];
    unsigned char packet[MUD_PKT_MAX_SIZE];
    struct msghdr msg;
    struct iovec iov;
    ssize_t len;
};

struct mud_tx_slot {
    unsigned char packet[MUD_PKT_MAX_SIZE];
    size_t size;
    unsigned char sock;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    unsigned int local_ifindex;
    struct mud_path *path;
};

/* Heap-allocated once per worker thread (not on the stack -- MUD_BATCH_MAX
 * slots of MUD_PKT_MAX_SIZE each would blow well past the 1MB worker stack
 * bind.c sizes for the rest of this function) and reused for the thread's
 * whole lifetime. */
struct mud_worker_scratch {
    struct mud_rx_slot rx[MUD_BATCH_MAX];
    struct mud_tx_slot tx[MUD_BATCH_MAX];
};

/* Drains up to `max` already-queued datagrams off one ready, non-blocking
 * socket in as few syscalls as possible: one recvmmsg() on Linux, or a
 * bounded recvmsg() loop elsewhere (still removes the old one-packet-per-
 * wakeup ceiling, just without the single-syscall win). Safe to call from
 * only one thread per socket -- see the socket-partitioning comment above;
 * this is not synchronized against another thread reading the same fd.
 * Returns the number of slots filled (0 on EAGAIN/nothing queued, -1 on a
 * real error). */
static int
mud_recv_batch(int fd, struct mud_rx_slot *slots, unsigned int max)
{
#if defined __linux__
    struct mmsghdr mmsg[MUD_BATCH_MAX];

    for (unsigned int i = 0; i < max; i++) {
        slots[i].iov.iov_base = slots[i].packet;
        slots[i].iov.iov_len = sizeof(slots[i].packet);
        memset(&mmsg[i].msg_hdr, 0, sizeof(mmsg[i].msg_hdr));
        mmsg[i].msg_hdr.msg_name = &slots[i].remote;
        mmsg[i].msg_hdr.msg_namelen = sizeof(slots[i].remote);
        mmsg[i].msg_hdr.msg_iov = &slots[i].iov;
        mmsg[i].msg_hdr.msg_iovlen = 1;
        mmsg[i].msg_hdr.msg_control = slots[i].ctrl;
        mmsg[i].msg_hdr.msg_controllen = sizeof(slots[i].ctrl);
    }
    const int n = recvmmsg(fd, mmsg, max, MSG_DONTWAIT, NULL);

    if (n <= 0)
        return n;

    for (int i = 0; i < n; i++) {
        slots[i].msg = mmsg[i].msg_hdr;
        slots[i].len = (ssize_t)mmsg[i].msg_len;
    }
    return n;
#else
    unsigned int n = 0;

    while (n < max) {
        slots[n].iov.iov_base = slots[n].packet;
        slots[n].iov.iov_len = sizeof(slots[n].packet);
        memset(&slots[n].msg, 0, sizeof(slots[n].msg));
        slots[n].msg.msg_name = &slots[n].remote;
        slots[n].msg.msg_namelen = sizeof(slots[n].remote);
        slots[n].msg.msg_iov = &slots[n].iov;
        slots[n].msg.msg_iovlen = 1;
        slots[n].msg.msg_control = slots[n].ctrl;
        slots[n].msg.msg_controllen = sizeof(slots[n].ctrl);

        const ssize_t r = recvmsg(fd, &slots[n].msg, 0);

        if (r == -1)
            break;

        slots[n].len = r;
        n++;
    }
    return (int)n;
#endif
}

/* Sends `n` already-encrypted TX slots, grouping by destination socket (a
 * batch can span more than one physical path/sub-flow) -- one sendmmsg()
 * per distinct sock on Linux, a plain per-message sendmsg() loop elsewhere.
 * `n` is bounded by MUD_BATCH_MAX, so the O(n^2) grouping scan is cheap.
 * Stats/window bookkeeping matches mud_send_path()'s, just applied once per
 * slot actually confirmed sent instead of once per syscall. */
static void
mud_send_batch(struct mud *mud, struct mud_tx_slot *tx, unsigned int n,
              uint64_t now)
{
    unsigned char done[MUD_BATCH_MAX] = {0};

    /* Slots with no selected path (mud_select_path() found nothing running)
     * have uninitialized sock/local/remote -- never read those fields,
     * just mark them done so neither loop below groups on garbage. */
    for (unsigned int g = 0; g < n; g++) {
        if (!tx[g].path)
            done[g] = 1;
    }

    for (unsigned int g = 0; g < n; g++) {
        if (done[g])
            continue;

        const unsigned char sock = tx[g].sock;
        unsigned int members[MUD_BATCH_MAX];
        unsigned int member_count = 0;

        for (unsigned int j = g; j < n; j++) {
            if (!done[j] && tx[j].sock == sock)
                members[member_count++] = j;
        }
#if defined __linux__
        struct mmsghdr mmsg[MUD_BATCH_MAX];
        struct iovec iov[MUD_BATCH_MAX];
        unsigned char ctrl[MUD_BATCH_MAX][MUD_CTRL_SIZE];

        for (unsigned int m = 0; m < member_count; m++) {
            struct mud_tx_slot *s = &tx[members[m]];

            iov[m].iov_base = s->packet;
            iov[m].iov_len = s->size;
            memset(ctrl[m], 0, sizeof(ctrl[m]));
            memset(&mmsg[m].msg_hdr, 0, sizeof(mmsg[m].msg_hdr));
            mmsg[m].msg_hdr.msg_iov = &iov[m];
            mmsg[m].msg_hdr.msg_iovlen = 1;
            mmsg[m].msg_hdr.msg_control = ctrl[m];

            if (s->remote.sa.sa_family == AF_INET) {
                mmsg[m].msg_hdr.msg_name = &s->remote.sin;
                mmsg[m].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                mmsg[m].msg_hdr.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE);

                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mmsg[m].msg_hdr);
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = MUD_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);
                memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
                       &s->local.sin.sin_addr, sizeof(struct in_addr));
#if defined IP_PKTINFO
                MUD_PKTINFO_IFINDEX(CMSG_DATA(cmsg)) = s->local_ifindex;
#endif
            } else if (s->remote.sa.sa_family == AF_INET6) {
                mmsg[m].msg_hdr.msg_name = &s->remote.sin6;
                mmsg[m].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
                mmsg[m].msg_hdr.msg_controllen =
                    CMSG_SPACE(sizeof(struct in6_pktinfo));

                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mmsg[m].msg_hdr);
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                       &s->local.sin6.sin6_addr, sizeof(struct in6_addr));
                ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex =
                    s->local_ifindex;
            } else {
                member_count = m; /* unreachable in practice; drop the rest */
                break;
            }
        }
        const int sent = sendmmsg(mud->sock[sock], mmsg, member_count, 0);

        if (sent > 0) {
            pthread_mutex_lock(&mud->state_lock);
            for (int m = 0; m < sent; m++) {
                struct mud_tx_slot *s = &tx[members[m]];

                if (!s->path || (size_t)mmsg[m].msg_len != s->size)
                    continue;

                s->path->tx.total++;
                s->path->tx.bytes += s->size;
                s->path->tx.time = now;

                if (mud->window > s->size)
                    mud->window -= s->size;
                else
                    mud->window = 0;
            }
            pthread_mutex_unlock(&mud->state_lock);
        }
#else
        for (unsigned int m = 0; m < member_count; m++) {
            struct mud_tx_slot *s = &tx[members[m]];
            const ssize_t r = mud_sendmsg_to(mud, s->sock, &s->local,
                                             s->local_ifindex, &s->remote,
                                             s->packet, s->size, 0);

            if (r == (ssize_t)s->size && s->path) {
                pthread_mutex_lock(&mud->state_lock);
                s->path->tx.total++;
                s->path->tx.bytes += s->size;
                s->path->tx.time = now;

                if (mud->window > s->size)
                    mud->window -= s->size;
                else
                    mud->window = 0;
                pthread_mutex_unlock(&mud->state_lock);
            }
        }
#endif
        for (unsigned int m = 0; m < member_count; m++)
            done[members[m]] = 1;
    }
}

/* Buffers one already-decrypted data packet instead of letting the caller
 * deliver it to TUN immediately, so mud_reorder_flush() can release it once
 * its deadline passes, in deadline order relative to whatever else is
 * currently buffered. Returns 1 if buffered (caller must not also deliver
 * it), 0 if the caller should fall back to delivering it immediately --
 * buffer full, the packet is larger than a slot, or `hold` capped out at
 * zero (this packet's own path is already the tunnel's slowest RUNNING
 * one, or reorder_window itself is very small -- either way there's
 * nothing for it to legitimately wait on). Correctness never depends on
 * the outcome: a packet this returns 0 for is simply delivered
 * unreordered, exactly like every packet is with the feature off.
 *
 * `hold` is the caller's already-resolved path's mud_path.reorder_hold
 * (see mud_update()) -- how much longer, relative to the tunnel's current
 * slowest RUNNING path, a packet on that specific path might still need to
 * wait for an earlier-sent packet on that slower path to arrive. This is
 * the whole point of computing it per path instead of applying one flat
 * mud_conf.reorder_window to every packet regardless of which path it
 * actually took: a packet on the slowest path gets `hold` at or near zero
 * and skips the buffer entirely (see below), while a packet on a much
 * faster path is held roughly as long as its real speed advantage, not
 * the full configured window. A flat window measurably hurt single-flow
 * throughput on a long-haul path in testing -- see "Packet resequencing"
 * in glorytun-notes.html -- because it delayed every packet by the same
 * amount regardless of whether that specific packet needed it.
 * mud_conf.reorder_window still caps `hold` here, protecting against a
 * noisy or momentarily wrong RTT reading rather than driving the common
 * case directly.
 *
 * mud->conf.reorder_window is read here (and at the top of
 * mud_reorder_flush()) without state_lock, unlike every other mud->conf
 * field elsewhere in this file. Same reasoning as mud_send()'s unlocked
 * read of mud->window: this is a per-packet hot path, the value changes
 * only on a rare, deliberate mud_set() call, and the worst case of reading
 * a moment-stale value is one packet delivered unbuffered (or, in the
 * other direction, one extra buffered packet) right at the instant it
 * changes -- harmless, and far cheaper than a lock/unlock on every
 * decrypted packet for a value that in practice never changes at
 * runtime. */
static int
mud_reorder_insert(struct mud *mud, uint64_t hold, uint64_t now,
                   const unsigned char *data, size_t size)
{
    if (size > MUD_REORDER_SLOT_SIZE)
        return 0;

    if (hold > mud->conf.reorder_window)
        hold = mud->conf.reorder_window;

    if (!hold)
        return 0;

    struct mud_reorder *ro = &mud->reorder;

    pthread_mutex_lock(&ro->lock);

    if (ro->count >= MUD_REORDER_MAX) {
        pthread_mutex_unlock(&ro->lock);
        return 0;
    }
    struct mud_reorder_slot *s = &ro->slot[ro->count++];

    memcpy(s->data, data, size);
    s->size = size;
    s->deadline = now + hold;

    pthread_mutex_unlock(&ro->lock);
    return 1;
}

/* Delivers every currently-buffered packet whose deadline (see
 * mud_reorder_insert()) has passed, via tun_write(), in ascending deadline
 * order. Since deadline = (this side's arrival time) + (this path's own
 * reorder_hold), and reorder_hold is derived from real per-path RTT so
 * that deadline ends up approximating (this packet's own send time) plus
 * a constant shared by every path (the tunnel's current slowest RUNNING
 * path's own one-way transit) -- sorting by deadline reproduces the
 * packets' original send order to the precision the per-path RTT
 * measurements and mud_update()'s ~100ms recompute cadence allow, without
 * this function needing to know each packet's actual send time at all.
 * Every comparison here is against this side's own mud_now() clock only
 * -- never the peer's -- so the two sides' clocks (only loosely
 * synchronized; see mud_recv_finish()'s timetolerance check) are never
 * mixed.
 *
 * flush_lock serializes this whole function across worker threads -- not
 * just the tun_write() calls, but the buffer scan and compaction too.
 * ro->lock guards only plain memory access to the buffer and is never held
 * across a syscall (same discipline as state_lock elsewhere in this file),
 * but strict delivery order requires that only one thread is ever inside
 * this function's body at a time, or two threads racing to flush
 * concurrently could interleave their releases and reintroduce the exact
 * reordering this exists to remove. That, in turn, is what makes it safe
 * to release ro->lock between the sort below and the delivery loop that
 * follows it: mud_reorder_insert() (called from other threads, under
 * ro->lock) only ever appends a new entry at ro->slot[ro->count++], never
 * touches an existing index -- so nothing can invalidate the `ready[]`
 * indices this function computed while flush_lock (which no insert ever
 * takes) still excludes any other compaction from running concurrently.
 *
 * The readiness scan and sort below deliberately consider every ready
 * entry, not just the first MUD_REORDER_FLUSH_BATCH found -- capping the
 * scan itself would sort correctly only within whatever arbitrary subset
 * of the buffer happened to be seen first (array order, not deadline
 * order), silently reintroducing the exact reordering this buffer exists
 * to remove once more than one batch's worth is ready at once, which is
 * routine under sustained throughput. MUD_REORDER_FLUSH_BATCH instead only
 * bounds how many entries' data are staged/copied per chunk during
 * delivery (for bounded stack usage) -- the order those chunks are read in
 * was already fixed by the single, complete sort beforehand. */
static void
mud_reorder_flush(struct mud *mud, int tun_fd, mud_tun_write_fn tun_write)
{
    if (!mud->conf.reorder_window)
        return;

    struct mud_reorder *ro = &mud->reorder;

    pthread_mutex_lock(&ro->flush_lock);
    pthread_mutex_lock(&ro->lock);

    const uint64_t now = mud_now(mud);
    unsigned ready[MUD_REORDER_MAX];
    unsigned ready_count = 0;

    for (unsigned i = 0; i < ro->count; i++) {
        if (now >= ro->slot[i].deadline)
            ready[ready_count++] = i;
    }
    /* Full insertion sort of the complete ready set by deadline. Runs
     * once per mud_worker_loop() iteration (not per packet), and
     * ready_count is bounded by MUD_REORDER_MAX, so O(n^2) here is cheap
     * in practice. */
    for (unsigned i = 1; i < ready_count; i++) {
        const unsigned key = ready[i];
        const uint64_t key_deadline = ro->slot[key].deadline;
        unsigned j = i;

        while (j > 0 && ro->slot[ready[j - 1]].deadline > key_deadline) {
            ready[j] = ready[j - 1];
            j--;
        }
        ready[j] = key;
    }
    pthread_mutex_unlock(&ro->lock);

    /* Deliver in chunks of MUD_REORDER_FLUSH_BATCH, strictly following the
     * order `ready[]` already established above -- see this function's own
     * doc comment for why re-locking per chunk (rather than once for the
     * whole delivery) is still safe. */
    unsigned char out_data[MUD_REORDER_FLUSH_BATCH][MUD_REORDER_SLOT_SIZE];
    size_t out_size[MUD_REORDER_FLUSH_BATCH];

    for (unsigned base = 0; base < ready_count; base += MUD_REORDER_FLUSH_BATCH) {
        const unsigned n = (ready_count - base < MUD_REORDER_FLUSH_BATCH)
                          ? ready_count - base : MUD_REORDER_FLUSH_BATCH;

        pthread_mutex_lock(&ro->lock);
        for (unsigned i = 0; i < n; i++) {
            struct mud_reorder_slot *s = &ro->slot[ready[base + i]];

            memcpy(out_data[i], s->data, s->size);
            out_size[i] = s->size;
        }
        pthread_mutex_unlock(&ro->lock);

        for (unsigned i = 0; i < n; i++)
            tun_write(tun_fd, out_data[i], out_size[i]);
    }
    if (ready_count) {
        /* Single compaction pass removing every entry just delivered --
         * the indices in `ready[]` are still valid; see the doc comment
         * above for why. */
        pthread_mutex_lock(&ro->lock);

        unsigned char keep[MUD_REORDER_MAX] = {0};

        for (unsigned i = 0; i < ready_count; i++)
            keep[ready[i]] = 1;

        unsigned w = 0;

        for (unsigned i = 0; i < ro->count; i++) {
            if (!keep[i])
                ro->slot[w++] = ro->slot[i];
        }
        ro->count = w;
        pthread_mutex_unlock(&ro->lock);
    }
    pthread_mutex_unlock(&ro->flush_lock);
}

/* One thread's full packet-processing loop -- see the extended comment on
 * this function in mud.h for the intended usage and the safety argument
 * for running several of these concurrently, and the comment on
 * MUD_BATCH_MAX above for why each thread only polls a subset of sockets.
 * Locking summary: state_lock guards path/socket-pool state and is taken
 * in short sections around plain memory access, keyx_lock guards mud->keyx
 * the same way, and neither is ever held across a syscall (poll/recvmsg/
 * recvmmsg/sendmsg/sendmmsg/tun_read/tun_write) or the AEAD encrypt/decrypt
 * call itself -- see mud_encrypt(), mud_decrypt(), mud_sendmsg_to(), and
 * mud_recv_finish(), which this function is built out of. */
int
mud_worker_loop(struct mud *mud, unsigned int worker_index,
                unsigned int worker_count, int tun_fd,
                mud_tun_read_fn tun_read, mud_tun_write_fn tun_write,
                const volatile sig_atomic_t *quit)
{
    if (!mud || tun_fd < 0 || !tun_read || !tun_write || !quit ||
        !worker_count || worker_index >= worker_count) {
        errno = EINVAL;
        return -1;
    }
    struct mud_worker_scratch *scratch = malloc(sizeof(*scratch));

    if (!scratch) {
        errno = ENOMEM;
        return -1;
    }
    unsigned char plain[MUD_MTU_HARD_MAX];
    unsigned char out[MUD_MTU_HARD_MAX];
    int ret = 0;

    while (!*quit) {
        pthread_mutex_lock(&mud->state_lock);
        const unsigned int sock_count = mud->sock_count;
        pthread_mutex_unlock(&mud->state_lock);

        /* mud->sock[i] for i < sock_count (just snapshotted above) never
         * changes once written -- see struct mud's comment -- so reading
         * it here needs no lock. */
        struct pollfd fds[1 + MUD_SOCK_MAX];
        unsigned int fd_sock[1 + MUD_SOCK_MAX];
        unsigned int n = 1;

        fds[0].fd = tun_fd;
        fds[0].events = POLLIN;

        for (unsigned int i = worker_index; i < sock_count; i += worker_count) {
            fds[n].fd = mud->sock[i];
            fds[n].events = POLLIN;
            fd_sock[n] = i;
            n++;
        }
        /* Bounded so *quit is rechecked promptly even with nothing to do,
         * same idle cadence bind.c's old event loop used. */
        const int pret = poll(fds, n, 100);

        if (pret == -1) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (pret == 0) {
            /* Nothing ready this cycle -- still give the reorder buffer
             * (if enabled) a chance to release anything that's timed out
             * while traffic went quiet; see mud_reorder_flush()'s timeout
             * backstop. A no-op when reorder_window is 0. */
            mud_reorder_flush(mud, tun_fd, tun_write);
            continue;
        }

        /* TX half: TUN has a packet ready to encrypt and send. Concurrent
         * tun_read() from multiple threads against the same fd is safe --
         * the kernel hands each call a distinct queued packet. Drains up
         * to MUD_BATCH_MAX packets (bounded by attempts, not just
         * successes, so a run of no-path drops can't turn this into an
         * unbounded spin) before handing them to mud_send_batch() as one
         * or a few syscalls instead of one sendmsg() per packet. */
        if ((fds[0].revents & POLLIN) && mud_send_wait(mud)) {
            /* Rate window depleted -- tun_fd stays readable (the kernel
             * still has queued packets), so without this a thread would
             * spin calling poll() at 100% CPU doing nothing useful until
             * housekeeping's next mud_update() refills the window. A
             * short, bounded sleep instead of reading-and-dropping mirrors
             * what bind.c's old !mud_send_wait(mud) gate did before ever
             * touching tun. Still falls through to the RX half below --
             * a depleted TX window says nothing about inbound work. */
            struct timespec ts = {.tv_nsec = 1000000}; /* 1ms */
            nanosleep(&ts, NULL);
        } else if (fds[0].revents & POLLIN) {
            unsigned int tx_n = 0, tx_attempts = 0;
            uint16_t tx_key[MUD_BATCH_MAX];

            /* Pass 1: drain TUN and encrypt, with no locking at all --
             * mud_encrypt() takes only the much less contended keyx_lock,
             * briefly, internally. Path selection is deliberately deferred
             * to pass 2 below rather than done per packet here: with the
             * TUN wakeup still shared across every worker (see the comment
             * above MUD_BATCH_MAX), several threads can win a real packet
             * from the same readiness event and batch-drain concurrently:
             * locking state_lock per packet inside this loop would mean up
             * to MUD_BATCH_MAX threads each doing up to MUD_BATCH_MAX
             * lock/unlock cycles at once -- worse mutex contention than the
             * unbatched original ever had. One lock covering the whole
             * batch's selection (pass 2) bounds that to one acquisition per
             * thread per wakeup, same as before batching existed. */
            while (tx_n < MUD_BATCH_MAX && tx_attempts < MUD_BATCH_MAX) {
                tx_attempts++;

                const int r = tun_read(tun_fd, plain, sizeof(plain));

                if (r <= 0)
                    break;

                struct mud_tx_slot *s = &scratch->tx[tx_n];
                const size_t packet_size = mud_encrypt(mud, mud_now(mud),
                                                       s->packet,
                                                       sizeof(s->packet),
                                                       plain, (size_t)r);
                if (!packet_size)
                    continue;

                memcpy(&tx_key[tx_n], &s->packet[packet_size - sizeof(tx_key[0])],
                      sizeof(tx_key[0]));
                s->size = packet_size;
                s->path = NULL;
                tx_n++;

                if (mud_send_wait(mud))
                    break;
            }
            /* Pass 2: one lock for the whole batch's path selection, then
             * one unlock before any syscall -- sendmmsg()/sendmsg() itself
             * intentionally runs outside state_lock -- see
             * mud_sendmsg_to()'s comment. Each slot's `path` stays a valid
             * pointer across that gap (mud->paths is fixed-size, never
             * moves); the only residual risk is that exact slot getting
             * recycled by housekeeping's 5-minutes-silent cleanup in the
             * tiny window before the stats update re-locks -- unreachable
             * in practice (a path just selected here is by definition not
             * idle), and even then the failure mode is misattributing a
             * few bytes to a reused slot's stats, not a crash or security
             * issue. Slots that find no path (s->path left NULL) are
             * skipped by mud_send_batch(), not compacted out -- avoids
             * copying MUD_PKT_MAX_SIZE-sized slots around for what should
             * be a rare case (no path up at all). */
            if (tx_n) {
                const uint64_t now = mud_now(mud);

                pthread_mutex_lock(&mud->state_lock);
                for (unsigned int t = 0; t < tx_n; t++) {
                    struct mud_tx_slot *s = &scratch->tx[t];
                    struct mud_path *path = mud_select_path(mud, tx_key[t]);

                    if (!path)
                        continue;

                    path->idle = now;
                    s->local = path->conf.local;
                    s->remote = path->conf.remote;
                    s->local_ifindex = path->conf.local_ifindex;
                    s->sock = path->conf.sock;
                    s->path = path;
                }
                pthread_mutex_unlock(&mud->state_lock);

                mud_send_batch(mud, scratch->tx, tx_n, now);
            }
        }
        /* RX half: each ready socket is drained via mud_recv_batch() --
         * up to MUD_BATCH_MAX packets in as few syscalls as possible --
         * instead of one recvmsg() per wakeup. Safe to drain fully now
         * (unlike the old shared-poll design) because socket partitioning
         * above guarantees no other thread is waiting on this same fd. */
        for (unsigned int k = 1; k < n; k++) {
            if (!(fds[k].revents & POLLIN))
                continue;

            const unsigned int sock_index = fd_sock[k];
            const int rx_n = mud_recv_batch(fds[k].fd, scratch->rx,
                                            MUD_BATCH_MAX);
            if (rx_n <= 0)
                continue;

            for (int j = 0; j < rx_n; j++) {
                struct mud_rx_slot *rs = &scratch->rx[j];
                uint64_t path_hold;
                const int wn = mud_recv_finish(mud, sock_index, &rs->msg,
                                               &rs->remote, rs->packet,
                                               rs->len, out, sizeof(out),
                                               &path_hold);
                if (wn <= 0)
                    continue;

                /* Reordering (mud_conf.reorder_window) is opt-in and off
                 * by default -- when disabled this is exactly the
                 * unconditional tun_write() this loop always did. When
                 * enabled, a packet mud_reorder_insert() couldn't buffer
                 * (full, oversized, or this path's own hold capped to
                 * zero) is still delivered immediately here instead of
                 * being dropped -- see mud_reorder_insert()'s own
                 * comment. */
                if (!mud->conf.reorder_window ||
                    !mud_reorder_insert(mud, path_hold, mud_now(mud),
                                        out, (size_t)wn))
                    tun_write(tun_fd, out, (size_t)wn);
            }
        }
        /* Deliver anything in the reorder buffer that's ready after this
         * iteration's RX work -- a no-op when reorder_window is 0. */
        mud_reorder_flush(mud, tun_fd, tun_write);
    }
    free(scratch);
    return ret;
}
