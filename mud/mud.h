#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Bounds paths to a single peer (mud is point-to-point), not a mesh.
 * Multiplied by sub-flow sockets per path (see MUD_SOCK_MAX below): e.g.
 * 2-3 physical uplinks x several sub-flows each adds up quickly, and the
 * passive side mirrors the same count independently (one auto-discovered
 * path per distinct source port it observes). struct mud_path is ~2-4KB
 * (dominated by two 60-sample struct mud_loss_track members below), so
 * this ceiling is a memory/lookup-cost tradeoff, not a hard resource
 * limit. */
#define MUD_PATH_MAX    (64U)
/* Local UDP sockets one mud instance may open, shared across every path --
 * not one-per-remote. Lets a single logical path be split into this many
 * independent sub-flows (distinct source ports) for bandwidth aggregation
 * on long/high-RTT links, similar to parallel TCP streams. The pool's
 * backing array is allocated once, fixed at this size, in mud_create() --
 * not grown on demand -- specifically so worker threads can read mud->sock[]
 * without synchronization (see mud_worker_loop()); 256 ints is 1KB, trivial
 * to just pre-allocate in full rather than defend against it moving. It
 * exists as a ceiling only because struct mud_path_conf.sock is a single
 * unsigned char, the actual limit on how many sockets one instance can
 * distinguish. Requests above this are rejected, not clamped, since
 * silently wrapping the index would corrupt path identity. */
#define MUD_SOCK_MAX    (256U)
#define MUD_PUBKEY_SIZE (32U)

/* Hard wire-size ceiling: 65535 is UDP's own length-field maximum
 * (header + payload). Note that over IPv4 the practical limit is lower
 * (65507 = 65535 - 20-byte IPv4 header - 8-byte UDP header) -- a
 * configured value between 65508 and 65535 will pass every check here but
 * still fail at sendto() on an IPv4 path, since the datagram can't
 * physically fit in an IPv4 packet at that size. Fixed packet buffers
 * throughout mud.c and bind.c are sized to this, so anything up to it is
 * memory-safe end-to-end regardless; the configured MTU
 * (struct mud_path_conf.mtu) is clamped to this at the point it's applied
 * (mud_mtu_apply()). The CLI is the layer that actually rejects an
 * out-of-range request with a clear error; this is only a last-resort
 * backstop, not a competing decision. */
#define MUD_MTU_HARD_MAX (65535U)

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_PASSIVE,
    MUD_UP,
    MUD_LAST,
};

enum mud_path_status {
    MUD_DELETING = 0,
    MUD_PROBING,
    MUD_DEGRADED,
    MUD_LOSSY,
    MUD_WAITING,
    MUD_READY,
    MUD_RUNNING,
    MUD_LATE,
};

struct mud_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

/* 60 one-second buckets. The in-progress bucket closes and publishes as
 * soon as 1s of wall-clock time has passed since it opened; the ring holds
 * the last (up to) 60 closed buckets so their combined counts give a true
 * rolling 60-second window, not 60 independently-decaying estimates. */
#define MUD_LOSS_SAMPLES (60U)

struct mud_loss_track {
    uint64_t bucket_time;
    uint64_t bucket_sent;
    uint64_t bucket_recv;
    uint64_t sample_sent[MUD_LOSS_SAMPLES];
    uint64_t sample_recv[MUD_LOSS_SAMPLES];
    uint64_t sum_sent;
    uint64_t sum_recv;
    unsigned next;
};

struct mud_conf {
    uint64_t keepalive;
    uint64_t timetolerance;
    uint64_t kxtimeout;
    /* 0 (default) = disabled: a decrypted data packet is handed to
     * mud_worker_loop()'s tun_write callback the instant it's decrypted,
     * exactly as before this existed. When set, mud_worker_loop() briefly
     * buffers decrypted data packets (bounded by this duration, in the
     * same time unit as the other fields above) tunnel-wide -- across
     * every path, not per-path -- so packets that arrive out of order
     * because they crossed different physical paths get sorted back into
     * send order before delivery, instead of reaching whatever protocol
     * (typically TCP) rides the tunnel looking exactly like loss. Trades
     * added latency, bounded by this value, for a single flow being able
     * to use more of a multipath tunnel's combined throughput. See
     * "Packet resequencing" in docs/architecture.md. Only mud_worker_loop()
     * honors this -- the single-packet mud_recv()/mud_send() API is
     * unaffected, by design (see mud_worker_loop's own doc comment). */
    uint64_t reorder_window;
};

union mud_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct mud_path_conf {
    enum mud_state state;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    unsigned int local_ifindex;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t beat;
    unsigned char pref;
    unsigned char fixed_rate;
    unsigned char loss_limit;
    unsigned char tx_pinned;
    unsigned char sock; /* index into the owning mud's socket pool
                          * (0..mud_get_sock_count()-1) this path sends and
                          * receives on -- local metadata, never sent to the
                          * peer, meaningful for both active and passive
                          * paths (unlike local_ifindex, never zeroed) */
    uint64_t rtt_limit;
    uint64_t mtu; /* 0 = library default (MUD_MTU_DEFAULT); clamped to
                   * MUD_MTU_HARD_MAX regardless of what's requested -- see
                   * mud_mtu_apply() */
};

struct mud_path {
    struct mud_path_conf conf;
    enum mud_path_status status;
    union mud_sockaddr remote;
    struct mud_stat rtt;
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;
        uint64_t rate;
        uint64_t loss;      /* rolling 60x1s window; drives loss_limit/MUD_LOSSY */
        uint64_t loss_live; /* most recently closed 1s bucket; status display */
    } tx, rx;
    struct {
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
        } tx, rx;
        struct mud_loss_track tx_loss;
        struct {
            uint64_t peer_total;
            uint64_t peer_bytes;
            uint64_t own_total;
            uint64_t time;
        } rxloss;
        struct mud_loss_track rx_loss;
        uint64_t time;
        uint64_t sent;
        uint64_t set;
    } msg;
    size_t mtu; /* the fixed wire size this path sends at -- always set (see
                 * mud_mtu_apply()), no discovery/negotiation involved */
    uint64_t select_weight; /* recomputed once per mud_update() tick, used by
                              * mud_select_path() instead of tx.rate directly:
                              * equal to the average tx.rate across every
                              * RUNNING path sharing this one's physical
                              * identity (same interface/local address and
                              * remote address, regardless of which sub-flow
                              * socket each one uses). Sub-flows of the same
                              * physical link are therefore selected evenly
                              * regardless of which one currently measures
                              * fastest, while distinct physical links still
                              * split traffic proportional to their real
                              * measured capacity. tx.rate itself is left
                              * alone -- still each sub-flow's own genuine
                              * measured throughput, for display/diagnostics
                              * and for its own AIMD growth/decay. */
    uint64_t idle;
    int traffic_idle; /* no real traffic in the last second; loss_live is
                        * stale/unmeasured while this is set -- see
                        * mud_update_loss(). Refreshed every mud_update()
                        * tick, so it stays current even if the peer goes
                        * fully silent. */
    uint64_t reorder_hold; /* recomputed once per mud_update() tick, same
                             * cadence as select_weight above: how much
                             * longer, relative to the tunnel's current
                             * slowest RUNNING path, a packet arriving on
                             * this specific path might still need to wait
                             * for an earlier-sent packet on that slower
                             * path to arrive. Zero for the slowest path
                             * itself (or when reorder_window is off).
                             * Used by mud_reorder_insert() (see mud.c) so
                             * held duration adapts to each path's real
                             * measured RTT instead of one flat delay
                             * applied to every packet regardless of which
                             * path it took. */
};

struct mud_error {
    union mud_sockaddr addr;
    uint64_t time;
    uint64_t count;
};

struct mud_errors {
    struct mud_error decrypt;
    struct mud_error clocksync;
    struct mud_error keyx;
};

struct mud_paths {
    struct mud_path path[MUD_PATH_MAX];
    unsigned count;
};

struct mud *mud_create (union mud_sockaddr *, unsigned char *, int *);
void        mud_delete (struct mud *);

int mud_set      (struct mud *, struct mud_conf *);
int mud_set_path (struct mud *, struct mud_path_conf *);
int mud_rebind_path (struct mud *, unsigned int, union mud_sockaddr *,
                     unsigned int, union mud_sockaddr *, unsigned int);

/* Grows the instance's local socket pool to `count` sockets (lazily, and
 * capped at MUD_SOCK_MAX), all bound to an ephemeral port on the same
 * address family as the original mud_create() socket. Monotonic -- never
 * shrinks. A struct mud_path_conf.sock value must be < the pool size
 * (mud_get_sock_count()) or mud_set_path() rejects it with EINVAL, so grow
 * the pool before configuring paths that reference new indices. Returns 0
 * on success, -1 (errno set) on failure, leaving sock_count unchanged. Safe
 * to call while worker threads are running (see mud_worker_loop()). */
int mud_set_sock_count (struct mud *, unsigned int count);

int mud_update    (struct mud *);
int mud_send_wait (struct mud *);

/* Single-packet API -- unchanged in meaning, now internally synchronized
 * against any concurrently running mud_worker_loop() threads (see below),
 * so a caller may still use these directly (as mud/test.c does) instead of
 * running worker threads at all. */
int mud_recv (struct mud *, unsigned int sock, void *, size_t);
int mud_send (struct mud *, const void *, size_t);

/* How many worker threads mud_worker_loop() is meant to be run with on this
 * host: min(cores - 1, MUD_WORKERS_MAX), the same formula the transport's
 * crypto used internally before this became the caller's responsibility.
 * Just a sizing hint -- mud_worker_loop() itself doesn't care how many
 * copies of it are actually running. */
unsigned int mud_worker_count (void);

/* mud.c is a standalone transport library and deliberately knows nothing
 * about glorytun's own TUN device handling (platform-specific framing,
 * etc. -- see src/tun.h) -- mud_worker_loop() takes it as a pair of plain
 * function pointers instead of linking against src/tun.c directly. Both
 * signatures match src/tun.h's tun_read()/tun_write() exactly, so a caller
 * in this repo can pass those two functions straight through with no
 * wrapping needed. */
typedef int (*mud_tun_read_fn)(int fd, void *buf, size_t size);
typedef int (*mud_tun_write_fn)(int fd, const void *buf, size_t size);

/* Runs one worker's full packet-processing loop: waits (via poll()) on the
 * TUN device and this worker's share of the instance's socket pool, and
 * for whichever is ready, does the complete job itself with no hand-off to
 * another thread -- receive, decrypt, look up the path, update its stats,
 * write to TUN (via `tun_write`); or read TUN (via `tun_read`), encrypt,
 * pick a path, send. Safe to run from multiple threads concurrently
 * against the same `struct mud *` and `tun_fd` -- that is the intended
 * use: start mud_worker_count() threads, each with its own worker_index in
 * [0, worker_count), so the full pipeline -- not just encryption --
 * spreads across cores instead of running on one thread while only crypto
 * is parallel.
 *
 * `worker_index`/`worker_count` partition the socket pool: this call only
 * polls sock indices i where (i % worker_count == worker_index), so a
 * given socket is polled by exactly one thread rather than every thread
 * waking on every socket's readiness (a thundering herd where only one
 * waker ever does useful work per event). The TUN fd itself is still
 * shared -- it can't be partitioned the way a set of sockets can -- so its
 * wakeup remains shared across all workers, just with a much smaller herd
 * (worker_count wide, not worker_count x sock_count) and batched enough
 * work per successful read that losing the race is rare under load rather
 * than recurring per packet. Each ready fd is drained in batches (up to 16
 * packets per wakeup, via recvmmsg()/sendmmsg() on Linux, or an equivalent
 * bounded loop elsewhere) rather than one packet per poll() iteration.
 * Every caller must use the same worker_count for all threads of one
 * `struct mud *` (mismatched values just waste polling coverage rather
 * than corrupting state, but there is no reason to do it).
 *
 * Concurrent recvmsg()/recvmmsg()/sendmsg()/sendmmsg()/tun_read()/
 * tun_write() from multiple threads against the same socket or TUN fd are
 * safe (the kernel hands each call a distinct packet); everything else the
 * pipeline touches (path state, session keys, the socket pool) is
 * internally locked, and those locks are never held across a syscall or
 * the actual AEAD operation, so the syscalls and the crypto math itself
 * still run fully concurrently across threads.
 *
 * Blocks until `*quit` is observed true (checked between iterations, so
 * a thread may still be inside one iteration -- typically a bounded
 * poll() wait -- when the flag flips) or a fatal error occurs, then
 * returns 0 (quit requested) or -1 (errno set). */
int mud_worker_loop (struct mud *mud, unsigned int worker_index,
                     unsigned int worker_count, int tun_fd,
                     mud_tun_read_fn tun_read, mud_tun_write_fn tun_write,
                     const volatile sig_atomic_t *quit);

int    mud_get_errors    (struct mud *, struct mud_errors *);
int    mud_get_fd        (struct mud *, unsigned int sock);
unsigned int mud_get_sock_count (struct mud *);
size_t mud_get_mtu       (struct mud *);
int    mud_get_paths     (struct mud *, struct mud_paths *,
                          union mud_sockaddr *, union mud_sockaddr *);
