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
 * path per distinct source port it observes). This ceiling is a
 * memory/lookup-cost tradeoff, not a hard resource
 * limit -- and unlike MUD_SOCK_MAX below, raising it isn't free: every
 * packet's path lookup (mud_get_path()) linearly scans this whole array
 * under state_lock, so a much larger value makes every packet slower to
 * process, not just startup memory bigger. Raised 64 -> 512 (8x) once
 * MUD_SOCK_MAX (below) stopped being the binding constraint on real
 * sub-flow counts -- deliberately a smaller multiplier than that one, for
 * exactly this per-packet-cost reason. */
#define MUD_PATH_MAX    (512U)
/* Local UDP sockets one mud instance may open, shared across every path --
 * not one-per-remote. Lets a single logical path be split into this many
 * independent sub-flows (distinct source ports) for bandwidth aggregation
 * on long/high-RTT links, similar to parallel TCP streams, and backs the
 * SO_REUSEPORT receive-scaling pool mud_create() opens (see its own
 * comment). The pool's backing array is allocated once, fixed at this
 * size, in mud_create() -- not grown on demand -- specifically so worker
 * threads can read mud->sock[] without synchronization (see
 * mud_worker_loop()).
 *
 * Raised 256 -> 4096 (16x) alongside widening struct mud_path_conf.sock
 * from unsigned char to uint16_t -- 256 was that field's own range, not a
 * deliberate design ceiling, and it was already tight enough that
 * combining several physical links with generous connections=N sub-flow
 * counts plus the SO_REUSEPORT reservation could plausibly approach it.
 * uint16_t comfortably covers this value with headroom to raise it
 * further later without another type change (max 65535). Not raised
 * further than this for now because mud_worker_loop() stack-allocates a
 * struct pollfd plus an index per socket (~12 bytes each): at 4096 that's
 * ~48KB against the explicit 1MB worker stack (see bind.c's
 * pthread_attr_setstacksize()), comfortably within the ~768KB left after
 * that stack's existing ~256KB of packet buffers, but the tradeoff would
 * need re-examining before going much higher. Requests above this are
 * rejected, not clamped, since silently wrapping the index would corrupt
 * path identity. */
#define MUD_SOCK_MAX    (4096U)
#define MUD_PUBKEY_SIZE (32U)

/* Ring size backing a monitor path's own received-sequence-number window
 * (see struct mud_path's `probe` member and "Probe-based path health" in
 * mud.c). Fixed, always allocated as part of struct mud_path -- same no-
 * realloc rationale as everything else sized this way in this header --
 * costing one byte per slot regardless of whether this path is ever used
 * as a monitor (most aren't). 600 covers a 10-minute probewindow/
 * proberecover at the default 1-second probe interval, generous headroom
 * over any sane configuration; a user-configured window/recover duration
 * longer than this, at whatever interval they chose, is clamped to it. */
#define MUD_PROBE_RING_SIZE (600U)

/* How far a peer-reported probe seq is allowed to regress before
 * mud_probe_recv() treats it as the peer's counter having restarted from
 * zero, rather than as an ordinarily-reordered late arrival -- see that
 * function's peer-report ordering guard. At the probe cadence this
 * piggybacks on (at most 1/s), a handful of slots is already generous
 * tolerance for real reordering; deliberately far smaller than
 * MUD_PROBE_RING_SIZE, whose 10-minute sizing is tuned for the loss ring's
 * own purpose and would otherwise let an early restart hide as reordering
 * for minutes. */
#define MUD_PEER_REPORT_REORDER_MAX (8U)

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
     * unaffected, by design (see mud_worker_loop's own doc comment).
     *
     * Sequence-numbered resequencing: setting this also tells the peer
     * (in every control message) that we want sequence numbers. A peer that
     * understands the request then appends a 4-byte number to the data
     * packets it sends us -- inside the encrypted payload, from a start
     * time it announces in its own clock, so both ends always agree which
     * packets carry one -- and we release those strictly in number order,
     * waiting only for a number that is actually missing (at most this
     * window, and normally just the arrival path's reorder_hold plus a few
     * ms, then it is given up as lost). An in-order packet is never delayed,
     * so a lone packet on the fast path keeps the fast path's latency, and
     * back-to-back bursts come out in order, which the RTT-derived hold
     * alone cannot guarantee. Nothing is stamped toward a peer that has not
     * asked (reorderwindow off, or an older build), and packets from such a
     * peer are still resequenced by the RTT-derived hold as before. Each
     * direction is independent, like the option itself. Stamped packets are
     * 4 bytes longer than the path's nominal MTU allows for.
     *
     * A packet is only stamped if its inner protocol isn't TCP (see
     * mud_is_tcp() in mud.c) -- TCP already carries its own sequence
     * numbers and reordering tolerance, and testing found this tunnel's own
     * strict ordering measurably hurts TCP throughput despite fixing the
     * false-retransmit problem resequencing exists for in the first place.
     * A TCP packet still gets the RTT-derived hold, just not the stricter
     * (and for TCP, counterproductive) sequence-number treatment. */
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
    uint16_t sock; /* index into the owning mud's socket pool
                     * (0..mud_get_sock_count()-1) this path sends and
                     * receives on -- local metadata, never sent to the
                     * peer, meaningful for both active and passive
                     * paths (unlike local_ifindex, never zeroed).
                     * Widened from unsigned char alongside MUD_SOCK_MAX
                     * (see its own comment) -- was that field's own
                     * 0-255 range, not a deliberate ceiling. */
    uint64_t rtt_limit; /* synced from whichever side has `monitor` configured,
                          * same as probe_interval/probe_window/probe_recover
                          * below -- see their own comment. */
    uint64_t mtu; /* 0 = library default (MUD_MTU_DEFAULT); clamped to
                   * MUD_MTU_HARD_MAX regardless of what's requested -- see
                   * mud_mtu_apply() */
    /* Probe-based path health (see "Probe-based path health" in mud.c).
     * `monitor` marks this path as a dedicated health-check sub-flow:
     * mud_select_path() never picks it for data, and it sends its probe on
     * a fixed cadence (probe_interval) regardless of the idle-driven beat
     * backoff every other path is subject to. The three tunables below --
     * plus rtt_limit above -- are only meaningful when monitor is set, and
     * only need setting on the active side's `path up`: mud_send_msg()/
     * mud_recv_msg() propagate all four to a passively-discovered peer path
     * the same way monitor/loss_limit themselves already do (see
     * mud_recv_msg()'s tx_time==0 branch and struct mud_msg's own comment
     * in mud.c), so a VPS-side path that never runs its own `path up` still
     * ends up using the exact same window/recover/RTT budget the active
     * side configured, instead of silently falling back to its own
     * compiled-in defaults for whichever of these the active side didn't
     * happen to match. 0 means "use the compiled-in default" (see
     * MUD_PROBE_*_DEFAULT in mud.c) on whichever side has no explicit
     * `path up` of its own to set it from. */
    unsigned char monitor;
    uint64_t probe_interval;
    uint64_t probe_window;
    uint64_t probe_recover;
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
    } tx, rx;
    struct {
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
        } tx, rx;
        uint64_t time;
        uint64_t sent;
        uint64_t set;
    } msg;
    size_t mtu; /* the fixed wire size this path sends at -- always set (see
                 * mud_mtu_apply()), no discovery/negotiation involved */
    /* Pooled across every path sharing this one's physical link (same
     * definition of "group" as select_weight above: same interface/local
     * address and remote address) -- recomputed once per mud_update() tick,
     * identical value mirrored onto every member, from struct mud_group's
     * own probe_has_monitor/probe_loss_pub/probe_degraded -- see "Probe-
     * based path health" in mud.c. Byte-counter tx-loss/rx-loss used to be
     * pooled the same way here too (tx.loss/rx.loss above and their live
     * counterparts, plus group_tx_loss/group_rx_loss/group_tx_loss_live/
     * group_rx_loss_live) -- removed entirely along with the rest of that
     * mechanism, since `monitor` is mandatory on every path now.
     * group_probe_has_monitor lets display code (glorytun path) tell "this
     * group has no monitor configured, ignore the other four" apart from
     * "it has one and it currently reads 0%". group_probe_loss/
     * group_probe_degraded are this side's own reading of what it receives
     * from the peer -- display/diagnostic only as of the peer-reporting
     * addition below; group_peer_probe_loss/group_peer_probe_degraded are
     * what the peer last reported about receiving from *us*, and
     * group_peer_probe_degraded is now the actual latched decision
     * mud_path_update() uses for MUD_LOSSY -- "should I keep sending this
     * way" has to depend on whether the peer is hearing us, not on whether
     * we're hearing the peer, which group_probe_degraded alone could never
     * tell it. See struct mud_group's own comment in mud.c for the full
     * rationale. */
    int group_probe_has_monitor;
    uint64_t group_probe_loss;
    int group_probe_degraded;
    uint64_t group_peer_probe_loss;
    int group_peer_probe_degraded;
    uint64_t group_rtt; /* average rtt.val across every currently-RUNNING
                          * member of the group -- same rationale as the loss
                          * figures above, applied to latency: one path's own
                          * RTT reading is only as fresh as its own last
                          * successful exchange, while the group figure
                          * reflects whichever member(s) most recently heard
                          * back. */
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
    uint64_t created; /* mud_now() at creation, set once by mud_get_path()
                        * and never touched again -- unlike `idle` (reused
                        * for traffic-gap tracking once a path goes
                        * RUNNING). mud_now() is wall-clock-based (base_time
                        * + CLOCK_MONOTONIC, see its own comment) and so
                        * keeps advancing across a process restart on the
                        * same machine, not reset to 0 -- which is what lets
                        * this double as a freshness baseline: see
                        * `confirmed_live` just below and mud_recv_msg()'s
                        * own comment for how the two combine. */
    int confirmed_live; /* set (never cleared) by mud_recv_msg() the first
                          * time this path receives a genuine reply -- one
                          * whose echoed timestamp is >= `created` above,
                          * meaning it can only be answering something this
                          * process sent after this path existed, not a
                          * queued packet a since-dead peer is still
                          * flushing out. mud_path_promote() (see its own
                          * comment) requires this before spending an fd on
                          * a passively-discovered path, closing a real gap
                          * a plain elapsed-time check left open: several
                          * stale packets can keep trickling out of a dead
                          * process's send queue for well over a second,
                          * long enough to fool a timer but never able to
                          * forge a reply to something that hadn't been
                          * sent yet when they were queued. */
    int traffic_idle; /* no real traffic in the last second. Refreshed every
                        * mud_update() tick, so it stays current even if the
                        * peer goes fully silent -- see mud_path_track()'s
                        * own use of it (single-socket keepalive backoff). */
    /* Only populated/meaningful when conf.monitor is set -- see "Probe-
     * based path health" in mud.c. Sequence-gap based, not byte-counter
     * based: each side tracks gaps in what it *receives* from the peer,
     * entirely locally, no echo/round-trip involved, applied to both
     * directions here since both ends run this identical logic on their
     * own incoming stream. */
    struct {
        uint32_t tx_next;   /* next sequence number this side sends */
        uint64_t tx_last;   /* mud_now() the last probe was sent, 0 = never */
        uint32_t rx_next;   /* next sequence number expected from the peer */
        uint64_t rx_last;   /* mud_now() a probe from the peer was last
                              * successfully processed, 0 = never. Distinct
                              * from the ring below: the ring only advances
                              * on a genuine event, so a path that goes
                              * fully silent (not just lossy) would
                              * otherwise leave stale "mostly good" data
                              * sitting in the ring forever -- mirrors why
                              * mud_path_track()'s own per-path idle-aging
                              * exists for the byte-counter trackers.
                              * mud_path_track() reads this each tick to
                              * force a resync once a whole probe_window's
                              * worth of real time has passed with nothing
                              * received at all. */
        int rx_sync;        /* 0 until the first probe has ever been seen,
                              * so a fresh/restarted peer's own numbering is
                              * adopted instead of read as one huge gap */
        unsigned char seen[MUD_PROBE_RING_SIZE]; /* ring: 1 = that sequence
                              * number's slot was received, 0 = missed;
                              * indexed by seq % MUD_PROBE_RING_SIZE */
        uint32_t peer_report_seq; /* seq of the last probe whose piggybacked
                              * peer-report bytes were actually applied to
                              * the group (see mud_group_peer_report()) --
                              * a later-arriving but lower-numbered probe
                              * (reordered in flight) must not be allowed to
                              * overwrite a report from a probe we already
                              * applied, so a report is only ever adopted
                              * when its own seq is newer than this. */
        int peer_report_sync; /* 0 until the first report has ever been
                              * applied, so that first one is never rejected
                              * for "not being newer than" an unset zero */
    } probe;
    uint64_t reorder_hold; /* recomputed once per mud_update() tick, same
                             * cadence as select_weight above: how much
                             * longer, relative to the tunnel's current
                             * slowest RUNNING path, a packet arriving on
                             * this specific path might still need to wait
                             * for an earlier-sent packet on that slower
                             * path to arrive. Zero for the slowest path
                             * itself (or when reorder_window is off), and
                             * zero for any path within ~0.5ms of it --
                             * below that is RTT measurement noise, not a
                             * real path difference.
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
 * host: min(usable cores - 1, MUD_WORKERS_MAX) by default ("usable" = the
 * cores this process is allowed to run on, so a CPU restriction is
 * respected), or whatever
 * mud_set_worker_count() last set explicitly (see its own comment). Just a
 * sizing hint -- mud_worker_loop() itself doesn't care how many copies of
 * it are actually running. */
unsigned int mud_worker_count (void);

/* Overrides mud_worker_count()'s automatic cores-1 sizing with an explicit
 * value -- every worker thread contends for the same shared TUN device
 * wakeup (see mud_worker_loop()'s own comment), so the number of sub-flows
 * actually in use, not raw core count, is what determines the efficient
 * worker count; only the operator configuring `connections N` knows that
 * number in advance. Pass 0 to go back to the automatic sizing. Clamped
 * to [1, min(4 x usable cores, 64)] -- deliberately allowed to exceed the
 * core count, since more workers than cores lets sub-flows divide evenly
 * (16 paths over 3 workers is 6/5/5, over 8 is 2 each) while the scheduler
 * spreads the threads; call after any CPU restriction is in place, since
 * the ceiling is computed from the cores available at that moment. Must be called
 * before mud_create(), which reads mud_worker_count() once to size its
 * own SO_REUSEPORT receive-scaling pool (see its own comment). */
void mud_set_worker_count (unsigned int n);

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
