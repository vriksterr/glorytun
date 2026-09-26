#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mud.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#if defined __linux__
#include <sched.h>
#endif

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

/* Probe-based path health (see the section comment above mud_probe_send()).
 * Defaults used when a monitor path's own conf.probe_interval/probe_window/
 * probe_recover is left at 0 (unset). probe_window is a sample *count*, not
 * a duration -- at the default 1-second interval the two happen to match,
 * but a user who shortens probe_interval keeps the same statistical
 * smoothing (60 samples) unless they also raise probe_window. Both
 * probe_window and (probe_recover / probe_interval) are clamped to
 * MUD_PROBE_RING_SIZE -- see its own comment. */
#define MUD_PROBE_INTERVAL_DEFAULT (MUD_ONE_SEC)
#define MUD_PROBE_WINDOW_DEFAULT   (60U)
#define MUD_PROBE_RECOVER_DEFAULT  (60 * MUD_ONE_SEC)

/* Trailing block appended to a monitor path's own control message, after
 * struct mud_msg and (always, whether or not it's actually in use --
 * see mud_send_msg()) the MUD_SEQ_EXT_SIZE gap the sequence-numbering
 * feature uses at that same fixed offset: the sender's next probe sequence
 * number (4 bytes), followed by two more bytes piggybacking that sender's
 * own current view of receiving from its peer -- a 0-255 loss reading and
 * a 0/1 degraded verdict (see "Probe-based path health"'s own comment on
 * why mud_path_update()'s send/no-send decision needs this, not just the
 * local reading). Reuses struct mud_msg wholesale rather than inventing a
 * new wire message type -- same pattern as the sequence-numbering
 * extension just above, for the same reason: a build that predates this
 * feature (or a path that isn't a monitor) never writes or looks at these
 * bytes, so nothing about the existing control-message format, its size
 * checks, or its decrypt path needs to change. */
#define MUD_PROBE_EXT_SIZE (6U)

#define MUD_PKT_MIN_SIZE (MUD_TIME_SIZE + MUD_MAC_SIZE)
#define MUD_PKT_MAX_SIZE MUD_MTU_HARD_MAX

/* No discovery/negotiation: every path uses a single fixed wire size,
 * either configured explicitly (struct mud_path_conf.mtu) or this default
 * -- a conservative size safe under standard PPPoE overhead and typical
 * VPN-in-VPN encapsulation without needing to probe for it. */
#define MUD_MTU_DEFAULT (1400U)

/* Starting tx.rate (bytes/sec) for a brand-new path that has no operator-
 * configured `rate tx` ceiling -- see mud_get_path()'s own comment for the
 * deadlock this exists to break. ~1Mbit/s: small enough to be safe to
 * blast onto any real link unconditionally, large enough that AIMD growth
 * (see mud_update_rl(), ~10%/tick) reaches typical broadband speeds within
 * a few seconds, the same order of magnitude as TCP slow start. */
#define MUD_TX_RATE_INITIAL (125000ULL)

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
    unsigned char fixed_rate;
    unsigned char loss_limit;
    /* Probe-based path health (see "Probe-based path health" above
     * mud_probe_loss_255()). Propagated the same way as pref/loss_limit/
     * beat above (see mud_recv_msg()'s tx_time==0 branch) so a passively
     * discovered path picks up "this is a monitor path" and the interval
     * to expect it on from the active side automatically -- unlike
     * probe_window/probe_recover (mud_path_conf's own fields), which stay
     * local to whichever side computes that side's own probe_degraded and
     * don't need to match to be individually correct. */
    unsigned char monitor;
    unsigned char probe_interval[MUD_TIME_SIZE];
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

/* Ceiling on mud_worker_count() (see its own comment for the min(cores-1,
 * this) formula). Raised 8 -> 32 (4x) to give genuinely large multi-core
 * boxes real headroom -- previously even a 256-core machine got exactly
 * 7 workers, identical to an 8-core one. Not raised to "however many
 * cores exist" unconditionally: every worker thread polls the *same*
 * shared TUN device fd (it can't be partitioned the way sockets can --
 * see mud_worker_loop()'s own comment), so when it's readable every
 * worker wakes to check and most find nothing -- a bigger wasted wakeup
 * on every real packet as worker count grows, not more throughput past
 * whatever point real per-core AEAD throughput (multi-Gbit/s, see `bench
 * multicore`) already covers the traffic. 32 is a deliberate middle
 * ground: a real 4x increase over the old ceiling, still well short of
 * where that shared-fd contention would plausibly start costing more
 * than it gives back. Also interacts with MUD_REUSEPORT_SCALE just below
 * -- see the explicit clamp in mud_create() that keeps their product
 * from threatening MUD_SOCK_MAX regardless of how either constant gets
 * tuned later. */
#define MUD_WORKERS_MAX (32U)

/* Ceiling for an *explicit* mud_set_worker_count(), which may exceed the
 * number of usable cores (an operator confined to a few cores can still ask
 * for more workers than cores, so sub-flows divide evenly across them --
 * 16 paths over 3 workers is 6/5/5, over 8 workers is 2 each, and the
 * scheduler balances the threads). 64 keeps mud_create()'s receive pool
 * (workers x MUD_REUSEPORT_SCALE) exactly at its MUD_SOCK_MAX/4 clamp. */
#define MUD_WORKERS_EXPLICIT_MAX (64U)

/* How many SO_REUSEPORT sockets mud_create() opens per worker thread for
 * inbound receive scaling -- see its own comment for why one-per-worker
 * alone isn't enough once a real deployment has many more remote
 * sub-flows than local worker threads. Tested directly on paired VMs at
 * 1, 8, and 16 against a real 16-sub-flow sustained load: 1 -> 8 gave a
 * real, measured ~22% reduction in per-worker-thread CPU spread; 8 -> 16
 * gave nothing further *at that same 16-sub-flow count*, since 8 already
 * provided more reserved sockets (24, on the 3-worker box tested) than
 * there were real sub-flows to hash across -- once bins outnumber flows,
 * more bins stop helping. 16 is set here anyway, ahead of actually
 * needing it: it costs one extra idle UDP socket per worker per unit of
 * headroom (cheap), and a deployment that grows past roughly 24-32 real
 * sub-flows -- two physical links each bonding a dozen-plus
 * connections=N sub-flows is not exotic -- would put it back in the
 * regime where the extra bins are earning their keep, same as 8 did over
 * 1 at 16 real sub-flows. A 4-worker box now opens 64 listen sockets
 * (16x4), still well under MUD_SOCK_MAX even at MUD_WORKERS_MAX workers
 * (16x8 = 128). */
#define MUD_REUSEPORT_SCALE (16U)

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

/* A path whose computed reorder_hold is below this is treated as having no
 * hold at all (its packets bypass the buffer). Two paths that are, for
 * practical purposes, the same speed still differ by a few hundred
 * microseconds in their smoothed RTT readings (measurement noise), and
 * buffering every packet on the "faster" one for that long buys no real
 * reordering fix -- it only turns every such packet into one that has to be
 * released by the deadline logic instead of going straight to TUN. Half a
 * millisecond is comfortably above that noise and well below any path
 * difference worth resequencing. */
#define MUD_REORDER_MIN_HOLD    (500U)

/* Sequence numbers -- see "Sequence-numbered resequencing" in mud.h.
 *
 * MUD_SEQ_SIZE: bytes appended to a data packet's plaintext while the
 * sending side is stamping (inside the AEAD, so authenticated and never
 * visible on the wire).
 *
 * MUD_SEQ_EXT_SIZE: the optional block after struct mud_msg in a control
 * message -- one flags byte (bit 0: "I want sequence numbers on what you
 * send me") plus the 6-byte time (in the SENDER's own mud_now() clock) from
 * which that sender stamps its data packets, 0 = not stamping. It is only
 * written when at least one of the two is non-zero, and only read when the
 * message is long enough to hold it, so a build that has never heard of it
 * neither sends nor is confused by it.
 *
 * MUD_SEQ_LEAD: how far in the future a sender sets its stamping start time
 * when it first learns the peer wants numbers, so the announcement (carried
 * by the very next control message on every path, normally <= 100ms away)
 * reaches the receiver before the first stamped packet does.
 *
 * MUD_SEQ_GAP_MARGIN: extra time, on top of the arrival path's own
 * reorder_hold, that a packet waits for a missing predecessor before that
 * predecessor is declared lost. Only ever paid when something really is
 * missing (a loss or a very late packet) -- an in-order packet is never
 * delayed at all.
 *
 * MUD_SEQ_RESYNC: a stamped packet this far (in packets) from what was
 * expected means the stream restarted (peer restart) rather than a real
 * gap; start over from it. */
#define MUD_SEQ_SIZE       (4U)
#define MUD_SEQ_EXT_SIZE   (1U + MUD_TIME_SIZE)
#define MUD_SEQ_FLAG_WANT  (1U)
#define MUD_SEQ_LEAD       (2 * MUD_ONE_SEC)
#define MUD_SEQ_GAP_MARGIN (3 * MUD_ONE_MSEC)
#define MUD_SEQ_RESYNC     (65536)
#define MUD_TIME_HALF      (UINT64_C(1) << (MUD_TIME_BITS - 1))

#define MUD_ALOAD(P)     __atomic_load_n((P), __ATOMIC_RELAXED)
#define MUD_ASTORE(P, V) __atomic_store_n((P), (V), __ATOMIC_RELAXED)

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

/* Storage for stamped (sequence-numbered) packets -- deliberately NOT the
 * same array/algorithm as mud_reorder_slot above. An earlier version kept
 * stamped packets in that same array and sorted the whole buffered set by
 * sequence number on every flush; under sustained high packet rate a single
 * slow-to-arrive packet lets the buffer fill with everything sent after it,
 * and sorting that full set on every mud_worker_loop() iteration is O(n^2)
 * in the buffer size -- a single-stream TCP test caught this directly: CPU
 * climbed to a full core within ~8 seconds and throughput collapsed to a
 * fraction of the no-sequencing case. A sequence number is already a direct
 * array index, so there is no need to search or sort for it at all: this
 * ring stores a packet at `seq % MUD_SEQ_RING_SIZE` and finds it again the
 * same way, both O(1), and a release pass is O(1) amortized per packet
 * released (each packet is written once and read once) regardless of how
 * many packets are buffered at once. MUD_SEQ_RING_SIZE must be a power of
 * two (see MUD_SEQ_RING_MASK) and comfortably larger than throughput (pps)
 * times the largest hold this buffer will actually see -- 4096 covers
 * several hundred ms at a sustained 10,000pps, generous for any single
 * tunnel's worth of resequencing. */
#define MUD_SEQ_RING_SIZE (4096U)
#define MUD_SEQ_RING_MASK (MUD_SEQ_RING_SIZE - 1U)

struct mud_seq_slot {
    unsigned char data[MUD_REORDER_SLOT_SIZE];
    size_t size;
    uint32_t seq;
    int occupied;
    uint64_t deadline; /* set once, by whichever packet's arrival first
                        * revealed the gap this slot is blocking on -- see
                        * mud_seq_insert(). Meaningless while !occupied. */
};

/* Tunnel-wide (not per-path, not per-worker-thread): reordering happens
 * because packets from one flow cross different physical paths with
 * different latencies, so sorting has to happen after every path funnels
 * back into the single TUN device, not before. See
 * mud_reorder_insert()/mud_reorder_flush() and mud_conf.reorder_window. */
struct mud_reorder {
    struct mud_reorder_slot slot[MUD_REORDER_MAX];
    unsigned count;
    uint64_t next_deadline;    /* earliest slot[].deadline currently held
                                 * (0 = buffer empty), kept current by
                                 * mud_reorder_insert() and the compaction
                                 * step of mud_reorder_flush(); lets
                                 * mud_worker_loop() sleep in poll() exactly
                                 * until the next release is due instead of
                                 * waiting for unrelated traffic or its
                                 * idle timeout -- see
                                 * mud_reorder_poll_timeout(). Guarded by
                                 * lock, like slot[]/count. */
    /* Everything below is the sequence-numbered path's own state (see
     * struct mud_seq_slot) -- entirely separate storage and bookkeeping
     * from slot[]/count/next_deadline above, guarded by the same lock. */
    struct mud_seq_slot seq_ring[MUD_SEQ_RING_SIZE]; /* ~8.5MB, same
                                 * always-allocated-with-struct-mud rationale
                                 * as slot[] above and struct mud's own
                                 * comment; trivial next to any system this
                                 * workload runs on at all. */
    uint32_t seq_next;          /* next sequence number due for delivery */
    unsigned seq_count;          /* occupied seq_ring[] entries right now --
                                 * lets mud_seq_flush() tell "genuinely
                                 * nothing buffered" apart from "buffered,
                                 * just not at the head yet" in O(1), instead
                                 * of a scan across the whole ring finding
                                 * that out the hard way on every single
                                 * call (which is most calls, since most
                                 * packets need no holding at all) -- see
                                 * mud_seq_flush()'s own comment. */
    int seq_sync;                /* seq_next is meaningful (else adopt the
                                 * next stamped packet's number) */
    uint64_t seq_next_deadline; /* deadline of whichever occupied ring slot
                                 * is currently blocking delivery (0 = not
                                 * currently blocked on anything) */
    pthread_mutex_t lock;       /* guards slot[]/count -- plain memory
                                 * access only, never held across a
                                 * syscall, same discipline as state_lock */
    pthread_mutex_t flush_lock; /* serializes the deliver-to-TUN phase
                                 * across worker threads -- see
                                 * mud_reorder_flush() */
};

/* Pooled RTT/probe-health state for every path sharing one physical link --
 * see struct mud_path's group_rtt field (mud.h) for the full rationale.
 * Identity fields mirror mud_path_same_group()'s own comparison exactly
 * (see mud_group_get()), snapshotted once when the group is first created
 * rather than read live off some "representative" member path -- so the
 * group's identity survives regardless of which specific member paths come
 * and go over the tunnel's lifetime. Found/created via linear scan
 * (mud_group_get()): the number of distinct physical links on one tunnel is
 * small (a handful at most -- this is bounded by real WAN interfaces, not
 * by connections N or sub-flow count), so this costs nothing next to the
 * O(paths^2) select_weight computation this file already does every tick.
 * This used to also pool byte-counter tx-loss/rx-loss across a group's
 * members (tx_loss/rx_loss/tx_loss_pub/rx_loss_pub/tx_loss_live_pub/
 * rx_loss_live_pub) -- removed entirely along with the rest of that
 * mechanism, since `monitor` is mandatory on every path now and
 * peer_probe_degraded below is the signal mud_path_update() actually
 * reads for its send/no-send decision (probe_degraded is this side's own
 * receive-direction reading -- display/diagnostic only, see its own
 * comment). */
struct mud_group {
    int active;
    unsigned int local_ifindex;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    /* Transient: reset and recomputed from scratch every mud_update() tick
     * (see the group pass there), not meaningful between ticks the way the
     * rolling trackers above are. */
    uint64_t rtt_sum;
    unsigned rtt_count;
    /* Probe-based path health (see "Probe-based path health" below and
     * struct mud_path's own `probe` member). Populated from whichever of
     * this group's members has conf.monitor set -- at most one is expected
     * in practice, but nothing enforces that; the most recently processed
     * one wins, harmlessly, since a second would be redundant anyway.
     * mud_path_update()'s loss_limit/MUD_LOSSY check reads probe_degraded
     * directly (not probe_loss_pub) once probe_has_monitor is set, so the
     * fast-degrade/slow-recover hysteresis lives here, computed once,
     * rather than re-derived by every member on every tick. */
    int probe_has_monitor;   /* 1 once this group has a monitor path that has
                                 sent or received at least one probe */
    uint64_t probe_loss_pub; /* 0-255 scale, display/diagnostic only --
                                 the *decision* is probe_degraded below */
    int probe_degraded;      /* current latched state: fast to set (the
                                 instant probe_loss_pub crosses loss_limit),
                                 slow to clear (see probe_good_since) */
    uint64_t probe_good_since; /* mud_now() marking the start of the current
                                 unbroken under-threshold stretch; 0 while
                                 at/over threshold. Clears probe_degraded
                                 once now - probe_good_since >= the
                                 monitor's own configured probe_recover. */
    /* What our peer's own monitor last told US about receiving from US --
     * i.e. the health of the direction THIS side actually sends on, as
     * opposed to probe_loss_pub/probe_degraded above (which is the health
     * of the direction this side receives on). mud_path_update()'s
     * MUD_LOSSY decision keys off peer_probe_degraded, not probe_degraded,
     * for exactly this reason: "should I keep sending this way" needs to
     * know whether the peer is hearing us, not whether we're hearing the
     * peer -- see the wire-format comment in mud_send_msg() and
     * mud_group_peer_report()'s own comment for how this gets filled in.
     * Deliberately NOT wrapped in its own fast-degrade/slow-recover shape
     * the way the local fields above are: the peer already ran that
     * hysteresis on its own side before reporting the verdict, so applying
     * it a second time here would just be double smoothing -- confirmed
     * live, it roughly doubled how long a fresh group took to ever reach
     * healthy. peer_probe_degraded is adopted directly from whatever the
     * peer's own already-debounced verdict says. */
    uint64_t peer_probe_loss_pub; /* 0-255 scale, display/diagnostic only */
    int peer_probe_degraded;      /* the actual latched send/no-send decision */
    uint64_t peer_probe_last; /* mud_now() a peer report was last accepted;
                                 0 = never. mud_path_track()'s own per-tick
                                 check forces peer_probe_degraded once this
                                 goes stale for a full probe_window, same
                                 "silence means assume the worst" principle
                                 as the local silent-monitor fallback below
                                 -- but unlike that one, this check runs for
                                 both MUD_UP and MUD_PASSIVE paths, since a
                                 passive side's peer can go silent on it
                                 exactly as easily as an active side's can. */
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
    /* sock_count right after mud_create()'s own reserved SO_REUSEPORT pool
     * finished growing -- i.e. the boundary between those wildcard sockets
     * (kernel-hash-selected, shared across whichever remotes land on them)
     * and every index past it, which is always some specific, deliberately
     * assigned socket (either src/bind.c's own `connections N` fan-out, or
     * mud_path_promote()'s own dedicated per-remote sockets below). Used
     * only to decide whether a freshly-discovered passive path is eligible
     * for promotion -- see mud_path_promote()'s own comment. Set once, past
     * mud_create() returning; never touched again. */
    unsigned int passive_pool_size;
    int sock_v4, sock_v6;
    sa_family_t sock_family;
    struct mud_conf conf;
    struct mud_path paths[MUD_PATH_MAX];
    struct mud_group groups[MUD_PATH_MAX]; /* worst case one group per path
                                 * (every path its own physical link); a
                                 * real deployment has only a handful of
                                 * distinct WAN interfaces, so almost all of
                                 * this stays !active. See struct mud_group's
                                 * own comment. */
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
    /* Sequence-number state (see "Sequence-numbered resequencing" in
     * mud.h). Accessed with MUD_ALOAD/MUD_ASTORE on any thread, not under
     * state_lock: seq_tx_start is the time (own clock) from which we stamp
     * outgoing data packets (0 = not stamping), seq_tx_next the counter,
     * seq_rx_start the same start time as announced by the peer for what it
     * sends us. */
    uint64_t seq_tx_start;
    uint32_t seq_tx_next;
    uint64_t seq_rx_start;
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

        /* A monitor path (see struct mud_path_conf's own comment) can
         * legitimately reach MUD_RUNNING -- it still exchanges ordinary
         * control messages, same status machine as any other path -- but
         * must never carry a data packet regardless: that's the whole
         * point of keeping it separate from the sub-flows actually doing
         * the work it's measuring. */
        if (path->status != MUD_RUNNING || path->conf.monitor)
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
mud_sendmsg_to(struct mud *mud, uint16_t sock,
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

/* Finds this path's struct mud_group (see its own comment), creating one in
 * the first free slot if this is the first path seen with this identity.
 * Same grouping rule as mud_path_same_group() just above, applied against
 * the group's own stored identity rather than another path's live one, so a
 * group outlives any single member path coming or going. Returns NULL only
 * if every one of MUD_PATH_MAX slots is already a distinct active group --
 * unreachable in practice (that many distinct physical links on one tunnel
 * is not a real deployment), but callers still treat it as "no group
 * tracking for this path right now" rather than assuming success. Always
 * called with state_lock already held, same as mud_path_same_group()'s own
 * callers. */
static struct mud_group *
mud_group_get(struct mud *mud, struct mud_path *path)
{
    struct mud_group *free_slot = NULL;

    for (unsigned i = 0; i < MUD_PATH_MAX; i++) {
        struct mud_group *grp = &mud->groups[i];

        if (!grp->active) {
            if (!free_slot)
                free_slot = grp;
            continue;
        }
        if (path->conf.local_ifindex || grp->local_ifindex) {
            if (path->conf.local_ifindex != grp->local_ifindex)
                continue;
        } else if (mud_cmp_addr(&path->conf.local, &grp->local)) {
            continue;
        }
        if (!mud_cmp_addr(&path->conf.remote, &grp->remote))
            return grp;
    }
    if (!free_slot) {
        return NULL;
    }

    free_slot->active = 1;
    free_slot->local_ifindex = path->conf.local_ifindex;
    free_slot->local = path->conf.local;
    free_slot->remote = path->conf.remote;
    return free_slot;
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
        /* Deliberately not matching on `sock` here, unlike the ifindex-
         * based loop above -- on this passive/legacy side, the shared local
         * port means (local address, remote address, remote port) alone
         * already uniquely identifies a flow, so `sock` adds no real
         * discrimination. It used to be harmless to include anyway, back
         * when a passive path's sock never changed after creation; now
         * that mud_path_promote() deliberately moves a path from its
         * original reserved socket to a dedicated one, requiring sock to
         * still match made a stray packet -- one that arrives on the old
         * reserved socket, or on a different reserved-pool member due to a
         * SO_REUSEPORT group-resize reshuffle mid-promotion -- fail this
         * lookup and spawn a duplicate path for the same remote. Confirmed
         * live: exactly this, once, during a 16-sub-flow bring-up burst.
         * Dropping it here is safe: the active/`via IFACE` side (the loop
         * above) is untouched, and that is the one case where `sock` is
         * load-bearing -- a client's `connections N` sub-flows all share
         * one remote (the server), so only the client's own differing
         * local socket tells them apart there. */
        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            if (path->conf.state == MUD_EMPTY ||
                path->conf.local_ifindex ||
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
    /* auto-adjusting (not pinned) by default -- an operator who explicitly
     * wants a fixed rate says so with `rate fixed` (see src/path.c), which
     * overwrites this via mud_set_path()'s own conf->fixed_rate handling.
     * Was 1 (pinned): with tx_max_rate also starting at 0 (no configured
     * ceiling, meant as "uncapped") and tx.rate seeded to that same 0
     * below, mud_update_rl()'s AIMD growth (gated on !fixed_rate) and its
     * observed-rate branch never ran, and its trailing ceiling clamp
     * forced tx.rate back down to the "uncapped" tx_max_rate of 0 even on
     * the rare tick something else set it -- a real, silent deadlock: a
     * path with no explicit `rate tx` ever configured on either end could
     * never carry a single real data packet (mud_select_path() skips any
     * path with a zero select_weight, itself derived from tx.rate), while
     * beats -- sent via a direct path reference, not mud_select_path() --
     * kept exchanging normally, so RTT and status stayed healthy the
     * whole time with zero visible sign that real traffic was 100% lost.
     * Confirmed live on paired VMs: a path brought up with no `rate`
     * flag at all dropped every single packet (ping, TCP, everything)
     * until a rate was explicitly set. */
    path->conf.fixed_rate = 0;
    path->conf.loss_limit = 255;
    path->status          = MUD_PROBING;
    /* Same "0 == uncapped" deadlock applies to the rate itself: seeded
     * here rather than left at the memset's 0 so a fresh, unconfigured
     * path has an actual nonzero rate to advertise/select on from its
     * very first packet, instead of needing preexisting real traffic to
     * bootstrap a rate that real traffic itself requires to be selected
     * in the first place. Ignored entirely for a path with an explicit
     * `rate tx` ceiling -- mud_set_path() overwrites this with that
     * value before any packet ever uses it. */
    path->tx.rate          = MUD_TX_RATE_INITIAL;
    path->idle            = mud_now(mud);
    path->created         = path->idle;

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
#if defined SO_REUSEPORT
        /* Lets mud_create() open several sockets bound to the same local
         * port (see its own comment) instead of just one -- harmless here
         * for a connections-N sub-flow socket, which always binds an
         * OS-assigned ephemeral port of its own and so never actually
         * shares a port with anything. */
        (mud_sso_int(fd, SOL_SOCKET, SO_REUSEPORT, 1)) ||
#endif
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

    /* Verified directly: the passive side of a tunnel never calls
     * mud_set_sock_count() (it doesn't know in advance how many sub-flows
     * the peer will use), so without this it always has exactly one
     * socket -- meaning mud_worker_loop()'s per-worker socket
     * partitioning (see its own comment) has nothing to partition, and
     * every inbound packet, from every one of the peer's connections-N
     * sub-flows, is received and decrypted by whichever single worker
     * thread owns that one socket. Measured on real hardware: one core
     * pegged while the others sat mostly idle, regardless of how many
     * sub-flows the sender used or how evenly connections-N divided
     * across worker threads -- the sender-side fixes for that (matching
     * connections to worker count) don't touch this at all, since the
     * bottleneck is entirely on the receiving side.
     *
     * Opening mud_worker_count() sockets here instead of one, all bound
     * to the same resolved local port via SO_REUSEPORT, lets the kernel
     * itself spread inbound packets across them by hashing each packet's
     * own source address/port -- the same technique high-throughput UDP
     * servers (DNS, QUIC) use for multi-core receive scaling. A given
     * remote peer's packets consistently land on the same one of these
     * sockets (kernel-guaranteed per-flow consistency), and
     * mud_get_path() already stores whichever socket index a path was
     * first discovered on (see its own `sock` parameter) and keeps using
     * it for replies -- so this needs no change anywhere else: existing
     * per-worker socket ownership starts doing real work on every one of
     * these sockets instead of just index 0.
     *
     * Every socket after the first binds to `addr`, already updated by
     * the getsockname() above to the concrete resolved port (needed for
     * the common "bind to port 0, let the OS pick one" case) rather than
     * whatever the caller originally requested. Best-effort and capped by
     * mud_worker_count() (at most MUD_WORKERS_EXPLICIT_MAX, well under
     * MUD_SOCK_MAX): if SO_REUSEPORT isn't available on this platform, or
     * opening an additional socket fails for any reason, this simply
     * keeps whatever it already has rather than failing tunnel creation
     * over a scaling improvement the original single socket never
     * needed. A path with no explicit sub-flow configuration always sends
     * via socket 0 regardless of how many of these exist (see struct
     * mud_path_conf.sock's own default), so this is transparent to that
     * case.
     *
     * NOT transparent to a caller that also uses connections N to build
     * its own numbered sub-flow sockets on this same instance (glorytun's
     * active side does, via src/bind.c's connections=N fan-out): that
     * code relies on every sock index it hands out being its own genuinely
     * distinct local port, since that's what lets the peer tell sub-flows
     * apart at all -- and these sockets are deliberately the opposite, all
     * sharing one port on purpose. Handing out indices from this reserved
     * range to a connections=N group would silently collapse those
     * sub-flows into one from the peer's point of view (identical source
     * port). src/bind.c's own fan-out is responsible for skipping this
     * reserved prefix -- it asks mud_get_sock_count() right after
     * mud_create() returns rather than assuming any particular size, so
     * it stays correct regardless of the multiplier below. See its own
     * comment where it computes `base_sock`, right next to the
     * SO_REUSEPORT-collision bug that section exists to prevent, found by
     * testing this exact interaction on paired VMs before this comment
     * did. This file has no visibility into what a caller intends to do
     * with sock indices later, so it cannot enforce that on its own.
     *
     * mud_worker_count() sockets is the minimum useful number -- one per
     * worker thread -- but not necessarily enough on its own: the kernel
     * spreads inbound packets across these sockets by hashing each one's
     * *remote* address/port, and a real deployment routinely has many more
     * distinct remote sub-flows than local worker threads (e.g. two
     * physical links each split connections=8 is 16 remote sub-flows
     * arriving at, say, a 4-worker box). Hashing 16 things into only 4
     * bins produces real, sometimes large, per-bin variance even with a
     * good hash -- confirmed live: even after this fix existed, one
     * worker still measured roughly 3x another's CPU load in exactly this
     * shape of deployment. Scaling the socket count well past the worker
     * count gives the kernel many more bins to spread the same remote
     * sub-flows across; each worker still ends up owning several of them
     * (mud_worker_loop()'s existing striding), and the *sum* over several
     * bins per worker has much lower relative variance than a single
     * bin's share did, by the same law-of-large-numbers reasoning that
     * makes averaging over more samples more stable. MUD_REUSEPORT_SCALE
     * is a fixed multiplier rather than sized to the actual remote
     * sub-flow count because this side has no way to know that count in
     * advance -- it's whatever connections=N the peer independently
     * chooses, possibly changed at runtime long after this socket pool is
     * created. */
    /* Clamped to at most a quarter of MUD_SOCK_MAX, guaranteeing at least
     * three-quarters of the socket-index space stays available for real
     * connections=N sub-flows no matter how MUD_WORKERS_MAX or
     * MUD_REUSEPORT_SCALE get tuned later -- both are compile-time
     * constants today (32 and 16, a worst case of 512, well under this
     * clamp at MUD_SOCK_MAX=4096), but this file has no way to enforce
     * that relationship stays safe on its own if either changes down the
     * line, and src/bind.c's connections=N fan-out (see its own
     * base_sock comment) depends entirely on this reservation never
     * eating the space it needs. Belt-and-suspenders for the exact class
     * of bug this session already found and fixed once. */
    const unsigned int want_sock_unclamped =
        mud_worker_count() * MUD_REUSEPORT_SCALE;
    const unsigned int want_sock = (want_sock_unclamped > MUD_SOCK_MAX / 4)
                                  ? MUD_SOCK_MAX / 4
                                  : want_sock_unclamped;

    while (mud->sock_count < want_sock) {
        int fd = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

        if ((fd == -1) ||
            (mud_setup_socket(fd, v4, v6)) ||
            (bind(fd, &addr->sa, addrlen))) {
            if (fd != -1)
                close(fd);
            break;
        }
        mud->sock[mud->sock_count] = fd;
        mud->sock_count++;
    }
    mud->passive_pool_size = mud->sock_count;

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

static inline void
mud_store32(unsigned char *dst, uint32_t v)
{
    dst[0] = (unsigned char)v;
    dst[1] = (unsigned char)(v >> 8);
    dst[2] = (unsigned char)(v >> 16);
    dst[3] = (unsigned char)(v >> 24);
}

static inline uint32_t
mud_load32(const unsigned char *src)
{
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

/* True if a data packet whose (sender's-clock) timestamp is `t` falls in a
 * stamping period that began at `start` (0 = never). The very same test is
 * made by the sender, on the exact timestamp it is about to write, and by
 * the receiver, on the timestamp it reads -- so both always agree whether a
 * given packet carries a sequence number, with no per-packet flag and no
 * clock agreement between the two ends (both values are the sender's own
 * clock). */
static inline int
mud_seq_active(uint64_t start, uint64_t t)
{
    return start && MUD_TIME_MASK(t - start) < MUD_TIME_HALF;
}

/* Best-effort classification of a tunneled IP packet's inner protocol --
 * used only to decide whether a packet is eligible for this tunnel's own
 * strict sequence-number resequencing (mud_seq_insert()/mud_seq_flush()),
 * never for anything that needs to be exactly right for correctness.
 *
 * TCP already carries its own sequence numbers, retransmission and (with
 * SACK, which is effectively universal today) a reordering tolerance tuned
 * by decades of real-world use. Layering this tunnel's own strict ordering
 * on top of that measurably hurt TCP throughput in testing -- see
 * "Sequence numbers" in glorytun-notes.html -- even though it eliminated
 * the false-retransmit problem resequencing exists to fix in the first
 * place (out-of-order arrival, from mud_select_path()'s per-packet
 * striping, misread by TCP as loss): TCP's own congestion control reacts
 * worse to the added tail latency of a released backlog than it does to an
 * occasional false retransmit. UDP and everything else has no such
 * built-in tolerance, so it is exactly what benefits from strict
 * resequencing while paying none of TCP's downside. A TCP packet excluded
 * this way still gets the older RTT-derived hold (mud_reorder_insert()) if
 * reorder_window is set -- it is not left completely unresequenced.
 *
 * Deliberately conservative, in the direction that costs nothing: anything
 * not confidently identified as TCP -- too short to hold a full IP header,
 * an unrecognized IP version, or an IPv6 packet whose immediate next-header
 * isn't TCP (a true extension-header chain is not walked) -- is treated as
 * NOT TCP, i.e. eligible for stamping, exactly like every packet already
 * was before this existed. Getting the classification wrong never affects
 * correctness or which bytes are delivered, only which of two already-safe
 * paths a packet takes: at worst a TCP packet gets stamped like UDP
 * (already extensively tested), or a non-TCP packet falls back to the RTT
 * hold (also already-tested, safe behavior either way). */
static inline int
mud_is_tcp(const unsigned char *ip, size_t size)
{
    if (!size)
        return 0;

    const unsigned char version = ip[0] >> 4;

    if (version == 4)
        return size > 9 && ip[9] == 6;

    if (version == 6)
        return size > 6 && ip[6] == 6;

    return 0;
}

static size_t
mud_encrypt(struct mud *mud, uint64_t now,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    /* Sequence number for the peer's resequencing buffer, appended to the
     * plaintext (so it is encrypted and authenticated with the packet).
     * Only while the peer has asked for them -- otherwise this packet is
     * byte-for-byte what it always was. The copy is the price of not
     * requiring every caller to leave room after its plaintext. */
    unsigned char stamped[MUD_PKT_MAX_SIZE];

    if (mud_seq_active(MUD_ALOAD(&mud->seq_tx_start), now) &&
        !mud_is_tcp(src, src_size)) {
        if (src_size + MUD_SEQ_SIZE + MUD_PKT_MIN_SIZE > dst_size ||
            src_size + MUD_SEQ_SIZE > sizeof(stamped))
            return 0;

        memcpy(stamped, src, src_size);
        mud_store32(stamped + src_size,
                    __atomic_fetch_add(&mud->seq_tx_next, 1, __ATOMIC_RELAXED));
        src = stamped;
        src_size += MUD_SEQ_SIZE;
    }
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

    /* Optional sequence-number block after the fixed message: "I want
     * numbers" (we resequence what we receive) and "I stamp from time T".
     * Omitted entirely -- message size and contents unchanged -- unless one
     * of the two applies, so with reorderwindow off nothing on the wire
     * differs from a build without this. */
    const unsigned int seq_want = mud->conf.reorder_window ? MUD_SEQ_FLAG_WANT : 0;
    const uint64_t seq_start = MUD_ALOAD(&mud->seq_tx_start);

    if (seq_want || seq_start) {
        const size_t need = MUD_PKT_MIN_SIZE + sizeof(struct mud_msg) +
                            MUD_SEQ_EXT_SIZE;
        unsigned char *ext = src + sizeof(struct mud_msg);

        if (size < need)
            size = need;
        ext[0] = (unsigned char)seq_want;
        mud_store(ext + 1, seq_start, MUD_TIME_SIZE);
    }

    /* Probe sequence number for a monitor path (see "Probe-based path
     * health" above MUD_PROBE_INTERVAL_DEFAULT). Always placed right after
     * the MUD_SEQ_EXT_SIZE gap, whether or not the sequence-numbering block
     * above actually wrote anything into it -- src[] starts zeroed, so an
     * inactive gap here is just harmless padding, and both this sender and
     * the receiver agree on a fixed offset regardless of reorder_window
     * state instead of one extension's presence shifting the other's
     * position. */
    if (path->conf.monitor) {
        const size_t need = MUD_PKT_MIN_SIZE + sizeof(struct mud_msg) +
                            MUD_SEQ_EXT_SIZE + MUD_PROBE_EXT_SIZE;
        unsigned char *ext = src + sizeof(struct mud_msg) + MUD_SEQ_EXT_SIZE;

        if (size < need)
            size = need;
        mud_store32(ext, path->probe.tx_next++);

        /* Piggyback this side's own current reading of the group (how well
         * *we're* receiving from the peer) so the peer can use it for its
         * own send/no-send decision about this path -- see the wire-format
         * comment above MUD_PROBE_EXT_SIZE. A brand new group (nothing
         * measured yet) reads 0/healthy here for a probe interval or two
         * until real measurement catches up -- harmless, self-correcting,
         * same spirit as every other "not yet warmed up" edge case in this
         * file. */
        struct mud_group *grp = mud_group_get(mud, path);

        ext[4] = grp ? (unsigned char)grp->probe_loss_pub : 0;
        ext[5] = (grp && grp->probe_degraded) ? 1 : 0;
    }

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

    msg->pref = path->conf.pref;
    msg->fixed_rate = path->conf.fixed_rate;
    msg->loss_limit = path->conf.loss_limit;
    msg->monitor = path->conf.monitor;
    MUD_STORE_MSG(msg->probe_interval, path->conf.probe_interval
                                      ? path->conf.probe_interval
                                      : MUD_PROBE_INTERVAL_DEFAULT);

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

static void
mud_update_rl(struct mud_path *path, uint64_t tx_dt, uint64_t tx_bytes,
              uint64_t rx_dt, uint64_t rx_bytes)
{
    /* Byte-counter tx-loss tracking used to live in this branch -- removed
     * entirely (not just skipped): with `monitor` mandatory on every path
     * (see "Probe-based path health" above mud_probe_loss_255()), nothing
     * ever reads it again, and computing a number nothing consults costs
     * real cycles on every single control message for no benefit. Rate
     * adaptation below is unrelated to loss tracking and always runs
     * regardless -- unchanged. */
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {
        if (!path->conf.fixed_rate)
            path->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
    } else {
        if (!path->conf.fixed_rate)
            path->tx.rate += path->tx.rate / 10;
    }
    /* tx_max_rate == 0 means "no operator-configured ceiling", not "cap
     * of zero" -- see mud_get_path()'s own comment for the real, silent
     * deadlock this distinction fixes (every tick otherwise forced
     * tx.rate straight back down to zero, permanently, for any path
     * with no explicit `rate tx` ceiling). */
    if (path->conf.tx_max_rate && path->tx.rate > path->conf.tx_max_rate)
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

/* Probe-based path health: how mud_path_update() decides whether a physical
 * link is healthy. This tunnel used to also infer loss from byte counters
 * riding on data-driven traffic (tx-loss/rx-loss) as a fallback for groups
 * with no monitor configured; that mechanism -- and the fallback -- have
 * been removed entirely, since `monitor` is mandatory on every path now
 * (see glorytun-notes.html's "Probe-based path health" section for the full
 * history, including what that byte-counter mechanism's inherently variable
 * timing caused in practice -- beat cadence backs off when idle, echoed
 * totals lag a round trip, multiple sub-flows' catch-up events can land in
 * the same pooled bucket). A monitor path (see struct mud_path_conf's own
 * `monitor` field) sends a tiny sequence-numbered probe on a genuinely
 * fixed interval, and each side independently counts gaps in what it
 * *receives* -- no echo, no round trip, no dependency on real data traffic
 * existing at all. Reuses struct mud_msg wholesale as the carrier (see
 * MUD_PROBE_EXT_SIZE above) purely to avoid a second wire format; the loss
 * unit here is "how many of the last N sequence numbers arrived", not
 * bytes. */

/* Recomputes the current loss fraction (0-255 scale, same convention as
 * every other loss figure in this file) directly from path->probe.seen[],
 * looking back `window` sequence numbers from the next-expected one. Cheap
 * (at most MUD_PROBE_RING_SIZE iterations, and window is clamped to that)
 * and deliberately recomputed from scratch on every call rather than
 * incrementally maintained -- there is no hot path here to protect (a probe
 * arrives on the order of once a second, not once a packet), and computing
 * it fresh means there is no separate running-total invariant that could
 * ever drift out of sync with the ring it's supposedly summarizing. */
static unsigned
mud_probe_loss_255(struct mud_path *path, unsigned window)
{
    if (!window || window > MUD_PROBE_RING_SIZE)
        window = MUD_PROBE_WINDOW_DEFAULT;

    const unsigned actual = (path->probe.rx_next < window)
                           ? path->probe.rx_next : window;
    if (!actual)
        return 0;

    unsigned missed = 0;

    for (unsigned i = 0; i < actual; i++) {
        const uint32_t seq = path->probe.rx_next - 1 - i;

        if (!path->probe.seen[seq % MUD_PROBE_RING_SIZE])
            missed++;
    }
    return missed * 255U / actual;
}

/* Publishes `loss255` onto this path's group and updates the fast-degrade/
 * slow-recover latch mud_path_update() reads (see struct mud_group's own
 * comment on probe_degraded). Called both from mud_probe_recv() below (a
 * genuine probe just arrived) and from mud_path_track()'s per-tick check
 * (a monitor path has gone completely silent, not just lossy -- see that
 * call site's own comment for why the ring alone can't catch that case). */
static void
mud_probe_publish(struct mud *mud, struct mud_path *path, uint64_t now,
                  unsigned loss255)
{
    struct mud_group *grp = mud_group_get(mud, path);

    if (!grp)
        return;

    grp->probe_has_monitor = 1;
    grp->probe_loss_pub = loss255;

    if (loss255 > path->conf.loss_limit) {
        grp->probe_degraded = 1;
        grp->probe_good_since = 0;
        return;
    }
    if (!grp->probe_good_since)
        grp->probe_good_since = now;

    if (grp->probe_degraded) {
        const uint64_t recover = path->conf.probe_recover
                                ? path->conf.probe_recover
                                : MUD_PROBE_RECOVER_DEFAULT;

        if (mud_timeout(now, grp->probe_good_since, recover))
            grp->probe_degraded = 0;
    }
}

/* Applies a peer-reported (loss255, degraded) pair -- what the peer's own
 * monitor last told us about receiving from *us* -- onto this path's group.
 * Deliberately adopts `peer_degraded` directly, with no fast-degrade/slow-
 * recover of its own layered on top: the peer already ran its own
 * mud_probe_publish() hysteresis before ever putting this verdict on the
 * wire, so re-debouncing an already-debounced decision here would just be
 * double smoothing -- confirmed live, it was adding the peer's own
 * proberecover delay on top of ours, roughly doubling how long a fresh
 * group took to ever reach healthy. Staleness (the peer's reports going
 * quiet, not just one saying "degraded") is guarded separately, by
 * peer_report_seq's ordering check in mud_probe_recv() and by
 * mud_path_track()'s own per-tick timeout below -- this function only
 * needs to trust whatever verdict actually arrives. Called from
 * mud_probe_recv() (a genuine report just arrived, piggybacked on this
 * probe) and from mud_path_track()'s own per-tick check (the peer's
 * reports have gone stale -- see that call site's own comment). */
static void
mud_group_peer_report(struct mud *mud, struct mud_path *path, uint64_t now,
                      unsigned peer_loss255, int peer_degraded)
{
    struct mud_group *grp = mud_group_get(mud, path);

    if (!grp)
        return;

    grp->peer_probe_last = now;
    grp->peer_probe_loss_pub = peer_loss255;
    grp->peer_probe_degraded = peer_degraded ? 1 : 0;
}

/* Feeds one freshly received probe sequence number into path->probe (see
 * its own comment in mud.h). Three cases: the very first probe this path
 * has ever seen (adopt it as the baseline -- handles a peer that started
 * after this side did, same spirit as mud_get_path()'s own passive-path
 * handling); a plain gap-free or reordered-but-still-in-window arrival
 * (mark it seen, marking anything skipped over as missed); or a gap/
 * reversal too large to be routine reordering, which can only mean the
 * peer restarted its own counter from zero -- resynced the same as the
 * first-ever case, rather than either reading a restarted peer's small
 * seq as an enormous multi-hundred-slot loss or leaving stale pre-restart
 * history mixed into the window. */
static void
mud_probe_recv(struct mud *mud, struct mud_path *path, uint64_t now,
               uint32_t seq, unsigned peer_loss255, int peer_degraded)
{
    if (!path->probe.rx_sync) {
        path->probe.rx_sync = 1;
        memset(path->probe.seen, 0, sizeof(path->probe.seen));
        path->probe.seen[seq % MUD_PROBE_RING_SIZE] = 1;
        path->probe.rx_next = seq + 1;
    } else if (seq + 1 == path->probe.rx_next) {
        /* replay of the most recent one -- nothing new to record */
    } else if (seq < path->probe.rx_next &&
               path->probe.rx_next - seq <= MUD_PROBE_RING_SIZE) {
        /* late/reordered arrival still within the window: correct its slot
         * from "missed" to "seen" rather than leaving a false gap */
        path->probe.seen[seq % MUD_PROBE_RING_SIZE] = 1;
    } else if (seq >= path->probe.rx_next &&
               seq - path->probe.rx_next < MUD_PROBE_RING_SIZE) {
        for (uint32_t s = path->probe.rx_next; s != seq; s++)
            path->probe.seen[s % MUD_PROBE_RING_SIZE] = 0;
        path->probe.seen[seq % MUD_PROBE_RING_SIZE] = 1;
        path->probe.rx_next = seq + 1;
    } else {
        memset(path->probe.seen, 0, sizeof(path->probe.seen));
        path->probe.seen[seq % MUD_PROBE_RING_SIZE] = 1;
        path->probe.rx_next = seq + 1;
    }
    path->probe.rx_last = now;

    const unsigned window = path->conf.probe_window
                           ? (unsigned)path->conf.probe_window : 0;

    mud_probe_publish(mud, path, now, mud_probe_loss_255(path, window));

    /* Only adopt the piggybacked peer report if this probe's own seq is
     * newer than the one we last adopted a report from -- a reordered,
     * lower-numbered probe arriving late must not be allowed to overwrite a
     * report from a probe we've already applied. But a regression larger
     * than MUD_PEER_REPORT_REORDER_MAX can only mean the peer's own seq
     * counter restarted from zero, same reasoning as this function's own
     * rx_next/seen[] restart case above -- ordinary reordering at a probe
     * cadence of at most 1/s never regresses by more than a handful of
     * slots. Deliberately its own small, purpose-specific tolerance rather
     * than reusing MUD_PROBE_RING_SIZE (sized for the loss ring's own
     * in-window reordering tolerance, up to 10 minutes' worth): gating this
     * resync behind that much larger threshold would let a restart
     * happening within the first MUD_PROBE_RING_SIZE seconds of a fresh
     * connection masquerade as routine reordering, delaying the resync by
     * up to that same 10 minutes instead of resyncing on the very next
     * probe -- confirmed live, a restart minutes into a freshly-settled
     * test tunnel took far longer than proberecover to clear because of
     * exactly this. Signed subtraction the same wrap-safe way the rest of
     * this function reasons about seq gaps. */
    const int32_t report_diff = (int32_t)(seq - path->probe.peer_report_seq);

    if (!path->probe.peer_report_sync || report_diff > 0 ||
        -report_diff > (int32_t)MUD_PEER_REPORT_REORDER_MAX) {
        path->probe.peer_report_sync = 1;
        path->probe.peer_report_seq = seq;
        mud_group_peer_report(mud, path, now, peer_loss255, peer_degraded);
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

    /* Sequence-number block (see MUD_SEQ_EXT_SIZE). Handled before anything
     * else here -- this runs before the key exchange below can complete, so a
     * restarted peer's "not stamping" always lands before any of its data
     * packets can even be decrypted. A message without the block (older
     * build, or reorderwindow off at the peer) reads as "doesn't want
     * numbers, isn't stamping". */
    {
        const size_t plain = size - MUD_PKT_MIN_SIZE;
        unsigned int flags = 0;
        uint64_t start = 0;

        if (plain >= sizeof(struct mud_msg) + MUD_SEQ_EXT_SIZE) {
            const unsigned char *ext = data + sizeof(struct mud_msg);

            flags = ext[0];
            start = mud_load(ext + 1, MUD_TIME_SIZE);
        }
        if (flags & MUD_SEQ_FLAG_WANT) {
            /* Start stamping a little in the future (MUD_SEQ_LEAD) so the
             * peer has heard our start time before the first stamped packet
             * reaches it. Once started, leave it alone. */
            if (!MUD_ALOAD(&mud->seq_tx_start)) {
                uint64_t st = MUD_TIME_MASK(now + MUD_SEQ_LEAD);

                MUD_ASTORE(&mud->seq_tx_start, st ? st : 2);
            }
        } else if (MUD_ALOAD(&mud->seq_tx_start)) {
            MUD_ASTORE(&mud->seq_tx_start, 0);
        }
        if (MUD_ALOAD(&mud->seq_rx_start) != start) {
            MUD_ASTORE(&mud->seq_rx_start, start);
            pthread_mutex_lock(&mud->reorder.lock);
            mud->reorder.seq_sync = 0; /* new stream: adopt its numbering */
            pthread_mutex_unlock(&mud->reorder.lock);
        }
    }

    /* Probe sequence number (see MUD_PROBE_EXT_SIZE and "Probe-based path
     * health" above mud_probe_loss_255()) -- always at this fixed offset
     * regardless of whether the sequence-numbering block just above is
     * actually in use, same reasoning as mud_send_msg()'s own write side.
     * Only meaningful, and only ever sent, on a path configured `monitor`
     * on at least one end; a plain data/beat sub-flow's peer never writes
     * anything here, so this simply never fires for one. */
    if (path->conf.monitor &&
        size - MUD_PKT_MIN_SIZE >=
            sizeof(struct mud_msg) + MUD_SEQ_EXT_SIZE + MUD_PROBE_EXT_SIZE) {
        const unsigned char *ext = data + sizeof(struct mud_msg) +
                                   MUD_SEQ_EXT_SIZE;

        mud_probe_recv(mud, path, now, mud_load32(ext), ext[4], ext[5]);
    }

    if (tx_time) {
        mud_update_stat(&path->rtt, MUD_TIME_MASK(now - tx_time));

        const uint64_t tx_bytes = MUD_LOAD_MSG(msg->fw.bytes);
        const uint64_t tx_total = MUD_LOAD_MSG(msg->fw.total);
        const uint64_t rx_bytes = MUD_LOAD_MSG(msg->rx.bytes);
        const uint64_t rx_total = MUD_LOAD_MSG(msg->rx.total);
        const uint64_t rx_time  = sent_time;

        /* See `confirmed_live`'s own comment (mud.h) -- tx_time is this
         * message's echo of an earlier outer packet timestamp *we*
         * (mud_send_msg()) wrote using our own mud_now(), so tx_time >=
         * created can only hold if the peer actually received and replied
         * to something sent after this path was created on this side. A
         * dead peer's own kernel can still flush already-queued packets
         * for a surprisingly long time after the process exits (confirmed
         * live, well over a second in one trial), but none of those carry
         * a timestamp from after their sender died -- so this is immune
         * to that, unlike a plain elapsed-time-since-creation check. */
        if (tx_time >= path->created)
            path->confirmed_live = 1;

        /* tx_total/rx_total (packet counts, used below only to gate the
         * mud_update_rl() rate-adaptation call and the baseline updates
         * that follow it) must also be checked here, not just
         * tx_bytes/rx_bytes -- confirmed live in production: they are NOT
         * guaranteed to move together. tx_total in particular arrives via
         * an echo (msg->fw.total, the peer's own re-transmission of an
         * earlier tx.total we told it) rather than directly, one extra
         * round trip removed from tx_bytes -- and control messages ride
         * the same per-packet-striped paths as data (see "Packet
         * resequencing" earlier in glorytun-notes.html), so they are
         * exactly as subject to arriving out of send order. A message
         * whose echoed tx_total is momentarily behind what's already been
         * recorded, while tx_bytes/tx_time/rx_bytes/rx_time all still
         * happen to look forward-moving, used to pass this guard anyway --
         * and every field below is unsigned, so `tx_total -
         * path->msg.tx.total` doesn't go negative, it wraps to a number
         * near UINT64_MAX. Back when this fed the now-removed byte-counter
         * tx-loss tracker as this path's "sent" count against a real, small
         * "received" count, that used to read as ~100% loss for one window,
         * sitting in the rolling tracker until it aged out ~60 seconds
         * later -- confirmed live: multiple sub-flows, and both group
         * figures pooling them, spiking to ~99% loss for minutes at a time
         * in production despite the tunnel otherwise working normally
         * throughout. The removed rx-loss check used to guard both of its
         * own two fields (peer_tx_total and peer_tx_bytes) for exactly this
         * reason; this one only ever checked one of its two -- fixed here
         * regardless of that tracker's later removal, since the guard below
         * still needs both totals to move forward before trusting them for
         * the baseline updates and the rate-adaptation call. */
        if ((tx_time > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (tx_total > path->msg.tx.total) &&
            (rx_time > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes) &&
            (rx_total > path->msg.rx.total)) {
            if (path->msg.set && path->status > MUD_PROBING) {
                mud_update_rl(path,
                        MUD_TIME_MASK(tx_time - path->msg.tx.time),
                        tx_bytes - path->msg.tx.bytes,
                        MUD_TIME_MASK(rx_time - path->msg.rx.time),
                        rx_bytes - path->msg.rx.bytes);
            }
            path->msg.tx.time = tx_time;
            path->msg.rx.time = rx_time;
            path->msg.tx.bytes = tx_bytes;
            path->msg.rx.bytes = rx_bytes;
            path->msg.tx.total = tx_total;
            path->msg.rx.total = rx_total;
            path->msg.set = 1;
        }
        /* Byte-counter rx-loss tracking used to live here -- removed
         * entirely, same reasoning as the matching removal in
         * mud_update_rl(): with `monitor` mandatory on every path, nothing
         * ever reads it again. */
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
        path->conf.monitor = msg->monitor;
        path->conf.probe_interval = MUD_LOAD_MSG(msg->probe_interval);

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

/* Gives a freshly (passively) discovered remote sub-flow its own OS-level
 * socket, connect()ed to that exact remote address, instead of leaving it
 * sharing one of mud_create()'s wildcard SO_REUSEPORT sockets forever.
 * Which wildcard socket a given remote's packets land on (and therefore
 * which worker thread ends up owning all of that sub-flow's processing --
 * see mud_worker_loop()'s `i % worker_count` partitioning) is decided by
 * the kernel's own hash of the packet's source address/port, not by
 * anything this program controls; with a small, fixed number of real
 * remote sub-flows spread across that many independent worker-owned socket
 * groups, that hash can easily leave one worker with zero real flows while
 * another gets several -- confirmed live: an 8-worker box with 16 real
 * sub-flows left one worker at ~0% CPU and another at ~83%, purely from
 * hash luck (see glorytun-notes.html's scaling section).
 *
 * Linux's UDP socket lookup prefers an exact 4-tuple match (a fully
 * connect()ed socket) over the reuseport hash across wildcard sockets in
 * the same group, so once this succeeds, every future packet from this
 * exact remote is delivered straight to the new socket -- bypassing the
 * hash (and its imbalance) entirely, with no ongoing per-packet cost. The
 * new socket is appended at the next sock_count index, so the existing
 * `i % worker_count` ownership rule automatically hands each successively-
 * discovered remote sub-flow the next worker in round-robin order -- the
 * same guarantee src/bind.c's own `connections N` fan-out already gives
 * the active side, now extended to the passive side's own discoveries.
 *
 * Best-effort and silent on failure: the path just stays on its original
 * reserved socket, exactly as it did before this existed -- never treated
 * as fatal. Caller must already hold state_lock (mirrors mud_get_path()'s
 * own contract) and must only call this for a path still on one of
 * mud_create()'s own reserved sockets (see mud->passive_pool_size) --
 * promoting an already-dedicated `via IFACE` sub-flow socket would just
 * waste an fd for no benefit, since those already have their own unique
 * port and no hash-driven ambiguity to fix.
 *
 * Deliberately called from mud_path_update() (the housekeeping thread's
 * once-per-tick sweep, see mud_update()) once a passive path first proves
 * genuine two-way liveness (reaches this function's own `return 1`, i.e.
 * status settles at MUD_READY or MUD_RUNNING), not from mud_recv_finish()
 * on the very first packet. mud->sock[] is append-only by design (see
 * struct mud's own comment: a worker thread's already-read fd can never be
 * invalidated by another thread resizing the array underneath it), so
 * nothing ever closes a promoted socket even after mud_path_update()'s own
 * 5-minute idle reap clears the *path* it belonged to -- promoting on
 * first sight, as this used to, meant a single decrypt-successful stray
 * packet (a peer restarted from a killed process with packets still
 * in-flight, a scan, anything that never develops into a real
 * conversation) permanently leaked one fd for the life of the process,
 * bounded only by MUD_PATH_MAX. A one-off packet's path never reaches
 * status better than MUD_WAITING once any other real traffic is flowing
 * (mud_path_update()'s own MUD_PASSIVE-waiting check trips within a few
 * beat intervals, well before the 5-minute reap), so gating promotion on
 * genuine liveness here means a fd is only ever spent on a flow that's
 * actually going to use it. Confirmed live: the exact ghost-path/leaked-fd
 * scenario above, reproduced with a killed-and-restarted peer. */
static void
mud_path_promote(struct mud *mud, struct mud_path *path, unsigned int old_sock)
{
    if (mud->sock_count >= MUD_SOCK_MAX)
        return;

    const int old_fd = (old_sock < mud->sock_count) ? mud->sock[old_sock] : -1;

    if (old_fd < 0)
        return;

    union mud_sockaddr local;
    socklen_t local_len = sizeof(local);

    memset(&local, 0, sizeof(local));

    if (getsockname(old_fd, &local.sa, &local_len))
        return;

    const int fd = socket(mud->sock_family, SOCK_DGRAM, IPPROTO_UDP);

    if (fd == -1)
        return;

    const socklen_t addrlen = (mud->sock_family == AF_INET)
                             ? sizeof(struct sockaddr_in)
                             : sizeof(struct sockaddr_in6);

    if (mud_setup_socket(fd, mud->sock_v4, mud->sock_v6) ||
        bind(fd, &local.sa, addrlen) ||
        connect(fd, &path->conf.remote.sa, addrlen)) {
        close(fd);
        return;
    }
    /* mud_recv_batch()'s non-Linux fallback calls recvmsg() without
     * MSG_DONTWAIT, relying entirely on O_NONBLOCK already being set on the
     * fd (every other socket in mud->sock[] gets this from its creator --
     * src/bind.c, right after mud_create()/mud_set_sock_count() -- since
     * this socket is instead opened deep inside the housekeeping thread's
     * own tick, that same external step never gets a chance to run on it). */
    const int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        close(fd);
        return;
    }
    mud->sock[mud->sock_count] = fd;
    path->conf.sock = (uint16_t)mud->sock_count;
    mud->sock_count++;
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
                uint64_t *reorder_hold_out, int *stamped_out,
                uint32_t *seq_out)
{
    if (reorder_hold_out)
        *reorder_hold_out = 0;
    if (stamped_out)
        *stamped_out = 0;

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

    size_t ret = MUD_MSG(sent_time)
               ? mud_decrypt_msg(mud, data, data_cap, packet, (size_t)packet_size)
               : mud_decrypt(mud, data, data_cap, packet, (size_t)packet_size);

    /* A data packet sent while its sender was stamping ends in a sequence
     * number; take it off so nothing downstream ever sees it. Whether this
     * packet is one is decided by its own timestamp against the start time
     * the peer announced (see mud_seq_active()), and -- matching the
     * sender's own mud_is_tcp() check in mud_encrypt(), computed here
     * against the same early header bytes regardless of whether a trailing
     * sequence number is actually present -- by its inner protocol not
     * being TCP. */
    uint32_t seq = 0;
    int stamped = 0;

    if (ret && !MUD_MSG(sent_time) &&
        mud_seq_active(MUD_ALOAD(&mud->seq_rx_start), sent_time) &&
        !mud_is_tcp(data, ret)) {
        if (ret > MUD_SEQ_SIZE) {
            seq = mud_load32(data + ret - MUD_SEQ_SIZE);
            ret -= MUD_SEQ_SIZE;
            stamped = 1;
        } else {
            ret = 0; /* claims a number but can't hold one: malformed */
        }
    }

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
    if (stamped_out && stamped) {
        *stamped_out = 1;
        if (seq_out)
            *seq_out = seq;
    }

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
                           data, size, NULL, NULL, NULL);
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
    /* Read against the whole physical link's pooled probe health (see
     * struct mud_group's own comment on probe_degraded), not just this one
     * sub-flow's -- a whole link degrades and recovers together, by design
     * (see "Group loss" and "Probe-based path health" in glorytun-
     * notes.html). `monitor` is mandatory on every path now, so a group
     * with no monitor (misconfiguration) simply never goes LOSSY via this
     * check -- there is no byte-counter fallback anymore.
     * Keyed off peer_probe_degraded (what the peer reports about receiving
     * from us), not probe_degraded (what we ourselves receive from the
     * peer) -- "should I keep sending this way" is a question about the
     * direction we send on, which only the peer can actually measure. See
     * struct mud_group's own comment on peer_probe_degraded for the full
     * reasoning. */
    struct mud_group *grp = mud_group_get(mud, path);

    if (grp && grp->probe_has_monitor && grp->peer_probe_degraded) {
        path->status = MUD_LOSSY;
        return 0;
    }
    if (path->conf.rtt_limit && path->rtt.val > path->conf.rtt_limit) {
        path->status = MUD_LATE;
        return 0;
    }
    /* Excludes conf.monitor: this check's own patience budget
     * (MUD_MSG_SENT_MAX * conf.beat) is sized for a normal data sub-flow's
     * fast, frequent beat -- a monitor's genuinely-once-a-second cadence
     * blows through that budget every single cycle, which used to make a
     * passive side's own monitor row flicker between running/waiting on a
     * steady ~1Hz rhythm even in perfect health (confirmed live). A
     * monitor path doesn't need this check standing in for it any more:
     * mud_path_track()'s own peer-report staleness timeout (see its
     * comment) already detects "this monitor's peer has gone quiet" more
     * precisely -- against the monitor's real probe_interval/probe_window,
     * not the wrong beat-based budget -- and turns it into an actual
     * degraded verdict feeding the real failover decision, not just a
     * cosmetic status word. */
    if (path->conf.state == MUD_PASSIVE && !path->conf.monitor &&
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
    /* Reaching here means this path passed every liveness check above --
     * but that alone does NOT prove it's a real, ongoing conversation
     * rather than a one-off stray packet: the MUD_PASSIVE waiting-check
     * just above only trips once `mud->last_recv_time` has pulled ahead of
     * *this* path's own rx.time by a beat-scaled margin, and a path's
     * rx.time is (by construction) always freshly set at creation -- so on
     * the very first tick after any path is created, that gap is
     * necessarily still ~0, and every fresh path, ghost or genuine, sails
     * through to here regardless.
     *
     * An earlier version of this gate additionally required a fixed
     * multiple of that same beat-scaled margin to have elapsed since
     * creation, reasoning that a one-off path would fail the waiting-check
     * well before such a margin passed. Confirmed live that this is NOT
     * reliable: a killed process's kernel can keep flushing already-queued
     * packets for well over a second (a real trial measured a steady
     * trickle spanning ~20s), which keeps refreshing rx.time often enough
     * to dodge the waiting-check for as long as the trickle lasts,
     * defeating any fixed elapsed-time margin.
     *
     * `confirmed_live` (see its own comment, and mud_recv_msg()'s) is the
     * actual fix: it can only be set by a genuine reply whose echoed
     * timestamp is >= this path's own creation time, which a dead
     * process's queued packets can never produce regardless of how long
     * or how densely they keep trickling out, since none of them can carry
     * a timestamp from after their sender stopped running. A live peer
     * satisfies this within one real round trip (typically single-digit
     * milliseconds), so this is also strictly faster than the elapsed-time
     * version was for the common, genuine case. */
    if (path->conf.state == MUD_PASSIVE &&
        path->conf.sock < mud->passive_pool_size &&
        path->confirmed_live)
        mud_path_promote(mud, path, path->conf.sock);
    return 1;
}

static uint64_t
mud_path_track(struct mud *mud, struct mud_path *path, uint64_t now)
{
    /* Still needed below (single-socket beat backoff) even though the
     * byte-counter loss tracking that used to be the other consumer of
     * this flag has been removed entirely -- `monitor` is mandatory on
     * every path now (see "Probe-based path health" above
     * mud_probe_loss_255()), so nothing tracks a byte-counter tx/rx loss
     * figure at all anymore. */
    path->traffic_idle = mud_timeout(now, path->idle, MUD_ONE_SEC);

    /* Peer-report staleness fallback -- deliberately runs before the
     * MUD_UP-only return just below, so it applies equally to a passive
     * path's own monitor. A passive side has no send-scheduling block of
     * its own (its replies only ever go out in response to hearing from
     * the peer -- see mud_recv_msg()), but its peer can still go silent on
     * it exactly as easily as an active side's peer can, and unlike the
     * local silent-monitor fallback further below (MUD_UP only, since only
     * an active side independently sends on a schedule to time out against),
     * this one has to be symmetric: whichever side stops hearing peer
     * reports needs to stop trusting a stale "peer says I'm healthy"
     * reading, or the send-decision at the top of mud_path_update() would
     * keep using it forever. Same "silence means assume the worst"
     * principle, same probe_window-sized budget, just against
     * peer_probe_last instead of path->probe.rx_last. */
    if (path->conf.monitor) {
        struct mud_group *grp = mud_group_get(mud, path);

        if (grp) {
            const uint64_t interval = path->conf.probe_interval
                                     ? path->conf.probe_interval
                                     : MUD_PROBE_INTERVAL_DEFAULT;
            const uint64_t window = path->conf.probe_window
                                   ? path->conf.probe_window
                                   : MUD_PROBE_WINDOW_DEFAULT;

            if (mud_timeout(now, grp->peer_probe_last, window * interval))
                mud_group_peer_report(mud, path, now, 255, 1);
        }
    }

    if (path->conf.state != MUD_UP)
        return now;

    /* Monitor paths (see struct mud_path_conf's own comment) skip every bit
     * of the ordinary beat scheduling below: they send on a genuinely fixed
     * interval, never backed off the way an idle data sub-flow's beat is
     * (that backoff is exactly the mechanism the probe design exists to
     * avoid being subject to), and their status never needs to reach
     * MUD_RUNNING/MUD_LOSSY/etc. -- mud_select_path() already excludes them
     * from data regardless of status, and their contribution to the
     * degrade decision is grp->peer_probe_degraded, published by
     * mud_group_peer_report() from whatever the peer reports back, not
     * this path's own path->status. */
    if (path->conf.monitor) {
        const uint64_t interval = path->conf.probe_interval
                                 ? path->conf.probe_interval
                                 : MUD_PROBE_INTERVAL_DEFAULT;

        if (mud_timeout(now, path->probe.tx_last, interval)) {
            path->probe.tx_last = now;
            mud_send_msg(mud, path, now, 0, 0, 0, path->mtu);
            now = mud_now(mud);
        }
        /* A silent peer (the whole physical link down, not just lossy)
         * never trips mud_probe_recv()'s gap-filling at all -- nothing
         * arrives to fill a gap with -- so path->probe.seen[] would
         * otherwise sit frozen on whatever it last held, indefinitely,
         * exactly the class of bug the byte-counter mechanism's own per-
         * path idle-aging (just above in this function) exists to prevent.
         * Once a full probe_window's worth of real time has passed with
         * nothing received at all, force the group to 100% rather than
         * leave stale good data live. path->probe.rx_last starting at 0
         * (never yet received anything) is handled the same way by
         * mud_timeout()'s own !last short-circuit -- correctly treated as
         * "already timed out", not "just started", since a monitor path
         * that has NEVER heard from its peer is exactly the silent case
         * this exists to catch. */
        const uint64_t window = path->conf.probe_window
                               ? path->conf.probe_window
                               : MUD_PROBE_WINDOW_DEFAULT;

        if (mud_timeout(now, path->probe.rx_last, window * interval))
            mud_probe_publish(mud, path, now, 255);

        return now;
    }

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

        if (path->status != MUD_RUNNING || path->conf.monitor) {
            path->select_weight = 0;
            continue;
        }
        uint64_t group_total = 0;
        unsigned group_count = 0;

        for (unsigned j = 0; j < mud->capacity; j++) {
            struct mud_path *other = &mud->paths[j];

            /* Excludes monitor siblings too -- their tx.rate never reflects
             * real throughput (mud_select_path() never gives them data to
             * carry), so folding one into this average would understate
             * the group's real capacity by 1/(N+1) for no reason. */
            if (other->status != MUD_RUNNING || other->conf.monitor ||
                !mud_path_same_group(path, other))
                continue;

            group_total += other->tx.rate;
            group_count++;
        }
        path->select_weight = group_count ? group_total / group_count : 0;
        weighted_rate += path->select_weight;
    }
    mud->rate = weighted_rate;

    /* Group RTT aggregation, and mirroring it (plus probe health) onto
     * every member path -- see struct mud_group's own comment. This used to
     * also aggregate/mirror byte-counter tx-loss/rx-loss the same way;
     * removed along with the rest of that mechanism, since `monitor` is
     * mandatory on every path now and mud_path_update() reads
     * grp->peer_probe_degraded directly, fed continuously by
     * mud_probe_recv()/mud_group_peer_report() rather than by anything
     * computed in this pass. */
    for (unsigned i = 0; i < MUD_PATH_MAX; i++) {
        struct mud_group *grp = &mud->groups[i];

        if (grp->active) {
            grp->rtt_sum = 0;
            grp->rtt_count = 0;
        }
    }
    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->status != MUD_RUNNING)
            continue;

        struct mud_group *grp = mud_group_get(mud, path);

        if (!grp)
            continue;
        grp->rtt_sum += path->rtt.val;
        grp->rtt_count++;
    }
    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->conf.state != MUD_UP && path->conf.state != MUD_PASSIVE) {
            path->group_rtt = 0;
            path->group_probe_has_monitor = 0;
            path->group_probe_loss = 0;
            path->group_probe_degraded = 0;
            path->group_peer_probe_loss = 0;
            path->group_peer_probe_degraded = 0;
            continue;
        }
        struct mud_group *grp = mud_group_get(mud, path);

        if (!grp) {
            path->group_rtt = path->rtt.val;
            path->group_probe_has_monitor = 0;
            path->group_probe_loss = 0;
            path->group_probe_degraded = 0;
            path->group_peer_probe_loss = 0;
            path->group_peer_probe_degraded = 0;
            continue;
        }
        path->group_rtt = grp->rtt_count ? grp->rtt_sum / grp->rtt_count
                                          : path->rtt.val;
        path->group_probe_has_monitor = grp->probe_has_monitor;
        path->group_probe_loss = grp->probe_loss_pub;
        path->group_probe_degraded = grp->probe_degraded;
        path->group_peer_probe_loss = grp->peer_probe_loss_pub;
        path->group_peer_probe_degraded = grp->peer_probe_degraded;
    }

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

        uint64_t hold = (path->status == MUD_RUNNING &&
                         max_running_rtt > path->rtt.val)
                       ? (max_running_rtt - path->rtt.val) / 2
                       : 0;

        /* Below MUD_REORDER_MIN_HOLD is RTT measurement noise, not a real
         * path difference -- see that constant's comment. */
        path->reorder_hold = (hold >= MUD_REORDER_MIN_HOLD) ? hold : 0;
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
    /* Same 0-means-unchanged convention as every conditional field above:
     * `path set ... probeinterval N` on an already-monitor path must not
     * require re-stating `monitor` too, so a bare 0 here can only mean
     * "not specified", same as loss_limit/beat/rtt_limit/mtu just above.
     * One real asymmetry: there is no way to *clear* monitor once set this
     * way, short of deleting and recreating the path -- acceptable for a
     * property this structural (mud_select_path() and the group's degrade
     * decision both key off it), not something an operator would expect
     * to toggle back and forth on a live path. */
    if (conf->monitor) c.monitor = 1;
    if (conf->probe_interval) c.probe_interval = conf->probe_interval * MUD_ONE_MSEC;
    if (conf->probe_window)   c.probe_window   = conf->probe_window;
    if (conf->probe_recover)  c.probe_recover  = conf->probe_recover * MUD_ONE_MSEC;

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
    /* 0 == uncapped, not "rate 0" -- see mud_get_path()'s own comment.
     * Reseeds an uncapped path exactly like a brand-new one instead of
     * silently re-triggering the same deadlock on every interface
     * rebind (this function's whole purpose). */
    path->tx.rate = conf.tx_max_rate ? conf.tx_max_rate : MUD_TX_RATE_INITIAL;
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

static unsigned int mud_worker_count_override;

/* Cores this process may actually run on: its CPU affinity mask on Linux
 * (so a `cpus` restriction, taskset, a cgroup or systemd CPUAffinity= are
 * all respected), else the online core count. */
static unsigned int
mud_usable_cores(void)
{
#if defined __linux__
    cpu_set_t set;

    if (!sched_getaffinity(0, sizeof(set), &set)) {
        unsigned int n = 0;

        for (int c = 0; c < CPU_SETSIZE; c++)
            if (CPU_ISSET(c, &set))
                n++;
        if (n)
            return n;
    }
#endif
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);

    return (ncpu > 1) ? (unsigned int)ncpu : 1;
}

void
mud_set_worker_count(unsigned int n)
{
    if (!n) {
        mud_worker_count_override = 0;
        return;
    }
    unsigned int max_useful = 4 * mud_usable_cores();

    if (max_useful > MUD_WORKERS_EXPLICIT_MAX)
        max_useful = MUD_WORKERS_EXPLICIT_MAX;

    mud_worker_count_override = (n > max_useful) ? max_useful : n;
}

unsigned int
mud_worker_count(void)
{
    if (mud_worker_count_override)
        return mud_worker_count_override;

    const unsigned int cores = mud_usable_cores();
    /* Floor of 1, not 0 -- unlike the old shared-pool design, where a
     * calling thread with no workers still processed everything itself,
     * here the worker threads are the only thing that ever processes a
     * packet, so a single-core box still needs exactly one. Sized from the
     * cores this process may use, not the machine's -- otherwise a process
     * confined to 3 of 32 cores would default to 31 workers. */
    unsigned want = (cores > 1) ? cores - 1 : 1;

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
    uint16_t sock;
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

        const uint16_t sock = tx[g].sock;
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

    if (!ro->next_deadline || s->deadline < ro->next_deadline)
        ro->next_deadline = s->deadline;

    pthread_mutex_unlock(&ro->lock);
    return 1;
}

/* Buffers a data packet that carries a sequence number, in mud->reorder.
 * seq_ring[seq % MUD_SEQ_RING_SIZE] -- an O(1) array write, no search or
 * sort (see struct mud_seq_slot's own comment for why that matters). Unlike
 * mud_reorder_insert() this never guesses from RTT whether a predecessor
 * might still be in flight: the packet is released as soon as every lower
 * number has been delivered (see mud_seq_flush()), so an in-order packet --
 * including the only packet of a sparse flow -- is not delayed at all.
 *
 * `deadline`, stored with every slot, is how long a packet still missing
 * when this one arrived may keep being waited for before it is given up on
 * as lost: this packet's own path's reorder_hold (how much later than this
 * path a slower one can legitimately be) plus MUD_SEQ_GAP_MARGIN, capped by
 * mud_conf.reorder_window. mud_seq_flush() only ever reads the deadline of
 * whichever occupied slot is currently blocking delivery -- see its own
 * comment -- so computing and storing it here unconditionally, whether or
 * not this insert turns out to be that slot, costs nothing worth avoiding
 * and needs no extra bookkeeping about the ring's current shape.
 *
 * Returns 0, leaving the packet for the caller to deliver at once, when it
 * is late (its number is already behind what was delivered -- holding it
 * would achieve nothing), a duplicate, or when the ring has wrapped all the
 * way around onto an entry still awaiting delivery (a real backlog of a
 * full MUD_SEQ_RING_SIZE packets -- caller falls back to delivering this
 * one unordered rather than overwriting the older one). */
static int
mud_seq_insert(struct mud *mud, uint32_t seq, uint64_t hold, uint64_t now,
               const unsigned char *data, size_t size)
{
    if (size > MUD_REORDER_SLOT_SIZE)
        return 0;

    struct mud_reorder *ro = &mud->reorder;

    pthread_mutex_lock(&ro->lock);

    int32_t dist = (int32_t)(seq - ro->seq_next);

    if (!ro->seq_sync || dist > MUD_SEQ_RESYNC || dist < -MUD_SEQ_RESYNC) {
        /* First stamped packet of a stream, or a number so far from the
         * expected one that the peer must have restarted its counter. The
         * ring is indexed by seq & MUD_SEQ_RING_MASK, not by the full seq
         * value, so a stale entry left over from before the restart could
         * otherwise sit at the same ring position a new packet needs and
         * be mistaken for a real duplicate (mud_seq_insert() returning 0,
         * silently degrading that one packet to unordered delivery, never
         * anything worse) until the new counter cycles past it. Clearing
         * the ring on every resync -- itself a rare event, so paying
         * MUD_SEQ_RING_SIZE here costs nothing that matters -- avoids that
         * instead of waiting it out. */
        memset(ro->seq_ring, 0, sizeof(ro->seq_ring));
        ro->seq_count = 0;
        ro->seq_next_deadline = 0;
        ro->seq_next = seq;
        ro->seq_sync = 1;
        dist = 0;
    }
    if (dist < 0) {
        pthread_mutex_unlock(&ro->lock);
        return 0;
    }
    struct mud_seq_slot *s = &ro->seq_ring[seq & MUD_SEQ_RING_MASK];

    if (s->occupied) {
        /* Either this exact packet again (a retransmitted duplicate at the
         * UDP level, which glorytun does not otherwise produce, or a
         * duplicated path), or the ring has wrapped a full
         * MUD_SEQ_RING_SIZE ahead of a still-unresolved gap -- either way,
         * nothing safe to do but leave this one for the caller. */
        pthread_mutex_unlock(&ro->lock);
        return 0;
    }
    uint64_t wait = hold + MUD_SEQ_GAP_MARGIN;

    if (wait > mud->conf.reorder_window)
        wait = mud->conf.reorder_window;

    memcpy(s->data, data, size);
    s->size = size;
    s->seq = seq;
    s->deadline = now + wait;
    s->occupied = 1;
    ro->seq_count++;

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

    if (!ro->count) {
        pthread_mutex_unlock(&ro->lock);
        pthread_mutex_unlock(&ro->flush_lock);
        return;
    }
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
     * in practice -- this array only ever holds packets sent before
     * stamping began or by a peer that doesn't stamp at all (see
     * mud_seq_flush() for the stamped, high-throughput path, which does
     * not sort). */
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
        uint64_t next = 0;

        for (unsigned i = 0; i < ro->count; i++) {
            if (keep[i])
                continue;
            if (!next || ro->slot[i].deadline < next)
                next = ro->slot[i].deadline;
            ro->slot[w++] = ro->slot[i];
        }
        ro->count = w;
        ro->next_deadline = next; /* includes anything inserted meanwhile */
        pthread_mutex_unlock(&ro->lock);
    }
    pthread_mutex_unlock(&ro->flush_lock);
}

/* Delivers every currently-releasable stamped packet (see mud_seq_insert()),
 * strictly in sequence order, via tun_write(). Unlike mud_reorder_flush()
 * above there is nothing to sort: seq_ring is already indexed by sequence
 * number, so "the next packet due" is exactly ro->seq_next & mask, an O(1)
 * lookup, and a whole run of consecutive ready packets is released in a
 * single O(k) walk (k = packets released this call) rather than a scan over
 * the entire buffer. The forward scan used to find a give-up deadline for a
 * gap is bounded by MUD_SEQ_RING_SIZE, but that bound is not what keeps this
 * function cheap in the case that actually matters: this is called on every
 * mud_worker_loop() iteration, and on most calls nothing needs holding at
 * all, i.e. the ring is completely empty -- a case an earlier version of
 * this scan (correctly, but expensively) confirmed by walking every one of
 * MUD_SEQ_RING_SIZE slots and finding none occupied, on every single call.
 * Caught the same way as the O(n^2) sort this replaced: a live throughput
 * test, not code review -- CPU climbed to a full core and throughput
 * collapsed by ~4x under sustained TCP, this time because call *frequency*
 * (one attempted scan per RX pass, thousands/sec at real throughput) makes
 * even a bound this size add up. ro->seq_count (see its own comment) turns
 * that common case back into an O(1) check.
 *
 * Same locking discipline as mud_reorder_flush(): flush_lock serializes
 * this whole function across worker threads so releases stay strictly
 * ordered even with several threads inserting concurrently; ro->lock guards
 * only plain memory access and is dropped before the tun_write() calls. */
static void
mud_seq_flush(struct mud *mud, int tun_fd, mud_tun_write_fn tun_write)
{
    if (!mud->conf.reorder_window)
        return;

    struct mud_reorder *ro = &mud->reorder;

    pthread_mutex_lock(&ro->flush_lock);
    pthread_mutex_lock(&ro->lock);

    if (!ro->seq_sync || !ro->seq_count) {
        ro->seq_next_deadline = 0;
        pthread_mutex_unlock(&ro->lock);
        pthread_mutex_unlock(&ro->flush_lock);
        return;
    }
    const uint64_t now = mud_now(mud);
    unsigned char out_data[MUD_REORDER_FLUSH_BATCH][MUD_REORDER_SLOT_SIZE];
    size_t out_size[MUD_REORDER_FLUSH_BATCH];
    unsigned n = 0;

    for (;;) {
        struct mud_seq_slot *s = &ro->seq_ring[ro->seq_next & MUD_SEQ_RING_MASK];

        if (!s->occupied) {
            /* Gap at the head. Look ahead (bounded scan -- see this
             * function's own doc comment) for the first packet that has
             * actually arrived: its own deadline says how much longer the
             * missing one(s) below it may still be waited for. Nothing
             * found at all means genuinely nothing is queued yet -- not a
             * gap, just traffic that hasn't arrived, so there is nothing to
             * give up on and no reason to keep scanning. */
            uint32_t d = 1;
            struct mud_seq_slot *g = NULL;

            for (; d <= MUD_SEQ_RING_MASK; d++) {
                struct mud_seq_slot *cand =
                    &ro->seq_ring[(ro->seq_next + d) & MUD_SEQ_RING_MASK];

                if (cand->occupied) {
                    g = cand;
                    break;
                }
            }
            if (!g || now < g->deadline) {
                ro->seq_next_deadline = g ? g->deadline : 0;
                break;
            }
            /* Given up: the whole run below the found packet is skipped in
             * one step, exactly like the array-based version used to. */
            ro->seq_next += d;
            continue;
        }
        if (n == MUD_REORDER_FLUSH_BATCH) {
            /* Deliver what's staged so far and keep going -- same chunking
             * mud_reorder_flush() uses, for bounded stack usage, and safe
             * for the same reason: seq_ring is only ever appended to by
             * insert (at ro->seq_next + something), never rewritten behind
             * where this loop has already advanced past. */
            pthread_mutex_unlock(&ro->lock);
            for (unsigned i = 0; i < n; i++)
                tun_write(tun_fd, out_data[i], out_size[i]);
            n = 0;
            pthread_mutex_lock(&ro->lock);
            continue;
        }
        memcpy(out_data[n], s->data, s->size);
        out_size[n] = s->size;
        n++;
        s->occupied = 0;
        ro->seq_count--;
        ro->seq_next++;
    }
    pthread_mutex_unlock(&ro->lock);

    for (unsigned i = 0; i < n; i++)
        tun_write(tun_fd, out_data[i], out_size[i]);

    pthread_mutex_unlock(&ro->flush_lock);
}

/* How long mud_worker_loop() may sleep in poll(): the idle cadence
 * (`idle_ms`) normally, but no longer than until the earlier of the two
 * buffers' (mud_reorder_flush()'s and mud_seq_flush()'s) next pending
 * release -- so a held packet leaves at its deadline (rounded up to the
 * next millisecond, poll()'s resolution) instead of waiting for the next
 * unrelated packet or the idle timeout to give some worker a reason to wake
 * up and flush. Without this a sparse flow's held packets were released one
 * packet-gap late (or up to the 100ms idle timeout late), regardless of how
 * small the hold was. A worker that just inserted a packet always passes
 * through here again before its next poll(), so a new deadline is never
 * missed. */
static int
mud_reorder_poll_timeout(struct mud *mud, int idle_ms)
{
    if (!mud->conf.reorder_window)
        return idle_ms;

    struct mud_reorder *ro = &mud->reorder;

    pthread_mutex_lock(&ro->lock);
    uint64_t next = ro->next_deadline;

    if (!next || (ro->seq_next_deadline && ro->seq_next_deadline < next))
        next = ro->seq_next_deadline;
    pthread_mutex_unlock(&ro->lock);

    if (!next)
        return idle_ms;

    const uint64_t now = mud_now(mud);

    if (now >= next)
        return 0;

    const uint64_t wait_ms = (next - now + MUD_ONE_MSEC - 1) / MUD_ONE_MSEC;

    return (wait_ms < (uint64_t)idle_ms) ? (int)wait_ms : idle_ms;
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
         * same idle cadence bind.c's old event loop used -- and shortened
         * to the reorder buffer's next release time when one is pending. */
        const int pret = poll(fds, n, mud_reorder_poll_timeout(mud, 100));

        if (pret == -1) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (pret == 0) {
            /* Nothing ready this cycle -- still give both reorder buffers
             * (if enabled) a chance to release anything that's timed out
             * while traffic went quiet; see mud_reorder_flush()'s and
             * mud_seq_flush()'s own timeout backstop. A no-op when
             * reorder_window is 0. */
            mud_reorder_flush(mud, tun_fd, tun_write);
            mud_seq_flush(mud, tun_fd, tun_write);
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
            /* A connected socket (see mud_path_promote()) whose peer has
             * gone away -- restarted process, changed source port -- gets
             * an ICMP "port unreachable" from the kernel, which sits on
             * the socket as a pending error and makes poll() report
             * POLLERR immediately, every time, until something consumes
             * it. Nothing here ever read such a socket (POLLIN isn't set
             * for it), so its owning worker spun at 100% CPU forever.
             * Reading SO_ERROR clears it. The error itself needs no other
             * handling: the path just stops answering and times out the
             * usual way. */
            if (fds[k].revents & POLLERR) {
                int err = 0;
                socklen_t errlen = sizeof(err);

                getsockopt(fds[k].fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            }
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
                int stamped;
                uint32_t seq = 0;
                const int wn = mud_recv_finish(mud, sock_index, &rs->msg,
                                               &rs->remote, rs->packet,
                                               rs->len, out, sizeof(out),
                                               &path_hold, &stamped, &seq);
                if (wn <= 0)
                    continue;

                /* Carries a sequence number: released strictly in sequence
                 * (waiting only for a genuinely missing predecessor), not
                 * by the RTT-derived hold below. Anything the buffer can't
                 * take -- late, full, oversized, or resequencing off -- goes
                 * straight to TUN. */
                if (stamped) {
                    if (!mud->conf.reorder_window ||
                        !mud_seq_insert(mud, seq, path_hold, mud_now(mud),
                                        out, (size_t)wn))
                        tun_write(tun_fd, out, (size_t)wn);
                    continue;
                }

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
        /* Deliver anything in either reorder buffer that's ready after this
         * iteration's RX work -- a no-op when reorder_window is 0. */
        mud_reorder_flush(mud, tun_fd, tun_write);
        mud_seq_flush(mud, tun_fd, tun_write);
    }
    free(scratch);
    return ret;
}
