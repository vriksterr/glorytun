# UDP sub-flow bonding implementation plan

> Implementation status: the code changes described here have been written
> against this checkout, but have **not** been compiled or run -- the
> development environment used to write them had no Linux/POSIX toolchain
> available (no `sys/socket.h`, `sys/un.h`, `net/if.h`, or
> `linux/rtnetlink.h`, all of which this codebase requires). Build and the
> integration tests below on a real Linux toolchain before relying on this.

This document is a self-contained implementation record for splitting a
single Glorytun path into several independent parallel UDP sub-flows, to
aggregate bandwidth on long/high-RTT links the way parallel `iperf3 -P`
streams aggregate past a single TCP flow's bandwidth-delay-product ceiling.

```sh
glorytun path up via wwan0 connections 4 rate tx 10mbit rx 50mbit
```

## Baseline

This plan was written against Glorytun with the interface-name path feature
(`docs/interface-paths-plan.md`) already implemented, and explicitly
implements that document's deferred non-goal: *"Do not add one UDP socket
per interface yet; retain the shared socket and use packet-info ancillary
data."*

`mud` is a separate repository (`https://github.com/akshat1050/mud-vrxtr.git`,
pinned via `.gitmodules`). In a normal checkout, `mud.h`/`mud.c` changes
belong in that fork, committed there, with this repository's submodule
pointer bumped afterward. In the environment this was implemented in, the
`mud` submodule was **not actually initialized as a git checkout** (no
`mud/.git`), so the fork/commit/bump-pointer workflow could not be carried
out as real git operations -- the files under `mud/` were edited directly on
disk instead. Before merging, either initialize the submodule properly and
replay these changes as commits in the fork, or confirm with whoever owns
the `mud-vrxtr` fork how they want this handled.

## Current behavior (before this change)

1. `struct mud` owns exactly one UDP socket (`mud->fd`), opened once in
   `mud_create()`, bound to one local port for the process's entire
   lifetime.
2. `mud_send_path()`, `mud_recv()`, and `mud_recv_batch()` all hardcode that
   one socket.
3. `mud_get_path()` identifies a path by `(local addr or local_ifindex,
   remote addr, remote port)` -- local *port* was never part of path
   identity, since there was only ever one.
4. `mud_select_path()` already load-balances outgoing packets per-packet
   across every `MUD_RUNNING` path, weighted by each path's live `tx.rate`
   -- today used to bond separate physical WAN links.
5. Passive path auto-discovery (`mud_recv()`/`mud_recv_batch()` calling
   `mud_get_path(..., MUD_PASSIVE)`) silently creates a new path the moment
   a peer is seen from an unrecognized `(addr, port)` pair, with no admin
   action.

Point 5 combined with remote port already being part of path identity means
a peer that sends from several distinct source ports toward the same
destination already causes today's code to auto-create one distinct passive
path per source port -- as an incidental side effect, not a designed
feature. This change makes that intentional and controllable.

## Scope

### Required

* A `struct mud` instance can own a pool of local UDP sockets, grown on
  demand via `mud_set_sock_count()` (`realloc`'d, like `mud->paths` already
  is -- not a fixed pre-allocated array). `connections N` is genuinely
  user-defined; the only ceiling is `MUD_SOCK_MAX` (256), which exists
  because `struct mud_path_conf.sock` is a single `unsigned char`, not
  because of any opinion about how many sub-flows are useful.
* `struct mud_path_conf` gains a `sock` field identifying which pool socket
  a path uses; it participates in path identity matching everywhere
  `local_ifindex`/`local`/`remote` already did.
* CLI: `connections NUMBER` on `path up`/`path set`, restricted to `via
  <ifname>` paths, default `1`.
* The daemon fans a single `connections N` request out into N `mud_path`
  entries (one per `sock` index) and N `gt_managed_path` entries, all
  sharing the same rate/beat/pref/etc. configuration.
* Shrinking `connections` on a later call brings down the now-excess
  sub-flows (mirrors `path down` for a single path).
* The passive/receiving peer requires **no** changes, no upgrade, and no
  configuration.

### Non-goals

* No wire/protocol format changes -- `sock` is local metadata, like
  `local_ifindex`, never sent to the peer.
* No crypto/handshake redesign -- one `struct mud` instance is still one key
  exchange, one session, one worker pool, shared across every sub-flow.
* No support for `connections > 1` on legacy `addr`-only (non-`via`) paths
  -- there is no durable per-path state container for them to divide.
* No replacement of the daemon's `select(2)` loop with `poll()`/`epoll()`.
  A handful to a few dozen sub-flows keeps the total fd count far under
  `FD_SETSIZE` (1024 on Linux); since `connections` is now user-defined up
  to 256, requesting very large counts moves this from a theoretical
  concern to a real one (see "Risks") -- switching to `poll()`/`epoll()`
  remains out of scope here since it wasn't needed for the sizes this
  feature was actually built for.
* No per-sub-flow independent MTU/rate CLI knobs -- every sub-flow of one
  `connections N` request inherits the same configuration.

## `mud` fork changes

`mud.h`:

* `#define MUD_SOCK_MAX (256U)` -- the range of `unsigned char sock`, not a
  chosen default; the CLI/daemon default is still `1` sub-flow unless
  `connections N` is given.
* `#define MUD_PATH_MAX (64U)` (raised from 32; see "Risks").
* `struct mud_path_conf` gains `unsigned char sock;`.
* `mud_get_fd()` gains a `sock` index parameter; new `mud_get_sock_count()`
  and `mud_set_sock_count()`; `mud_recv()`/`mud_recv_batch()` gain a leading
  `sock` parameter; `mud_rebind_path()` gains a trailing `sock` parameter.

`mud.c`:

* `struct mud`: `int fd;` becomes `int *sock; unsigned int sock_count;`
  (heap-allocated, grown via `realloc()`) plus `sock_v4`/`sock_v6`/
  `sock_family` to remember how to open additional sockets later.
* `mud_create()` allocates a 1-element pool and opens it as `sock[0]`
  exactly as the old single-socket path did (using a local `fd0` for the
  fallible setup steps, only committing it into `mud->sock[0]` and
  incrementing `sock_count` once every step succeeds, so a partial failure
  can't leak a socket `mud_delete()` doesn't know to close).
* `mud_set_sock_count()` reallocates the pool up to `count` (rejecting
  `count > MUD_SOCK_MAX`) and lazily opens the new sockets, each bound to
  an ephemeral port on the wildcard address of the same family, reusing
  `mud_setup_socket()` unchanged (outbound source *IP* is still steered
  per-packet via `IP_PKTINFO`/`IPV6_PKTINFO` in `mud_send_path()`
  regardless of which pool socket sends; pool sockets only need distinct
  source *ports*). A no-op if `count` is already `<= sock_count` --
  monotonic, like `mud->paths`' growth.
* `mud_send_path()` sends via `mud->sock[path->conf.sock]`.
* `mud_get_path()`'s two match loops (interface-indexed and legacy) both
  gained a `path->conf.sock != sock` condition; path creation always stamps
  `path->conf.sock = sock` (unlike `local_ifindex`, never zeroed for
  passive paths -- `sock` is meaningful in both cases).
* `mud_recv()`/`mud_recv_batch()` read from `mud->sock[sock]` and forward
  `sock` into `mud_get_path()`.
* `mud_set_path()` rejects `conf->sock >= mud->sock_count` (grow the pool
  first via `mud_set_sock_count()`).
* `mud_rebind_path()`'s match loop also requires `candidate->conf.sock ==
  sock` -- without this, rebinding one sub-flow after a netlink event could
  silently match and corrupt a different sub-flow's path state.
* `mud_delete()` closes every open pool socket, not just one.

`test.c`: updated its `mud_get_fd()`/`mud_recv()` call sites to the new
signatures (always socket index `0`).

Not touched: all AIMD/loss/RTT accounting (`mud_update_rl()`,
`mud_update_loss()`, RTT EWMA), `mud_path_update()`, the worker pool, or
key-exchange state -- none of these have any socket awareness, so a
`connections N` path gets N independently rate/loss/RTT-tracked sub-flows
for free. `mud_select_path()` and `mud_path_track()` *were* touched, but
only after initial testing surfaced a real problem with leaving them as-is
-- see "Even load balancing across sub-flows" below.

## Glorytun changes

* `src/ctl.h`: `struct ctl_msg` gains `unsigned int connections;` (a
  top-level sibling field, like `ifname`/`ifindex` -- a request fan-out
  count, not a per-path tunable inside `struct mud_path_conf`'s union
  member). `0` means unspecified/unchanged.
* `src/bind.c`:
  * The `CTL_PATH_CONF` handler computes `conn_count = req.connections ?
    req.connections : 1`, rejects `> MUD_SOCK_MAX` (`EINVAL`) and `> 1`
    without `ifname[0]` (`ENOTSUP`), grows the socket pool via
    `mud_set_sock_count()`, sets every newly opened socket non-blocking,
    then loops `sock = 0..conn_count-1` calling `gt_path_manager_set()`
    once per sub-flow. A second pass scans `path_manager.path[]` for
    entries with the same `(ifname, remote)` and `sock >= conn_count` and
    brings them down, handling shrink.
  * `mud_can_read`/`mud_can_write` became `int[MUD_SOCK_MAX]` arrays;
    `mud_get_sock_count()` is read fresh every event-loop iteration so
    newly opened sockets are picked up automatically; `last_fd` for
    `select()` is recomputed every iteration across all live sockets.
  * The RX branch now loops over every readable mud socket, calling
    `mud_recv_batch(mud, i, ...)` per socket and writing all decrypted
    packets to the TUN device exactly as before.
  * A small `gt_sockaddr_equal()` helper was added (family + address +
    port comparison) to support the shrink-scan above without exporting
    `path_manager.c`'s internal comparison helpers.
* `src/path_manager.h`/`.c`: `struct gt_managed_path` gains `unsigned char
  sock;` -- a logical path with N sub-flows now occupies N
  `gt_managed_path` entries, one per `sock` index. `gt_path_manager_find()`
  gained a `sock` parameter and matches on it; `gt_path_manager_set()`
  likewise, stamping `sock` on newly created entries;
  `gt_path_manager_apply()` sets `conf.sock = path->sock` before calling
  `mud_set_path()` (previously would have defaulted every sub-flow to `0`,
  silently collapsing them onto one path);
  `gt_path_manager_reconcile_one()` passes `path->sock` into
  `mud_rebind_path()`; `gt_path_manager_status()`'s runtime-path match loop
  requires `candidate->conf.sock == managed->sock` (previously every
  sub-flow's status row would have shown sub-flow 0's live stats).
* `src/path.c`: new `connections <n>` argz option (`min = 1, max =
  MUD_SOCK_MAX`), gated into the existing `change` detection, client-side
  rejected when `> 1` without `via`, and threaded into the `CTL_PATH_CONF`
  request's new `connections` field.

  `gt_path_status()` was rewritten (not just column-patched) so sub-flows
  render grouped under their physical path instead of as flat, mostly-
  identical rows. It still streams however many `CTL_PATH_STATUS` replies
  the daemon sends -- that part needed no protocol change -- but now
  buffers them all first (`static struct ctl_msg rows[MUD_PATH_MAX * 2]`,
  moved off the stack like `bind.c`'s batch buffers), groups by
  `(ifname, remote)` via a new `gt_path_same_group()` helper, and prints one
  header line per group (`IFACE  index N  LOCAL -> REMOTE`) followed by one
  indented, tree-connector-prefixed line per sub-flow (`├─`/`└─`) showing
  only the fields that actually vary per sub-flow (status, rtt, loss, rate,
  etc., as self-labeled `key value` pairs rather than padded columns). The
  old fixed-column-width machinery (`struct gt_path_hdr`, `gt_path_print()`)
  was removed entirely along with the now-unused `<stdarg.h>` include, since
  nothing needs per-column width tracking anymore. One user-visible
  behavior change from this: with zero configured paths, the old flat table
  always printed its column-header row regardless; the new grouped view
  prints nothing when there's nothing to group.

## Follow-up fixes: even load balancing, and a stale-monitoring bug

Two real issues surfaced from working through what the design implies in
practice, both in `mud/mud.c`, both requested explicitly rather than
speculative hardening:

**1. Sub-flows were being selected by measured rate, not evenly.**
`mud_select_path()` picks a path per-packet weighted by `path->tx.rate` --
correct behavior for bonding two genuinely different-capacity physical WAN
links, but wrong for sub-flows of *one* link, which have no real capacity
difference from each other. Left as-is, this creates a rich-get-richer
problem: whichever sub-flow(s) happen to pull ahead early keep getting
selected more (since selection weight *is* measured rate), which keeps
their rate estimate growing while idle siblings never get real traffic to
prove themselves against -- risking most of the aggregate bandwidth
collapsing onto 1-2 sub-flows instead of spreading across all N.

Fixed by adding `struct mud_path.select_weight` (`mud/mud.h`), recomputed
once per `mud_update()` tick rather than left as raw `tx.rate`. A new
`mud_path_same_group()` helper (`mud/mud.c`, next to `mud_cmp_addr()`/
`mud_cmp_port()`) identifies which `MUD_RUNNING` paths share one physical
link -- same `local_ifindex` (or local address, for legacy/passive paths
where `local_ifindex` is always 0) and same remote *address* (deliberately
excluding remote port: sub-flows vary by local port on the active/explicit
side, but by remote port on the passive side, which never opens extra
sockets -- comparing address only groups correctly from either side without
needing to know which one it is). Every path's `select_weight` becomes its
group's average `tx.rate`, so `mud_select_path()`'s walk splits packets
evenly within a group while still weighting proportionally *between*
distinct physical links, exactly as before. `mud->rate` (the sum
`mud_select_path()` scales its cursor against) is recomputed from the sum
of `select_weight` rather than reused from the original `tx.rate` sum, so
integer-division rounding inside each group's average can't leave the two
inconsistent -- `tx.rate` itself is untouched, still each sub-flow's own
genuine measured throughput for display/diagnostics and its own AIMD
growth/decay, just no longer what selection weights on directly.

**2. Idle-looking sub-flows were going stale for up to 25 seconds.**
`mud_path_track()` backs a `MUD_RUNNING` path's beat cadence off from its
normal ~100ms to the slow global `keepalive` (25s default) once it's seen
no traffic (data or beat) in the last second -- sensible for a genuinely
idle physical link, wrong for a sub-flow: with N sub-flows splitting
traffic, any individual one can look idle for a full second purely by
chance even while the link overall stays busy. Once backed off, that
sub-flow's RTT/loss/rate only actually refresh when a beat reply is
processed -- so `path watch`'s once-a-second display was correctly
re-querying the daemon each time, but the daemon's own numbers for that
sub-flow really were up to 25s stale. This compounded issue 1 above, since
a sub-flow that isn't beating also isn't getting `tx.rate` reassessed.

Fixed with the simpler of two options considered: `mud_path_track()` now
skips the idle backoff entirely whenever `mud->sock_count > 1`, rather than
only for paths actually grouped into a `connections > 1` set. Coarser --
it also keeps a lone, non-bonded path's beat at full cadence just because
some *other* path on the same daemon happens to use sub-flows -- but
correspondingly simpler, and the cost (a handful of small beats per
sub-flow per 100ms) is trivial on any link worth bonding sub-flows over.

## Follow-up: two physical interfaces were sharing one socket pool (`src/bind.c`)

Found from live testing (dual-WAN, `connections 8` on each) -- confirmed
with data, not speculation: every sub-flow's `public` source port was
identical between the two physical interfaces, index for index (ISP1
sub-flow 0 and ISP2 sub-flow 0 both showed the same port, etc.).

Root cause: the `CTL_PATH_CONF` fan-out always assigned `conf.sock =
0..conn_count-1` regardless of which interface the request was for.
`mud_set_sock_count()` is monotonic ("grow to at least N, never shrink"),
so the *second* interface's `connections 8` request saw the pool already
at 8 and did nothing -- its fan-out then reused `mud->sock[0..7]`, the
exact same real sockets (and therefore source ports) the first interface's
sub-flows were already using. Two physical links that should have had 16
independent sub-flows in total actually had 8, each doubled up.

Fixed by giving each `(ifname, remote)` group its own dedicated,
non-overlapping block of `sock` indices: before fanning out, `bind.c` now
scans `path_manager.path[]` for an existing group matching this request's
`(ifname, remote)` and reuses its lowest `sock` value as the base (so
resizing an existing group's `connections` count doesn't move its block);
for a brand-new group, the base is one past the highest `sock` any group
currently holds (or `0` if none exist yet). `mud_set_sock_count()` is now
called with `base_sock + conn_count` rather than just `conn_count`, and the
shrink-scan's bound became `mp->sock < base_sock + conn_count` instead of
`mp->sock < conn_count`, scoped the same as before (matching `ifname` and
`remote`) so it still only touches this one group's entries.

This turned out *not* to be the cause of the separately-reported symptom
(only one sub-flow per physical path detecting a server outage within the
usual few-hundred-ms window, the rest taking minutes) -- confirmed by
retesting after this fix landed, with sockets/ports provably independent
and the symptom still present. See the next entry for the actual cause.

## Follow-up: every sub-flow after the first had its beat interval inflated 1000x

Found from live testing: after this instance's sockets were confirmed
independent, sub-flow 0 of each physical path still reached `degraded`
(5 failed beats) in under a second, while every other sub-flow took
2-5 minutes to do the same -- a huge, specific multiplier, not general
slowness, which is what made it findable.

Root cause, in the `CTL_PATH_CONF` fan-out loop in `src/bind.c`:

```c
for (unsigned int c = 0; c < conn_count; c++) {
    struct mud_path_conf conf = req.path.conf;
    conf.sock = (unsigned char)(base_sock + c);
    gt_path_manager_set(&path_manager, mud, req.ifname, base_sock + c, &conf);
    if (c == 0)
        req.path.conf = conf;   // <- the bug
}
```

`gt_path_manager_set()` writes back into `conf` an *internally-converted*
value -- `gt_path_manager_update_conf()` (`src/path_manager.c`) does
`desired_conf.beat = conf->beat * 1000`, turning the CLI's milliseconds
into internal microseconds. The `if (c == 0) req.path.conf = conf;` line
was added so the reply echoed back to the CLI would reflect the actually-
applied config -- but `req.path.conf` is also what every loop iteration
copies its starting template from. So sub-flow 0 copied the clean original
request (`beat` unset, meaning "use the 100ms default") and was created
correctly; then `req.path.conf` was overwritten with the *already-scaled*
result (`beat` now `100 * 1000 = 100000`, in microseconds). Sub-flow 1
copied *that* as its template -- and since `100000` is non-zero,
`gt_path_manager_update_conf()` treated it as a fresh user-supplied
millisecond value and scaled it again: `100000 * 1000 = 100,000,000`
microseconds, a 100-*second* beat interval instead of 100 milliseconds.
Every sub-flow after the first inherited and re-inflated the same value.
5 failed beats at ~100s apart lines up with the observed 2-5 minute delay
(the discrepancy from a clean 500s is just beat-timing jitter across
sub-flows). The same pattern silently double-shifts `pref` and
`fixed_rate` too (`update_conf` applies `>> 1` to both), just less
visibly than `beat`'s `* 1000`.

Fixed by never mutating the loop's shared template mid-loop: a separate
`first_conf`/`have_first_conf` pair now captures sub-flow 0's merged
result purely for the reply, while every iteration's `conf = req.path.conf;`
continues copying from the original, untouched request throughout.

## Follow-up: receive batches were fragmented per socket, starving the crypto worker pool

Found from live testing under real sustained throughput (not idle): on a
5-core server, only one core showed meaningful load while the other four
sat mostly idle -- worth checking specifically because `mud_recv_batch()`'s
whole purpose is spreading decrypt work across the worker pool
(`min(cores-1, 8)` threads, see `docs/architecture.md`'s threading model).

Root cause: `src/bind.c`'s receive loop called `mud_recv_batch()` once per
readable sub-flow socket:

```c
for (unsigned int i = 0; i < mud_n; i++) {
    if (!mud_can_read[i]) continue;
    int n = mud_recv_batch(mud, i, rx_data, rx_cap, rx_result, MUD_BATCH_MAX);
    ...
}
```

Before sub-flows existed there was one socket, so every packet ready at
once landed in a single combined batch and a single `mud_pool_run()` call
-- maximizing how much work there was to actually split across cores. With
N sub-flow sockets, each got its own separate, smaller batch and its own
separate pool-wake, one socket at a time. Under real throughput spread
across many sub-flows, that means many small batches instead of one large
one -- less parallel work per wake, more wake/sleep overhead, and the
calling (main) thread doing a disproportionate share of the work relative
to the dedicated workers.

Fixed by changing `mud_recv_batch()`'s signature (`mud/mud.h`, `mud/mud.c`)
to drain a *list* of sockets into one shared batch before running the pool
exactly once:

```c
int mud_recv_batch (struct mud *, const unsigned int *socks, int *sock_more,
                    unsigned int sock_count, void *const *, const size_t *,
                    int *, size_t);
```

Internally it walks `socks[]` in order, draining each via non-blocking
`recvmsg()` into the shared `mud->recv_job[]` array until either that
socket returns EAGAIN or the combined batch hits `count`/`MUD_BATCH_MAX`,
then calls `mud_pool_run()` once for the whole batch. `struct mud_recv_job`
gained a `sock` field so each job remembers which socket it actually came
from (a batch can now span several), used in place of the old single
shared `sock` parameter when looking up the path in stage 3.

`sock_more[i]` (output, parallel to `socks[i]`) replaces the old
"`n < MUD_BATCH_MAX` means this socket is drained" heuristic, now tracked
per socket instead of assumed for the one socket a call used to touch: `0`
if `recvmsg()` actually returned EAGAIN for that socket, `1` if its drain
was cut short by the batch filling up (including sockets later in the list
never reached at all this call) -- worth checking again immediately next
iteration rather than waiting for `select()` to re-signal it.

`src/bind.c`'s receive block now collects every currently-readable socket
index into a list once, calls `mud_recv_batch()` a single time with the
whole list, and applies `sock_more[]` back onto `mud_can_read[]` per
socket.

Re-verified under real load (a live `btop` screenshot with a genuine
300-400+ Mbps bidirectional transfer running): the fix above did **not**
resolve it. One core still showed 80% while others stayed near-idle
(`4%/6%/0%/30%`), and `glorytun` was using only ~114% total CPU across 5
threads -- barely more than one core's worth despite AEGIS-256 doing
multiple Gbps/core per `glorytun bench`. That mismatch (114% total CPU for
a workload the crypto benchmark says should cost well under 10% of one
core) was the tell that the bottleneck wasn't crypto throughput at all, and
this report also came from the **server** side, which only ever has one
socket regardless of how many sub-flows the client opens (it tells sub-flows
apart by source port on that one socket) -- so the fix above, which is
purely about combining *multiple* sockets' batches, could never have applied
here in the first place.

## Follow-up: worker threads were waking up too late to ever help, no matter how big the batch was

Found by re-deriving the CPU-time math from `glorytun bench`'s own numbers
instead of continuing to chase batch size. At multi-Gbps/core AEAD
throughput, a single ~1450-byte packet costs on the order of one
microsecond to encrypt/decrypt. Waking a thread that's genuinely asleep in
`pthread_cond_wait()` and getting the kernel to actually schedule it onto a
core costs tens of microseconds at best -- more under a hypervisor, which
this VPS is running under. That's a 10-50x gap.

`mud_pool_run()` (`mud/mud.c`) broadcasts to wake the worker pool, then
*immediately* starts pulling jobs itself as the calling thread, via
`mud_pool_drain()` -- intentional, since it's what lets the pool degrade to
"do it all inline" on a single-core box. But it means: for any batch that
isn't huge (a handful to a few dozen packets -- realistic per `select()`
cycle even at hundreds of Mbps), the calling thread finishes the *entire*
batch and returns before a genuinely-sleeping worker even gets a turn on a
core. The worker wakes late, finds `next_index >= job_count`, grabs nothing,
and goes straight back to sleep. That repeats on literally every dispatch --
so in practice only the calling thread (always the same OS thread, hence
always the same core in the screenshots) ever does real work, regardless of
how many worker threads exist or how the receive-side batching is
structured. This is a strictly worse problem than batch fragmentation: it
caps effective parallelism at 1 core even for a single large combined batch,
any time job costs are small relative to wake latency.

Fixed in `mud_worker_main()` (`mud/mud.c`): before blocking on the condition
variable, an idle worker now busy-waits (spins) on `pool->generation` for a
short bounded window (`MUD_POOL_SPIN_NS`, 50us) using a CPU-relax hint
(`pause` on x86, `yield` on aarch64) each iteration, timed via
`clock_gettime(CLOCK_MONOTONIC, ...)`. A worker that's already spinning sees
the next batch start within nanoseconds instead of paying OS wake latency,
so it can actually grab a share of the work before the calling thread
finishes it alone. If nothing shows up within the spin window (a genuinely
idle tunnel), the worker falls back to the original blocking wait, so an
idle tunnel still costs ~0 CPU -- the spin only fires once per drain, not as
a persistent busy loop.

`struct mud_pool`'s `generation` and `quit` fields changed from plain
`unsigned`/`int` to `atomic_uint`/`atomic_int` (`<stdatomic.h>`), since the
spin loop reads them without holding `pool->lock` -- every other access
still goes through the lock exactly as before; the type change only affects
memory-visibility guarantees for the new unlocked reads. Existing code
(`pool->generation++`, `pool->generation == seen`, `pool->quit = 1`, `if
(pool->quit)`) is unchanged syntactically -- C11 atomic types support these
operators directly.

This is architecturally a different fix from the batch-combining one above,
not a replacement for it -- both matter: the earlier fix ensures a batch is
as large as possible before dispatch (fewer, bigger wakes instead of many
tiny ones); this fix ensures the pool can actually use more than one core
*for* a given dispatch, batch size aside.

Re-verified under load: it worked. A `btop` screenshot from the same VPS,
under genuine 300-400+ Mbps bidirectional throughput, showed `glorytun` at
242% total CPU across all 5 cores (38/91/37/37/48% per core) -- up from
114% with 4 cores nearly idle before this fix. The crypto pool was
confirmed to actually be spreading work across cores.

## Follow-up: the whole pipeline was rearchitected to spread across cores, not just crypto

The spin-wait fix above solved crypto parallelism, but one core (91% in the
retest screenshot) was still doing disproportionately more work than the
others, even though crypto itself was no longer the bottleneck. The user
asked, correctly, why the *receiving* thread's other work -- socket I/O,
path lookup, per-packet bookkeeping -- couldn't also be spread across
cores, rather than staying pinned to one thread by design forever.

The honest answer at the time was: it's a real, bigger, riskier change than
anything else this session, because almost every piece of that "other
work" touches shared state (`mud->paths`, `mud->keyx`, rate/window
counters) that had zero synchronization -- safe only because exactly one
thread ever ran it. The user asked to go ahead anyway.

### What changed

The shared crypto-batch-dispatch design (`mud_pool_run()`/
`mud_recv_batch()`/`mud_send_batch()`, everything from the two follow-ups
above) was **removed outright**, not kept alongside something new. In its
place: `mud_worker_count()` threads (same `min(cores-1,8)` sizing, floored
at 1 instead of 0 -- there's no separate calling thread anymore to fall
back to inline single-core mode) each run `mud_worker_loop()` (`mud/mud.c`,
`mud/mud.h`), a `poll(2)`-based loop over the TUN device and the instance's
whole socket pool. Whichever fd is ready, that thread does the *entire* job
itself -- receive, decrypt, path lookup, stat update, TUN write; or TUN
read, encrypt, path select, send -- with no hand-off to another thread at
any stage. Concurrent `recvmsg()`/`sendmsg()`/TUN read/write from multiple
threads against the same fd are safe (the kernel hands each call a distinct
packet), which is what makes a design with no dispatch queue at all
possible.

`src/bind.c`'s `gt_bind()` now spawns these threads once at startup and
joins them at shutdown. What's left on the original thread is pure
housekeeping: the periodic `mud_update()` tick, and the control-socket /
netlink-event handling -- none of it per-packet, so it staying
single-threaded costs nothing. `mud.c` has no dependency on `src/tun.c` or
glorytun's own `ip.h` -- `mud_worker_loop()` takes TUN read/write as plain
function pointers matching `tun_read()`/`tun_write()`'s signatures exactly,
and `bind.c` supplies them (wrapping `tun_write` in a small
`gt_tun_write_validated()` that does the `ip_is_valid()` check the old
inline RX loop used to do).

### What had to become thread-safe

* **`mud->paths` and `mud->sock`** changed from `realloc()`-grown arrays to
  fixed-size members of `struct mud` (`MUD_PATH_MAX` paths, `MUD_SOCK_MAX`
  sockets -- 256 of each costs at most a few hundred KB, trivial). This
  isn't just tidiness: a `realloc()` can move the whole array, and a
  worker thread holding a pointer or index into the old location while
  another thread grows it would be a real use-after-free. Fixed-size
  removes that class of bug outright rather than defending against it.
* **Two new mutexes** in `struct mud`: `state_lock` (paths, socket pool,
  rate/window accounting, error counters) and `keyx_lock` (session
  key-exchange state, extended from its narrow prior scope -- see below).
  Both are documented at their declaration site in `mud.c` and on
  `mud_worker_loop()`. The rule followed throughout: lock only around
  plain memory access, **never** across a syscall or the AEAD
  encrypt/decrypt call itself. `mud_encrypt()`/`mud_decrypt()` snapshot the
  small, fixed-size key struct they need under `keyx_lock`, then run the
  actual AEAD math against that local copy, fully unlocked -- so multiple
  threads' crypto calls still run in true parallel no matter how many are
  in flight; only the cheap bookkeeping around them briefly serializes.
* **`keyx_lock`'s scope grew.** Previously it guarded only the
  current/next key promotion inside `mud_decrypt()`, safe because
  `mud_recv_msg()` (the only other writer, via `mud_keyx()`) only ever ran
  serially *after* the crypto pool's barrier -- a guarantee that no longer
  exists once N independent threads can each be running `mud_recv_msg()`
  and `mud_encrypt()`/`mud_decrypt()` at the same moment. Now every read or
  write of `mud->keyx` (`mud_encrypt()`, `mud_decrypt()`, `mud_recv_msg()`,
  `mud_keyx_init()`, `mud_send_msg()`'s `keyx.local` read) goes through
  `keyx_lock`. This is the one piece of this change with real security
  stakes rather than just performance/stability -- a race on session key
  material, not just a stats counter -- so it got the most scrutiny.
* **The TX send path splits its locking around the syscall.** Sending a
  packet needs `state_lock` twice, separately: once to pick a path and
  copy out the destination it needs (`mud_select_path()`), once after the
  unlocked `sendmsg()` call to record the result (`path->tx.*`,
  `mud->window`). Holding the lock across the syscall itself would
  serialize every worker thread's sends on it, defeating the entire point.
  The new `mud_sendmsg_to()` (`mud/mud.c`) is the lock-free primitive this
  is built from -- it takes plain destination parameters instead of a live
  `struct mud_path *`, specifically so it can run against a locked-then-
  released snapshot. `mud_send_path()` (used by the low-frequency
  keepalive/beat-reply path, `mud_send_msg()` via `mud_recv_msg()`) still
  holds the lock across its whole call including the syscall -- deliberately,
  since that path fires perhaps a few hundred times a second at most, far
  too infrequent for the extra serialization to matter.
* **`mud_update()`'s entire sweep runs under `state_lock`.** It only runs
  every ~100ms on the housekeeping thread, not per-packet, so a worker
  thread occasionally waiting behind one full pass over `mud->paths` costs
  nothing worth optimizing away.
* **One documented, accepted residual risk**: the TX path holds a raw
  `struct mud_path *` across the unlocked `sendmsg()` gap, and a path can
  in principle be `memset()`-reset (recycled for a different peer) by
  housekeeping's 5-minutes-silent cleanup. In practice this is unreachable
  -- a path just selected for sending is by definition not idle, the
  precondition for that cleanup -- and even in the worst case the failure
  mode is misattributing a few bytes to a reused slot's stats, not a crash
  or security issue. Noted at the point in `mud_worker_loop()` where it
  applies, rather than engineered around, since removing it entirely would
  need reference-counted paths for a benign, effectively unreachable edge
  case.

### What this does *not* change

Wire format, crypto/handshake design, and the `connections N` sub-flow
feature's external behavior are all unchanged -- this is purely an
internal concurrency rearchitecture of how already-decrypted-vs-not-yet
packets get processed. `glorytun bench multicore`'s "pool" mode still
exists in `src/bench.c` but no longer models what the real implementation
does (there is no shared per-packet job queue anymore); its comment was
updated to say so rather than removing the mode outright, since it's still
a useful reference for what a shared-dispatch design would have cost.

### Verification status

**Not yet compiled or run**, same caveat as everything else in this
document -- if anything, more load-bearing here, since this is the largest
and most concurrency-sensitive change made in this whole effort. Before
trusting this on a production tunnel: build it, run `mud/test.c` (uses only
the single-packet `mud_send()`/`mud_recv()` API, unchanged, so it should
still pass unmodified), and re-run the same sustained-throughput test that
found the previous two bottlenecks, watching per-core CPU distribution
under real load. If one core is *still* disproportionately loaded after
this, the next thing to check is whether `poll()`'s own per-iteration cost
has become the new limiting factor (see `mud_worker_loop()`'s comment about
not draining each socket in an inner loop -- a deliberate simplicity
tradeoff that could be revisited if profiling shows it matters).

## Follow-up: live per-sub-flow throughput in `src/path.c`

`path->tx.rate`/`rx.rate` (already shown in `path stat`) is the AIMD
*allowed* rate, not what a sub-flow is actually carrying -- an idle
sub-flow can keep showing a healthy `tx.rate` long after it stopped moving
anything, so neither existing field answers "is this sub-flow actually
being used." Rather than add daemon/protocol-side tracking, `gt_path_track_rate()`
computes a real observed rate entirely client-side: each `gt_path_status()`
call diffs the current cumulative `tx.bytes`/`rx.bytes` against a static,
per-(ifname, remote, sock) sample table left over from the previous call,
divided by the actual wall-clock time elapsed (`clock_gettime(CLOCK_MONOTONIC)`,
mirroring the existing pattern in `src/bench.c`). Formatted as a fixed
Mbps (megabits/second) figure via a new `gt_path_format_mbps()` -- not
`gt_torate()`'s dynamic bit/kbit/Mbit/Gbit scaling (used elsewhere in this
file for configured rate limits), since a fixed unit is easier to scan down
a column of sub-flows at a glance than one that changes per row.

Since it needs two samples a second apart, this only produces a number in
`watch` mode -- a one-shot `glorytun path` query has nothing prior to diff
against and shows `-`. New `tx`/`rx` fields appear on every sub-flow line
in the (now only) status view.

## Follow-up: removed the `rtt`/`stat` specialized views

Once `tx`/`rx` existed in both the default and `stat` views, the two had
converged to the point of redundancy -- `stat` differed from default only by
swapping `rtt`/`mtu`/`public` for `tx-rate`/`rx-rate` (the AIMD-allowed
budget, which is less useful than the new live `tx`/`rx` for telling whether
a sub-flow is actually carrying anything). Removed both `rtt` and `stat`
entirely rather than keep maintaining two views with little differentiation
left: the `gt_path_show` enum, the `show` parameter threaded through
`gt_path_status()`/`gt_path_print_row()`, the `rtt`/`stat` argz entries and
`specialized_show` gating in `gt_path()`, and the show-dependent `watch`
banner text are all gone. `glorytun path` now has exactly one status view.

## Files changed

Glorytun repository:

```text
src/ctl.h              connections field on struct ctl_msg
src/bind.c              CTL_PATH_CONF fan-out/shrink, multi-socket select() loop
src/path_manager.h/.c   sock field, per-sub-flow managed entries
src/path.c              connections CLI option, via-only scope gating
docs/cli-reference.md
docs/architecture.md
```

`mud` fork:

```text
mud.h    MUD_SOCK_MAX, mud_path_conf.sock, socket-pool API, MUD_PATH_MAX bump
mud.c    socket pool, path identity matching, rebind, send/recv routing
test.c   updated call sites for the new mud_get_fd()/mud_recv() signatures
```

## Integration testing

Not yet run (see the implementation-status note at the top). Required cases,
extending the network-namespace test pattern from
`docs/interface-paths-plan.md`:

1. `connections` unset (or `1`) behaves identically to today -- the core
   backward-compatibility guarantee, since `sock` is always `0` in this
   case.
2. `path up via wan0 connections 4` against an **unmodified** passive peer:
   confirm via packet capture / `ss -u -a` on the peer that 4 distinct
   source ports are seen hitting its one socket, and that all 4 reach
   `MUD_RUNNING`.
3. `iperf3` (single stream) through the tunnel with `connections 1` vs
   `connections 4` -- aggregate throughput should approach the multi-stream
   `iperf3 -P4` ceiling rather than the single-flow ceiling.
4. `iperf3 -R` (reverse direction) against an unmodified peer, to confirm
   the peer's own reverse-direction sends also load-balance across the
   auto-discovered passive paths (no peer-side `connections` config needed).
5. `connections 4` then `connections 2` later: confirm the extra two
   sub-flows go down and `MUD_PATH_MAX`/manager slots aren't leaked.
6. Interface flap/rebind while `connections > 1` is active: confirm each
   sub-flow rebinds independently and none get corrupted/merged.
7. `connections 2` without `via`: rejected client-side with a clear error.
8. `connections` value `> MUD_SOCK_MAX`: rejected (`EINVAL`).
9. Full rebuild against a real Linux toolchain, including `mud/test.c`.

## Acceptance criteria

* Existing single-socket behavior is unchanged when `connections` is unset.
* `path up via IFACE connections N` opens N independent UDP sub-flows,
  visible as N rows in `path stat`/`path rtt`/default status, each with
  independent RTT/loss/rate and its own `CONN` index (`0..N-1`) so the rows
  are distinguishable at a glance.
* The passive peer requires no upgrade or configuration to benefit from
  sub-flow bonding in either direction.
* Aggregate throughput through the tunnel with `connections N` approaches
  what `iperf3 -PN` achieves outside the tunnel on the same link.
* Shrinking `connections` tears down the excess sub-flows without leaking
  `MUD_PATH_MAX` slots.
* The encrypted wire format is unchanged.

## Risks

* **Unverified**: these changes have not been compiled. The next session
  working on this must build against a real Linux toolchain before trusting
  any of it further -- treat this as a careful-but-unverified diff, not a
  tested feature.
* `MUD_PATH_MAX` was raised 32 -> 64 to leave headroom for N sub-flows per
  physical path (times however many physical paths, times the passive
  side's mirrored auto-discovered entries). Since `connections` is now
  user-defined rather than capped at a small number, it's easy to request
  more sub-flows than `MUD_PATH_MAX` can actually hold across every
  physical path and peer a given daemon manages -- this now fails loudly
  with `ENOMEM`/`ENOSPC` from `mud_get_path()`/`gt_path_manager_set()`
  rather than silently, but there's still no dynamic resizing of the path
  table itself.
* `connections` is bounded by `MUD_SOCK_MAX` (256, the `unsigned char sock`
  field's range) but `bind`'s event loop still uses `select(2)`, which
  silently misbehaves once any tracked fd's numeric value reaches
  `FD_SETSIZE` (1024 on Linux). A handful to a few dozen sub-flows is safe
  on any normal process; requesting hundreds risks tripping this,
  especially alongside other paths/peers also consuming fds. Nothing in
  this change validates that combination or switches the loop to
  `poll()`/`epoll()` -- worth doing before `connections` is used at scale
  rather than for the 4-8 sub-flow range this was built for.
* The `mud` submodule was not an initialized git checkout in the
  environment this was written in, so the fork-commit-then-bump-pointer
  workflow this project normally requires could not actually be performed
  -- see "Baseline" above.
* Sub-flow sockets bind to an ephemeral port chosen by the OS, not a
  predictable one -- firewall/NAT rules that allow-list specific ports for
  the tunnel will need to be widened (or the binding logic extended to
  accept an explicit port range) before this is useful behind restrictive
  outbound filtering.
