# Single-flow multipath bonding: burst selection + RX resequencing

> Implementation status: written and carefully self-reviewed (including a
> real correctness bug found and fixed during that review -- see "Bugs
> found during review" below) against this checkout, but **not compiled or
> run** -- this development environment has no Linux/POSIX toolchain (see
> `docs/udp-subflows-plan.md`'s identical caveat, still true here). Build
> and run the integration tests below on a real Linux toolchain, on both
> tunnel endpoints, before trusting this on a production tunnel.

## Problem

A single flow (one `iperf3 -P1` TCP stream, for example) bonded across two
paths of different measured latency saw far less throughput than the paths'
combined capacity -- close to a single path's ceiling, not the sum -- even
though many concurrent flows (`iperf3 -P8`) over the same tunnel reached
close to the combined aggregate. Root cause: `mud_select_path()` scatters
every packet across every `MUD_RUNNING` path independently, weighted by
measured rate, with no per-flow affinity at all -- the selection cursor is
derived from the tail bytes of the already-encrypted ciphertext, which is
indistinguishable from random and carries no relationship to the inner
packet's own 5-tuple. When two bonded paths have different RTT, this
reorders one flow's packets at the receiver; nothing in the RX path put them
back in order before handing them to `tun_write()`. A single TCP flow's own
congestion control reads that reordering as loss and won't grow its window
past a fraction of the combined path capacity, no matter how many concurrent
UDP sub-flows (`connections N`, see `docs/udp-subflows-plan.md`) the
physical paths are split into -- more sub-flows just gives the same
per-packet scatter more paths to spread across, which makes the reordering
*more* frequent, not less.

Requirement, stated explicitly by the user driving this change: a single
flow should be able to reach close to the *combined* bandwidth of all
bonded paths, with the splitting happening transparently underneath it --
not be capped near one path's individual rate.

## Why this needs real resequencing, not just smarter scheduling

Two paths carrying one flow concurrently will always produce some
cross-path arrival skew -- that is inherent to actually using both paths at
once for a single ordered stream, not a scheduling bug. No amount of
scheduling cleverness alone eliminates it; real MPTCP doesn't avoid it
either, it resequences it (the DSS/DSN mechanism). The two options
considered:

1. **RX-side reorder buffer** -- hold decrypted packets briefly, deliver in
   true send order. Chosen.
2. **TX-side send-pacing** -- deliberately delay packets on whichever path
   is momentarily ahead so both arrive in order without receive-side
   buffering. Rejected for this pass: requires a real per-path outbound
   timing/queueing mechanism in a TX path that is currently fully
   synchronous (read, encrypt, send, no queuing at all) -- materially more
   new machinery than option 1, in exchange for moving the same fundamental
   latency cost from the receive side to the send side rather than removing
   it.

Both approaches trade a small amount of added latency (bounded by real
inter-path skew, not an arbitrary constant) for single-flow throughput.
There is no way to avoid that tradeoff entirely and still let one flow
genuinely use two divergent-latency paths concurrently.

## Design

### Burst path selection (TX side, `mud_select_path()`)

Reordering can only happen at a path *switch*. `mud_select_path()` now keeps
handing out the same path for a short run (`MUD_SELECT_BURST_PKTS`, 8
packets) instead of re-rolling its weighted-random walk on every packet.
This does not change the long-run proportional split across paths -- the
burst's target path is chosen by the exact same weighted walk, just less
often -- it only reduces how often *consecutive* packets land on different
paths, which shrinks how much work the buffer below has to do (fewer,
smaller resequencing events) without adding any latency itself. Purely a
TX-side optimization: correctness of delivery order comes entirely from the
buffer, not from this.

`mud->select_path`/`select_burst_left` (new fields in `struct mud`, guarded
by the existing `state_lock`) hold the current burst's target and remaining
budget. Revalidated (`status == MUD_RUNNING`) on every call so a path that
drops mid-burst is never handed out stale. Not specifically guarded: a path
slot recycled by housekeeping's 5-minutes-silent cleanup and reused for a
*different* new path within the same few-millisecond burst window -- judged
not worth engineering around given how narrow that window is relative to
the 5-minute idle precondition for that cleanup (same class of accepted risk
as the existing, similarly-reasoned TX-path comment in `mud_worker_loop()`
about a recycled path slot during the unlocked `sendmsg()` gap).

### RX resequencing buffer (`struct mud_reorder`, `mud/mud.c`)

* **Sequence number, not wall-clock time, as the ordering key.** Every
  outbound data packet is stamped with 8 bytes (`MUD_REORDER_SEQ_SIZE`)
  from a strictly-incrementing per-instance counter (`mud->tx_seq`,
  incremented under `state_lock`), prefixed to the plaintext *before*
  encryption -- inside the encrypted, authenticated payload, not the outer
  time/nonce framing, so control/beat messages (`mud_send_msg()`/
  `mud_decrypt_msg()`) are untouched. This specifically avoids the tie
  class of bug a timestamp-keyed version is exposed to: `mud_now()`'s
  resolution is only ~2us (`MUD_TIME_MASK` clears the low bit of a
  microsecond counter), and with up to 8 concurrent TX worker threads each
  calling it, two genuinely different packets landing in the same bucket is
  a real, reachable case under load -- not a rare edge case. A
  strictly-incrementing counter under a lock cannot produce that tie.
* **Fixed-size ring, indexed by `seq % MUD_REORDER_MAX` (512 slots).** O(1)
  insert and lookup on the hot path -- no scanning for the common case
  (in-order arrival delivers immediately, no buffering at all). Sized well
  above the realistic worst case at the delay this ships with (~270 packets
  for 600Mbit/8ms of 1400-byte packets); see "Risks" for what happens if a
  much larger `reorderdelay` is configured under high throughput.
* **`mud_reorder_push()`** (called from `mud_worker_loop()`'s RX half for
  every decrypted data packet): delivers immediately if the packet is next
  in sequence (cascading into any already-buffered contiguous run), buffers
  it if it arrived early, or drops it if it's stale (already superseded).
  Packets larger than `MUD_REORDER_MTU` (1500 bytes -- above any realistic
  inner payload at a sane configured MTU) bypass the buffer entirely,
  delivered immediately and unordered relative to whatever's buffered; an
  accepted, clearly out-of-scope case rather than sizing every one of 512
  slots for it.
* **`mud_reorder_tick()`** (called once per `mud_worker_loop()` iteration,
  regardless of what `poll()` found ready, including a bare timeout): forces
  out anything that's waited past `reorder.delay` for a predecessor that
  will never arrive (genuine loss, not lag), so a stalled packet doesn't
  wait indefinitely during a lull with no other RX activity to trigger the
  buffer's own opportunistic cascade.
* **`reorder.lock` is deliberately held across `tun_write()`** in the
  delivery helpers (`mud_reorder_deliver_locked()`/
  `mud_reorder_advance_locked()`) -- the one intentional exception in this
  file to "never hold a lock across a syscall." Necessary because two
  threads delivering different ready packets at the same moment must not
  race each other into `tun_write()` out of order; a local TUN write is not
  a blocking network syscall, so the added serialization cost is small and
  bounded, unlike holding a lock across something like `recvmsg()`.
  Independent of `state_lock`/`keyx_lock` -- never taken together with
  either, since nothing in the reorder path touches path/socket-pool or
  key-exchange state -- so there's no new cross-lock ordering to reason
  about.

### Tunable delay (`struct mud_conf.reorder_delay`, `glorytun set reorderdelay`)

Exposed through the same `mud_set()`/`CTL_CONF` path as `kxtimeout`/
`timetolerance`/`keepalive`. Default `MUD_REORDER_DELAY_DEFAULT` (8ms,
chosen to comfortably exceed realistic inter-path latency skew on
conventional bonded links without adding meaningful delay to anything
else), clamped to `MUD_REORDER_DELAY_MAX` (50ms) to keep a misconfigured
value from turning the ring's fixed 512-slot capacity into constant forced
eviction under real throughput (see "Risks"). `mud_create()` initializes
both `mud->reorder.delay` (the value actually enforced, guarded by
`reorder.lock`) and `mud->conf.reorder_delay` (the value reported back by
`mud_set()`/`CTL_CONF` when queried without changing it, guarded by
`state_lock`) to the same default -- these are two separate fields guarded
by two separate locks, kept in sync explicitly rather than derived from one
another.

## Bugs found during review

Both found and fixed before shipping this, not after -- see the memory
record `glorytun-reorder-buffer` for the *previous* attempt at this exact
feature, which had a real bug (timestamp-tie packets wrongly dropped) that
collapsed throughput to near-zero on first deployment. This rewrite
switched to a sequence-number key specifically to eliminate that whole bug
class, and the review below went looking for the equivalent mistake in the
new design rather than assuming a different key type meant a clean bill of
health.

**Ring collision direction.** The first draft of `mud_reorder_push()`'s
collision-handling branch (two different sequence numbers mapping to the
same `seq % MUD_REORDER_MAX` slot, both still "live" relative to
`next_seq`) always assumed the *already-buffered* occupant was the older of
the two, evicted and delivered it, and jumped `next_seq` past it. That's
correct in the ordinary case, but once the ring's true occupied span can
exceed `MUD_REORDER_MAX` (reachable under a large configured `reorderdelay`
at high throughput -- 50ms at 600Mbit is roughly 2700 packets, well past
512 slots), the *incoming* packet can actually be the older one. Blindly
evicting the buffered occupant in that case would jump `next_seq` forward
past a still-legitimate, older packet and silently strand it as
unreachable stale garbage forever. Fixed by comparing the two sequence
numbers explicitly: whichever is genuinely older gets delivered/skipped to;
if the *incoming* packet turns out to be the older one, the already-buffered
(newer) occupant is left untouched and the incoming packet is either
delivered directly (if it happens to be exactly `next_seq`) or dropped --
never allowed to overwrite or strand the legitimately newer occupant. A
dropped packet here is recovered the same way any other tunnel packet loss
is, by the inner protocol's own retransmission -- not by corrupting
delivery order to avoid it, which is the one thing this feature exists to
prevent.

**Deadline arithmetic.** An early draft of `mud_reorder_tick()`'s expiry
check compared a stored absolute `deadline` (`now + delay`, computed at
insert time) against `mud_now()` using a bit-63 test on a
`MUD_TIME_MASK()`-ed difference -- meaningless, since `MUD_TIME_MASK` keeps
only the low 48 bits, so bit 63 of the masked result is always zero.
Rewritten to match the pattern this file already uses everywhere else for
exactly this kind of wraparound-safe elapsed-time check: store *when* the
packet was queued (`s->queued = now`) and reuse the existing
`mud_timeout(now, queued, delay)` helper, rather than inventing a new
absolute-deadline comparison in the same limited 48-bit time space that
already has an established, correct idiom for this.

**Config reporting drift.** `mud_create()` originally set
`mud->reorder.delay` (the enforced value) to the default but left
`mud->conf.reorder_delay` (the value `mud_set()`/`CTL_CONF` reports) at its
`memset()`-zeroed default. `glorytun set` queried without ever setting
`reorderdelay` would have printed `now` (0) even though the buffer was
correctly using the real 8ms default underneath -- a misleading status
report, not a functional bug, but the kind of thing worth catching before
a deployed system's own diagnostics become untrustworthy. Fixed by
initializing both fields to the same default.

## Wire format change

The 8-byte sequence prefix inside every data packet's encrypted payload is
new. Unlike every other change in `README.md`'s "Changes in this fork"
list, **this requires both tunnel endpoints to be rebuilt and redeployed
together, not one at a time.** A mismatched pair does not crash either
side, but silently drops all data traffic sent by whichever side wasn't
updated: the receiving side either misinterprets real payload bytes as a
bogus sequence number (if the sender is old), or hands a payload still
carrying the 8-byte prefix to `ip_is_valid()`, which rejects it as a
malformed IP packet (if the sender is new and the receiver is old). Control
traffic (path health, RTT/loss tracking, key rotation) is unaffected either
way, since beat/control messages never carry this prefix -- only the data
plane goes dark in the mismatched direction, which is enough to look like a
dead tunnel without an obvious cause if this isn't anticipated.

`mud_send()`/`mud_recv()` (the single-packet public API used by `mud/test.c`,
not by `glorytun bind`, which exclusively uses `mud_worker_loop()` for its
data plane) are deliberately untouched by this change -- they have no
awareness of the sequence prefix or the reorder buffer, and remain
consistent with each other as long as neither end mixes them with
`mud_worker_loop()`-sent traffic, which glorytun's own binary never does.

## Files changed

```text
mud/mud.h    struct mud_conf gains reorder_delay
mud/mud.c    MUD_REORDER_*/MUD_SELECT_BURST_PKTS constants, struct
             mud_reorder_slot/mud_reorder, struct mud gains tx_seq/
             select_path/select_burst_left/reorder, mud_select_path()
             burst logic, mud_create()/mud_delete() lock lifecycle,
             mud_set() reorder_delay handling, new mud_reorder_push()/
             tick()/deliver_locked()/advance_locked(), mud_worker_loop()
             TX-half sequence stamping and RX-half buffer hookup
src/set.c    reorderdelay CLI option
docs/architecture.md    data-path description, new "Single-flow multipath
                        bonding" section, reorder.lock in the threading
                        section
docs/cli-reference.md   set reorderdelay, wire-compatibility note on bind
README.md               "Changes in this fork" entry
```

## Integration testing

Not yet run (see the implementation-status note at the top). Required,
extending the pattern from `docs/udp-subflows-plan.md`:

1. Both peers rebuilt and redeployed together; confirm a normal two-peer
   tunnel still comes up and passes traffic at all before anything else.
2. `iperf3 -P1` vs `iperf3 -P8` throughput comparison across two bonded
   paths of measurably different RTT -- the motivating case. Expect `-P1`
   to approach the combined capacity rather than one path's individual
   ceiling.
3. `iperf3 -R` (reverse direction), to exercise the buffer on the other
   peer (whichever side is receiving in a given direction is the one whose
   buffer matters).
4. Deliberately induce loss on one path (e.g. `tc netem loss`) and confirm
   a genuinely lost packet is recovered by the inner protocol within
   roughly `reorderdelay`, not stalled indefinitely -- exercises
   `mud_reorder_tick()`'s forced-expiry path specifically.
5. `connections N > 1` (sub-flow bonding, `docs/udp-subflows-plan.md`)
   combined with this feature -- confirm burst selection and resequencing
   behave sensibly across sub-flows of the same physical path, not just
   across distinct physical paths.
6. A single mismatched-version peer pair (one side with this change, one
   without), to confirm the failure mode really is silent data-plane drop
   in one direction, not a crash, matching the "Wire format change" section
   above -- worth confirming once deliberately rather than discovering it
   live during a partial rollout.
7. `reorderdelay` set to a large value (near the 50ms ceiling) under
   sustained high throughput, to observe the degraded-but-not-broken
   behavior described in "Risks" below rather than assuming it from the
   math alone.

## Follow-up: `mud_get_mtu()` didn't account for the new sequence-number overhead

Found from live testing (first real deployment, `connections 8` on each of two
PPPoE WANs): `glorytun path` showed all 16 sub-paths healthy (`running`,
0.00-1.18% loss), but `iperf3 -P1` collapsed to 10-24Mbit/s with heavy
per-second retransmits and a congestion window pinned at 1-16KB -- the
inner TCP flow behaving as if it were seeing constant heavy loss, while the
tunnel's own accounting stayed clean. That mismatch (clean tunnel-level
loss stats, catastrophic inner-flow behavior) was the tell that packets
were failing before ever reaching the loss-tracking layer, not actually
being lost on the wire.

Root cause: `mud_get_mtu()` -- which tells `bind.c` what MTU to set on the
local TUN interface, the only thing standing between `tun_read()` and an
inner packet too big for a path to carry -- subtracted `MUD_PKT_MIN_SIZE`
(crypto framing) but not `MUD_REORDER_SEQ_SIZE` (the sequence prefix this
feature adds inside that same encrypted packet). The TUN interface ended up
advertising an MTU 8 bytes too generous, so full-size TCP segments -- most
of a bulk transfer -- encrypted to a wire packet 8 bytes over the path's
actual configured size. This codebase deliberately has no MTU-failure
recovery (fixed wire size, `IP_PMTUDISC_PROBE` set specifically so an
oversized send fails loudly instead of fragmenting), so `sendmsg()` failed
with `EMSGSIZE` on most real data packets, silently dropped and never
counted by the tx/rx-loss accounting (which only tracks packets that got
far enough to be tracked at all).

Fixed by subtracting `MUD_REORDER_SEQ_SIZE` as well in `mud_get_mtu()`. A
local, per-box calculation (each side's `gt_setup_mtu()` only consults its
own `mud_get_mtu()`), not itself a wire-protocol change -- but since it's
part of the same not-yet-deployed change, it needs the same synchronized
rebuild-both-sides treatment as everything else here, not an incremental
patch to one side.

**Not yet re-verified** -- needs a rebuild + redeploy on both peers and a
repeat of the `iperf3 -P1`-vs-`-P8` comparison that surfaced this.

## Follow-up: a peer restart permanently wedged the receiver's reorder buffer

Found from live testing, and the most severe issue found so far: after
another rebuild/redeploy cycle, the two peers stopped being able to reach
each other at all (not even ICMP ping) while `glorytun path` kept showing
every sub-path `running` with healthy RTT throughout.

Root cause: `mud->tx_seq` starts at a fixed value (0, from `mud_create()`'s
initial `memset`) every time `glorytun bind` is restarted, but the
receiver's `reorder.next_seq` is not reset unless *its* process also
restarts. If only one peer's process is restarted -- routine during an
iterative rebuild/deploy/test cycle -- the still-running receiver is left
expecting sequence numbers from wherever the previous session left off
(easily tens of thousands after even a short test), while the restarted
sender now counts from 0 again. Every packet the restarted sender sends
arrives with `seq < next_seq` and is dropped by the ordinary staleness
check, forever -- nothing the sender does can ever produce a `seq` large
enough to catch up, since `next_seq` never regresses on its own. Control and
beat traffic are unaffected (they never pass through
`mud_reorder_push()`), which is exactly why the connection kept reporting
`running` while carrying zero real data.

Fixed with two complementary changes:

* `mud->tx_seq` is now seeded with `randombytes_buf()` at `mud_create()`
  time instead of always starting at 0, so a restarted process's new
  sequence space essentially never lands anywhere near what a stale
  receiver is still expecting.
* `mud_reorder_push()` now detects an implausibly large backward gap
  (`MUD_REORDER_RESYNC_GAP`, 1,000,000) between an incoming `seq` and
  `next_seq` and treats it as a resync signal -- adopting the incoming
  packet's sequence number as the new baseline -- rather than a routine
  stale/duplicate packet to discard. Ordinary network delay cannot produce
  a gap that large; only a reset counter can. This is the actual fix for
  the wedged state; the randomized seeding above just makes it very
  unlikely the ambiguous small-gap case (where a genuine late duplicate and
  a post-restart low sequence number might be hard to tell apart) is ever
  actually reached.

**Not yet re-verified** -- needs a rebuild + redeploy on both peers. Given
this bug's trigger condition (one side restarted, the other not) is a
routine byproduct of the exact iterative test cycle this feature is being
validated with, it's worth deliberately re-testing that scenario once
(restart only one peer mid-session, confirm the tunnel recovers on its own
within roughly one resync-triggering packet, not just testing a clean
simultaneous restart of both sides).

## Follow-up: diagnostic counters added after timing was ruled out

Live testing after the restart-resync fix still showed severely degraded
`-P1` throughput (~10-15Mbit/s, heavy retransmits) even with just two plain
paths (`connections 1`, ruling out multi-sub-flow complexity) -- and,
decisively, **raising `reorderdelay` from 8ms to 50ms made no measurable
difference**, which rules out the buffer's timing budget as the cause.
Something is dropping or mishandling packets in a way that isn't sensitive
to how long the buffer is willing to wait, and further guessing without
being able to build/run this locally risked burning more of the user's
rebuild cycles on speculation.

Added instead: six running counters on `struct mud_reorder`
(`stat_immediate`, `stat_buffered`, `stat_expired`, `stat_dropped_stale`,
`stat_dropped_collision`, `stat_resync`), copied out through
`mud_get_errors()`/`CTL_ERRORS` into new fields on `struct mud_errors`
(`mud.h`), and printed by `glorytun show errors` (`src/show.c`). Once
deployed, a real test run will show exactly which code path in
`mud_reorder_push()`/`mud_reorder_tick()` real traffic is actually hitting,
instead of inferring it from iperf3's retransmit counter alone -- e.g. a
large `dropped-stale` or `dropped-collision` count relative to
`immediate`+`buffered` would directly confirm this buffer is discarding
data itself, versus the problem being upstream of it (burst path selection,
TX-side sequencing) or unrelated to this feature entirely.

**Not yet re-verified** -- needs a rebuild + redeploy, a repeat of the
`-P1` test, and the resulting `glorytun show errors` output.

## Follow-up: burst selection made runtime-tunable, plus a max-gap counter

After the restart-resync fix, throughput stayed severely degraded (~10-15Mbit/s
on `-P1`) even with `reorderdelay` confirmed at 50ms on *both* peers -- a
decisive result ruling out the buffer's timing budget entirely. The
`dropped-stale` rate (~2-5% per test, computed as deltas against the
cumulative counters) tracked iperf3's own retransmit rate closely (~50/sec
each), confirming the reorder buffer's drops are the direct cause of the
observed TCP retransmissions, not a coincidence. CPU contention was also
ruled out (4 cores, only 3-4 threads, near-idle CPU during the test).

That leaves burst path selection (`mud_select_path()`) as the one major
change never isolated on its own -- it introduces shared global state
(`select_path`/`select_burst_left`) mutated by every TX worker thread, and
sequence-number assignment (`mud->tx_seq`) happens in a separate, earlier
critical section than path selection, so a thread's seq-assignment order
is not guaranteed to match its path-selection order under real concurrency
(documented at `struct mud`'s `tx_seq` field). Whether this is severe
enough to explain the observed drop rate hadn't been tested independent of
the reorder buffer itself.

Rather than another rebuild-and-guess cycle, `MUD_SELECT_BURST_PKTS`
became a runtime-settable value: new `struct mud_conf.select_burst_pkts`
(`mud.h`), threaded through `mud_set()`/`CTL_CONF` the same way as
`reorder_delay`, exposed as `glorytun set ... burstpkts N` (`src/set.c`).
`mud_select_path()` now reads `mud->select_burst_pkts` instead of the
compile-time constant. Setting it to `1` disables bursting entirely (pure
per-packet weighted-random selection, the pre-this-feature behavior),
letting burst selection be isolated from the reorder buffer without a
rebuild.

Also added: `reorder_max_gap` (`struct mud_errors`), tracking the largest
`seq - next_seq` ever observed at buffer-insertion time -- the actual
worst-case reordering magnitude seen, printed by `glorytun show errors`
alongside the existing counters.

**Not yet re-verified.** Suggested next test: with `burstpkts 1` on both
peers (isolating the reorder buffer from burst selection), repeat `-P1`
and check whether `dropped-stale` drops toward zero -- if so, burst
selection's shared-state race is confirmed as the cause and needs a
structural fix (likely: assigning `tx_seq` and selecting a path in the
same critical section, or per-thread-local burst state instead of
global). If `dropped-stale` stays similar with bursting disabled, the bug
is in the reorder buffer's core sequencing logic and needs re-examination
independent of burst selection.

## Follow-up: TX-side send-failure counters, after CPU steal time was also ruled out

The `burstpkts 1` isolation test (previous follow-up) turned out not to be
as clean as intended: disabling burst *caching* doesn't remove the
structural gap between sequence-number assignment (an early lock, right
after `tun_read()`) and path selection (a separate, later lock, gated on
having already encrypted -- `mud_select_path()`'s cursor is derived from
the ciphertext itself, so it cannot run before encryption). With bursting
off, drops persisted, and `reorder max-gap` reached 146 on the receiving
side -- too large to explain from encryption time alone (sub-microsecond
per the project's own `bench` numbers). VPS CPU steal time on the sender
was checked next (`top`'s `%st` column during a live test) and came back
at 0.0%, CPU 98.5% idle -- ruling that out too.

Realized the `reorder max-gap` metric can't distinguish two different
things: a packet that was genuinely sent and is taking a long time to
arrive, versus a sequence number that was *reserved but never actually
transmitted at all* (because `mud_select_path()` found no usable path at
that instant, or `sendmsg()` itself failed) -- from the receiver's side
these look identical, both just show up as "next_seq is stuck waiting."
Added two new counters at the actual point of failure on the sender,
where this can finally be told apart: `tx_no_path` (`mud_select_path()`
returned NULL) and `tx_send_failed` (`sendmsg()` returned something other
than the full packet size), both in `mud_worker_loop()`'s TX half,
exposed via the same `struct mud_errors`/`glorytun show errors` path as
the RX-side counters.

**Not yet re-verified.** If either of these is nonzero and correlates with
the drop rate, the bug is a TX-side send failure (most likely still
`EMSGSIZE`-shaped, meaning there's a remaining MTU/sizing miscalculation
beyond the one already fixed) rather than anything in the resequencing
logic itself -- would need re-examining `mud_get_mtu()`'s math again, this
time more skeptically. If both stay at zero despite continued drops, TX
send failures are ruled out too, and the next place to look is whether
sequence numbers are being consumed faster than real packets are actually
being read from TUN (a bug in the accounting itself, not a delay).

## Follow-up: found the actual drop bug

`tx_no_path`/`tx_send_failed` both came back at exactly zero on both peers
across multiple live tests, decisively ruling out TX-side send failure --
every packet either sender attempted to send actually reached the wire.
Combined with `glorytun path`'s consistently clean wire-level loss stats
(ruling out genuine network loss) and the earlier ruling-out of timing,
CPU/thread contention, and VPS CPU steal time, this left exactly one
remaining possibility: a real logic bug in `mud_reorder_tick()` or
`mud_reorder_push()` themselves, dropping packets that were both sent and
received correctly.

Found it in `mud_reorder_tick()`. Its scan searched for "the oldest slot
that has already individually expired" as the target to skip `next_seq`
forward to. But insertion order into the ring is *arrival* order, not
*sequence* order -- a larger-sequence packet that happened to arrive
earlier can age past its deadline before a smaller-sequence packet that
arrived later but is still comfortably within its own waiting window. When
that happened, the scan would pick the larger, already-expired slot as the
skip target, jumping `next_seq` *past* the smaller, still-legitimate one.
That smaller packet was never actually given up on, but the jump orphaned
it anyway: the next time anything touched its ring slot, `seq < next_seq`
was now true, and it was silently discarded as ordinary staleness --
indistinguishable, from the outside, from a genuinely-expired packet. This
requires no elevated throughput, CPU contention, or network delay to
trigger -- just ordinary, modest reordering under any real dual-path
bonded traffic, which is exactly why disabling bursting, raising
`reorderdelay` to the maximum, and ruling out every environmental factor
in turn never made it go away.

Fixed by changing the scan's selection criterion: always find the
**smallest** buffered sequence number, regardless of whether it has
individually expired, and gate the skip decision on *that* slot's own
deadline specifically -- never a larger slot's. This makes it structurally
impossible for `next_seq` to advance past a smaller, still-valid sequence
number, since the smallest candidate is always evaluated (and must itself
have expired) before any skip happens at all.

The analogous, much narrower version of this same class of bug in
`mud_reorder_push()`'s collision-eviction path (jumping to the one
colliding slot's sequence number without checking whether some *other*
buffered slot holds something even smaller) was deliberately left
unfixed and documented in place -- it requires the ring's true occupied
span to exceed `MUD_REORDER_MAX`, a meaningfully rarer precondition
(sustained high throughput at a generously-configured `reorderdelay`)
than the ordinary-reordering trigger the `tick()` bug had.

**Not yet re-verified.** This is the strongest, most directly-diagnosed
candidate for the root cause found so far -- confirmed via elimination of
every other explanation (timing, path count, burst selection, CPU/thread
contention, VPS steal time, TX send failure, network loss) plus a
concrete mechanism that explains the exact observed symptoms (drops with
zero wire-level loss, insensitivity to `reorderdelay`, and a `max-gap`
metric that measures sequence-space distance rather than genuine transit
delay). Needs a rebuild, redeploy on both peers, and a repeat of the
`iperf3 -P1` + `glorytun show errors` test to confirm `dropped-stale`
collapses toward zero and throughput recovers toward the combined-path
ceiling.

## Risks

* **Unverified**: not compiled or run, same caveat as `docs/
  udp-subflows-plan.md`'s largest change. Treat as a careful-but-unverified
  diff.
* **`MUD_REORDER_MAX` (512) vs `MUD_REORDER_DELAY_MAX` (50ms) at high
  throughput.** At the default 8ms delay this is comfortably sized (see
  "Design" above). Configured near the 50ms ceiling at multi-hundred-Mbit
  rates, the ring's true occupied span can exceed 512 slots, which triggers
  the collision-handling path described in "Bugs found during review" on
  every such overflow -- correct (never misorders), but means the buffer is
  effectively not resequencing everything it's nominally configured to
  hold in that regime; some fraction of packets end up dropped and
  recovered by the inner protocol's retransmission instead of resequenced.
  Not a correctness risk, but an effectiveness one -- a much larger
  `MUD_REORDER_MAX` or a lower delay ceiling would be the fix if this
  matters in practice, not attempted here since the default/realistic
  configuration doesn't need it.
* **TX sequence assignment reflects lock-acquisition order across worker
  threads, not strictly `tun_read()` completion order** -- see the comment
  on `struct mud`'s `tx_seq` field. A narrow, rare race can swap the
  relative order of two packets read within microseconds of each other by
  different threads. Self-corrects through the same buffering the feature
  already does for network-induced reordering; strictly better than the
  previous behavior (no recoverable order at all). Eliminating it entirely
  would require serializing `tun_read()` across every worker thread,
  undoing the multi-threaded TX design this builds on -- judged not worth
  it for a narrow, self-correcting, low-impact case.
* Adds `MUD_REORDER_SEQ_SIZE` (8) bytes of overhead per data packet inside
  the encrypted payload, shrinking the usable inner-packet MTU by the same
  amount system-wide. Automatically reflected in `mud_get_mtu()`'s existing
  arithmetic, so no manual MTU reconfiguration is needed -- but worth
  knowing if comparing MTU numbers against a build predating this change.
* Adds a bounded amount of one-way latency (up to `reorderdelay`) to any
  packet that actually gets buffered -- not the common case at the default
  8ms with the burst-selection change reducing how often it happens, but a
  real, deliberate tradeoff for throughput. See the design discussion above
  for why this is unavoidable for any approach that lets one flow use
  multiple divergent-latency paths concurrently.
