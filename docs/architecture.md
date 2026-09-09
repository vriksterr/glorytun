# Architecture

Glorytun is a small, multi-threaded layer-3 tunnel. The executable combines a
TUN adapter, the `mud` encrypted multipath transport, and a local management
server. There is no persistent configuration database. Every worker thread
runs the entire packet pipeline end to end -- receive, decrypt, path lookup,
encrypt, send -- rather than one thread doing I/O and handing crypto off to a
pool; see "Cryptography, session behavior, and threading" below for why, and
for the locking that makes several threads touching the same session safe.

## Runtime overview

```text
inner IP packets
      |
      v
  TUN device <===> worker threads (N, one full pipeline each) <===> UDP socket pool
                         ^                    |
                         |                    +-- encryption/key exchange
                         |                    +-- multipath scheduling
                         |                    +-- MTU/rate/loss tracking
                         |
                 Unix datagram socket
                         ^
                         |
              list/show/set/path commands
```

The `bind` command owns the TUN, UDP, and control descriptors. On Linux it also
owns an rtnetlink descriptor subscribed to link and IPv4/IPv6 address changes.
`N` worker threads (`mud_worker_count()`, see below) each run `mud_worker_loop()`
-- a `poll(2)`-based loop over the TUN device and every socket in the
instance's pool, moving packets in whichever direction is ready with no
hand-off to another thread. The main thread that spawned them is left with
only housekeeping that isn't per-packet: a `select(2)` loop over the control
and netlink descriptors, calling `mud_update()` for protocol timers,
servicing control requests, reconciling interface-managed paths, and applying
MTU changes.

## Data path

Each worker thread's `mud_worker_loop()` iteration does both directions
itself, in whichever order the just-completed `poll()` found ready:

### Outbound

1. `tun_read()` reads an inner IPv4 or IPv6 packet from the TUN interface.
2. `mud_send_wait()` provides transport backpressure -- if the rate window is
   depleted, the thread backs off with a short sleep rather than spinning on
   an always-readable TUN fd, and leaves the packet for the next iteration.
3. The packet is encrypted and scheduled over an available UDP path.

The maximum stack buffer is bounded by `MUD_MTU_HARD_MAX`. The effective
tunnel MTU is managed by `mud`, so normal packets should remain well within
that bound.

### Inbound

1. A packet is received and decrypted from whichever pool socket the
   `poll()` call found readable.
2. `ip_is_valid()` accepts only structurally consistent IPv4 or IPv6 packets:
   the IP version and encoded total/payload length must match the received
   length. This check now lives in `bind.c` (`gt_tun_write_validated()`),
   passed into `mud_worker_loop()` as its `tun_write` callback -- the `mud`
   library itself has no IP-format awareness, deliberately.
3. `tun_write()` injects the packet into the host's layer-3 stack.

Concurrent `recvmsg()`/`sendmsg()`/`tun_read()`/`tun_write()` calls from
multiple worker threads against the same socket or TUN fd are safe: the
kernel hands each call a distinct queued packet, with no coordination needed
between threads for the I/O itself.

BSD-style TUN devices include a four-byte address-family header. `src/tun.c`
adds or removes it on macOS and OpenBSD; Linux uses `IFF_NO_PI` and transfers
plain IP packets.

## Control plane

Each `bind` process creates a Unix datagram socket named after its TUN device in
a per-effective-user runtime directory. Short-lived CLI invocations create a
temporary client socket, send a fixed-size `struct ctl_msg`, receive one or
more replies, print the result, and remove their socket.

The request types are:

* `CTL_STATUS` — PID, MTU, cipher, and endpoints;
* `CTL_CONF` — tunnel-wide key-exchange, clock, and keepalive values;
* `CTL_PATH_STATUS` — a streamed list of matching paths;
* `CTL_PATH_CONF` — path state, preference, loss, beat, and rates; and
* `CTL_ERRORS` — decryption, clock, and key-exchange counters.

Path-list replies use `EAGAIN` as a continuation marker, followed by a final
reply with a zero result. This protocol copies native C structures directly;
it assumes local communication between matching builds and should not be
treated as a portable ABI.

Interface-managed path configuration is retained in the bind process. The
interface name is durable configuration; its kernel index and selected address
are runtime values. Link loss suspends the corresponding `mud` path without
clearing the desired-up state. A new address or index triggers an in-place
rebind that preserves configuration and returns runtime measurements to the
probing state. Legacy address-identified paths continue to be owned directly
by `mud`.

## Path health

Each path reports round-trip time and, per direction, two loss figures --
never a value taken on trust from the peer. `TX-LOSS` (of what this side
sent, how much the peer confirms receiving) and `RX-LOSS` (of what the peer
sent, how much this side actually received) are both derived from real local
packet counters exchanged in every tracking message, not a self-reported
number copied as-is.

Loss is tracked as a rolling window of 60 one-second buckets. A *stable*
figure is the combined count across the whole window and is what drives the
`lossy` path state; a *live* figure is the most recently closed bucket alone,
refreshed roughly every second, shown separately so the status view can be
responsive without a single noisy second being able to flip a path's state on
its own. Neither figure is fabricated from too little evidence: while a path
has carried no real traffic in the last second, both hold their last reading
rather than computing a percentage from a single sparse heartbeat.

## Packet resequencing

Multipath striping (see `mud_select_path()`, above) selects a path per
packet, weighted by measured capacity -- not per flow. A single ordered
protocol's packets (almost always TCP) crossing several physical paths at
once routinely arrive out of order at the far end, since paths differ in
latency. TCP reads that as loss (duplicate ACKs, fast retransmit) and
throttles itself, even though nothing was actually dropped -- this is why a
single flow measures far below a multipath tunnel's combined throughput
while several concurrent flows, run in parallel, add up to close to it.

`mud_conf.reorder_window` (`glorytun set ... reorderwindow DURATION`,
default off) addresses this at the transport layer, so it benefits every
ordered-delivery protocol riding the tunnel without any change on either
end's applications. When set, `mud_worker_loop()`'s receive side briefly
buffers decrypted data packets, tunnel-wide (across every path, not
per-path, since reordering happens *between* paths), and releases them to
the TUN device in ascending send-timestamp order rather than arrival order.
No wire-protocol change was needed: every data packet already carries the
sender's timestamp (the same field `mud_recv_finish()` uses for its
replay/clock-tolerance check), previously discarded after that check.

A buffered packet is released once either a newer packet has arrived that's
a full `reorder_window` ahead of it, or it has simply been waiting
`reorder_window` locally with nothing newer arriving (the backstop for
traffic going quiet mid-window). The second comparison is deliberately
against this side's own clock only, never the peer's -- the two sides'
clocks are only loosely synchronized (minutes, via `timetolerance`), nowhere
near the precision resequencing would need, so the two clock domains are
never mixed. The buffer is fixed-size (`MUD_REORDER_MAX` slots in `mud.c`)
and never blocks or drops a packet to make room: a packet that doesn't fit
is simply delivered immediately, unreordered, exactly like every packet is
when the feature is off. Correctness never depends on this buffer; only the
reordering benefit does.

This is a real latency/throughput trade-off, not a free improvement: raising
`reorder_window` lets a single flow tolerate more cross-path skew before its
congestion control reacts, at the cost of adding up to that same duration of
latency to every packet on the tunnel, including traffic that isn't the
flow benefiting from it. It defaults to off (`0`) so existing deployments
see no behavior change unless explicitly configured. The single-packet
`mud_recv()`/`mud_send()` API (used directly by `mud/test.c`, bypassing
`mud_worker_loop()`) is entirely unaffected -- resequencing only ever
happens on the worker-thread receive path `bind` actually runs.

## Cryptography, session behavior, and threading

`bind` initializes libsodium and passes the 32-byte pre-shared secret to
`mud_create()`. The transport submodule owns authentication, ephemeral key
exchange, key rotation, replay/timestamp policy, encryption, path discovery,
and packet scheduling.

Glorytun requests AEGIS-256 unless `chacha` is specified. `mud_create()` can
clear that request when the cipher is unavailable, causing the process to log
the fallback and use ChaCha20-Poly1305. Configuration and error queries are
forwarded to the transport through its public API.

### Worker threads: one full pipeline each, not a shared crypto pool

Earlier versions of this design kept one thread doing all socket I/O and
path bookkeeping, and handed only the AEAD encrypt/decrypt step off to a
fixed pool (`min(online cores - 1, 8)` threads) that woke on a condition
variable, pulled jobs from one shared counter, and slept again. That
architecture was replaced (see `docs/udp-subflows-plan.md`'s follow-up
entries for the full history) after live testing kept showing one core
pegged and the others nearly idle under real sustained throughput, even
after two rounds of fixing the crypto batching itself: the actual ceiling
was per-packet socket I/O (`recvmsg()`/`sendmsg()`/TUN read/write) and path
bookkeeping *outside* the crypto call, none of which the pool touched, all
of it serialized on the one collecting thread by design.

The current design instead spawns `mud_worker_count()` threads
(`min(online cores - 1, 8)`, floored at 1 rather than 0 -- there is no
separate "calling thread" that falls back to doing everything inline
anymore, so even a single-core host needs one real worker), each running
`mud_worker_loop()`: a full receive-decrypt-lookup-write and
read-encrypt-select-send pipeline, with no hand-off between threads at any
stage. `glorytun bench multicore`'s "pool" mode still measures a
shared-job-counter pattern for reference, but that pattern no longer exists
in the real implementation -- see the comment on `gt_bench_pool_worker()` in
`src/bench.c`.

Making that safe required two changes to `struct mud`'s internals:

* **`mud->paths` and `mud->sock` are fixed-size arrays** (`MUD_PATH_MAX`
  paths, `MUD_SOCK_MAX` sockets), allocated once in `mud_create()`, never
  `realloc()`'d. A pointer or index one worker thread is using can no
  longer be invalidated by another thread growing the array underneath it.
  `connections N` (splitting a path into `N` independent UDP sub-flows,
  see `path up ... connections N` in the CLI reference) still works the
  same way from the outside -- `mud_set_sock_count()` still grows
  `sock_count` on demand -- it just fills in more of an already-allocated
  array instead of moving it.
* **Two mutexes guard everything mutable in `struct mud`**: `state_lock`
  covers path/socket-pool state, rate/window accounting, and error
  counters; `keyx_lock` covers the session key-exchange state (`mud->keyx`)
  separately, since it's touched by both the per-packet crypto path and the
  much less frequent key-rotation path. Both are held only around plain
  memory access (array scans, struct field reads/writes) and are never held
  across a syscall or the AEAD encrypt/decrypt call itself -- see the
  locking summary on `mud_worker_loop()` in `mud.c`. Encrypt/decrypt instead
  copy out the small, fixed-size key material they need under a brief lock
  and operate on that local copy, so multiple threads' crypto calls still
  run fully in parallel regardless of how many are in flight; only the
  bookkeeping around them briefly serializes, and it's cheap enough
  (microseconds of simple arithmetic, not a syscall) that this doesn't
  meaningfully limit throughput.

A single `struct mud` instance -- one crypto session, one key exchange --
can still own more than one local UDP socket, used to split a single
logical path into several independent UDP sub-flows (see `path up ...
connections N` in the CLI reference). `connections N` is user-defined
rather than fixed by the library; the only real ceiling is `MUD_SOCK_MAX`
(256), which exists purely because `struct mud_path_conf.sock` is a single
`unsigned char` -- not a design opinion about how many sub-flows are
useful. The socket pool is shared per-instance, not per-remote or
per-path: any path's `struct mud_path_conf.sock` just selects which pool
socket it sends/receives on.

`mud.c` deliberately has no dependency on `src/tun.c` or glorytun's own IP
validation -- `mud_worker_loop()` takes TUN read/write as plain function
pointers (`mud_tun_read_fn`/`mud_tun_write_fn`) matching `tun_read()`/
`tun_write()`'s signatures exactly, so `bind.c` passes them straight
through (wrapping `tun_write` with an `ip_is_valid()` check first -- see
"Data path" above). This keeps `mud` a standalone, reusable transport
library rather than something coupled to this specific TUN/IP-validation
implementation.

Note `bind`'s housekeeping loop still uses `select(2)` for the control and
netlink descriptors, and each worker thread uses `poll(2)` for the TUN
device and its socket pool -- neither is `FD_SETSIZE`-constrained the way a
single shared `select(2)` loop across every descriptor would be, since the
control/netlink loop only ever watches two descriptors and each worker's
`poll()` set (TUN plus up to `MUD_SOCK_MAX` sockets) is independent of the
others.

## MTU management

There is no discovery or probing: each path sends at a single fixed wire size,
set once and never adjusted based on send failures or black-holed traffic.
`mud_path_conf.mtu` holds it; `0` means the library default (`MUD_MTU_DEFAULT`,
1400), and any configured value is hard-clamped to `MUD_MTU_HARD_MAX` (65535)
purely as a backstop, since the fixed packet buffers throughout `mud` are
sized to that constant -- not a realistic operating value.

An explicitly configured size (`path up ... mtu N`) always wins locally and is
authoritative for that path. It is also sent to the peer in every beat
message (`mud_msg.mtu`), so a path that has no explicit local configuration of
its own instead adopts whatever its peer last advertised, re-applied on every
beat. This is a live fallback, not a one-time negotiation: it keeps tracking a
later change to the peer's configured value, and if both ends of a path leave
it unconfigured, the peer that does set it drives the value for both sides.
Setting it on one end (typically the side you control, e.g. the client) is
enough to put the whole path on that size without configuring the other end
to match.

`bind`'s tunnel-wide MTU (what actually reaches the TUN device) is the minimum
wire size across every currently up path, recomputed each housekeeping tick.
On every iteration, `bind` checks `mud_get_mtu()` and, when the value is
non-zero and changed, uses `SIOCSIFMTU` to update the TUN interface. An MTU
update requires network-administration privileges. Failure is logged but does
not terminate the tunnel.

## Process lifecycle

Startup order:

1. install signal handlers;
2. parse the command and initialize libsodium;
3. read the shared key;
4. create the `mud` transport/UDP socket;
5. create the TUN device and set its initial MTU/persistence;
6. create the local control socket; and
7. enter the event loop.

Shutdown destroys the transport and deletes the control socket. Closing a
non-persistent TUN descriptor removes that interface on supported platforms.
`SIGHUP` first requests persistence and then follows the same shutdown path.

## Source map

| Path | Responsibility |
| --- | --- |
| `src/main.c` | signal setup and top-level command dispatch |
| `src/bind.c` | tunnel creation, event loop, packet forwarding, control server |
| `src/netlink.c` | Linux link/address notifications and address selection |
| `src/path_manager.c` | durable interface bindings and runtime reconciliation |
| `src/tun.c` | Linux, macOS, and BSD TUN device adaptation |
| `src/iface.c` | interface MTU update |
| `src/ip.h` | minimal inbound IPv4/IPv6 length validation |
| `src/ctl.c`, `src/ctl.h` | local socket discovery and management protocol |
| `src/argz.c`, `src/argz.h` | Glorytun-specific CLI value parsers/formatters |
| `src/list.c` | active-tunnel discovery |
| `src/show.c` | status and error reporting |
| `src/set.c` | tunnel-wide live configuration |
| `src/path.c` | path filtering, configuration, and status tables |
| `src/keygen.c` | shared-secret generation |
| `src/bench.c` | cipher microbenchmark, single- and multi-core |
| `argz/` | command parser submodule |
| `mud/` | encrypted multipath UDP transport submodule |
| `systemd/` | instance service, setup helper, and networkd profiles |

## Platform boundaries

* Linux opens `/dev/net/tun`, creates devices with `TUNSETIFF`, supports
  persistence, and updates MTU through an ioctl.
* macOS creates `utunN` through the kernel-control socket API.
* Other supported BSDs open `/dev/tunN`; OpenBSD uses the BSD packet framing
  path.
* `tun_set_persist()` returns `ENOSYS` where the platform has no
  `TUNSETPERSIST` equivalent.
* The systemd/networkd deployment files are Linux-specific even though the core
  packet path has portability code.

## Trust and privilege boundaries

The pre-shared key is the primary long-lived secret. The control directory is
mode `0700`, which limits management commands to the tunnel's effective user,
subject to normal superuser access. Tunnel creation and MTU changes interact
with privileged kernel networking APIs.

The inbound validation in `ip.h` is deliberately minimal: it checks packet
version and length consistency, not checksums or higher-level semantics. Full
IP processing remains the host kernel's responsibility after TUN injection.
