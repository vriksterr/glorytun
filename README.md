# Glorytun

Glorytun is a small, simple and secure multipath UDP tunnel.

Please use the [stable branch](https://github.com/angt/glorytun/tree/stable).
Visit the [wiki](https://github.com/angt/glorytun/wiki) for how-to guides,
tutorials, etc.

## Features

The key features of Glorytun come directly from [mud](https://github.com/angt/mud).

 * **Fast and highly secure**

   When AES-NI is available, the new and extremely fast AEAD construction
   [AEGIS-256](https://github.com/angt/aegis256) is used.
   Otherwise, an automatic fallback to ChaCha20-Poly1305 is done in both peers.
   All messages are encrypted, authenticated and timestamped to mitigate a
   large set of attacks.
   This implies that the client and the server must be synchronized,
   an offset of 10min is accepted by default.
   Perfect forward secrecy is also implemented with ECDH over Curve25519.
   Keys are rotated every hours.

 * **Multipath and failover**

   Connectivity is now crucial, especially in the SD-WAN world.
   This feature allows a TCP connection (and all other protocols) to explore
   and exploit all available links without being disconnected.
   Aggregation should work on all conventional links.
   Only very high latency (+500ms) links are not recommended for now.
   Backup paths are also supported, they will be used only in case of emergency,
   it is useful when aggregation is not your priority.

 * **Traffic shaping**

   Shaping is very important in network, it allows to keep a low latency
   without sacrificing the bandwidth.
   It also helps the multipath scheduler to make better decisions.
   Currently it must be configured by hand, but soon Glorytun will do it
   for you.

 * **Fixed, operator-set MTU**

   Bad MTU configuration is a very common problem in the world of VPN.
   Each path sends at a single fixed wire size (`path up ... mtu N`,
   default 1400) rather than probing for it -- no ICMP next-hop MTU
   dependency, and nothing to black-hole. Set on one end, the value is
   advertised to the peer and adopted there automatically unless it has its
   own explicit value configured too. In asymmetric situations the tunnel's
   effective MTU is the minimum of every path's own fixed size.

## Changes in this fork

This build carries a few changes on top of upstream glorytun/mud, beyond the
interface-rebinding patch (`mud_rebind_path`, `via IFACE` path selection)
this fork's `mud` submodule already added. None of them touch the wire
protocol, so they're safe to deploy on one end of a tunnel at a time.

 * **Pinned rates actually stay pinned**

   Previously, an explicitly configured `path ... rate tx X` could be
   silently overwritten within about 100ms by the peer's own advertised
   `rx` rate, every time a keepalive arrived. A path's tx rate is now
   marked pinned once set locally, and the peer can no longer reset it.

 * **Multi-core encryption and decryption**

   AEAD encrypt/decrypt now run across a worker-thread pool sized to the
   machine's CPU core count instead of a single core doing all the crypto
   work. Path selection, rate limiting, and the actual socket I/O stay
   single-threaded, since those hold shared tunnel state that isn't safe
   to parallelize without a much larger rewrite.

   This does not scale to very high core counts. The pool is capped at
   8 worker threads (`MUD_WORKERS_MAX` in `mud/mud.c`) regardless of how
   many cores are available, and even without that cap, throughput would
   plateau well before it: every worker pulls jobs from a single
   mutex-protected queue, and the packet-read/path-selection/socket-I/O
   work described above is single-threaded no matter the core count.
   Expect this to help meaningfully on machines with roughly 2-8 cores;
   a 64- or 128-core box will not see proportional gains from it alone.

 * **Batched packet I/O**

   The main event loop drains up to 256 packets per direction per wakeup
   instead of one, cutting `select()`/syscall overhead per packet at high
   throughput. The tx-rate limiter is still enforced exactly as before,
   just decided per batch instead of per packet.

 * **Configurable RTT-based path health (`rttlimit`)**

   A new `path ... set rttlimit DURATION` option, mirroring the existing
   `losslimit`: once a path's measured RTT exceeds the configured limit
   it's marked `late` and excluded from the active bond, automatically
   rejoining once RTT recovers.

 * **Richer default `path` status output**

   `glorytun path` with no arguments now also prints RTT, TX-LOSS, and
   RX-LOSS alongside STATUS/PUBLIC, instead of requiring a separate
   `show rtt` or `show stat` call.

 * **Optional packet resequencing (`reorderwindow`)**

   Multipath striping schedules per packet, not per flow, so a single
   TCP-like flow crossing several paths at once routinely sees packets
   arrive out of order and throttles itself as if they'd been lost. `set
   ... reorderwindow DURATION` (off by default) buffers decrypted packets
   briefly, tunnel-wide, and releases them in send order instead of arrival
   order, trading up to that much added latency for a single flow being
   able to use more of the tunnel's combined throughput. See "Packet
   resequencing" in `docs/architecture.md`.

## Compatibility

Glorytun only depends on [libsodium](https://github.com/jedisct1/libsodium)
version >= 1.0.4.
Which can be installed on a wide variety of systems.

Linux is the platform of choice but the code is standard so it should be
easily ported on other posix systems.
It was successfully tested on OpenBSD, FreeBSD and MacOS.

IPv4 and IPv6 are supported.
On Linux you can have both at the same time by binding `::`.

---
For feature requests and bug reports,
please create an [issue](https://github.com/angt/glorytun/issues).
