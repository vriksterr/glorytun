# Getting started

This guide builds Glorytun and starts one endpoint on a server and one on a
client. The examples use Linux, IPv4, UDP port 5000, and a TUN device named
`gt0`.

## Requirements

You need:

* a C99 compiler and `make` (or Meson and Ninja);
* git, including git-submodule support;
* libsodium 1.0.4 or newer and its development headers;
* Linux TUN support (`/dev/net/tun`) and permission to administer network
  interfaces; and
* synchronized clocks on both peers. The protocol rejects timestamps outside
  its configured tolerance.

On Linux, tunnel operation normally requires root or `CAP_NET_ADMIN`. Building,
generating a key, printing the version, and running the crypto benchmark do not
require those privileges.

## Fetch dependencies

For a fresh clone, include the submodules:

```sh
git clone --recurse-submodules https://github.com/angt/glorytun.git
cd glorytun
```

For an existing checkout:

```sh
git submodule update --init --recursive
```

The submodules provide the argument parser (`argz`) and encrypted multipath
transport (`mud`). A checkout without them cannot compile.

## Build

### With the system libsodium

The simplest repository build is:

```sh
make CPPFLAGS="$(pkg-config --cflags libsodium)" \
     LDFLAGS="$(pkg-config --libs-only-L libsodium)" \
     LDLIBS="$(pkg-config --libs-only-l libsodium)"
```

The top-level `Makefile` defaults to the bundled `.sodium` location. Supplying
the flags above points it at the installed library instead.

Alternatively, use Meson:

```sh
meson setup build
meson compile -C build
```

The resulting binary is `./glorytun` for Make or `./build/glorytun` for Meson.
See [Development](development.md) for Autotools, a private libsodium build, and
installation details.

Verify the binary:

```sh
./glorytun version
```

## Create the shared key

Generate one 32-byte key, encoded as 64 hexadecimal characters:

```sh
install -d -m 700 secrets
./glorytun keygen > secrets/glorytun.key
chmod 600 secrets/glorytun.key
```

Securely copy the same key file to the other peer. Anyone with this key can
authenticate as a peer, so do not commit it, log it, or send it over an
untrusted channel.

## Start both endpoints

The CLI uses bare words rather than `--flags`. Address groups accept both an
explicit form such as `from addr 0.0.0.0 port 5000` and the compact positional
form `0.0.0.0 5000` used by the bundled scripts.

On the server at `203.0.113.10`:

```sh
sudo ./glorytun bind \
  dev gt0 \
  keyfile secrets/glorytun.key \
  from addr 0.0.0.0 port 5000
```

On the client:

```sh
sudo ./glorytun bind \
  dev gt0 \
  keyfile secrets/glorytun.key \
  from addr 0.0.0.0 port 0 \
  to addr 203.0.113.10 port 5000
```

Using local port `0` asks the operating system to select an ephemeral client
port. Omitting `dev` makes Glorytun try `tun0` through `tun31`. Omitting address
options uses IPv4 wildcard address and UDP port 5000.

For IPv6, bind `::` rather than `0.0.0.0` and provide an IPv6 remote address.
Linux can receive both IPv4 and IPv6 traffic through an IPv6 wildcard socket
when the host's socket configuration permits it.

## Configure the inner network

In separate terminals, assign addresses after the TUN devices appear. For a
point-to-point example:

Server:

```sh
sudo ip address add 10.77.0.1/30 dev gt0
sudo ip link set gt0 up
```

Client:

```sh
sudo ip address add 10.77.0.2/30 dev gt0
sudo ip link set gt0 up
```

Then test from the client:

```sh
ping 10.77.0.1
```

Routing traffic beyond those two inner addresses requires additional routes,
IP forwarding, and usually firewall/NAT rules. Those choices are deployment
specific and are intentionally not performed by the `bind` command.

## Inspect and stop the tunnel

From another terminal under the same user identity as the tunnel process:

```sh
sudo ./glorytun list
sudo ./glorytun show dev gt0
sudo ./glorytun path dev gt0
sudo ./glorytun show dev gt0 errors
```

The management socket lives in a per-effective-user runtime directory. A
non-root command will therefore not discover a tunnel started as root; use
`sudo` consistently when needed.

Stop a foreground endpoint with `Ctrl-C` or send it `SIGTERM`. The TUN device is
removed on exit unless `persist` was passed to `bind`. A `SIGHUP` also stops the
process, but marks the TUN device persistent first.

## Next steps

Read [CLI reference](cli-reference.md) for path rate limits, failover settings,
clock tolerance, key rotation, and diagnostics. For managed Linux deployment,
see the systemd section in that document.
