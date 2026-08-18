# Interface-based paths implementation plan

> Implementation status: the Linux interface-name path flow described here is
> implemented in this checkout. The milestone and acceptance sections remain
> as design rationale and a regression checklist.

This document is a self-contained implementation handoff for changing
Glorytun paths from IP-address identity to Linux interface-name identity.

The target behavior is that an operator configures a path once:

```sh
glorytun path up via wwan0 rate tx 10mbit rx 50mbit
```

If `wwan0` loses connectivity, changes address, or is deleted and recreated,
Glorytun must preserve the desired configuration and automatically probe it
again when it becomes usable. The operator must not need another `path down`
or `path up` command.

## Baseline

This plan was written against:

* Glorytun repository commit `32267e8`
* `mud` submodule commit `e991dc9b4510367c0d03540dabdc84188ab9d009`

The checkout initially has unpopulated `argz` and `mud` submodules. Initialize
them before compiling:

```sh
git submodule update --init --recursive
```

`mud` is a separate repository. Develop changes to its path API in a maintained
fork, commit them there, and update Glorytun's submodule commit. Do not leave
the main repository dependent on uncommitted submodule changes.

## Current behavior

The existing path lifecycle crosses these components:

1. `src/path.c` parses `addr LOCAL_IP`, `to REMOTE`, path state, rates,
   preference, beat, and loss limit.
2. It sends a native `struct ctl_msg` containing `struct mud_path_conf` to the
   running `bind` process.
3. `src/bind.c` handles `CTL_PATH_CONF` and calls `mud_set_path()`.
4. `mud_get_path()` identifies a path using local IP, remote IP, and remote
   port.
5. `mud_send_path()` places the configured local IP in `IP_PKTINFO` or
   `IPV6_PKTINFO` before `sendmsg()`.
6. `mud_recv()` extracts the receiving local IP from ancillary packet data and
   uses it to locate or create a path.

A DHCP or mobile-network address change therefore produces a different path
identity. The configured physical interface is not represented anywhere.

Runtime recovery already exists for an unchanged path. An administratively
`MUD_UP` path may become `MUD_DEGRADED`, `MUD_LOSSY`, or `MUD_PROBING`; it
continues sending tracking messages and can return to `MUD_RUNNING`. The
missing behavior is rebinding that logical path after a local interface-index
or address change.

## Scope

### Required

* Linux-first implementation.
* Configure an active path using a physical interface name.
* Bind outgoing packets using the interface's kernel index.
* Monitor link and address events with rtnetlink.
* Preserve desired configuration while the interface is unavailable.
* Rebind and reprobe automatically after an address or index change.
* Preserve the existing IP-address CLI as a compatibility mode.
* Show interface name, current index, current address, and runtime state.
* Add repeatable network-namespace integration tests.

### Non-goals

* Do not identify paths by MAC address.
* Do not add multithreaded or multicore processing in this change.
* Do not change the encrypted on-wire protocol.
* Do not add one UDP socket per interface yet; retain the shared socket and use
  packet-info ancillary data.
* Do not implement macOS or BSD monitoring in the first milestone.

## Design invariants

Keep these concepts separate:

```text
configured identity:  interface name, for example wwan0
runtime identity:     interface index, for example 12
runtime address:      current IPv4 or IPv6 address
administrative state: desired up/down state
health state:         probing/degraded/lossy/running
```

An outage changes health and runtime state. It must not silently change the
administrative state from up to down.

Interface names are configuration. Interface indices and addresses are
replaceable runtime values. An interface may be recreated under the same name
with a new index.

## User-facing CLI

Add `via INTERFACE` to the `path` command:

```sh
glorytun path up via wwan0 rate tx 10mbit rx 50mbit
glorytun path down via wwan0
glorytun path via wwan0
glorytun path via wwan0 mtu
glorytun path via wwan0 rtt
glorytun path via wwan0 stat
```

Keep current commands working:

```sh
glorytun path up 192.0.2.20 rate tx 10mbit rx 50mbit
glorytun path addr 192.0.2.20
```

`dev` continues to identify the Glorytun TUN device. `via` identifies the
physical interface, avoiding an ambiguous second use of `dev`.

Reject requests containing both `via` and a local `addr`. Initially, infer the
address family from the configured remote endpoint. An IPv4 remote selects an
IPv4 interface address and an IPv6 remote selects an IPv6 address.

Validate the name against `IFNAMSIZ` and reject empty or truncated names.

## Proposed state structures

Keep durable, user-facing bindings in Glorytun rather than transmitting
interface names through `mud`:

```c
struct gt_managed_path {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    union mud_sockaddr current_local;
    union mud_sockaddr remote;
    struct mud_path_conf desired_conf;
    int desired_up;
    int link_up;
    int address_ready;
};
```

The exact container may be an array bounded by `MUD_PATH_MAX`. It must support
lookup by interface name, address family, and remote endpoint. More than one
remote endpoint may use the same interface.

Add local interface-index information to the `mud` path configuration:

```c
struct mud_path_conf {
    /* existing fields */
    unsigned int local_ifindex;
};
```

`local_ifindex == 0` means legacy address-based behavior. This is local
metadata; do not add it to `struct mud_msg` or transmit it to the peer.

The local control protocol may grow because it is already native and
same-build. One simple source change is interface metadata outside the payload
union:

```c
struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    char tun_name[64];
    char ifname[IFNAMSIZ];
    /* existing union */
};
```

Every sender must zero-initialize messages as it does today. Old and new
binaries are not expected to share this private protocol.

## Address-selection policy

An interface can have several addresses. Make selection deterministic and
isolate it behind a helper so policy can evolve.

For IPv4:

1. Ignore loopback.
2. Ignore `169.254.0.0/16` unless link-local behavior is added explicitly.
3. Prefer the primary non-link-local address reported by rtnetlink.

For IPv6:

1. Ignore loopback and tentative, duplicate, or deprecated addresses.
2. Ignore link-local addresses for non-link-local remotes.
3. Prefer a stable global address over a temporary privacy address.

If no suitable address exists, retain the managed path as desired-up but do
not schedule it. Report `waiting-address` in status output.

Do not alternate between several eligible addresses. Retain the selected
address while valid and re-evaluate after relevant netlink events.

## Linux interface monitoring

Add a small rtnetlink subsystem, for example:

```text
src/netlink.c
src/netlink.h
src/path_manager.c
src/path_manager.h
```

Subscribe to:

```text
RTMGRP_LINK
RTMGRP_IPV4_IFADDR
RTMGRP_IPV6_IFADDR
```

Handle at least:

```text
RTM_NEWLINK
RTM_DELLINK
RTM_NEWADDR
RTM_DELADDR
```

Add the netlink descriptor to the `select()` loop in `gt_bind()`. Drain all
pending messages when readable, then run one reconciliation pass. Netlink
notifications are not guaranteed to describe every intermediate transition;
reconcile against current state rather than trusting a single event.

Use the stored name to recover after recreation:

```text
wwan0 ifindex 12 disappears
wwan0 ifindex 19 appears
managed path changes to index 19 and reprobes
```

## Reconciliation state machine

Run reconciliation after configuration and relevant netlink events:

```text
desired down
    -> administratively disable runtime path

desired up + interface absent/down
    -> retain configuration
    -> stop normal scheduling
    -> report interface-down

desired up + interface present + no eligible address
    -> retain configuration
    -> stop normal scheduling
    -> report waiting-address

desired up + usable interface/address unchanged
    -> no operation

desired up + new index or address
    -> rebind existing logical path
    -> reset path-dependent measurements
    -> enter probing
```

Do not implement address changes by repeatedly creating paths and leaving old
entries in `MUD_DELETING`. Address churn could exhaust `MUD_PATH_MAX`.

## `mud` changes

### Transmit binding

In `mud_send_path()`, retain source-address behavior and set the interface
index when non-zero.

IPv4 with `IP_PKTINFO`:

```c
struct in_pktinfo *pi = CMSG_DATA(cmsg);
pi->ipi_ifindex = path->conf.local_ifindex;
pi->ipi_spec_dst = path->conf.local.sin.sin_addr;
```

IPv6:

```c
struct in6_pktinfo *pi6 = CMSG_DATA(cmsg);
pi6->ipi6_ifindex = path->conf.local_ifindex;
pi6->ipi6_addr = path->conf.local.sin6.sin6_addr;
```

Where packet-info has no interface index, leave it zero and retain legacy
behavior.

### Receive identity

Change `mud_localaddr()` to return the receiving local address and incoming
interface index when ancillary data provides it. Path lookup should:

* use interface index plus remote endpoint for interface-managed paths; and
* fall back to local address plus remote endpoint for legacy paths.

This permits a reply received on the same interface after an address change to
belong to the same logical path.

### In-place rebind API

Add an explicit local API for changing a path's runtime binding without losing
its administrative configuration. The exact signature may be adjusted:

```c
int mud_rebind_path(struct mud *mud,
                    unsigned int old_ifindex,
                    union mud_sockaddr *remote,
                    unsigned int new_ifindex,
                    union mud_sockaddr *new_local);
```

Rebinding must preserve:

* administrative state;
* transmit and receive rate configuration;
* preference;
* beat interval;
* loss limit; and
* fixed/automatic rate mode.

Rebinding must reset or reinitialize:

* observed public endpoint;
* MTU probing and confirmed MTU;
* RTT estimate;
* transient loss measurements;
* keepalive/probe counters; and
* runtime status, which returns to `MUD_PROBING`.

Preserve key/session state; a local DHCP change should not require replacing
the long-lived secret.

## Status output

Show desired identity and runtime resolution:

```text
IFACE  INDEX  LOCAL          REMOTE            STATUS
wwan0  12     10.24.8.17    203.0.113.5.5000  running
eth1   4      -              203.0.113.5.5000  interface-down
wlan0  7      -              203.0.113.5.5000  waiting-address
```

Keep MTU, RTT, and statistics views. Legacy address paths may display `-` in
the interface column.

## Files expected to change

Glorytun repository:

```text
src/path.c          CLI parsing, selectors, status formatting
src/ctl.h           local interface-name control metadata
src/bind.c          managed paths, reconciliation, netlink event-loop input
src/argz.c/.h       reusable interface-name parser, if useful
src/netlink.c/.h    Linux rtnetlink monitoring and address selection
src/path_manager.c/.h desired/runtime path state and reconciliation
Makefile            new source files
Makefile.am         new source files
meson.build         new source files
docs/cli-reference.md
docs/architecture.md
```

`mud` fork:

```text
mud.h               interface index and rebind API
mud.c               packet binding, receive identity, lookup, rebind
test.c              focused identity/rebind tests where practical
```

Keep all three Glorytun build source lists synchronized.

## Integration testing

Add a Linux network-namespace test with a client namespace containing `wan0`,
`wan1`, and the client TUN, plus a server namespace and intermediate
network/NAT namespaces as needed.

Required cases:

1. Configure a path using only `via wan0`.
2. Confirm packets leave through `wan0` when the default route points elsewhere.
3. Bring `wan0` down and verify it leaves normal scheduling.
4. Restore the same address and verify automatic recovery.
5. Replace its address and verify recovery without another CLI command.
6. Delete and recreate `wan0`; verify recovery with its new index.
7. Keep a second path carrying traffic throughout the outage.
8. Repeat address changes more than `MUD_PATH_MAX` times without a slot leak.
9. Verify rates, preference, beat, and loss limit survive rebinding.
10. Verify IPv4 and IPv6 independently.
11. Verify multiple-address selection follows the documented policy.
12. Verify legacy `addr LOCAL_IP` still works.
13. Verify `via` and `addr` together are rejected.
14. Verify all existing status and control commands still work.

Run the handwritten Makefile and Meson builds. If packaging changes, also run
the Autotools build and `make distcheck`.

## Acceptance criteria

The feature is complete when:

* A path can be configured with `via INTERFACE` and no local IP.
* Packets are forced through the selected interface index.
* Link loss removes the path from normal scheduling without clearing desired
  administrative state.
* The same path automatically returns after restoration.
* Address and interface-index changes trigger in-place rebinding and probing.
* Healthy paths continue carrying traffic during another path's outage.
* No manual down/up command is required.
* Repeated churn leaks no path slots or stale control entries.
* The encrypted wire format remains unchanged.
* Address-based CLI behavior remains supported.

## Implementation milestones

### Milestone 1: CLI and static resolution

Add `via`, resolve the current index/address when configured, and bind outgoing
packet-info to the index. Verify routing through the intended interface.

### Milestone 2: Managed path state

Store desired bindings in `bind`, add status output, and separate desired-up
from runtime availability.

### Milestone 3: Netlink reconciliation

Add link/address notifications and move managed paths automatically among
interface-down, waiting-address, probing, and running.

### Milestone 4: In-place `mud` rebinding

Preserve configuration, reset only path-dependent measurements, and test
repeated address and interface-index churn.

### Milestone 5: Integration and compatibility

Add namespace tests, IPv6 coverage, all build-system updates, documentation,
and regression validation for address-based paths.

## Risks

* A source IP alone does not guarantee an output interface; packet-info must
  include the interface index.
* Interface indices do not persist across recreation.
* IPv6 temporary and deprecated addresses can cause unintended churn.
* Rtnetlink events may arrive in surprising sequences; reconcile from current
  state.
* Control-message layout changes require CLI and daemon from the same build.
* Direct changes in an uncommitted submodule are easy to lose.

## Starter prompt for another Codex task

Use this prompt from the repository workspace:

> Implement the Linux-first interface-name path feature described in
> `glorytun/docs/interface-paths-plan.md`. Read the entire plan and the current
> Glorytun and pinned `mud` sources before editing. Work milestone by milestone,
> preserve legacy IP-based path configuration, do not change the encrypted wire
> format, update all three build systems, and add network-namespace tests for
> link loss, DHCP address change, and interface recreation. Treat the interface
> name as durable configuration and interface index/IP as runtime state. Report
> any plan assumption that the existing `mud` API makes impossible before
> expanding scope.
