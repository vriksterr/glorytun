# Glorytun documentation

These documents describe the code in this repository. The `master` branch is
the development line; the project README recommends the `stable` branch for
deployments.

## Start here

* [Getting started](getting-started.md) explains how to fetch dependencies,
  build Glorytun, create a shared key, and start a minimal two-peer tunnel.
* [CLI reference](cli-reference.md) documents the commands implemented by the
  `glorytun` binary.
* [Architecture](architecture.md) follows packets and control messages through
  the process and maps the source tree.
* [Development](development.md) describes the build variants, CI, validation,
  and the main extension points.
* [Interface-based paths plan](interface-paths-plan.md) is an implementation
  handoff for configuring paths by Linux interface name and surviving address
  changes automatically.

## Scope

Glorytun creates an encrypted layer-3 tunnel. It creates the TUN interface and
updates its discovered MTU, but it does not generally assign interface
addresses, add routes, or configure forwarding. Those host-networking steps
belong to the operator or to the included systemd/networkd integration.

The `mud` and `argz` directories are git submodules. Initialize them before
building or following source references into those directories.
