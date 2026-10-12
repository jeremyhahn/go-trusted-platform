# Gateway documentation has moved

The gateway is documented in one place: the [`docs/gateway/`](../../gateway/)
feature folder.

- [architecture.md](../../gateway/architecture.md) — service sections, trust
  boundaries, the base pipeline, high availability
- [engineering.md](../../gateway/engineering.md) — packages, errors, the load
  balancer datapath, the handler libraries in `modes/`
- [cli.md](../../gateway/cli.md) — `platformctl sdn gateway` (incl. `lb`,
  `nat64`, `perf`) and `gatewayd`
- [api.md](../../gateway/api.md) — REST, gRPC, QUIC, MCP and Unix surfaces
- [user.md](../../gateway/user.md) — configuring and operating a gateway

Gateway modes (overlay, edge, transit) are deprecated compatibility, not the
model: a gateway runs the service sections its configuration enables.
