# Factory Image — API

> **Status: NORMATIVE** · Scope: factory disk images on every transport · Last verified: 2026-09-16
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

**No API surface: build-host CLI only.** There is no `/api/v1/diskimage`
route, no gRPC service, no QUIC opcode, no MCP tool and no Unix-socket method
for this feature, and none is missing. Building an image runs `docker` and
`losetup` on a build host, under `--privileged`, against a local image file;
there is nothing for a daemon to serve, and no node identity exists yet to
authorise a request with. The embedded Go entry points are `diskimage.Create`,
`diskimage.Assemble` and `diskimage.Inspect` ([engineering.md §2](engineering.md#2-exported-surface)),
driven by [`platformctl diskimage`](cli.md).

This is a decision, not a gap: like the installer
([`docs/installer/api.md`](../installer/api.md)), the feature ends where the
device's first boot begins, and everything after that is served by
provisioning and attestation on their own routes.
