# Trust — API

> **Status: NORMATIVE** · Scope: trust capabilities on every transport · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G<n>`, never omitted.

---

## 1. Trust is an in-process library, not a service

`pkg/trust` has no proto service, no REST route, no QUIC opcode and no MCP tool.
Both capabilities are local verification decisions made inside the process that
holds the peer connection; there is no remote caller to serve. The transport
model is documented once in [`docs/daemon/api.md`](../daemon/api.md).

The trust-adjacent network surfaces belong to other features:

| Surface | Owner |
|---|---|
| `GET /api/v1/ca/bootstrap` (unauthenticated PEM CA bundle) and the Noise_NK bundle server | [`docs/bootstrap/api.md`](../bootstrap/api.md) |
| DANE TLSA records served by DNS | [`docs/dns/`](../dns/) |
| BMC TLS enrollment (pins captured in `TOFUPin`) | [`docs/bmc/api.md`](../bmc/api.md) |

## 2. Capability matrix

| Capability | REST | gRPC | QUIC | MCP | Unix | Embedded |
|---|---|---|---|---|---|---|
| Resolve trust for a class + endpoint (`Resolver.TLSConfig`, `CAPool`, `CABundlePEM`) | N/A in-process | N/A in-process | N/A in-process | N/A in-process | N/A in-process | Go call: `trust.Resolver` (`App.TrustResolver()`) |
| Platform anchor (`Anchor.Certificates`, `CAPool`, `TLSConfig`) | N/A in-process | N/A in-process | N/A in-process | N/A in-process | N/A in-process | Go call: `*trust.Anchor` (`App.PlatformAnchor()`) |
| Install CA bundle to the OS store (`InstallToSystemTrust`) | N/A in-process | N/A in-process | N/A in-process | N/A in-process | N/A in-process | Go call: `trust.InstallToSystemTrust`; CLI: [`platformctl bootstrap trust`](cli.md) |

`N/A in-process` means the capability is deliberately not remotely callable: a
remote verb that returned a node's trust decision, or that set its anchor, would
let a caller influence what the node trusts. This is a design decision
([architecture.md §7](architecture.md)), not a gap, so there is no
`docs/13 G<n>` reference. If a remote trust capability is ever required it needs
an owner ruling and an `MISSING — docs/13 G<n>` entry on every transport at the
same time.

## 3. Go surface

The Go signatures, errors and configuration keys are in
[engineering.md](engineering.md). The `scp` permission model does not apply: the
library performs no authorization of its own.

## 4. Versioning

No routes, hence no versions and nothing deprecated. The `trust:` YAML shape
changed once: `trust.default` → `trust.bootstrap` and `trust.internal` → the
platform anchor (no key). Both retired keys are ignored by the decoder, so
shipped templates are tested to contain neither.
