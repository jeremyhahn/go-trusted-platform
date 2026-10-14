# Remote-Access VPN — API

> **Status: PARTIAL — the operator control plane ships on every transport (#584 PR 3) and in the JS SDK and the web console (#584 PR 4), and the gateway lease record (§6) is served; the gateway's admission listener serves the client verbs over HTTPS (#557), and the client in `pkg/vpn/agent` speaks them (§5).** · Last verified: 2026-10-14
> §1–§4 describe `VPNService` as it is routed today. §5 is the gateway's
> admission listener: routed, but `gatewayd` does not yet assemble the VPN
> runtime that opens it (see [engineering.md](engineering.md) §1).
> Feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · api (this file) · [user.md](user.md).

## 1. Transport matrix — operator control plane

`VPNService` (`pkg/api/grpc/proto/vpn.proto`) is served by the daemon
(`pkg/api/daemon/vpn_grpc_service.go`) over `pkg/vpn.Service`. Every row is on
every transport; the per-transport tables are pinned against
`VPNService_ServiceDesc`, so a method missing from one transport fails its tests.

| RPC | REST | QUIC `0x52` sub | MCP tool | Scope |
|---|---|---|---|---|
| `EnrolPeer` | `POST /api/v1/vpn/peers` (body: `VPNPeer`) | `0x01` | `vpn_peer_enrol` | `vpn:write` |
| `ListPeers` | `GET /api/v1/vpn/peers?tenant_id=` | `0x02` | `vpn_peer_list` | `vpn:read` |
| `RevokePeer` | `DELETE /api/v1/vpn/peers/{device_id}?tenant_id=` | `0x03` | `vpn_peer_revoke` | `vpn:write` |
| `GetStatus` | `GET /api/v1/vpn/status?gateway_id=` | `0x04` | `vpn_status` | `vpn:read` |
| `GetPosturePolicy` | `GET /api/v1/vpn/posture-policies/{name}?tenant_id=` | `0x05` | `vpn_posture_policy_get` | `vpn:admin` |
| `SetPosturePolicy` | `PUT /api/v1/vpn/posture-policies/{name}` (body: `VPNPosturePolicy`) | `0x06` | `vpn_posture_policy_set` | `vpn:admin` |
| `DeletePosturePolicy` | `DELETE /api/v1/vpn/posture-policies/{name}?tenant_id=` | `0x07` | `vpn_posture_policy_delete` | `vpn:admin` |
| `ListPosturePolicies` | `GET /api/v1/vpn/posture-policies?tenant_id=` | `0x08` | `vpn_posture_policy_list` | `vpn:admin` |

- **gRPC / Unix**: `platform.v1.VPNService/<RPC>`; the scope comes from the gRPC
  method catalog (`pkg/api/grpc/method_permissions.go`).
- **QUIC**: category opcode `OpVPNCategory` (`0x52`), sub-opcodes `VPNSub*` in
  `sdk/go/wire/quicwire/vpn_opcodes.go`; scopes in
  `pkg/api/quic/opcode_permissions.go`.
- **MCP**: tool scopes in `pkg/api/mcp/authz.go`.
- **REST**: the same paths on the daemon listener (`pkg/api/rest/vpn_handlers.go`)
  and on the webservice (`pkg/webservice/v1/rest/vpn`). On the daemon listener
  every route requires the scope above through `restapi.ScopeGuard`: a platform
  token's `scp`, or the verified mTLS client certificate admitted as the
  operator (`*:*`). No credential is 401, a missing scope 403, and handlers
  built without a guard refuse every route with 403. On the webservice each
  route takes the scope when a scope authorizer is configured.
- **Embedded / Go SDK**: `sdk/go/services/vpn.Client`, over any of the
  transports above.
- **JS SDK**: `VPNService` (`client.vpn`, React `useVPN()`) in
  `sdk/javascript/src/services/vpn-service.ts`, over the REST routes, with the
  same eight operations.

How each transport authenticates is the platform-wide picture in
[docs/daemon/api.md](../daemon/api.md); the VPN adds no transport of its own.

An empty `tenant_id` on the list routes lists every tenant; the item routes
require it. `GetStatus` with an empty `gateway_id` returns every gateway that
reports telemetry.

## 2. Schemas

```json
// VPNPeer
{ "tenant_id": "acme", "device_id": "laptop-1", "zones": ["management"], "enrolled_at_unix": 1760300000 }

// VPNPosturePolicy
{ "tenant_id": "acme", "name": "corp", "module": "package vpn.posture\n…", "updated_at_unix": 1760300000 }

// VPNGatewayStatus
{ "gateway_id": "gw-01", "reported_at_unix": 1760300000, "reporting": true, "running": true,
  "admissions": 12, "refusals": 1, "last_refusal": "posture violation", "enrolled_peers": 3,
  "leases_by_data_plane": {"masque": 2}, "leases": [{"id": "…", "tenant_id": "acme",
  "device_id": "laptop-1", "address": "10.8.0.2", "data_plane": "masque", "zones": ["management"],
  "issued_at_unix": 1760300000, "expires_at_unix": 1760328800, "renewals": 0}],
  "posture_policy_errors": [], "rejected_peers": [{"tenant_id": "acme", "device_id": "laptop-9",
  "reason": "vpn: zone \"storage\" is not reachable through this service"}] }
```

- The names above are the proto field names. REST bodies are protojson: it
  writes camelCase names (`tenantId`, `enrolledAtUnix`) and reads either form,
  and it encodes the 64-bit fields (the `*_unix` times, `admissions`,
  `refusals`) as decimal strings. The JS SDK types follow that encoding.
- `zones` narrows the gateway's `allow-to` set; empty means every allowed zone.
- `enrolled_at_unix` and `updated_at_unix` are set by the service and ignored on
  write. Re-enrolling a device replaces its zones and keeps its first enrolment
  time.
- A policy name is letters, digits, `_`, `-` and `.`. The module must compile
  and declare package `vpn.posture`, or the write is refused.
- `reporting: false` means the gateway sends telemetry without a VPN section:
  the service is not configured there, and the remaining fields are zero.
- `rejected_peers` lists the enrolments the gateway refused from the last set
  it applied, each with the reason: today a zone the gateway's `allow-to` does
  not serve. A refused peer is not enrolled there and loses its leases; the
  rest of the set applies. Every transport returns the field.

The enrolment set and the posture policies reach the gateways as the `vpn`
section of the desired config ([engineering.md](engineering.md) §1).

## 3. Status and error mapping

| `pkg/vpn` error | gRPC | REST | QUIC |
|---|---|---|---|
| `ErrInvalidArgument`, `ErrInvalidPosturePolicy` | `InvalidArgument` | 400 | `StatusInvalidArgument` |
| `ErrPeerNotFound`, `ErrPosturePolicyNotFound`, `ErrGatewayNotFound` | `NotFound` | 404 | `StatusNotFound` |
| `ErrKeyCollision` (two keys hash to one record; the write is refused) | `Aborted` | 409 | `StatusAlreadyExists` |
| `ErrStoreUnavailable`, `ErrPolicyEngineUnavailable`, `ErrStatusUnavailable` | `Unavailable` | 503 | `StatusUnavailable` |
| caller deadline | `DeadlineExceeded` | 504 | `StatusTimeout` |
| anything else | `Internal` | 500 | `StatusInternalError` |

MCP returns the gRPC error as a tool error.

**Fails closed.** A daemon without a VPN control plane refuses every RPC with
`Unavailable` (REST 503, QUIC `StatusUnavailable`); none of them answers with
an empty result. `GetStatus` is `Unavailable` on a daemon that has no gateway
telemetry store.

## 4. Pagination and versioning

The list RPCs are not paginated: they return the full set for the tenant.
Routes are unversioned beyond the `/api/v1` prefix.

## 5. Client admission

These verbs terminate on the **gateway's admission listener**
(`vpn.AdmissionListener`, bound to `management_vpn.listener`), not on the
control plane. The listener speaks HTTPS with TLS 1.3 and requires a client
certificate that chains to the device-identity anchor, read on every
handshake; a connection without one, with an expired one or one from another
CA fails the handshake and reaches no handler. There is no bearer token. The
wire contract (routes, bodies, refusal classes) is
`pkg/sdn/gateway/services/vpn/wire.go`, shared by the listener and the client
in `pkg/vpn/agent`. The client speaks all four routes and decodes every
body it sends with the listener's own decoder (`vpn.DecodeRequest`) in its
tests.

| Capability | REST (admission listener) | gRPC | Success |
|---|---|---|---|
| Challenge | `POST /api/v1/vpn/challenges` | *(planned)* `VPNService.Challenge` | 200, the challenge |
| Admit | `POST /api/v1/vpn/admissions` | *(planned)* `VPNService.Admit` | 201, the lease |
| Renew | `POST /api/v1/vpn/leases/{id}/renew` | *(planned)* `VPNService.Renew` | 200, the lease |
| Disconnect | `DELETE /api/v1/vpn/leases/{id}` | *(planned)* `VPNService.Revoke` | 204 |

Renew and disconnect act only on the lease admitted with the presented
certificate; another device's lease answers `lease-not-found`. A re-issued
device certificate therefore has to admit again.

The challenge answers a single-use nonce and the data planes this gateway
serves (`management_vpn.data-planes`), in its order of preference:

```json
{ "nonce": "<base64>", "data_planes": ["masque", "wireguard"] }
```

`AdmissionRequest` (unknown fields, trailing data, a PCR value that is not hex
and bodies over 1 MiB are refused with `invalid-request`):

```json
{
  "tenant_id": "…",
  "device_id": "…",
  "nonce": "<base64, from the challenge>",
  "attestation": { "quote": "<base64>", "signature": "<base64>", "pcrs": [{"index": 7, "value": "<hex>"}], "ak_public_key": "<base64>", "idevid_certificate": "<base64 DER>" },
  "posture": { "secure_boot": {"enabled": true, "setup_mode": false}, "ima": {"available": true, "enabled": true, "policy_loaded": true, "log_digest": "<hex>"}, "fde": {"root_encrypted": true}, "agent_version": "…", "os_release": "…", "kernel_release": "…", "collected_at": "<RFC 3339>" },
  "person_factor": { "kind": "fido2|piv", "assertion": "<base64>", "credential_id": "…" },
  "data_plane": "wireguard|masque",
  "peer": { "wireguard_public_key": "<base64>" },
  "zones": ["management"]
}
```

`RenewalRequest` carries fresh evidence: `nonce`, `attestation`, `posture` and
`person_factor`, shaped as above.

The response is the lease (the `VPNLease` fields above, plus the data plane's
endpoint and the verdict), with `renew_at_unix` — when the renewal window
(`management_vpn.renew-window`) opens — so the client knows its next
re-attestation:

```json
{
  "id": "…", "device_id": "…", "tenant_id": "…", "address": "10.8.0.2/32", "zones": ["management"],
  "data_plane": "masque", "issued_at_unix": 0, "expires_at_unix": 0, "renew_at_unix": 0, "renewals": 0,
  "verdict": "…",
  "endpoint": { "masque": { "template": "https://gw.example:443/.well-known/masque/ip/", "routes": ["10.20.0.0/16"] } }
}
```

A WireGuard lease carries `endpoint.wireguard` (`public_key`, `endpoint`,
`routes`) instead. The listener sends `endpoint` empty today: neither plane
exposes its client-facing endpoint to it yet.

A renewal fetches a fresh challenge and posts a `RenewalRequest` body to the
lease's `renew` route. Its evidence is fresh — a quote over the new nonce, a
new posture report and, when the admission carried one, the same kind of
person factor signed over the new nonce. The body carries no `device_id`,
`data_plane`, `zones` or `peer`: the lease keeps the device, plane, zones and
peer it was admitted with, and an `AdmissionRequest` body on this route is
refused with `invalid-request`. The response is the renewed lease, the same
`id` with new `expires_at_unix` and `renew_at_unix`. A `renewal-not-open` or
`nonce-unknown` refusal, or a 503, leaves the lease standing; every other
refusal ends it.

A refusal carries only `reason` (the class from [engineering.md](engineering.md)
§3) and, for a posture violation, `rules` — the rule names, never the policy
text or the identity list; the full error stays in the gateway's log:

```json
{ "reason": "posture-violation", "rules": ["secure_boot", "fde"] }
```

| Status | Classes |
|---|---|
| 400 | `invalid-request` |
| 401 | `untrusted-issuer`, `no-identity`, `nonce-unknown`, `person-factor-required`, `person-factor-invalid` |
| 403 | the other identity refusals (`not-listed`, `not-attested`, …), `attestation-failed`, `posture-violation`, `peer-not-enrolled`, `zone-not-allowed` |
| 404 / 410 | `lease-not-found` / `lease-expired` |
| 409 | `renewal-not-open`, `peer-conflict` |
| 503 | `posture-unavailable`, `pool-exhausted`, `data-plane-unavailable`, `lease-store-unavailable`, `not-started` |
| 500 | `internal` |

The client verbs are not offered on MCP: an LLM client is not a device with a
TPM, and there is no honest way for it to attest.

## 6. Gateway lease record

A gateway writes each lease it admits, renews or revokes through to the
control plane, which keeps it under `tenant/<id>/vpn/lease/<lease-id>`
([engineering.md](engineering.md) §6). The routes are on the gateway-facing
half of the gateway control plane (`pkg/webservice/v1/rest/gateway`), beside
telemetry and the desired-config pull, and authenticate the same way: a
verified mTLS client certificate whose Common Name is `{id}`, with no token
and no scope ([docs/gateway/api.md](../gateway/api.md)). Like that pair they
are REST only — their one caller is gatewayd's `controlplane.Reporter`.

| Route | Body | Effect |
|---|---|---|
| `PUT /api/v1/gateway/vpn-leases/{id}` | `DesiredVPNLease` | Records the lease as gateway `{id}`'s, replacing an earlier write of it |
| `DELETE /api/v1/gateway/vpn-leases/{id}/{tenant}/{lease}` | — | Releases the lease; one already gone is a success, so a retry is safe |

```json
// DesiredVPNLease
{ "id": "…", "tenant_id": "acme", "device_id": "laptop-1", "address": "10.8.0.2/32",
  "zones": ["management"], "data_plane": "masque", "wireguard_public_key": "<base64>",
  "client_certificate_sha256": "<base64>", "issued_at": "<RFC 3339>",
  "expires_at": "<RFC 3339>", "renewals": 0,
  "verdict": { "passed": true, "cryptographic": true, "profile_id": 7 } }
```

401 without a verified certificate; 403 when `{id}` names another gateway or
the lease was issued by another one (`ErrLeaseOwnedByOtherGateway`); 400 for
a malformed body or lease (`ErrInvalidArgument`); 500 when the store cannot
complete the write, or when the daemon has no VPN control plane. The gateway
reads its leases back as `leases` in the `vpn` section of its desired config,
expired ones already swept.
