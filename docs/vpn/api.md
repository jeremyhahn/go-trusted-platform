# Remote-Access VPN — API

> **Status: DESIGN — not implemented.** · Last verified: 2026-09-08
> Every row below is a requirement. Nothing is routed today; the Tier-1 rule
> (docs/00 L11) means each capability ships on all six transports in the
> implementing change set, so every cell reads `MISSING — docs/13 G7` until then.
> Feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · api (this file) · [user.md](user.md).

## 1. Transport matrix *(planned)*

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | `scp` |
|---|---|---|---|---|---|---|
| Admit (client) | `POST /api/v1/vpn/admissions` — `MISSING — docs/13 G7` | `VPNService.Admit` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | not offered (client-only) | `MISSING — docs/13 G7` | device identity (mTLS), no token |
| Renew (client) | `POST /api/v1/vpn/leases/{id}/renew` — `MISSING — docs/13 G7` | `VPNService.Renew` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | not offered | `MISSING — docs/13 G7` | device identity |
| Disconnect (client) | `DELETE /api/v1/vpn/leases/{id}` (own lease) — `MISSING — docs/13 G7` | `VPNService.Revoke` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | not offered | `MISSING — docs/13 G7` | device identity |
| List leases (operator) | `GET /api/v1/vpn/leases` — `MISSING — docs/13 G7` | `VPNService.ListLeases` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_lease_list` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:read` |
| Get lease (operator) | `GET /api/v1/vpn/leases/{id}` — `MISSING — docs/13 G7` | `VPNService.GetLease` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_lease_get` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:read` |
| Revoke lease (operator) | `DELETE /api/v1/vpn/leases/{id}` — `MISSING — docs/13 G7` | `VPNService.Revoke` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_lease_revoke` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:write` |
| Status | `GET /api/v1/vpn/status` — `MISSING — docs/13 G7` | `VPNService.Status` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_status` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:read` |
| Posture policy CRUD | `GET/PUT/DELETE /api/v1/vpn/posture-policies/{name}` — `MISSING — docs/13 G7` | `VPNService.{Get,Set,Delete}PosturePolicy` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_posture_policy_{get,set,delete}` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:admin` |
| Key rotation | `POST /api/v1/vpn/keys/rotate` — `MISSING — docs/13 G7` | `VPNService.RotateKeys` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn_keys_rotate` — `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vpn:admin` |

The client verbs terminate on the **gateway's admission listener** (mTLS,
device identity, no bearer token); the operator verbs terminate on the
**control plane** like every other operator surface and are gated by the
platform's role guard plus the `scp` claims above. QUIC frames take the next
free category opcode from the platform-wide table in
[docs/daemon/api.md](../daemon/api.md) when the implementing PR assigns it.

## 2. Schemas *(planned)*

`AdmissionRequest`:

```json
{
  "device_id": "…",
  "nonce": "<base64, echoed from the challenge>",
  "attestation": { "quote": "<base64>", "signature": "<base64>", "pcrs": [{"index": 7, "value": "<hex>"}], "ak_public_key": "<base64>", "idevid_certificate": "<base64 DER>" },
  "posture": { "secure_boot": {"enabled": true, "setup_mode": false}, "ima": {"available": true, "enabled": true, "policy_loaded": true, "log_digest": "<hex>"}, "fde": {"root_encrypted": true}, "agent_version": "…", "os_release": "…", "kernel_release": "…", "collected_at": "<RFC 3339>" },
  "person_factor": { "kind": "fido2|piv", "assertion": "<base64>", "credential_id": "…" },
  "data_plane": "wireguard|masque",
  "peer": { "wireguard_public_key": "<base64>" },
  "zones": ["management"]
}
```

`Lease` (response and operator read):

```json
{ "id": "…", "device_id": "…", "tenant_id": "…", "address": "…/32", "zones": ["management"], "data_plane": "masque", "expires_at": "<RFC 3339>", "renewals": 0,
  "endpoint": { "wireguard": {"server_public_key": "<base64>", "endpoint": "host:51820"}, "masque": {"template": "https://…/.well-known/masque/ip/"} },
  "verdict": { "passed": true, "cryptographic": true, "profile_id": 0 } }
```

A refusal body carries only `reason` (the class from
[engineering.md](engineering.md) §3) and, for a posture violation, the rule
names — never the policy text or the identity list.

## 3. Status and error mapping

Per [engineering.md](engineering.md) §3: 401 `Unauthenticated` for identity and
factor failures, 403 `PermissionDenied` for attestation and posture, 503
`Unavailable`/`ResourceExhausted` for verifier, policy engine, pool or datapath
unavailability (all refusals), 404/410 for lease lookups. QUIC status bytes map
onto the platform's canonical vocabulary in `pkg/api/quic/protocol.go`.

## 4. Pagination and versioning

`ListLeases` is paginated (`limit`/`cursor`) — a tenant may hold thousands of
leases. Routes are unversioned beyond the `/api/v1` prefix; the request and
lease schemas carry no version field until a breaking change requires one.

## 5. Deliberate omissions

The client admission verbs are not offered on MCP: an LLM client is not a
device with a TPM, and there is no honest way for it to attest. Operator verbs
are.
