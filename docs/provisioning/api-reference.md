# Config Delivery Provisioning API Reference

## Overview

The config delivery provisioning API (`platform.v1.ConfigDeliveryService`,
backed by `pkg/provisioning/configdelivery`) exposes the pre-enrollment
provisioning operations across every platform transport with full feature
parity:

| Operation | Description |
|-----------|-------------|
| GetNonce | Issue a single-use anti-replay nonce |
| FetchConfig | Authenticate a device and resolve its platform configuration |
| SignDigest | Sign a UKI / kernel-module digest with the control-plane Secure Boot DB key |
| PollSession | Check whether a pending provisioning session has been fulfilled |
| FulfillSession | Link a device profile to a pending session (operator action) |
| ListSessions | List all active (non-expired) provisioning sessions |
| GetSession | Get a provisioning session by ID |

## Transport-Specific Documentation

| Transport | Documentation | Endpoint |
|-----------|---------------|----------|
| **REST** | [api-reference-rest.md](api-reference-rest.md) | `https://host:8443/api/v1/provisioning` |
| **gRPC** | [api-reference-grpc.md](api-reference-grpc.md) | `host:10443` (TLS) |
| **QUIC** | [api-reference-quic.md](api-reference-quic.md) | `host:9444` (UDP), opcode `0xCF` |
| **MCP** | [api-reference-mcp.md](api-reference-mcp.md) | `https://host:9445`, `provision_*` tools |
| **Unix** | [api-reference-unix.md](api-reference-unix.md) | `/run/platformd.sock` (gRPC over UDS) |
| **CLI** | [config-delivery.md](config-delivery.md#session-management-cli) | `platformctl provision ...` |
| **SDK** | `sdk/go/services/provision` | Works over every SDK transport |

## Authentication Model

Authentication is enforced **inside the service**, not by the transport:

1. **Nonce** — the caller first requests a nonce (`GetNonce`). Nonces are
   single-use with a 5-minute TTL; the nonce is consumed on first use, before
   any other validation runs. Replay yields a "nonce expired or already used"
   error.
2. **EAB** — `FetchConfig` and `SignDigest` carry External Account Binding
   credentials (`eab_key_id` + base64url `eab_hmac`) validated against the
   platform EAB credential store.
3. **EK binding** — when the matched device profile carries a prestaged EK
   certificate (or `RequireEKMatch` is enforced, the default), the presented
   `ek_cert` (standard-base64 DER) public key must equal the prestaged one
   before any config is released or digest is signed.

Because the auth model is in-service, semantics are identical on every
transport. The transports differ only in *who can reach them*:

- **REST is the pre-identity, install-time path.** A booting device has no
  client certificate yet, so the `/api/v1/provisioning` routes are excluded
  from the mTLS middleware and are reachable with EAB + nonce alone.
- **gRPC, QUIC, MCP, and Unix sit behind the daemon transport auth**
  (mTLS / IAM / socket permissions). They exist for operators, services, and
  the SDK — e.g. fulfilling sessions from `platformctl` — with the same
  in-service EAB checks still applied to `FetchConfig` / `SignDigest`.

## Delivered vs Pending (Tri-State Results)

`FetchConfig` and `PollSession` are tri-state:

| State | Meaning | Wire form |
|-------|---------|-----------|
| **delivered** | A profile matched and EK binding passed; the merged config is returned | `config` (REST/MCP JSON) / `DeliveredConfig{config_json, status}` (pb oneof) |
| **pending** | No profile matched; a provisioning session was created (FetchConfig) or is not yet fulfilled (PollSession) — enter interactive QR mode / keep polling | `PendingSession{session_id, provision_url, poll_interval_seconds}` or `pending_status: "pending"` |
| **error** | Validation, auth, or EK-binding failure | Transport status code (below) |

gRPC/Unix express the tri-state as a protobuf `oneof`; QUIC flattens the
oneof into a single wire struct with a `result` discriminator
(`"delivered" | "pending"`); REST and MCP return the two alternative domain
JSON shapes directly.

## Error Mapping

Typed service errors map consistently across transports:

| Service error | REST | gRPC / Unix | QUIC status |
|---------------|------|-------------|-------------|
| `ErrInvalidRequest`, `ErrNonceRequired`, `ErrNonceExpired`, `ErrEKCertParseFailed` | 400 | `InvalidArgument` | `StatusInvalidArgument` |
| `ErrEABValidationFailed` (FetchConfig) | 401 | `Unauthenticated` | `StatusUnauthorized` |
| `ErrEABValidationFailed` (SignDigest), `ErrEABProfileMismatch`, `ErrEKCertRequired`, `ErrEKCertMismatch` | 403 | `PermissionDenied` | `StatusPermissionDenied` |
| `ErrSessionNotFound`, `ErrProfileNotFound` | 404 | `NotFound` | `StatusNotFound` |
| `ErrSessionExpired`, `ErrSessionAlreadyFulfilled` | 400 | `InvalidArgument` | `StatusInvalidArgument` |
| `ErrRemoteSignNotConfigured` | 409 | `FailedPrecondition` | `StatusInvalidRequest` |
| `ErrSignerUnavailable`, `ErrMissingProfileService` | 503 | `Unavailable` | `StatusUnavailable` |
| Anything else | 500 | `Internal` | `StatusInternalError` |

MCP surfaces the typed error text verbatim in the JSON-RPC tool error.

## Related Documentation

- [config-delivery.md](config-delivery.md) — post-bootstrap config delivery flow, trust model, CLI usage
- [interactive.md](interactive.md) — interactive QR provisioning
- [../bootstrap/config-delivery.md](../bootstrap/config-delivery.md) — bootstrap-time (deployer network) config delivery
- [../firmware/secure-boot.md](../firmware/secure-boot.md) — remote Secure Boot resign (`SignDigest`)
