# REST Router Layer (`/api/v1`)

This document describes how the platformd REST surface is wired together,
the conventions every router follows, and how to add a new service.

## Overview

```
WebUI (sdk/javascript)  ─────►  /api/v1/<service>/<path>
                                          │
                                          ▼
              pkg/webservice/v1/router.go (mounts /api/v1 subrouter)
                                          │
                                          ▼
              pkg/webservice/v1/rest/<service>/router.go
                                          │
                                          ▼
              pkg/webservice/v1/rest/<service>/handlers.go
                                          │
                                          ▼
                  platformv1.<X>ServiceServer  (in-process gRPC impl
                                                supplied by daemon.New())
```

The REST handlers never reach into `pkg/<service>` directly — they speak
to the gRPC server interface (`platformv1.XServiceServer`) supplied by the
daemon. This is the same surface that `sdk/go/services/<x>` consumes via
`embedded.Adapter`, so the REST layer and the SDK clients share one
contract: protobuf request/response messages, decoded from JSON with
`protojson`.

## Mounted Routes

| Service | Base path | Backing gRPC server |
|---|---|---|
| ACME | `/api/v1/acme` | `trustedca.ACMERestServicer` |
| Attestation | `/api/v1/attestation` | `platformv1.AttestationServiceServer` |
| CA | `/api/v1/ca` | `trustedca.CACertificateAuthority` |
| Compute | `/api/v1/compute` | `platformv1.ComputeServiceServer` |
| Devices | `/api/v1/devices`, `/api/v1/device/*` | `device.DeviceService` + `DeviceProfileService` |
| DNS | `/api/v1/dns` | `dns.DNSService` |
| EAB | `/api/v1/eab` | `platformv1.EABServiceServer` |
| Gateway | `/api/v1/gateway` | `platformv1.GatewayServiceServer` |
| IAM | `/api/v1/iam` | `restiam.IAMClient` |
| IDevID | `/api/v1/idevid` | `platformv1.IDevIDServiceServer` |
| Invitations | `/api/v1/invitations` | `platformv1.InvitationServiceServer` |
| KMS | `/api/v1/kms` | `proto.KeyManagementClient` |
| Overlay | `/api/v1/overlay` | `platformv1.OverlayServiceServer` |
| Platform | `/api/v1/platform` | `platform.ServicesManager` |
| PXE | `/api/v1/pxe` | `platformv1.PXEServiceServer` |
| SDN | `/api/v1/sdn` | `platformv1.SDNServiceServer` |
| Switches | `/api/v1/switches` | `device.SwitchServiceProvider` |
| Tenants | `/api/v1/tenants` | `platformv1.TenantServiceServer` |
| TPM | `/api/v1/tpm` | `platformv1.TPMServiceServer` |
| vTPM | `/api/v1/vtpm` | `vtpm.VTPMService` |

A router registers its routes only when the backing service is non-nil.
Daemon configurations that omit a service simply leave the route absent;
clients receive the standard `404` envelope (`message: "the requested API
endpoint does not exist"`) instead of a misleading `501`.

## Conventions

1. **basePath is relative** to `/api/v1`. The mux subrouter mounted by
   `webserver_v1.go` already carries the version prefix; routers MUST set
   `basePath = "/<service>"`. Embedding `/api/v1` inside a router's
   `basePath` produces a double prefix and silent 404s — see the bug fix
   commit history.
2. **Path variables are merged into the proto request** before the call
   so REST clients do not have to repeat the resource id in the body.
3. **JSON ↔ protobuf marshalling** uses
   `pkg/webservice/v1/rest/internal/protorest`:
   - `DecodeRequest(r, msg)` — body to proto, ignoring unknown fields
   - `WriteSuccess(w, r, writer, msg)` — proto to JSON in the standard
     `WebServiceResponse` envelope
   - `WriteError(w, r, writer, err)` — gRPC status code → HTTP status
4. **Path conflicts** between numeric and word-shaped ids are resolved
   with regex constraints (e.g. `{id:[0-9]+}` for integer-only routes).
5. **Nil-server safety** — every handler calls `ensure*` before
   dispatch. A nil server returns `500` with the
   `<service> service is not available` envelope.

## Adding a new service

1. Define the `platformv1.XServiceServer` interface in
   `sdk/go/gen/<x>_grpc.pb.go` (proto buffers).
2. Implement the server in `pkg/api/daemon/<x>_grpc_service.go` and
   wire it into `daemon.New()` (store on the Daemon struct + add a
   public accessor).
3. Add an `XServiceServer` field to
   `pkg/webservice/v1/registry.go::RegistryParams` and
   `RestHandlerRegistry`. Implement the accessor on
   `*HandlerRegistry`.
4. Create `pkg/webservice/v1/rest/<x>/router.go` and `handlers.go`
   following the conventions above. Use protorest helpers — do NOT
   hand-roll JSON marshalling.
5. Wire the router into `pkg/webservice/v1/router.go::RegisterRoutes`
   with a nil-guard.
6. Plumb the daemon accessor into
   `pkg/daemon/commands/serve.go` so production deployments populate
   `RegistryParams.XServiceServer`.
7. Add a `router_test.go` next to the new router that:
   - Confirms every documented route resolves under
     `parent.PathPrefix("/api/v1").Subrouter()`.
   - Confirms a nil server triggers the
     `service is not available` envelope.
8. Add an entry under `test/integration/restroutes/routes_smoke_test.go`
   so CI verifies platformd actually mounts the route.

## Error mapping

| gRPC code | HTTP status |
|---|---|
| `OK` | `200` |
| `InvalidArgument`, `FailedPrecondition`, `OutOfRange` | `400` |
| `Unauthenticated` | `401` |
| `PermissionDenied` | `403` |
| `NotFound` | `404` |
| `AlreadyExists`, `Aborted` | `409` |
| `ResourceExhausted` | `429` |
| `Unimplemented` | `501` |
| `Unavailable` | `503` |
| `DeadlineExceeded` | `504` |
| anything else | `500` |
