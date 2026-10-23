# REST Router Layer (`/api/v1`)

> **Status: REFERENCE** · Last verified: 2026-10-14
> How the `pkg/webservice/v1` REST routers are wired, gated and added.

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

| Service | Base path | Backing gRPC server | Gate |
|---|---|---|---|
| ACME | `/api/v1/acme` | `trustedca.ACMERestServicer` | public — ACME account keys / EAB |
| Images (curated) | `/api/v1/compute/images` | `grpcapi.RegistryService` | `admin`; the `/v2` OCI surface at the host root is separate and authenticates by TPM attestation |
| Attestation | `/api/v1/attestation` | `platformv1.AttestationServiceServer` | **ungated** — held pending the node-push credential ruling (#165) |
| CA | `/api/v1/ca` | `trustedca.CACertificateAuthority` | split — see below |
| Compute | `/api/v1/compute` | `platformv1.ComputeServiceServer` | `admin` |
| Devices | `/api/v1/devices`, `/api/v1/device/*` | `device.DeviceService` + `DeviceProfileService` | `admin` for CRUD/templates/assignment and the provisioning session surface; `/device/{profile,activate,heartbeat}` verify mTLS instead, and `/provisioning/{config,config/nonce,sign}` authenticate by EAB (+EK) |
| DNS | `/api/v1/dns` | `dns.DNSService` | `admin` |
| EAB | `/api/v1/eab` | `platformv1.EABServiceServer` | `admin` |
| Gateway | `/api/v1/gateway` | `platformv1.GatewayServiceServer` | `admin` for the operator half; `/gateway/{telemetry,desired-config/{id},vpn-leases/**}` authenticate by verified mTLS client certificate instead |
| IAM | `/api/v1/iam` | `restiam.IAMClient` | `admin` (+ tenant guards) |
| IDevID | `/api/v1/idevid` | `platformv1.IDevIDServiceServer` | `admin` |
| Invitations | `/api/v1/invitations` | `platformv1.InvitationServiceServer` | `admin`; `/invitations/{accept,token/{token}}` stay open — the invitation token is the credential |
| KMS | `/api/v1/kms` | `proto.KeyManagementClient` | `admin` |
| Overlay | `/api/v1/overlay` | `platformv1.OverlayServiceServer` | `admin` |
| Platform | `/api/v1/platform` | `platform.ServicesManager` | `admin`; `/platform/service-registry` stays public |
| PXE | `/api/v1/pxe` | `platformv1.PXEServiceServer` | `admin`; `POST /pxe/webhook/complete` is registered only when `pxe.ServiceConfig.WebhookEnabled` is true (default false, so 404) and is then **unauthenticated** — it sits off the gate and checks no credential; #238 owns what a booting node presents |
| SDN | `/api/v1/sdn` | `platformv1.SDNServiceServer` | `admin` |
| Switches | `/api/v1/switches` | `device.SwitchServiceProvider` | `admin` |
| Tenants | `/api/v1/tenants` | `platformv1.TenantServiceServer` | `admin`, plus a within-tenant boundary: `/{id}/**` requires the caller's own tenant **or** the system tenant; list/create/sync are system-tenant only (#234); by-name resolves the caller's own tenant's name, or any name for the system tenant (#304) |
| TPM | `/api/v1/tpm` | `platformv1.TPMServiceServer` | `admin` |
| vTPM | `/api/v1/vtpm` | `vtpm.VTPMService` | `admin` |

A router registers its routes only when the backing service is non-nil.
Daemon configurations that omit a service simply leave the route absent;
clients receive the standard `404` envelope (`message: "the requested API
endpoint does not exist"`) instead of a misleading `501`.

## Where SDK route claims are served

The Go SDK's REST adapter has one route table
(`sdk/go/transport/rest.RouteClaims()`) for both servers on `/api/v1`: this
router and the daemon REST server, `pkg/api/daemon.RESTServer` (#232). These
prefixes are served by the daemon alone; this router mounts nothing under
them:

| Prefix | Daemon setter |
|---|---|
| `/api/v1/bmc` | `SetBMCHandler` |
| `/api/v1/ceremony` | `SetCeremonyService` |
| `/api/v1/cluster` | `SetClusterService` |
| `/api/v1/fido2` | `SetFIDO2Service` |
| `/api/v1/luks` | `SetLUKSService` |
| `/api/v1/piv` | `SetPIVService` |
| `/api/v1/proxy` | `SetProxyService` |
| `/api/v1/version` | `registerRoutes` |
| `/api/v1/sdn/gateway/{nat64,overlay,perf}` | `SetGatewayIPAMService` (this router serves `/api/v1/sdn/gateway/ipam`) |
| `/api/v1/kms/{batch-encrypt,batch-decrypt,rewrap}`, `/api/v1/kms/keys/{id}/export` | `SetKMSHandlers` (this router serves the rest of `/api/v1/kms`) |

The list is `DaemonOnlyPrefixes` in `pkg/testutil/routeclaims.go`; a
placeholder segment in an entry matches any one path segment. Two tests
check every claim against a built table (#452):

- `TestSDKRouteClaims` (`pkg/webservice/v1/route_coverage_test.go`) checks
  every claim outside those prefixes against this router, and
  `TestDaemonOnlyPrefixes_ThisRouterServesNone` fails if this router mounts
  a route under one of them.
- `TestDaemonRESTRouteClaims_ResolveAgainstBuiltRoutes`
  (`pkg/api/daemon/rest_route_claims_test.go`) checks every claim under a
  prefix the daemon serves against the daemon's table, and requires the
  matched route to have the claim's own shape. Prefixes both servers serve
  differ in places — IDevID under `/tpm/idevid`, KMS keys in the body, CA
  revoke as `POST .../revoke`. Each such claim sits in that test's
  `daemonDivergentClaims` ledger with its reason until the choice of server
  is made.

When `platformd serve` runs with a `webservices:` section the daemon has no
REST listener, and this router mounts the daemon's own route groups — BMC,
ceremony, cluster, FIDO2, LUKS, PIV, version, health, services and protocols —
from `RegistryParams.DaemonRESTRoutes`, behind a verified-client-certificate
gate (`pkg/webservice/v1/daemon_routes.go`). `/api/v1/proxy` and the gateway
and KMS rows above are not in that set, so they are served only by a daemon
REST listener.

## Authorization

**Scope: this document describes the `pkg/webservice/v1` router.**
`pkg/api/daemon.RESTServer` is a separate server on the same `/api/v1`
prefix, with its own handlers in `pkg/api/rest/` and no authentication
middleware; it is tracked on #232 and nothing here applies to it.

A router does not mount its own authentication. `pkg/webservice/v1/router.go`
registers it on either the ungated `/api/v1` subrouter or on a **protected
group** obtained from `v1Router.gated(roles...)` (`authz.go`), which is a
matcher-less mux subrouter carrying two middlewares: `middleware.Authenticator`
over the configured inbound seam, then `iam.SessionGuard.RequireRoles`. Groups
are memoised per role set, and a router still registers its own `basePath`
underneath, so nothing about path matching or registration order changes.

Passing the gated group is the whole of the wiring:

```go
r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
```

**The default is deny.** `TestRegisterRoutes_EveryRouteDeniesWithoutCredential`
(`pkg/webservice/v1/router_authz_test.go`) walks the finished route table,
issues a credential-free request against every registered route, and requires a
refusal from each one not named in `publicRoutes` — a map from route to the
reason it must stay open. A router mounted on the ungated parent by mistake
fails that test. `TestRegisterRoutes_EveryDeclaredOpenRouteIsActuallyOpen`
asserts the converse so the list cannot go stale, and `pendingRoutes` carries
the routers #165 has not reached yet.

`/api/v1/ca` is the one split surface: `CARouter.RegisterRoutes` takes the
gated group and carries certificate issuance, revocation and the issued-
certificate inventory, while `CARouter.RegisterPublicRoutes` takes the ungated
router and carries the CA's own chain, the CRL and the trust-bootstrap fetch —
the endpoints whose callers cannot yet hold a credential. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c for the full
justification, route by route.

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
   with a nil-guard, registering it on `v1Router.gated(<roles>)` rather
   than on `v1Router.router`. A route that genuinely must answer callers
   with no credential goes in `publicRoutes` in
   `pkg/webservice/v1/router_authz_test.go` **with the reason** — the
   default-deny audit fails otherwise.
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
