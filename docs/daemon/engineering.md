# Platform Daemon and Binaries — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/api/daemon/`, `pkg/api/{grpc,rest,quic,mcp,noise}/`, `cmd/*` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix
> and the **canonical QUIC category-opcode table**: [api.md](api.md).

---

## 1. The six binaries

Node **roles are configuration, not binaries**. There are six binaries:

| Binary | `cmd/` | What it is |
|---|---|---|
| `platformd` | `platformd/main.go` | The platform daemon. Runs as a **control-plane** node or a **worker** by configuration. |
| `gatewayd` | `gatewayd/main.go` | The **edge** role — [`docs/gateway/`](../gateway/). Has its own import-closure guard (`pkg/arch/gatewayguard_test.go`). |
| `platformctl` | `platformctl/` — 31 files | The CLI **and** the desktop GUI. |
| `pxeboot` | `pxeboot/main.go`, `errors.go` | *"a minimal container entrypoint that runs the PXE bootstrap server… delegates to `container.Server` for DHCP, TFTP, and HTTP boot services."* |
| `platform-initrd` | `platform-initrd/main.go` | *"a minimal binary optimized for initramfs boot operations… `boot`: Unlock encrypted root filesystem using TPM-sealed keys; `recovery`: Recovery mode for boot failures. **This binary is NOT user-facing.** It is called by dracut hooks during the early boot process. After `switch_root`, firstboot provisioning runs via `platformctl firstboot`."* |
| `deployer-pin` | `deployer-pin/main.go` | Deployer pin management; the doc comment notes a pin is *"rotated (removed then re-added)"*. |

`platformd` and `gatewayd` are each a single `main.go`. All the substance is in
`pkg/`.

### `platformctl` is two products in one binary

31 files, of which **22 are `bindings_*.go`** — attestation, ca, cluster,
compute, daemon, desktop, device, dns, gateway, iam, idevid, kms, ntp, overlay,
pxe, registry, sdn, server, tenant, tpm, types, plus `bindings.go`. Those are
the **desktop GUI bindings**.

`gui_desktop.go` and `gui_stub.go` are a build-tagged pair, and
`display_linux.go` / `display_darwin.go` / `display_windows.go` are the
per-platform display code.

So: **the CLI and the GUI share one binary and one bindings layer, and the GUI
is compiled out by default.** A change to a service surface needs the matching
`bindings_*.go` updated or the GUI silently lags the CLI. That is the CLI/GUI
feature-parity obligation, made concrete.

## 2. The multi-protocol API server

`pkg/api/daemon/` is the composition point — roughly 130 non-test files. The
naming tells you the shape:

| Prefix | Transport |
|---|---|
| `*_grpc_service.go` | gRPC service implementations |
| `rest_*.go`, `*_rest.go` | REST wiring |
| `quic_*.go` | QUIC handlers |
| `mcp_*.go` | MCP tools |
| `*_service.go` | Shared business services the transports delegate to |

The important property: **transports are adapters over shared services**, not
parallel implementations. `sdk/go/wire/quicwire/vm_ops_opcodes.go` states it for its own
area — the QUIC handlers *"decode the platform.v1 pb request and delegate to the
shared `*ComputeGRPCService`… the same business path the gRPC transport uses."*

Protocol servers live in `pkg/api/`: `grpc/`, `rest/`, `quic/`, `mcp/`, `noise/`,
`tpmnv/`, plus `daemon/`. `pkg/api/noise/` is a Noise-protocol surface;
`pkg/api/tpmnv/` is TPM NV access.

### Interceptors and cross-cutting wiring

| File | Role |
|---|---|
| `mtls_interceptor.go` | mTLS |
| `recovery_interceptor.go` | Panic recovery |
| `platform_token_validator.go` | Broker-token validation |
| `oidc_interceptor.go` (in `pkg/api/grpc/`) | OIDC |
| `pkg/util/peercred/peercred.go` | Unix socket peer credentials (leaf, shared with gatewayd IPC) |
| `health_checker.go`, `iam_health_checker.go`, `ntp_health_checker.go` | Health |
| `managed_service.go`, `service.go`, `service_provider.go` | Service lifecycle |
| `config_reload.go` | Configuration reload |

`recovery_interceptor.go` matters: the QUIC server also converts a panicking
handler into `StatusInternalError` and logs the stack, *"so the client never sees
a bare EOF from a panicking handler"* (`pkg/api/quic/server.go`). Panics do not
become connection drops.

## 3. `PlatformDaemon` — 17 RPCs, five of them streaming

`pkg/api/grpc/proto/daemon.proto`:

**Unary:** `GetStatus`, `GetHealth`, `Shutdown`, `GetVersion`, `GetConfig`,
`UpdateConfig`, `ReloadConfig`, `StartService`, `StopService`, `RestartService`,
`GetServiceStatus`, `ListServices`, `ListEntityTypes`.

**Streaming:** `StreamEvents`, `StreamLogs`, `StreamMetrics`,
`DumpEntityType`.

`ListEntityTypes` and `DumpEntityType` are a debugging surface — enumerate the
stored entity types and stream a dump of one. `DumpEntityType` streams because a
dump is unbounded.

**`Shutdown` is an RPC.** A caller with a valid token can stop the daemon; see
§6.

## 4. Configuration snapshots and rollback

REST exposes something the gRPC service does not:

```
GET    /api/v1/platform/config/snapshots
POST   /api/v1/platform/config/snapshots
GET    /api/v1/platform/config/snapshots/{id}
DELETE /api/v1/platform/config/snapshots/{id}
POST   /api/v1/platform/config/snapshots/{id}/rollback
POST   /api/v1/platform/config/validate
```

**Snapshot, validate, rollback.** Configuration changes on a platform that
programs a datapath and enforces attestation policy are the changes most likely
to lock you out, and this is the undo. There is **no gRPC or QUIC equivalent** —
it is REST-only.

`ValidateConfig` before `UpdateConfig` is the intended order.

## 5. Invariants

1. **A transport never implements business logic.** It decodes, delegates to a
   shared service, and encodes. Adding logic to a handler puts it on one
   transport only.
2. **An unwired service answers `StatusUnavailable` / 503, not 404.** The
   capability exists and is off. `iam_service_stub.go` and
   `cluster_service_stub.go` are the mechanism.
3. **A panicking handler becomes an error response**, not a dropped connection.
4. **Roles are configuration.** Do not add a binary for a role.
5. **The GUI bindings must track the service surface.** 22 `bindings_*.go` files
   are the coupling.
6. **`gatewayd`'s import closure is guarded separately** and the guard is
   normative — a failure is an architecture violation, not a flaky test.
7. **No listen address is a literal (#93).** Both `platformd serve` paths
   (webservice and daemon-only) write transport addresses only through
   `applyDaemonListeners` (`pkg/daemon/commands/serve.go`), from the `daemon:`
   section resolved as flag > env > file > defaults
   ([configuration.md](configuration.md)). In webservice mode the daemon does
   not serve REST, so `daemon.rest` is not applied; the webservice binds its
   own `bind-host`. `TestServeCommands_NoListenAddressOutsideApplyDaemonListeners`
   fails with `file:line` on any other assignment, or on a string literal or
   `fmt.Sprintf` in an address field, anywhere in `pkg/daemon/commands`.

## 6. Authorization

`pkg/api/grpc/method_permissions.go` is **default-deny** (#768). Its own doc
comment states the rule: *"Every method the daemon registers on its gRPC server
must appear either here, with the scope it requires, or in preAuthMethods
below. The interceptor refuses any other method with codes.PermissionDenied
before it looks at a token."* `TestGRPCMethodCatalog_*` derives the method list
from the generated service descriptors and fails on any gap, so a new RPC
cannot ship unclassified.

**All 17 `PlatformDaemon` RPCs are scoped.** The observers (`GetHealth`,
`GetStatus`, `GetVersion`, `GetConfig`, `GetServiceStatus`, `ListServices`,
`ListEntityTypes` and the three `Stream*` calls) need `platform:read`.
`UpdateConfig`, `ReloadConfig`, `StartService`, `StopService` and
`RestartService` need `platform:write`. `Shutdown` and `DumpEntityType` need
`platform:admin`.

MCP is default-deny too (#300). The eight `platform_daemon_*` tools are
unclassified, so every caller is refused with `AuthErrorToolNotClassified`. The
`platform_health`, `platform_liveness` and `platform_readiness` tools are
explicitly open.

The catalog totals and the pre-auth list are in [api.md](api.md) §5.

## 7. Daemon TLS identity: reuse, supersede, upgrade

`daemonServerIdentity` (`pkg/daemon/commands/provision_identity.go`) resolves
the `platformd.localhost` server identity on every boot. Key custody is in
[architecture.md](architecture.md) §Daemon TLS identity and key custody.

1. **Reuse.** `CA.TLSCertificate` loads the keystore signer and its
   certificate. If the certificate chains to the CA, covers the required DNS
   SANs and is outside the 30-day renewal window, it is served as is. Nothing
   is issued or revoked, so a restart causes no churn.
2. **Supersede.** In every other case the certificate the CA store holds for
   the CN is looked up with `CA.Certificate`, which reads the certificate
   store and never needs the key. If there is one, `RevokeCert` with
   `DeleteKeys` revokes it and removes the cert-store entry and any keystore
   key.
3. **Issue.** `CA.IssueCertificate` with `KeyAttributes` generates a fresh key
   in the keystore and issues its certificate.

**Upgrade from the PEM-backed identity (before #33).** The old provisioner
signed an externally generated CSR for `platformd.localhost`. `SignCSR` stored
the certificate in the CA certificate store, but the key existed only in the
PEM bundle under `/tmp/platformd-integration/tls`. On the first boot after the
upgrade, `TLSCertificate` fails because the keystore has no key. Step 2 still
finds the certificate, because the lookup does not go through the key, and
revokes it. Without that step, `IssueCertificate` would reject the CN with
`ErrCertificateAlreadyExists` and the daemon would not start. The old PEM
bundle is not read and not migrated: its key is not imported into the keystore.

**Failure leaves nothing half-provisioned.** A lookup that fails with anything
other than `ErrCertificateNotFound`, or a failed revocation, returns
`ErrTLSIdentityKeystore{Op: "supersede"}` before anything is issued or written.
The stored certificate stays in place, no TLS listener starts, and the next
boot retries.

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/api/daemon/*_test.go` and per-transport tests | Service behaviour, interceptors, adapters |
| **Architecture** | `pkg/arch/layerguard_test.go`, `pkg/arch/gatewayguard_test.go` | Import boundaries — **normative** |
| Integration | `test/integration/daemon/`, `cmd/`, `cli/`, `quic/`, `restroutes/`, `multi_protocol_test.go` | Cross-transport behaviour |

`pkg/arch/layerguard_test.go` runs in `make test` and forbids direct imports of
the four lower-layer modules, including in `_test.go` files.
`pkg/arch/gatewayguard_test.go` guards `gatewayd`'s closure. **Never weaken
either to make a build pass.**

**Fault-injection seam — the subscribe hook.** `Service.onSubscribe` is an
unexported `func()` invoked by `StreamEvents`, `StreamLogs` and `StreamMetrics`
once each has registered its subscription channel and can therefore receive a
publish. It is nil on every production path, so it changes neither the exported
surface nor runtime behaviour.

It exists because registration happens inside a goroutine the caller does not
control, and publishing before it completes fans out to **nobody** — not to
fewer subscribers, to none. `streaming_test.go` used to bridge that with `//
Give stream time to initialize` plus `time.Sleep(50ms)`, stating the condition
in a comment and then guessing a duration for it. Under CI load 50ms was not
enough and the assertion saw 0 of 2, failing a PR whose diff was in another
package entirely (issue #255).

Both halves of every streaming test now wait on the event: `observeSubscriptions`
for registration, and a per-mock send signal for delivery, each with a generous
deadline as a liveness backstop rather than a timing assumption. The failure
messages name what was awaited — "streams registered: got 0 of 1" rather than
"sent log count = 0, want 2" — which points at the cause instead of the
symptom.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide — which is a
daemon-and-CLI-level observation, not a per-feature one.

## 9. Observability

`StreamEvents`, `StreamLogs` and `StreamMetrics` are the live surfaces;
`/api/v1/platform/logs`, `/logs/services`, `/logs/stream`, `/metrics`,
`/health`, `/status`, `/version`, `/system` and `/protocols` are the REST
equivalents.

The log store is the JSON-lines sink `installJSONLLogging` tees onto the
daemon logger (`pkg/daemon/commands/log_sink.go`). It returns a **new**
logger, and `serve` hands that one to everything built afterwards (the
webservice registry included). A component given the pre-tee logger logs
around the store, and its records never reach the console Logs page.

Levels are stored as `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL` and
`SECURITY`, lowest to highest. `SECURITY` is `logging.LevelSecurity`, the
level `Logger.Security` writes. The store names it explicitly because slog
would write `ERROR+12`, which ranks as `INFO` under a `?level=` filter. A
`?level=` minimum keeps every record at or above it, so a `SECURITY`
record survives every filter.

`/api/v1/platform/protocols` reports which transports are actually serving —
the fastest way to answer "is QUIC even on".

Health has three shapes on MCP: `platform_health`, `platform_liveness`,
`platform_readiness`. Liveness and readiness are different questions; do not
wire a load balancer to the wrong one.

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — the `gatewayd` binary and the edge role
- [`docs/cluster/`](../cluster/) — control-plane cluster and node state (not
  converted in this pass)
- [`docs/provisioning/`](../provisioning/) — `pxeboot` and `platform-initrd` in context
- Deep dives carried over and not re-verified in this pass:
  [api-reference.md](api-reference.md) and the five per-transport
  `api-reference-*.md` files, [configuration.md](configuration.md)
