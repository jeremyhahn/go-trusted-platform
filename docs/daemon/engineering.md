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
| `managed_service.go`, `service.go` | Service lifecycle |
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
8. **Start-up returns typed errors; it never panics or exits (#44).**
   `App.Init` returns the log setup's `LogDirInvalidError` (an empty,
   whitespace-only or NUL-bearing `--log-dir`), `LogDirCreateError` and
   `LogFileOpenError`, and a `HostnameError` when no hostname is configured and
   the OS cannot supply one. `pkg/app` calls no `log.Fatal`, `Fatalf` or
   `panic` on these paths, and neither does the test helper
   `TestConfigWithStorage`, which returns `(*App, error)`.
9. **systemd owns the runtime user (#349).** `platformd` does not change its
   own credentials: there is no `--setuid` flag and no privilege drop. The
   unit's `User=` sets the user it runs as; both shipped units
   (`configs/os/platformd.service`, `configs/os/trusted-platform.service`) run
   `User=root`, because the daemon needs root for the TPM, OVS and network
   namespaces. The log file is created by whoever starts the process.

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

MCP is default-deny too (#300). Seven `platform_daemon_*` tools carry the
scope of their gRPC twin (#304) and reach the same `daemon.Service` gRPC
serves: `platform_daemon_status`, `_version`, `_list_services` and
`_get_service` need `platform:read`, and `_start_service`, `_stop_service` and
`_restart_service` need `platform:write`. `platform_daemon_list_protocols` has
no gRPC twin; it needs `platform:read`, the scope of QUIC
`OpDaemonListProtocols`. The `platform_health`, `platform_liveness` and
`platform_readiness` tools are explicitly open.

**Service start, stop and restart do what they say or refuse (#317).** The
seven configured services (`tpm`, `sdn`, `compute`, `dns`, `acme`,
`webservice`, `attestation`) are registered as `subsystemService`
(`pkg/api/daemon/managed_service.go`). The process owns each of them and none
has a lifecycle that is safe to run again, so `Start` and `Stop` return
`ErrServiceNotControllable` (`FailedPrecondition`). `Service.StartService`,
`StopService` and the daemon REST handlers check `processOwned` first and
refuse before they touch the recorded status, counters or last error;
`RestartService` is Stop then Start, so it refuses at the stop. `IsRunning`
reads a probe: the in-daemon subsystems (`tpm`, `sdn`, `compute`, `dns`,
`attestation`) are probed by whether `New` wired them, read once at
registration because `Daemon.Stop` holds `d.mu` while it drains, and
`webservice` and `acme` by a counter `serve.go` holds while `WebServerV1.Run`
blocks, set through `SetSubsystemProbe` (a lock-free `sync.Map`). Every status
read goes through `serviceState.observedStatus`: `IsRunning` wins, then a
recorded `STARTING`, `STOPPING` or `ERROR`, else `STOPPED`. Auto-start and
`Shutdown` skip process-owned services, so they are never marked `ERROR`. The
per-transport mapping is in [api.md](api.md) §2;
`TestProcessOwnedService_RefusedOnEveryTransport`
(`managed_service_test.go`) drives every verb over gRPC, Unix, REST, QUIC and
MCP and checks that the service is still running afterwards.

The catalog totals and the pre-auth list are in [api.md](api.md) §5.

## 7. Daemon TLS identity: two slots, reuse, renew, upgrade

`daemonServerIdentity` (`pkg/daemon/commands/provision_identity.go`) resolves
the server identity on every boot. Key custody is in
[architecture.md](architecture.md) §Daemon TLS identity and key custody.

The identity lives in one of two keystore slots, the common names
`platformd.localhost` and `platformd-alt.localhost` (`daemonServerSlots`). Both
certificates carry the `localhost` and `platformd.localhost` DNS SANs, so a
client cannot tell them apart. There are two slots because `CA.IssueCertificate`
refuses a common name the CA store already holds and no CA call replaces a
certificate atomically. The new key needs its own key ID while the old key is
still serving.

1. **Reuse.** `CA.TLSCertificate` loads each slot. The slot with the latest
   `NotAfter` is the held identity. If it chains to the CA, covers the required
   DNS SANs and is outside the 30-day renewal window, it is served as is and
   the other slot is retired. Nothing is issued, so a restart causes no churn.
2. **Issue into the other slot.** Anything left in the slot that is not
   serving is retired first; a renewal that failed after its issue leaves such
   a leftover. `CA.IssueCertificate` with that slot's `KeyAttributes` then
   generates a fresh key under its own ID, and `CA.TLSCertificate` loads it.
3. **Swap.** At boot the listeners start on the new identity. While running,
   `ServingCertificate.Store` swaps it in.
4. **Retire the old slot** (`retireDaemonServerSlot`). `CA.Certificate` finds
   the stored certificate without needing the key. `RevokeCert` revokes it
   unless `IsRevoked` says it already is. The keystore key, the keystore
   certificate and the certificate-store entry are then deleted under the
   slot's own key attributes, and each deletion is confirmed by looking the
   item up again.

The platform does the deletes itself through the CA's `KeyStore()` and
`CertStore()`, not with `RevokeOptions.DeleteKeys`. go-xkms `CA.RevokeCert`
with `DeleteKeys` deletes under key attributes that lack the key type and
store, discards every delete error, and on a second call stops at
`ErrAlreadyRevoked`, so a failed delete would never be retried.

**Upgrade from the PEM-backed identity (before #33).** The old provisioner
signed an externally generated CSR for `platformd.localhost`. `SignCSR` stored
the certificate in the CA certificate store, but the key existed only in the
PEM bundle under `/tmp/platformd-integration/tls`. On the first boot after the
upgrade neither slot loads, because the keystore has no key. The new identity
is issued into `platformd-alt.localhost`, and the legacy certificate in
`platformd.localhost` is then revoked and removed from the store. The old PEM
bundle is not read and not migrated: its key is not imported into the keystore.

**A failure before the swap touches nothing that serves.** A failure to clear
the other slot, to issue or to load returns `ErrTLSIdentityKeystore{Op}`, with
`Op` set to `retire`, `issue` or `load`. The old slot's certificate and key stay
in place. At boot no TLS listener starts and the next boot retries. While
running, the old identity keeps serving and the next sweep retries.

**A failure after the swap never takes serving down.** If the old slot cannot
be retired, the new identity still serves. The failure is logged as a warning,
and the next sweep retries the retirement.

**Renewal while running (#36).** The `daemon.platformd` cert target
(`daemonIdentityCertTarget`, `pkg/daemon/commands/daemon_identity_renewal.go`)
runs steps 2 to 4 from the platform renewal sweep. `Current` returns the leaf
currently served, and on every sweep it also retires the slot that is not
serving, which finishes any retirement that failed before. `Reissue` issues into
the other slot, stores the new certificate in the `ServingCertificate` that
every TLS listener reads through `GetCertificate`, and only then retires the old
slot. Design and caveats are in [architecture.md](architecture.md) §Daemon TLS
identity renewal while running.

What an operator sees:

| Signal | Meaning |
|---|---|
| `daemon TLS identity: issued keystore-held server identity` with `cn`, `serial`, `not_after` | A new identity was issued into slot `cn`, at boot or by the sweep |
| `daemon TLS identity: retired server identity slot` with `cn`, `serial` | The replaced identity was revoked and its key and certificate deleted |
| `daemon TLS identity: the replaced server identity could not be retired; the next renewal sweep retries` with `cn`, `error` | Warning. The new identity serves, and the old slot is retried on the next sweep |
| `cert-renewal: renewed` with `target=daemon.platformd` | The sweep renewed it. The next handshake presents the new serial |
| `cert-renewal: reissue failed` with `target=daemon.platformd` | Renewal failed. The current certificate and key still serve, and the next sweep retries |
| `cert renewal: cannot register the daemon TLS identity cert target` | Boot-time warning. The identity renews only at restart |
| `platform.cert-renewal.<nodeID>` job result: `cert-renewal sweep: N renewed, N skipped, N failed (of N targets)` | The sweep summary in job history |

The unit tests drive the real sweep on an injected clock (#284) against a
`127.0.0.1:0` TLS listener (`pkg/daemon/commands/daemon_identity_renewal_test.go`).
They cover these cases:

- a certificate inside the window is renewed and presented on the next handshake;
- an issue failure, and a load failure, keep the old certificate and key
  serving and untouched; the failure is typed and logged, and is retried;
- the old key is deleted only after the new identity is serving;
- a failed retirement keeps the new identity serving and is retried on the
  next sweep;
- a certificate outside the window is left alone.

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/api/daemon/*_test.go` and per-transport tests | Service behaviour, interceptors, adapters |
| **Architecture** | `pkg/arch/layerguard_test.go`, `pkg/arch/gatewayguard_test.go`, `pkg/arch/dispatch_*_test.go` | Import boundaries; no served stubs — **normative** |
| Integration | `test/integration/daemon/`, `cmd/`, `cli/`, `quic/`, `multi_protocol_test.go` | Cross-transport behaviour |

`pkg/arch/layerguard_test.go` runs in `make test` and forbids direct imports of
the four lower-layer modules, including in `_test.go` files.
`pkg/arch/gatewayguard_test.go` guards `gatewayd`'s closure. **Never weaken
either to make a build pass.**

**Dispatch-stub check (#317).** `TestDispatchedOperationsReachRealImplementations`
(`pkg/arch/dispatch_*_test.go`, in `make test`) walks every operation the
daemon serves: the QUIC category and opcode dispatch, the gRPC services
registered on TCP and Unix, the daemon and webservice REST routes, and the MCP
tools. It resolves each handler through the file's import bindings, never by a
bare name, so a stub and a real type that share a constructor name are told
apart. An operation fails when the last statement of its handler answers a stub
marker: `codes.Unimplemented`, a `*NotImplemented*` name, a "not yet
supported" string, or an embedded `Unimplemented*Server` method nothing
overrides. The report names the operation and the stub's `file:line`. The check
is static (`go/ast`). A runtime probe would need a fully wired daemon, and it
could not tell a stub from a request the service rightly refused.

Stubs already on `main` are listed in `stubExceptions`
(`pkg/arch/dispatch_stub_test.go`), each with its `file:line` and a reason. To
clear one, implement the operation, delete its entry, and lower
`stubExceptionCeiling` to the new length. The check fails on an entry whose stub
is gone, so the list can only shrink. Never add an entry for a new stub:
implement the operation instead.

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
- [configuration.md](configuration.md) — the listen-address keys and
  `platformd serve` flags, checked against the code 2026-10-13. The older
  api-reference.md and the five per-transport
  `api-reference-*.md` files are deleted; [api.md](api.md) holds their content.
