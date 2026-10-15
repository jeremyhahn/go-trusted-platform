# Compute — API

> **Status: NORMATIVE** · Scope: VM and container routes on every transport · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Compute` carries the service in-process.

gRPC: `ComputeService`, 36 RPCs (`pkg/api/grpc/proto/compute.proto`) — the
largest service in the platform after IAM.
REST: base path `/api/v1/compute` — web service
(`pkg/webservice/v1/rest/compute/router.go`) and platformd's REST listener
(`pkg/api/rest/compute_handlers.go`, mounted by `RESTServer.SetComputeHandlers`).
On web-service nodes where the compute orchestrator is not configured (e.g. a control
plane without a container runtime), the surface registers through the
service registry loud-failure policy: every `/api/v1/compute/*` request
answers a structured 503, and the dark surface is listed on
`GET /api/v1/platform/service-registry`. `/api/v1/compute/images` is owned by
the registry service and stays live independently of compute.

```json
{
  "code": 503,
  "error": "compute service not configured by daemon — REST surface is dark",
  "success": false,
  "service": "compute",
  "reason": "SERVICE_NOT_CONFIGURED"
}
```

`reason` is the **contract**: `SERVICE_NOT_CONFIGURED` is a stable,
machine-readable discriminator (`ReasonServiceNotConfigured` in
`pkg/webservice/v1/service_registry.go`) that separates "this node
deliberately does not host compute" from a transient 503 out of a live
service, which carries no `reason`. `error` is operator-facing prose and may
change at any time — clients MUST NOT match on it. The TypeScript SDK lifts
`reason` and `service` into `ApiError.details` and exposes the predicate as
`isServiceNotConfigured(err)`, which additionally requires status 503.
QUIC: top-level VM opcodes `0x60`–`0x6A`, extended lifecycle `0xB6`–`0xBF`, and
a **VM extended category opcode `0x69`** for the operational sub-opcodes — §6.

**Two REST servers serve `/api/v1/compute`.** The web service mounts its router
(the 503 above and the `admin` gate of §7 are its behaviour); platformd's own
REST listener mounts `restapi.ComputeHandlers`. **Every daemon-listener route
calls one RPC of the daemon's `ComputeService`** — the same
`ComputeGRPCService` that gRPC and Unix call, with no compute logic of its own
— behind the scope that RPC requires on gRPC (§7), granted by a platform bearer
token or the verified client certificate. A daemon with no compute service
mounts none of these routes. Each route speaks the SDK wire contract
(`TestComputeRoutesServeTheSDKContract`, `pkg/api/rest/compute_handlers_test.go`;
§2–§5 list the routes):

- The request is the RPC's request message. The body is protojson, with either
  the camelCase JSON name (the SDKs) or the proto name of each field. An enum
  is its proto name (`VM_STATE_RUNNING`, `PCR_BANK_SHA256`) or number; the
  short `RUNNING` is refused. The JavaScript SDK types every compute enum by
  its proto name, the spelling every response carries too, and prefixes only
  the short PCR bank (`SHA256`) its TPM types share before sending. An empty
  body is the empty request.
- Query parameters and path parameters set fields of the same message, by
  either name: a field of a nested message by dotted path
  (`pagination.pageSize=20`), a string-map entry as `field.key`
  (`selector.matchLabels.tier=web`), and one parameter per element of a
  repeated field (`?states=VM_STATE_RUNNING&states=VM_STATE_STOPPED`). A path
  parameter wins over a query parameter of the same name.
- **A field the message does not have is `400`, never a silent default** — in
  the body (`ErrInvalidRequestBody`, `unknown field "x"`) or as a parameter
  (`ErrInvalidQueryParameter`). So is a parameter that does not parse, or a
  single-valued field given twice. The compute service is not called.
- The reply is the bare protojson response message, with camelCase keys and
  every field present. An RPC error is the standard error envelope, its status
  mapped from the gRPC code as on the TPM routes.

The daemon listener has no console or logs route: they are streams (§5).

---

## 2. VM lifecycle

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create VM | `POST /api/v1/compute/vms` | `CreateVM` | `OpVMCreate` (`0x60`) | `vm_create` | ✅ |
| List VMs | `GET /api/v1/compute/vms` | `ListVMs` | `OpVMList` (`0x65`) | `vm_list` | ✅ |
| Get VM | `GET /api/v1/compute/vms/{id}` | `GetVM` | `OpVMGet` (`0x64`) | `vm_get` | ✅ |
| Delete VM | `DELETE /api/v1/compute/vms/{id}` | `DeleteVM` | `OpVMDelete` (`0x61`) | `vm_delete` | ✅ |
| Start VM | `POST /api/v1/compute/vms/{id}/start` | `StartVM` | `OpVMStart` (`0x62`) | `vm_start` | ✅ |
| Stop VM | `POST /api/v1/compute/vms/{id}/stop` | `StopVM` | `OpVMStop` (`0x63`) | `vm_stop` | ✅ |
| Reboot VM | `POST /api/v1/compute/vms/{id}/reboot` | `RebootVM` | `OpVMRestart` (`0xB6`) | `vm_reboot` | ✅ |
| Suspend VM | `POST /api/v1/compute/vms/{id}/suspend` | `SuspendVM` | `OpVMSuspend` (`0xB7`) | `vm_suspend` | ✅ |
| Resume VM | `POST /api/v1/compute/vms/{id}/resume` | `ResumeVM` | `OpVMResume` (`0xB8`) | `vm_resume` | ✅ |
| Update VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get VM state | `MISSING — docs/13 G7` | (via `GetVM`) | `OpVMGetState` (`0x6A`) | `MISSING — docs/13 G7` | — |
| Activate VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVMActivate` (`0x68`) | `MISSING — docs/13 G7` | — |

**Suspend pauses a running VM in memory; resume continues it** (#704). The
QEMU orchestrator sends QMP `stop` and `cont` (`pkg/compute/qemu_suspend.go`)
and records the VM as `suspended`, which `GetVM` reports as `VM_STATE_PAUSED`
and the container view of the compute adapter as `paused`.
Suspending a VM that is not running, or resuming one that is not suspended, is
FailedPrecondition. Stop and delete accept a suspended VM; start refuses it.

**A VM is recorded `stopped` only when stop asked for it.** When the QEMU
process exits, the orchestrator (`recordExit`, `pkg/compute/qemu.go`) moves a
`stopping` VM to `stopped`. The lifecycle has no transition into `stopped` from
any other state, so a VM whose guest powers off or crashes while `running` or
`suspended` keeps that state, with its PID cleared and a warning logged. An
`error` VM stays `error`, and a VM already deleted or migrated away is not
recreated.

**Reboot is stop then start** on every transport (`compute.Reboot`,
`pkg/compute/reboot.go`), so a stopped VM refuses a reboot with
FailedPrecondition.

QUIC carries `OpVMRestart`, `OpVMSuspend` and `OpVMResume` as sub-opcodes under
`OpVMExtendedCategory` (`0x69`). The payload after the sub-opcode byte is the
`RebootVMRequest`, `SuspendVMRequest` or `ResumeVMRequest` message, and the
daemon answers through the same `ComputeService` as gRPC (§6).

**The Go SDK carries each verb the daemon answers.** Its REST adapter maps all
six lifecycle verbs to the routes above, with the id in the path and
`delete_disks` as a query parameter. Its MCP adapter maps all six to the
`vm_*` tools. The tools take only `id`, so the adapter refuses `force`,
`timeout_seconds` or `delete_disks` with InvalidArgument rather than drop them
(`sdk/go/transport/mcp/compute_vm.go`). Its QUIC adapter maps reboot, suspend
and resume. Start, stop and delete fail locally with Unimplemented, because
`0x62`, `0x63` and `0x61` answer `StatusUnavailable` on a running daemon (§6).
Every adapter returns the client's typed error (`ErrStartVMFailed`, ...,
`sdk/go/services/compute/errors.go`) wrapping the transport status: an unknown VM
is NotFound everywhere. A VM in the wrong state is FailedPrecondition, except
over REST, where it is InvalidArgument because both REST servers render
FailedPrecondition as HTTP 400. `TestVMLifecycleSDKParity_*`
(`pkg/api/daemon/compute_sdk_parity_test.go`) holds this.

---

## 3. VM disks, snapshots and migration

QUIC serves these as **sub-opcodes under `OpVMExtendedCategory` (`0x69`)** — see
§6 before using the byte values.

| Capability | REST | gRPC / Unix | QUIC (under `0x69`) | MCP | Embedded |
|---|---|---|---|---|---|
| Attach disk | `POST /api/v1/compute/vms/{id}/disks` | `AttachDisk` | `OpVMAttachDisk` (`0xCD`) | `vm_disk_attach` | ✅ |
| Detach disk | `DELETE /api/v1/compute/vms/{id}/disks/{diskId}` | `DetachDisk` | `OpVMDetachDisk` (`0xCE`) | `vm_disk_detach` | ✅ |
| Resize disk | `PATCH /api/v1/compute/vms/{id}/disks/{diskId}` | `ResizeDisk` | `OpVMResizeDisk` (`0xCF`) | `vm_disk_resize` | ✅ |
| Create snapshot | `POST /api/v1/compute/vms/{id}/snapshots` | `CreateSnapshot` | `MISSING — docs/13 G7` | `vm_snapshot_create` | ✅ |
| List snapshots | `GET /api/v1/compute/vms/{id}/snapshots` | `ListSnapshots` | `MISSING — docs/13 G7` | `vm_snapshot_list` | ✅ |
| Get snapshot | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vm_snapshot_get` | — |
| Delete snapshot | `DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}` | `DeleteSnapshot` | `MISSING — docs/13 G7` | `vm_snapshot_delete` | ✅ |
| Restore snapshot | `POST /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore` | `RestoreSnapshot` | `MISSING — docs/13 G7` | `vm_snapshot_restore` | ✅ |
| Migrate VM | `POST /api/v1/compute/vms/{id}/migrate` | `MigrateVM` | `OpVMMigrate` (`0xD0`) | `vm_migrate` | ✅ |
| Prepare migration | `MISSING — docs/13 G7` | `PrepareMigration` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Finalize migration | `MISSING — docs/13 G7` | `FinalizeMigration` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| VM metrics | `GET /api/v1/compute/vms/{id}/metrics` | `GetVMMetrics` | `OpVMMetrics` (`0xCC`) | `vm_metrics` | ✅ |
| VM logs | `MISSING` — streaming, §5 | `GetVMLogs` (server stream) | `MISSING` — streaming | `vm_logs` | ✅ |

`PrepareMigration` and `FinalizeMigration` are gRPC-only and exist so a
migration can be staged and confirmed; `MigrateVM` is the one-shot form. Do not
treat the pair as internal — they are the two-phase contract.

`ResizeDisk` is a `PATCH`, the only `PATCH` in the compute surface.

---

## 4. Containers

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create container | `POST /api/v1/compute/containers` | `CreateContainer` | `OpContainerCreate` (`0xFC`) | `container_create` | ✅ |
| List containers | `GET /api/v1/compute/containers` | `ListContainers` | `OpContainerList` (`0xAE`) | `container_list` | ✅ |
| Get container | `GET /api/v1/compute/containers/{id}` | `GetContainer` | `OpContainerGet` (`0x6F`) | `container_get` | ✅ |
| Delete container | `DELETE /api/v1/compute/containers/{id}` | `DeleteContainer` | `OpContainerRemove` (`0xFF`) | `container_remove` | ✅ |
| Start container | `POST /api/v1/compute/containers/{id}/start` | `StartContainer` | `OpContainerStart` (`0xFD`) | `container_start` | ✅ |
| Stop container | `POST /api/v1/compute/containers/{id}/stop` | `StopContainer` | `OpContainerStop` (`0xFE`) | `container_stop` | ✅ |
| Exec in container | `POST /api/v1/compute/containers/{id}/exec` | `ExecContainer` | `OpContainerExec` (`0xCA`) | `container_exec` | ✅ |
| Container metrics | `GET /api/v1/compute/containers/{id}/metrics` | `GetContainerMetrics` | `OpContainerMetrics` (`0xCB`) | `container_metrics` | ✅ |
| Container logs | `MISSING` — streaming, §5 | `GetContainerLogs` (server stream) | `OpContainerLogs` (`0xAF`) | `container_logs` | ✅ |
| Attach to container | `MISSING` — streaming, §5 | `AttachContainer` (server stream) | `MISSING` — streaming | `MISSING` | ✅ |

Containers are the most evenly covered capability set in this feature.

---

## 5. Attestation of workloads

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Attest VM | `POST /api/v1/compute/vms/{id}/attest` | `AttestVM` | `OpVMAttest` (`0xB9`) | `vm_attest` | ✅ |
| Verify VM attestation | `POST /api/v1/compute/vms/{id}/attest/verify` | `VerifyVMAttestation` | `OpVMVerifyAttest` (`0xBF`) | `vm_attest_verify` | ✅ |
| Attest container | `POST /api/v1/compute/containers/{id}/attest` | `AttestContainer` | `OpContainerAttest` (`0xEC`) | `container_attest` | ✅ |

`platformctl container attest` is the only attestation CLI verb in the whole
platform — see [`docs/attestation/cli.md`](../attestation/cli.md).

### A VM quote declares its signature scheme

Attest VM returns `signature_algorithm` beside `signature` on every transport:
the scheme the vTPM's attestation key signed the quote with, named as
`x509.SignatureAlgorithm` names it (`SHA256-RSA`, `SHA256-RSAPSS`,
`ECDSA-SHA256`, and the SHA-384/512 forms). It comes from the AK's key
attributes, not from its key type.

Verify VM attestation takes the same field back (REST and MCP
`signature_algorithm`, gRPC `VerifyVMAttestationRequest.signature_algorithm`,
QUIC `signature_algorithm`) and checks the signature under that scheme alone.
An absent or unknown scheme, or one the live AK cannot carry, is not a
transport error: the call succeeds with `verified` and `signature_valid` false
and the reason in `message`. A client therefore echoes Attest VM's
`signature_algorithm` unchanged.

### Streaming capabilities are transport-limited by design

`AttachVMConsole`, `SendVMConsoleInput`, `AttachContainer`, `GetVMLogs` and
`GetContainerLogs` are gRPC streams with **no unary equivalent**. The QUIC
layer's own comment records the decision: *"interactive console and log-follow
remain streaming-only and daemon-native"*
(`sdk/go/wire/quicwire/vm_ops_opcodes.go`). These are **not** gaps to close by adding a
REST route; a console session over request/response is not a console session.

---

## 6. QUIC opcode values are reused, deliberately

`OpVMMetrics` is `0xCC` — and so is `OpSwitchCategory`. `OpVMAttachDisk` is
`0xCD` and so is `OpKMSExtendedCategory`. `OpVMDetachDisk` is `0xCE` /
`OpSecretsCategory`, `OpVMResizeDisk` is `0xCF` / `OpProvisioningCategory`, and
`OpVMMigrate` is `0xD0` / `OpKMSEncrypt`.

This is not a collision. `sdk/go/wire/quicwire/vm_ops_opcodes.go` states it explicitly:
these values are **sub-opcodes carried in `payload[0]` under
`OpVMExtendedCategory` (`0x69`)**, never sent at top level, so they only need to
be unique among sub-opcodes under `0x69`. The daemon dispatcher inspects them
only after matching `0x69`.

The same pattern applies to `OpContainerExec` (`0xCA`) and `OpContainerMetrics`
(`0xCB`), which reuse the top-level KMS range.

**A client that sends `0xCC` at top level is talking to the switch service, not
asking for VM metrics.** Under `0x69` the daemon first offers every sub-opcode
to the `ComputeService` path (`handleVMPB`, `pkg/api/daemon/quic_vm_pb.go`):
the operational sub-opcodes above and the lifecycle sub-opcodes `OpVMRestart`,
`OpVMSuspend` and `OpVMResume` (`0xB6`–`0xB8`) are answered there, and the rest
of `0xB9`–`0xBF` fall through to the flat VM handler. platformd does not wire
that handler (nothing outside tests calls `SetVMOrchestrator`), so those
sub-opcodes, and the top-level opcodes `0x60`–`0x6A`, answer
`StatusUnavailable` on a running daemon.

The full category-opcode table is in
[`docs/daemon/api.md`](../daemon/api.md).

---

## 7. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`ComputeService` is fully scoped on gRPC** (`pkg/api/grpc/method_permissions.go`)
under two resources:

| Permission | RPCs |
|---|---|
| `container:read` | `GetContainer`, `ListContainers`, `GetContainerLogs`, `GetContainerMetrics`, `AttestContainer` |
| `container:write` | `CreateContainer`, `StartContainer`, `StopContainer`, `ExecContainer`, `AttachContainer` |
| `container:delete` | `DeleteContainer` |
| `vm:read` | `GetVM`, `ListVMs`, `GetVMLogs`, `GetVMMetrics`, `ListSnapshots`, `AttestVM`, `VerifyVMAttestation` |
| `vm:write` | `CreateVM`, `StartVM`, `StopVM`, `RebootVM`, `SuspendVM`, `ResumeVM`, `AttachDisk`, `DetachDisk`, `ResizeDisk`, `CreateSnapshot`, `RestoreSnapshot`, `MigrateVM`, `PrepareMigration`, `FinalizeMigration`, `AttachVMConsole`, `SendVMConsoleInput` |
| `vm:delete` | `DeleteVM`, `DeleteSnapshot` |

`ExecContainer` is arbitrary command execution inside a workload, so
`container:write` is the scope to guard.

**The MCP tools answer under the scope of their gRPC twin** (#304). The MCP
permission map (`pkg/api/mcp/authz.go`) holds each tool that reaches a real
backend:

| Permission | MCP tools |
|---|---|
| `container:read` | `container_get`, `container_list`, `container_logs`, `container_metrics`, `container_attest` |
| `container:write` | `container_create`, `container_start`, `container_stop`, `container_exec` |
| `container:delete` | `container_remove` |
| `vm:read` | `vm_list`, `vm_get`, `vm_snapshot_list`, `vm_snapshot_get`, `vm_attest`, `vm_attest_verify`, `vm_metrics`, `vm_logs` |
| `vm:write` | `vm_create`, `vm_start`, `vm_stop`, `vm_reboot`, `vm_suspend`, `vm_resume`, `vm_snapshot_create`, `vm_snapshot_restore`, `vm_disk_attach`, `vm_disk_detach`, `vm_disk_resize`, `vm_migrate` |
| `vm:delete` | `vm_delete`, `vm_snapshot_delete` |

`vm_disk_detach` is `vm:write`, not `vm:delete`, because `DetachDisk` is.

The nine VM lifecycle tools answer through their RPC
(`pkg/api/daemon/mcp_vm_lifecycle.go`): the daemon builds the RPC request,
calls `ComputeService`, and returns its reply in the proto's field names.
`vm_create` takes what `CreateVM` reads (`name`, `memory`, `cpus`,
`tpm_enabled`, `secure_boot`); an omitted `memory` or `cpus` takes the RPC's
default of 1024 MB and one core. `vm_list` takes no filter, because `ListVMs`
applies none.

A tool's failure carries the gRPC status class its twin RPC answers the same
failure with: NotFound for an unknown VM, container, snapshot or disk,
InvalidArgument for malformed input (including a PCR index outside 0-23),
FailedPrecondition for a missing orchestrator or VM capability, and
Unimplemented for a missing container capability. A VM in the wrong state for
the verb (starting a running VM, suspending a stopped one, resuming a running
one) is FailedPrecondition. `CreateVM`, `StartVM`, `StopVM`, `RebootVM`,
`SuspendVM`, `ResumeVM` and `DeleteVM` classify an orchestrator failure as the
disk RPCs do, so an unknown VM is NotFound there too; any other failure
stays Internal.

`vm_snapshot_get` has no gRPC or REST twin. It reads one entry of what
`ListSnapshots` returns, so it takes `ListSnapshots`' `vm:read`. #304 deleted
`vm_update`, which had no twin and no executor behind it; #704 brought
`vm_suspend` and `vm_resume` back with `SuspendVM` and `ResumeVM` as their twins.

No transport scopes a VM or container to a tenant. `compute.Instance` has no
tenant field, and neither `ComputeService` nor the MCP tools filter by tenant.
A caller holding `vm:read` reads every VM on the node.

### The web-service REST surface is gated on the `admin` role (#165)

On the web service, `/api/v1/compute/**` requires an authenticated caller holding `admin`. That
covers VM create/delete/start/stop/reboot/migrate, snapshot create and restore,
disk attach/detach/resize, and container create/delete/start/stop — including
`POST /compute/containers/{id}/exec`, which is arbitrary command execution
inside a workload and previously answered a caller with no token at all.

Reads are gated with the writes: the VM and container inventory is the map of
what runs on this node and for whom.

The web-service gate is role-based. The one exception is container
attestation: `POST /compute/containers/{id}/attest` also requires
`container:read`, the scope of `AttestContainer`, whenever the session
middleware checks scopes. The legacy JWT handler carries roles, not scopes, so
under it the route has the `admin` gate alone. The body carries `nonce`,
`pcr_indices` and `pcr_bank`, and the container ID comes from the path.

platformd's REST listener checks the gRPC
scope catalog above, route by route: each route requires exactly the
permission of the RPC it calls (`computeRouteScopes`,
`pkg/api/rest/route_scope_test.go`). The MCP position is its own catalog. See [`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | Compute cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed VM or container spec |
| `0x02` | `StatusNotFound` | 404 | Unknown VM, container, disk or snapshot |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | QEMU or podman failure |
| `0x06` | `StatusAlreadyExists` | 409 | Name already in use |
| `0x07` | `StatusPermissionDenied` | 403 | Port authentication refused the VNIC |
| `0x08` | `StatusResourceExhausted` | 429 | Tenant quota, or `max_instances` |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrNoNetworkInZone` |
| `0x0A` | `StatusUnavailable` | 503 | Compute not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | `ErrComputeProviderNotCompiled` |
| `0x0C` | `StatusFailedPrecondition` | 400 | VM in the wrong state for reboot, suspend or resume |

**501 means the binary was built without the provider's build tag** (`awscompute`,
`azurecompute`, `gcpcompute`) — not that the feature is unfinished.

Quota rejection comes from tenancy ([`docs/tenant/`](../tenant/)), which checks
capacity before allocation.

---

## 9. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated in the
compute surface as of 2026-08-18.
