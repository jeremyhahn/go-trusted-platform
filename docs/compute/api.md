# Compute — API

> **Status: NORMATIVE** · Scope: VM and container routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Compute` carries the service in-process.

gRPC: `ComputeService`, 34 RPCs (`pkg/api/grpc/proto/compute.proto`) — the
largest service in the platform after IAM.
REST: base path `/api/v1/compute` (`pkg/webservice/v1/rest/compute/router.go`).
On nodes where the compute orchestrator is not configured (e.g. a control
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
| Suspend VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVMSuspend` (`0xB7`) | `vm_suspend` | — |
| Resume VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVMResume` (`0xB8`) | `vm_resume` | — |
| Update VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `vm_update` | — |
| Get VM state | `MISSING — docs/13 G7` | (via `GetVM`) | `OpVMGetState` (`0x6A`) | `MISSING — docs/13 G7` | — |
| Activate VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVMActivate` (`0x68`) | `MISSING — docs/13 G7` | — |

**Suspend and resume have no REST and no gRPC route.** They exist on QUIC and
MCP only. That is a plain asymmetry in the most-used capability set — an
operator on REST can stop a VM but not suspend it.

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
| Verify VM attestation | `POST /api/v1/compute/vms/{id}/attest/verify` | `VerifyVMAttestation` | `MISSING — docs/13 G7` | `vm_attest_verify` | ✅ |
| Attest container | `MISSING — docs/13 G7` | `AttestContainer` | `OpContainerAttest` (`0xEC`) | `container_attest` | ✅ |

`platformctl container attest` is the only attestation CLI verb in the whole
platform — see [`docs/attestation/cli.md`](../attestation/cli.md).

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
asking for VM metrics.** The extended VM lifecycle sub-opcodes `0xB6`–`0xBF` are
handled by the flat VM handler and intercepted ahead of that fallthrough by the
dispatcher's `IsVMSubOpcode` check.

The full category-opcode table is in
[`docs/daemon/api.md`](../daemon/api.md).

---

## 7. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

**`ComputeService` is not in the gRPC scope catalog.**
`pkg/api/grpc/method_permissions.go` maps 185 methods across eleven services;
compute is not among them, and a method absent from the map carries no required
scope.

**No VM or container MCP tool is in the MCP authorization map either** — 71 of
449 declared tool names carry a permission, and none of the 33 compute tools do.

So **any validated token can create, delete, migrate and exec into workloads**
on gRPC, Unix, MCP and embedded. `ExecContainer` in particular is arbitrary
command execution inside a workload. Raised as an owner question in the
migration report.

### REST is gated on the `admin` role (#165)

`/api/v1/compute/**` requires an authenticated caller holding `admin`. That
covers VM create/delete/start/stop/reboot/migrate, snapshot create and restore,
disk attach/detach/resize, and container create/delete/start/stop — including
`POST /compute/containers/{id}/exec`, which is arbitrary command execution
inside a workload and previously answered a caller with no token at all.

Reads are gated with the writes: the VM and container inventory is the map of
what runs on this node and for whom.

This closes the REST half only. **The gRPC, Unix, MCP and embedded positions
above are unchanged** — `ComputeService` still carries no required scope on
those transports, so a validated token remains sufficient there, and that is
still the owner question. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

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

**501 means the binary was built without the provider's build tag** (`awscompute`,
`azurecompute`, `gcpcompute`) — not that the feature is unfinished.

Quota rejection comes from tenancy ([`docs/tenant/`](../tenant/)), which checks
capacity before allocation.

---

## 9. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated in the
compute surface as of 2026-08-18.
