# Compute — API

> **Status: NORMATIVE** · Scope: VM and container routes on every transport · Last verified: 2026-10-15
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Compute` carries the service in-process.

gRPC: `ComputeService`, 37 RPCs (`pkg/api/grpc/proto/compute.proto`) — the
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
QUIC: the **VM extended category opcode `0x69`**, whose sub-opcodes carry the
VM verbs (§2), the snapshot verbs (§3), the attestation verbs (§5) and the
operational calls — §6.

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
| Get VM state | (via `GET /api/v1/compute/vms/{id}`) | (via `GetVM`) | (via `OpVMGet`) | (via `vm_get`) | (via `GetVM`) |
| Activate VM | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |

**Suspend pauses a running VM in memory; resume continues it** (#704). The
QEMU orchestrator sends QMP `stop` and `cont` (`pkg/compute/qemu_suspend.go`)
and records the VM as `suspended`, which `GetVM` reports as `VM_STATE_PAUSED`,
`GetContainer` and `ListContainers` as `CONTAINER_STATE_PAUSED`, and the
container view of the compute adapter as `paused`.
Suspending a VM that is not running, or resuming one that is not suspended, is
FailedPrecondition. Stop and delete accept a suspended VM; start refuses it.

The proto views map the lifecycle state through one table each
(`instanceStateToVMProtoState`, `instanceStateToContainerProtoState`,
`pkg/api/daemon/compute_grpc_service.go`). gRPC, Unix, REST and QUIC all carry
these messages:

| Lifecycle state | `VMState` | `ContainerState` |
|---|---|---|
| `creating` | `UNSPECIFIED` | `CREATED` |
| `starting` | `STARTING` | `STARTING` |
| `running` | `RUNNING` | `RUNNING` |
| `suspended` | `PAUSED` | `PAUSED` |
| `stopping` | `STOPPING` | `STOPPING` |
| `stopped` | `STOPPED` | `EXITED` |
| `error` | `ERROR` | `ERROR` |
| `unknown`, `deleting` | `UNSPECIFIED` | `UNSPECIFIED` |

The proto enums have no value for `unknown` or `deleting`, and `VMState` none
for `creating`.

**A VM is recorded `stopped` only when stop asked for it.** When the QEMU
process exits, the orchestrator (`recordExit`, `pkg/compute/qemu.go`) moves a
`stopping` VM to `stopped`. The lifecycle has no transition into `stopped` from
any other state, so a VM whose guest powers off or crashes while `running` or
`suspended` keeps that state, with its PID cleared and a warning logged. An
`error` VM stays `error`, and a VM already deleted or migrated away is not
recreated.

**Reboot is stop then start** on every transport (`compute.RebootWithOptions`,
`pkg/compute/reboot.go`), so a stopped VM refuses a reboot with
FailedPrecondition.

**Create honours its config, or refuses it** (#704; `ComputeService.CreateVM`,
`pkg/api/daemon/compute_vm_create.go`, and `compute.VMSpec`,
`pkg/compute/vm_create.go`). The `local-qemu` backend builds one shape of VM:
UEFI firmware, one qcow2 boot disk, one virtio-net NIC on the orchestrator's
bridge, an emulated TPM 2.0 and no display. CreateVM applies the fields it
can and refuses every other setting with InvalidArgument
(`ErrVMCreateUnsupportedField`, "config.`<field>` is not supported: ...")
before anything is created. A field left at its zero value is never refused.

| Field | What CreateVM does with it |
|---|---|
| `name` | the VM name; required |
| `description`, `labels`, `metadata` | stored on the VM and returned by `GetVM` and `ListVMs`; `labels` is what `selector.match_labels` matches |
| `firmware` | `UEFI` (or unset) boots UEFI; `UEFI_SECURE_BOOT` turns on Secure Boot |
| `secure_boot` | turns on Secure Boot, as `UEFI_SECURE_BOOT` does |
| `boot_device` | `DISK` (or unset) boots the disk; `NETWORK` PXE-boots |
| `cpu.cores` | the vCPU count; unset is the orchestrator's `default_cpus` |
| `memory.size_mb` | the memory; unset is the orchestrator's `default_memory` |
| `disks[0].size_gb` | the boot disk size; unset is the orchestrator's `default_disk_size` |
| `disks[0].type` | `QCOW2` (or unset) |
| `disks[0].bus` | the architecture's bus (or unset): `SATA` on x86_64, `VIRTIO` on aarch64 |
| `disks[0].bootable` | accepted; the one disk is always the boot disk |
| `networks[0].mac_address` | the NIC's MAC address; unset leaves it to QEMU |
| `networks[0].bridge` | the orchestrator's bridge (or unset) |
| `networks[0].model` | `VIRTIO` (or unset) |
| `tpm` | unset or `enabled: true` attaches a vTPM; `enabled: false` creates the VM without one |
| `tpm.version` | `2_0` (or unset) |
| `tpm.emulated` | accepted; the vTPM is always emulated |

| Refused | Why |
|---|---|
| `firmware` `BIOS` | VMs boot UEFI firmware |
| `boot_device` `CDROM` | CD-ROM boot needs an installation ISO, which CreateVM cannot carry |
| `cpu.sockets` or `cpu.threads` over 1, `cpu.model`, `cpu.features` | vCPUs are single-thread cores on one socket of the default model |
| `memory.hugepages`, `memory.shared` | not available |
| more than one `disks` entry | attach more with `AttachDisk` |
| `disks[0].id`, `.path`, `.readonly`, `.backing_file`; another `.type` | the orchestrator creates a fresh writable qcow2 disk and names it |
| more than one `networks` entry | attach more with `AttachNetwork` |
| `networks[0].id`, `.vlan`, `.bandwidth_limit_mbps`; another `.model` | NIC ids are assigned, VLANs come from the network policy, no bandwidth limits |
| `graphics` (any type but `NONE`, or any listen, port, password or keymap) | VMs have no display; use the serial console |
| `tpm.version` other than `2_0`, `tpm.device_path`, `tpm.state_dir` | the vTPM is an emulated TPM 2.0 kept in the VM's work directory |
| `nvram` | UEFI variables start from the configured template |

Three checks depend on the orchestrator's configuration and are made by it
(`checkVMSpec`, `pkg/compute/qemu_create.go`), also as InvalidArgument: Secure
Boot when `ovmf_code_secure` is not configured, a `disks[0].bus` the
architecture does not use, and a `networks[0].bridge` other than its own. A
malformed `mac_address` is InvalidArgument too. An orchestrator other than
`local-qemu` builds only its default VM: a config that sets any field in the
first table to other than its default is FailedPrecondition there.

**`start` deletes the VM it could not start.** With `start` set, CreateVM
starts the new VM and returns it running. If the start fails, it deletes the
VM and returns the start error with its class (an unknown disk is NotFound,
and so on), so a failed create-and-start leaves nothing behind
(`compute.StartOrDelete`). If the delete fails too, the error carries both.

**Stop and reboot honour `force` and `timeout_seconds`**
(`compute.StopOptions`, `pkg/compute/vm_stop.go`). By default the guest
gets an ACPI power-button press and 30 seconds to power off, then the process
gets SIGTERM. `timeout_seconds` replaces the 30 seconds, up to 3600. `force`
kills the process with SIGKILL at once; a forced stop of a suspended VM kills
it without continuing it first. `RebootVM` has only `force`, which forces its
stop half. A forced stop that also carries a timeout, or a timeout over 3600,
is InvalidArgument before the VM is touched. An orchestrator that cannot honour
the options (any but `local-qemu`) answers FailedPrecondition for a non-default
stop rather than taking a default one.

No transport raises its write timeout for a stop; the reply's deadline moves
instead. Over REST — the daemon's routes (`pkg/api/rest/compute_handlers.go`)
and the webservice's (`pkg/webservice/v1/rest/compute/`) — the stop and reboot
routes move the reply's write deadline to `StopOptions.ReplyWindow`: the
guest's power-down window (`StopOptions.GuestWait`) plus 30 seconds. The
daemon's REST middleware writers unwrap, so the move reaches the connection.
Over MCP every call's write deadline restarts at `RequestTimeout` once its
reply is ready (`pkg/api/mcp/server.go`). Either way a graceful stop that runs
past the server's 30-second write timeout still answers instead of closing
the connection.

No transport puts a deadline of its own on the call either. A gRPC call runs
until its client's deadline; an MCP tool runs until its HTTP request ends
(`ToolRegistry.ExecuteTool`, `pkg/api/mcp/tools.go`, adds none), so a reboot,
a stop window plus a start, finishes over MCP as it does over gRPC. stdio has
no request to end with its client, so there the server's `RequestTimeout`
bounds each call, except that `vm_stop` and `vm_reboot` get
`StopOptions.ReplyWindow` when it is longer, the window REST moves its reply
deadline to (`toolReplyWindows`, `pkg/api/mcp/tool_reply_window.go`).

The client waits as long. The SDK owns the window
(`StopReplyWindow` in `sdk/go/services/compute/stop_window.go`) and
`StopOptions.ReplyWindow` uses its margin, so the two cannot drift. The SDK's
MCP transport sends `vm_stop` and `vm_reboot` with that window as the
request's HTTP timeout when it is longer than the client's own
(`platform.WithTimeout`, 5 seconds by default; `sdk/go/transport/mcp/compute_vm.go`,
`mcpwire.Client.CallToolWithin`). Every other call keeps the client's timeout.

**List honours `states`, `selector` and `pagination`**
(`ComputeService.ListVMs`, `pkg/api/daemon/compute_vm_list.go`). `states`
keeps the VMs in any listed state; an empty list keeps every state.
`selector.match_labels` keeps the VMs that carry every listed label with an
equal value; a VM carries the `config.labels` it was created with.
`pagination` pages the way the EAB credential list does
(`pkg/api/daemon/pagination.go`): `sort_by` is `id` (the default, always
ascending), `name` or `created_at`, ties broken by id, in the direction
`ascending` names. `page_size` 0 is one page of every VM, page 0
is page 1, and a page past the end is an empty list. The response's
`pagination` reports the page, the page size, and the total pages and VMs.
A list that matches nothing is an empty list, not an error. An unknown state
number, any `selector.match_expressions` entry (the API defines no expression
syntax) and any other `sort_by` are InvalidArgument (`ErrVMListUnknownState`,
`ErrVMListSelectorExpression`, `ErrVMListUnsupportedSortField`) before the
orchestrator is asked.

Every transport reaches that one filter. gRPC and the Unix socket call
`ListVMs` directly, QUIC `0x65` and MCP `vm_list` carry the full request, and
both REST servers read the `ListVMsRequest` as the JSON body of
`GET /api/v1/compute/vms`, which is how the Go SDK's REST adapter sends it
(`sdk/go/transport/rest/adapter.go`). The web service also takes `page` and
`page_size` query parameters, which replace the body's page and page size.
`TestVMListSDKParity_*` (`pkg/api/daemon/compute_sdk_parity_test.go`) holds
this over REST, MCP and QUIC.

QUIC carries create, list, get, delete, start, stop, reboot, suspend and resume
as sub-opcodes under `OpVMExtendedCategory` (`0x69`), with the values in the
table above. The payload after the sub-opcode byte is the RPC's request message
(`CreateVMRequest`, ..., `ResumeVMRequest`), and the daemon answers through the
same `ComputeService` as gRPC (§6).

**The Go SDK carries each verb the daemon answers.** Its REST adapter maps all
six lifecycle verbs to the routes above, with the id in the path and
`delete_disks` as a query parameter, and sends the full `CreateVMRequest` as
the body of `POST /api/v1/compute/vms`. Its MCP adapter maps all six, plus
create, get and list, to the `vm_*` tools and sends each RPC's full request,
`force`, `timeout_seconds` and `delete_disks` included
(`sdk/go/transport/mcp/compute_vm.go`). Its QUIC adapter maps all six, and
create, get and list, to their sub-opcodes (`sdk/go/transport/quic/adapter.go`).
Every adapter returns the client's typed error (`ErrStartVMFailed`, ...,
`sdk/go/services/compute/errors.go`) wrapping the transport status: an unknown VM
is NotFound everywhere. A VM in the wrong state is FailedPrecondition, except
over REST on any method but `DELETE`, where it is AlreadyExists: both REST
servers render FailedPrecondition as HTTP 409 Conflict (#665), and the SDK
reads a 409 as AlreadyExists unless the request was a `DELETE` (a snapshot
delete stays FailedPrecondition). `TestVMLifecycleSDKParity_*`
(`pkg/api/daemon/compute_sdk_parity_test.go`) holds this over REST, MCP, QUIC,
gRPC, the Unix socket and the embedded transport.

Create travels the same way. gRPC, the Unix socket and the embedded transport
call `CreateVM` directly, QUIC `0x60`, MCP `vm_create` and SDK REST send the
full request, and the CLI builds it from its flags. A refused field is
InvalidArgument on every one of them. `TestVMCreateSDKParity_*` holds the
config, the refusal and the failed start over every transport.

Against a running daemon, `TestComputeMultiProtocol/<transport>/VMSuspendResumeReboot`
(`test/integration/compute/multiprotocol_test.go`) sends suspend, resume and
reboot over the CLI, REST, gRPC, QUIC, MCP and Unix to a VM a gRPC fixture
created and started. It checks that the VM reads `paused` after suspend and
`running` after resume and after reboot, reading the state over the same
transport. It also checks that resuming a running VM answers that
transport's wrong-state class:

| Transport | Wrong-state answer |
|---|---|
| gRPC, Unix, QUIC, MCP | FailedPrecondition (over MCP, the SDK turns the JSON-RPC code of that class back into it) |
| REST | HTTP 400 |
| CLI | non-zero exit, with `code = FailedPrecondition` in the output |

`TestComputeMultiProtocol/<transport>/VMCreateRefusesUnsupportedField` asks
each transport for a BIOS VM and checks that the refusal arrives in that
transport's class and that no VM is left behind: InvalidArgument over gRPC, the
Unix socket, QUIC and MCP, HTTP 400 over REST, and `code = InvalidArgument` in
the CLI's output.

The suite's VMs boot UEFI firmware from a blank disk, so no guest OS answers
the ACPI power button: every graceful stop runs to the end of its power-down
window, then SIGTERM ends the process, as the stop contract above says. `VMLifecycle` therefore stops
with `timeout_seconds` 1, which takes the same graceful path in one second.
The reboot in `VMSuspendResumeReboot` has no timeout field and spends the
default 30 seconds. All six transports share the test's five-minute context.
Each case's cleanup runs on its own 30-second context, so a case that failed
on that deadline still stops and deletes its VM.

The suite's MCP adapter (`test/integration/compute/mcp_adapter.go`) is the
compute SDK client over MCP, so every case — create with disks, firmware and
labels, list by label, forced stop and reboot, and delete with its disks —
runs on MCP with the same options as on gRPC.

`make integration-test-compute` runs the suite in the devcontainer against
`platformd` with the `local-qemu` provider: the runner appends
`compute: provider: local-qemu` to the integration config, because with no
`compute:` section the daemon serves the container orchestrator. No workflow
runs it; like the other per-package suites it needs the devcontainer.

`TestQEMUOrchestratorSuspendResumeReboot`
(`test/integration/compute/orchestrator_integration_test.go`) drives the same
verbs on the QEMU orchestrator directly. It checks `ErrInstanceNotRunning` and
`ErrInstanceNotSuspended` for wrong-state calls.

---

## 3. VM disks, snapshots and migration

QUIC serves these as **sub-opcodes under `OpVMExtendedCategory` (`0x69`)** — see
§6 before using the byte values.

| Capability | REST | gRPC / Unix | QUIC (under `0x69`) | MCP | Embedded |
|---|---|---|---|---|---|
| Attach disk | `POST /api/v1/compute/vms/{id}/disks` | `AttachDisk` | `OpVMAttachDisk` (`0xCD`) | `vm_disk_attach` | ✅ |
| Detach disk | `DELETE /api/v1/compute/vms/{id}/disks/{diskId}` | `DetachDisk` | `OpVMDetachDisk` (`0xCE`) | `vm_disk_detach` | ✅ |
| Resize disk | `PATCH /api/v1/compute/vms/{id}/disks/{diskId}` | `ResizeDisk` | `OpVMResizeDisk` (`0xCF`) | `vm_disk_resize` | ✅ |
| Create snapshot | `POST /api/v1/compute/vms/{id}/snapshots` | `CreateSnapshot` | `OpVMSnapshotCreate` (`0xBB`) | `vm_snapshot_create` | ✅ |
| List snapshots | `GET /api/v1/compute/vms/{id}/snapshots` | `ListSnapshots` | `OpVMSnapshotList` (`0xBE`) | `vm_snapshot_list` | ✅ |
| Get snapshot | `GET /api/v1/compute/vms/{id}/snapshots/{snapshotId}` | `GetSnapshot` | `OpVMSnapshotGet` (`0xBA`) | `vm_snapshot_get` | ✅ |
| Delete snapshot | `DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}` | `DeleteSnapshot` | `OpVMSnapshotDelete` (`0xBD`) | `vm_snapshot_delete` | ✅ |
| Restore snapshot | `POST /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore` | `RestoreSnapshot` | `OpVMSnapshotRestore` (`0xBC`) | `vm_snapshot_restore` | ✅ |
| Migrate VM | `POST /api/v1/compute/vms/{id}/migrate` | `MigrateVM` | `OpVMMigrate` (`0xD0`) | `vm_migrate` | ✅ |
| Prepare migration | `POST /api/v1/compute/migrations/prepare` | `PrepareMigration` | `OpVMPrepareMigration` (`0xD1`) | `vm_migration_prepare` | ✅ |
| Finalize migration | `POST /api/v1/compute/migrations/{receiverId}/finalize` | `FinalizeMigration` | `OpVMFinalizeMigration` (`0xD2`) | `vm_migration_finalize` | ✅ |
| VM metrics | `GET /api/v1/compute/vms/{id}/metrics` | `GetVMMetrics` | `OpVMMetrics` (`0xCC`) | `vm_metrics` | ✅ |
| VM logs | `MISSING` — streaming, §5 | `GetVMLogs` (server stream) | `MISSING` — streaming | `vm_logs` | ✅ |

The five snapshot sub-opcodes carry the RPC's request message
(`CreateSnapshotRequest`, `ListSnapshotsRequest`, `GetSnapshotRequest`,
`DeleteSnapshotRequest`, `RestoreSnapshotRequest`) and are answered by the same
`ComputeService` as gRPC (§6), with the same checks: a missing VM or snapshot
id, or a snapshot that takes memory without disk or disk without memory, is
InvalidArgument; an unknown VM or snapshot is NotFound; a VM that is not
running, or an orchestrator without snapshots, is FailedPrecondition. The
snapshot's id is its name. `GetSnapshot` answers the one entry of
`ListSnapshots` with that id (`GetSnapshotResponse.snapshot`), so it fails
exactly as `ListSnapshots` does, and an id the list does not hold is NotFound
(`ErrVMSnapshotNotFound`). `DeleteSnapshot` looks the snapshot up the same way
before it deletes: QEMU's `delvm` answers success for a name no disk holds, so
without the lookup a deleted snapshot would delete again
(`QEMUOrchestrator.DeleteSnapshot`, `pkg/compute/qemu_snapshot.go`).

The Go SDK carries the snapshot verbs over every transport, returning the
client's typed error (`ErrCreateSnapshotFailed`, ...,
`sdk/go/services/compute/errors.go`) around the transport status. Its REST
adapter maps them to the routes above, with the VM and snapshot ids in the
path and never in the body (`sdk/go/transport/rest/adapter.go`); an empty id is
InvalidArgument before the request leaves the client. Its MCP adapter maps them
to the `vm_snapshot_*` tools with the arguments in §7
(`sdk/go/transport/mcp/compute_vm.go`). Its QUIC adapter maps them to their
sub-opcodes (`sdk/go/transport/quic/adapter.go`). As with the lifecycle verbs
(§2), a VM in the wrong state is FailedPrecondition except over REST, where it
is InvalidArgument. `TestVMSnapshotSDKParity_*` and
`TestVMSnapshotAttestSDKParity_MissingVMID`
(`pkg/api/daemon/compute_sdk_snapshot_parity_test.go`) hold this over REST,
QUIC, MCP, gRPC, Unix and embedded; `TestVMSnapshotSDKParity_GetUnknownSnapshot`
holds that an unknown snapshot id is `ErrGetSnapshotFailed` around NotFound on
each. Against a running daemon, `TestComputeSnapshotsMultiProtocol`
(`test/integration/compute/multiprotocol_test.go`) creates, lists, gets,
restores and deletes a snapshot of a running VM over REST, gRPC, QUIC, MCP and
Unix, then checks that getting or deleting it again answers NotFound and that
listing without a VM id answers InvalidArgument. The CLI has no snapshot verb.

`PrepareMigration` and `FinalizeMigration` are served on REST, gRPC, QUIC, MCP
and the Unix socket and exist so a migration can be staged and confirmed;
`MigrateVM` is the one-shot form. Do not treat the pair as internal — they are
the two-phase contract. Every transport calls the same `ComputeService`
methods, so a missing `spec` or `receiver_id` is InvalidArgument, an unknown
receiver is NotFound, and an orchestrator that cannot receive a migration is
FailedPrecondition except over REST, where it is InvalidArgument (§2). The Go SDK client carries the pair as
`Client.PrepareMigration` and `Client.FinalizeMigration`, failing with
`ErrPrepareMigrationFailed` and `ErrFinalizeMigrationFailed` around the
transport status. `TestVMMigrationSDKParity_*`
(`pkg/api/daemon/compute_sdk_migration_parity_test.go`) holds this over REST,
QUIC, MCP, gRPC, Unix and embedded, and
`TestComputeMigrationMultiProtocol`
(`test/integration/compute/multiprotocol_test.go`) holds the refusals against
a running daemon.

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
| Attach to container | `MISSING` — streaming, §5 | `AttachContainer` (server stream) | `MISSING` — streaming | `MISSING` | ✅ |

Containers are the most evenly covered capability set in this feature.

---

## 5. Attestation of workloads

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Attest VM | `POST /api/v1/compute/vms/{id}/attest` | `AttestVM` | `OpVMAttest` (`0xB9`) | `vm_attest` | ✅ |
| Verify VM attestation | `POST /api/v1/compute/vms/{id}/attest/verify` | `VerifyVMAttestation` | `OpVMVerifyAttest` (`0xBF`) | `vm_attest_verify` | ✅ |
| Attest container | `POST /api/v1/compute/containers/{id}/attest` | `AttestContainer` | `OpContainerAttest` (`0xEC`) | `container_attest` | ✅ |

`platformctl container attest` is the only compute attestation CLI verb: VM
attestation has no `platformctl compute` verb. The platform's other attest
verbs (`device attest`, `device attest-cert`, `piv attest` and the
`attestation` group) are not compute verbs — see [`docs/attestation/cli.md`](../attestation/cli.md).

The two VM attestation sub-opcodes carry the RPC's request message
(`AttestVMRequest`, `VerifyVMAttestationRequest`) and are answered by the same
`ComputeService` as gRPC (§6), with the same checks: a missing VM id, a PCR
bank other than SHA-256, or evidence without its quote, signature or nonce is
InvalidArgument; an unknown VM is NotFound; a VM that is not running, has no
vTPM, or runs on an orchestrator without attestation is FailedPrecondition.

The Go SDK carries both verbs over every transport, returning the client's
typed `ErrAttestVMFailed` or `ErrVerifyVMAttestationFailed` around the
transport status. Its REST adapter maps them to the two routes above with the
VM id in the path; its MCP adapter maps them to `vm_attest` and
`vm_attest_verify` and refuses a PCR bank other than SHA-256 (§7); its QUIC
adapter maps them to their sub-opcodes. A VM in the wrong state is
FailedPrecondition except over REST, where it is InvalidArgument (§2).
`TestVMAttestSDKParity_*` (`pkg/api/daemon/compute_sdk_attest_parity_test.go`)
and `TestVMSnapshotAttestSDKParity_MissingVMID` hold this over REST, QUIC and
MCP. Against a running daemon, `TestComputeAttestationMultiProtocol`
(`test/integration/compute/multiprotocol_test.go`) checks over REST, gRPC,
QUIC, MCP and Unix that attesting a stopped VM answers the transport's
wrong-state class, attesting an unknown VM is NotFound, attesting without a VM
id is InvalidArgument, and verifying evidence without a quote is
InvalidArgument.

### A VM quote declares its signature scheme

Attest VM returns `signature_algorithm` beside `signature` on every transport:
the scheme the vTPM's attestation key signed the quote with, named as
`x509.SignatureAlgorithm` names it (`SHA256-RSA`, `SHA256-RSAPSS`,
`ECDSA-SHA256`, and the SHA-384/512 forms). It comes from the AK's key
attributes, not from its key type.

Verify VM attestation takes the same field back (REST and MCP
`signature_algorithm`, gRPC and QUIC
`VerifyVMAttestationRequest.signature_algorithm`)
and checks the signature under that scheme alone.
An absent or unknown scheme, or one the live AK cannot carry, is not a
transport error: the call succeeds with `verified` and `signature_valid` false
and the reason in `message`. A client therefore echoes Attest VM's
`signature_algorithm` unchanged.

### Streaming capabilities are transport-limited by design

`AttachVMConsole`, `SendVMConsoleInput`, `AttachContainer` and `GetVMLogs`
are gRPC streams with **no unary equivalent**. The QUIC
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
the operational sub-opcodes above and the VM verbs `OpVMCreate`–`OpVMList`
(`0x60`–`0x65`), `OpVMRestart`, `OpVMSuspend` and `OpVMResume` (`0xB6`–`0xB8`),
the snapshot verbs `OpVMSnapshotGet` (`0xBA`), `OpVMSnapshotCreate`,
`OpVMSnapshotRestore`, `OpVMSnapshotDelete` and `OpVMSnapshotList`
(`0xBB`–`0xBE`), and the
attestation verbs `OpVMAttest` (`0xB9`) and `OpVMVerifyAttest` (`0xBF`) are
answered there.
A verb's failure keeps its class: a missing id or VM config is
`StatusInvalidArgument`, an unknown VM or snapshot `StatusNotFound`, and a VM
in the wrong state `StatusFailedPrecondition`.

The top-level bytes `0x61`–`0x68` and `0x6A` are unassigned, and `0x60` is
object storage's category (#704). The flat VM
handler that once answered them was never wired into platformd and has been
removed. `0x60`–`0x65` survive only as sub-opcodes under `0x69`. Of the
sub-opcodes `0xB9`–`0xBF` that went with it, `0xBA`–`0xBE` now carry the
snapshot verbs and `0xB9` and `0xBF` the attestation verbs through
`ComputeService`. `0xBA` was the flat handler's console verb; it now means
`GetSnapshot`.

The permission guard (`AuthMiddleware.GuardRequest`, `pkg/api/quic/auth.go`)
runs before dispatch. It answers `StatusPermissionDenied` to an authenticated
request for a byte or sub-opcode it has no permission for, which now includes
the retired ones, and `StatusInvalidRequest` to `0x69` with an empty payload.
A classified sub-opcode that no handler answers gets `StatusNotImplemented`
from `handleVMServiceOperation` (`pkg/api/daemon/quic_vm.go`).

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
| `container:read` | `GetContainer`, `ListContainers`, `GetContainerMetrics`, `AttestContainer` |
| `container:write` | `CreateContainer`, `StartContainer`, `StopContainer`, `ExecContainer`, `AttachContainer` |
| `container:delete` | `DeleteContainer` |
| `vm:read` | `GetVM`, `ListVMs`, `GetVMLogs`, `GetVMMetrics`, `ListSnapshots`, `GetSnapshot`, `AttestVM`, `VerifyVMAttestation` |
| `vm:write` | `CreateVM`, `StartVM`, `StopVM`, `RebootVM`, `SuspendVM`, `ResumeVM`, `AttachDisk`, `DetachDisk`, `ResizeDisk`, `CreateSnapshot`, `RestoreSnapshot`, `MigrateVM`, `PrepareMigration`, `FinalizeMigration`, `AttachVMConsole`, `SendVMConsoleInput` |
| `vm:delete` | `DeleteVM`, `DeleteSnapshot` |

`ExecContainer` is arbitrary command execution inside a workload, so
`container:write` is the scope to guard.

**The MCP tools answer under the scope of their gRPC twin** (#304). The MCP
permission map (`pkg/api/mcp/authz.go`) holds each tool that reaches a real
backend:

| Permission | MCP tools |
|---|---|
| `container:read` | `container_get`, `container_list`, `container_metrics`, `container_attest` |
| `container:write` | `container_create`, `container_start`, `container_stop`, `container_exec` |
| `container:delete` | `container_remove` |
| `vm:read` | `vm_list`, `vm_get`, `vm_snapshot_list`, `vm_snapshot_get`, `vm_attest`, `vm_attest_verify`, `vm_metrics`, `vm_logs` |
| `vm:write` | `vm_create`, `vm_start`, `vm_stop`, `vm_reboot`, `vm_suspend`, `vm_resume`, `vm_snapshot_create`, `vm_snapshot_restore`, `vm_disk_attach`, `vm_disk_detach`, `vm_disk_resize`, `vm_migrate`, `vm_migration_prepare`, `vm_migration_finalize` |
| `vm:delete` | `vm_delete`, `vm_snapshot_delete` |

`vm_disk_detach` is `vm:write`, not `vm:delete`, because `DetachDisk` is.

The VM lifecycle and migration tools take their RPC's full request and answer its
response, both in protojson with the proto's field names
(`pkg/api/mcp/vm_lifecycle_tools.go`). Each tool calls the gRPC
`ComputeService` servicer the daemon builds over its orchestrator
(`pkg/api/daemon/mcp_vm_lifecycle.go`), so it validates and fails as gRPC does.
An unknown argument, a wrong type, an out-of-range number or an unknown enum
name is InvalidArgument before the service runs. `vm_create` takes
`{"config": {...}, "start": bool}`, `vm_list` takes `selector`, `pagination`
and `states`, `vm_migration_prepare` takes `vm_id`, `vm_name`, `mode` and `spec` (the
`VMMigrationSpec` fields), `vm_migration_finalize` takes `receiver_id` and
`commit`, and the others take `id` plus the RPC's flags.
[api-reference-mcp.md](api-reference-mcp.md) lists every argument.
`CreateVM` applies or refuses every `config` field and acts on `start`, stop
and reboot read `force` and `timeout_seconds`, and `ListVMs` reads `states`,
`selector` and `pagination` (§2); delete ignores `delete_disks`. That holds on
every transport.

The snapshot and attestation tools answer through their RPC the same way
(`pkg/api/daemon/mcp_vm.go`), so each reply is the RPC's response in the
proto's field names. Since #704 this replaces the tools' earlier hand-built
maps: `vm_snapshot_list` returns `ListSnapshotsResponse` with no `count`,
`vm_snapshot_get` returns `GetSnapshotResponse`, whose `snapshot` holds the
entry it once returned bare, and `vm_attest` returns `AttestVMResponse`, whose `pcr_values` is a list of
`{index, bank, value}` entries with base64 values rather than a map of index
to hex. The arguments map onto the request:

| Tool | Arguments | RPC request |
|---|---|---|
| `vm_snapshot_create` | `vm_id`, `name`, `description`, `memory_snapshot`, `disk_snapshot` | `CreateSnapshotRequest` (`config`); the two flags must be equal |
| `vm_snapshot_list` | `vm_id` | `ListSnapshotsRequest` |
| `vm_snapshot_get`, `vm_snapshot_delete`, `vm_snapshot_restore` | `vm_id`, `snapshot_id` | `GetSnapshotRequest`, `DeleteSnapshotRequest`, `RestoreSnapshotRequest` |
| `vm_attest` | `vm_id`, `nonce` (base64), `include_pcrs` | `AttestVMRequest`, SHA-256 bank |
| `vm_attest_verify` | `vm_id`, `quote`, `signature`, `nonce` (base64), `signature_algorithm`, `expected_pcrs` (index → base64 SHA-256) | `VerifyVMAttestationRequest`, SHA-256 bank |

No tool takes a PCR bank, so the SDK's MCP adapter refuses an `AttestVM` or
`VerifyVMAttestation` request naming another bank with InvalidArgument rather
than send it as SHA-256 (`sdk/go/transport/mcp/compute_vm.go`).

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

`vm_snapshot_get`'s twin is `GetSnapshot` (#704), which reads one entry of
what `ListSnapshots` returns and takes the same `vm:read`. #304 deleted
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
| `0x0C` | `StatusFailedPrecondition` | 409 | VM in the wrong state for the verb |

**501 means the binary was built without the provider's build tag** (`awscompute`,
`azurecompute`, `gcpcompute`) — not that the feature is unfinished.

Quota rejection comes from tenancy ([`docs/tenant/`](../tenant/)), which checks
capacity before allocation.

---

## 9. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated in the
compute surface as of 2026-08-18.
