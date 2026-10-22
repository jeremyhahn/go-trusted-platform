# Compute MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The compute MCP tools, their arguments and error codes.

Endpoint: `https://localhost:9445/mcp`

## Overview

The compute MCP tools manage VMs and containers. The VM lifecycle tools are
the gRPC `ComputeService` RPCs; the other VM tools and the container tools take
the arguments listed below. The permission each tool needs is in
[api.md](api.md) §7. A tool's result is a `CallToolResult` whose text block
holds the tool's JSON output ([daemon api.md](../daemon/api.md) §1 "MCP tool
results").

## VM lifecycle tools

Each VM lifecycle tool takes its gRPC request as its arguments and returns its
gRPC response as its result, both in protojson form
(`pkg/api/mcp/vm_lifecycle_tools.go`):

- field names are the proto names (`size_mb`, `delete_disks`);
- enums are their names (`FIRMWARE_TYPE_UEFI`, `VM_STATE_RUNNING`);
- 64-bit integers are JSON strings in results and a number or a string in
  arguments;
- `bytes` fields are base64.

The tool calls the gRPC `ComputeService` servicer, so it validates, answers
and fails as gRPC does. An unknown argument, a wrong type, a number out of
range or an unknown enum name answers invalid argument (`-32602`) before the
service runs.

| Tool | gRPC method | Required |
|------|-------------|----------|
| `vm_create` | `CreateVM` | `config` |
| `vm_list` | `ListVMs` | — |
| `vm_get` | `GetVM` | `id` |
| `vm_delete` | `DeleteVM` | `id` |
| `vm_start` | `StartVM` | `id` |
| `vm_stop` | `StopVM` | `id` |
| `vm_reboot` | `RebootVM` | `id` |
| `vm_suspend` | `SuspendVM` | `id` |
| `vm_resume` | `ResumeVM` | `id` |

`vm_start`, `vm_stop`, `vm_reboot`, `vm_suspend`, `vm_resume` and `vm_delete`
return `{"status": {"success": true, "message": "..."}}`. `vm_create` returns
`{"status": ..., "vm": VM}` and `vm_get` returns `{"vm": VM}`, where `VM` is
`{"id", "config", "state", "created_at", "updated_at", "host_id", "metrics"}`.

### vm_create

```json
{
  "name": "vm_create",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config": {"type": "object"},
      "start": {"type": "boolean"}
    },
    "required": ["config"]
  }
}
```

`config` is a `VMConfig`:

| Field | Type |
|-------|------|
| `name` | string (required by the service) |
| `description` | string |
| `firmware` | `FIRMWARE_TYPE_UNSPECIFIED` (boots UEFI), `FIRMWARE_TYPE_UEFI`, `FIRMWARE_TYPE_UEFI_SECURE_BOOT`; `FIRMWARE_TYPE_BIOS` is refused |
| `boot_device` | `BOOT_DEVICE_UNSPECIFIED`, `BOOT_DEVICE_DISK`, `BOOT_DEVICE_CDROM`, `BOOT_DEVICE_NETWORK` |
| `cpu` | `{"cores", "sockets", "threads", "model", "features": [string]}` |
| `memory` | `{"size_mb", "hugepages", "shared"}` |
| `disks` | `[{"id", "path", "type", "bus", "size_gb", "readonly", "bootable", "backing_file"}]`; `type` is `DISK_TYPE_*`, `bus` is `DISK_BUS_*` |
| `networks` | `[{"id", "bridge", "mac_address", "model", "vlan", "bandwidth_limit_mbps"}]`; `model` is `NETWORK_MODEL_*` |
| `graphics` | `{"type", "listen", "port", "password", "keymap"}`; `type` is `GRAPHICS_TYPE_*` |
| `tpm` | `{"enabled", "version", "device_path", "emulated", "state_dir"}`; `version` is `TPM_VERSION_1_2` or `TPM_VERSION_2_0` |
| `secure_boot` | boolean |
| `nvram` | base64 |
| `labels`, `metadata` | object of strings |

```json
{
  "config": {
    "name": "web-1",
    "firmware": "FIRMWARE_TYPE_UEFI",
    "cpu": {"cores": 2},
    "memory": {"size_mb": "2048"},
    "disks": [{"size_gb": "20"}],
    "tpm": {"enabled": true, "version": "TPM_VERSION_2_0"},
    "secure_boot": true,
    "labels": {"tier": "web"}
  },
  "start": true
}
```

The service applies each field the backend can honour and refuses the rest
with InvalidArgument naming the field (`config.firmware is not supported: ...`),
before anything is created. On `local-qemu` it refuses, among others,
`FIRMWARE_TYPE_BIOS`, `BOOT_DEVICE_CDROM`, a disk or NIC `id`, a second disk
or NIC, and any `graphics`; [api.md §2](api.md#2-vm-lifecycle) lists every
field. With `start`, a VM that fails to start is deleted and the tool fails
with the start error. The same holds on every transport.

### vm_list

```json
{
  "name": "vm_list",
  "inputSchema": {
    "type": "object",
    "properties": {
      "selector": {"type": "object"},
      "pagination": {"type": "object"},
      "states": {"type": "array", "items": {"type": "string", "enum": ["VM_STATE_UNSPECIFIED", "VM_STATE_STOPPED", "VM_STATE_STARTING", "VM_STATE_RUNNING", "VM_STATE_PAUSED", "VM_STATE_STOPPING", "VM_STATE_REBOOTING", "VM_STATE_MIGRATING", "VM_STATE_ERROR"]}}
    }
  }
}
```

`selector` is `{"match_labels": {string: string}, "match_expressions":
[string]}` and `pagination` is `{"page", "page_size", "sort_by",
"ascending"}`. The result is `{"vms": [VM], "pagination": {...}}`. The
service keeps the VMs in any listed state that carry every `match_labels`
pair, sorts by `sort_by` (`id`, `name` or `created_at`) and pages, as on every
transport ([api.md §2](api.md#2-vm-lifecycle)). An unknown state, any
`match_expressions` entry or another `sort_by` is InvalidArgument.

### vm_get, vm_start, vm_suspend, vm_resume

```json
{
  "name": "vm_get",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "string"}
    },
    "required": ["id"]
  }
}
```

`vm_start`, `vm_suspend` and `vm_resume` take the same `id` argument.

### vm_stop

```json
{
  "name": "vm_stop",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "string"},
      "force": {"type": "boolean"},
      "timeout_seconds": {"type": "integer"}
    },
    "required": ["id"]
  }
}
```

### vm_reboot

```json
{
  "name": "vm_reboot",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "string"},
      "force": {"type": "boolean"}
    },
    "required": ["id"]
  }
}
```

### vm_delete

```json
{
  "name": "vm_delete",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "string"},
      "delete_disks": {"type": "boolean"}
    },
    "required": ["id"]
  }
}
```

`vm_stop` and `vm_reboot` honour `force` and `timeout_seconds` as `StopVM` and
`RebootVM` do ([api.md](api.md) §2): `force` with a timeout, or a timeout over
3600, is invalid argument. A graceful stop may run past the server's 30-second
`RequestTimeout`; the reply still answers, because the write deadline restarts
once the reply is ready, and the tool runs as long as the HTTP request. Over
stdio the call runs for its reply window, described next, when that is longer
than `RequestTimeout`. The Go SDK's MCP transport waits for that reply for
the stop's reply window — the guest's power-down window (`timeout_seconds`,
30 by default, none when forced) plus 30 seconds — instead of its 5-second
default request timeout ([api.md](api.md) §2). The service does not yet read `delete_disks`, on
any transport.

### vm_migration_prepare

The destination half of a staged migration (`PrepareMigration`, `vm:write`).
`spec` is a `VMMigrationSpec` describing the guest: `memory_mb` and `cpus`
(integers), `disk_size`, `boot_mode`, `network_mode`, `mac_address` and `arch`
(strings), `secure_boot`, `enable_kvm` and `tpm_enabled` (booleans). The reply
is `PrepareMigrationResponse`, whose `receiver_id`, `port` and `tls_hostname`
the source dials.

```json
{
  "name": "vm_migration_prepare",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vm_id": {"type": "string"},
      "vm_name": {"type": "string"},
      "mode": {"type": "string"},
      "spec": {"type": "object"}
    },
    "required": ["spec"]
  }
}
```

### vm_migration_finalize

Commits (`commit: true`) or discards a received migration
(`FinalizeMigration`, `vm:write`).

```json
{
  "name": "vm_migration_finalize",
  "inputSchema": {
    "type": "object",
    "properties": {
      "receiver_id": {"type": "string"},
      "commit": {"type": "boolean"}
    },
    "required": ["receiver_id"]
  }
}
```

A missing `spec` or `receiver_id` is invalid argument, an unknown receiver is
not found, and a daemon whose orchestrator cannot receive a migration answers
failed precondition, as `PrepareMigration` and `FinalizeMigration` do on gRPC.

## Other VM tools

| Tool | Required | Optional (default) |
|------|----------|--------------------|
| `vm_snapshot_create` | `vm_id`, `name` | `description`, `memory_snapshot` (false), `disk_snapshot` (false); the two flags must be equal |
| `vm_snapshot_get` | `vm_id`, `snapshot_id` | — |
| `vm_snapshot_list` | `vm_id` | — |
| `vm_snapshot_delete` | `vm_id`, `snapshot_id` | — |
| `vm_snapshot_restore` | `vm_id`, `snapshot_id` | — |
| `vm_attest` | `vm_id` | `nonce` (base64), `include_pcrs` (integer array), `include_event_log` (false) |
| `vm_attest_verify` | `vm_id`, `quote`, `signature`, `nonce` | `signature_algorithm`, `expected_pcrs` (object, PCR index → base64) |
| `vm_metrics` | `vm_id` | — |
| `vm_disk_attach` | `vm_id`, `path` | `disk_id`, `bus`, `size_gb`, `readonly` (false) |
| `vm_disk_detach` | `vm_id`, `disk_id` | — |
| `vm_disk_resize` | `vm_id`, `disk_id`, `new_size_gb` | — |
| `vm_logs` | `vm_id` | `tail_lines` (100) |
| `vm_migrate` | `vm_id`, `destination_host` | `live` (false), `bandwidth_mbps` |

## Container tools

| Tool | Required | Optional (default) |
|------|----------|--------------------|
| `container_create` | `name`, `image` | `command`, `args` (string arrays), `env`, `labels` (objects), `working_dir`, `user`, `privileged` (false), `mounts` (`[{"source", "target", "read_only", "type"}]`), `ports` (`[{"container_port", "host_port", "host_ip", "protocol"}]`), `resources` (`{"cpu_limit", "memory_limit", "pids_limit"}`) |
| `container_start` | `id` | — |
| `container_stop` | `id` | `timeout` (10) |
| `container_remove` | `id` | `force` (false) |
| `container_get` | `id` | — |
| `container_list` | — | `all` (false), `filters` (object), `limit` (50) |
| `container_logs` | `id` | `stdout` (true), `stderr` (true), `tail` ("100"), `timestamps` (false) |
| `container_exec` | `id`, `command` | `env` (object), `working_dir`, `tty` (false) |
| `container_metrics` | `id` | — |
| `container_attest` | `id` | — |

## Error Handling

MCP errors follow JSON-RPC 2.0. A failed tool call answers the code for its
error class (#505); the message is the error text and `data` names the tool:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "the arguments are not a platform.v1.GetVMRequest: proto: (line 1:2): unknown field \"vm_id\"",
    "data": "vm_get"
  }
}
```

| Code | Description |
|------|-------------|
| -32602 | Invalid argument (also an unknown tool) |
| -32601 | Unimplemented (a container capability the runtime lacks) |
| -32001 / -32002 / -32003 | Authentication required / invalid token / permission denied |
| -32004 | Service unavailable (no compute backend wired) |
| -32005 | Not found |
| -32006 | Already exists |
| -32007 | Failed precondition (the VM lifecycle tools with no compute orchestrator) |
| -32603 | Unclassified failure |

The classification rules are in [`docs/daemon/api.md`](../daemon/api.md) §1.

See [api.md](api.md) for the compute transport matrix.
