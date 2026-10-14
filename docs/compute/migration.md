# VM Migration

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on cold and live VM migration: modes, transport security and the inter-daemon handshake.

Live and cold VM migration move a running guest from one `platformd` (the
**source**) to a peer `platformd` (the **destination**) over a mutually
authenticated, CA-secured channel. Migration is available only on the local
QEMU/KVM provider (`compute.provider: local-qemu`); container and cloud
providers reject the operation with a typed capability error.

## Modes

| Mode | Shared storage | What streams | Guest downtime |
|------|----------------|--------------|----------------|
| **Cold** (default) | Not required | Guest RAM **and** block devices | Guest is paused for the transfer |
| **Live** | **Required** | Guest RAM only (disks are already reachable) | Near-zero |

Cold migration always works because QEMU copies the disks alongside RAM. Live
migration only streams RAM, so it is gated on an explicit shared-storage
declaration; requesting it without shared storage fails with a typed error
rather than silently degrading:

```yaml
compute:
  provider: local-qemu
  shared_storage:
    enabled: true          # gates live migration
    backend: nfs           # informational
    mount_path: /vms       # informational
```

- `shared_storage.enabled: false` (or omitted) → only cold migration is
  offered; a live request returns `FAILED_PRECONDITION`
  (`live migration requires shared storage to be configured`).

## Transport security

Every migration stream is TLS-encrypted and mutually authenticated against the
**shared platform CA** — there is no plaintext path and `InsecureSkipVerify` is
never used anywhere in the flow. Two distinct trust legs are involved:

1. **Control plane (inter-daemon handshake)** — the source dials the
   destination daemon's gRPC endpoint using an mTLS client certificate issued
   on demand from the platform CA (`ClientAuth` EKU, one-day validity). The
   destination's server certificate is validated against the CA bundle. Both
   daemons already share the platform CA as their trust root.

2. **Data plane (QEMU migration stream)** — the guest bytes travel over QEMU's
   `tls-creds-x509` channel:
   - The **destination** issues a short-lived **server** certificate for its
     hostname (`ServerAuth` EKU) and launches the receiving QEMU with
     `-object tls-creds-x509,endpoint=server,verify-peer=on`.
   - The **source** issues a short-lived **client** certificate (`ClientAuth`
     EKU), installs it on the running guest's QMP monitor as
     `tls-creds-x509,endpoint=client,verify-peer=on`, and pins the
     destination hostname via `migrate-set-parameters tls-hostname`.

All migration certificates are ephemeral (one-day validity) and issued through
the QuicBaaS SDK CA surface — the same platform CA that issues the daemon's own
TLS identity and vTPM EK certificates.

## Inter-daemon handshake

The destination side of a migration is exposed as two RPCs on the
`ComputeService`, served on the same gRPC TCP and Unix-socket listeners as every
other compute method:

```protobuf
// Inter-daemon migration handshake (destination side)
rpc PrepareMigration(PrepareMigrationRequest) returns (PrepareMigrationResponse);
rpc FinalizeMigration(FinalizeMigrationRequest) returns (FinalizeMigrationResponse);
```

```protobuf
message VMMigrationSpec {
  int32  memory_mb    = 1;
  int32  cpus         = 2;
  string disk_size    = 3;
  string boot_mode    = 4;
  bool   secure_boot  = 5;
  bool   enable_kvm   = 6;
  bool   tpm_enabled  = 7;
  string network_mode = 8;
  string mac_address  = 9;
}

message PrepareMigrationRequest {
  string vm_id   = 1;   // source instance id (informational)
  string vm_name = 2;   // guest name
  string mode    = 3;   // "cold" | "live"
  VMMigrationSpec spec = 4;
}

message PrepareMigrationResponse {
  Status status       = 1;
  string receiver_id  = 2;   // token returned to FinalizeMigration
  int32  port         = 3;   // TCP port the receiver listens on
  string tls_hostname = 4;   // hostname the source pins in migration tls-creds
}

message FinalizeMigrationRequest {
  string receiver_id = 1;
  bool   commit      = 2;    // true = register/resume received VM, false = abort
}

message FinalizeMigrationResponse {
  Status status = 1;
}
```

### Flow

```
Source platformd                         Destination platformd
----------------                         ---------------------
MigrateVM(vm, dest:port, {live?})
  │
  ├── PrepareMigration (mTLS gRPC) ─────▶ materialize server tls-creds (CA)
  │                                       launch receiver QEMU:
  │                                         -incoming defer
  │                                         -object tls-creds-x509,endpoint=server
  │                                       QMP: migrate-set-parameters tls-creds
  │                                       QMP: migrate-incoming tcp:LISTEN:PORT
  │   ◀── {receiver_id, port, tls_hostname}
  │
  ├── install client tls-creds on source QMP monitor (CA-issued)
  ├── migrate-set-parameters {tls-creds, tls-hostname=dest}
  ├── (cold only) pause guest + enable "block" capability
  ├── migrate tcp:dest:PORT ─────────────▶ receiving QEMU accepts TLS stream
  ├── poll query-migrate until completed
  │
  ├── FinalizeMigration{commit=true} ───▶ QMP: cont (resume received guest)
  │   ◀── {success}
  │
  └── quit source QEMU, drop local bookkeeping
```

On any failure the source calls `FinalizeMigration{commit=false}`, the
destination tears the idle receiver down and releases its TLS material, and the
source rolls back (cancel migration, resume a cold-paused guest). The receiver
token correlates the two calls; it is retained by the source coordinator keyed
by `(destination, source-instance)` and never leaks into the orchestrator.

## Triggering a migration

`MigrateVM` addresses the destination by the **host:port of its daemon gRPC
endpoint**:

```
rpc MigrateVM(MigrateVMRequest) returns (MigrateVMResponse);

message MigrateVMRequest {
  string vm_id                 = 1;
  string destination_host      = 2;  // dest daemon gRPC host:port
  bool   live_migration        = 3;  // requires shared storage
  uint64 bandwidth_limit_mbps  = 4;  // 0 = unlimited
}
```

The source combines `destination_host` with the receiver `port` returned by
`PrepareMigration` to form the QEMU migrate URI (`tcp:<host>:<port>`).

The destination's receiver binds `compute.migration_listen_address` (`LISTEN`
and `PORT` in the flow above). By default that is `0.0.0.0:0`: every address,
with an ephemeral port per receiver. Set it to the migration network's address
to keep the stream on that network, and give it a fixed port when a firewall
needs one ([Configuration](engineering.md#4-configuration)).

## Error semantics

| Condition | gRPC status |
|-----------|-------------|
| Live migration without shared storage | `FAILED_PRECONDITION` |
| Migration coordinator / TLS provider not wired (no CA) | `FAILED_PRECONDITION` |
| Empty destination / VM id / receiver id / spec | `INVALID_ARGUMENT` |
| Orchestrator does not support VM migration | `FAILED_PRECONDITION` |
| Unknown receiver on finalize | `NOT_FOUND` |
| Receiver launch / stream failure | `INTERNAL` |
| Destination `compute.migration_listen_address` unset or not an `IP:port` (`MigrationListenAddressError`) | `FAILED_PRECONDITION` |

When the platform CA is available (the daemon has provisioned its TLS identity)
the migration coordinator and TLS provider are wired automatically for the
`local-qemu` provider; no additional operator configuration is required beyond
the optional `shared_storage` block and `migration_listen_address`.

## See Also

- [API](api.md) — full ComputeService surface
- [Engineering](engineering.md) — `compute.shared_storage` and the migration invariants
- [Architecture](architecture.md) — orchestrator internals
