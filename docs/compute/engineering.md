# Compute — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/compute/`, `pkg/qemu/`, `pkg/swtpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

| Piece | Files / dirs |
|---|---|
| Orchestration | `orchestrator.go`, `provider.go`, `provider_vm.go`, `lifecycle.go` |
| Placement | `placement.go` |
| Port authentication | `port_auth.go` |
| QEMU/KVM VM backend | `qemu.go`, `qemu_disk.go`, `qemu_snapshot.go`, `qemu_migrate.go`, `qemu_console.go`, `qemu_logs.go`, `qemu_metrics.go`, `qemu_attest.go`, `register_qemu.go` |
| VM operations | `vm_capabilities.go`, `vm_ops_capabilities.go`, `vm_migrate.go`, `vm_receive.go`, `vm_ops_errors.go` |
| Containers | `container/`, `podman/` |
| Networking | `network/` |
| Network boot | `pxe/` |
| Cloud providers | `aws/`, `azure/`, `gcp/` — **all build-tag gated** |
| Configuration | `config.go`, `types.go` |

## 2. Exported surface

```go
type Orchestrator interface        // the provider-agnostic contract
func NewOrchestratorForConfig(ctx context.Context, cfg *OrchestratorConfig, deps *Deps) (Orchestrator, error)
func NewLifecycleManager() *LifecycleManager
```

Types: `Instance`, `InstanceConfig`, `InstanceFilter`, `DiskInfo`,
`NetworkAttachment`, `PlaceVNICConfig`, `VNICPlacement`, `PortAuthConfig`,
`Deps`.

`NewOrchestratorForConfig` takes explicit `*Deps` rather than reaching for
globals — that is the injection point for storage, networking and attestation
in tests.

## 3. Cloud providers are compiled out by default

AWS, Azure and GCP support is behind build tags: `awscompute`, `azurecompute`,
`gcpcompute`, each with a `!tag` stub file. Roughly ten files per provider are
tagged in, one tagged out.

`ErrComputeProviderNotCompiled` is what a caller gets when it asks for a
provider the binary was not built with. **This is a first-class error, not a
panic**: a default build genuinely cannot create an AWS instance, and it says
so.

Cloud integration tests carry compound tags —
`cloud_integration && awscompute`, and one `floci_integration && awscompute`.
They do not run in an ordinary `make test`.

**Check the build tags before concluding a cloud path is broken.** The usual
cause of "the AWS provider does nothing" is a binary built without
`-tags awscompute`.

## 4. Configuration

`pkg/compute/config.go`. Keys use **snake_case with underscores**, unlike
attestation and SDN which use hyphens. Do not carry a hyphenated key over from
another feature.

**Local virtualization:**

| Key | Meaning |
|---|---|
| `enabled` | Compute on/off |
| `type` | Provider selection |
| `work_dir` | Where VM state lives |
| `enable_kvm` | Hardware acceleration |
| `default_cpus`, `default_memory`, `default_disk_size` | Defaults for a new VM |
| `max_instances` | Ceiling on instances |
| `auto_cleanup` | Reap stopped instances |
| `debug` | Verbose backend logging |

**Networking:**

| Key | Meaning |
|---|---|
| `network_bridge` | Bridge new VNICs attach to |
| `ovs_socket_path` | OVS control socket |
| `port_auth_enabled` | **Whether a VM's port must authenticate** |

**`port_auth_enabled` is the setting that ties compute to port authentication.**
With it on, a VM's virtual port goes through the same IDevID port-authentication
state machine as a physical device ([`docs/sdn/`](../sdn/)). With it off, VMs get
network access without proving anything.

**Cloud (only meaningful with the matching build tag):** `ami_id`,
`instance_type`, `region` (AWS); `vm_size`, `resource_group`, `location`,
`subscription_id`, `image_reference` (Azure); `machine_type`, `project_id`,
`zone`, `source_image` (GCP).

`zone` appears in the GCP block and **is not** the platform's network zone. Two
different concepts, one key name.

## 5. Invariants

1. **A VM with a vTPM gets its own virtual TPM instance.** `--tpm` on create
   provisions one through `pkg/vtpm` / `pkg/swtpm`
   ([`docs/vtpm/`](../vtpm/)); it is not shared with the host TPM.
2. **Secure Boot requires UEFI firmware.** `--firmware` accepts `bios`, `uefi`
   and `uefi-secure-boot`; `--secure-boot` is meaningless with `bios`.
3. **Attestation of a VM requires the host to have attested first.** The
   ordering is enforced in `pkg/attestation` — see
   [`docs/attestation/`](../attestation/).
4. **Migration is two-phase.** `PrepareMigration` and `FinalizeMigration` exist
   alongside `MigrateVM` precisely so a migration can be staged and confirmed;
   `vm_receive.go` is the receiving side.
5. **Live migration requires shared storage.** The CLI says so on `--live`; the
   backend cannot copy a disk it does not share.
6. **Placement decides where, port auth decides whether.** `placement.go` picks
   a host; `port_auth.go` decides whether the resulting VNIC is allowed on the
   network. Both must succeed.
7. **`ErrNoNetworkInZone`** means placement found no network in the requested
   zone — a configuration gap in the zone graph, not a capacity problem.

## 6. Streaming operations are transport-limited

Four gRPC RPCs stream and have **no non-streaming equivalent**:

- `AttachVMConsole` → `stream ConsoleOutput`
- `SendVMConsoleInput` → client-streaming
- `GetVMLogs` → `stream LogEntry`
- `AttachContainer` → `stream ConsoleOutput`
- `GetContainerLogs` → `stream LogEntry`

The QUIC layer's own comment records the consequence: *"interactive console and
log-follow remain streaming-only and daemon-native"*
(`sdk/go/wire/quicwire/vm_ops_opcodes.go`). A console session is not available over
REST or MCP, and will not be — it is not a gap to close by adding a route.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/compute/*_test.go` | Config validation, placement, port auth, lifecycle, QEMU argument construction |
| Example | `example_swtpm_test.go` | Documented swtpm wiring |
| Integration | `test/integration/compute/`, `test/integration/container/`, `test/integration/compute-aws/` | Real VMs and containers |

`pkg/compute/podman` is one of the package trees `make test` excludes because it
needs a container runtime; it is covered by `make integration-test`.

Cloud integration tests need both `cloud_integration` and the provider tag.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`GetVMMetrics` and `GetContainerMetrics` are unary; `GetVMLogs` and
`GetContainerLogs` stream. `qemu_metrics.go` and `qemu_logs.go` are the QEMU-side
implementations.

VM attestation results are observable through the attestation feature's event
surface, not through compute.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/vtpm/`](../vtpm/) — the virtual TPM a `--tpm` VM gets
- [`docs/attestation/`](../attestation/) — VM and container attestation
- [`docs/sdn/`](../sdn/) — the port authentication a VNIC goes through
- [`docs/tenant/`](../tenant/) — the quota a VM is admitted against
- [`docs/registry/`](../registry/) — where container images come from
- Deep dives carried over and not re-verified in this pass:
  [container-orchestrator.md](container-orchestrator.md),
  [embedded-podman.md](embedded-podman.md),
  [swtpm-integration.md](swtpm-integration.md),
  [cloud-providers.md](cloud-providers.md), [migration.md](migration.md),
  [network-auth.md](network-auth.md),
  [802.1X-network-attachment.md](802.1X-network-attachment.md),
  [pxe-provisioning.md](pxe-provisioning.md), [testing.md](testing.md)
