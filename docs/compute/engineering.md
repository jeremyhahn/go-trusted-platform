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

**Guest architecture and firmware (local QEMU):**

| Key | Meaning |
|---|---|
| `arch` | Guest architecture: `x86_64` or `aarch64` |
| `qemu_binary` | QEMU system emulator |
| `ovmf_code` | UEFI firmware code: OVMF on x86_64, AAVMF on aarch64 |
| `ovmf_code_secure` | UEFI firmware code for a Secure Boot VM |
| `ovmf_vars` | UEFI vars template, copied once per instance |

An unset `arch` follows the host: `amd64` runs `x86_64` guests and `arm64` runs
`aarch64` guests. On any other host, `ApplyLocalQEMUDefaults` returns
`ErrUnsupportedHostArch` at config load unless `arch` is set. `Validate` refuses
a local VM config without a known `arch` (`ErrInvalidConfiguration`). Nothing
falls back to x86_64.

The other four keys default per `arch`. An unset key takes the default; a set
key is never replaced. A configured `arch` picks its own defaults, so
`arch: aarch64` on an amd64 host gets AAVMF and runs without KVM.

| Key | `x86_64` default | `aarch64` default |
|---|---|---|
| `qemu_binary` | `qemu-system-x86_64` | `qemu-system-aarch64` |
| `ovmf_code` | `/usr/share/OVMF/OVMF_CODE_4M.fd` | `/usr/share/AAVMF/AAVMF_CODE.fd` |
| `ovmf_code_secure` | `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` | `/usr/share/AAVMF/AAVMF_CODE.fd` |
| `ovmf_vars` | `/usr/share/OVMF/OVMF_VARS_4M.fd` | `/usr/share/AAVMF/AAVMF_VARS.fd` |

The aarch64 defaults are the Alpine `aavmf` package's paths. AAVMF ships one
code image, so it is also the Secure Boot code default.

Every compute VM boots UEFI from pflash on both architectures:

- unit 0 is the code, read-only;
- unit 1 is the instance's own vars copy at `<work_dir>/<instance>/nvram/OVMF_VARS.fd`.

The disk is qcow2 on both, because snapshots and migration need it.

| | `x86_64` | `aarch64` |
|---|---|---|
| Machine | `q35` (`q35,smm=on` with Secure Boot) | `virt,gic-version=host` under KVM (the host's GIC: GICv2 on a Raspberry Pi 4), `virt,gic-version=3` without |
| CPU | `host` | `host` under KVM, `cortex-a72` without |
| KVM | on an amd64 host | on an arm64 host |
| vTPM device | `tpm-tis` | `tpm-tis-device` |
| Secure Boot pflash | `cfi.pflash01` `secure=on` global | none: `virt` has no SMM |

`pkg/qemu` builds the command line (`arch.go`). `qemu.Config.HostArch` injects
the host for tests; empty means the build host. An aarch64 `qemu.Config` with a
`Firmware` image instead boots U-Boot with `-bios`. That is the
`pkg/diskimage/qemuvirt` path, and compute never takes it.

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
   `vm_receive.go` is the receiving side. The receiver binds
   `compute.migration_listen_address` (defaults layer `0.0.0.0:0`, port 0 =
   ephemeral per receiver). An empty or non-`IP:port` value refuses the
   receiver with `MigrationListenAddressError` (`FAILED_PRECONDITION`); no
   address is assumed ([Configuration](#4-configuration)).
5. **Live migration requires shared storage.** The CLI says so on `--live`; the
   backend cannot copy a disk it does not share. `compute.shared_storage`
   reaches the orchestrator through `applyLocalQEMUSettings`
   (`pkg/daemon/commands/serve.go`).
6. **Placement decides where, port auth decides whether.** `placement.go` picks
   a host; `port_auth.go` decides whether the resulting VNIC is allowed on the
   network. Both must succeed.
7. **`ErrNoNetworkInZone`** means placement found no network in the requested
   zone — a configuration gap in the zone graph, not a capacity problem.
8. **The fleet container attestor fails closed.** `container.FleetContainerAttestor`
   (`fleet_attestor.go`) serves the go-quicbaas `WithContainerAttestor` seam.
   - **Before any quote, it refuses:**
     - a trust level that does not use the host TPM;
     - a device other than this host's own record;
     - a device that is not activated or attested;
     - a profile with no usable golden baseline;
     - a request PCR value that contradicts the baseline.
   - **The baseline is checked on its own first.** The upstream check reports
     only the lowest-numbered mismatch, so a lower PCR added by the request
     could hide drift in a baseline PCR. The attestor quotes the baseline set
     alone, then quotes again with the request's extra PCRs only if it added
     any.
   - **When a quote does not match:**
     - a baseline PCR that differs from the quote is host drift
       (`ErrFleetHostDrift`). The attestor:
       1. records a cryptographic failure verdict, so the SDN quarantine
          observer isolates the host's port when SDN is wired;
       2. moves the device record to quarantined itself, so the host is
          contained without SDN or without a `NetworkPortID`. A device the
          observer already contained, or one suspended or revoked, is left
          as it is;
       3. asks the collector to re-attest the host.

       A step that fails does not stop the next one. Each failure is
       reported on the drift error (`VerdictErr`, `QuarantineErr` as
       `ErrFleetQuarantineFailed`, `ReattestErr`): a quarantine that did not
       happen is never reported as done;
     - a PCR that only the request supplied is a policy mismatch, not drift.
   - **Missing evidence is refused, never quarantined.** Evidence is missing
     when there is no quote, no measurement or no TPM.
   - **A pass records nothing.** The collector's scheduled quote remains the
     authority on the host's own verdict.

   `platformd` installs the attestor only when all of these exist:
   - `attestation.reporting.enabled`, which provides the control plane's own
     device record;
   - the device and profile services;
   - the attestation service;
   - a host TPM;
   - a container runtime binary.

   Without them, `AttestContainer` returns
   `ErrContainerAttestorNotAvailable`.
9. **A VM quote is verified under the scheme it declares.** `AttestVM` stamps
   `VMAttestationReport.SignatureAlgorithm` from the vTPM AK's key attributes
   (`VMAttestorDevice.GetAIKSignatureAlgorithm`); `VerifyVMAttestation` passes
   `VMAttestationEvidence.SignatureAlgorithm` to
   `vm.VerifyQuoteSignatureWithAlgorithm`, the one quote verifier
   ([`docs/attestation/engineering.md`](../attestation/engineering.md)
   invariant 12). The scheme is never inferred from the AK key type, so an
   RSA-PSS AK verifies and an absent, unknown or mismatched scheme fails.
   The container host-IAK path holds the same rule: `HostTPMProvider.VerifyQuote`
   takes the scheme from the IAK's key attributes (`vm.QuoteSignatureAlgorithm`),
   because the evidence type is the SDK's `orchestration.ContainerAttestation`
   and the verifier owns the IAK that signed it.

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
- Deep dives, checked against the code 2026-10-13 (the ARCHIVE pxe-provisioning.md is deleted):
  [container-orchestrator.md](container-orchestrator.md),
  [embedded-podman.md](embedded-podman.md),
  [swtpm-integration.md](swtpm-integration.md),
  [cloud-providers.md](cloud-providers.md), [migration.md](migration.md),
  [network-auth.md](network-auth.md),
  [802.1X-network-attachment.md](802.1X-network-attachment.md),
  [testing.md](testing.md)
