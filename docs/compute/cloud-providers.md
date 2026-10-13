# Cloud Compute Providers

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on the cloud compute providers, their build tags and the vTPM target resolution.

The compute module launches and manages TPM-enabled instances across local
and cloud backends behind a single `Orchestrator` interface. Cloud providers
are conditionally compiled behind build tags so the default binary stays lean
and free of cloud SDKs; an operator opts a provider in at build time and
selects it at run time via configuration.

- **Local providers** (always compiled): QEMU/KVM virtual machines with a
  per-VM `swtpm` vTPM, and OCI containers via the consolidated container
  orchestrator.
- **Cloud providers** (tag-gated), all implemented against the same factory:
  AWS EC2 **NitroTPM 2.0**, GCP **Shielded VM** (vTPM), and Azure **Trusted
  Launch** (vTPM).

## Architecture: the provider factory

Provider selection is unified through a registry in `pkg/compute`:

```
pkg/compute/provider.go
  ProviderKind                      // "local-qemu" | "local-container" | "aws" | "gcp" | "azure"
  OrchestratorFactory               // func(ctx, *OrchestratorConfig, *Deps) (Orchestrator, error)
  RegisterOrchestrator(kind, fac)   // called from package init()s
  NewOrchestratorForConfig(...)     // resolver — fails closed
  ErrComputeProviderNotCompiled     // typed fail-closed error
```

Each backend registers a factory in an `init()`:

| Provider          | Registered from                              | Compiled |
|-------------------|----------------------------------------------|----------|
| `local-qemu`      | `pkg/compute/register_qemu.go`               | always   |
| `local-container` | `pkg/compute/container/register.go`          | always   |
| `aws`             | `pkg/compute/aws/register_awscompute.go`     | `awscompute` tag |
| `gcp`             | `pkg/compute/gcp/register_gcpcompute.go`     | `gcpcompute` tag |
| `azure`           | `pkg/compute/azure/register_azurecompute.go` | `azurecompute` tag |

`NewOrchestratorForConfig` normalizes the configured `provider:` (an empty
value defaults to `local-container`, preserving historical behavior), looks up
the factory, and **fails closed** with `ErrComputeProviderNotCompiled` when
the named provider's build tag was not compiled into the binary. An operator
can never silently get a different backend than they asked for.

The daemon wires this in `cmd/platformd` → `pkg/daemon/commands/serve.go`
(`newComputeOrchestrator`), passing shared `Deps` (logger, host TPM).

### Conditional compilation (stub / no-stub pattern)

Mirroring the go-xkms backend convention, the AWS package carries a tagged
implementation and a negated stub:

- `//go:build awscompute` — the real `AWSOrchestrator`, its `New` factory, and
  the `init()` that registers `ProviderAWS`.
- `//go:build !awscompute` — `stub.go` keeps the package buildable for
  `go build ./...` without the tag and exposes `New` returning the typed
  `ErrProviderNotCompiled`. It never registers a factory, so the resolver
  fails closed.

The daemon blank-imports `pkg/compute/aws` from a tagged file
(`register_awscompute.go`); without the tag the AWS SDK is never linked.

## Build-tag and Makefile usage

The cloud gates mirror the `WITH_AWS` / `WITH_GCP` / `WITH_AZURE` grouping used
across the workspace (go-objstore, go-xkms). Local compute is **always
compiled** — there is no `computelocal` gate — so the default build is never at
risk.

| Make variable        | Default | Build tag       |
|----------------------|---------|-----------------|
| `WITH_AWS_COMPUTE`   | `0`     | `awscompute`    |
| `WITH_GCP_COMPUTE`   | `0`     | `gcpcompute`    |
| `WITH_AZURE_COMPUTE` | `0`     | `azurecompute`  |

Setting the umbrella `WITH_AWS=1` expands to `WITH_AWS_KMS`,
`WITH_OBJSTORE_S3`, **and** `WITH_AWS_COMPUTE` (GCP/Azure analogously).

```bash
make build WITH_AWS=1            # KMS + S3 + EC2 NitroTPM compute
make build WITH_AWS_COMPUTE=1    # just the AWS compute orchestrator
go build -tags awscompute ./...  # direct
```

The assembled `BUILD_TAGS` flows to every `go build` target (platformd,
platformctl, gatewayd), so `awscompute` rides along automatically.

## AWS (NitroTPM) capability matrix

The AWS orchestrator provides full lifecycle parity with the local QEMU
orchestrator. Capabilities with a real EC2 primitive are implemented;
capabilities with no honest EC2 equivalent return the typed
`ErrCapabilityNotSupported` and are documented here rather than faked.

| Capability (interface method) | AWS mapping | Status |
|-------------------------------|-------------|--------|
| `Create` | `RunInstances` on a Nitro instance type from a `TpmSupport=v2.0` AMI (UEFI). AMI verified via `DescribeImages` before launch — fails closed with `ErrNitroTPMUnsupported`. | Implemented |
| `Start` / `Stop` / `Delete` | `StartInstances` / `StopInstances` / `TerminateInstances` | Implemented |
| `List` / `Get` | `DescribeInstances` (managed-tag filter; client-side `InstanceFilter`) | Implemented |
| `GetState` | `DescribeInstances` → mapped to `InstanceState` | Implemented |
| `Wait` | Polls `DescribeInstances` until stopped/terminated (ticker + `select`, no `time.Sleep`) | Implemented |
| `AttachNetwork` | `AttachNetworkInterface` (portName = ENI ID) at next device index | Implemented |
| `DetachNetwork` | `DetachNetworkInterface` (resolve attachment via `DescribeInstances`) | Implemented |
| `ActivateInstance` | 802.1X OVS port authorization — **no EC2 equivalent** | Not supported (typed) |
| `VMSnapshotter.CreateSnapshot` | `CreateSnapshot` of the instance's EBS root volume | Implemented |
| `VMSnapshotter.DeleteSnapshot` | resolve by tag → `DeleteSnapshot` | Implemented |
| `VMSnapshotter.ListSnapshots` | `DescribeSnapshots` (vm-id tag filter) | Implemented |
| `VMSnapshotter.RestoreSnapshot` | stop → detach root → `CreateVolume` from snapshot → attach → start | Implemented (disk-only; EBS has no memory snapshot) |
| `VMAttester.AttestVM` | `GetInstanceTpmEkPub` → NitroTPM EK identity | Implemented (EK identity) |
| `VMAttester.VerifyVMAttestation` | control-plane PCR-quote verification needs the in-guest AK | Not supported (typed) |

### Honestly-rejected capabilities

- **`ActivateInstance`** — 802.1X port authorization is an OVS construct. The
  nearest EC2 analogue is swapping security groups, but the OVS `PortPolicy`
  carries no security-group mapping, so the orchestrator returns
  `ErrCapabilityNotSupported` instead of silently succeeding. Manage instance
  network access with security groups at launch (`security_group_ids`).
- **`VerifyVMAttestation`** — the EC2 control plane cannot read a guest's PCRs
  or drive its attestation key. Full PCR-quote verification is performed by the
  in-guest agent + `pkg/attestation/vm` (below), not the control plane.

## NitroTPM attestation flow

AWS attestation has two honest halves:

1. **Control-plane EK identity (`AttestVM`)** — the orchestrator calls
   `GetInstanceTpmEkPub` (DER format), validates the endorsement key parses as
   a PKIX public key (the same crypto the platform VM verifier relies on), and
   returns a `VMAttestationReport` carrying the EK public key in `AKPublicKey`.
   This cryptographically proves *which NitroTPM hardware root of trust backs
   the instance* — retrievable without any in-guest agent.

2. **In-guest PCR quote** — a full PCR quote requires code running inside the
   instance. The in-guest platform agent resolves the standard TPM 2.0 device
   with `vtpm.ResolveTPMTarget` (`/dev/tpmrm0`), generates a quote, and submits
   it to the platform VM attestation verifier (`pkg/attestation/vm`), reusing
   exactly the same verifier the QEMU orchestrator uses. The AWS orchestrator
   does not reimplement any TPM crypto.

```
   control plane                         guest instance
   ─────────────                         ──────────────
   AttestVM ──GetInstanceTpmEkPub──▶ NitroTPM EK (identity)
                                         │
   pkg/attestation/vm ◀──quote────── in-guest agent (/dev/tpmrm0)
   (VerifyQuote)                        vtpm.ResolveTPMTarget
```

Disk sealing / KMS operations continue to flow through the existing awskms
path via the quicbaas SDK (`sdk/go/xkms`); the compute orchestrator adds no new
crypto.

## GCP (Shielded VM) capability matrix

The GCP orchestrator provides lifecycle parity with the local QEMU
orchestrator. Capabilities with a real Compute Engine primitive are
implemented; capabilities with no honest GCE equivalent return the typed
`ErrCapabilityNotSupported` and are documented here rather than faked.

| Capability (interface method) | GCP mapping | Status |
|-------------------------------|-------------|--------|
| `Create` | `Instances.Insert` with `ShieldedInstanceConfig{EnableVtpm, EnableIntegrityMonitoring, EnableSecureBoot}` on a UEFI Shielded VM image. The vTPM is requested explicitly at insert; GCE rejects a non-UEFI image, so the launch fails closed. | Implemented |
| `Start` / `Stop` / `Delete` | `Instances.Start` / `Instances.Stop` / `Instances.Delete` (operation waited to completion) | Implemented |
| `List` / `Get` | `Instances.List` (managed-label filter; client-side `InstanceFilter`) / `Instances.Get` | Implemented |
| `GetState` | `Instances.Get` → status string mapped to `InstanceState` | Implemented |
| `Wait` | Polls `Instances.Get` until `STOPPED`/`TERMINATED` (ticker + `select`, no `time.Sleep`) | Implemented |
| `AttachNetwork` / `DetachNetwork` | GCE network interfaces are fixed at instance creation — **no hot NIC-attach primitive** | Not supported (typed) |
| `ActivateInstance` | 802.1X OVS port authorization — **no GCE equivalent** | Not supported (typed) |
| `VMSnapshotter.CreateSnapshot` | `Disks.CreateSnapshot` of the instance's boot disk | Implemented |
| `VMSnapshotter.DeleteSnapshot` | resolve by label → `Snapshots.Delete` | Implemented |
| `VMSnapshotter.ListSnapshots` | `Snapshots.List` (vm-id label filter) | Implemented |
| `VMSnapshotter.RestoreSnapshot` | stop → detach boot disk → `Disks.Insert` from snapshot → attach → start | Implemented (disk-only; no memory snapshot) |
| `VMAttester.AttestVM` | `Instances.GetShieldedInstanceIdentity` → Shielded VM vTPM EK identity (RSA `EncryptionKey.EkPub`, PEM→DER, validated PKIX) | Implemented (EK identity) |
| `VMAttester.VerifyVMAttestation` | control-plane PCR-quote verification needs the in-guest AK | Not supported (typed) |

**Honestly-rejected on GCP:** `AttachNetwork` / `DetachNetwork` (a Compute
Engine NIC is bound at instance creation — there is no ENI-equivalent
control-plane hot-attach, so the orchestrator rejects rather than pretending);
`ActivateInstance` (802.1X OVS construct); `VerifyVMAttestation` (the control
plane cannot read a guest's PCRs). The GCP attestation split mirrors AWS: the
control plane proves *which vTPM hardware root of trust backs the instance* via
`GetShieldedInstanceIdentity`, while the in-guest agent produces the PCR quote
through `vtpm.ResolveTPMTarget` (`/dev/tpmrm0`) and submits it to
`pkg/attestation/vm` — the orchestrator reimplements no TPM crypto.

## Azure (Trusted Launch) capability matrix

The Azure orchestrator provides lifecycle parity with the local QEMU
orchestrator, including NIC attach/detach (Azure NICs are first-class resources,
the honest analogue of an EC2 ENI). Attestation is honestly rejected from the
control plane: Azure exposes no Resource Manager API for vTPM EK / quote
material — Trusted Launch attestation is guest-driven through Microsoft Azure
Attestation.

| Capability (interface method) | Azure mapping | Status |
|-------------------------------|---------------|--------|
| `Create` | `VirtualMachines.BeginCreateOrUpdate` with `SecurityProfile{SecurityType: TrustedLaunch, UefiSettings{VTpmEnabled, SecureBootEnabled}}`. The vTPM is requested explicitly; Azure rejects a non-Trusted-Launch size/image, so the launch fails closed. | Implemented |
| `Start` / `Stop` / `Delete` | `BeginStart` / `BeginPowerOff` / `BeginDelete` (poller driven to completion) | Implemented |
| `List` / `Get` | `NewListPager` (managed-tag filter; client-side `InstanceFilter`) / `Get` | Implemented |
| `GetState` | `InstanceView` power state → `InstanceState` | Implemented |
| `Wait` | Polls `InstanceView` until stopped/deallocated (ticker + `select`, no `time.Sleep`) | Implemented |
| `AttachNetwork` | `BeginUpdate` adding a NIC (portName = NIC resource ID) to the VM network profile | Implemented |
| `DetachNetwork` | `BeginUpdate` removing the NIC from the VM network profile | Implemented |
| `ActivateInstance` | 802.1X OVS port authorization — **no Azure equivalent** | Not supported (typed) |
| `VMSnapshotter.CreateSnapshot` | `Snapshots.BeginCreateOrUpdate` (Copy) of the VM's OS managed disk | Implemented |
| `VMSnapshotter.DeleteSnapshot` | resolve by tag → `Snapshots.BeginDelete` | Implemented |
| `VMSnapshotter.ListSnapshots` | `NewListByResourceGroupPager` (vm-id tag filter) | Implemented |
| `VMSnapshotter.RestoreSnapshot` | deallocate → `Disks.BeginCreateOrUpdate` from snapshot → swap OS disk via `BeginUpdate` → start | Implemented (disk-only; no memory snapshot) |
| `VMAttester.AttestVM` | no control-plane vTPM EK / quote API on Azure | Not supported (typed) |
| `VMAttester.VerifyVMAttestation` | control-plane PCR-quote verification needs the in-guest AK | Not supported (typed) |

**Honestly-rejected on Azure:** both attester methods. Unlike AWS
(`GetInstanceTpmEkPub`) and GCP (`GetShieldedInstanceIdentity`), Azure has **no**
Resource Manager API to retrieve a Trusted Launch VM's vTPM EK or drive its
attestation key. Trusted Launch attestation is fundamentally guest-driven: the
in-guest agent reads the vTPM via `vtpm.ResolveTPMTarget` (`/dev/tpmrm0`),
obtains a quote, and submits it to Microsoft Azure Attestation and/or
`pkg/attestation/vm`. Rather than fabricate a hollow report, `AttestVM` rejects
with `ErrCapabilityNotSupported`. `ActivateInstance` is rejected for the same
802.1X-OVS reason as the other providers.

> **Azure OSProfile note.** Azure mandates an admin credential for image-based
> VM provisioning. The orchestrator generates a **throwaway ephemeral ed25519
> SSH key** per launch (admin user `platform`, password auth disabled) purely to
> satisfy the API contract; the key is discarded and never persisted. The
> platform reaches instances through its own trust mechanisms, not this key.

## Configuration

Select a provider in the `compute:` section. When unset, the default
container orchestrator is used.

```yaml
compute:
  provider: aws          # local-qemu | local-container | aws | gcp | azure
  aws:
    region: us-east-1
    ami_id: ami-0nitrotpm      # MUST be registered TpmSupport=v2.0, UEFI boot
    instance_type: m5.large    # a Nitro type
    subnet_id: subnet-abc123
    security_group_ids: [sg-abc123]
    key_name: my-keypair
    root_volume_size_gib: 30
    # credentials optional — falls back to the AWS default chain (IAM role/env)
    # access_key_id: ...
    # secret_access_key: ...

  gcp:
    project_id: my-project
    zone: us-central1-a
    machine_type: n2-standard-2      # a Shielded-VM-capable machine type
    source_image: projects/debian-cloud/global/images/family/debian-12  # UEFI/Shielded
    # network: projects/my-project/global/networks/default   # optional
    # subnetwork: projects/my-project/regions/us-central1/subnetworks/default
    # credentials_file: /path/sa.json   # optional — falls back to ADC

  azure:
    subscription_id: 00000000-0000-0000-0000-000000000000
    resource_group: my-rg
    location: eastus
    vm_size: Standard_D2s_v5          # a Trusted-Launch-capable size
    image_reference: Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest  # publisher:offer:sku:version, or a resource/gallery image ID
    # tenant_id: <aad-tenant>          # optional — falls back to the default chain
```

If a `provider:` is set in a binary built **without** that provider's tag
(`awscompute` / `gcpcompute` / `azurecompute`), startup fails closed with
`ErrComputeProviderNotCompiled` naming the missing tag.

## Testing

Compute is validated in **three layered tiers** — faked-client unit (full
surface, always run), Floci emulator (AWS EC2 lifecycle only, no creds), and
real cloud (creds-gated, the only true attestation validation). The full model,
the exact per-provider env vars, and an explicit list of what the emulator
**cannot** cover live in **[testing.md](testing.md)**. Summary:

| Tier | Command | Cloud API | Creds | Covers |
|------|---------|-----------|-------|--------|
| Faked unit | `go test -tags <provider>compute ./pkg/compute/<provider>/...` | none (`ec2API`/`gceAPI`/`vmAPI` seam) | none | full: lifecycle + snapshots + attestation |
| Floci (AWS) | `make integration-test-compute-aws` | real SDK → Floci :4566 | none | AWS EC2 lifecycle **only** |
| Real AWS | `make integration-test-compute-aws-real` | real AWS | yes | full incl. real NitroTPM |
| Real GCP | `make integration-test-compute-gcp-real` | real GCP | yes | full incl. real Shielded-VM vTPM |
| Real Azure | `make integration-test-compute-azure-real` | real Azure | yes | full incl. real Trusted-Launch vTPM |
| Real (all) | `make integration-test-compute-cloud-real` | all three | yes | definitive cross-cloud validation |

Every provider fakes its cloud SDK at a narrow seam so unit tests make **no
live cloud calls** and use no `time.Sleep` (state waits poll a ticker with
`select`). The Floci tier points the AWS orchestrator at the `floci/floci:latest`
emulator via `AWSProviderConfig.Endpoint`; because Floci does not populate
`DescribeImages` `TpmSupport`, it sets `AWSProviderConfig.SkipNitroTPMAssertion`
(defaults `false` — production launches still fail closed without a
`TpmSupport=v2.0` AMI). **Floci does NOT emulate EBS snapshots, NitroTPM, GCP
Compute Engine, or Azure VMs** — emulator green is never full coverage.

The real-cloud targets build with `-tags 'cloud_integration <provider>compute'`,
launch **billable** resources (terminated + snapshot-deleted via `t.Cleanup`),
and **never** call `t.Skip`: when the tag is present but configuration is
missing they fail loudly with a typed message, so a misconfigured CI run is
never silently green. `make test-cloud-compute-{aws,gcp,azure}` remain as
aliases.

## Honest-parity summary

All three cloud providers implement `compute.Orchestrator` +
`compute.VMSnapshotter` + `compute.VMAttester` against the shared factory, with
disk-only snapshot semantics (no live memory capture) and a consistent
attestation split: the control plane proves the vTPM hardware root of trust
where an API exists (AWS EK, GCP EK), and the in-guest agent + `pkg/attestation/vm`
produces and verifies the PCR quote via `vtpm.ResolveTPMTarget`. Capabilities
with no honest cloud primitive return the provider's typed
`ErrCapabilityNotSupported` rather than a silent success — see each matrix
above.
