# Cloud Compute Testing — the layered model

> **Status: REFERENCE** · Last verified: 2026-10-13
> How the cloud compute orchestrators are tested: faked-client unit tests, the Floci emulator and real-cloud runs.

The cloud compute orchestrators (`pkg/compute/aws`, `pkg/compute/gcp`,
`pkg/compute/azure`) are validated in **three deliberately layered tiers**.
Each tier trades coverage for fidelity. No single tier is sufficient on its own,
and the emulator tier is explicitly **not** a substitute for the real-cloud
tier. Read this before assuming "the emulator passed" means the provider works.

| Tier | Build tags | Cloud API | Creds | Surface covered | Runs in CI |
|------|-----------|-----------|-------|-----------------|-----------|
| 1. Faked-client unit | `<provider>compute` | none (fake at the `ec2API` / `gceAPI` / `vmAPI` seam) | none | **Full** — lifecycle + EBS/disk snapshots + NitroTPM/Shielded/Trusted-Launch attestation, error paths, `ErrCapabilityNotSupported` | **Always** |
| 2. Floci emulator | `floci_integration awscompute` | real `aws-sdk-go-v2` → Floci on :4566 | none (dummy `test`/`test`) | **AWS EC2 instance lifecycle only** | opt-in (`make integration-test-compute-aws`) |
| 3. Real cloud | `cloud_integration <provider>compute` | real AWS / GCP / Azure | **real** | **Full incl. real hardware root of trust** — the only true attestation validation | opt-in, creds-gated |

## Tier 1 — faked-client unit tests (always run)

Every provider fakes its cloud SDK at a narrow interface seam so the full
orchestrator surface is exercised with **no live cloud calls** and no
`time.Sleep` (state waits poll a ticker with `select`). These tests cover the
capabilities the higher tiers cannot reach cheaply or at all: EBS/disk snapshot
create/restore/list/delete, NitroTPM / Shielded VM / Trusted Launch endorsement-
key retrieval and verification, and the honestly-rejected capabilities
(`ErrCapabilityNotSupported`). They are the coverage backbone.

The provider tags are off by default (`WITH_*_COMPUTE ?= 0`). Turn one on
rather than typing a `-tags` list, which drops the codec tags:

```
make test-pkg PKG=./pkg/compute/aws/   WITH_AWS_COMPUTE=1
make test-pkg PKG=./pkg/compute/gcp/   WITH_GCP_COMPUTE=1
make test-pkg PKG=./pkg/compute/azure/ WITH_AZURE_COMPUTE=1
```

## Tier 2 — Floci emulator (AWS EC2 lifecycle, no creds)

[Floci](https://floci.io) ([github.com/floci-io/floci](https://github.com/floci-io/floci))
is an MIT-licensed, endpoint-URL drop-in AWS emulator — the successor to
LocalStack, whose OSS community edition was sunset 2026-03. `make
integration-test-compute-aws` brings up the `floci/floci:latest` container on
`:4566` via `test/integration/compute-aws/docker-compose.yml`, points the AWS
orchestrator at it through `AWSProviderConfig.Endpoint`, and runs
`TestAWSCompute_Floci` (`pkg/compute/aws/floci_integration_test.go`) through the
**real** `aws-sdk-go-v2` client — so the orchestrator's endpoint wiring,
request shapes, and lifecycle state mapping are validated against a real EC2
wire protocol without a cloud account.

Lifecycle operations exercised: **Create** (`RunInstances`) → **Get/List**
(`DescribeInstances`, incl. the platform managed-tag filter) → **Stop**
(`StopInstances`) → **Start** (`StartInstances`) → **Delete**
(`TerminateInstances`), asserting each state transition
(running → stopped → running → terminated).

Because Floci's `DescribeImages` does not populate `TpmSupport`, the test sets
`AWSProviderConfig.SkipNitroTPMAssertion = true` to bypass the production
pre-launch NitroTPM check. This flag exists for non-attesting deployments and
emulators; it defaults `false`, so production launches still fail closed unless
the AMI is registered `TpmSupport=v2.0`. When it is `true` the guest is **not**
guaranteed a NitroTPM device and attestation MUST NOT be relied upon.

Per platform policy the test **never** `t.Skip`s: if `FLOCI_EC2_ENDPOINT` is
unset it uses `http://localhost:4566`; if Floci is unreachable it fails with a
typed `flociUnavailableError` that names the expected container and how to start
it.

### What Floci CANNOT test (on the record)

Floci emulates the EC2 **instance lifecycle** only. It does **not** emulate:

- **EBS snapshots** — `CreateSnapshot` / `DescribeSnapshots` are absent (only
  `CreateVolume` / `DescribeVolumes` / `DeleteVolume` exist). The orchestrator's
  `VMSnapshotter` path is therefore **not** covered here.
- **NitroTPM** — no `TpmSupport` on `DescribeImages`, no
  `GetInstanceTpmEkPub`. No endorsement key, no attestation.
- **GCP Compute Engine** — no GCE emulation at all.
- **Azure Virtual Machines** — Floci-Az covers Blob/Queue/Table/Functions only,
  not VMs or Trusted Launch.

Snapshots and attestation for AWS, and everything for GCP/Azure, are validated
by Tier 1 (faked) and Tier 3 (real cloud). **Emulator green ≠ full coverage.**

## Tier 3 — real cloud (creds-gated, the definitive validation)

The real-cloud tests are the **only** tier that validates the actual hardware
root of trust: AWS NitroTPM 2.0, GCP Shielded VM vTPM, Azure Trusted Launch
vTPM. They provision **real, billable** resources and clean them up (instance
`Delete` and snapshot `DeleteSnapshot` are registered with `t.Cleanup` at
creation time, so teardown runs even on assertion failure). They never run in
the default suite and never `t.Skip`: when the build tag is present but the
required env is missing they fail loudly with a typed message, so a
misconfigured CI run is never silently green.

| Target | Test | Required env (plus provider credentials) |
|--------|------|------------------------------------------|
| `make integration-test-compute-aws-real` | `TestAWSCompute_RealCloud` | `COMPUTE_AWS_REGION`, `COMPUTE_AWS_AMI` (registered `TpmSupport=v2.0`), `COMPUTE_AWS_INSTANCE_TYPE` (a Nitro type); optional `COMPUTE_AWS_SUBNET`; AWS creds (`AWS_*` / IAM role) |
| `make integration-test-compute-gcp-real` | `TestGCPCompute_RealCloud` | `COMPUTE_GCP_PROJECT`, `COMPUTE_GCP_ZONE`, `COMPUTE_GCP_MACHINE_TYPE` (Shielded-capable), `COMPUTE_GCP_IMAGE` (UEFI/Shielded); optional `COMPUTE_GCP_NETWORK`, `COMPUTE_GCP_SUBNETWORK`, `COMPUTE_GCP_CREDENTIALS`; Google ADC |
| `make integration-test-compute-azure-real` | `TestAzureCompute_RealCloud` | `COMPUTE_AZURE_SUBSCRIPTION`, `COMPUTE_AZURE_RESOURCE_GROUP`, `COMPUTE_AZURE_LOCATION`, `COMPUTE_AZURE_VM_SIZE` (Trusted-Launch-capable), `COMPUTE_AZURE_IMAGE`; optional `COMPUTE_AZURE_TENANT`; Azure default credential chain |
| `make integration-test-compute-cloud-real` | all three | every provider's env + credentials above |

Each real-cloud test launches an instance, waits for it to reach running
(ticker + `select`, no `time.Sleep`), retrieves and verifies the vTPM/NitroTPM
endorsement key via `AttestVM`, creates and lists a disk snapshot, then relies
on `t.Cleanup` to terminate the instance and delete the snapshot. Because the
tests provision real resources, run them deliberately and confirm cleanup in
the provider console afterward.

The legacy aliases `make test-cloud-compute-{aws,gcp,azure}` run the same
`cloud_integration` tests and remain for backward compatibility.

## Summary

- **Tier 1 (faked)** proves the orchestrator logic across its full surface,
  always, for free.
- **Tier 2 (Floci)** proves the AWS wire protocol + lifecycle state machine
  against a real SDK, no account, no cost — **AWS lifecycle only**.
- **Tier 3 (real cloud)** is the sole validation of real attestation and cloud
  behavior — creds-gated, billable, definitive.

Do not conflate the tiers. A passing Floci run says nothing about snapshots,
NitroTPM, GCP, or Azure.
