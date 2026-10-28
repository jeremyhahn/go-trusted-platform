# Compute — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Running VMs and containers on the platform, in the order you do it. Internals
> are in [engineering.md](engineering.md).

---

## What this is

VMs (QEMU/KVM) and containers (podman) on platform nodes, with two things an
ordinary hypervisor does not do:

- **A VM can have its own virtual TPM**, so it can be attested independently of
  the host.
- **A workload's network port authenticates**, through the same
  IDevID-certificate state machine a physical device goes through.

Cloud providers (AWS, Azure, GCP) exist but are compiled out by default.

---

## Prerequisites

1. A worker node with compute enabled and `enable_kvm` on if you want
   acceleration.
2. **A bridge to attach to** — `network_bridge` in configuration, or
   `--network-bridge` per VM. See [`docs/sdn/`](../sdn/).
3. **A tenant with quota**, if you are running under tenancy. Creation is
   refused when the quota has no room ([`docs/tenant/`](../tenant/)).
4. For attested VMs: the **host must have attested first**. VM attestation is
   bound to host attestation and the ordering is enforced.

---

## Creating a VM you can actually trust

```bash
platformctl compute create --name web-01 \
    --firmware uefi-secure-boot \
    --label tenant=tenant-a \
    --start
```

Two settings carry the weight:

**The vTPM.** On by default (`--tpm`). Without a virtual TPM the VM cannot
produce a quote, so it can never be attested. `--tpm=false` leaves it off, and
you cannot retrofit it into a running VM's identity.

**`--firmware uefi-secure-boot`.** `--firmware` defaults to `uefi` and
`--secure-boot` defaults to off; the combined firmware value states Secure Boot
once. The daemon refuses `--firmware bios`: VMs boot UEFI firmware.

**A create the daemon cannot honour is refused, not approximated.** A BIOS VM,
a CD-ROM boot or a bridge other than the orchestrator's fails with
`code = InvalidArgument` naming the field, and nothing is created. If `--start`
cannot start the new VM, the daemon deletes it and reports why.

Then confirm it:

```bash
platformctl compute list --all
platformctl compute get web-01
```

**`list` shows only running VMs unless you pass `--all`.** A VM created without
`--start` is invisible by default, which reads as "creation failed".

---

## Running a container

```bash
platformctl container create --name api \
    --image registry.example.com/apps/api:1.4.2 \
    --env LOG_LEVEL=info \
    --port 8443:8443 \
    --memory 1g --cpu 2 \
    --network-mode bridge \
    --start

platformctl container list --all
```

Images come from the platform's attestation-gated registry
([`docs/registry/`](../registry/)) — an unattested node cannot pull, so a
container that will not start on one node and starts on another is often an
attestation difference, not an image problem.

### Two flags to think hard about

**`--privileged`** removes container isolation. Everything the platform does to
contain a workload stops applying.

**`--tpm-access`** mounts the **host's** TPM device into the container — not a
virtual one. The workload can then perform operations against the host's root of
trust. That is occasionally what you want (a workload that measures the host)
and usually not.

Neither belongs in a default deployment. If a container needs one of them, that
is a decision worth writing down.

---

## Attesting a workload

```bash
platformctl container attest 7f3a9c21b804 --output json
```

This is the only attestation verb in the CLI. VM attestation is API-only:

```bash
curl -s -X POST https://platform.example.com/api/v1/compute/vms/<id>/attest
curl -s -X POST https://platform.example.com/api/v1/compute/vms/<id>/attest/verify
```

The host must have attested first. "Host not attested" is an ordering error, not
a failure of the VM.

SDK clients of the embedded server can call
`Security().Attestation().AttestContainer`, which checks the host against the
golden PCRs of its device profile. A mismatch quarantines the host and triggers
a fresh attestation, so the host shows as `quarantined` in
`platformctl device` until it passes again. The call is answered only on a node
that has the following:

- attestation reporting enabled;
- a host TPM;
- a container runtime.

On any other node it returns "container attestor not available".

---

## Snapshots and disks — API only

The CLI has no snapshot or disk verbs. Use REST:

```bash
curl -s -X POST   https://platform.example.com/api/v1/compute/vms/<id>/snapshots
curl -s           https://platform.example.com/api/v1/compute/vms/<id>/snapshots
curl -s -X POST   https://platform.example.com/api/v1/compute/vms/<id>/snapshots/<snap>/restore
curl -s -X DELETE https://platform.example.com/api/v1/compute/vms/<id>/snapshots/<snap>

curl -s -X POST   https://platform.example.com/api/v1/compute/vms/<id>/disks
curl -s -X PATCH  https://platform.example.com/api/v1/compute/vms/<id>/disks/<disk>   # resize
curl -s -X DELETE https://platform.example.com/api/v1/compute/vms/<id>/disks/<disk>
```

---

## Migrating a VM

```bash
platformctl compute migrate web-01 --destination worker-02.example.com:9443 --live
```

`--destination` is the **destination daemon's mTLS gRPC endpoint**, not a
hostname — migration is daemon-to-daemon.

**`--live` requires shared storage.** Without it the destination has no way to
reach the disk. For a staged migration with a confirmation point, use the
two-phase pair (`PrepareMigration`, `FinalizeMigration`, on REST, gRPC, QUIC
and MCP) rather than the one-shot CLI verb.

---

## Deleting things

```bash
platformctl compute delete web-01 --force --delete-disks
platformctl container remove api --force --volumes
```

**Disks and volumes survive deletion unless you ask for them to go.** That is
the safe default and it is also why storage fills up. Decide which you want
each time rather than adopting one habit.

---

## Troubleshooting

**"compute: provider <name> is not compiled into this build …"**
The `compute:` config names a cloud provider and the binary was built without
`awscompute` / `azurecompute` / `gcpcompute`. A build fact, not a runtime
failure — a default build genuinely cannot create a cloud instance. The daemon
hits it at start-up, logs *"Compute orchestrator not available (container
operations will fail)"* with this message as the reason, and runs without a
compute orchestrator.

**VM creation is refused with a resource error.**
Tenant quota, or `max_instances`. Check
`platformctl tenant usage <tenant>`.

**VM creation is refused and the error mentions a network zone.**
Placement found no network in the requested zone. That is a gap in the zone
graph, not a capacity problem — see [`docs/sdn/`](../sdn/).

**The VM starts but has no network.**
If `port_auth_enabled` is on, the VM's virtual port goes through the same
authentication state machine as a physical device. Check the port state
(`platformctl sdn port state ...`) before suspecting the VM.

**A VM cannot be attested.**
Either it was created with `--tpm=false` — in which case it has no virtual TPM
and never will — or the host has not attested.

**A container will not pull its image on one node but will on another.**
Registry access is attestation-gated. The difference is usually the node's
attestation state, not the image.

**A VM you created does not appear in `list`.**
`list` shows only running VMs by default. Pass `--all`.

---

## One thing to be aware of

**`ExecContainer` runs an arbitrary command inside a workload.** On gRPC and
Unix it needs `container:write`; treat that grant as shell access on every
container the caller can name. Over MCP each `vm_*` and `container_*` tool
takes its gRPC twin's scope, so `container_exec` needs `container:write` too.
See [api.md](api.md) §7.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — orchestration, placement, port auth
- [`docs/vtpm/`](../vtpm/) · [`docs/attestation/`](../attestation/) ·
  [`docs/sdn/`](../sdn/) · [`docs/tenant/`](../tenant/) ·
  [`docs/registry/`](../registry/)
