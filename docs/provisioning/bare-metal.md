# Bare Metal Provisioning

> **Status: REFERENCE** · Last verified: 2026-10-15
> Provisioning a racked server through its BMC, from ISO mount to enrollment.

End-to-end automated provisioning of bare metal servers using BMC out-of-band management.

## Overview

Bare metal provisioning drives a racked server through its BMC: it sets the
boot device, optionally mounts an installation ISO, powers the server on, waits
for the install, and then switches the server to boot from disk. The
orchestrator is `pkg/provisioning/baremetal`.

> **Not wired on a stock daemon.** `pkg/api/daemon/daemon.go` constructs the
> BMC gRPC service with a nil bare-metal orchestrator and nothing calls
> `SetBaremetalService`, so `Provision` and `ProvisionStatus` answer
> `Unavailable` on gRPC, QUIC, MCP and Unix, and `503`
> (`bmc: bare metal provisioning service not available`) on REST. See
> [BMC API](../bmc/api.md) and [BMC CLI](../bmc/cli.md). The rest of this page
> describes the orchestrator as implemented, for when it is wired.

## PXE Boot via Gateway

For greenfield deployments or large-scale rollouts, the PXE bootstrap system provides an alternative to ISO-based provisioning. Instead of mounting ISOs via virtual media, nodes boot from the network using PXE:

1. A bootstrap container serves DHCP, TFTP, and HTTP
2. BMC sets each server to PXE boot and powers it on
3. Servers netboot, install, and self-enroll

```bash
platformctl bootstrap run --config bootstrap.yaml
```

See [PXE Bootstrap Documentation](../bootstrap/user.md) for the complete guide. PXE bootstrap supports both BMC-managed and [manual nodes](../bootstrap/user.md).

## ISO-Based Provisioning Workflow

```
1. Create Profile        2. Trigger Provision      3. Orchestrator
   (device profile         (CLI, REST or gRPC)
    with BMC settings)
        |                         |                       |
        v                         v                       v
   +-------------+          +-----------+         +------------------+
   | Profile     |--------->| Provision |-------->| check power      |
   | BMC address |          | profile + |         | power off if on  |
   | protocol    |          | ISO URL   |         | set boot device  |
   | credentials |          | (opt.)    |         | mount ISO        |
   +-------------+          +-----------+         | power on         |
                                                  | wait for install |
                                                  | finalize         |
                                                  +------------------+
```

## Provisioning Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | `pending` | Provision request created, queued for execution |
| 2 | `connecting` | Reading power state; powering off a server that is on |
| 3 | `setting_boot` | Configuring boot device (virtual media or PXE) |
| 4 | `mounting_iso` | Mounting installation ISO via virtual media |
| 5 | `powering_on` | Powering on the server |
| 6 | `installing` | OS installation in progress |
| 7 | `finalizing` | Post-install cleanup (unmount ISO, set boot to disk, power cycle) |
| 8 | `complete` | Provisioning finished successfully |
| - | `failed` | Provisioning failed at any step |

## Step-by-Step Guide

The `bmc` commands below are daemon-only and take the common connection flags:
`--server-url`, plus `--ca-cert`, `--client-cert` and `--client-key` (defaulting
to `$PLATFORM_CA_CERT`, `$PLATFORM_CLIENT_CERT` and `$PLATFORM_CLIENT_KEY`).

### Step 1: Create a Device Profile

Create the server's device profile. The BMC settings the orchestrator uses come
from the profile's BMC configuration (`DeviceProfile.BMC`, read through
`pkg/api/daemon/bmc_profile_store.go`); see [BMC Operations](../bmc/user.md)
for how a BMC is enrolled against a profile.

```bash
platformctl device profile create \
  --name dell-r640-001 \
  --role server \
  --mac 00:25:90:FF:AA:02 \
  --config-file /path/to/platform.yaml
```

### Step 2: Verify BMC Connectivity

Confirm the platform can communicate with the server's BMC.

```bash
# Check power status
platformctl bmc power-status --server-url https://platform:8443 --profile-id 42

# Get system info
platformctl bmc system-info --server-url https://platform:8443 --profile-id 42
```

### Step 3: Trigger Provisioning

Start the automated provisioning workflow. `--iso-url` is optional; without it
the server is set to PXE boot instead of virtual media.

**CLI:**
```bash
platformctl bmc provision \
  --server-url https://platform:8443 \
  --profile-id 42 \
  --iso-url "https://iso.internal/debian-12-amd64.iso"
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/provision \
  -H "Content-Type: application/json" \
  -d '{"iso_url": "https://iso.internal/debian-12-amd64.iso"}'
```

**Response** (`201`; `provision_id` is a random 32-character hex ID, `message`
is present only when set):
```json
{
  "provision_id": "9f2c4e1a7b3d5f60a1c2e3d4b5a69788",
  "profile_id": 42,
  "status": "pending",
  "started_at": "2026-03-31T10:00:00Z",
  "updated_at": "2026-03-31T10:00:00Z"
}
```

### Step 4: Monitor Provisioning Status

Poll the provisioning status until completion. There is no CLI status command;
use REST or the gRPC `BMCService.ProvisionStatus` RPC.

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/provision
```

### Step 5: Post-Provisioning

After provisioning completes, the server boots from local disk. What runs
there is up to the installed image; the platform's first-boot enrollment and
config delivery are described in [Bootstrap](../bootstrap/user.md) and
[Config Delivery](config-delivery.md).

## What Happens During Provisioning

The orchestrator (`runProvision`, `pkg/provisioning/baremetal/service.go`)
executes these steps in order:

1. **Check power** - Read the server's power state (`connecting`)
2. **Power off** - Power the server off if it is on (`connecting`)
3. **Set boot device** - One-time boot from virtual media when an ISO URL was
   given, otherwise from PXE (`setting_boot`)
4. **Mount ISO** - Attach the installation ISO via virtual media, skipped
   without an ISO URL (`mounting_iso`)
5. **Power on** - Boot the server (`powering_on`)
6. **Wait for installation** - Block until the install is reported complete
   (`Service.CompleteInstall`) or the workflow timeout expires (`installing`).
   Only tests call `CompleteInstall` today.
7. **Unmount ISO** - Skipped without an ISO URL (`finalizing`)
8. **Set boot to disk** - Persistent boot device (`finalizing`)
9. **Power cycle** - Restart into the installed OS (`finalizing`)
10. **Report status** - Mark provisioning `complete`, or `failed` at the first
    step that errors

## Configuration

### Provisioning Service Config

The orchestrator's settings (`baremetal.Config`, `pkg/provisioning/baremetal/config.go`)
are not part of the platform configuration file; `DefaultConfig` applies:

| Field | Default | Meaning |
|-------|---------|---------|
| `InstallTimeout` | `30m` | Timeout for the whole workflow, from the first step to the last |
| `PowerOnDelay` | `5s` | Defined but not read by the workflow |

### ISO Requirements

The installation ISO must:

- Be accessible via HTTP/HTTPS from the platform server
- Support unattended installation (preseed, kickstart, or autoinstall)
- Include the trusted-platform bootstrap agent
- Configure the system to contact the platform on first boot

## Error Handling

Errors from `pkg/provisioning/baremetal/errors.go`:

| Error | Cause | Resolution |
|-------|-------|------------|
| `baremetal: profile <id> has no BMC configuration` | Profile lookup failed or the profile has no BMC settings | Check the profile ID and its BMC settings |
| `baremetal: provision already in progress for profile <id>` | Another provision is running for the profile | Wait for it to complete or check status |
| `baremetal: install timeout for profile <id> after <timeout>` | The workflow exceeded `InstallTimeout` | Check the ISO and the server console |
| `baremetal: invalid provision request: <reason>` | Missing profile ID | Pass a non-zero profile ID |
| `baremetal: provision not found: <id>` | Unknown provision ID | Check the ID |

## Related Documentation

- [BMC Configuration](../bmc/engineering.md) - BMC connection setup
- [BMC Operations](../bmc/user.md) - Individual BMC operations
- [Device Templates](templates.md) - Template configuration
- [Config Delivery](config-delivery.md) - Post-install configuration
- [PXE Bootstrap](../bootstrap/user.md) - PXE-based greenfield deployment
