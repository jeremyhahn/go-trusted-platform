# Bare Metal Provisioning

End-to-end automated provisioning of bare metal servers using BMC out-of-band management.

## Overview

Bare metal provisioning automates the complete lifecycle of turning a racked server into a production-ready system. The platform connects to the server's BMC, mounts an installation ISO, boots the server, and monitors the installation process through to completion and enrollment.

## PXE Boot via Gateway

For greenfield deployments or large-scale rollouts, the PXE bootstrap system provides an alternative to ISO-based provisioning. Instead of mounting ISOs via virtual media, nodes boot from the network using PXE:

1. A bootstrap container serves DHCP, TFTP, and HTTP
2. BMC sets each server to PXE boot and powers it on
3. Servers netboot, install, and self-enroll

```bash
platformctl bootstrap run --config bootstrap.yaml
```

See [PXE Bootstrap Documentation](../bootstrap/pxe-bootstrap.md) for the complete guide. PXE bootstrap supports both BMC-managed and [manual nodes](../bootstrap/manual-nodes.md).

## ISO-Based Provisioning Workflow

```
1. Create Template    2. Create Profile    3. Trigger Provision
   (BMC blueprint)      (server-specific)    (CLI or API)
        |                     |                    |
        v                     v                    v
   +----------+        +----------+         +--------------+
   | Template |------->| Profile  |-------->|  Provisioner  |
   | BMC cfg  |        | BMC addr |         |               |
   | ISO URL  |        | serial   |         | 1. Connect    |
   | boot dev |        | creds    |         | 2. Mount ISO  |
   +----------+        +----------+         | 3. Set boot   |
                                            | 4. Power on   |
                                            | 5. Monitor    |
                                            | 6. Finalize   |
                                            +--------------+
```

## Provisioning Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | `pending` | Provision request created, queued for execution |
| 2 | `connecting` | Establishing BMC connectivity |
| 3 | `setting_boot` | Configuring boot device (virtual media or PXE) |
| 4 | `mounting_iso` | Mounting installation ISO via virtual media |
| 5 | `powering_on` | Powering on the server |
| 6 | `installing` | OS installation in progress |
| 7 | `finalizing` | Post-install cleanup (unmount ISO, set boot to disk) |
| 8 | `complete` | Provisioning finished successfully |
| - | `failed` | Provisioning failed at any step |

## Step-by-Step Guide

### Step 1: Create a Device Template

Define the hardware blueprint with BMC configuration.

```bash
platformctl device template create \
  --name "dell-r640-standard" \
  --bmc-port 623 \
  --bmc-protocol "ipmi" \
  --description "Dell R640 standard provisioning template"
```

### Step 2: Create a Device Profile

Create a server-specific profile from the template.

```bash
platformctl device template create-profile \
  --template-id 1 \
  --serial "DELL-R640-001" \
  --bmc-address "10.10.0.101" \
  --bmc-username "admin" \
  --bmc-password "vault://bmc/dell-r640-001"
```

### Step 3: Verify BMC Connectivity

Confirm the platform can communicate with the server's BMC.

```bash
# Check power status
platformctl bmc power-status --profile-id 42

# Get system info
platformctl bmc system-info --profile-id 42
```

### Step 4: Trigger Provisioning

Start the automated provisioning workflow.

**CLI:**
```bash
platformctl bmc provision \
  --profile-id 42 \
  --iso-url "https://iso.internal/debian-12-amd64.iso"
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/provision \
  -H "Content-Type: application/json" \
  -d '{"iso_url": "https://iso.internal/debian-12-amd64.iso"}'
```

**Response:**
```json
{
  "provision_id": "prov-a1b2c3d4",
  "profile_id": 42,
  "status": "pending",
  "started_at": "2026-03-31T10:00:00Z",
  "updated_at": "2026-03-31T10:00:00Z"
}
```

### Step 5: Monitor Provisioning Status

Poll the provisioning status until completion.

**CLI:**
```bash
platformctl bmc provision-status --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/provision
```

### Step 6: Post-Provisioning

After provisioning completes, the server:

1. Boots from local disk with the installed OS
2. Runs the trusted-platform bootstrap agent
3. Enrolls with the platform via ACME (obtains IDevID certificate)
4. Fetches its device configuration
5. Transitions to the production network

## What Happens During Provisioning

The provisioner executes the following sequence:

1. **Connect to BMC** - Establish IPMI/Redfish session with the server's BMC
2. **Mount ISO** - Attach the installation ISO via virtual media
3. **Set Boot Device** - Configure the server to boot from virtual media (one-time)
4. **Power On/Cycle** - Boot the server (power on if off, cycle if already on)
5. **Wait for Installation** - Monitor until the install completes or times out
6. **Finalize** - Unmount ISO, set boot device back to local disk
7. **Report Status** - Mark provisioning as complete or failed

## Configuration

### Provisioning Service Config

```yaml
provisioning:
  baremetal:
    install_timeout: 30m    # Maximum time to wait for OS install
    power_on_delay: 5s      # Delay after power-on before monitoring
```

### ISO Requirements

The installation ISO must:

- Be accessible via HTTP/HTTPS from the platform server
- Support unattended installation (preseed, kickstart, or autoinstall)
- Include the trusted-platform bootstrap agent
- Configure the system to contact the platform on first boot

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `profile has no BMC configuration` | Profile missing BMC settings | Add BMC config to the profile |
| `provision already in progress` | Another provision is running | Wait for it to complete or check status |
| `connection failed` | BMC unreachable | Verify network connectivity and credentials |
| `install timeout` | Installation exceeded timeout | Check ISO, increase timeout, or investigate server console |

## Related Documentation

- [BMC Configuration](../bmc/configuration.md) - BMC connection setup
- [BMC Operations](../bmc/operations.md) - Individual BMC operations
- [Device Templates](templates.md) - Template configuration
- [Config Delivery](config-delivery.md) - Post-install configuration
- [PXE Bootstrap](../bootstrap/pxe-bootstrap.md) - PXE-based greenfield deployment
