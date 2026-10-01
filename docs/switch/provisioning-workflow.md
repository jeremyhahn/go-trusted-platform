# Device Provisioning Workflow with Switch Integration

This document describes the complete PXE provisioning workflow with physical switch management.

> **Superseded (#708).** The VLAN numbers and the `provisioning_vlan` /
> `production_vlan` profile keys below describe an earlier design that the code
> never implemented. The current model: switch ports are configured by **port
> class**, the hypervisor trunk's native VLAN is the provisioning zone so a factory
> NIC PXE-boots without a port move, and every VLAN is derived from
> `sdn.environment`. See [switch-management](../bootstrap/switch-management.md) and
> the [reference network](../architecture/reference-network.md#switch-port-model).
> Where this file disagrees, those documents win.

## Overview

The provisioning workflow automates device onboarding from initial registration through production activation. Switch management enables VLAN isolation during provisioning and automatic transition to production.

## Workflow Phases

```
PHASE 1: REGISTRATION
├─ Device discovers platform via PXE
├─ Device boots platform-initrd
├─ Device registers serial + TPM pub key
└─ Device enters "registered" state

PHASE 2: PROVISIONING
├─ Platform places device port on provisioning VLAN (manual or switch)
├─ Device boots from ISO (install, attestation, firstboot)
├─ Device completes installation
├─ Device enters "activated" state
└─ Device is ready for production

PHASE 3: ACTIVATION
├─ Device calls POST /device/activate
├─ Platform moves port to production VLAN (if switch configured)
├─ Platform applies production policy (ACLs, rate limits)
├─ Device enters "production" state
└─ Workflow complete
```

## Detailed Sequence Diagram

```
Device              Platform            Switch
  │                    │                    │
  │  1. PXE boot       │                    │
  ├───────────────────>│                    │
  │                    │  2. Allocate VLAN  │
  │                    │    Provisioning:100│
  │                    ├──────────────────>│
  │                    │<──────────────────┤
  │  3. Boot ISO       │    Device port:    │
  │  Download          │    Eth1/3→VLAN 100│
  ├───────────────────>│                    │
  │                    │  4. Set port       │
  │  5. Register       │    for device      │
  │  serial + TPM      │  (may auto-detect)│
  ├───────────────────>│                    │
  │  "registered"      │                    │
  │  state confirmed   │                    │
  │<───────────────────┤                    │
  │                    │  6. Attestation,   │
  │                    │    install, etc.   │
  ├───────────────────>│                    │
  │  (progress)        │                    │
  ├───────────────────>│                    │
  │                    │  7. Activated      │
  │                    │    state confirmed │
  │                    │                    │
  │  8. POST /activate │                    │
  ├───────────────────>│                    │
  │                    │  9. Get profile    │
  │                    │    (VLAN 200)      │
  │                    │                    │
  │                    │  10. SetPortVLAN   │
  │                    │     Eth1/3→VLAN 200│
  │                    ├──────────────────>│
  │                    │  11. Execute       │
  │                    │   (SSH commands)   │
  │                    │<──────────────────┤
  │  200 OK            │     Success        │
  │<───────────────────┤                    │
  │  Status: activated │                    │
  │  VLAN: 200         │                    │
  │                    │  12. Apply policy  │
  │                    │     (ACLs, etc.)   │
  │                    │  13. Device ready  │
  │                    │     for production │
```

## Phase 1: Registration

### Step 1.1: Device discovers platform

Device boots via PXE (from jumpbox or network):

```bash
# Jumpbox or network infrastructure
# provides DHCP + TFTP bootstrap
# Device receives:
# - DHCP IP in provisioning VLAN
# - TFTP server (jumpbox 192.0.2.91)
# - Boot file (platform-initrd or platform-iso)
```

### Step 1.2: Device port placed on provisioning VLAN

**Option A: Manual (operator)**
```bash
# Operator runs switch commands
configure terminal
interface Eth1/3
switchport mode access
switchport access vlan 100  # Provisioning VLAN
end
```

**Option B: Automatic via platform (with switch configured)**
```go
// Platform daemon has switch service initialized
// At device registration, platform can:
// 1. Allocate VLAN 100 for provisioning (or hardcode)
// 2. Call mgr.SetPortVLAN(ctx, "Eth1/3", 100)
// 3. Device receives DHCP, boots
```

### Step 1.3: Device registers with platform

Device boots platform-initrd and registers:

```bash
# Device performs:
# - TPM attestation (PCRs, event log)
# - Generates EK cert, signing pub key
# - Sends registration request:
#   POST /device/register
#   {
#     "serial": "device-001",
#     "ek_cert": "...",
#     "signing_pub": "...",
#     "event_log": "...",
#     "hash_algo": 12,  // TPM_ALG_SHA256
#     "model": "Supermicro X10SDV"
#   }

# Platform responds:
# {
#   "state": "registered",
#   "profile": {
#     "provisioning_vlan": 100,
#     "production_vlan": 200,
#     "policies": {...}
#   }
# }
```

**Device state after:** `registered`

## Phase 2: Provisioning

### Step 2.1: Device boots from ISO

Device receives boot files and downloads platform ISO:

```bash
# Device:
# 1. Download platform.iso from jumpbox
# 2. Write to virtual media (IPMI/Redfish) or direct boot
# 3. Boot into platform installation environment
```

### Step 2.2: Platform runs pre-flight checks

Before installation:

```bash
# Platform-initrd or installer:
# - Verify TPM functionality
# - Check hardware compatibility
# - Validate installation media
# - Unlock LUKS (if encrypted)
```

### Step 2.3: Platform installs system

Installation proceeds:

```bash
# In provisioning environment:
# 1. Partition disk
# 2. Install root filesystem
# 3. Install kernel + bootloader
# 4. Set up firstboot service
```

### Step 2.4: Device firstboot

After reboot, firstboot service runs:

```bash
# Firstboot steps:
# 1. Upload attestation logs to platform
# 2. Extend TPM PCRs to production state
# 3. Provision platform certs (mTLS)
# 4. Start daemon services
# 5. Signal "firstboot complete" to platform
```

**Device state after:** `activated`

## Phase 3: Activation

### Step 3.1: Device calls activate endpoint

Device enters production network:

```bash
# Device:
curl --cert /etc/certs/device.crt \
     --key /etc/certs/device.key \
     -X POST https://platform:8443/device/activate

# Platform handler receives request:
# 1. Extract device serial from mTLS cert: "device-001"
# 2. Look up device profile via serial
# 3. Get ProductionVLAN = 200, SwitchName = "core-switch-01", SwitchPort = "Eth1/3"
```

### Step 3.2: Platform transitions switch port

Platform moves physical port to production VLAN:

```go
// handler.go: transitionSwitchPort()
mgr, _ := switchService.Manager("core-switch-01")
mgr.SetPortVLAN(ctx, "Eth1/3", 200)

// SSH to switch:
// 1. Execute: "configure terminal"
// 2. Execute: "interface Eth1/3"
// 3. Execute: "switchport mode access"
// 4. Execute: "switchport access vlan 200"
// 5. Execute: "end"
// 6. Check output for errors
```

### Step 3.3: Platform applies SDN policy

Platform configures network policies:

```go
// Apply production policy via SDN engine
policy := &policy.PortPolicy{
    VLAN: 200,
    ACLs: []{
        // Prod-only ACLs (no telemetry, no debugging)
    },
    RateLimit: 1000,  // Mbps
    IssuedAt: now(),
}
policyEngine.ApplyPolicy("device-001", policy)
```

### Step 3.4: Device enters production

Device now has full network access:

```bash
# Device (on production VLAN 200):
# - DHCP assigned IP from production subnet (203.0.113.0/24)
# - Can communicate with other production devices
# - Subject to production ACLs and policies
# - Can be attested by remote platforms
```

**Device state after:** `activated` (or `attested` after remote attestation)

**Response to device:**
```json
{
  "status": "activated",
  "vlan": 200,
  "transitionedAt": "2025-04-13T10:30:45Z"
}
```

## Failure Handling

### Scenario: Switch port not found

```bash
# Configuration has wrong switch/port
Config: SwitchPort = "Eth1/99" (doesn't exist)

# Platform calls: mgr.SetPortVLAN(ctx, "Eth1/99", 200)
# Switch responds: "% Invalid interface name Eth1/99"
# Platform error: switchmgmt.ErrPortNotFound{Port: "Eth1/99"}

# Device receives: HTTP 500 with error message
# Device does NOT transition to production
# Device stays on provisioning VLAN
# Operator must fix config and retry
```

### Scenario: VLAN not created on switch

```bash
# Configuration has production VLAN = 999 (doesn't exist)
# Platform calls: mgr.SetPortVLAN(ctx, "Eth1/3", 999)
# Switch responds: "% Invalid VLAN number 999"
# Platform error: switchmgmt.ErrVLANNotFound{VLANID: 999}

# Device receives: HTTP 500 with error message
# Operator must:
# 1. Create VLAN 999 on switch
# 2. Device retries /activate
```

### Scenario: SSH connection fails

```bash
# Switch is unreachable or credentials wrong
# Platform calls: mgr.SetPortVLAN(ctx, "Eth1/3", 200)
# Platform error: switchmgmt.ErrSSHConnectionFailed{
#     Host: "10.0.1.50",
#     Cause: "connection timeout"
# }

# Device receives: HTTP 500 with error message
# Device stays on provisioning VLAN
# Operator must:
# 1. Verify switch is reachable: ping 10.0.1.50
# 2. Verify credentials: ssh -u admin@10.0.1.50
# 3. Device retries /activate
```

### Scenario: No switch configured

```bash
# Config has no switches (or switch disabled)
# Device calls: POST /device/activate
# Platform's transitionSwitchPort() returns early:
#   if h.switchService == nil { return nil }

# Device receives: HTTP 200 OK (normal activation)
# Device stays on current VLAN (manual management)
# Works fine for small deployments
```

## Recovery Procedures

### Device stuck on provisioning VLAN

```bash
# Problem: Device activated but still on VLAN 100
# Cause: Network isolated, can't reach platform for second activate

# Recovery:
# Option 1: Operator manually moves port
#   configure terminal
#   interface Eth1/3
#   switchport access vlan 200
#   end

# Option 2: Device retries (if gateway exists)
#   curl -X POST https://platform:8443/device/activate

# Option 3: Platform moves port (if reachable via band)
#   platformctl device activate --serial device-001
```

### Device stuck in "activated" but not "attested"

```bash
# Problem: Device completed firstboot but attestation failed
# Cause: Remote attestation service unreachable

# Recovery:
# Option 1: Retry attestation
#   curl -X POST https://platform:8443/device/attest

# Option 2: Skip attestation (admin approval needed)
#   platformctl device transition --serial device-001 --state attested

# Device continues on production VLAN regardless
```

## Workflow Customization

### Custom provisioning duration

By default, devices have 1 hour from registration to activation. Customize:

```yaml
provisioning:
  registration_timeout: 1h      # Auto-cleanup if not activated
  vlan_reservation_timeout: 2h  # Override for large deployments
```

### Custom VLAN allocation

Hardcode provisioning/production VLANs per switch:

```yaml
switches:
  - name: core-switch-01
    vendor: cisco-nexus
    host: 10.0.1.50
    user: admin
    ssh_key: /etc/certs/switch.key
    vlans:
      - id: 100
        name: provisioning
      - id: 200
        name: production
    # These VLANs are created once during setup
    # All devices use them automatically
```

Or per-device profile:

```yaml
device_profiles:
  - name: default
    provisioning_vlan: 100
    production_vlan: 200
    switch: core-switch-01

  - name: development
    provisioning_vlan: 101
    production_vlan: 201
    switch: dev-switch-01
```

### Automatic port detection

Instead of hardcoding port in device profile, platform could:

```go
// Auto-discover port from MAC at registration
mac := getDeviceMACFromARP(deviceIP)
port := lookupPortByMAC(mac)  // Check switch MAC table
device.SwitchPort = port  // Store discovered port
```

Not yet implemented; would require:
- Port discovery service reading switch MAC tables
- Consistent MAC address across boot/registration
- Fallback for devices with dynamically assigned MACs

## Monitoring and Logging

Platform logs all switch operations:

```json
{
  "timestamp": "2025-04-13T10:30:45Z",
  "level": "info",
  "message": "device activated with switch vlan transition",
  "device_serial": "device-001",
  "switch_name": "core-switch-01",
  "switch_port": "Eth1/3",
  "production_vlan": 200,
  "transition_duration_ms": 234
}
```

Failed transitions logged as errors:

```json
{
  "timestamp": "2025-04-13T10:30:45Z",
  "level": "error",
  "message": "switch vlan transition failed",
  "device_serial": "device-001",
  "switch_name": "core-switch-01",
  "switch_port": "Eth1/3",
  "target_vlan": 200,
  "error": "switchmgmt: failed to set port Eth1/3 to vlan 200: command failed",
  "error_type": "switchmgmt.ErrPortVLANSetFailed"
}
```

## Testing the Workflow

### Unit tests
- Mock Manager confirms correct API calls
- Verify error handling without switch

### Integration tests
- Real switch (in devcontainer with OVS simulation)
- Full workflow from registration to activation
- Failure scenarios (switch down, invalid VLAN, etc.)

### Manual testing
```bash
# 1. Start platform with switch config
platformctl serve --config platform.yaml

# 2. Register device (simulate via REST)
curl -X POST https://localhost:8443/device/register \
  -d '{"serial": "test-001", ...}'

# 3. Place device on provisioning VLAN (manual or switch)
# 4. Device boots and calls POST /device/activate
# 5. Verify platform moved port to production VLAN

# Check switch:
ssh admin@10.0.1.50
show interfaces Eth1/3 switchport
# Verify: "Access Mode VLAN: 200"
```

## Workflow Diagrams (ASCII)

### Timeline

```
Time    Registration    Provisioning         Activation      Production
|
0h      ├─ Device      ├─ Download ISO
        │  registers   │
        │  "registered"│
        │              │
12m     │              ├─ Install OS
        │              │  Attestation
        │              │  Firstboot
        │              │
45m     │              ├─ "activated" state
        │              │
48m     │              ├─ Call /activate
        │              │  ├─ Switch VLAN: 100→200
        │              │  ├─ Policy applied
        │              │  └─ 200 OK
        │              │
        │              └─ Device joins prod network
        │                 "activated"
        │
        │              ├─ Optional: remote attestation
        │              │  "attested"
        │
        └──────────────┴──────────────────────┴─────────────────────>
                                              48m+                   ∞
                                         Production lifetime
```

### VLAN States

```
Device port state timeline:

Disconnected    Prov VLAN(100)    Prod VLAN(200)
    │                │                 │
    ├─ PXE boot ─────┤─ Install ──────┤─ Production
    │                │                 │
    │              Registration      Activation
    │                 Provisioning
    │              ├─ 12 minutes ─┤
    │
   ~0m             ~12m           ~45m              ∞
```

## Next Steps

After device is activated and in production:
- Continue with attestation (if required)
- Monitor device health
- Apply workload policies
- Manage certificate lifecycle
- Handle device deprovisioning (move to quarantine VLAN if needed)
