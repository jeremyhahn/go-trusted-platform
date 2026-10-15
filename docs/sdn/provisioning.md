# Device Provisioning Flow

> **Status: REFERENCE** · Last verified: 2026-10-15
> The SDN side of device provisioning.

## Overview

Device provisioning uses RFC 8555 (ACME) for certificate enrollment with
mTLS-authenticated profile retrieval. The flow ensures zero-trust network
access with explicit client activation.

## Network Phases

VLANs follow the environment numbering in
[configuration.md](configuration.md#zone-based-network-configuration); the
examples use environment 4.

| Phase | VLAN | Access | Purpose |
|-------|------|--------|---------|
| Provisioning | provisioning zone (405) | Limited | DHCP, DNS, TFTP, ACME enrollment |
| Admitted | the profile's admitted network | The zones of its role | Normal operation |
| Quarantine | quarantine zone (404) | Isolated | Zone mismatch, remediation |
| Blocked | N/A | None | Certificate expired or revoked |

## Provisioning Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                       PROVISIONING VLAN (405)                       │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Device boots, receives DHCP lease (10.4.5.x)                     │
│ 2. Device initiates ACME enrollment (enroll-01 challenge)           │
│ 3. Server validates TPM attestation, issues IDevID                  │
│ 4. SDNEnrollmentHook marks port as "enrolled"                       │
│ 5. Device uses IDevID for mTLS: GET /api/v1/device/profile          │
│ 6. Device receives full profile with admitted network config        │
│ 7. Device prepares for network transition                           │
│ 8. Device signals ready: POST /api/v1/device/activate               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                     ┌───────────▼───────────┐
                     │   SERVER ACTIVATES    │
                     │  - Transition port    │
                     │    to admitted        │
                     │  - Apply 802.1X       │
                     │    policy             │
                     │  - Update OVS flows   │
                     └───────────┬───────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────────┐
│                     ADMITTED VLAN (from profile)                    │
├─────────────────────────────────────────────────────────────────────┤
│ 9. Device applies admitted network config                           │
│ 10. Device operational on admitted network                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Detailed Step-by-Step

### Step 1: Device Boot

```
Device                             DHCP Server
   │                                     │
   │──── DHCPDISCOVER ──────────────────>│
   │<─── DHCPOFFER (10.4.5.x) ───────────│
   │──── DHCPREQUEST ───────────────────>│
   │<─── DHCPACK ────────────────────────│
   │                                     │
   │ Device now has IP in VLAN 405       │
```

### Step 2: ACME Enrollment

```
Device                             ACME Server
   │                                     │
   │──── GET /directory ────────────────>│
   │<─── Directory URLs ─────────────────│
   │                                     │
   │──── POST /newAccount ──────────────>│
   │<─── Account URL ────────────────────│
   │                                     │
   │──── POST /newOrder ────────────────>│
   │     (CSR with TPM attestation)      │
   │<─── Order URL + Challenges ─────────│
   │                                     │
   │──── POST /challenge ───────────────>│
   │     (enroll-01 response)            │
   │<─── Challenge validated ────────────│
   │                                     │
   │──── POST /finalize ────────────────>│
   │<─── Certificate URL ────────────────│
   │                                     │
   │──── GET /certificate ──────────────>│
   │<─── IDevID Certificate ─────────────│
```

### Step 3: Enrollment Hook

The ACME order-finalize hook (`NewSDNEnrollmentHookAdapter`,
`pkg/webservice/v1/registry.go`) calls the SDN enrollment hook for TCG CSR
enrollments only. In outline (`pkg/sdn/policy/enrollment_hook.go`):

```go
func (h *SDNEnrollmentHook) OnEnrollmentComplete(event *EnrollmentEvent) error {
    // Serialize against activation of the same serial
    unlock := h.LockSerial(event.ProductSerial)
    defer unlock()

    // 1. Find the device profile: by serial, then by the MAC behind the
    //    client IP (ARP)
    profile, err := h.findProfileBySerial(event.ProductSerial)
    if profile == nil {
        profile, err = h.findProfileByMAC(h.macExtractor(event.ClientIP))
    }

    // 2. Get port ID from MAC. A miss is not an error: the device enrolled
    //    before attaching to the fabric (e.g. over the management LAN).
    macAddr := h.macExtractor(event.ClientIP)
    portID, ok := h.GetPortByMAC(macAddr)
    if !ok {
        // Record the pending activation with the MAC and defer the
        // transition; activation resolves the port once it exists.
        h.pendingActivations.Store(event.ProductSerial, &PendingActivation{
            MAC: macAddr, Profile: profile, Certificate: event.Certificate,
        })
        return nil
    }

    // 3. Transition to Enrolled state (known port only)
    err = h.policyEngine.SetPortState(portID, PortStateEnrolled)

    // 4. Store pending activation (the MAC lets a deferred port be
    //    resolved at activation)
    h.pendingActivations.Store(event.ProductSerial, &PendingActivation{
        PortID: portID, MAC: macAddr, Profile: profile, Certificate: event.Certificate,
    })
    return nil
}
```

### Step 4: Profile Retrieval

```
Device                             Platform Server
   │                                     │
   │──── GET /api/v1/device/profile ────>│
   │     (mTLS with IDevID cert)         │
   │                                     │
   │<─── 200 OK ─────────────────────────│
   │     {                               │
   │       "serialNumber": "ABC123",     │
   │       "admittedNetwork": {          │
   │         "vlan": 100,                │
   │         "useDHCP": true,            │
   │         "gateway": "10.0.1.1"       │
   │       },                            │
   │       "acls": [...]                 │
   │     }                               │
```

### Step 5: Device Activation

```
Device                             Platform Server
   │                                     │
   │──── POST /api/v1/device/activate ──>│
   │     (mTLS with IDevID cert)         │
   │                                     │
   │     Server:                         │
   │     - Look up pending activation    │
   │     - Build admitted policy         │
   │     - Apply policy to port          │
   │     - Set VLAN via OVSDB            │
   │     - Install admitted flows        │
   │                                     │
   │<─── 200 OK ─────────────────────────│
   │     {                               │
   │       "status": "activated",        │
   │       "vlan": 100,                  │
   │       "transitionedAt": "..."       │
   │     }                               │
```

## Why This Design

### RFC 8555 Compliance

The ACME order finalize response contains only standard fields:
- Certificate URL
- Order status
- Finalized timestamp

No custom extensions or proprietary data in the ACME response.

### mTLS Profile Retrieval

Benefits of using IDevID for profile fetch:
1. **Authentication** - Proves device identity with newly issued cert
2. **Authorization** - Server validates cert before returning profile
3. **No Duplication** - Profile is single source of truth
4. **Immediate Use** - Validates IDevID works before network transition

### Explicit Activation

Client controls when network transition occurs:
- Can validate profile data first
- Can prepare local configuration
- Can handle errors gracefully
- No race conditions with server-initiated transitions

## REST API Endpoints

### GET /api/v1/device/profile

Retrieves device profile using mTLS with IDevID.

**Request:**
- Method: GET
- Authentication: mTLS with IDevID certificate
- Headers: Standard

**Response (200 OK):**
```json
{
  "serialNumber": "ABC123",
  "admittedNetwork": {
    "vlan": 100,
    "useDHCP": true,
    "gateway": "10.0.1.1",
    "dns": ["10.0.1.53"]
  },
  "provisioningNetwork": {
    "vlan": 405,
    "useDHCP": true
  },
  "acls": [
    {
      "name": "allow-internal",
      "priority": 100,
      "match": {"dst_network": "10.0.0.0/8"},
      "action": "permit"
    }
  ],
  "rateLimit": {
    "ingressMbps": 1000,
    "egressMbps": 1000
  }
}
```

`staticIP`, `gateway`, `dns`, `provisioningNetwork`, `acls` and `rateLimit`
are omitted when empty.

**Errors:**
| Code | Description |
|------|-------------|
| 400 | No device serial in the request context |
| 401 | No TLS, no client certificate, a certificate that does not verify for client auth, or no device serial in the certificate |
| 404 | Profile not found for device serial |
| 500 | Profile retrieval is not configured on this server |

### POST /api/v1/device/activate

Signals device is ready for the admitted network transition.

**Request:**
- Method: POST
- Authentication: mTLS with IDevID certificate
- Body: none (the handler does not read it)

**Response (200 OK):**
```json
{
  "status": "activated",
  "vlan": 100,
  "transitionedAt": "2025-01-15T10:30:00Z"
}
```

**Server Actions (validate-then-commit on one immutable plan):**
1. `LockSerial`: the whole sequence below runs under the hook's
   per-serial lock, which `OnEnrollmentComplete` also takes — a
   concurrent re-enrollment waits instead of replacing the pending
   activation mid-flight
2. `PrecheckActivation`: validate with no side effects — pending
   activation present, port resolvable (deferred to the device MAC when
   enrollment happened before any fabric attach), and a policy
   buildable from the profile. Returns an `ActivationPlan` reserving
   the exact pending-activation version and policy that were validated,
   plus a value-copy snapshot of the switch VLANs; a zone mismatch is
   recorded on the plan (`ExpectQuarantine`) — the sequence continues,
   but the physical port is not opened. Any precheck failure returns
   without changing anything anywhere
3. Validate the physical switch move (when configured) with no side
   effects: switch mapping, a provisioning network present with a VLAN
   distinct from the admitted VLAN (the one fail-closed revert target),
   and a resolvable switch manager. A profile without a provisioning
   network — or one whose provisioning and admitted VLANs are equal —
   refuses the activation outright before anything is committed; equal
   VLANs are also rejected (400) when the profile is created or updated,
   on every transport. Skipped for a quarantine plan
4. `ActivateDevice(plan)`: atomically consume the plan's reserved
   pending-activation version — a version replaced since the precheck is
   refused (`ErrPendingActivationSuperseded`) with nothing applied and
   the switch never touched — then apply the plan's policy and
   transition the port to Authorized. The plan fixes the policy, so the
   outcome never diverges from what the precheck reported. The physical
   port has not been opened yet: a slow or failed policy application
   admits no traffic
5. Commit the physical switch move strictly AFTER enforcement — the
   admitted VLAN opens only onto an enforced datapath, with every VLAN
   taken from the plan's value-copy snapshot. SSH command sequences are
   not atomic, so any switch failure triggers a move to the
   **provisioning VLAN** followed by a read-back verification: only a
   read-back showing the provisioning VLAN confirms the port closed
   (500, SDN authorized, physical port closed, pending activation
   reinstated — the device retries activation without re-enrolling);
   anything else is reported as "physical port state INDETERMINATE —
   operator action required"
6. A still-unregistered port returns 404 and retains the pending
   activation; the device retries after attaching to the fabric

**Errors:**
| Code | Description |
|------|-------------|
| 400 | No device serial in the request context |
| 401 | Invalid or missing client certificate |
| 404 | No pending activation for device (including a device already activated: a successful activation consumes it) |
| 404 | No port registered for the device MAC (not yet attached to the fabric — retry after attaching; the pending activation is retained) |
| 500 | Activation is not configured on this server (no SDN enrollment) |
| 500 | Failed to apply network policy |
| 500 | Pending activation superseded by a concurrent re-enrollment — nothing was applied, the switch was never touched; a retry prechecks the current record |
| 500 | Physical switch commit failed after SDN activation — SDN side authorized, physical port verified closed on the provisioning VLAN, pending activation reinstated (retry activation, no re-enrollment needed) |
| 500 | Certificate carries an unreadable network zone extension — invalid policy input is refused outright, never mapped to the trusted policy |
| 500 | Physical switch VLAN transition failed (port reverted; read-back confirmed it closed) |
| 500 | Physical port state INDETERMINATE — the revert or read-back could not confirm the port closed; operator action required |
| 500 | Zone mismatch requires quarantine but the profile declares no quarantine or provisioning VLAN, or its quarantine VLAN equals the admitted VLAN — activation refused, nothing committed |
| 500 | Zone mismatch requires quarantine but the engine has no zone flow manager to enforce it — hard failure, physical port reverted |
| 500 | Quarantine policy applied but the port state could not be marked quarantined — state INDETERMINATE, pending activation retained, operator action required |

`status` is the outcome actually applied (`activated` or `quarantined`) and
`vlan` is the VLAN the port was actually placed on — the quarantine VLAN
when `status` is `quarantined`, never the admitted VLAN.

## Port State Transitions

```go
const (
    PortStateUnconnected   PortState = iota
    PortStateProvisioning  // Provisioning VLAN, limited access
    PortStateEnrolled      // Still on the provisioning VLAN, awaiting activation
    PortStateUnauthorized  // 802.1X: not authenticated
    PortStateAuthenticating // 802.1X: authentication in progress
    PortStateAuthorized    // Admitted, the zones of its role
    PortStateQuarantined   // Quarantine VLAN, remediation required
    PortStateBlocked       // DROP all traffic
)
```

### State Machine

The provisioning path (`pkg/sdn/policy/state.go`; the 802.1X states are in
[802.1x.md](802.1x.md)):

```
                 device_connect
Unconnected ──────────────────────────> Provisioning <──────────────┐
                                              │                     │
                                              │ enrollment_complete │ re-enroll
                                              ▼                     │
                                          Enrolled ─────────────────┤
                                              │                     │
                                              │ client_activates    │
                                              ▼                     │
                                         Authorized <─────────────┐ │
                                              │                   │ │
                                 zone mismatch│                   │ remediation
                                 at activation│                   │ complete
                                              ▼                   │ │
                                        Quarantined ──────────────┘ │
                                              │  └──────────────────┘
                                              │ remediation fails
                                              ▼
                                           Blocked ──> Unconnected / Provisioning (admin)
```

An expired or revoked certificate moves an Authorized port straight to
Blocked. Any state can move to Blocked.

## Provisioning Network Flows

The provisioning zone's OpenFlow rules (ARP, DHCP, DNS, TFTP, ACME, package
repositories, optional ICMP, default drop) are listed with their priorities
in [configuration.md](configuration.md#per-zone-openflow-templates).

## Client Implementation

`pkg/provisioning` is the device-side client for both endpoints:

```go
// After receiving the IDevID from ACME enrollment:
client, err := provisioning.NewClient(&provisioning.ClientConfig{
    ServerURL:      "https://platform.example.com:8443",
    Certificate:    idevidCert,
    PrivateKey:     idevidKey,
    CACertPool:     caCertPool,
    TLSCertificate: &idevidChain, // leaf plus intermediates
}, logger)
if err != nil {
    return err
}
defer func() {
    if err := client.Close(); err != nil {
        logger.Warn("closing provisioning client", "error", err)
    }
}()

// GET /api/v1/device/profile, then POST /api/v1/device/activate
profile, activation, err := client.FetchProfileAndActivate(ctx)
if err != nil {
    return err
}

// "activated": apply profile.AdmittedNetwork.
// "quarantined": the port is on activation.VLAN, the quarantine VLAN.
applyNetworkConfig(profile.AdmittedNetwork, activation)
```

`FetchProfile`, `Activate`, `Heartbeat` and `BootDelivery` are also available
on their own.

## Security Considerations

1. **Provisioning Network Isolation** - the provisioning zone reaches only DHCP, DNS, TFTP, ACME and package repositories
2. **mTLS Required** - Profile endpoint requires valid IDevID
3. **No Unauthenticated Access** - All device data requires certificate auth
4. **Server-Side Transition** - Client cannot force VLAN change
5. **Attestation Required** - IDevID only issued after TPM attestation
6. **MAC Binding** - the pending activation records the device MAC seen at enrollment

## Error Recovery

### Enrollment Failure

If enrollment fails, device remains in provisioning VLAN:
1. Device can retry enrollment
2. No network disruption (still has DHCP/DNS)
3. Error logged on server for debugging

### Activation Failure

If activation fails:
1. Device remains in enrolled state
2. Can retry activation
3. Server rolls back partial policy application

### Network Transition Failure

If network transition fails after activation:
1. Device may lose connectivity briefly
2. Device should retry profile fetch and activation
3. A failed physical switch commit leaves the port closed on the provisioning
   VLAN and reinstates the pending activation; there is no server-side timeout

## Monitoring

No provisioning metrics are exported. The hook and the activation handler log
each step:

```
level=INFO msg="device enrolled successfully, awaiting activation" port_id=... previous_state=... new_state=enrolled serial=ABC123
level=INFO msg="activating device" serial=ABC123 port_id=... profile=...
Device ABC123 activation complete: status=activated vlan=100 zone=... port=...
SDN activation failed for device ABC123: ...
```
