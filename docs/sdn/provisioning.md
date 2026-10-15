# Device Provisioning Flow

> **Status: REFERENCE**
> The SDN side of device provisioning.

## Overview

Device provisioning uses RFC 8555 (ACME) for certificate enrollment with
mTLS-authenticated profile retrieval. The flow ensures zero-trust network
access with explicit client activation.

## Network Phases

| Phase | VLAN | Access | Purpose |
|-------|------|--------|---------|
| Provisioning | 998 | Limited | ACME enrollment only |
| Production | Profile-defined | Full | Normal operation |
| Quarantine | 666 | Isolated | Compliance remediation |
| Blocked | N/A | None | Certificate revoked |

## Provisioning Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                       PROVISIONING VLAN (998)                       │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Device boots, receives DHCP lease (10.99.98.x)                   │
│ 2. Device initiates ACME enrollment (enroll-01 challenge)           │
│ 3. Server validates TPM attestation, issues IDevID                  │
│ 4. SDNEnrollmentHook marks port as "enrolled"                       │
│ 5. Device uses IDevID for mTLS: GET /api/v1/device/profile          │
│ 6. Device receives full profile with production network config      │
│ 7. Device prepares for network transition                           │
│ 8. Device signals ready: POST /api/v1/device/activate               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                     ┌───────────▼───────────┐
                     │   SERVER ACTIVATES    │
                     │  - Transition port    │
                     │    to production      │
                     │  - Apply 802.1X       │
                     │    policy             │
                     │  - Update OVS flows   │
                     └───────────┬───────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────────┐
│                    PRODUCTION VLAN (from profile)                   │
├─────────────────────────────────────────────────────────────────────┤
│ 9. Device applies production network config                         │
│ 10. Device operational on production network                        │
└─────────────────────────────────────────────────────────────────────┘
```

## Detailed Step-by-Step

### Step 1: Device Boot

```
Device                             DHCP Server
   │                                     │
   │──── DHCPDISCOVER ──────────────────>│
   │<─── DHCPOFFER (10.99.98.x) ─────────│
   │──── DHCPREQUEST ───────────────────>│
   │<─── DHCPACK ────────────────────────│
   │                                     │
   │ Device now has IP in VLAN 998       │
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

```go
// SDN enrollment hook triggered
func (h *SDNEnrollmentHook) OnEnrollmentComplete(event *EnrollmentEvent) error {
    // 1. Extract MAC from client IP via ARP
    macAddr := h.macExtractor(event.ClientIP)

    // 2. Look up device profile
    profile, err := h.findProfileBySerial(event.ProductSerial)

    // 3. Get port ID from MAC. A miss is not an error: the device enrolled
    //    before attaching to the fabric (e.g. over the management LAN).
    portID, ok := h.GetPortByMAC(macAddr)
    if !ok {
        // Record the pending activation with the MAC and defer the
        // transition; activation resolves the port once it exists.
        h.pendingActivations.Store(event.ProductSerial, &PendingActivation{
            MAC:         macAddr,
            Profile:     profile,
            Certificate: event.Certificate,
        })
        return nil
    }

    // 4. Transition to Enrolled state (known port only)
    err = h.policyEngine.SetPortState(portID, PortStateEnrolled)

    // 5. Store pending activation (the MAC lets a deferred port be
    //    resolved at activation)
    h.pendingActivations.Store(event.ProductSerial, &PendingActivation{
        PortID:      portID,
        MAC:         macAddr,
        Profile:     profile,
        Certificate: event.Certificate,
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
   │       "productionNetwork": {        │
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
   │     - Build production policy       │
   │     - Apply policy to port          │
   │     - Set VLAN via OVSDB            │
   │     - Install production flows      │
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
  "productionNetwork": {
    "vlan": 100,
    "useDHCP": true,
    "staticIP": "",
    "gateway": "10.0.1.1",
    "dns": ["10.0.1.53"]
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

**Errors:**
| Code | Description |
|------|-------------|
| 401 | Invalid or missing client certificate |
| 403 | Certificate not authorized for this device |
| 404 | Profile not found for device serial |

### POST /api/v1/device/activate

Signals device is ready for production network transition.

**Request:**
- Method: POST
- Authentication: mTLS with IDevID certificate
- Body: Empty or optional metadata

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
| 401 | Invalid or missing client certificate |
| 404 | No pending activation for device |
| 404 | No port registered for the device MAC (not yet attached to the fabric — retry after attaching; the pending activation is retained) |
| 409 | Device already activated |
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
    PortStateProvisioning  // VLAN 998, limited access
    PortStateEnrolled      // Still VLAN 998, awaiting activation
    PortStateAuthorized    // Production VLAN, full access
    PortStateQuarantined   // VLAN 666, remediation required
    PortStateBlocked       // DROP all traffic
)
```

### State Machine

```
                 device_connect
Unconnected ──────────────────────────> Provisioning
                                              │
                                              │ enrollment_complete
                                              ▼
                                          Enrolled
                                              │
                                              │ client_activates
                                              ▼
                                         Authorized <─────────────┐
                                              │                   │
                                cert_expired/ │                   │ remediation
                                compliance    │                   │ complete
                                              ▼                   │
                                        Quarantined ──────────────┘
                                              │
                                              │ cert_revoked
                                              ▼
                                           Blocked
```

## Provisioning Network Flows

OVS flows for provisioning VLAN allow limited access:

```
# DHCP (UDP 67, 68)
priority=100,udp,tp_dst=67,actions=normal
priority=100,udp,tp_dst=68,actions=normal

# DNS (UDP/TCP 53, 8053)
priority=100,udp,tp_dst=53,actions=normal
priority=100,tcp,tp_dst=53,actions=normal
priority=100,udp,tp_dst=8053,actions=normal
priority=100,tcp,tp_dst=8053,actions=normal

# HTTPS to platform server (443, 8443)
priority=100,tcp,tp_dst=443,actions=normal
priority=100,tcp,tp_dst=8443,actions=normal

# Drop all other traffic
priority=0,actions=drop
```

## Client Implementation

```go
// After receiving IDevID from ACME enrollment:

// 1. Create mTLS client with IDevID
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{idevidCert},
    RootCAs:      caCertPool,
}
client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

// 2. Fetch device profile
resp, err := client.Get("https://platform.example.com/api/v1/device/profile")
if err != nil {
    return err
}
var profile DeviceProfile
json.NewDecoder(resp.Body).Decode(&profile)

// 3. Prepare for network transition
saveProductionConfig(profile.ProductionNetwork)

// 4. Signal ready for activation
resp, err = client.Post("https://platform.example.com/api/v1/device/activate",
    "application/json", nil)
if err != nil {
    return err
}

// 5. Server has transitioned port - apply new network config
time.Sleep(500 * time.Millisecond) // Allow OVS transition
applyNetworkConfig(profile.ProductionNetwork)

// 6. Verify connectivity on production network
if err := waitForConnectivity(profile.ProductionNetwork.Gateway); err != nil {
    return err
}

log.Println("Successfully transitioned to production network")
```

## Security Considerations

1. **Provisioning Network Isolation** - VLAN 998 only reaches platform server
2. **mTLS Required** - Profile endpoint requires valid IDevID
3. **No Unauthenticated Access** - All device data requires certificate auth
4. **Server-Side Transition** - Client cannot force VLAN change
5. **Attestation Required** - IDevID only issued after TPM attestation
6. **Certificate Binding** - MAC address bound to certificate during enrollment

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
3. Server-side timeout returns port to provisioning

## Monitoring

### Key Metrics

| Metric | Description |
|--------|-------------|
| provisioning_duration | Time from boot to enrollment |
| enrollment_success_rate | Successful enrollments / attempts |
| activation_duration | Time from enrollment to activation |
| transition_failures | Failed network transitions |

### Log Events

```json
{"level":"info","msg":"device enrolled","serial":"ABC123","port":"eth1","vlan":998}
{"level":"info","msg":"device activated","serial":"ABC123","port":"eth1","vlan":100}
{"level":"warn","msg":"activation failed","serial":"ABC123","error":"..."}
```
