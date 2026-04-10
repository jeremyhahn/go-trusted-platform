# Device Provisioning Flow

## Overview

Device provisioning uses RFC 8555 (ACME) for certificate enrollment with
mTLS-authenticated profile retrieval. The flow ensures zero-trust network
access with explicit client activation.

## Network Phases

| Phase | VLAN | Access | Purpose |
|-------|------|--------|---------|
| Provisioning | 7 | Limited | ACME enrollment only |
| Production | Profile-defined | Full | Normal operation |
| Quarantine | 6 | Isolated | Compliance remediation |
| Blocked | N/A | None | Certificate revoked |

## Provisioning Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     PROVISIONING VLAN (7)                       │
├─────────────────────────────────────────────────────────────────┤
│ 1. Device boots, receives DHCP lease (172.16.7.x)               │
│ 2. Device initiates ACME enrollment (enroll-01 challenge)       │
│ 3. Server validates TPM attestation, issues IDevID              │
│ 4. SDNEnrollmentHook marks port as "enrolled"                   │
│ 5. Device uses IDevID for mTLS: GET /api/v1/device/profile      │
│ 6. Device receives full profile with production network config  │
│ 7. Device prepares for network transition                       │
│ 8. Device signals ready: POST /api/v1/device/activate           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   SERVER ACTIVATES    │
                    │  1. Transition port   │
                    │     to production     │
                    │  2. Apply 802.1X      │
                    │  3. Update flows      │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                   PRODUCTION VLAN (from profile)                │
├─────────────────────────────────────────────────────────────────┤
│ 9. Device applies production network config                     │
│ 10. Device operational on production network                    │
└─────────────────────────────────────────────────────────────────┘
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

**Response:**
```json
{
  "serialNumber": "ABC123",
  "productionNetwork": {
    "vlan": 11,
    "useDHCP": true,
    "staticIP": "",
    "gateway": "172.16.11.1",
    "dns": ["172.16.5.1"]
  },
  "acls": [
    {
      "name": "allow-internal",
      "priority": 100,
      "match": {"dst_network": "172.16.0.0/16"},
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
- 401: Invalid or missing client certificate
- 403: Certificate not authorized for this device
- 404: Profile not found for device serial

### POST /api/v1/device/activate

Signals device is ready for production network transition.

**Request:**
- Method: POST
- Authentication: mTLS with IDevID certificate
- Body: Empty or optional metadata

**Response:**
```json
{
  "status": "activated",
  "vlan": 11,
  "transitionedAt": "2025-01-15T10:30:00Z"
}
```

**Server Actions:**
1. Look up device port by MAC (via ARP table from client IP)
2. Get device profile for VLAN configuration
3. Transition OVS port to production VLAN
4. Apply production OpenFlow rules
5. Update port state to Authorized

## Port State Transitions

```go
const (
    PortStateUnconnected   PortState = iota
    PortStateProvisioning  // VLAN 7, limited access
    PortStateEnrolled      // Still VLAN 7, awaiting activation
    PortStateAuthorized    // Production VLAN, full access
    PortStateQuarantined   // VLAN 6, remediation required
    PortStateBlocked       // DROP all traffic
)
```

### State Machine

```
                 device_connect
Unconnected ─────────────────────> Provisioning
                                         │
                                         │ enrollment_complete
                                         ▼
                                     Enrolled
                                         │
                                         │ client_activates
                                         ▼
                                    Authorized <────────────┐
                                         │                  │
                           cert_expired/ │                  │ remediation
                           compliance    │                  │ complete
                                         ▼                  │
                                   Quarantined ─────────────┘
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
var profile DeviceProfile
json.NewDecoder(resp.Body).Decode(&profile)

// 3. Prepare for network transition
saveProductionConfig(profile.ProductionNetwork)

// 4. Signal ready for activation
resp, err = client.Post("https://platform.example.com/api/v1/device/activate", nil, nil)

// 5. Server has transitioned port - apply new network config
time.Sleep(500 * time.Millisecond) // Allow OVS transition
applyNetworkConfig(profile.ProductionNetwork)

// 6. Verify connectivity on production network
waitForConnectivity(profile.ProductionNetwork.Gateway)
```

## Security Considerations

1. **Provisioning Network Isolation** - VLAN 7 only reaches platform server
2. **mTLS Required** - Profile endpoint requires valid IDevID
3. **No Unauthenticated Access** - All device data requires certificate auth
4. **Server-Side Transition** - Client cannot force VLAN change
5. **Attestation Required** - IDevID only issued after TPM attestation
