# Device Provisioning Flow

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Archived 2026-08-18. This file lived beside a lower-case sibling of the
> same name in `docs/sdn/`, which makes the repository impossible to check
> out on a case-insensitive filesystem — and this repository publishes to a
> public host where contributors have those. Its content is a strict subset
> of the surviving file: same title, same section structure, fewer sections.
>
> **Superseded by:** `docs/sdn/provisioning.md`


## Overview

Device provisioning uses RFC 8555 (ACME) for certificate enrollment with
mTLS-authenticated profile retrieval. The flow ensures zero-trust network
access with explicit client activation.

## Network Phases

Policy is driven by **zones**, not VLAN numbers (see
[reference-network.md](../architecture/reference-network.md) for the
authoritative zone taxonomy and default VLAN assignments). The table below
shows the default segment IDs; all values are configurable.

| Phase | Zone | Default VLAN | Access | Purpose |
|-------|------|:------------:|--------|---------|
| Provisioning | `provisioning` | 201 | Limited | ACME enrollment only |
| Trusted | `trusted` | 200 | Full (per profile) | Normal operation |
| Quarantine | `quarantine` | 202 | Isolated | Compliance remediation |
| Blocked | n/a | n/a | None | Certificate revoked |

## Provisioning Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              PROVISIONING ZONE (default VLAN 201)               │
├─────────────────────────────────────────────────────────────────┤
│ 1. Device boots, receives DHCP lease                            │
│ 2. Device initiates ACME enrollment (enroll-01 challenge)       │
│ 3. Server validates TPM attestation, issues IDevID              │
│ 4. SDNEnrollmentHook marks port as "enrolled"                   │
│ 5. Device uses IDevID for mTLS: GET /api/v1/device/profile      │
│ 6. Device receives full profile with zone + network config      │
│ 7. Device prepares for zone transition                          │
│ 8. Device signals ready: POST /api/v1/device/activate           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   SERVER ACTIVATES    │
                    │  1. Transition port   │
                    │     to profile zone   │
                    │  2. Apply zone flows  │
                    │  3. Update OVS VLAN   │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│          PROFILE ZONE (default: trusted, VLAN per profile)      │
├─────────────────────────────────────────────────────────────────┤
│ 9. Device applies network config from profile                   │
│ 10. Device operational on profile zone network                  │
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
    "zone": "trusted",
    "vlan": 200,
    "useDHCP": true,
    "staticIP": "",
    "gateway": "198.18.0.1",
    "dns": ["198.18.0.1"]
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

Signals device is ready for zone-based network transition.

**Request:**
- Method: POST
- Authentication: mTLS with IDevID certificate
- Body: Empty or optional metadata

**Response:**
```json
{
  "status": "activated",
  "zone": "trusted",
  "vlan": 200,
  "transitionedAt": "2025-01-15T10:30:00Z"
}
```

**Server Actions:**
1. Look up device port by MAC (via ARP table from client IP)
2. Get device profile for zone + VLAN configuration
3. Transition OVS port to the profile zone (ZoneFlowManager.ApplyZoneFlows)
4. Apply per-zone OpenFlow template rules + inter-zone matrix rules
5. Update port state to Authorized

## Port State Transitions

```go
const (
    PortStateUnconnected   PortState = iota
    PortStateProvisioning  // provisioning zone (default VLAN 201), limited access
    PortStateEnrolled      // still provisioning zone, awaiting activation
    PortStateAuthorized    // profile zone (e.g. trusted VLAN 200), full access
    PortStateQuarantined   // quarantine zone (default VLAN 202), remediation required
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

OVS flows for the provisioning zone enforce least-privilege access. The full
rule set is generated by `pkg/sdn/policy/zoneflows` (provisioning template).
Representative rules:

```
# ARP
priority=1900,arp,dl_vlan=201,actions=normal

# DHCP (UDP 67, 68)
priority=1850,udp,dl_vlan=201,tp_src=68,tp_dst=67,actions=normal

# DNS (UDP/TCP 53, 8053, 9053)
priority=1800,udp,dl_vlan=201,tp_dst=53,actions=normal
priority=1800,tcp,dl_vlan=201,tp_dst=53,actions=normal

# ACME/HTTPS to platform server (443, 8443, 9443)
priority=1700,tcp,dl_vlan=201,tp_dst=443,actions=normal
priority=1700,tcp,dl_vlan=201,tp_dst=8443,actions=normal

# Default drop
priority=900,dl_vlan=201,actions=drop
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

// 3. Prepare for zone transition
saveNetworkConfig(profile.ProductionNetwork)

// 4. Signal ready for activation
resp, err = client.Post("https://platform.example.com/api/v1/device/activate",
    "application/json", nil)

// 5. Apply new network config once server confirms activation
if resp.StatusCode == http.StatusOK {
    applyNetworkConfig(profile.ProductionNetwork)
    waitForConnectivity(profile.ProductionNetwork.Gateway)
}
```

## Security Considerations

1. **Zone Isolation** - provisioning zone only reaches required CP services (DHCP/DNS/ACME)
2. **mTLS Required** - Profile endpoint requires valid IDevID; SC-7, AC-4
3. **No Unauthenticated Access** - All device data requires certificate auth
4. **Server-Side Transition** - Client cannot force zone/VLAN change
5. **Attestation Required** - IDevID only issued after TPM attestation
6. **Zone Mismatch Quarantine** - Certificate zone vs. profile zone cross-check; mismatch → quarantine zone; SC-7, SC-4, AC-4
