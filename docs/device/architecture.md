# Device Architecture

## Overview

The device package manages device identity and provisioning profiles within
the Trusted Platform. It provides the data layer for TPM-based device
attestation and network phase configuration.

## Component Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            Device Package                                │
│  (pkg/device)                                                            │
│                                                                          │
│  ┌─────────────────────┐  ┌────────────────────────┐                     │
│  │ Device Service      │  │ Profile Service        │                     │
│  │ • Save/Get/Delete   │  │ • Save/Get/Delete      │                     │
│  │ • FindBySerial      │  │ • FindByMACPrefix      │                     │
│  │ • Pagination        │  │ • FindBySerialPrefix   │                     │
│  └──────────┬──────────┘  │ • FindMatchingProfile  │                     │
│             │             └──────────┬─────────────┘                     │
│             │                        │                                   │
│  ┌──────────▼────────────────────────▼─────────────┐                     │
│  │                    Datastore                    │                     │
│  │  • Factory for DAO implementations              │                     │
│  │  • Supports Local/Memory backends               │                     │
│  └─────────────────────┬───────────────────────────┘                     │
│                        │                                                 │
│  ┌─────────────────────▼───────────────────────────┐                     │
│  │                  DAO Layer                      │                     │
│  │  ┌──────────────────┐  ┌─────────────────────┐  │                     │
│  │  │ DeviceDAO        │  │ DeviceProfileDAO    │  │                     │
│  │  │ • GenericDAO     │  │ • GenericDAO        │  │                     │
│  │  │ • FindBySerial   │  │ • FindByMACPrefix   │  │                     │
│  │  └──────────────────┘  │ • FindBySerialPrefix│  │                     │
│  │                        │ • FindMatchingProfile│ │                     │
│  │                        └─────────────────────┘  │                     │
│  └─────────────────────────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Device Lifecycle

### Device Registration

```
┌─────────────────────┐
│    Device Boot      │
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  TPM Attestation    │  EK cert, AK, event log
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  Device.Save()      │  Store identity in datastore
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  Profile Matching   │  FindMatchingProfile(MAC, Serial, Model)
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  Network Phase      │  Apply ProvisioningNetwork config
└─────────────────────┘
```

### Device Entity Fields

```go
type Device struct {
    ID         uint64  // Unique identifier (snowflake ID)
    Serial     string  // Hardware serial number
    Model      string  // Device model identifier
    EKCert     string  // TPM Endorsement Key certificate (PEM)
    AttestPub  string  // TPM Attestation Key public (PEM)
    SigningPub string  // TPM Signing Key public (PEM)
    EventLog   []byte  // TPM PCR event log
    HashAlgoId uint32  // TPM hash algorithm (SHA-256, SHA-384, etc.)
}
```

## Profile Lifecycle

### Profile Creation

Profiles define templates for device classes:

```
Administrator creates profile
           │
           ▼
┌──────────┴──────────┐
│  Define MatchRules  │  MAC prefix, serial prefix, model
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  Configure Network  │  Provisioning, Production, Quarantine
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  Set Platform Cfg   │  platformd configuration reference
└──────────┬──────────┘
           │
           ▼
┌──────────┴──────────┐
│  ProfileSvc.Save()  │  Persist to datastore
└─────────────────────┘
```

### Profile Matching Flow

```
Device connects with MAC: 52:54:00:aa:bb:cc
                    │
                    ▼
    ┌───────────────┴────────────────────────────┐
    │ ProfileService.FindMatchingProfile()       │
    └───────────────┬────────────────────────────┘
                    │
    ┌───────────────▼────────────────────────────┐
    │ Iterate profiles (ID ascending)            │
    │   For each profile:                        │
    │     Check MatchRules.Matches(mac, serial,  │
    │                              model)        │
    │       - MACPrefix match?                   │
    │       - SerialPrefix match?                │
    │       - Model match?                       │
    └───────────────┬────────────────────────────┘
                    │
          ┌─────────┴─────────┐
          │                   │
    Match found         No match
          │                   │
          ▼                   ▼
    Return profile      Return ErrRecordNotFound
```

## Network Phases

Devices transition through network phases during their lifecycle:

### Phase Diagram

```
                     device_connect
 ┌───────────────┐  ─────────────────▶  ┌──────────────────┐
 │  Unconnected  │                      │ Provisioning     │
 └───────────────┘                      │ VLAN: 998        │
                                        │ Limited access   │
                                        └────────┬─────────┘
                                                 │
                                                 │ enrollment_complete
                                                 ▼
                                        ┌────────┴─────────┐
                                        │ Production       │
                                        │ VLAN: profile    │
                                        │ Full access      │
                                        └────────┬─────────┘
                                                 │
                              cert_expired/      │
                              compliance_fail    │
                                                 ▼
                                        ┌────────┴─────────┐
                                        │ Quarantine       │
                                        │ VLAN: 666        │
                                        │ Remediation      │
                                        └──────────────────┘
```

### Network Phase Configuration

Each phase has independent network settings:

```go
type NetworkPhaseConfig struct {
    VLAN       uint16           // VLAN ID for this phase
    DHCPPool   *DHCPPoolConfig  // Optional DHCP settings
    StaticIP   string           // Optional static IP
    Gateway    string           // Default gateway
    DNS        []string         // DNS servers
    AuthMethod AuthMethod       // none or 802.1x
    ACLs       []ACLConfig      // Access control rules
}
```

### Phase Characteristics

| Phase | VLAN | Access | Authentication |
|-------|------|--------|----------------|
| Provisioning | 998 | DHCP, DNS, HTTPS to platform | None |
| Production | Profile-defined | Per ACLs | 802.1X (IDevID cert) |
| Quarantine | 666 | Remediation portal only | None |

## Data Storage

### Partition Structure

```
trusted-data/datastore/devices/
├── {device_id}.json          # Device entities
└── profiles/
    └── {profile_id}.json     # Profile entities
```

### Storage Backends

| Backend | Description | Use Case |
|---------|-------------|----------|
| LOCAL | Filesystem-based | Production |
| MEMORY | In-memory | Testing |

### Consistency Levels

| Level | Description |
|-------|-------------|
| local | Read from local store only |
| eventual | Allow stale reads |
| strong | Require latest data |

## Thread Safety

- Services are thread-safe via underlying DAO implementation
- DAOs use mutex protection for concurrent access
- Pagination uses snapshot isolation

## Error Handling

All errors are typed:

```go
var (
    ErrInvalidDeviceID  = fmt.Errorf("invalid device ID")
    ErrInvalidProfileID = fmt.Errorf("invalid profile ID")
)

// From datastore package
var (
    ErrRecordNotFound = errors.New("record not found")
    ErrStopIteration  = errors.New("stop iteration")
)
```

## Integration Points

### SDN Policy Engine

```go
// Profile informs network policy
profile, _ := profileSvc.FindMatchingProfile(mac, serial, model)
portPolicy := &policy.PortPolicy{
    VLAN: profile.ProductionNetwork.VLAN,
    ACLs: convertACLs(profile.ProductionNetwork.ACLs),
}
engine.ApplyPolicy(portID, portPolicy)
```

### Compute Orchestrator

```go
// VM gets profile-based networking
profile, _ := profileSvc.FindMatchingProfile(vmMAC, "", vmModel)
tapConfig := &TAPConfig{
    VLAN:     profile.ProvisioningNetwork.VLAN,
    AuthMode: profile.ProvisioningNetwork.AuthMethod,
}
```

### ACME Enrollment

```go
// Device profile determines enrollment parameters
profile, _ := profileSvc.FindMatchingProfile(mac, serial, model)
enrollmentConfig := profile.PlatformdConfig
```

## Performance Considerations

- Profile matching iterates all profiles (O(n))
- Use specific match rules to reduce false positives
- Pagination limits memory usage for large datasets
- Consider caching frequently accessed profiles
