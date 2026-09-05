# Device Package

Device profile and provisioning management for the Trusted Platform.

## Overview

The device package provides:
- Device identity management (TPM-based attestation data)
- Device profile templates for network provisioning
- Profile matching rules for automatic device classification
- Network phase configuration (provisioning, production, quarantine)

## Package Structure

```
pkg/device/
+-- config.go           # Package configuration
+-- datastore.go        # Datastore factory
+-- service.go          # Device service (CRUD operations)
+-- profile_service.go  # Profile service (CRUD + matching)
+-- entities/
|   +-- device.go       # Device entity (TPM identity data)
|   +-- profile.go      # DeviceProfile entity (templates)
+-- dao/
    +-- types.go        # DAO interfaces
    +-- kvstore/        # Key-value store implementation
```

## Core Entities

### Device

Represents a physical or virtual device with TPM identity:

| Field | Type | Description |
|-------|------|-------------|
| ID | uint64 | Unique device identifier |
| Serial | string | Device serial number |
| Model | string | Device model/type |
| EKCert | string | Endorsement Key certificate (PEM) |
| AttestPub | string | Attestation public key (PEM) |
| AttestCert | string | Attestation (IAK/AK) certificate issued by the platform CA at enrollment (PEM); the quote trust anchor |
| SigningPub | string | Signing public key (PEM) |
| EventLog | []byte | TPM event log |
| HashAlgoId | uint32 | TPM hash algorithm ID |

### DeviceProfile

Template defining device behavior across network phases:

| Field | Type | Description |
|-------|------|-------------|
| ID | uint64 | Unique profile identifier |
| Name | string | Human-readable profile name |
| Model | string | Target device model |
| Role | DeviceRole | Device function (server, client, iot, etc.) |
| MatchRules | ProfileMatchRules | Auto-assignment criteria |
| ProvisioningNetwork | NetworkPhaseConfig | Initial enrollment network |
| ProductionNetwork | NetworkPhaseConfig | Full operational network |
| QuarantineNetwork | NetworkPhaseConfig | Isolation network |
| PlatformdConfig | PlatformdConfigRef | Platform daemon configuration |

### Device Roles

| Role | Description |
|------|-------------|
| control-plane | Platform control-plane node (bootstrap role) |
| gateway | Edge gateway node (bootstrap role) |
| worker | Platform worker node (bootstrap role) |
| server | Server workload |
| client | Client device |
| workstation | Developer/user workstation |
| edge | Edge computing node |
| iot | IoT/embedded device |
| load-balancer | Load balancer |

## Quick Start

### Device Service

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/device"
    "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// Create service
config := &device.Config{
    QuicBaaS: &quicbaas.Config{
        StorageBackend:   "pebble",
        DataDir:          "trusted-data/quicbaas",
        WALDir:           "trusted-data/quicbaas/wal",
        NodeID:           1,
        CacheSize:        64 * 1024 * 1024, // 64MB
        LogLevel:         "warn",
        ConsistencyLevel: quicbaas.ConsistencyLinearizable,
    },
    ShardID:   0, // Default shard
    Partition: "devices",
}

svc, err := device.NewService(config)
if err != nil {
    return err
}

// Save device
dev := &entities.Device{
    ID:     1,
    Serial: "SN-12345",
    Model:  "TrustedNode-v1",
    EKCert: ekCertPEM,
}
err = svc.Save(dev)

// Retrieve device
dev, err := svc.Get(1)

// Find by serial
dev, err := svc.FindBySerial("SN-12345")
```

### Profile Service

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/device"

svc, err := device.NewProfileService(config)
if err != nil {
    return err
}

// Create profile
profile := &entities.DeviceProfile{
    ID:    1,
    Name:  "IoT Sensor Profile",
    Model: "IoT-Sensor-v1",
    Role:  entities.DeviceRoleIoT,
    MatchRules: &entities.ProfileMatchRules{
        MACPrefix:    "52:54:00",
        SerialPrefix: "IOT-",
    },
    ProvisioningNetwork: &entities.NetworkPhaseConfig{
        VLAN:       998,
        AuthMethod: entities.AuthMethodNone,
    },
    ProductionNetwork: &entities.NetworkPhaseConfig{
        VLAN:       100,
        AuthMethod: entities.AuthMethod802_1X,
    },
}
err = svc.Save(profile)

// Find matching profile for device
profile, err := svc.FindMatchingProfile("52:54:00:aa:bb:cc", "IOT-001", "IoT-Sensor-v1")
```

## Profile Matching

Profiles are automatically matched to devices using `ProfileMatchRules`:

| Rule | Match Type | Example |
|------|------------|---------|
| MACPrefix | Prefix match | "52:54:00" matches "52:54:00:aa:bb:cc" |
| SerialPrefix | Prefix match | "SRV-" matches "SRV-001234" |
| Model | Exact match | "TrustedNode-v1" |
| ModelPattern | Pattern match (legacy) | "TrustedNode-*" |
| ManufacturerMatch | String match (legacy) | "Dell Inc." |
| TPMVendor | String match (legacy) | "STM" |

Match priority: First matching profile wins (ordered by ID ascending).

## Integration

### SDN Policy Engine

Device profiles integrate with the SDN policy engine for 802.1X network access:

```
Device connects
      |
      v
Profile Service.FindMatchingProfile()
      |
      v
Apply ProvisioningNetwork (VLAN 998)
      |
      v
Device enrolls (ACME/TPM attestation)
      |
      v
Apply ProductionNetwork (profile VLAN)
```

### Compute Orchestrator

Virtual machines use device profiles for network configuration:

```go
// VM provisioning
profile, _ := profileSvc.FindMatchingProfile(macAddr, "", "")
policyEngine.SetPortState(tapDevice, policy.PortStateProvisioning)
```

## Documentation

- [Architecture](architecture.md) - Device profile lifecycle and network phases
- [Configuration](configuration.md) - Configuration options reference
- [Network Setup](network-setup.md) - Client-side network configuration for device profile activation
- [API Reference](api-reference.md) - Device API endpoints
- [CLI Usage](cli-usage.md) - Command-line interface

## References

- [SDN Package](../sdn/README.md) - Network policy enforcement
- [802.1X Authentication](../sdn/802.1x.md) - Port-based authentication
