# Device Configuration Reference

## Overview

Configuration options for the device package, including QuicBaaS storage settings,
entity fields, and profile definitions.

## Package Configuration

### Config Structure

```go
type Config struct {
    QuicBaaS  *quicbaas.Config `yaml:"quicbaas" json:"quicbaas" mapstructure:"quicbaas"`
    ShardID   uint64           `yaml:"shard-id" json:"shard_id" mapstructure:"shard-id"`
    Partition string           `yaml:"partition" json:"partition" mapstructure:"partition"`
}
```

### Default Configuration

```go
var DefaultConfig = Config{
    QuicBaaS: &quicbaas.Config{
        StorageBackend:   "pebble",
        DataDir:          "trusted-data/quicbaas",
        WALDir:           "trusted-data/quicbaas/wal",
        NodeID:           1,
        CacheSize:        64 * 1024 * 1024, // 64MB
        LogLevel:         "warn",
        ConsistencyLevel: quicbaas.ConsistencyLinearizable,
    },
    ShardID:   0,
    Partition: "devices",
}
```

### QuicBaaS Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| StorageBackend | string | "pebble" | Storage backend (memory, file, pebble, raft) |
| DataDir | string | "trusted-data/quicbaas" | Data directory for QuicBaaS files |
| WALDir | string | "trusted-data/quicbaas/wal" | Write-ahead log directory |
| NodeID | uint64 | 1 | Node ID for Raft cluster (raft backend only) |
| CacheSize | int64 | 67108864 | In-memory cache size in bytes (64MB) |
| LogLevel | string | "warn" | Logging level (debug, info, warn, error) |
| ConsistencyLevel | ConsistencyLevel | Linearizable | Read consistency (linearizable, strong, eventual) |
| RaftAddress | string | "" | Raft cluster address (raft backend only) |

### Service-specific Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| ShardID | uint64 | 0 | QuicBaaS shard ID for device data |
| Partition | string | "devices" | Partition name for disk isolation |

### YAML Configuration

```yaml
device:
  quicbaas:
    storage-backend: pebble
    data-dir: trusted-data/quicbaas
    wal-dir: trusted-data/quicbaas/wal
    node-id: 1
    cache-size: 67108864
    log-level: warn
    consistency-level: linearizable
  shard-id: 0
  partition: devices
```

## Device Entity

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| ID | uint64 | id | id | Unique identifier |
| Serial | string | serial | serial | Hardware serial number |
| Model | string | model | model | Device model identifier |
| EKCert | string | ek-cert | ek_cert | TPM EK certificate (PEM) |
| AttestPub | string | att-pub | att_pub | TPM AK public key (PEM) |
| SigningPub | string | signing-pub | signing_pub | TPM SK public key (PEM) |
| EventLog | []byte | event-log | event_log | TPM event log |
| HashAlgoId | uint32 | hash-algo | hash_algo | TPM hash algorithm ID |

### Example Device (JSON)

```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "att_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "signing_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "hash_algo": 11
}
```

## Device Profile Entity

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| ID | uint64 | id | id | Unique identifier |
| Name | string | name | name | Human-readable name |
| Model | string | model | model | Target device model |
| Role | DeviceRole | role | role | Device function |
| EventLog | []byte | eventLog | eventLog | Reference event log |
| MatchRules | ProfileMatchRules | match-rules | match_rules | Auto-assignment criteria |
| ProvisioningNetwork | NetworkPhaseConfig | provisioning-network | provisioning_network | Enrollment network config |
| ProductionNetwork | NetworkPhaseConfig | production-network | production_network | Operational network config |
| QuarantineNetwork | NetworkPhaseConfig | quarantine-network | quarantine_network | Isolation network config |
| PlatformdConfig | PlatformdConfigRef | platformd | platformd | Platform daemon config |

### Device Roles

| Role | Value | Description |
|------|-------|-------------|
| Unknown | "unknown" | Unclassified device |
| Server | "server" | Server workload |
| Client | "client" | Client device |
| Workstation | "workstation" | Developer/user workstation |
| Edge | "edge" | Edge computing node |
| IoT | "iot" | IoT/embedded device |
| Gateway | "gateway" | Network gateway |
| LoadBalancer | "load-balancer" | Load balancer |

## Profile Match Rules

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| MACPrefix | string | mac_prefix | mac_prefix | MAC address prefix (e.g., "52:54:00") |
| SerialPrefix | string | serial_prefix | serial_prefix | Serial number prefix |
| Model | string | model | model | Exact model match |
| ModelPattern | string | model_pattern | model_pattern | Model pattern (legacy) |
| SerialPattern | string | serial_pattern | serial_pattern | Serial pattern (legacy) |
| ManufacturerMatch | string | manufacturer_match | manufacturer_match | Manufacturer (legacy) |
| TPMVendor | string | tpm_vendor | tpm_vendor | TPM vendor ID (legacy) |
| CustomAttributes | map[string]string | custom_attributes | custom_attributes | Custom key-value pairs |

### Match Behavior

- MAC addresses are normalized to lowercase before comparison
- Serial numbers are normalized to uppercase before comparison
- Prefix matching uses string prefix comparison
- Model matching uses exact string equality
- First matching rule wins (OR logic across fields)

## Network Phase Configuration

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| VLAN | uint16 | vlan | vlan | VLAN ID (1-4094) |
| DHCPPool | DHCPPoolConfig | dhcp_pool | dhcp_pool | DHCP pool settings |
| StaticIP | string | static_ip | static_ip | Static IP address |
| Gateway | string | gateway | gateway | Default gateway |
| DNS | []string | dns | dns | DNS server list |
| AuthMethod | AuthMethod | auth_method | auth_method | Authentication method |
| ACLs | []ACLConfig | acls | acls | Access control rules |

### Authentication Methods

| Method | Value | Description |
|--------|-------|-------------|
| None | "none" | No authentication required |
| 802.1X | "802.1x" | Certificate-based port authentication |

### Reserved VLANs

| VLAN | Purpose | Description |
|------|---------|-------------|
| 998 | Provisioning | Initial enrollment, limited access |
| 666 | Quarantine | Security isolation, remediation only |

## DHCP Pool Configuration

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| Network | string | network | network | CIDR notation (e.g., "10.0.0.0/24") |
| RangeStart | string | range_start | range_start | Pool start IP |
| RangeEnd | string | range_end | range_end | Pool end IP |
| LeaseTime | int | lease_time | lease_time | Lease duration (seconds) |

## ACL Configuration

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| Priority | int | priority | priority | Rule priority (lower = higher) |
| Protocol | string | protocol | protocol | Protocol (tcp, udp, icmp, any) |
| SrcIP | string | src_ip | src_ip | Source IP/CIDR |
| DstIP | string | dst_ip | dst_ip | Destination IP/CIDR |
| SrcPort | uint16 | src_port | src_port | Source port (0 = any) |
| DstPort | uint16 | dst_port | dst_port | Destination port (0 = any) |
| Action | string | action | action | Rule action (allow, deny) |

## Platformd Configuration Reference

### Fields

| Field | Type | YAML Key | JSON Key | Description |
|-------|------|----------|----------|-------------|
| ConfigType | string | config_type | config_type | Type: "inline" or "reference" |
| Inline | interface{} | inline | inline | Inline configuration object |
| Reference | string | reference | reference | Path to external config file |

### Legacy Fields

| Field | Type | Description |
|-------|------|-------------|
| ConfigName | string | Configuration name |
| ConfigPath | string | Path to configuration |
| Version | string | Configuration version |

## Complete Profile Example (YAML)

```yaml
id: 1
name: "IoT Sensor Profile"
model: "IoT-Sensor-v1"
role: "iot"
match-rules:
  mac_prefix: "52:54:00"
  serial_prefix: "IOT-"
provisioning-network:
  vlan: 998
  auth_method: "none"
  dhcp_pool:
    network: "10.99.98.0/24"
    range_start: "10.99.98.100"
    range_end: "10.99.98.200"
    lease_time: 3600
  gateway: "10.99.98.1"
  dns:
    - "10.99.98.1"
  acls:
    - priority: 100
      protocol: "udp"
      dst_port: 67
      action: "allow"
    - priority: 100
      protocol: "udp"
      dst_port: 68
      action: "allow"
    - priority: 100
      protocol: "tcp"
      dst_port: 443
      action: "allow"
    - priority: 1
      protocol: "any"
      action: "deny"
production-network:
  vlan: 100
  auth_method: "802.1x"
  static_ip: "10.100.0.50"
  gateway: "10.100.0.1"
  dns:
    - "10.100.0.1"
    - "8.8.8.8"
  acls:
    - priority: 1000
      protocol: "tcp"
      dst_port: 443
      action: "allow"
    - priority: 1000
      protocol: "tcp"
      dst_port: 8883
      action: "allow"
    - priority: 500
      protocol: "icmp"
      action: "allow"
    - priority: 1
      protocol: "any"
      action: "deny"
quarantine-network:
  vlan: 666
  auth_method: "none"
  dhcp_pool:
    network: "10.66.6.0/24"
    range_start: "10.66.6.100"
    range_end: "10.66.6.200"
    lease_time: 1800
  gateway: "10.66.6.1"
  acls:
    - priority: 100
      protocol: "tcp"
      dst_ip: "10.66.6.1"
      dst_port: 443
      action: "allow"
    - priority: 1
      protocol: "any"
      action: "deny"
platformd:
  config_type: "reference"
  reference: "/etc/platformd/iot-sensor.yaml"
```

## Complete Profile Example (JSON)

```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "model": "IoT-Sensor-v1",
  "role": "iot",
  "match_rules": {
    "mac_prefix": "52:54:00",
    "serial_prefix": "IOT-"
  },
  "provisioning_network": {
    "vlan": 998,
    "auth_method": "none",
    "dhcp_pool": {
      "network": "10.99.98.0/24",
      "range_start": "10.99.98.100",
      "range_end": "10.99.98.200",
      "lease_time": 3600
    },
    "gateway": "10.99.98.1",
    "dns": ["10.99.98.1"]
  },
  "production_network": {
    "vlan": 100,
    "auth_method": "802.1x",
    "gateway": "10.100.0.1",
    "dns": ["10.100.0.1"]
  },
  "quarantine_network": {
    "vlan": 666,
    "auth_method": "none",
    "gateway": "10.66.6.1"
  },
  "platformd": {
    "config_type": "reference",
    "reference": "/etc/platformd/iot-sensor.yaml"
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DEVICE_QUICBAAS_BACKEND | pebble | Storage backend (memory, file, pebble, raft) |
| DEVICE_QUICBAAS_DATA_DIR | trusted-data/quicbaas | QuicBaaS data directory |
| DEVICE_QUICBAAS_WAL_DIR | trusted-data/quicbaas/wal | Write-ahead log directory |
| DEVICE_SHARD_ID | 0 | QuicBaaS shard ID |
| DEVICE_PARTITION | devices | Partition name for disk isolation |
