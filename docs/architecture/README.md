# System Architecture

This section documents the overall architecture of go-trusted-platform, including the binary architecture, privilege separation model, inter-service communication, security boundaries, and integration with QuicBaaS.

## Overview

go-trusted-platform uses a **three-binary architecture** with nginx/apache-style privilege separation:

| Binary | Purpose | Size |
|--------|---------|------|
| `platform-initrd` | Initramfs boot operations (LUKS unlock, recovery) | ~22MB |
| `platformd` | Daemon with privilege separation (root master, deprivileged workers) | ~65MB |
| `platformctl` | CLI client for interacting with platformd | ~52MB |

This design ensures privileged operations remain isolated while web-exposed services run without root privileges.

## Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                           BOOT TIME                                    │
│                                                                       │
│   ┌──────────────────────────────────────────────────────────────┐    │
│   │                      platform-initrd                          │    │
│   │                                                              │    │
│   │  Initramfs execution:                                        │    │
│   │  • Unlock LUKS via TPM/FIDO2/password                        │    │
│   │  • Mount root filesystem                                     │    │
│   │  • switch_root to real filesystem                            │    │
│   └──────────────────────────────────────────────────────────────┘    │
│                              │                                        │
└──────────────────────────────┼────────────────────────────────────────┘
                               │ switch_root
                               ▼
┌───────────────────────────────────────────────────────────────────────┐
│                             User Layer                                │
│                                                                       │
│   ┌──────────────────┐     ┌──────────────────┐                       │
│   │   platformctl    │     │   External       │                       │
│   │   (CLI client)   │     │   Clients        │                       │
│   └────────┬─────────┘     └────────┬─────────┘                       │
│            │                        │                                 │
└────────────┼────────────────────────┼─────────────────────────────────┘
             │                        │
             │ Unix socket            │ HTTPS (mTLS)
             │ or HTTPS               │
             │                        │
┌────────────┼────────────────────────┼─────────────────────────────────┐
│            ▼                        ▼                                 │
│   ┌───────────────────────────────────────────────────────────┐       │
│   │                      platformd                            │       │
│   │                                                           │       │
│   │  ┌─────────────────────────────────────────────────────┐  │       │
│   │  │              Master Process (root)                  │  │       │
│   │  │                                                     │  │       │
│   │  │  • TPM operations      • OVS/OpenFlow management    │  │       │
│   │  │  • QEMU/KVM lifecycle  • TAP device creation        │  │       │
│   │  │  • LUKS operations     • Network namespaces         │  │       │
│   │  │  • Process spawning    • Capability management      │  │       │
│   │  └──────────────────────────┬──────────────────────────┘  │       │
│   │                             │                             │       │
│   │                    spawns   │   IPC                       │       │
│   │                             ▼                             │       │
│   │  ┌─────────────────────────────────────────────────────┐  │       │
│   │  │           Worker Processes (platform user)          │  │       │
│   │  │                                                     │  │       │
│   │  │  • REST/gRPC/QUIC/MCP APIs  • ACME server           │  │       │
│   │  │  • DNS server               • Web UI                │  │       │
│   │  │  • Certificate mgmt         • Device enrollment     │  │       │
│   │  └─────────────────────────────────────────────────────┘  │       │
│   └───────────────────────────────────────────────────────────┘       │
│                                                                       │
│                            Service Layer                              │
└───────────────────────────────────────────────────────────────────────┘
             │
┌────────────┼──────────────────────────────────────────────────────────┐
│            │                                                          │
│   ┌────────▼─────────┐                                                │
│   │                  │                                                │
│   │    QuicBaaS      │     Provides: KMS, IAM, Secrets, KV Store      │
│   │                  │     Backend: PebbleDB (standalone) or Raft     │
│   └──────────────────┘                                                │
│                                                                       │
│                        Infrastructure Layer                           │
└───────────────────────────────────────────────────────────────────────┘
             │
┌────────────┼──────────────────────────────────────────────────────────┐
│            │                                                          │
│   ┌────────┴────────┬─────────┬─────────┐                             │
│   │        │        │         │         │                             │
│   ▼        ▼        ▼         ▼         ▼                             │
│ ┌────┐  ┌─────┐  ┌─────┐  ┌──────┐  ┌──────┐                          │
│ │OVS │  │QEMU │  │ TPM │  │PKCS11│  │Cloud │                          │
│ └────┘  └─────┘  └─────┘  └──────┘  │ KMS  │                          │
│                                     └──────┘                          │
│                       Hardware/External Layer                         │
└───────────────────────────────────────────────────────────────────────┘
```

## Documentation Index

| Document | Description |
|----------|-------------|
| [binary-separation.md](binary-separation.md) | Three-binary architecture and privilege separation |
| [communication.md](communication.md) | Inter-service communication protocols |
| [quicbaas-integration.md](quicbaas-integration.md) | QuicBaaS service layer integration |
| [sdk-integration.md](sdk-integration.md) | Unified SDK integration and Platform Service Registry |
| [platform-modes.md](platform-modes.md) | Local, P2P, and Hosted operational modes |
| [reference.md](reference.md) | IoT hybrid cloud reference architecture |
| [reference-network.md](reference-network.md) | Reference VLAN architecture and network segmentation |

## SDK Integration

The platform provides SDKs for Go and JavaScript that wrap both platform services and QuicBaaS services through a unified Platform Service Registry:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Consumer Applications                            │
│                   (platformctl, web dashboard)                       │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│               go-trusted-platform SDK                                │
│                                                                      │
│  sdk/go/platform/             sdk/javascript/                        │
│  ├── Client interface         ├── PlatformClient                     │
│  ├── 16 Platform services     ├── 16 Platform services               │
│  └── QuicBaaS() accessor ◄────┴── 28 QuicBaaS services               │
│                                                                      │
│  Multi-Protocol Support: Embedded | REST | gRPC | QUIC | MCP | Unix  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│          Platform Service Registry (pkg/platform/registry.go)        │
│                                                                      │
│  SDK Adapters (internal/)         Native Services (pkg/)             │
│  ├── quicbaas/adapter.go          ├── tpm/                           │
│  ├── ca/adapter.go                ├── vtpm/                          │
│  └── xkms/adapter.go          ├── device/                        │
│          │                        └── dns/, sdn/, compute/...        │
│          ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              go-quicbaas SDK (go-quicbaas/sdk/go)           │    │
│  │  ├── 28 service clients (KV, KMS, IAM, Vector, etc.)        │    │
│  │  └── Transport: Embedded | Unix | gRPC | REST | QUIC        │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

For detailed documentation:
- [SDK Integration Architecture](sdk-integration.md) - Platform Service Registry and SDK adapters
- [SDK Overview](../api/sdk-overview.md) - Complete SDK documentation
- [QuicBaaS Integration](quicbaas-integration.md) - QuicBaaS service details

## Key Design Principles

### 1. Three-Binary Architecture

The platform is split into three binaries for different lifecycle stages:

| Binary | When | Purpose |
|--------|------|---------|
| `platform-initrd` | Boot time (initramfs) | Unlock encrypted root filesystem |
| `platformd` | Runtime (daemon) | Provide all platform services |
| `platformctl` | Runtime (CLI) | User/admin interaction |

### 2. Privilege Separation (nginx/apache Model)

`platformd` uses a process model similar to nginx and Apache:

- **Master process** starts as root and handles:
  - Binding privileged ports (< 1024)
  - TPM device access
  - OVS/OpenFlow operations
  - QEMU/KVM management
  - Network namespace creation
  - Spawning and managing worker processes

- **Worker processes** run as unprivileged `platform` user:
  - Handle all network-facing services
  - Process API requests
  - Manage certificates and enrollment
  - Communicate with master via IPC for privileged operations

### 3. Defense in Depth

Multiple security layers protect the system:
- LUKS encryption with TPM-sealed keys
- Unix socket with file permissions (0660)
- gRPC with TLS for internal communication
- mTLS for external API access
- ABAC authorization policies
- Certificate-based device authentication

### 4. Zero Trust Networking

Every device must prove identity before network access:
- New devices start in provisioning VLAN
- ACME enrollment issues IDevID certificate
- Certificate attributes determine network policy
- Continuous attestation validates device state

### 5. Distributed State

QuicBaaS provides:
- Raft consensus for consistency
- Key management with HSM backend support
- Identity and access management
- Secrets management

## Boot Sequence

```
1. BIOS/UEFI → Secure Boot → Kernel + Initramfs
                                    │
2. Initramfs: platform-initrd boot  │
   ├── TPM-PCR unlock (normal boot) │
   ├── TPM-Upgrade unlock (kernel update)
   ├── FIDO2 unlock (hardware key)  │
   └── Password unlock (fallback)   │
                                    │
3. switch_root to real filesystem   │
                                    │
4. First boot: platformctl firstboot│
   ├── TPM provisioning (EK, SRK, IAK, IDevID)
   └── Seal LUKS key with PCR policy│
                                    │
5. systemd starts platformd         │
   ├── Master process (root)        │
   └── Worker processes (platform)  │
                                    │
6. Normal operation                 ▼
```

## Deployment Modes

### Standalone Mode

Single node deployment with PebbleDB backend:

```
┌───────────────────────────────────┐
│         Single Node               │
│                                   │
│  platformd                        │
│  ├── Master (root)                │
│  │   └── TPM, OVS, QEMU           │
│  └── Worker (platform)            │
│      ├── REST/gRPC/QUIC/MCP APIs  │
│      └── QuicBaaS (PebbleDB)      │
└───────────────────────────────────┘
```

### Clustered Mode

Multi-node deployment with Raft consensus:

```
┌────────────┐    ┌────────────┐    ┌────────────┐
│   Node 1   │    │   Node 2   │    │   Node 3   │
│  (Leader)  │    │ (Follower) │    │ (Follower) │
│            │    │            │    │            │
│ platformd  │◀──▶│ platformd  │◀──▶│ platformd  │
│ ├─Master   │    │ ├─Master   │    │ ├─Master   │
│ └─Workers  │    │ └─Workers  │    │ └─Workers  │
│            │    │            │    │            │
│ QuicBaaS   │    │ QuicBaaS   │    │ QuicBaaS   │
│  (Raft)    │    │  (Raft)    │    │  (Raft)    │
└────────────┘    └────────────┘    └────────────┘
```

## Related Documentation

- [Binary Separation](binary-separation.md) - Detailed three-binary architecture
- [Platform Modes](platform-modes.md) - Local, P2P, and Hosted modes
- [CLI Reference](../cli/) - platform-initrd, platformd, and platformctl commands
- [SDN Architecture](../sdn/architecture.md)
- [Compute Architecture](../compute/)
- [CA/ACME Documentation](../ca/)
