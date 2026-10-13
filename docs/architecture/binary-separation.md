# Binary Architecture & Privilege Separation

go-trusted-platform uses a three-binary architecture with nginx/apache-style privilege separation, providing security isolation while maintaining operational flexibility.

## Overview

| Binary | Purpose | Privilege Model | Size |
|--------|---------|-----------------|------|
| `platform-initrd` | Initramfs boot operations (LUKS unlock, recovery) | Root (initramfs context) | ~22MB |
| `platformd` | Platform daemon | Master (root) + Workers (deprivileged) | ~65MB |
| `platformctl` | CLI client | Unprivileged user | ~52MB |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    THREE-BINARY ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     BOOT TIME (Initramfs)                           │   │
│  │                                                                     │   │
│  │   platform-initrd                                                   │   │
│  │   ├── boot        Unlock LUKS, mount root filesystem               │   │
│  │   └── recovery    Recovery mode with manual unlock options          │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              │ switch_root                                  │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     RUNTIME (Root Filesystem)                       │   │
│  │                                                                     │   │
│  │   platformd (daemon)                                                │   │
│  │   ├── Master Process (root)                                        │   │
│  │   │   └── Privileged operations (TPM, OVS, KVM, LUKS)              │   │
│  │   └── Worker Processes (platform user)                             │   │
│  │       └── API servers (REST, gRPC, QUIC, MCP, Unix)                │   │
│  │                                                                     │   │
│  │   platformctl (CLI)                                                 │   │
│  │   └── All operational commands via API                             │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Binary Details

### platform-initrd

The initramfs binary handles early boot operations before the root filesystem is mounted.

| Command | Purpose |
|---------|---------|
| `boot` | Unlock LUKS volume using TPM, FIDO2, or password fallback |
| `recovery` | Interactive recovery mode for manual intervention |

**Characteristics:**
- Runs in initramfs context (before root mount)
- Statically linked for minimal dependencies
- Includes TPM, LUKS, and FIDO2 support
- Optimized for minimal size (~22MB)

**Boot Flow:**
```
1. Kernel loads initramfs
2. platform-initrd boot executes:
   ├── Execute unlock strategy chain:
   │   ├── Keyfile (first boot from installer.luks)
   │   ├── TPM-PCR (normal boot with PCR policy)
   │   ├── TPM-Upgrade (after kernel update)
   │   ├── FIDO2 (hardware security key)
   │   └── Password (fallback)
   └── Unlock LUKS and switch_root
3. After switch_root: platformctl firstboot (if first boot)
4. systemd/openrc starts platformd
```

**Source Code:**
- `cmd/platform-initrd/` - Binary entry point
- `pkg/boot/commands/` - Boot commands (boot, recovery)
- `pkg/initrd/` - Boot orchestration and unlock strategies

---

### platformd

The platform daemon provides all runtime services using privilege separation.

| Command | Purpose |
|---------|---------|
| `serve` | Start the daemon with all services |
| `version` | Display version information |

**Privilege Separation Model:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                           platformd                                  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Master Process (root)                      │  │
│  │                                                               │  │
│  │  Responsibilities:                                            │  │
│  │  • Start as root, bind privileged ports                       │  │
│  │  • Open TPM device (/dev/tpm0, /dev/tpmrm0)                   │  │
│  │  • Manage OVS bridges and OpenFlow rules                      │  │
│  │  • Create/destroy TAP devices                                 │  │
│  │  • Spawn and manage QEMU/KVM processes                        │  │
│  │  • Create network namespaces                                  │  │
│  │  • Perform LUKS operations                                    │  │
│  │  • Spawn and supervise worker processes                       │  │
│  │  • Handle signals (SIGHUP for reload, SIGTERM for shutdown)   │  │
│  └───────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│                    spawns    │    IPC (Unix socket / pipe)          │
│                              │                                      │
│  ┌───────────────────────────▼───────────────────────────────────┐  │
│  │               Worker Processes (platform user)                │  │
│  │                                                               │  │
│  │  Responsibilities:                                            │  │
│  │  • Handle REST/gRPC/QUIC/MCP API requests                     │  │
│  │  • Serve ACME server for device enrollment                    │  │
│  │  • Run DNS server                                             │  │
│  │  • Manage certificates and PKI                                │  │
│  │  • Process device profiles and activation                     │  │
│  │  • Run QuicBaaS (embedded)                                    │  │
│  │  • Delegate privileged ops to master via IPC                  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Source Code:**
- `cmd/platformd/` - Binary entry point
- `pkg/daemon/commands/` - Daemon commands (serve, version)
- `pkg/app/` - Application bootstrap

---

### platformctl

The CLI client provides all operational commands via the daemon's APIs.

**Command Groups:**

| Group | Purpose |
|-------|---------|
| `firstboot` | First-boot TPM provisioning and LUKS key sealing (runs after switch_root) |
| `tpm` | TPM operations (provision, install, destroy, extend, seal/unseal, idevid, iak) |
| `ca` | Certificate Authority (sign, revoke, list, verify) |
| `kms` | Key Management (keys, secrets, crypto, DEKs) |
| `iam` | Identity & Access Management (users, groups, roles, policies) |
| `tenant` | Multi-tenancy (create, list, quotas, network) |
| `device` | Device management (profiles, enrollment) |
| `vtpm` | Virtual TPM management |
| `dns` | DNS zone and record management |
| `sdn` | Software-defined networking (bridges, ports, flows) |
| `vm` | Virtual machine lifecycle |
| `container` | Container lifecycle |
| `cluster` | Cluster management |
| `acme` | ACME client enrollment |
| `iso` | ISO building |
| `profile` | Configuration profiles |
| `install` | System installation (system, uki) |
| `wipe` | Secure data wiping |
| `fido2` | FIDO2 device management |
| `authenticode` | Authenticode signing |
| `pkcs11` | PKCS#11 operations |

**Connection Methods:**

| Method | Target | Use Case |
|--------|--------|----------|
| Unix Socket | /run/platformd.sock | Local management (default) |
| gRPC | host:10443 | High-performance |
| REST | https://host:8443 | Web/curl access |
| QUIC | host:9444 | Low-latency |

**Source Code:**
- `cmd/platformctl/` - Binary entry point
- `pkg/cli/commands/` - All CLI command implementations
- `pkg/cli/client/` - API client abstractions

---

## Why Three Binaries?

| Binary | Rationale |
|--------|-----------|
| **platform-initrd** | Initramfs has strict size constraints (~22MB). Contains only boot and recovery - no firstboot. Statically linked for minimal dependencies. Cannot use platformd as it requires services not available before root mount. |
| **platformd** | Daemon needs privilege separation for security. Long-running process managing all services. |
| **platformctl** | CLI runs as unprivileged user. Contains firstboot command (runs after switch_root when filesystem is available). Connects to daemon via APIs for other commands. |

**Benefits:**
- **Size optimization**: platform-initrd is minimal (~22MB) with only boot/recovery commands
- **Security**: Clear privilege boundaries between binaries
- **Modularity**: Each binary has focused responsibility
- **Deployment**: Can deploy only what's needed (e.g., CLI-only for remote management)

---

## Privileged Operations

The master process retains root privileges for operations that require them:

| Operation | Description | Required Privilege |
|-----------|-------------|-------------------|
| TPM Access | Open TPM device, perform operations | `/dev/tpm0` access |
| OVS Management | Create/delete bridges and ports | CAP_NET_ADMIN |
| OpenFlow | Install/remove flow rules | CAP_NET_ADMIN |
| TAP Devices | Create/configure TAP interfaces | CAP_NET_ADMIN |
| QEMU/KVM | Start/stop/manage VMs | CAP_SYS_ADMIN, `/dev/kvm` |
| Network Namespaces | Create/manage netns | CAP_SYS_ADMIN |
| swtpm | Manage software TPM instances | CAP_SYS_ADMIN |
| LUKS | Encrypt/decrypt block devices | CAP_SYS_ADMIN |
| Mount Operations | Mount filesystems | CAP_SYS_ADMIN |
| Privileged Ports | Bind ports < 1024 | CAP_NET_BIND_SERVICE |

---

## API Services

Worker processes handle all network-facing services:

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| REST API | HTTPS | 8443/9443 | Public/internal HTTP endpoints |
| gRPC API | TCP | 10443 | High-performance RPC |
| QUIC API | UDP | 9444 | Low-latency transport |
| MCP API | HTTP | 8000 | AI/LLM integration (OAuth 2.1) |
| Unix Socket | gRPC UDS | /run/platformd.sock | Local IPC (SO_PEERCRED) |
| ACME Server | HTTPS | 8443 | Device enrollment |
| DNS Server | UDP/TCP | 8053/9053 | Zone management |

---

## Deployment

### systemd Service

```ini
# /etc/systemd/system/platformd.service
[Unit]
Description=Trusted Platform Daemon
After=network.target openvswitch.target

[Service]
Type=notify
ExecStart=/usr/bin/platformd serve --enable-mtls
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Master runs as root, spawns deprivileged workers
User=root
Group=root

RuntimeDirectory=platformd
StateDirectory=platformd

[Install]
WantedBy=multi-user.target
```

### First Boot Service

```ini
# /etc/systemd/system/platform-firstboot.service
[Unit]
Description=Platform First Boot Provisioning
After=local-fs.target
ConditionPathExists=!/var/lib/trusted-platform/.provisioned

[Service]
Type=oneshot
ExecStart=/usr/bin/platformctl firstboot
ExecStartPost=/usr/bin/touch /var/lib/trusted-platform/.provisioned
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

---

## Security Summary

| Component | Privilege Level | Network Exposure | Data Access |
|-----------|----------------|------------------|-------------|
| platform-initrd | root (initramfs) | None | TPM, LUKS, EFI partition |
| platformd master | root | None (IPC only) | Devices, hardware |
| platformd worker | platform user | mTLS protected | QuicBaaS, configs |
| platformctl | user | Via worker APIs | Client-side only |

### Key Security Properties

1. **Minimal privilege**: Workers run as non-root; master only performs privileged ops
2. **No network exposure for root**: Master only communicates via IPC, never network
3. **mTLS everywhere**: All network APIs require mutual TLS authentication
4. **Process isolation**: Workers in separate address space from privileged master
5. **Crash resilience**: Worker crash doesn't affect master; automatic respawn
6. **Boot security**: LUKS keys sealed to TPM PCRs, only accessible with correct boot chain
