# Compute Orchestrator Architecture

> **Status: NORMATIVE** · Scope: `pkg/compute/`, `pkg/qemu/`, `pkg/swtpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, build tags, configuration keys, CLI
> flags and the transport matrix were checked against code on 2026-08-18. The
> narrative below predates the migration and was carried over.

## The problem

A hypervisor answers "can this workload run here". A trusted-computing platform
also has to answer "can this workload be *proved* to be what it claims, and is
it allowed on this network" — and both answers have to be enforceable by
something other than the workload's own assertion.

## The shape chosen

One `Orchestrator` interface over pluggable backends (QEMU/KVM for VMs, podman
for containers, optionally AWS/Azure/GCP), with three platform-specific
additions:

1. **Per-VM virtual TPM.** A `--tpm` VM gets its own swtpm instance, so it
   attests with its own identity rather than borrowing the host's.
2. **Port authentication on the VNIC.** With `port_auth_enabled`, a VM's virtual
   port goes through the same IDevID state machine as a physical device — a VM
   is not on the network because it exists.
3. **Placement then admission.** `placement.go` decides *where*; port auth and
   tenant quota decide *whether*.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Sharing the host TPM with guests** | Every VM would attest as the host, so per-workload attestation would mean nothing and one compromised guest could exercise the host's root of trust. Each attestable VM gets its own vTPM. `--tpm-access` on a *container* deliberately does the opposite and is why that flag needs a decision each time. |
| **Giving VMs network access on creation** | A VM would be on the network before anything proved what it was, which is precisely the failure port authentication exists to prevent. `port_auth_enabled` routes VNICs through the same state machine as physical ports. |
| **Compiling cloud providers in by default** | Three SDK dependency trees in every binary, on a platform whose gateway and worker binaries are attested and whose import closure is guarded. Cloud support is build-tag gated and `ErrComputeProviderNotCompiled` reports its absence as a first-class error rather than a panic. |
| **One-shot migration only** | A migration that cannot be staged cannot be confirmed. `PrepareMigration` / `FinalizeMigration` exist alongside `MigrateVM` so the destination can be readied and the cutover verified. |
| **Deleting disks with the VM by default** | Deletion would be unrecoverable by default. Disks survive unless `--delete-disks` is given — at the cost of storage that must be reclaimed deliberately. |
| **Unary console and log-follow** | An interactive console is not a request/response operation. Console attach and log-follow are gRPC streams with no unary equivalent, and that is recorded in code as a decision rather than a gap. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Orchestrator, provider, lifecycle | `pkg/compute/orchestrator.go`, `provider.go`, `lifecycle.go` | this repo |
| Placement | `pkg/compute/placement.go` | this repo |
| VNIC port authentication | `pkg/compute/port_auth.go` | this repo |
| QEMU/KVM backend | `pkg/compute/qemu*.go`, `pkg/qemu/` | this repo |
| Container backend | `pkg/compute/container/`, `podman/` | this repo |
| Network attachment | `pkg/compute/network/` | this repo |
| Network boot | `pkg/compute/pxe/` | this repo |
| Cloud backends | `pkg/compute/{aws,azure,gcp}/` — **build-tag gated** | this repo |
| **Virtual TPM provisioning** | `pkg/vtpm/`, `pkg/swtpm/` — [`docs/vtpm/`](../vtpm/) | this repo |
| **VM and container attestation** | `pkg/attestation/` — [`docs/attestation/`](../attestation/) | this repo |
| **The datapath a VNIC attaches to** | `pkg/sdn/` — [`docs/sdn/`](../sdn/) | this repo |
| **Quota admission** | `pkg/tenant/` — [`docs/tenant/`](../tenant/) | this repo |
| **Container images** | `pkg/registry/` — [`docs/registry/`](../registry/) | this repo |
| **Container trust tiers (pinned/attested/measured)** | consumed through the quicbaas SDK | **not this repo** |
| **Storage, keys, identity** | consumed through the quicbaas SDK | **not this repo** |

The §R capability row is *"Compute — VM and container orchestration, placement,
lifecycle"*, Tier 1, reached through `services/compute`.

Container trust tiers are go-quicbaas's. This repo registers the fleet attestor
(`container.FleetContainerAttestor`) through `WithContainerAttestor`. The fleet
attestor adds the platform's policy around the SDK's runtime attestor:

- it looks the host up in the device registry;
- it applies the golden PCRs of the host's device profile, checked on their
  own before any PCR the request adds;
- on drift it records a cryptographic failure verdict, moves the device to
  quarantine itself (SDN port isolation is added when SDN is wired), and asks
  the attestation collector to re-attest it.

The embedded server registers a lazy adapter
(`pkg/storage/quicbaas.ContainerAttestorAdapter`) when it starts. `platformd`
installs the fleet attestor into that adapter once the attestation services
exist (`pkg/daemon/commands/container_attestor_init.go`). Until then, and on a
node that lacks a prerequisite, `Security().Attestation().AttestContainer`
refuses with a typed error.

## Data flow — creating an attestable VM

1. **Admission.** Tenant quota is checked before allocation.
2. **Placement.** A host is selected; `ErrNoNetworkInZone` if the requested zone
   has no network.
3. **vTPM.** With `--tpm`, a virtual TPM instance is provisioned.
4. **Firmware.** UEFI, optionally with Secure Boot.
5. **VNIC.** Attached to the configured bridge; with `port_auth_enabled` it
   enters the port state machine at `provisioning`.
6. **Boot.** The VM measures into its own vTPM.
7. **Attestation.** `AttestVM` produces a quote against the vTPM, bound to the
   host's own attestation.

Steps 1, 2 and 5 can each refuse. None of them can be bypassed by the workload.

## Trust boundaries

1. **Guest → host.** A VM is untrusted. Its vTPM is the only channel through
   which it makes a claim the host can check.
2. **Container → host.** `--privileged` removes the isolation on this boundary;
   `--tpm-access` puts the **host's** TPM device on the guest side of it. Both
   are deliberate escapes and neither should be routine.
3. **VNIC → network.** Crossed only after port authentication when
   `port_auth_enabled` is on. With it off, this boundary does not exist.
4. **Node → node (migration).** Crossed over mTLS gRPC between daemons. Live
   migration additionally assumes shared storage, which is a shared trust
   domain for the disk.
5. **Node → registry.** Image pulls are attestation-gated.

## What this feature deliberately does not do

- **It does not attest anything itself.** It provisions the vTPM and calls the
  attestation feature.
- **It does not program the network.** It requests a VNIC; SDN decides whether
  it is allowed.
- **It does not enforce quota.** Tenancy does, ahead of allocation.
- **It does not build or store images.** The registry does.
- **It does not offer console or log-follow over REST or MCP**, and will not —
  see the rejected alternatives.

## Overview

The compute orchestrator provides VM lifecycle management with integrated
vTPM provisioning and 802.1X-style network access control.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Compute Orchestrator                           │
│  (pkg/compute)                                                          │
│                                                                         │
│  ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │
│  │  QEMUOrchestrator │   │ LifecycleManager  │   │   PortAuth        │  │
│  │                   │   │                   │   │                   │  │
│  │  instances map    │   │  State Machine    │   │  Policy Engine    │  │
│  │  ovsClient        │   │  Transitions      │   │  Enrollment Hook  │  │
│  │  config           │   │  Validation       │   │  Port Mapping     │  │
│  └────────┬──────────┘   └────────┬──────────┘   └────────┬──────────┘  │
│           │                       │                       │             │
├───────────┼───────────────────────┼───────────────────────┼─────────────┤
│           │                       │                       │             │
│   ┌───────▼───────┐       ┌───────▼───────┐       ┌───────▼───────┐     │
│   │  qemuInstance │       │   Instance    │       │ SDN Policy    │     │
│   │               │       │   States      │       │ Engine        │     │
│   │  • QEMU proc  │       │               │       │               │     │
│   │  • swtpm      │       │  unknown      │       │  SetPortState │     │
│   │  • network    │       │  creating     │       │  ApplyPolicy  │     │
│   │  • metadata   │       │  stopped      │       │  Flows        │     │
│   └───────┬───────┘       │  starting     │       └───────────────┘     │
│           │               │  running      │                             │
│   ┌───────▼───────┐       │  stopping     │                             │
│   │    swtpm      │       │  error        │                             │
│   │    (vTPM)     │       │  deleting     │                             │
│   │               │       └───────────────┘                             │
│   │  • State dir  │                                                     │
│   │  • Socket     │                                                     │
│   │  • Lifecycle  │                                                     │
│   └───────────────┘                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### QEMUOrchestrator

The main orchestrator implementation for QEMU/KVM virtual machines.

```go
type QEMUOrchestrator struct {
    config    *OrchestratorConfig
    logger    *logging.Logger
    lifecycle *LifecycleManager
    ovsClient *ovs.Client
    mu        sync.RWMutex
    instances map[string]*qemuInstance
}
```

Key responsibilities:
- Instance creation and deletion
- VM process management
- Network attachment/detachment
- State synchronization

### qemuInstance

Internal representation of a running VM instance.

```go
type qemuInstance struct {
    instance        *Instance
    swtpm           *swtpm.SWTPM
    cmd             *exec.Cmd
    ovsNetwork      *ovsNetwork
    mu              sync.Mutex
    cancelFunc      context.CancelFunc
    waitGroup       sync.WaitGroup
    networkAttached bool
}
```

### LifecycleManager

Manages instance state transitions with validation.

```go
type LifecycleManager struct {
    mu     sync.RWMutex
    states map[string]InstanceState
}
```

Valid state transitions:
```
unknown    ──▶ creating, error
creating   ──▶ stopped, error
stopped    ──▶ starting, deleting, error
starting   ──▶ running, error
running    ──▶ stopping, error
stopping   ──▶ stopped, error
```

## QEMU Integration

### QMP Control Channel

The compute orchestrator uses QEMU Machine Protocol (QMP) for runtime VM control
via the go-qemu library (github.com/digitalocean/go-qemu).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          QMP Control Architecture                        │
│                                                                         │
│  ┌───────────────────┐                    ┌───────────────────┐         │
│  │  QEMUOrchestrator │                    │   QEMU Process    │         │
│  │                   │                    │                   │         │
│  │  ┌─────────────┐  │   Unix Socket      │  ┌─────────────┐  │         │
│  │  │  QMPMonitor │◄─┼────────────────────┼─►│ QMP Server  │  │         │
│  │  │             │  │  JSON-RPC 2.0      │  │             │  │         │
│  │  │  • Status   │  │                    │  │ • Commands  │  │         │
│  │  │  • Shutdown │  │                    │  │ • Events    │  │         │
│  │  │  • Pause    │  │                    │  │ • Queries   │  │         │
│  │  │  • Migrate  │  │                    │  │             │  │         │
│  │  └─────────────┘  │                    │  └─────────────┘  │         │
│  └───────────────────┘                    └───────────────────┘         │
│                                                                         │
│  QMP Operations:                                                        │
│  • query-status      - Get VM state (running/paused/stopped)           │
│  • system_powerdown  - ACPI graceful shutdown                          │
│  • stop / cont       - Pause and resume VM                             │
│  • savevm / loadvm   - Create and restore snapshots                    │
│  • migrate           - Live migration to another host                  │
│  • query-block       - Disk device information                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### VM Lifecycle with QMP

```
                    os/exec                          QMP
  ┌──────────────────────────────────────┬────────────────────────────────┐
  │          Pre-Launch Phase            │       Runtime Phase            │
  │                                      │                                │
  │  1. Build QEMU command line          │  4. Connect to QMP socket      │
  │  2. Start QEMU process (os/exec)     │  5. Query status, control VM   │
  │  3. Wait for QMP socket ready        │  6. Graceful shutdown via QMP  │
  └──────────────────────────────────────┴────────────────────────────────┘
```

### VM Configuration

```
QEMU Command Structure:
┌────────────────────────────────────────────────────────────────────┐
│ qemu-system-x86_64                                                 │
│   -name <instance-name>                                            │
│   -machine q35,accel=kvm                                           │
│   -cpu host                                                        │
│   -smp <cpus>                                                      │
│   -m <memory>                                                      │
│   -drive file=<disk>,format=qcow2,if=virtio                        │
│   -drive if=pflash,format=raw,readonly=on,file=<OVMF_CODE>         │
│   -drive if=pflash,format=raw,file=<OVMF_VARS>                     │
│   -netdev tap,id=net0,ifname=<tap>,script=no,downscript=no         │
│   -device virtio-net-pci,netdev=net0,mac=<mac>                     │
│   -chardev socket,id=chrtpm,path=<swtpm.sock>                      │
│   -tpmdev emulator,id=tpm0,chardev=chrtpm                          │
│   -device tpm-tis,tpmdev=tpm0                                      │
│   -qmp unix:<qmp.sock>,server,wait=off    ← QMP control socket     │
└────────────────────────────────────────────────────────────────────┘
```

That is the x86_64 guest. An aarch64 guest, the default on an arm64 host such
as the Raspberry Pi 4, runs `qemu-system-aarch64` with:

- `-machine virt,gic-version=host` under KVM, so the guest gets the host's
  own GIC (the Raspberry Pi 4's GIC-400 is GICv2 only), and
  `virt,gic-version=3` without;
- `-cpu host` under KVM, `cortex-a72` without;
- the same two pflash drives, carrying AAVMF;
- `-device tpm-tis-device` for the vTPM.

The arch keys and their defaults are in
[engineering.md §4](engineering.md#4-configuration).

### UEFI Boot

OVMF (x86_64) and AAVMF (aarch64) firmware provide UEFI boot with optional
Secure Boot. Each instance gets its own copy of the vars template.

```
x86_64 standard boot:
  OVMF_CODE_4M.fd - UEFI firmware
  OVMF_VARS_4M.fd - NVRAM template

x86_64 Secure Boot:
  OVMF_CODE_4M.secboot.fd - Secure Boot firmware
  OVMF_VARS_4M.fd - NVRAM with secure keys

aarch64 (standard and Secure Boot):
  /usr/share/AAVMF/AAVMF_CODE.fd - UEFI firmware
  /usr/share/AAVMF/AAVMF_VARS.fd - NVRAM template
```

## swtpm Integration

### Lifecycle Flow

```
Create VM ──▶ Initialize swtpm ──▶ Create TPM State
                    │
Start VM ──▶ Start swtpm ──▶ Wait for Socket ──▶ Start QEMU
                    │
VM Running ──▶ swtpm Running
                    │
Stop VM ──▶ VM Exits ──▶ Auto-stop swtpm
                    │
Delete VM ──▶ Cleanup swtpm ──▶ Remove TPM State
```

### TPM Configuration

```go
type TPMConfig struct {
    StateDir   string  // {workDir}/tpm/
    SocketPath string  // {workDir}/tpm/swtpm.sock
    LogPath    string  // {workDir}/tpm/swtpm.log
    Version    string  // TPM 2.0
    PCRBanks   string  // SHA-256
}
```

### State Persistence

TPM state files in `{workDir}/tpm/`:
- `tpm2-00.permall` - Permanent state
- `.lock` - Lock file
- `swtpm.sock` - Unix socket (ephemeral)
- `swtpm.log` - Daemon logs

## TAP/Network Integration

### TAP Device Creation

```
┌───────────────────┐          ┌───────────────────┐
│   Platform        │          │  Linux Kernel     │
│   (Compute Orch.) │          │                   │
│                   │  Netlink │   ┌───────────┐   │
│  ┌─────────────┐  │  Socket  │   │ TAP/TUN   │   │
│  │ TAP Manager │──────┬──────┼───│ Driver    │   │
│  └─────────────┘  │          │   └───────────┘   │
│                   │          │         │         │
└───────────────────┘          │   ┌─────▼─────┐   │
                               │   │ tap-vm-X  │   │
      VM (QEMU)                │   └───────────┘   │
   ┌─────────────┐             │         │         │
   │ virtio-net  │─────────────┼─────────┘         │
   └─────────────┘             │                   │
                               └───────────────────┘
```

### OVS Port Attachment

```go
// AttachNetwork flow
1. Create TAP device via netlink
2. Add TAP to OVS bridge
3. Set VLAN (provisioning: 998)
4. Register with policy engine
5. Store attachment in instance

// DetachNetwork flow
1. Remove from policy engine
2. Delete OVS port
3. Delete TAP device
4. Remove attachment from instance
```

## 802.1X Port Authentication

### Integration with Policy Engine

```
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   Orchestrator    │     │   Policy Engine   │     │   OVS Bridge      │
│                   │     │                   │     │                   │
│  AttachNetwork    │────▶│  SetPortState     │────▶│  SetPortVLAN      │
│  (Provisioning)   │     │  (Provisioning)   │     │  (VLAN 998)       │
│                   │     │                   │     │                   │
└───────────────────┘     └───────────────────┘     └───────────────────┘
         │                        │                        │
         │                        │ OnEnrollment           │
         │                        ▼                        │
         │                ┌───────┴───────┐                │
         │                │   Enrolled    │                │
         │                └───────┬───────┘                │
         │                        │                        │
         │  ActivateInstance      │ ApplyPolicy            │
         └───────────────────────▶┼───────────────────────▶│
                                  │ (Authorized)           │
                                  │                        │
                                  └────────────────────────┘
                                         VLAN 100
```

### Port State Flow

```
VM Created
    │
    ▼
AttachNetwork() ──▶ Port: Provisioning (VLAN 998)
    │
    ▼
VM Enrolls (ACME) ──▶ Port: Enrolled (VLAN 998)
    │
    ▼
ActivateInstance() ──▶ Port: Authorized (Production VLAN)
    │
    ▼
Certificate Expires ──▶ Port: Quarantined (VLAN 666)
    │
    ▼
Certificate Revoked ──▶ Port: Blocked (DROP)
```

## Instance Configuration

### OrchestratorConfig

```go
type OrchestratorConfig struct {
    Type            ComputeType   // vm, container
    WorkDir         string        // Base work directory
    DefaultMemory   int           // Default RAM (MB)
    DefaultCPUs     int           // Default CPU cores
    DefaultDiskSize string        // Default disk size
    MaxInstances    int           // Maximum instances
    EnableKVM       bool          // KVM acceleration
    NetworkBridge   string        // OVS bridge name
    OVSSocketPath   string        // OVSDB socket
    QEMUBinary      string        // QEMU executable
    OVMFCode        string        // UEFI firmware
    OVMFCodeSecure  string        // Secure Boot firmware
    OVMFVars        string        // NVRAM template

    // Port authentication
    PortAuthEnabled bool
    PolicyEngine    policy.PolicyEngine
}
```

### InstanceConfig

```go
type InstanceConfig struct {
    Memory      int               // RAM (MB)
    CPUs        int               // CPU cores
    DiskPath    string            // Disk image path
    DiskSize    string            // Disk size
    WorkDir     string            // Work directory
    SecureBoot  bool              // UEFI Secure Boot
    EnableKVM   bool              // KVM acceleration
    TPMEnabled  bool              // vTPM
    NetworkMode string            // bridge, user, none
    MACAddress  string            // Network MAC
    BootMode    string            // install, boot, pxe
    ISOPath     string            // Installation ISO
}
```

## Thread Safety

### Locking Strategy

```go
// Orchestrator level - protects instances map
orchestrator.mu.RLock()  // Read access to instances
orchestrator.mu.Lock()   // Write access to instances

// Instance level - protects instance state
instance.mu.Lock()       // State changes

// Lifecycle level - protects state transitions
lifecycle.mu.Lock()      // State updates
```

### Concurrent Operations

Safe for concurrent use:
- Create multiple instances simultaneously
- Start/Stop different instances in parallel
- Query instances while others are modifying

Not safe without orchestrator lock:
- Modifying same instance from multiple goroutines

## Error Handling

### Typed Errors

```go
var (
    ErrInstanceNotFound         = errors.New("instance not found")
    ErrInstanceAlreadyExists    = errors.New("instance already exists")
    ErrInstanceNotRunning       = errors.New("instance is not running")
    ErrInstanceAlreadyRunning   = errors.New("instance is already running")
    ErrInvalidConfiguration     = errors.New("invalid configuration")
    ErrInvalidInstanceID        = errors.New("invalid instance ID")
    ErrInvalidProfile           = errors.New("invalid device profile")
    ErrNetworkAttachmentFailed  = errors.New("network attachment failed")
    ErrNetworkDetachmentFailed  = errors.New("network detachment failed")
    ErrOrchestratorNotInitialized = errors.New("orchestrator not initialized")
    ErrUnsupportedOperation     = errors.New("unsupported operation")
    ErrInvalidState             = errors.New("invalid state transition")
    ErrTimeout                  = errors.New("operation timed out")
    ErrResourceExhausted        = errors.New("resource limit reached")
)
```

### Rollback on Failure

```go
// Example: Start with rollback
func (o *QEMUOrchestrator) Start(ctx context.Context, id string) error {
    // Start swtpm
    if err := inst.swtpm.Start(ctx); err != nil {
        return err
    }

    // Wait for socket
    if err := waitForSocket(inst.swtpm.SocketPath()); err != nil {
        inst.swtpm.Stop() // Rollback
        return err
    }

    // Start QEMU
    if err := startQEMU(inst); err != nil {
        inst.swtpm.Stop() // Rollback
        return err
    }

    return nil
}
```

## Performance Considerations

### Instance Creation

- Disk image creation: ~1-5 seconds (depending on size)
- swtpm initialization: ~100-200ms
- Network attachment: ~50-100ms
- Total: ~2-6 seconds

### Instance Startup

- swtpm start: ~50ms
- Socket ready: ~100-200ms
- QEMU start: ~500ms-2s
- Total: ~1-3 seconds

### Recommendations

1. **Pre-create disk images** - Use copy-on-write backing files
2. **Warm start swtpm** - Keep state initialized
3. **Pool TAP devices** - Pre-create TAP devices
4. **Parallel operations** - Create instances concurrently

## Security

### Threat Vectors and Mitigations

| Threat | Mitigation | Validation |
|--------|------------|------------|
| **Network Isolation Bypass** | OVS VLAN tagging enforced at hypervisor level, not guest-configurable | OpenFlow rules verified after creation, policy engine monitors state changes |
| **TPM State Manipulation** | vTPM socket owned by QEMU process, filesystem permissions 0600 | swtpm state directory read-only to orchestrator, writable only to swtpm process |
| **Resource Exhaustion (DoS)** | MaxInstances limit, disk quota enforcement, memory limits via cgroups | Pre-flight resource checks before instance creation |
| **VM Escape** | QEMU sandboxing (seccomp, AppArmor/SELinux profiles), non-root execution | Security audits, CVE monitoring for QEMU updates |
| **Privilege Escalation** | Orchestrator runs as non-root, uses capabilities for network operations (CAP_NET_ADMIN) | Least-privilege principle, no setuid binaries |

### Security Patterns

- **Defense in depth**: Multiple layers (VM isolation, network isolation, TPM sealing)
- **Fail-safe defaults**: Quarantine network for attestation failures
- **Least privilege**: Orchestrator process has minimal capabilities

## Scalability

### 10x Load Scenario (1000 Concurrent VMs)

**Strategies**:
1. **Resource Pooling**: Pre-allocated disk images and network ports
2. **Horizontal Scaling**: Multiple orchestrator instances with shared state
3. **Lazy Initialization**: Networks and vTPM sockets created on-demand
4. **Cleanup Workers**: Background goroutines for stopped instance cleanup
5. **Rate Limiting**: MaxInstances configuration enforced at orchestrator level

**Bottlenecks**:
- OVS OVSDB connection (single socket) - mitigated with connection pooling
- Disk I/O for VM disk creation - use copy-on-write qcow2 backing files
- vTPM socket file descriptors - increase ulimit and use cleanup workers

## Container Orchestrator

The Container Orchestrator extends the compute subsystem with container lifecycle
management, integrated attestation, and policy enforcement.

### Container Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Container Orchestrator                             │
│  (pkg/compute/container)                                                │
│                                                                         │
│  ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │
│  │  Orchestrator     │   │ Measurement Log   │   │   OPA Policy      │  │
│  │                   │   │                   │   │   Engine          │  │
│  │  • Create/Start   │   │  • Event entries  │   │  • Builtin rules  │  │
│  │  • Stop/Remove    │   │  • PCR 14 extend  │   │  • Custom rules   │  │
│  │  • Attest/Verify  │   │  • Log replay     │   │  • Policy bundles │  │
│  └────────┬──────────┘   └────────┬──────────┘   └────────┬──────────┘  │
│           │                       │                       │             │
├───────────┼───────────────────────┼───────────────────────┼─────────────┤
│           │                       │                       │             │
│   ┌───────▼───────┐       ┌───────▼───────┐       ┌───────▼───────┐     │
│   │ Podman Manager│       │   TPM 2.0     │       │   SDN/OVS     │     │
│   │               │       │               │       │               │     │
│   │  • Lifecycle  │       │  • PCR extend │       │  • VLAN       │     │
│   │  • Images     │       │  • Quote      │       │  • OpenFlow   │     │
│   │  • Networks   │       │  • Verify     │       │  • Policies   │     │
│   └───────────────┘       └───────────────┘       └───────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Integration with Embedded Podman Runtime

The Container Orchestrator uses the embedded `pkg/compute/podman.PodmanManager`
which provides direct OCI runtime invocation without external daemon dependencies:

- **Single trust boundary**: No external Podman daemon to attest
- **Direct container control**: Full access to container internals for TPM measurements
- **No IPC vulnerabilities**: No socket connections that could be compromised
- **Attestation-aware lifecycle**: TPM measurements on container start/stop
- **Policy enforcement**: OPA evaluation before container creation
- **Unified networking**: Same SDN/OVS model as VMs

See [Embedded Podman Runtime](embedded-podman.md) for detailed package documentation.

### Consolidated Compute Orchestrator

The daemon's compute-orchestrator slot is filled by
`container.ComputeOrchestrator` (`pkg/compute/container/compute_orchestrator.go`),
which wraps the rich container `Orchestrator` engine behind the platform-wide
`compute.Orchestrator` interface. It carries the OVS network attach/detach and
802.1X port-authentication logic formerly owned by the deleted thin
`compute.ContainerOrchestrator`, and forwards the rich capability verbs
(`Logs`, `Attest`, `VerifyAttestation`, `EvaluatePolicy`, `PullImage`,
`VerifyImage`) for API-layer capability assertions. Container workload
attestation uses `container.HostTPMProvider`, an adapter from the go-xkms SDK
`TrustedPlatformModule` (the host TPM, `App.TPM`) to the
`container.TPMProvider` interface (PCR 14 extend, SHA-256 bank reads,
IAK-signed quotes, quote signature verification).

VM RPCs (snapshots, vTPM attestation) reach the daemon through the same
single compute-orchestrator slot; because the container orchestrator does not
implement `compute.VMSnapshotter` / `compute.VMAttester`, those RPCs return
typed capability-not-supported errors unless a `QEMUOrchestrator` is wired.

```go
type ContainerOrchestrator interface {
    // Lifecycle
    Create(ctx context.Context, spec *ContainerSpec) (*Container, error)
    Start(ctx context.Context, id string) error
    Stop(ctx context.Context, id string, timeout time.Duration) error
    Remove(ctx context.Context, id string, force bool) error

    // Status
    Get(ctx context.Context, id string) (*Container, error)
    List(ctx context.Context, opts ListOptions) ([]*Container, error)

    // Attestation
    Attest(ctx context.Context, id string) (*AttestationReport, error)
    VerifyAttestation(ctx context.Context, id string, evidence []byte) error

    // Policy
    EvaluatePolicy(ctx context.Context, spec *ContainerSpec) (*PolicyDecision, error)
}
```

### Event-Log Based Attestation

Unlike VMs which can have dedicated vTPM instances, containers share the host
TPM. The Container Orchestrator uses an event-log based attestation approach:

- **PCR 14** holds the aggregate hash of all container measurements
- A **Measurement Log** tracks individual container events
- Verification replays the log to reconstruct expected PCR value

```
Container Lifecycle Events → Measurement Log → PCR 14 Extension
```

| Event Type | Data Measured |
|------------|---------------|
| CREATE | Image digest + config digest (see [measured field list and gaps](../attestation/workload-attestation.md#container-configuration-included-in-measurement)) |
| START | Container ID + timestamp |
| STOP | Container ID + exit code |
| REMOVE | Container ID + timestamp |

**Verification Flow:**
1. Generate TPM quote over PCR 14
2. Provide measurement log to verifier
3. Verifier replays log to compute expected PCR
4. Compare computed value with quoted value
5. Extract individual container measurements from log

### Unified Network Model

Containers share the same SDN/OVS/OpenFlow network model as VMs:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      OpenFlow Controller                             │
│                   (Unified Policy Enforcement)                       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                         OVS Bridge (br-platform)                     │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┤
│  eth0    │  eth1    │  vnet0   │  vnet1   │  ctr-xxx │  ctr-yyy     │
│  (host)  │ (trunk)  │  (VM)    │  (VM)    │(container)│(container)  │
│  VLAN 1  │ trunk    │ VLAN 100 │ VLAN 200 │ VLAN 100 │ VLAN 100     │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┘
```

Network features:
- Same security groups apply to VMs and containers
- VLAN isolation per workload
- OpenFlow policies control container traffic
- Physical NICs can be managed under OVS for host traffic control

### Service Modes

Containers can run in two service modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| **Embedded** | platformd manages container directly | Sidecars, tightly-coupled services |
| **Standalone** | Runs as systemd/rc service | Databases, long-running services |

**Embedded Mode:**
- Container lifecycle tied to platformd
- Shared TPM context for attestation
- Lower overhead, simpler management

**Standalone Mode:**
- platformd generates and manages service files
- Container survives platformd restarts
- Init system auto-detected from OS (systemd/OpenRC)

See [Container Orchestrator](container-orchestrator.md) for detailed documentation.
