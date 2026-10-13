# Embedded Podman Runtime

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on `pkg/compute/podman`, the embedded OCI runtime under the container orchestrator.

Direct OCI container runtime for trusted computing without external daemon dependencies.

## Overview

The `pkg/compute/podman` package provides embedded container management using direct
OCI runtime invocation (crun/runc). This architecture eliminates external daemon
dependencies for improved security and simplified trust boundaries.

### Design Goals

- **Single Trust Boundary**: One binary to attest, no external daemon
- **Direct Container Control**: Full access to container internals for TPM measurements
- **No IPC Vulnerabilities**: No socket connections that could be compromised
- **TPM Integration**: First-class support for container attestation

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Embedded Podman Runtime                        │
│  (pkg/compute/podman)                                                   │
│                                                                         │
│  ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │
│  │  PodmanManager    │   │     Runtime       │   │ ContainerAttestor │  │
│  │                   │   │                   │   │                   │  │
│  │  • Create/Start   │   │  • OCI Spec Gen   │   │  • OnStart/Stop   │  │
│  │  • Stop/Remove    │   │  • crun/runc exec │   │  • TPM Extend     │  │
│  │  • List/Inspect   │   │  • State Tracking │   │  • Quote/Verify   │  │
│  └────────┬──────────┘   └────────┬──────────┘   └────────┬──────────┘  │
│           │                       │                       │             │
│           └───────────────────────┼───────────────────────┘             │
│                                   │                                     │
│                           ┌───────▼───────┐                             │
│                           │  OCI Runtime  │                             │
│                           │  (crun/runc)  │                             │
│                           └───────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Interfaces

### PodmanManager Interface

```go
type PodmanManager interface {
    // Initialize initializes the embedded runtime
    Initialize(ctx context.Context) error

    // Image operations
    PullImage(ctx context.Context, imageRef string) error
    ListImages(ctx context.Context) ([]*Image, error)
    InspectImage(ctx context.Context, imageRef string) (*Image, error)
    RemoveImage(ctx context.Context, imageRef string, force bool) error

    // Container operations
    CreateContainer(ctx context.Context, config *ContainerConfig) (*Container, error)
    StartContainer(ctx context.Context, id string) error
    StopContainer(ctx context.Context, id string, timeout *int) error
    RemoveContainer(ctx context.Context, id string, force bool) error
    InspectContainer(ctx context.Context, id string) (*Container, error)
    ListContainers(ctx context.Context, all bool) ([]*Container, error)
    WaitContainer(ctx context.Context, id string) (int, error)
    GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*ContainerLogs, error)

    // Attestation (optional - set via WithAttestor)
    SetAttestor(attestor ContainerAttestor)
    GetAttestor() ContainerAttestor

    // Lifecycle
    Close() error
    IsInitialized() bool
}
```

### ContainerAttestor Interface

```go
type ContainerAttestor interface {
    // OnContainerStart measures container at startup
    OnContainerStart(ctx context.Context, container *Container) error

    // OnContainerStop records container stop measurement
    OnContainerStop(ctx context.Context, container *Container) error

    // GetContainerQuote generates TPM quote for container
    GetContainerQuote(ctx context.Context, containerID string, nonce []byte) (*ContainerQuote, error)

    // GetMeasurementLog returns measurement log for container
    GetMeasurementLog(ctx context.Context, containerID string) ([]*ContainerMeasurement, error)

    // VerifyQuote verifies a container quote against expected PCR
    VerifyQuote(ctx context.Context, quote *ContainerQuote, expectedPCR []byte) error
}
```

## Configuration

### PodmanConfig

Top-level configuration for the embedded runtime:

```go
type PodmanConfig struct {
    // Storage paths
    StorageRoot string  // Default: /var/lib/containers/storage
    RunRoot     string  // Default: /run/containers/storage
    TmpDir      string  // Default: /run/libpod

    // Storage driver (overlay, vfs, btrfs, zfs, devmapper)
    GraphDriver string  // Default: overlay

    // OCI Runtime (crun, runc, youki, runsc, kata)
    OCIRuntime string   // Default: crun

    // Cgroup manager (systemd, cgroupfs)
    CgroupManager string  // Default: systemd

    // Events logger (file, journald, none)
    EventsLogger string   // Default: file

    Namespace          string
    NetworkConfigDir   string  // Default: /etc/cni/net.d
    DefaultNetworkMode string  // Default: bridge
    DefaultImage       string
    Debug              bool

    // Timeouts
    Timeout     time.Duration  // Default: 30s
    StopTimeout int            // Default: 10 (seconds)

    // Limits
    MaxContainers int  // Default: 100

    // TPM access. This is a default for the container SPECIFICATION, which
    // ComputeOrchestrator.buildContainerSpec copies into
    // OrchestratorContainerSpec.TPMAccess before the container is measured.
    // It is deliberately not carried into RuntimeConfig or ManagerConfig.
    EnableTPMAccess bool  // Default: false

    // Registry configuration
    RegistryAuth       map[string]*RegistryCredentials
    InsecureRegistries []string
}
```

### RuntimeConfig

Low-level runtime configuration:

```go
type RuntimeConfig struct {
    Root            string  // Container storage root
    RunRoot         string  // Runtime state directory
    TmpDir          string  // Temporary files directory
    GraphDriverName string  // Storage driver name
    StaticDir       string  // Static libpod data
    VolumePath      string  // Volume storage path
    OCIRuntime      string  // OCI runtime binary
    ImageStorePath  string  // Image storage path
}
```

The runtime carries **no** TPM default. A host-level `EnableTPMAccess` flag used
to grant `/dev/tpm0` to every container the runtime started, whatever its
configuration said, so a container could receive the host root of trust without
that grant appearing in its configuration digest. The grant now has exactly one
source: `ContainerConfig.TPMAccess`, which the orchestrator derives from the
measured `/dev/tpm0` mount (`PodmanContainerConfig.GrantsTPMDevice`). A caller
that wants a default must put it in the specification, where it is measured,
before the container is created.

## Usage

### Basic Container Lifecycle

```go
// Create manager with default configuration
config := podman.DefaultPodmanConfig()
manager, err := podman.NewPodmanManager(config.ToManagerConfig())
if err != nil {
    return err
}

// Initialize the embedded runtime
ctx := context.Background()
if err := manager.Initialize(ctx); err != nil {
    return err
}
defer manager.Close()

// Pull image
if err := manager.PullImage(ctx, "docker.io/library/alpine:latest"); err != nil {
    return err
}

// Create container
containerConfig := &podman.ContainerConfig{
    Name:    "my-container",
    Image:   "docker.io/library/alpine:latest",
    Command: []string{"/bin/sh", "-c", "echo hello"},
}

container, err := manager.CreateContainer(ctx, containerConfig)
if err != nil {
    return err
}

// Start container
if err := manager.StartContainer(ctx, container.ID); err != nil {
    return err
}

// Wait for completion
exitCode, err := manager.WaitContainer(ctx, container.ID)

// Cleanup
timeout := 10
manager.StopContainer(ctx, container.ID, &timeout)
manager.RemoveContainer(ctx, container.ID, false)
```

### With TPM Attestation

```go
// Create manager with attestor
manager, _ := podman.NewPodmanManager(
    config.ToManagerConfig(),
    podman.WithAttestor(myAttestor),
    podman.WithManagerLogger(logger),
)

// Containers automatically measured on start/stop
if err := manager.StartContainer(ctx, id); err != nil {
    return err
}
// TPM PCR 14 extended, measurement log updated
```

## Container Configuration

### ContainerConfig Fields

```go
type ContainerConfig struct {
    Name        string              // Container name (required, unique)
    Image       string              // Image reference (required)
    Command     []string            // Command to run
    Entrypoint  []string            // Override image entrypoint
    Environment map[string]string   // Environment variables
    Labels      map[string]string   // Container labels
    Mounts      []Mount             // Volume/bind mounts
    Ports       []PortMapping       // Port mappings
    Resources   *ResourceLimits     // Resource limits
    TPMAccess   bool                // TPM device access
    NetworkMode string              // bridge, host, none, slirp4netns
    User        string              // User to run as (uid or username)
    WorkDir     string              // Working directory
    Hostname    string              // Container hostname
    Privileged  bool                // Privileged mode
    ReadOnly    bool                // Read-only root filesystem
    AutoRemove  bool                // Remove on exit
    StopTimeout *int                // Stop timeout (seconds)
    CapAdd      []string            // Linux capabilities to add
    CapDrop     []string            // Linux capabilities to drop
    SecurityOpt []string            // Security options
    DNS         []string            // DNS servers
    DNSSearch   []string            // DNS search domains
}
```

### Resource Limits

```go
type ResourceLimits struct {
    MemoryLimit       int64    // Memory limit in bytes
    MemoryReservation int64    // Memory soft limit in bytes
    MemorySwap        int64    // Memory+swap limit in bytes
    CPUQuota          int64    // CPU quota (microseconds per period)
    CPUPeriod         int64    // CPU CFS period (microseconds)
    CPUShares         int64    // CPU shares (relative weight)
    CPUs              float64  // Number of CPUs, e.g. 1.5
    PidsLimit         int64    // Process limit
}
```

### TPM Device Access

Enable container access to host TPM:

```go
config := &podman.ContainerConfig{
    Name:      "tpm-aware-container",
    Image:     "my-app:latest",
    TPMAccess: true,  // Adds the /dev/tpm0 device (char 10:224)
}
```

## Package Structure

```
pkg/compute/podman/
├── config.go           # Configuration types (PodmanConfig, ManagerConfig)
├── manager.go          # PodmanManager implementation
├── manager_ops.go      # PodmanManager operations
├── runtime.go          # Embedded OCI runtime (crun/runc invocation)
├── types.go            # Container, Image, and related types
├── attestation.go      # ContainerAttestor interface and types
├── attach.go           # Container attach
├── exec.go             # Container exec
├── metrics.go          # Container metrics
├── pty_linux.go        # PTY support (pty_other.go elsewhere)
├── errors.go           # Typed error definitions
└── *_test.go           # Unit tests
```

## Error Handling

All errors are typed for proper error handling:

```go
var (
    ErrClientNotConnected       = errors.New("client not connected")
    ErrImageNotFound            = errors.New("image not found")
    ErrContainerNotFound        = errors.New("container not found")
    ErrContainerAlreadyExists   = errors.New("container already exists")
    ErrContainerNotRunning      = errors.New("container is not running")
    ErrContainerAlreadyRunning  = errors.New("container is already running")
    ErrInvalidContainerConfig   = errors.New("invalid container configuration")
)

// Wrapped errors for context
type ImageError struct {
    ImageRef  string
    Operation string
    Err       error
}

type ContainerError struct {
    ContainerID string
    Operation   string
    Err         error
}

type RuntimeError struct {
    Operation string
    Err       error
}

type ConfigValidationError struct {
    Field   string
    Message string
}
```

## Security Considerations

### Trust Boundary

The embedded architecture provides a single trust boundary:

```
┌─────────────────────────────────────────────┐
│              platformd Binary               │
│                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │
│  │ Runtime │  │ Manager │  │ Attestation │  │
│  └─────────┘  └─────────┘  └─────────────┘  │
│                                             │
│         Single Binary to Attest             │
└─────────────────────────────────────────────┘
         │
         │ exec
         ▼
┌─────────────────────────────────────────────┐
│           OCI Runtime (crun/runc)           │
│         (Isolated per container)            │
└─────────────────────────────────────────────┘
```

### TPM Integration

- PCR 14 used for container measurements
- Image digest + config digest measured at creation
- Start/stop events recorded in measurement log
- Quote verification replays log to validate PCR

### Compared to Daemon Architecture

| Aspect | Embedded | External Daemon |
|--------|----------|-----------------|
| Trust boundary | Single binary | Multiple processes |
| Attack surface | Minimal | IPC/socket exposure |
| TPM access | Direct | Proxy required |
| Startup time | Fast | Daemon startup overhead |
| Resource usage | Lower | Daemon overhead |

## OCI Runtime Support

Supported OCI runtimes:

| Runtime | Description |
|---------|-------------|
| `crun` | Default, fast C-based runtime |
| `runc` | Reference OCI runtime |
| `youki` | Rust-based runtime |
| `runsc` | gVisor sandboxed runtime |
| `kata` | Kata Containers VM-based runtime |

## See Also

- [Container Orchestrator](container-orchestrator.md) - Higher-level orchestration
- [Architecture](architecture.md) - Overall compute architecture
- [TPM Attestation](../tpm/attestation.md) - TPM measurement details
