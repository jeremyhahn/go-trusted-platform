# vTPM API Reference

The vTPM service exposes bundle and template management operations via multiple protocols for maximum interoperability.

## Supported Protocols

| Protocol | Transport | Port/Path | Use Case |
|----------|-----------|-----------|----------|
| [REST](api-reference-rest.md) | HTTPS | 8443 | Web clients, external systems |
| [gRPC](api-reference-grpc.md) | TCP | 9443 | High-performance service-to-service |
| [QUIC](api-reference-quic.md) | UDP | 9444 | Low-latency, mobile clients |
| [MCP](api-reference-mcp.md) | stdio/HTTP | 9445 | AI/LLM integration |
| [Unix Socket](api-reference-unix.md) | Unix | /run/platformd.sock | Local IPC, CLI |

## Service Interface

```go
type VTPMService interface {
    // Bundle CRUD
    CreateBundle(ctx context.Context, opts *CreateBundleOptions) (*Bundle, error)
    GetBundle(ctx context.Context, id string) (*Bundle, error)
    DeleteBundle(ctx context.Context, id string) error
    ListBundles(ctx context.Context, opts *ListOptions) ([]*Bundle, error)

    // Template CRUD
    CreateTemplate(ctx context.Context, opts *CreateTemplateOptions) (*Template, error)
    GetTemplate(ctx context.Context, id string) (*Template, error)
    DeleteTemplate(ctx context.Context, id string) error
    ListTemplates(ctx context.Context) ([]*Template, error)
    CloneTemplate(ctx context.Context, opts *CloneOptions) (*Bundle, error)

    // Export/Import
    ExportBundle(ctx context.Context, id string, w io.Writer) error
    ImportBundle(ctx context.Context, r io.Reader) (*Bundle, error)

    // Validation
    ValidateBundle(ctx context.Context, id string) error

    // Path helpers
    GetBundlePath(id string) string
    GetTPMSocketPath(id string) string
    GetNVRAMPath(id string) string
}
```

## Operations Summary

| Operation | Description |
|-----------|-------------|
| CreateBundle | Create vTPM bundle with CA-issued EK certificate |
| GetBundle | Retrieve bundle by ID |
| DeleteBundle | Delete bundle and associated files |
| ListBundles | List bundles with filtering |
| CreateTemplate | Create reusable template for cloning |
| GetTemplate | Retrieve template by ID |
| DeleteTemplate | Delete template |
| ListTemplates | List all templates |
| CloneTemplate | Clone template to create bundle with unique identity |
| ExportBundle | Export bundle to tar.gz archive |
| ImportBundle | Import bundle from tar.gz archive |
| ValidateBundle | Verify bundle integrity via checksums |
| GetBundlePath | Get bundle filesystem path |
| GetTPMSocketPath | Get swtpm socket path for VM attachment |
| GetNVRAMPath | Get OVMF NVRAM path for VM attachment |

## Data Types

### BundleMode

```go
type BundleMode string

const (
    BundleModeTemplate    BundleMode = "template"     // No identity, EK cert at clone time
    BundleModePreAssigned BundleMode = "pre-assigned" // Complete identity at creation
)
```

### EKAlgorithm

```go
type EKAlgorithm string

const (
    EKAlgorithmRSA EKAlgorithm = "RSA"  // RSA 2048, NV Index 0x01C00002
    EKAlgorithmECC EKAlgorithm = "ECC"  // ECC P-256, NV Index 0x01C0000A
)
```

### Bundle

```go
type Bundle struct {
    ID             string              `json:"id"`
    Mode           BundleMode          `json:"mode"`
    Manifest       *Manifest           `json:"manifest"`
    TPMState       *TPMState           `json:"tpm_state"`
    OVMFState      *OVMFState          `json:"ovmf_state"`
    SecureBootKeys *SecureBootKeyPaths `json:"secure_boot_keys"`
    CreatedAt      time.Time           `json:"created_at"`
    ClonedFrom     string              `json:"cloned_from,omitempty"`
}
```

### Template

```go
type Template struct {
    ID                string      `json:"id"`
    Description       string      `json:"description,omitempty"`
    TPMStateDir       string      `json:"tpm_state_dir"`
    NVRAMPath         string      `json:"nvram_path"`
    SecureBootKeysDir string      `json:"secure_boot_keys_dir"`
    EKAlgorithm       EKAlgorithm `json:"ek_algorithm"`
    SecureBootEnabled bool        `json:"secure_boot_enabled"`
    CreatedAt         time.Time   `json:"created_at"`
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrBundleNotFound` | Bundle with specified ID does not exist |
| `ErrTemplateNotFound` | Template with specified ID does not exist |
| `ErrBundleExists` | Bundle with specified ID already exists |
| `ErrTemplateExists` | Template with specified ID already exists |
| `ErrInvalidConfig` | Configuration validation failed |
| `ErrInvalidManifest` | Manifest validation failed |
| `ErrChecksumMismatch` | File checksum verification failed |
| `ErrOVMFNotFound` | OVMF firmware files not found |
| `ErrSwtpmFailed` | swtpm operation failed |

## Service Initialization

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"

config := vtpm.DefaultConfig()
config.BaseDir = "/var/lib/my-app/vtpm"

if err := config.Validate(); err != nil {
    return err
}

service, err := vtpm.NewService(config, logger, caAdapter)
if err != nil {
    return err
}
defer service.Close()
```
