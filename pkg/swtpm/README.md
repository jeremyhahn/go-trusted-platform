# SWTPM Package

The `swtpm` package provides a Go interface for managing software TPM (Trusted Platform Module) instances using the `swtpm` daemon. This is particularly useful for testing, virtualization, and development scenarios where a hardware TPM is not available or desired.

## Features

- Initialize TPM state with configurable PCR banks
- Start and stop swtpm daemon processes
- Monitor daemon status
- Socket readiness detection
- Graceful shutdown with timeout handling
- Thread-safe operations
- Comprehensive error handling

## Requirements

The following binaries must be installed on the system:

- `swtpm` - Software TPM emulator daemon
- `swtpm_setup` - TPM state initialization utility

### Installation

**Debian/Ubuntu:**
```bash
sudo apt-get install swtpm swtpm-tools
```

**Fedora/RHEL:**
```bash
sudo dnf install swtpm swtpm-tools
```

**Alpine:**
```bash
sudo apk add swtpm swtpm-tools
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

func main() {
    // Create configuration
    config := &swtpm.Config{
        StateDir:   "/tmp/my-tpm",
        SocketPath: "/tmp/my-tpm/swtpm.sock",
        PCRBanks:   []string{"sha256"},
        LogLevel:   20,
        Debug:      true,
    }

    // Create logger
    logger := logging.DefaultLogger()

    // Create SWTPM instance
    tpm, err := swtpm.NewSWTPM(config, logger)
    if err != nil {
        log.Fatal(err)
    }

    // Initialize TPM state
    ctx := context.Background()
    if err := tpm.Initialize(ctx); err != nil {
        log.Fatal(err)
    }

    // Start the daemon
    if err := tpm.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer tpm.Stop()

    // Wait for socket to be ready
    if err := tpm.WaitForSocket(5 * time.Second); err != nil {
        log.Fatal(err)
    }

    // Check status
    if tpm.IsRunning() {
        log.Printf("TPM is running with PID: %d", tpm.PID())
        log.Printf("Socket path: %s", tpm.SocketPath())
    }
}
```

### Using with QEMU

```go
package main

import (
    "context"
    "fmt"
    "os/exec"

    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

func main() {
    config := &swtpm.Config{
        StateDir: "/tmp/qemu-tpm",
        PCRBanks: []string{"sha256"},
    }

    logger := logging.DefaultLogger()
    tpm, _ := swtpm.NewSWTPM(config, logger)

    ctx := context.Background()
    tpm.Initialize(ctx)
    tpm.Start(ctx)
    defer tpm.Stop()

    // Build QEMU command with TPM
    qemuArgs := []string{
        "-machine", "q35",
        "-chardev", fmt.Sprintf("socket,id=chrtpm,path=%s", tpm.SocketPath()),
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
        // ... other QEMU arguments
    }

    cmd := exec.Command("qemu-system-x86_64", qemuArgs...)
    cmd.Run()
}
```

### Cleanup Existing Processes

```go
// Stop any existing swtpm processes for a state directory
if err := swtpm.StopExisting("/tmp/my-tpm"); err != nil {
    log.Printf("Warning: failed to stop existing processes: %v", err)
}
```

## Configuration

### Config Structure

```go
type Config struct {
    StateDir   string   // TPM state directory (required)
    SocketPath string   // Socket path for connections (default: {StateDir}/swtpm.sock)
    PCRBanks   []string // PCR banks to enable (default: ["sha256"])
    LogLevel   int      // Log level 0-20 (default: 20)
    Debug      bool     // Enable debug logging (default: false)
}
```

### PCR Banks

Supported PCR banks:
- `sha1`
- `sha256` (recommended)
- `sha384`
- `sha512`

You can enable multiple banks:
```go
config := &swtpm.Config{
    StateDir: "/tmp/tpm",
    PCRBanks: []string{"sha256", "sha384"},
}
```

## Error Handling

The package defines several sentinel errors:

```go
var (
    ErrSWTPMNotInstalled = errors.New("swtpm not installed")
    ErrSocketNotReady    = errors.New("swtpm socket not ready")
    ErrInitFailed        = errors.New("swtpm initialization failed")
    ErrAlreadyRunning    = errors.New("swtpm already running")
    ErrNotRunning        = errors.New("swtpm not running")
    ErrInvalidConfig     = errors.New("invalid swtpm configuration")
    ErrTimeout           = errors.New("operation timed out")
)
```

Example error handling:

```go
if err := tpm.Start(ctx); err != nil {
    if errors.Is(err, swtpm.ErrAlreadyRunning) {
        log.Println("TPM is already running")
    } else {
        log.Fatal(err)
    }
}
```

## Thread Safety

All SWTPM methods are thread-safe. The implementation uses read-write mutexes to protect concurrent access to internal state.

## Testing

Run the tests with:

```bash
# Unit tests
make test-swtpm

# With coverage
make coverage-swtpm

# With verbose output
go test -v ./pkg/swtpm/...
```

The unit tests need neither `swtpm` nor `swtpm_setup`: they replace both
binaries with an in-memory fake and never skip. The tests that drive the real
daemon live in `test/integration/vtpm/swtpm_test.go` and run in the
devcontainer with `make integration-test-vtpm`; a missing binary fails them.

## Architecture

### Initialization Flow

1. Create state directory if it doesn't exist
2. Run `swtpm_setup` with TPM2 and PCR bank configuration
3. Generate TPM state files in the state directory

### Daemon Management

1. Start `swtpm socket` in daemon mode
2. Monitor process health via PID and signal checks
3. Wait for socket file creation
4. Handle graceful shutdown with SIGTERM
5. Force kill with SIGKILL if graceful shutdown fails

### Process Cleanup

- Process group management for clean shutdown
- Timeout-based kill fallback
- Automatic process reaping
- Concurrent operation safety

## Related Packages

- `pkg/tpm2` - TPM 2.0 operations and utilities
- `pkg/logging` - Structured logging interface

## References

- [SWTPM Documentation](https://github.com/stefanberger/swtpm)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
