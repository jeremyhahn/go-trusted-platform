# SWTPM Integration with QEMU Orchestrator

This document describes the automatic TPM provisioning via swtpm in the QEMU compute orchestrator.

## Overview

The QEMU orchestrator now automatically provisions and manages software TPM (swtpm) instances for each virtual machine. This provides TPM 2.0 functionality to VMs without requiring physical TPM hardware or manual swtpm configuration.

## Architecture

### Components

1. **QEMUOrchestrator**: Main orchestrator managing VM instances
2. **qemuInstance**: Extended to include swtpm reference
3. **swtpm.SWTPM**: Software TPM implementation from `pkg/swtpm`

### Lifecycle Flow

```
Create VM → Initialize swtpm → Create TPM State
                ↓
Start VM → Start swtpm → Wait for Socket → Start QEMU
                ↓
VM Running → swtpm Running
                ↓
Stop VM → VM Exits → Auto-stop swtpm
                ↓
Delete VM → Cleanup swtpm → Remove TPM State
```

## Features

### Automatic TPM Provisioning

- **Unique TPM per VM**: Each VM instance gets its own isolated swtpm instance
- **Persistent State**: TPM state is preserved across VM restarts
- **Automatic Initialization**: First boot initializes TPM state with `swtpm_setup`
- **State Reuse**: Subsequent boots reuse existing TPM state

### TPM Configuration

Default swtpm configuration:
- **TPM Version**: TPM 2.0
- **PCR Banks**: SHA-256 (default)
- **Socket Mode**: QEMU mode (--ctrl socket)
- **State Directory**: `{workDir}/tpm/`
- **Socket Path**: `{workDir}/tpm/swtpm.sock`

### Lifecycle Management

#### Creation
- Creates TPM state directory
- Initializes TPM state if not present
- Configures QEMU to use TPM socket

#### Startup
- Starts swtpm daemon before QEMU
- Waits for socket to be ready (5s timeout)
- Passes socket path to QEMU via `-chardev` and `-tpmdev`

#### Shutdown
- Automatically stops swtpm when VM exits
- Preserves TPM state for next boot
- Copies state files back from temp directories (Docker compatibility)

#### Deletion
- Ensures swtpm is stopped
- Removes TPM state directory
- Cleans up all VM resources

## Usage

### Basic Example

```go
// Create orchestrator
config := DefaultOrchestratorConfig(ComputeTypeVM)
orch, err := NewQEMUOrchestrator(config, logger)

// Create VM with automatic TPM
profile := &entities.DeviceProfile{
    Name: "my-vm",
}
instance, err := orch.Create(ctx, profile)
// TPM is automatically created and initialized

// Start VM - swtpm starts automatically
err = orch.Start(ctx, instance.ID)
// swtpm is running and connected to QEMU

// Stop VM - swtpm stops automatically
err = orch.Stop(ctx, instance.ID)

// Delete VM - TPM state is cleaned up
err = orch.Delete(ctx, instance.ID)
```

### TPM Socket Path

The TPM socket path is stored in instance metadata:

```go
instance, err := orch.Get(ctx, instanceID)
tpmSocket := instance.Metadata["tpm_socket"]
```

### Disabling TPM

To create a VM without TPM, modify the instance config:

```go
// After Create(), before Start()
instance.Config.TPMEnabled = false
```

## Implementation Details

### createSWTPM Helper

```go
func (o *QEMUOrchestrator) createSWTPM(ctx context.Context, instanceID, workDir string) (*swtpm.SWTPM, error)
```

Creates and initializes an swtpm instance:
1. Creates `{workDir}/tpm/` directory
2. Configures swtpm with QEMU mode enabled
3. Initializes TPM state using `swtpm_setup`
4. Returns configured swtpm instance

### Start Sequence

1. Check instance state (must be StateStopped)
2. Update state to StateStarting
3. **Start swtpm daemon**
4. **Wait for socket (5s timeout)**
5. Start QEMU VM
6. Update state to StateRunning
7. Launch wait goroutine

### Wait Goroutine

Background goroutine that monitors VM exit:
1. Waits for QEMU process to exit
2. **Stops swtpm automatically**
3. Updates instance state to StateStopped
4. Cleans up resources

### Error Handling

- **swtpm start failure**: Rolls back to StateError, cleans up
- **Socket timeout**: Stops swtpm, rolls back to StateError
- **VM start failure**: Stops swtpm, rolls back to StateError
- **State update failure**: Stops both VM and swtpm

## Testing

Comprehensive test suite covering:

### Integration Tests
- `TestQEMUOrchestrator_SWTPM_Integration`: Full lifecycle
- `TestQEMUOrchestrator_SWTPM_Lifecycle`: Start/stop operations
- `TestQEMUOrchestrator_SWTPM_MultipleInstances`: Concurrent VMs

### Unit Tests
- `TestQEMUOrchestrator_SWTPM_CreateHelper`: Helper method
- `TestQEMUOrchestrator_SWTPM_SocketPath`: Path management
- `TestQEMUOrchestrator_SWTPM_StatePermissions`: File permissions
- `TestQEMUOrchestrator_SWTPM_CleanupOnError`: Error handling

### Running Tests

```bash
# Run all swtpm integration tests
go test -v -run TestQEMUOrchestrator_SWTPM ./pkg/compute

# Run specific test
go test -v -run TestQEMUOrchestrator_SWTPM_Integration ./pkg/compute
```

## Requirements

### System Dependencies
- `swtpm` - Software TPM emulator
- `swtpm_setup` - TPM state initialization tool
- `qemu-system-x86_64` - QEMU virtualization

### Installation

```bash
# Debian/Ubuntu
sudo apt-get install swtpm swtpm-tools qemu-system-x86

# Fedora/RHEL
sudo dnf install swtpm swtpm-tools qemu-kvm
```

## QEMU Integration

The swtpm socket is passed to QEMU using:

```bash
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/path/to/swtpm.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

This creates a TPM 2.0 device at `/dev/tpm0` inside the guest VM.

## State Persistence

### State Files

TPM state is stored in `{workDir}/tpm/`:
- `tpm2-00.permall` - Permanent state
- `.lock` - Lock file
- `swtpm.sock` - Unix socket (ephemeral)
- `swtpm.log` - swtpm daemon logs

### Docker Compatibility

For Docker volume mounts that don't support Unix sockets:
- State files are copied to `/tmp/swtpm-run-*`
- swtpm runs from temp directory
- State files are copied back on shutdown

## Security Considerations

### Isolation
- Each VM has isolated TPM state
- Unique socket per instance
- State directory permissions: 0755 (owner rwx)

### State Protection
- TPM state survives VM restarts
- State is deleted only on explicit VM deletion
- Lock files prevent concurrent access

### QEMU Mode
- Uses `--ctrl` socket (QEMU control channel)
- Proper handshaking with QEMU TPM emulator
- Compatible with UEFI firmware TPM access

## Troubleshooting

### swtpm not starting
- Check if swtpm is installed: `which swtpm`
- Check logs: `{workDir}/tpm/swtpm.log`
- Verify state directory permissions

### Socket not ready
- Check socket file exists: `ls -la {workDir}/tpm/swtpm.sock`
- Verify swtpm process is running: `ps aux | grep swtpm`
- Check for SELinux/AppArmor denials

### TPM not visible in VM
- Verify QEMU sees TPM: Check QEMU command line
- Check guest OS: `ls -la /dev/tpm0`
- Verify OVMF firmware supports TPM

## Performance

### Overhead
- swtpm daemon: ~5MB RAM per instance
- Startup delay: ~100-200ms (socket initialization)
- Negligible CPU impact (idle)

### Scalability
- Tested with multiple concurrent instances
- Each swtpm runs as separate process
- Linear scaling with instance count

## Future Enhancements

Potential improvements:
- Configurable PCR banks (SHA-384, SHA-512)
- TPM state encryption at rest
- Remote attestation support
- TPM event log persistence
- vTPM migration support

## References

- [swtpm GitHub](https://github.com/stefanberger/swtpm)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [QEMU TPM Documentation](https://qemu.readthedocs.io/en/latest/specs/tpm.html)
