# SWTPM Integration with QEMU Orchestrator

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on how `pkg/compute` (QEMU orchestrator) provisions and runs a `pkg/swtpm` instance per VM.

This document describes the automatic TPM provisioning via swtpm in the QEMU compute orchestrator.

## Overview

The QEMU orchestrator now automatically provisions and manages software TPM (swtpm) instances for each virtual machine. This provides TPM 2.0 functionality to VMs without requiring physical TPM hardware or manual swtpm configuration.

## Architecture

### Components

1. **QEMUOrchestrator**: Main orchestrator managing VM instances
2. **qemuInstance**: holds its swtpm as the `tpmEmulator` interface
   (`swtpm tpmEmulator`)
3. **swtpm.SWTPM**: Software TPM implementation from `pkg/swtpm`, the default
   `tpmEmulator` the orchestrator's `emulatorFor` seam opens

`Create` sources the swtpm in `provisionVTPM` (`pkg/compute/qemu.go`):

- **vTPM generator configured**: the VM gets the profile's `pkg/vtpm` bundle
  (looked up, or generated on first use), with a CA-issued EK. State lives in
  `{bundle StoragePath}/tpm/` and the socket is the bundle's `SocketPath`.
- **No generator**: the VM gets an anonymous swtpm in `{workDir}/tpm/` with no
  EK identity, and a warning is logged. A profile that carries `EKCert` or
  `EKSerial` fails with `ErrVTPMIdentityRequired` instead.

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

Default swtpm configuration (anonymous swtpm; a vTPM bundle uses its own paths):
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
- Copies the `tpm2-*` and `.lock` files back from the temp directory, if one was used (see Docker Compatibility)

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

The per-instance switch is `VMSpec.DisableTPM` (`pkg/compute/vm_create.go`),
which the daemon sets from a CreateVM request carrying `tpm.enabled: false`
(`platformctl compute create --tpm=false`). `CreateWithSpec` sets
`TPMEnabled: !spec.DisableTPM` and, when it is enabled, provisions the TPM
before it returns; plain `Create` is `CreateWithSpec` with an empty `VMSpec`,
so it always gets a TPM. `Start` launches swtpm whenever the
instance holds one, so setting `instance.Config.TPMEnabled = false` after
`Create` has no effect.

## Implementation Details

### createSWTPM Helper

```go
func (o *QEMUOrchestrator) createSWTPM(ctx context.Context, instanceID, workDir string) (tpmEmulator, error)
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

### Unit Tests

`pkg/compute/qemu_swtpm_test.go` replaces swtpm, swtpm_setup and qemu-img
with in-memory fakes through the orchestrator's `emulatorFor` and
`createDisk` seams, so the tests need none of the binaries and never skip:

- `TestQEMUOrchestrator_SWTPM_Create`: TPM state, socket metadata, disk, Delete
- `TestQEMUOrchestrator_SWTPM_DeleteStopsRunningSWTPM`: Delete stops swtpm
- `TestQEMUOrchestrator_SWTPM_CreateHelper`: state reuse without re-initializing
- `TestQEMUOrchestrator_SWTPM_CreateHelperErrors`: open, setup and directory failures
- `TestQEMUOrchestrator_SWTPM_MultipleInstances`: one socket and state directory per VM
- `TestQEMUOrchestrator_SWTPM_StatePermissions`: owner rwx on the state directory
- `TestQEMUOrchestrator_SWTPM_CleanupOnError`: no instance kept after a failure
- `TestQEMUOrchestrator_SWTPM_Bundle`: a VM boots against its profile's vTPM bundle

```bash
make test-pkg PKG=./pkg/compute/ TESTFLAGS=-run=TestQEMUOrchestrator_SWTPM
```

### Integration Tests

`test/integration/vtpm/qemu_swtpm_test.go` creates and deletes a VM with
the real swtpm_setup, qemu-img and OVMF firmware. It runs in the
devcontainer, and a missing binary fails it:

```bash
make integration-test-vtpm
```

## Requirements

### System Dependencies
- `swtpm` - Software TPM emulator
- `swtpm_setup` - TPM state initialization tool
- `qemu-system-x86_64` (amd64 host) or `qemu-system-aarch64` (arm64 host) -
  QEMU virtualization

### Installation

```bash
# Debian/Ubuntu
sudo apt-get install swtpm swtpm-tools qemu-system-x86

# Fedora/RHEL
sudo dnf install swtpm swtpm-tools qemu-kvm

# Alpine arm64 (the Raspberry Pi 4 compute template)
apk add qemu-system-aarch64 qemu-img swtpm swtpm-tools aavmf
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

On aarch64 the front-end is `-device tpm-tis-device` (`pkg/qemu/arch.go`).
`pkg/qemu` adds these arguments only if the socket exists when QEMU starts.
Otherwise the guest boots without a TPM.

This creates a TPM 2.0 device at `/dev/tpm0` inside the guest VM.

## State Persistence

### State Files

TPM state is stored in `{workDir}/tpm/`:
- `tpm2-00.permall` - Permanent state
- `.lock` - Lock file
- `swtpm.sock` - Unix socket (ephemeral)
- `swtpm.log` - swtpm daemon logs

The socket and the log are written beside each other, so both move to the temp
directory when one is in use.

### Docker Compatibility

`swtpm.Start` (`pkg/swtpm/swtpm.go`) runs swtpm from a temp directory when the
state directory is outside `/tmp/` and `/var/run/`, or when the socket path is
too long for a Unix socket. The default compute work directory,
`/var/lib/trusted-platform/compute`, is outside both, so this is the default
case:
- State files are copied to `$TMPDIR/swtpm-*`
- swtpm runs there, with its socket and log
- On `Stop`, the `tpm2-*` and `.lock` files are copied back (mode 0640), and the temp directory is removed

`swtpm_setup` also runs in its own `swtpm-init-*` temp directory, and its
output is copied into the state directory.

The relocated socket path is not handed to QEMU. `Create` stores the original
path in the QEMU config and in `Metadata["tpm_socket"]`.

## Security Considerations

### Isolation
- Each VM has isolated TPM state
- Unique socket per instance
- State directory permissions: 0755 (world-readable, owner-writable)

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
- Check logs: `swtpm.log` beside the socket (`$TMPDIR/swtpm-*/` when relocated, else `{workDir}/tpm/`)
- Verify state directory permissions

### Socket not ready
- Check socket file exists: `swtpm.sock` in the same directory as the log
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
