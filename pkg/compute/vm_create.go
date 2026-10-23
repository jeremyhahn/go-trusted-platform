// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package compute

import (
	"context"
	"errors"
	"net"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// ErrInvalidVMSpec is returned when a VMSpec carries a value the
// orchestrator cannot honour.
var ErrInvalidVMSpec = errors.New("invalid VM spec")

// Disk buses a VMSpec may name. Each architecture has exactly one boot-disk
// bus, so naming the other one is refused rather than ignored.
const (
	DiskBusSATA   = "sata"
	DiskBusVirtio = "virtio"
)

// Boot modes a VMSpec may ask for. Install mode needs an ISO, which a
// VMSpec cannot carry, so it is not offered.
const (
	BootModeDisk = "boot"
	BootModePXE  = "pxe"
)

// VMSpec is what a caller asks of a new VM beyond its device profile. The
// zero value is the orchestrator's default VM.
type VMSpec struct {
	// MemoryMB is the guest RAM. Zero means the orchestrator default.
	MemoryMB int

	// CPUs is the number of vCPUs. Zero means the orchestrator default.
	CPUs int

	// DiskSizeGB is the size of the boot disk. Zero means the orchestrator
	// default.
	DiskSizeGB int

	// DiskBus is the boot disk's bus. Empty means the architecture's bus.
	DiskBus string

	// SecureBoot boots the guest under UEFI Secure Boot.
	SecureBoot bool

	// DisableTPM creates the VM without a vTPM. A VM has one by default.
	DisableTPM bool

	// BootMode is BootModeDisk or BootModePXE. Empty means BootModeDisk.
	BootMode string

	// MACAddress is the primary NIC's address. Empty means generated.
	MACAddress string

	// Bridge is the bridge the primary NIC attaches to. Empty means the
	// orchestrator's bridge.
	Bridge string

	// Description, Labels and Metadata are the caller's own; the
	// orchestrator stores and reports them.
	Description string
	Labels      map[string]string
	Metadata    map[string]string
}

// IsDefault reports whether spec asks for nothing beyond a default VM.
func (spec VMSpec) IsDefault() bool {
	return spec.MemoryMB == 0 && spec.CPUs == 0 && spec.DiskSizeGB == 0 &&
		spec.DiskBus == "" && !spec.SecureBoot && !spec.DisableTPM &&
		spec.BootMode == "" && spec.MACAddress == "" && spec.Bridge == "" &&
		spec.Description == "" && len(spec.Labels) == 0 && len(spec.Metadata) == 0
}

// Validate refuses a value no orchestrator can honour: a negative size, an
// unknown disk bus or boot mode, or a malformed MAC address.
func (spec VMSpec) Validate() error {
	switch {
	case spec.MemoryMB < 0:
		return invalidVMSpec("memory must not be negative")
	case spec.CPUs < 0:
		return invalidVMSpec("cpus must not be negative")
	case spec.DiskSizeGB < 0:
		return invalidVMSpec("disk size must not be negative")
	case spec.DiskBus != "" && spec.DiskBus != DiskBusSATA && spec.DiskBus != DiskBusVirtio:
		return invalidVMSpec("unknown disk bus " + spec.DiskBus)
	case spec.BootMode != "" && spec.BootMode != BootModeDisk && spec.BootMode != BootModePXE:
		return invalidVMSpec("unknown boot mode " + spec.BootMode)
	}
	if spec.MACAddress != "" {
		if _, err := net.ParseMAC(spec.MACAddress); err != nil {
			return invalidVMSpec("invalid MAC address " + spec.MACAddress)
		}
	}
	return nil
}

func invalidVMSpec(msg string) error {
	return &SentinelCauseError{Sentinel: ErrInvalidVMSpec, Cause: &MessageError{Msg: msg}}
}

// VMCreator is implemented by orchestrators that can honour a VMSpec.
type VMCreator interface {
	CreateWithSpec(ctx context.Context, profile *entities.DeviceProfile, spec VMSpec) (*Instance, error)
}

// CreateWithSpec creates a VM under spec. An orchestrator without VMCreator
// can only create a default VM; anything else is refused with
// ErrUnsupportedOperation rather than silently ignored.
func CreateWithSpec(ctx context.Context, o Orchestrator, profile *entities.DeviceProfile, spec VMSpec) (*Instance, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if creator, ok := o.(VMCreator); ok {
		return creator.CreateWithSpec(ctx, profile, spec)
	}
	if !spec.IsDefault() {
		return nil, &SentinelCauseError{Sentinel: ErrUnsupportedOperation, Cause: &MessageError{Msg: "VM specs are not supported by this compute orchestrator"}}
	}
	return o.Create(ctx, profile)
}

// StartCleanupError is returned when a just-created instance failed to start
// and could not be deleted afterwards either. It unwraps to the start error,
// which is what the caller asked about; the cleanup failure rides along in
// the message.
type StartCleanupError struct {
	Start   error
	Cleanup error
}

func (e *StartCleanupError) Error() string {
	return e.Start.Error() + " (deleting the instance also failed: " + e.Cleanup.Error() + ")"
}

func (e *StartCleanupError) Unwrap() error {
	return e.Start
}

// StartOrDelete starts a just-created instance. If the start fails the
// instance is deleted, so a failed create-and-start leaves nothing behind,
// and the start error is returned.
func StartOrDelete(ctx context.Context, o Orchestrator, instanceID string) error {
	startErr := o.Start(ctx, instanceID)
	if startErr == nil {
		return nil
	}
	// The delete runs even when the start failed because ctx ended.
	if err := o.Delete(context.WithoutCancel(ctx), instanceID); err != nil {
		return &StartCleanupError{Start: startErr, Cleanup: err}
	}
	return startErr
}
