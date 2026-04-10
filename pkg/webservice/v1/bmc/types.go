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

package bmc

import (
	"context"
	"net/http"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
)

// RestHandler defines the BMC REST endpoint interface.
type RestHandler interface {
	// PowerAction executes a power action (on, off, reset, cycle).
	// POST /api/v1/bmc/{profileID}/power
	PowerAction(w http.ResponseWriter, r *http.Request)

	// PowerStatus returns the current power state.
	// GET /api/v1/bmc/{profileID}/power
	PowerStatus(w http.ResponseWriter, r *http.Request)

	// SetBootDevice sets the boot device for the system.
	// POST /api/v1/bmc/{profileID}/boot-device
	SetBootDevice(w http.ResponseWriter, r *http.Request)

	// GetBootDevice returns the current boot device override.
	// GET /api/v1/bmc/{profileID}/boot-device
	GetBootDevice(w http.ResponseWriter, r *http.Request)

	// MountISO mounts an ISO image via virtual media.
	// POST /api/v1/bmc/{profileID}/virtual-media
	MountISO(w http.ResponseWriter, r *http.Request)

	// UnmountISO unmounts the currently mounted ISO virtual media.
	// DELETE /api/v1/bmc/{profileID}/virtual-media
	UnmountISO(w http.ResponseWriter, r *http.Request)

	// VirtualMediaStatus returns the current virtual media state.
	// GET /api/v1/bmc/{profileID}/virtual-media
	VirtualMediaStatus(w http.ResponseWriter, r *http.Request)

	// GetSensors returns sensor readings from the BMC.
	// GET /api/v1/bmc/{profileID}/sensors
	GetSensors(w http.ResponseWriter, r *http.Request)

	// GetSystemInfo returns system identification information.
	// GET /api/v1/bmc/{profileID}/system-info
	GetSystemInfo(w http.ResponseWriter, r *http.Request)

	// Provision triggers a bare metal provisioning workflow.
	// POST /api/v1/bmc/{profileID}/provision
	Provision(w http.ResponseWriter, r *http.Request)

	// ProvisionStatus returns the status of a provisioning workflow.
	// GET /api/v1/bmc/{profileID}/provision
	ProvisionStatus(w http.ResponseWriter, r *http.Request)
}

// BMCServicer defines the BMC service operations required by the handler.
type BMCServicer interface {
	PowerOn(ctx context.Context, profileID uint64) error
	PowerOff(ctx context.Context, profileID uint64) error
	PowerReset(ctx context.Context, profileID uint64) error
	PowerCycle(ctx context.Context, profileID uint64) error
	PowerStatus(ctx context.Context, profileID uint64) (bmcpkg.PowerState, error)
	SetBootDevice(ctx context.Context, profileID uint64, device bmcpkg.BootDevice, persistent bool) error
	GetBootDevice(ctx context.Context, profileID uint64) (bmcpkg.BootDevice, error)
	MountISO(ctx context.Context, profileID uint64, isoURL string) error
	UnmountISO(ctx context.Context, profileID uint64) error
	VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcpkg.VirtualMediaInfo, error)
	GetSensors(ctx context.Context, profileID uint64) ([]bmcpkg.SensorReading, error)
	GetSystemInfo(ctx context.Context, profileID uint64) (*bmcpkg.SystemInfo, error)
}

// BaremetalServicer defines the bare metal provisioning operations required by the handler.
type BaremetalServicer interface {
	Provision(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error)
	Status(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error)
}

// PowerActionRequest represents the request body for a power action.
type PowerActionRequest struct {
	Action string `json:"action"`
}

// PowerStatusResponse represents the response for a power status query.
type PowerStatusResponse struct {
	State string `json:"state"`
}

// SetBootDeviceRequest represents the request body for setting the boot device.
type SetBootDeviceRequest struct {
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

// BootDeviceResponse represents the response for a boot device query.
type BootDeviceResponse struct {
	Device string `json:"device"`
}

// MountISORequest represents the request body for mounting an ISO image.
type MountISORequest struct {
	ISOURL string `json:"iso_url"`
}

// ProvisionRequest represents the request body for triggering provisioning.
type ProvisionRequest struct {
	ISOURL string `json:"iso_url,omitempty"`
}
