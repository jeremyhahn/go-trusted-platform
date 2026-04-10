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

package baremetal

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// ProvisioningStatus represents the current phase of a bare metal provision.
type ProvisioningStatus string

const (
	// StatusPending indicates the provision has been created but not started.
	StatusPending ProvisioningStatus = "pending"

	// StatusConnecting indicates BMC connectivity is being established.
	StatusConnecting ProvisioningStatus = "connecting"

	// StatusSettingBoot indicates the boot device is being configured.
	StatusSettingBoot ProvisioningStatus = "setting_boot"

	// StatusMountingISO indicates virtual media is being mounted.
	StatusMountingISO ProvisioningStatus = "mounting_iso"

	// StatusPoweringOn indicates the system is being powered on.
	StatusPoweringOn ProvisioningStatus = "powering_on"

	// StatusInstalling indicates the OS installation is in progress.
	StatusInstalling ProvisioningStatus = "installing"

	// StatusFinalizing indicates post-install cleanup is in progress.
	StatusFinalizing ProvisioningStatus = "finalizing"

	// StatusComplete indicates provisioning completed successfully.
	StatusComplete ProvisioningStatus = "complete"

	// StatusFailed indicates provisioning failed.
	StatusFailed ProvisioningStatus = "failed"
)

// validStatuses provides O(1) lookup for valid provisioning statuses.
var validStatuses = map[ProvisioningStatus]struct{}{
	StatusPending:     {},
	StatusConnecting:  {},
	StatusSettingBoot: {},
	StatusMountingISO: {},
	StatusPoweringOn:  {},
	StatusInstalling:  {},
	StatusFinalizing:  {},
	StatusComplete:    {},
	StatusFailed:      {},
}

// terminalStatuses provides O(1) lookup for terminal provisioning statuses.
var terminalStatuses = map[ProvisioningStatus]struct{}{
	StatusComplete: {},
	StatusFailed:   {},
}

// IsValid returns true if the status is a recognized provisioning status.
func (s ProvisioningStatus) IsValid() bool {
	_, ok := validStatuses[s]
	return ok
}

// IsTerminal returns true if the status represents a final state.
func (s ProvisioningStatus) IsTerminal() bool {
	_, ok := terminalStatuses[s]
	return ok
}

// ProvisionRequest contains the parameters for a bare metal provision.
type ProvisionRequest struct {
	ProfileID uint64 `json:"profile_id" yaml:"profile-id"`
	ISOURL    string `json:"iso_url,omitempty" yaml:"iso-url,omitempty"`
}

// ProvisionResult tracks the state of an in-flight or completed provision.
type ProvisionResult struct {
	ProvisionID string             `json:"provision_id" yaml:"provision-id"`
	ProfileID   uint64             `json:"profile_id" yaml:"profile-id"`
	Status      ProvisioningStatus `json:"status" yaml:"status"`
	Message     string             `json:"message,omitempty" yaml:"message,omitempty"`
	StartedAt   time.Time          `json:"started_at" yaml:"started-at"`
	UpdatedAt   time.Time          `json:"updated_at" yaml:"updated-at"`
}

// BMCOperator defines the BMC operations required by the provisioning service.
type BMCOperator interface {
	PowerOn(ctx context.Context, profileID uint64) error
	PowerOff(ctx context.Context, profileID uint64) error
	PowerCycle(ctx context.Context, profileID uint64) error
	PowerStatus(ctx context.Context, profileID uint64) (bmc.PowerState, error)
	SetBootDevice(ctx context.Context, profileID uint64, device bmc.BootDevice, persistent bool) error
	MountISO(ctx context.Context, profileID uint64, isoURL string) error
	UnmountISO(ctx context.Context, profileID uint64) error
}

// ProfileChecker validates that a device profile exists.
type ProfileChecker interface {
	Get(ctx context.Context, id uint64) (*bmc.Config, error)
}
