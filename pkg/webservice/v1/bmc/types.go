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

	// GetWebCertificate returns the metadata of the BMC's current web
	// server TLS certificate.
	// GET /api/v1/bmc/{profileID}/cert
	GetWebCertificate(w http.ResponseWriter, r *http.Request)

	// ReplaceWebCertificate uploads a new web server TLS certificate
	// and private key to the BMC.
	// PUT /api/v1/bmc/{profileID}/cert
	ReplaceWebCertificate(w http.ResponseWriter, r *http.Request)

	// ListUsers returns the populated user slots known to the BMC.
	// GET /api/v1/bmc/{profileID}/users
	ListUsers(w http.ResponseWriter, r *http.Request)

	// CreateUser creates a new BMC user account.
	// POST /api/v1/bmc/{profileID}/users
	CreateUser(w http.ResponseWriter, r *http.Request)

	// DeleteUser deletes the BMC user occupying the given slot.
	// DELETE /api/v1/bmc/{profileID}/users/{slot}
	DeleteUser(w http.ResponseWriter, r *http.Request)

	// SetUserPassword updates the password for an existing BMC user
	// slot.
	// PUT /api/v1/bmc/{profileID}/users/{slot}/password
	SetUserPassword(w http.ResponseWriter, r *http.Request)

	// SetUserPrivilege updates the channel privilege level for an
	// existing BMC user slot.
	// PUT /api/v1/bmc/{profileID}/users/{slot}/privilege
	SetUserPrivilege(w http.ResponseWriter, r *http.Request)

	// EnrollBMC runs the BMC enrollment ceremony for the given profile.
	// POST /api/v1/bmc/{profileID}/enroll
	EnrollBMC(w http.ResponseWriter, r *http.Request)

	// SetEnroller injects the enroller and profile lookup after handler
	// construction. The daemon calls this once App and DeviceProfileService
	// are available.
	SetEnroller(enroller BMCEnrollerServicer, lookup ProfileLookup)

	// RestoreBMC runs the BMC factory-certificate restore ceremony for
	// the given profile, reverting the BMC's web TLS certificate to its
	// vendor-default self-signed certificate and cleaning up platform-side
	// trust state (SPKI pin + DANE TLSA record).
	// POST /api/v1/bmc/{profileID}/cert/restore
	RestoreBMC(w http.ResponseWriter, r *http.Request)

	// SetRestorer injects the restorer and profile lookup after handler
	// construction. The daemon calls this once App and DeviceProfileService
	// are available.
	SetRestorer(restorer BMCRestorerServicer, lookup ProfileLookup)
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

	// Certificate management.
	GetWebCertificate(ctx context.Context, profileID uint64) (*bmcpkg.CertificateInfo, error)
	ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error

	// User management.
	ListUsers(ctx context.Context, profileID uint64) ([]bmcpkg.User, error)
	CreateUser(ctx context.Context, profileID uint64, user bmcpkg.User, password string) error
	DeleteUser(ctx context.Context, profileID uint64, slot uint8) error
	SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error
	SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege bmcpkg.Privilege) error
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

// ReplaceWebCertificateRequest represents the request body for replacing
// the BMC web server TLS certificate.
//
// Both CertPEM and KeyPEM are PEM-encoded as plain strings rather than
// base64 byte fields so the JSON wire format is human-readable.
type ReplaceWebCertificateRequest struct {
	// CertPEM is the PEM-encoded certificate (leaf, optionally
	// followed by intermediates).
	CertPEM string `json:"cert_pem"`
	// KeyPEM is the PEM-encoded private key matching CertPEM.
	KeyPEM string `json:"key_pem"`
}

// CreateUserRequest represents the request body for creating a BMC
// user account.
type CreateUserRequest struct {
	// Slot is the IPMI user slot (1-based) to assign. Some BMCs accept
	// 0 to mean "auto-assign next free slot".
	Slot uint8 `json:"slot"`
	// Username is the account name to provision.
	Username string `json:"username"`
	// Enabled indicates whether the user should be able to authenticate
	// immediately after creation.
	Enabled bool `json:"enabled"`
	// Privilege is the channel privilege level. Accepted values mirror
	// the bmcpkg.Privilege.String() representation: "no-access",
	// "callback", "user", "operator", "administrator".
	Privilege string `json:"privilege"`
	// Channel is the IPMI channel index (typically 1 for the dedicated
	// NIC LAN channel).
	Channel uint8 `json:"channel"`
	// Password is the initial password for the account. Required by
	// most BMC implementations.
	Password string `json:"password"`
}

// SetUserPasswordRequest represents the request body for updating a
// BMC user's password.
type SetUserPasswordRequest struct {
	// Password is the new password. Required.
	Password string `json:"password"`
}

// SetUserPrivilegeRequest represents the request body for updating a
// BMC user's channel privilege.
type SetUserPrivilegeRequest struct {
	// Privilege is the new privilege level. See CreateUserRequest for
	// accepted values.
	Privilege string `json:"privilege"`
	// Channel is the IPMI channel index (typically 1 for the dedicated
	// NIC LAN channel).
	Channel uint8 `json:"channel"`
}
