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

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// Privilege represents a BMC user privilege level.
//
// Values mirror IPMI 2.0 channel privilege levels (Section 6.8 of the IPMI
// 2.0 specification). The same semantics map onto Redfish Roles by
// convention: PrivilegeAdministrator -> "Administrator",
// PrivilegeOperator -> "Operator", PrivilegeUser -> "ReadOnly",
// PrivilegeCallback -> "ReadOnly" (Redfish has no Callback equivalent),
// PrivilegeNoAccess -> the Redfish account-disabled state.
type Privilege uint8

const (
	// PrivilegeNoAccess revokes channel access for the user.
	PrivilegeNoAccess Privilege = 0x0F

	// PrivilegeCallback grants callback-only access (IPMI Callback level).
	PrivilegeCallback Privilege = 0x01

	// PrivilegeUser grants read-only and limited operational commands.
	PrivilegeUser Privilege = 0x02

	// PrivilegeOperator grants most operational commands.
	PrivilegeOperator Privilege = 0x03

	// PrivilegeAdministrator grants full administrative access.
	PrivilegeAdministrator Privilege = 0x04
)

// validPrivileges is a map-based lookup for valid privilege levels.
var validPrivileges = map[Privilege]struct{}{
	PrivilegeNoAccess:      {},
	PrivilegeCallback:      {},
	PrivilegeUser:          {},
	PrivilegeOperator:      {},
	PrivilegeAdministrator: {},
}

// IsValid reports whether p is a recognized privilege level.
func (p Privilege) IsValid() bool {
	_, ok := validPrivileges[p]
	return ok
}

// String returns a human-readable name for p.
func (p Privilege) String() string {
	switch p {
	case PrivilegeNoAccess:
		return "no-access"
	case PrivilegeCallback:
		return "callback"
	case PrivilegeUser:
		return "user"
	case PrivilegeOperator:
		return "operator"
	case PrivilegeAdministrator:
		return "administrator"
	default:
		return "unknown"
	}
}

// User represents a BMC account.
//
// Slot is the IPMI user slot (1-based). On most X10 BMCs slot 1 is the
// anonymous user and slot 2 is the default ADMIN account. Redfish
// implementations expose accounts by Username instead, so Slot is best
// treated as informational on Redfish backends.
//
// Enabled indicates whether the user can authenticate. Channel is the
// IPMI channel index (typically 1 for the dedicated NIC LAN channel).
type User struct {
	Slot      uint8     `json:"slot" yaml:"slot"`
	Username  string    `json:"username" yaml:"username"`
	Enabled   bool      `json:"enabled" yaml:"enabled"`
	Privilege Privilege `json:"privilege" yaml:"privilege"`
	Channel   uint8     `json:"channel" yaml:"channel"`
}

// UserManager exposes BMC account lifecycle operations.
//
// Implementations must accept a *memguard.Secret for any password material;
// raw strings or []byte passwords are not part of the public API to keep
// credentials inside locked memory across the call boundary.
type UserManager interface {
	// ListUsers returns the populated user slots known to the BMC.
	// Empty slots are omitted.
	ListUsers(ctx context.Context) ([]User, error)

	// CreateUser creates a new user in the requested slot. The caller is
	// responsible for choosing an unused slot (typically by inspecting
	// ListUsers first). password may be nil for a name-only entry, but
	// most BMCs reject empty-password users.
	CreateUser(ctx context.Context, u User, password *memguard.Secret) error

	// SetUserPassword changes the password of an existing user slot.
	SetUserPassword(ctx context.Context, slot uint8, password *memguard.Secret) error

	// SetUserPrivilege updates the channel privilege and enabled state of
	// an existing user slot.
	SetUserPrivilege(ctx context.Context, slot, channel uint8, priv Privilege) error

	// DeleteUser removes a user slot. On IPMI this clears the username
	// and disables the slot; on Redfish this DELETEs the account resource.
	DeleteUser(ctx context.Context, slot uint8) error

	// MaxUsers reports the maximum number of user slots the BMC supports.
	MaxUsers(ctx context.Context) (uint8, error)
}
