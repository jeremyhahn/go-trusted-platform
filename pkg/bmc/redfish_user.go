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
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// Redfish AccountService paths.
const (
	redfishAccountServicePath = "/redfish/v1/AccountService"
	redfishAccountsCollection = "/redfish/v1/AccountService/Accounts"
)

// privilegeToRole maps platform Privilege values to standard Redfish
// RoleId strings. PrivilegeNoAccess has no role; the account is
// disabled instead by setting Enabled = false.
var privilegeToRole = map[Privilege]string{
	PrivilegeAdministrator: "Administrator",
	PrivilegeOperator:      "Operator",
	PrivilegeUser:          "ReadOnly",
	PrivilegeCallback:      "ReadOnly",
	PrivilegeNoAccess:      "ReadOnly",
}

// roleToPrivilege is the inverse of privilegeToRole. Custom roles
// resolve to PrivilegeUser as a safe default.
var roleToPrivilege = map[string]Privilege{
	"Administrator": PrivilegeAdministrator,
	"Operator":      PrivilegeOperator,
	"ReadOnly":      PrivilegeUser,
}

// redfishAccountsList is the response shape for the Accounts collection.
type redfishAccountsList struct {
	Members []redfishRef `json:"Members"`
}

// redfishAccount is the relevant subset of a ManagerAccount resource.
type redfishAccount struct {
	ODataID  string `json:"@odata.id,omitempty"`
	ID       string `json:"Id,omitempty"`
	Username string `json:"UserName,omitempty"`
	RoleID   string `json:"RoleId,omitempty"`
	Enabled  bool   `json:"Enabled"`
}

// redfishAccountPatch is the body sent to PATCH a ManagerAccount. Fields
// are pointers so omitempty correctly excludes unmodified attributes.
type redfishAccountPatch struct {
	UserName *string `json:"UserName,omitempty"`
	Password *string `json:"Password,omitempty"`
	RoleID   *string `json:"RoleId,omitempty"`
	Enabled  *bool   `json:"Enabled,omitempty"`
}

// redfishUserManager implements UserManager via the Redfish 1.6+
// AccountService. Requires a BMC firmware that fully implements
// /redfish/v1/AccountService/Accounts (X11+, iDRAC9+, iLO5+).
type redfishUserManager struct {
	transport *redfishTransport
	logger    *slog.Logger
}

// Compile-time interface check.
var _ UserManager = (*redfishUserManager)(nil)
var _ ManagedUserManager = (*redfishUserManager)(nil)

// NewRedfishUserManager builds a UserManager backed by the Redfish
// AccountService. The returned manager owns its HTTP transport and
// the auth credentials; callers must Close it when finished.
func NewRedfishUserManager(cfg *Config, logger *slog.Logger) (ManagedUserManager, error) {
	t, err := newRedfishTransport(context.Background(), cfg, logger)
	if err != nil {
		return nil, err
	}
	return &redfishUserManager{transport: t, logger: logger}, nil
}

// Close releases the manager's transport and credentials.
func (m *redfishUserManager) Close() error {
	return m.transport.Close()
}

// MaxUsers reports the BMC's account limit.
//
// Redfish AccountService exposes this as MaxPasswordLength /
// AccountLockout… etc., but the canonical "max accounts" value is the
// length of the Accounts collection times some configurable multiplier.
// For practical purposes we return the current number of populated
// member slots, which matches IPMI semantics.
func (m *redfishUserManager) MaxUsers(ctx context.Context) (uint8, error) {
	var list redfishAccountsList
	if _, err := m.transport.doJSON(ctx, "GET", redfishAccountsCollection, nil, &list); err != nil {
		return 0, err
	}
	if len(list.Members) > 255 {
		return 255, nil
	}
	return uint8(len(list.Members)), nil
}

// ListUsers enumerates the AccountService Accounts collection.
func (m *redfishUserManager) ListUsers(ctx context.Context) ([]User, error) {
	var list redfishAccountsList
	if _, err := m.transport.doJSON(ctx, "GET", redfishAccountsCollection, nil, &list); err != nil {
		return nil, err
	}
	users := make([]User, 0, len(list.Members))
	for _, ref := range list.Members {
		var acc redfishAccount
		if _, err := m.transport.doJSON(ctx, "GET", ref.ODataID, nil, &acc); err != nil {
			return nil, err
		}
		if acc.Username == "" {
			continue
		}
		users = append(users, User{
			Slot:      slotFromAccountID(acc.ID),
			Username:  acc.Username,
			Enabled:   acc.Enabled,
			Privilege: privilegeFromRole(acc.RoleID),
		})
	}
	return users, nil
}

// CreateUser POSTs a new account to the Accounts collection.
//
// Some BMCs require all four fields (UserName, Password, RoleId,
// Enabled) on creation; we always send them.
func (m *redfishUserManager) CreateUser(ctx context.Context, u User, password *memguard.Secret) error {
	if err := validateUsername(u.Username); err != nil {
		return err
	}
	if password == nil || password.Size() == 0 {
		return ErrInvalidConfig{Field: "password", Reason: "password is required"}
	}
	if !u.Privilege.IsValid() {
		return ErrInvalidConfig{Field: "privilege", Reason: "unrecognized privilege level"}
	}
	role, ok := privilegeToRole[u.Privilege]
	if !ok {
		role = "ReadOnly"
	}
	enabled := u.Enabled && u.Privilege != PrivilegeNoAccess

	return password.WithBytes(func(pw []byte) error {
		body := struct {
			UserName string `json:"UserName"`
			Password string `json:"Password"`
			RoleID   string `json:"RoleId"`
			Enabled  bool   `json:"Enabled"`
		}{
			UserName: u.Username,
			Password: string(pw),
			RoleID:   role,
			Enabled:  enabled,
		}
		_, err := m.transport.doJSON(ctx, "POST", redfishAccountsCollection, body, nil)
		return err
	})
}

// SetUserPassword PATCHes the Password field of the given account slot.
func (m *redfishUserManager) SetUserPassword(ctx context.Context, slot uint8, password *memguard.Secret) error {
	if password == nil || password.Size() == 0 {
		return ErrInvalidConfig{Field: "password", Reason: "password is required"}
	}
	path := accountPath(slot)
	return password.WithBytes(func(pw []byte) error {
		s := string(pw)
		body := redfishAccountPatch{Password: &s}
		_, err := m.transport.doJSON(ctx, "PATCH", path, body, nil)
		return err
	})
}

// SetUserPrivilege PATCHes RoleId and Enabled. NoAccess disables the
// account (Enabled=false) and assigns ReadOnly as a safe minimal role.
func (m *redfishUserManager) SetUserPrivilege(ctx context.Context, slot, _ uint8, priv Privilege) error {
	if !priv.IsValid() {
		return ErrInvalidConfig{Field: "privilege", Reason: "unrecognized privilege level"}
	}
	role := privilegeToRole[priv]
	enabled := priv != PrivilegeNoAccess
	body := redfishAccountPatch{RoleID: &role, Enabled: &enabled}
	_, err := m.transport.doJSON(ctx, "PATCH", accountPath(slot), body, nil)
	return err
}

// DeleteUser issues a DELETE on the account resource. BMCs that don't
// support DELETE on ManagerAccount fall through to the Redfish
// "MethodNotAllowed" error, which surfaces as ErrRedfishRequest.
func (m *redfishUserManager) DeleteUser(ctx context.Context, slot uint8) error {
	resp, err := m.transport.doRequest(ctx, "DELETE", accountPath(slot), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return parseRedfishError(resp, "DELETE", accountPath(slot))
}

// accountPath formats the canonical ManagerAccount URI for the given slot.
func accountPath(slot uint8) string {
	return fmt.Sprintf("%s/%d", redfishAccountsCollection, slot)
}

// slotFromAccountID converts a Redfish account Id (typically "1", "2", ...)
// to a uint8 slot. Returns 0 if the Id is non-numeric — callers should
// treat slot == 0 as informational only.
func slotFromAccountID(id string) uint8 {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0
	}
	n, err := strconv.ParseUint(id, 10, 8)
	if err != nil {
		return 0
	}
	return uint8(n)
}

// privilegeFromRole maps a Redfish RoleId to a Privilege; unknown roles
// resolve to PrivilegeUser as a conservative default.
func privilegeFromRole(role string) Privilege {
	if p, ok := roleToPrivilege[role]; ok {
		return p
	}
	return PrivilegeUser
}
