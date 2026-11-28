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
	"io"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// IPMI 2.0 user management commands (NetFn 0x06 = App).
//
// References: IPMI Specification 2.0 Rev 1.1, Section 22 "IPMI Messaging
// Support Commands". Command codes 0x43-0x47 are user-management.
const (
	cmdSetUserAccess   = 0x43
	cmdGetUserAccess   = 0x44
	cmdSetUserName     = 0x45
	cmdGetUserName     = 0x46
	cmdSetUserPassword = 0x47
)

// IPMI Set User Password operations (Table 22-19).
const (
	pwdOpDisable = 0x00
	pwdOpEnable  = 0x01
	pwdOpSet     = 0x02
	pwdOpTest    = 0x03
)

// IPMI user limits.
const (
	ipmiMaxUsernameLen = 16
	ipmiMaxPasswordLen = 20
	ipmiPwdLenShort    = 16
	ipmiPwdLenLong     = 20

	// defaultIPMIChannel is the IPMI channel used for user management.
	// Channel 1 is the primary LAN channel on virtually all BMCs we
	// target (Supermicro X10/X11, Dell iDRAC, HPE iLO).
	defaultIPMIChannel uint8 = 1

	// ipmiMaxUserSlot is the largest user ID representable in the 6-bit
	// User ID field of NetFn 0x06 commands.
	ipmiMaxUserSlot uint8 = 0x3F
)

// Set User Access change bits (Table 22-22 byte 1).
const (
	suaChangeBits     byte = 0x80
	suaCallbackOnly   byte = 0x40
	suaLinkAuthEnable byte = 0x20
	suaIPMIMsgEnable  byte = 0x10
)

// Get User Access response byte 3 bit layout.
const (
	guaPrivilegeMask    byte = 0x0F
	guaIPMIMsgEnable    byte = 0x10
	guaLinkAuthEnable   byte = 0x20
	guaCallbackOnly     byte = 0x40
	guaUserCountMask    byte = 0x3F
	guaEnabledStateMask byte = 0xC0
	guaEnabledStateOn   byte = 0x40
)

// ipmiSender is the minimal command surface needed to issue IPMI requests.
// It mirrors *rmcpSession.Send and exists so ipmiUserManager can be unit
// tested without a real RMCP+ session.
type ipmiSender interface {
	Send(netFn, cmd byte, data []byte) ([]byte, error)
}

// ManagedUserManager is a UserManager that owns lifecycle resources.
// Production constructors return ManagedUserManager so callers can
// release the underlying IPMI session via Close.
type ManagedUserManager interface {
	UserManager
	io.Closer
}

// ipmiUserManager implements UserManager via IPMI 2.0 NetFn 0x06 commands.
//
// The implementation is intentionally stateless beyond its sender and
// channel — slot enumeration and privilege state always come from the BMC.
type ipmiUserManager struct {
	sender  ipmiSender
	channel uint8
	logger  *slog.Logger
	closer  io.Closer // nil for caller-managed sender; non-nil for owned session
}

// Compile-time interface check.
var _ UserManager = (*ipmiUserManager)(nil)

// NewIPMIUserManager builds a UserManager around an existing IPMI command
// channel. The channel parameter is the IPMI logical channel (typically 1
// for the primary LAN); pass 0 to use the package default.
//
// The returned manager does not own sender; callers retain responsibility
// for its lifecycle.
func NewIPMIUserManager(sender ipmiSender, channel uint8, logger *slog.Logger) UserManager {
	if channel == 0 {
		channel = defaultIPMIChannel
	}
	return &ipmiUserManager{sender: sender, channel: channel, logger: logger}
}

// NewUserManager opens a fresh IPMI 2.0 RMCP+ session against cfg and
// returns a ManagedUserManager that owns it. Callers must Close the
// returned manager when finished to release the session.
//
// Currently only IPMI is supported; Redfish AccountService is added in
// a future slice and will be selected here based on cfg.Protocol.
func NewUserManager(ctx context.Context, cfg *Config, logger *slog.Logger) (ManagedUserManager, error) {
	if cfg == nil {
		return nil, ErrNilConfig{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	session := newRMCPSession(cfg, logger)
	if err := session.Open(ctx); err != nil {
		return nil, ErrConnectionFailed{Address: cfg.Endpoint(), Cause: err}
	}
	return &ipmiUserManager{
		sender:  session,
		channel: defaultIPMIChannel,
		logger:  logger,
		closer:  session,
	}, nil
}

// Close releases the owned IPMI session, if any.
func (m *ipmiUserManager) Close() error {
	if m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

// MaxUsers returns the largest user slot the BMC supports.
//
// IPMI Get User Access (0x44) returns the max user count in its first
// response byte; we query slot 1 and read this field.
func (m *ipmiUserManager) MaxUsers(_ context.Context) (uint8, error) {
	resp, err := m.getUserAccess(1)
	if err != nil {
		return 0, err
	}
	return resp.maxUsers, nil
}

// ListUsers enumerates all populated user slots on the BMC.
//
// The implementation queries Get User Access on slot 1 to discover the
// max user count, then iterates through each slot fetching name + access.
// Slots with empty usernames are omitted from the result.
func (m *ipmiUserManager) ListUsers(_ context.Context) ([]User, error) {
	first, err := m.getUserAccess(1)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, first.maxUsers)
	for slot := uint8(1); slot <= first.maxUsers; slot++ {
		access := first
		if slot != 1 {
			access, err = m.getUserAccess(slot)
			if err != nil {
				return nil, err
			}
		}
		name, err := m.getUserName(slot)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		users = append(users, User{
			Slot:      slot,
			Username:  name,
			Enabled:   access.enabled,
			Privilege: access.privilege,
			Channel:   m.channel,
		})
	}
	return users, nil
}

// CreateUser writes a new user into the requested slot.
//
// The sequence follows the IPMI-recommended order: Set User Name, then
// Set User Password (set), then Set User Access. Most BMCs reject access
// changes on a slot with no name, so name first is required.
func (m *ipmiUserManager) CreateUser(_ context.Context, u User, password *memguard.MemoryEnclave) error {
	if err := validateSlot(u.Slot); err != nil {
		return err
	}
	if err := validateUsername(u.Username); err != nil {
		return err
	}
	if !u.Privilege.IsValid() {
		return ErrInvalidConfig{Field: "privilege", Reason: "unrecognized privilege level"}
	}
	// Refuse an oversized password before the first BMC write: a refusal
	// after setUserName would leave a named slot without password or access.
	if password != nil && password.Size() > ipmiMaxPasswordLen {
		return ErrInvalidConfig{Field: "password", Reason: "password exceeds 20 bytes"}
	}
	if err := m.setUserName(u.Slot, u.Username); err != nil {
		return err
	}
	if password != nil && password.Size() > 0 {
		if err := m.setUserPassword(u.Slot, pwdOpSet, password); err != nil {
			return err
		}
	}
	channel := u.Channel
	if channel == 0 {
		channel = m.channel
	}
	return m.setUserAccess(u.Slot, channel, u.Privilege, u.Enabled)
}

// SetUserPassword changes the password of an existing slot.
//
// password must be non-nil and contain at least one byte. Empty passwords
// are rejected since they are interpreted as "disable" by some BMCs and
// "no change" by others; callers wanting to disable should call
// SetUserPrivilege with PrivilegeNoAccess.
func (m *ipmiUserManager) SetUserPassword(_ context.Context, slot uint8, password *memguard.MemoryEnclave) error {
	if err := validateSlot(slot); err != nil {
		return err
	}
	if password == nil || password.Size() == 0 {
		return ErrInvalidConfig{Field: "password", Reason: "password is required"}
	}
	return m.setUserPassword(slot, pwdOpSet, password)
}

// SetUserPrivilege updates the channel privilege of an existing slot and
// enables IPMI messaging unless priv == PrivilegeNoAccess.
func (m *ipmiUserManager) SetUserPrivilege(_ context.Context, slot, channel uint8, priv Privilege) error {
	if err := validateSlot(slot); err != nil {
		return err
	}
	if !priv.IsValid() {
		return ErrInvalidConfig{Field: "privilege", Reason: "unrecognized privilege level"}
	}
	if channel == 0 {
		channel = m.channel
	}
	return m.setUserAccess(slot, channel, priv, priv != PrivilegeNoAccess)
}

// DeleteUser clears the username and revokes channel access for the slot.
//
// IPMI has no dedicated "delete" command — the standards-compliant form is
// to write an empty name + set privilege to NoAccess + disable IPMI msg.
func (m *ipmiUserManager) DeleteUser(_ context.Context, slot uint8) error {
	if err := validateSlot(slot); err != nil {
		return err
	}
	if err := m.setUserName(slot, ""); err != nil {
		return err
	}
	return m.setUserAccess(slot, m.channel, PrivilegeNoAccess, false)
}

// userAccessResponse decomposes the Get User Access (0x44) response.
type userAccessResponse struct {
	maxUsers  uint8
	enabled   bool
	privilege Privilege
}

// getUserAccess issues IPMI Get User Access for the given slot on the
// configured channel.
func (m *ipmiUserManager) getUserAccess(slot uint8) (userAccessResponse, error) {
	req := []byte{m.channel & 0x0F, slot & ipmiMaxUserSlot}
	resp, err := m.sender.Send(netFnApp, cmdGetUserAccess, req)
	if err != nil {
		return userAccessResponse{}, err
	}
	if len(resp) < 4 {
		return userAccessResponse{}, ErrIPMIShortResponse{Command: "Get User Access", Got: len(resp), Want: 4}
	}
	return userAccessResponse{
		maxUsers:  resp[0] & guaUserCountMask,
		enabled:   (resp[1] & guaEnabledStateMask) == guaEnabledStateOn,
		privilege: Privilege(resp[3] & guaPrivilegeMask),
	}, nil
}

// setUserAccess issues IPMI Set User Access for the given slot.
func (m *ipmiUserManager) setUserAccess(slot, channel uint8, priv Privilege, enabled bool) error {
	flags := suaChangeBits | (channel & 0x0F)
	if enabled {
		flags |= suaIPMIMsgEnable | suaLinkAuthEnable
	}
	req := []byte{
		flags,
		slot & ipmiMaxUserSlot,
		byte(priv) & guaPrivilegeMask,
		0x00, // session limit (unlimited)
	}
	_, err := m.sender.Send(netFnApp, cmdSetUserAccess, req)
	return err
}

// getUserName issues IPMI Get User Name for the given slot.
func (m *ipmiUserManager) getUserName(slot uint8) (string, error) {
	resp, err := m.sender.Send(netFnApp, cmdGetUserName, []byte{slot & ipmiMaxUserSlot})
	if err != nil {
		return "", err
	}
	return trimNullPadded(resp), nil
}

// setUserName issues IPMI Set User Name for the given slot. The name is
// null-padded to 16 bytes.
func (m *ipmiUserManager) setUserName(slot uint8, name string) error {
	req := make([]byte, 1+ipmiMaxUsernameLen)
	req[0] = slot & ipmiMaxUserSlot
	copy(req[1:], name)
	_, err := m.sender.Send(netFnApp, cmdSetUserName, req)
	return err
}

// setUserPassword issues IPMI Set User Password.
//
// The password byte slice in req is built and immediately sent; we wipe
// it on return as a defense in depth, even though copies will exist
// inside the RMCP+ encryption path.
func (m *ipmiUserManager) setUserPassword(slot uint8, op byte, password *memguard.MemoryEnclave) error {
	if password.Size() > ipmiMaxPasswordLen {
		return ErrInvalidConfig{Field: "password", Reason: "password exceeds 20 bytes"}
	}
	pwdLen := ipmiPwdLenShort
	slotByte := slot & ipmiMaxUserSlot
	if password.Size() > ipmiPwdLenShort {
		pwdLen = ipmiPwdLenLong
		slotByte |= 0x80 // bit 7 = 20-byte password
	}
	req := make([]byte, 2+pwdLen)
	req[0] = slotByte
	req[1] = op & 0x03
	err := password.Open(func(pw []byte) error {
		copy(req[2:], pw)
		return nil
	})
	if err != nil {
		zero(req)
		return err
	}
	_, sendErr := m.sender.Send(netFnApp, cmdSetUserPassword, req)
	zero(req)
	return sendErr
}

// trimNullPadded converts a null-padded byte slice to a Go string.
func trimNullPadded(b []byte) string {
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	return string(b[:end])
}

// zero overwrites b with zeros. Best-effort; the compiler may eliminate
// this if the buffer is otherwise unreachable, but the buffer is only
// allocated for the IPMI request and not retained, so wiping shrinks the
// window during which the password is recoverable from the heap.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// validateSlot rejects slot 0 and slots above the IPMI 6-bit max.
func validateSlot(slot uint8) error {
	if slot == 0 || slot > ipmiMaxUserSlot {
		return ErrInvalidConfig{Field: "slot", Reason: "slot must be in 1..63"}
	}
	return nil
}

// validateUsername rejects names longer than 16 bytes; an empty username
// is permitted (used by DeleteUser).
func validateUsername(name string) error {
	if len(name) > ipmiMaxUsernameLen {
		return ErrInvalidConfig{Field: "username", Reason: "username exceeds 16 bytes"}
	}
	return nil
}
