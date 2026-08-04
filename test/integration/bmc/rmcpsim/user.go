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

package rmcpsim

import "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"

// userEntry represents a single IPMI user slot in the simulator's
// in-memory user table. IPMI supports up to 15 user slots (1-indexed;
// slot 0 is reserved).
type userEntry struct {
	name     string
	password string
	access   byte // privilege level (0x00-0x05 per IPMI spec)
	enabled  bool
}

// userTableSize is the number of slots in the IPMI user table.
// Slot 0 is reserved; valid slots are 1-15.
const userTableSize = 16

// maxUserSlot is the highest valid user slot index.
const maxUserSlot = 15

// ipmiMaxUsernameLen is the maximum IPMI username length in bytes.
const ipmiMaxUsernameLen = 16

// ipmiMaxPasswordLenShort is the 16-byte IPMI password size.
const ipmiMaxPasswordLenShort = 16

// ipmiMaxPasswordLenLong is the 20-byte IPMI password size.
const ipmiMaxPasswordLenLong = 20

// IPMI completion codes returned by user management handlers.
const (
	ccSuccess             = 0x00
	ccInvalidFieldRequest = 0xCC // parameter out of range / invalid data field
	ccCommandNotAvailable = 0xD4 // insufficient privilege / cannot execute
)

// Set User Password operation codes (IPMI Table 22-32, byte 1 bits 1:0).
const (
	pwdOpDisable = 0x00
	pwdOpEnable  = 0x01
	pwdOpSet     = 0x02
	pwdOpTest    = 0x03
)

// initUserTable initializes the simulator's user table and populates
// slot 1 with the configured credentials at administrator privilege.
func (s *Simulator) initUserTable() {
	s.credMu.RLock()
	username := s.username
	password := s.password
	s.credMu.RUnlock()

	s.userMu.Lock()
	defer s.userMu.Unlock()

	// Zero all slots.
	for i := range s.users {
		s.users[i] = userEntry{}
	}

	// Slot 1: default admin account.
	s.users[1] = userEntry{
		name:     username,
		password: password,
		access:   bmc.RMCPPrivilegeAdministrator,
		enabled:  true,
	}
}

// registerUserHandlers adds user management command handlers to the
// simulator's instance-level handler map.
func (s *Simulator) registerUserHandlers() {
	s.handlers[ipmiKey{bmc.NetFnApp, bmc.CmdSetUserAccess}] = s.handleSetUserAccess
	s.handlers[ipmiKey{bmc.NetFnApp, bmc.CmdGetUserAccess}] = s.handleGetUserAccess
	s.handlers[ipmiKey{bmc.NetFnApp, bmc.CmdSetUserName}] = s.handleSetUserName
	s.handlers[ipmiKey{bmc.NetFnApp, bmc.CmdGetUserName}] = s.handleGetUserName
	s.handlers[ipmiKey{bmc.NetFnApp, bmc.CmdSetUserPassword}] = s.handleSetUserPassword
}

// enabledUserCount returns the number of enabled user slots.
func (s *Simulator) enabledUserCount() byte {
	var count byte
	for i := 1; i <= maxUserSlot; i++ {
		if s.users[i].enabled {
			count++
		}
	}
	return count
}

// populatedUserCount returns the number of populated (named) user slots.
func (s *Simulator) populatedUserCount() byte {
	var count byte
	for i := 1; i <= maxUserSlot; i++ {
		if s.users[i].name != "" {
			count++
		}
	}
	return count
}

// handleSetUserAccess handles IPMI Set User Access (cmd 0x43).
//
// IPMI request data layout (payload[6:]):
//
//	[0] = channel number (bits 3:0) | change bits (bits 7:4)
//	[1] = user ID (bits 5:0)
//	[2] = privilege limit (bits 3:0)
func (s *Simulator) handleSetUserAccess(ipmiPayload []byte) ([]byte, byte) {
	reqData := ipmiPayload[6:]
	if len(reqData) < 3 {
		return nil, ccInvalidFieldRequest
	}

	userID := reqData[1] & 0x3F
	if userID == 0 || userID > maxUserSlot {
		return nil, ccInvalidFieldRequest
	}

	privilege := reqData[2] & 0x0F

	s.userMu.Lock()
	s.users[userID].access = privilege
	s.userMu.Unlock()

	return nil, ccSuccess
}

// handleGetUserAccess handles IPMI Get User Access (cmd 0x44).
//
// IPMI request data layout (payload[6:]):
//
//	[0] = channel number (bits 3:0)
//	[1] = user ID (bits 5:0)
//
// Response data:
//
//	[0] = max user IDs (bits 5:0)
//	[1] = count of enabled users (bits 5:0) | enabled state (bits 7:6)
//	[2] = count of users with fixed names (always 0 for simulator)
//	[3] = user privilege (bits 3:0) | user enable (bit 6)
func (s *Simulator) handleGetUserAccess(ipmiPayload []byte) ([]byte, byte) {
	reqData := ipmiPayload[6:]
	if len(reqData) < 2 {
		return nil, ccInvalidFieldRequest
	}

	userID := reqData[1] & 0x3F
	if userID == 0 || userID > maxUserSlot {
		return nil, ccInvalidFieldRequest
	}

	s.userMu.RLock()
	user := s.users[userID]
	enabledCount := s.enabledUserCount()
	populatedCount := s.populatedUserCount()
	s.userMu.RUnlock()

	resp := make([]byte, 4)
	resp[0] = maxUserSlot
	resp[1] = 0x40 | (enabledCount & 0x3F) // enabled state = 0x40 (user-level access enabled)
	resp[2] = populatedCount & 0x3F        // fixed-name users (populated count)
	resp[3] = user.access & 0x0F
	if user.enabled {
		resp[3] |= 0x10 // IPMI messaging enabled bit
	}

	return resp, ccSuccess
}

// handleSetUserName handles IPMI Set User Name (cmd 0x45).
//
// IPMI request data layout (payload[6:]):
//
//	[0] = user ID (bits 5:0)
//	[1:17] = username (16 bytes, null-padded)
func (s *Simulator) handleSetUserName(ipmiPayload []byte) ([]byte, byte) {
	reqData := ipmiPayload[6:]
	if len(reqData) < 1+ipmiMaxUsernameLen {
		return nil, ccInvalidFieldRequest
	}

	userID := reqData[0] & 0x3F
	if userID == 0 || userID > maxUserSlot {
		return nil, ccInvalidFieldRequest
	}

	// Extract null-terminated username.
	nameBytes := reqData[1 : 1+ipmiMaxUsernameLen]
	name := trimNullBytes(nameBytes)

	s.userMu.Lock()
	s.users[userID].name = name
	s.userMu.Unlock()

	return nil, ccSuccess
}

// handleGetUserName handles IPMI Get User Name (cmd 0x46).
//
// IPMI request data layout (payload[6:]):
//
//	[0] = user ID (bits 5:0)
//
// Response data:
//
//	[0:16] = username (16 bytes, null-padded)
func (s *Simulator) handleGetUserName(ipmiPayload []byte) ([]byte, byte) {
	reqData := ipmiPayload[6:]
	if len(reqData) < 1 {
		return nil, ccInvalidFieldRequest
	}

	userID := reqData[0] & 0x3F
	if userID == 0 || userID > maxUserSlot {
		return nil, ccInvalidFieldRequest
	}

	s.userMu.RLock()
	name := s.users[userID].name
	s.userMu.RUnlock()

	resp := make([]byte, ipmiMaxUsernameLen)
	copy(resp, []byte(name))

	return resp, ccSuccess
}

// handleSetUserPassword handles IPMI Set User Password (cmd 0x47).
//
// IPMI request data layout (payload[6:]):
//
//	[0] = user ID (bits 5:0) | 20-byte flag (bit 7) | operation (bits 1:0 of low nibble)
//
// Wait -- IPMI spec Table 22-32 defines byte 1 as:
//
//	bits 5:0 = user ID
//	bit 7 = 0=16-byte pwd, 1=20-byte pwd
//
// Byte 2 = operation (bits 1:0):
//
//	0 = disable user
//	1 = enable user
//	2 = set password
//	3 = test password
//
// Bytes 3-18 or 3-22 = password (when operation is set/test).
func (s *Simulator) handleSetUserPassword(ipmiPayload []byte) ([]byte, byte) {
	reqData := ipmiPayload[6:]
	if len(reqData) < 2 {
		return nil, ccInvalidFieldRequest
	}

	userID := reqData[0] & 0x3F
	if userID == 0 || userID > maxUserSlot {
		return nil, ccInvalidFieldRequest
	}

	operation := reqData[1] & 0x03
	is20Byte := reqData[0]&0x80 != 0

	pwdLen := ipmiMaxPasswordLenShort
	if is20Byte {
		pwdLen = ipmiMaxPasswordLenLong
	}

	switch operation {
	case pwdOpDisable:
		s.userMu.Lock()
		s.users[userID].enabled = false
		s.userMu.Unlock()
		return nil, ccSuccess

	case pwdOpEnable:
		s.userMu.Lock()
		s.users[userID].enabled = true
		s.userMu.Unlock()
		return nil, ccSuccess

	case pwdOpSet:
		if len(reqData) < 2+pwdLen {
			return nil, ccInvalidFieldRequest
		}
		password := trimNullBytes(reqData[2 : 2+pwdLen])

		s.userMu.Lock()
		s.users[userID].password = password
		// Also update the simulator's active credentials if this is
		// slot 1 (the session-authentication account).
		if userID == 1 {
			s.credMu.Lock()
			s.password = password
			s.credMu.Unlock()
		}
		s.userMu.Unlock()
		return nil, ccSuccess

	case pwdOpTest:
		if len(reqData) < 2+pwdLen {
			return nil, ccInvalidFieldRequest
		}
		testPwd := trimNullBytes(reqData[2 : 2+pwdLen])

		s.userMu.RLock()
		match := s.users[userID].password == testPwd
		s.userMu.RUnlock()

		if match {
			return nil, ccSuccess
		}
		// Completion code 0x81 = password test failed (IPMI Table 22-32).
		return nil, 0x81

	default:
		return nil, ccInvalidFieldRequest
	}
}

// trimNullBytes returns a string from b with trailing null bytes removed.
func trimNullBytes(b []byte) string {
	n := len(b)
	for n > 0 && b[n-1] == 0 {
		n--
	}
	return string(b[:n])
}
