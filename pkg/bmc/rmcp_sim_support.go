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

import "log/slog"

// Exported re-exports of the unexported RMCP+ wire constants so the
// simulator package (test/integration/bmc/rmcpsim) can speak the same
// wire protocol without duplicating magic numbers. These mirror the
// values defined in rmcp.go verbatim.
const (
	RMCPVersion   = rmcpVersion
	RMCPClassIPMI = rmcpClassIPMI

	AuthTypeRMCPPlus = authTypeRMCPPlus

	PayloadTypeIPMI            = payloadTypeIPMI
	PayloadTypeOpenSessionReq  = payloadTypeOpenSessionReq
	PayloadTypeOpenSessionResp = payloadTypeOpenSessionResp
	PayloadTypeRAKP1           = payloadTypeRAKP1
	PayloadTypeRAKP2           = payloadTypeRAKP2
	PayloadTypeRAKP3           = payloadTypeRAKP3
	PayloadTypeRAKP4           = payloadTypeRAKP4

	AuthAlgoHMACSHA1   = authAlgoHMACSHA1
	AuthAlgoHMACSHA256 = authAlgoHMACSHA256

	IntegrityAlgoNone           = integrityAlgoNone
	IntegrityAlgoHMACSHA1_96    = integrityAlgoHMACSHA1_96
	IntegrityAlgoHMACSHA256_128 = integrityAlgoHMACSHA256_128

	CryptoAlgoNone      = cryptoAlgoNone
	CryptoAlgoAESCBC128 = cryptoAlgoAESCBC128

	RMCPPrivilegeAdministrator = privilegeAdministrator

	NetFnChassis = netFnChassis
	NetFnApp     = netFnApp
	NetFnStorage = netFnStorage

	CmdGetDeviceID          = cmdGetDeviceID
	CmdGetAuthCapabilities  = cmdGetAuthCapabilities
	CmdSetSessionPrivilege  = cmdSetSessionPrivilege
	CmdCloseSession         = cmdCloseSession
	CmdChassisStatus        = cmdChassisStatus
	CmdChassisControl       = cmdChassisControl
	CmdGetSystemBootOptions = cmdGetSystemBootOptions
	CmdSetSystemBootOptions = cmdSetSystemBootOptions

	CmdSetUserAccess   = cmdSetUserAccess
	CmdGetUserAccess   = cmdGetUserAccess
	CmdSetUserName     = cmdSetUserName
	CmdGetUserName     = cmdGetUserName
	CmdSetUserPassword = cmdSetUserPassword

	BootDevicePXEBits = bootDevicePXEBits

	CmdGetSDRRepositoryInfo = cmdGetSDRRepositoryInfo
	CmdReserveSDRRepository = cmdReserveSDRRepository
	CmdGetSDR               = cmdGetSDR
	CmdGetFRUInventoryArea  = cmdGetFRUInventoryArea
	CmdReadFRUData          = cmdReadFRUData
)

// ExtractUnauthPayload is the exported wrapper around the unexported
// extractUnauthPayload helper. It validates the RMCP+ header for an
// unauthenticated (session-setup) packet and returns the payload
// portion. Intended for use by test/integration/bmc/rmcpsim.
func ExtractUnauthPayload(resp []byte, expectedPayloadType byte) ([]byte, error) {
	return extractUnauthPayload(resp, expectedPayloadType)
}

// BuildRMCPPlusUnauthPacket is the exported wrapper around the
// unexported buildRMCPPlusUnauthPacket helper. It produces an
// unauthenticated RMCP+ packet (session setup / RAKP).
func BuildRMCPPlusUnauthPacket(payloadType byte, sessionID, seqNum uint32, payload []byte) []byte {
	return buildRMCPPlusUnauthPacket(payloadType, sessionID, seqNum, payload)
}

// IPMIChecksum computes the IPMI 2's-complement checksum over the
// given bytes. Exported so rmcpsim can build IPMI response frames.
func IPMIChecksum(data []byte) byte {
	return ipmiChecksum(data)
}

// DecryptSessionPayload decrypts an authenticated, AES-CBC-128 encrypted
// IPMI payload using the supplied K2 key. Returns the plaintext IPMI
// message bytes. Used by rmcpsim to decrypt client requests after the
// RAKP handshake completes.
func DecryptSessionPayload(cryptoAlgo uint8, k2, data []byte) ([]byte, error) {
	s := &rmcpSession{cryptoAlgo: cryptoAlgo, k2: k2}
	return s.decryptPayload(data)
}

// WrapSessionPayload wraps a raw IPMI response in an RMCP+ session
// envelope with the negotiated confidentiality + integrity algorithms.
// The clientSessionID parameter is the BMC's peer session ID -- the
// value placed in the outgoing session header per IPMI 2.0 Table 13-8
// (from the BMC's perspective, this is the "Managed System Session ID"
// of the remote console's session).
//
// This is the simulator-side counterpart of the client's wrapPayload
// and is exported so test/integration/bmc/rmcpsim can produce
// wire-identical frames without duplicating crypto code.
func WrapSessionPayload(cryptoAlgo, integrityAlgo uint8, clientSessionID uint32, k1, k2, ipmiMsg []byte, logger *slog.Logger) ([]byte, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgo,
		integrityAlgo: integrityAlgo,
		bmcSessionID:  clientSessionID,
		k1:            k1,
		k2:            k2,
		logger:        logger,
	}
	return s.wrapPayload(ipmiMsg)
}
