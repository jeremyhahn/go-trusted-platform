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

package quicwire

// Phase 3.5 category opcodes.
//
// Each Phase 3.5 service (ceremony, piv, luks, fido2) multiplexes its
// methods under a single category opcode. The first byte of the request
// payload selects the sub-operation per the Ceremony*Sub / PIV*Sub /
// LUKS*Sub / FIDO2*Sub constants defined here.
//
// The category pattern matches the existing overlay/gateway/switch
// categories in this file and keeps the globally-visible opcode surface
// compact (4 opcodes instead of 29).
const (
	// OpCeremonyCategory multiplexes ceremony sub-operations.
	OpCeremonyCategory byte = 0x9A
	// OpPIVCategory multiplexes PIV sub-operations.
	OpPIVCategory byte = 0x9B
	// OpLUKSCategory multiplexes LUKS sub-operations.
	OpLUKSCategory byte = 0x9C
	// OpFIDO2Category multiplexes FIDO2 sub-operations.
	OpFIDO2Category byte = 0x9D
	// OpTenantBarrierCategory multiplexes per-tenant barrier sub-operations
	// (Init/Unseal/Seal/Status). The first byte of the request payload
	// selects the sub-operation per the TenantBarrierSub* constants below.
	OpTenantBarrierCategory byte = 0x9E
	// OpBMCCategory multiplexes BMC enrollment sub-operations.
	// The first byte of the request payload selects the sub-operation
	// per the BMCSub* constants below.
	OpBMCCategory byte = 0x9F
)

// Tenant barrier sub-opcodes.
const (
	TenantBarrierSubInit   byte = 0x01
	TenantBarrierSubUnseal byte = 0x02
	TenantBarrierSubSeal   byte = 0x03
	TenantBarrierSubStatus byte = 0x04
)

// Ceremony sub-opcodes.
const (
	CeremonySubInit               byte = 0x01
	CeremonySubStatus             byte = 0x02
	CeremonySubClaimCertBegin     byte = 0x03
	CeremonySubClaimCertComplete  byte = 0x04
	CeremonySubClaimShareBegin    byte = 0x05
	CeremonySubSignCSR            byte = 0x06
	CeremonySubClaimShareComplete byte = 0x07
)

// PIV sub-opcodes.
const (
	PIVSubListDevices byte = 0x01
	PIVSubListSlots   byte = 0x02
	PIVSubSlotInfo    byte = 0x03
	PIVSubGenerate    byte = 0x04
	PIVSubImport      byte = 0x05
	PIVSubSign        byte = 0x06
	PIVSubAttest      byte = 0x07
	PIVSubReset       byte = 0x08
)

// LUKS sub-opcodes.
const (
	LUKSSubStatus           byte = 0x01
	LUKSSubListSlots        byte = 0x02
	LUKSSubInfo             byte = 0x03
	LUKSSubEnrollPassphrase byte = 0x04
	LUKSSubEnrollFIDO2      byte = 0x05
	LUKSSubEnrollTPM        byte = 0x06
	LUKSSubEnrollRecovery   byte = 0x07
	LUKSSubRemoveKey        byte = 0x08
	LUKSSubTestUnlock       byte = 0x09
	LUKSSubChangePassphrase byte = 0x0A
)

// FIDO2 sub-opcodes.
const (
	FIDO2SubListDevices  byte = 0x01
	FIDO2SubWaitDevice   byte = 0x02
	FIDO2SubInfo         byte = 0x03
	FIDO2SubRegister     byte = 0x04
	FIDO2SubAuthenticate byte = 0x05
)

// BMC sub-opcodes.
const (
	// BMCSubEnroll performs the BMC enrollment ceremony for a device profile.
	BMCSubEnroll byte = 0x01
	// BMCSubRestore performs the BMC factory-certificate restore ceremony.
	BMCSubRestore byte = 0x02
)
