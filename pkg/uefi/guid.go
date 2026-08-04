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

package uefi

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// GUID represents a UEFI Globally Unique Identifier (128-bit UUID)
// The format is: Data1-Data2-Data3-Data4[0:2]-Data4[2:8]
// Example: 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
type GUID struct {
	Data1 uint32  // Little-endian
	Data2 uint16  // Little-endian
	Data3 uint16  // Little-endian
	Data4 [8]byte // Big-endian
}

// GUIDSize is the size of a GUID in bytes
const GUIDSize = 16

// NewGUID generates a random GUID (UUID v4)
func NewGUID() GUID {
	var g GUID
	b := make([]byte, 16)
	rand.Read(b)

	// Set version (4) and variant (RFC 4122)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122

	g.Data1 = binary.LittleEndian.Uint32(b[0:4])
	g.Data2 = binary.LittleEndian.Uint16(b[4:6])
	g.Data3 = binary.LittleEndian.Uint16(b[6:8])
	copy(g.Data4[:], b[8:16])

	return g
}

// ParseGUID parses a GUID from string format
// Accepts: "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" or "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
func ParseGUID(s string) (GUID, error) {
	var g GUID

	// Remove braces and whitespace
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "{}")

	// Split by dash
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID format: expected 5 parts, got %d", len(parts))}
	}

	// Parse Data1 (4 bytes)
	data1, err := hex.DecodeString(parts[0])
	if err != nil || len(data1) != 4 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID Data1: %s", parts[0])}
	}
	g.Data1 = binary.BigEndian.Uint32(data1)

	// Parse Data2 (2 bytes)
	data2, err := hex.DecodeString(parts[1])
	if err != nil || len(data2) != 2 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID Data2: %s", parts[1])}
	}
	g.Data2 = binary.BigEndian.Uint16(data2)

	// Parse Data3 (2 bytes)
	data3, err := hex.DecodeString(parts[2])
	if err != nil || len(data3) != 2 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID Data3: %s", parts[2])}
	}
	g.Data3 = binary.BigEndian.Uint16(data3)

	// Parse Data4 (8 bytes from parts 3 and 4)
	data4a, err := hex.DecodeString(parts[3])
	if err != nil || len(data4a) != 2 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID Data4a: %s", parts[3])}
	}
	data4b, err := hex.DecodeString(parts[4])
	if err != nil || len(data4b) != 6 {
		return g, &MessageError{Msg: fmt.Sprintf("invalid GUID Data4b: %s", parts[4])}
	}
	copy(g.Data4[0:2], data4a)
	copy(g.Data4[2:8], data4b)

	return g, nil
}

// MustParseGUID parses a GUID or panics
func MustParseGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

// String returns the GUID in standard format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
func (g GUID) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// Bytes returns the GUID as a 16-byte slice in mixed-endian format (UEFI standard)
func (g GUID) Bytes() []byte {
	b := make([]byte, GUIDSize)
	binary.LittleEndian.PutUint32(b[0:4], g.Data1)
	binary.LittleEndian.PutUint16(b[4:6], g.Data2)
	binary.LittleEndian.PutUint16(b[6:8], g.Data3)
	copy(b[8:16], g.Data4[:])
	return b
}

// FromBytes creates a GUID from a 16-byte slice
func GUIDFromBytes(b []byte) (GUID, error) {
	if len(b) < GUIDSize {
		return GUID{}, &MessageError{Msg: fmt.Sprintf("insufficient bytes for GUID: need %d, got %d", GUIDSize, len(b))}
	}

	var g GUID
	g.Data1 = binary.LittleEndian.Uint32(b[0:4])
	g.Data2 = binary.LittleEndian.Uint16(b[4:6])
	g.Data3 = binary.LittleEndian.Uint16(b[6:8])
	copy(g.Data4[:], b[8:16])

	return g, nil
}

// Equal returns true if two GUIDs are equal
func (g GUID) Equal(other GUID) bool {
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4 == other.Data4
}

// IsZero returns true if the GUID is all zeros
func (g GUID) IsZero() bool {
	return g.Data1 == 0 && g.Data2 == 0 && g.Data3 == 0 && g.Data4 == [8]byte{}
}

// Well-known GUIDs

// EFIGlobalVariable is the EFI Global Variable GUID
// Used for: PK, KEK, SecureBoot, SetupMode
var EFIGlobalVariable = MustParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")

// EFIImageSecurityDatabase is the Image Security Database GUID
// Used for: db, dbx, dbt, dbr
var EFIImageSecurityDatabase = MustParseGUID("D719B2CB-3D3A-4596-A3BC-DAD00E67656F")

// Signature Type GUIDs

// EFIX509Cert identifies an X.509 certificate signature
var EFIX509Cert = MustParseGUID("A5C059A1-94E4-4AA7-87B5-AB155C2BF072")

// EFIX509SHA256 identifies an X.509 certificate hash (SHA-256 of TBSCertificate)
var EFIX509SHA256 = MustParseGUID("3BD2A492-96C0-4079-B420-FCF98EF103ED")

// EFISHA256 identifies a SHA-256 hash signature
var EFISHA256 = MustParseGUID("C1C41626-504C-4092-ACA9-41F936934328")

// EFISHA384 identifies a SHA-384 hash signature
var EFISHA384 = MustParseGUID("FF3E5307-9FD0-48C9-85F1-8AD56C701E01")

// EFISHA512 identifies a SHA-512 hash signature
var EFISHA512 = MustParseGUID("093E0FAE-A6C4-4F50-9F1B-D41E2B89C19A")

// EFIRSA2048 identifies an RSA-2048 signature
var EFIRSA2048 = MustParseGUID("3C5766E8-269C-4E34-AA14-ED776E85B3B6")

// EFIPKCS7Cert identifies a PKCS#7 signed certificate
var EFIPKCS7Cert = MustParseGUID("4AAFD29D-68DF-49EE-8AA9-347D375665A7")

// Firmware Volume GUIDs

// FFS2GUID identifies the Firmware File System version 2
var FFS2GUID = MustParseGUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")

// FFS3GUID identifies the Firmware File System version 3
var FFS3GUID = MustParseGUID("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")

// NVRAMVariableStoreGUID identifies the NVRAM variable store
var NVRAMVariableStoreGUID = MustParseGUID("DDCF3616-3275-4164-98B6-FE85707FFE7D")

// AuthenticatedVariableGUID identifies authenticated variable format
var AuthenticatedVariableGUID = MustParseGUID("AAF32C78-947B-439A-A180-2E144EC37792")

// TrustedPlatformGUID is the Trusted Platform vendor GUID
// Used for: TRUSTED_PLATFORM, TRUSTED_PLATFORM_BUILD, etc.
// Generated specifically for go-trusted-platform project
var TrustedPlatformGUID = MustParseGUID("F47E4B3D-8C21-4A9F-B6E5-1D2C3E4F5A6B")
