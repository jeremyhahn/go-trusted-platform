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

package firmware

import (
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVariableFilename(t *testing.T) {
	guid := uefi.GUID{
		Data1: 0x12345678,
		Data2: 0x1234,
		Data3: 0x1234,
		Data4: [8]byte{0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
	}

	filename := variableFilename("TestVar", guid)
	// GUID is formatted in uppercase
	expected := "TestVar-12345678-1234-1234-1234-123456789ABC"
	assert.Equal(t, expected, filename)
}

func TestIsAvailable_NotAvailable(t *testing.T) {
	// Test with non-existent path
	// The real efivarfs path won't exist in most test environments
	// This test verifies the function handles missing efivarfs gracefully
	available := IsAvailable()

	// On a typical development machine without EFI, this should be false
	// On a real EFI system, it would be true
	// We just verify it doesn't panic
	t.Logf("efivarfs available: %v", available)
}

func TestTrustedPlatformGUID(t *testing.T) {
	// Verify GUID is valid and consistent
	guid := TrustedPlatformGUID
	guidStr := guid.String()

	assert.NotEmpty(t, guidStr)
	assert.Len(t, guidStr, 36) // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

	// Parse and verify round-trip
	parsed, err := uefi.ParseGUID(guidStr)
	require.NoError(t, err)
	assert.Equal(t, guid, parsed)
}

func TestTrustedPlatformAttributes(t *testing.T) {
	// Verify attributes have the expected flags set
	attrs := TrustedPlatformAttributes

	// Should be NV + BS + RT
	assert.True(t, attrs&uefi.AttrNonVolatile != 0, "should have NV attribute")
	assert.True(t, attrs&uefi.AttrBootserviceAccess != 0, "should have BS attribute")
	assert.True(t, attrs&uefi.AttrRuntimeAccess != 0, "should have RT attribute")

	// Should NOT have authenticated write attribute (not a Secure Boot variable)
	assert.True(t, attrs&uefi.AttrTimeBasedAuthWriteAccess == 0, "should not have TIME_BASED_AUTH attribute")
}

func TestIsTrustedPlatform_NotAvailable(t *testing.T) {
	// When efivarfs is not available, IsTrustedPlatform should return false
	// This tests the graceful handling of missing efivarfs
	result := IsTrustedPlatform()

	// In a test environment without real efivarfs, this should be false
	// We're testing that it doesn't panic and returns a sensible default
	t.Logf("IsTrustedPlatform: %v", result)
}

func TestVariableDataFormat(t *testing.T) {
	// Test the efivarfs data format: 4-byte attrs + data
	attrs := uint32(0x00000007) // NV | BS | RT
	data := []byte("test data")

	// Create the formatted data
	varData := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(varData[:4], attrs)
	copy(varData[4:], data)

	// Verify format
	assert.Equal(t, 4+len(data), len(varData))

	// Read back attributes
	readAttrs := binary.LittleEndian.Uint32(varData[:4])
	assert.Equal(t, attrs, readAttrs)

	// Read back data
	readData := varData[4:]
	assert.Equal(t, data, readData)
}

func TestErrVariableNotFound(t *testing.T) {
	// Verify error types are properly defined
	assert.NotNil(t, ErrNotAvailable)
	assert.NotNil(t, ErrVariableNotFound)
	assert.NotNil(t, ErrPermissionDenied)
	assert.NotNil(t, ErrInvalidData)
	assert.NotNil(t, ErrImmutable)
	assert.NotNil(t, ErrNotTrustedPlatform)
}

// Note: Tests that actually write to efivarfs require root privileges
// and a real EFI system. Those should be in integration tests, not unit tests.
