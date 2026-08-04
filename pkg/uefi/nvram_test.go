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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"simple", "Hello"},
		{"with numbers", "Test123"},
		{"empty", ""},
		{"special chars", "PK"},
		{"variable name", "SecureBoot"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeUTF16LE(tt.input)
			decoded := decodeUTF16LE(encoded)
			assert.Equal(t, tt.input, decoded)
		})
	}
}

func TestDecodeUTF16LE_ShortData(t *testing.T) {
	// Test with less than 2 bytes
	result := decodeUTF16LE([]byte{0x41})
	assert.Equal(t, "", result)
}

func TestNVRAM_SetVariable(t *testing.T) {
	// Create a minimal NVRAM structure for testing
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Fill with 0xFF (erased state)
	for i := range nvram.data {
		nvram.data[i] = 0xFF
	}

	// Set a variable
	testData := []byte{0x01}
	err := nvram.SetVariable("SecureBoot", EFIGlobalVariable, SecureBootAttributes, testData)
	require.NoError(t, err)

	// Verify variable was added
	assert.Len(t, nvram.variables, 1)

	// Get the variable back
	v, err := nvram.GetVariable("SecureBoot", EFIGlobalVariable)
	require.NoError(t, err)
	assert.Equal(t, "SecureBoot", v.Name)
	assert.Equal(t, EFIGlobalVariable, v.GUID)
	assert.Equal(t, testData, v.Data)
}

func TestNVRAM_UpdateVariable(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Set initial value
	err := nvram.SetVariable("TestVar", EFIGlobalVariable, SecureBootAttributes, []byte{0x01})
	require.NoError(t, err)

	// Update value
	err = nvram.SetVariable("TestVar", EFIGlobalVariable, SecureBootAttributes, []byte{0x02})
	require.NoError(t, err)

	// Should still have only one variable
	assert.Len(t, nvram.variables, 1)

	// Verify updated value
	v, err := nvram.GetVariable("TestVar", EFIGlobalVariable)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x02}, v.Data)
}

func TestNVRAM_DeleteVariable(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Set a variable
	err := nvram.SetVariable("TestVar", EFIGlobalVariable, SecureBootAttributes, []byte{0x01})
	require.NoError(t, err)
	assert.Len(t, nvram.variables, 1)

	// Delete it
	err = nvram.DeleteVariable("TestVar", EFIGlobalVariable)
	require.NoError(t, err)
	assert.Len(t, nvram.variables, 0)

	// Try to get it - should fail
	_, err = nvram.GetVariable("TestVar", EFIGlobalVariable)
	assert.Equal(t, ErrVariableNotFound, err)
}

func TestNVRAM_DeleteVariable_NotFound(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	err := nvram.DeleteVariable("NonExistent", EFIGlobalVariable)
	assert.Equal(t, ErrVariableNotFound, err)
}

func TestNVRAM_ListVariables(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Add multiple variables
	err := nvram.SetVariable("Var1", EFIGlobalVariable, SecureBootAttributes, []byte{0x01})
	require.NoError(t, err)
	err = nvram.SetVariable("Var2", EFIGlobalVariable, SecureBootAttributes, []byte{0x02})
	require.NoError(t, err)
	err = nvram.SetVariable("Var3", EFIImageSecurityDatabase, SecureBootAttributes, []byte{0x03})
	require.NoError(t, err)

	vars := nvram.ListVariables()
	assert.Len(t, vars, 3)
}

func TestNVRAM_Bytes(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Initialize with valid FV header signature
	copy(nvram.data[40:44], FirmwareVolumeSignature[:])

	// Fill variable area with 0xFF
	for i := nvram.varStoreStart; i < nvram.varStoreEnd; i++ {
		nvram.data[i] = 0xFF
	}

	// Add a variable
	err := nvram.SetVariable("TestVar", EFIGlobalVariable, AttrNonVolatile|AttrBootserviceAccess, []byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	// Serialize
	data, err := nvram.Bytes()
	require.NoError(t, err)
	assert.Len(t, data, 4096)

	// The variable store area should contain our variable
	// First 0x55AA marker at varStoreStart
	startID := uint16(data[nvram.varStoreStart]) | uint16(data[nvram.varStoreStart+1])<<8
	assert.Equal(t, VariableHeaderStartID, startID)
}

func TestNVRAM_Bytes_InsufficientSpace(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 200),
		varStoreStart: 100,
		varStoreEnd:   150, // Very small variable store
		variables:     make([]*variableEntry, 0),
	}

	// Add a large variable that won't fit
	largeData := make([]byte, 100)
	err := nvram.SetVariable("LargeVar", EFIGlobalVariable, AttrNonVolatile, largeData)
	require.NoError(t, err)

	_, err = nvram.Bytes()
	assert.Error(t, err)
	assert.Equal(t, ErrInsufficientSpace, err)
}

func TestNVRAM_SaveTo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nvram-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	// Initialize
	for i := range nvram.data {
		nvram.data[i] = 0xFF
	}
	copy(nvram.data[40:44], FirmwareVolumeSignature[:])

	// Add a variable
	err = nvram.SetVariable("TestVar", EFIGlobalVariable, AttrNonVolatile, []byte{0x01})
	require.NoError(t, err)

	// Save
	outPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	err = nvram.SaveTo(outPath)
	require.NoError(t, err)

	// Verify file was created
	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, int64(4096), info.Size())
}

func TestNVRAM_SaveTo_Error(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 200),
		varStoreStart: 100,
		varStoreEnd:   150,
		variables:     make([]*variableEntry, 0),
	}

	largeData := make([]byte, 100)
	err := nvram.SetVariable("LargeVar", EFIGlobalVariable, AttrNonVolatile, largeData)
	require.NoError(t, err)

	err = nvram.SaveTo("/tmp/test.fd")
	assert.Error(t, err)
}

func TestNVRAM_Save_NoPath(t *testing.T) {
	nvram := &NVRAM{
		path:          "",
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	err := nvram.Save()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no file path specified")
}

func TestNVRAM_Save_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nvram-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	outPath := filepath.Join(tmpDir, "OVMF_VARS.fd")

	nvram := &NVRAM{
		path:          outPath,
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	for i := range nvram.data {
		nvram.data[i] = 0xFF
	}
	copy(nvram.data[40:44], FirmwareVolumeSignature[:])

	err = nvram.SetVariable("TestVar", EFIGlobalVariable, AttrNonVolatile, []byte{0x01})
	require.NoError(t, err)

	err = nvram.Save()
	require.NoError(t, err)

	_, err = os.Stat(outPath)
	assert.NoError(t, err)
}

func TestNVRAM_Path(t *testing.T) {
	nvram := &NVRAM{
		path: "/path/to/nvram.fd",
	}
	assert.Equal(t, "/path/to/nvram.fd", nvram.Path())
}

func TestNVRAM_Size(t *testing.T) {
	nvram := &NVRAM{
		data: make([]byte, 4096),
	}
	assert.Equal(t, 4096, nvram.Size())
}

func TestNVRAM_WriteTo(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 4096),
		varStoreStart: 100,
		varStoreEnd:   4000,
		variables:     make([]*variableEntry, 0),
	}

	for i := range nvram.data {
		nvram.data[i] = 0xFF
	}
	copy(nvram.data[40:44], FirmwareVolumeSignature[:])

	err := nvram.SetVariable("TestVar", EFIGlobalVariable, AttrNonVolatile, []byte{0x01})
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := nvram.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(4096), n)
	assert.Len(t, buf.Bytes(), 4096)
}

func TestNVRAM_WriteTo_Error(t *testing.T) {
	nvram := &NVRAM{
		data:          make([]byte, 200),
		varStoreStart: 100,
		varStoreEnd:   150,
		variables:     make([]*variableEntry, 0),
	}

	largeData := make([]byte, 100)
	err := nvram.SetVariable("LargeVar", EFIGlobalVariable, AttrNonVolatile, largeData)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = nvram.WriteTo(&buf)
	assert.Error(t, err)
}

func TestSerializeVariable(t *testing.T) {
	nvram := &NVRAM{}

	v := &Variable{
		Name:       "TestVar",
		GUID:       EFIGlobalVariable,
		Attributes: AttrNonVolatile | AttrBootserviceAccess,
		Data:       []byte{0x01, 0x02, 0x03},
	}

	// Non-authenticated
	data, err := nvram.serializeVariable(v, false)
	require.NoError(t, err)

	// Check start ID
	startID := uint16(data[0]) | uint16(data[1])<<8
	assert.Equal(t, VariableHeaderStartID, startID)

	// Check state
	assert.Equal(t, VarStateAdded, data[2])

	// Authenticated
	v.Attributes |= AttrTimeBasedAuthWriteAccess
	authData, err := nvram.serializeVariable(v, true)
	require.NoError(t, err)

	// Auth header should be larger
	assert.Greater(t, len(authData), len(data))
}

// Helper function to create a minimal valid NVRAM file for testing
func createMinimalNVRAM(t *testing.T) []byte {
	t.Helper()

	data := make([]byte, 512*1024)

	// Fill with erased state
	for i := range data {
		data[i] = 0xFF
	}

	// Write firmware volume header
	for i := 0; i < 16; i++ {
		data[i] = 0
	}

	copy(data[16:32], FFS2GUID.Bytes())

	fvLen := uint64(len(data))
	data[32] = byte(fvLen)
	data[33] = byte(fvLen >> 8)
	data[34] = byte(fvLen >> 16)
	data[35] = byte(fvLen >> 24)
	data[36] = byte(fvLen >> 32)
	data[37] = byte(fvLen >> 40)
	data[38] = byte(fvLen >> 48)
	data[39] = byte(fvLen >> 56)

	copy(data[40:44], FirmwareVolumeSignature[:])

	data[44] = 0x00
	data[45] = 0x04
	data[46] = 0x0F
	data[47] = 0x00

	data[48] = 0x48
	data[49] = 0x00

	data[50] = 0x00
	data[51] = 0x00

	data[52] = 0x00
	data[53] = 0x00

	data[54] = 0x00
	data[55] = 0x02

	// Variable store header at offset 72
	copy(data[72:88], NVRAMVariableStoreGUID.Bytes())

	vsSize := uint32(len(data) - 72)
	data[88] = byte(vsSize)
	data[89] = byte(vsSize >> 8)
	data[90] = byte(vsSize >> 16)
	data[91] = byte(vsSize >> 24)

	data[92] = VarStoreFormatted
	data[93] = VarStoreHealthy
	data[94] = 0
	data[95] = 0
	data[96] = 0
	data[97] = 0
	data[98] = 0
	data[99] = 0

	return data
}

func TestOpenNVRAM_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nvram-test-*")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	data := createMinimalNVRAM(t)
	err = os.WriteFile(nvramPath, data, 0644)
	require.NoError(t, err)

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)
	assert.NotNil(t, nvram)
	assert.Equal(t, nvramPath, nvram.path)
}

func TestOpenNVRAM_FileNotFound(t *testing.T) {
	_, err := OpenNVRAM("/nonexistent/path/OVMF_VARS.fd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read NVRAM file")
}

func TestParseNVRAM_Success(t *testing.T) {
	data := createMinimalNVRAM(t)

	nvram, err := ParseNVRAM(data, "/test/path.fd")
	require.NoError(t, err)
	assert.NotNil(t, nvram)
	assert.Equal(t, "/test/path.fd", nvram.path)
}

func TestParseNVRAM_TooShort(t *testing.T) {
	data := make([]byte, 10)

	_, err := ParseNVRAM(data, "/test/path.fd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file too small for firmware volume header")
}

func TestParseFirmwareVolumeHeader_InvalidSignature(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = 0xFF
	}

	// Set invalid signature
	copy(data[40:44], []byte{'B', 'A', 'D', 'S'})

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
}

func TestParseVariableStore_WithStandardGUID(t *testing.T) {
	data := createMinimalNVRAM(t)

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)
	assert.Greater(t, nvram.varStoreStart, 0)
	assert.Greater(t, nvram.varStoreEnd, nvram.varStoreStart)
}

func TestParseVariableStore_WithAuthenticatedGUID(t *testing.T) {
	data := createMinimalNVRAM(t)

	// Replace with authenticated variable GUID
	copy(data[72:88], AuthenticatedVariableGUID.Bytes())

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)
	assert.Greater(t, nvram.varStoreStart, 0)
}

func TestParseVariableStore_GUIDNotFound(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = 0xFF
	}

	// Write valid FV header
	copy(data[16:32], FFS2GUID.Bytes())
	copy(data[40:44], FirmwareVolumeSignature[:])
	data[48] = 0x48
	data[49] = 0x00

	// Put invalid GUID in variable store location
	invalidGUID := NewGUID()
	copy(data[72:88], invalidGUID.Bytes())

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)
	// Should still succeed with default values
}

func TestParseVariables_Empty(t *testing.T) {
	data := createMinimalNVRAM(t)

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)

	err = nvram.parseVariables()
	require.NoError(t, err)
	assert.Len(t, nvram.variables, 0)
}

func TestParseVariables_WithVariable(t *testing.T) {
	data := createMinimalNVRAM(t)

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)

	// Manually add a variable to the store
	offset := nvram.varStoreStart

	// Write variable header
	data[offset] = 0xAA
	data[offset+1] = 0x55
	data[offset+2] = VarStateAdded
	data[offset+3] = 0x00

	// Attributes
	attrs := AttrNonVolatile | AttrBootserviceAccess
	data[offset+4] = byte(attrs)
	data[offset+5] = byte(attrs >> 8)
	data[offset+6] = byte(attrs >> 16)
	data[offset+7] = byte(attrs >> 24)

	// Name size (UTF-16LE "Test" + null = 10 bytes)
	nameSize := uint32(10)
	data[offset+8] = byte(nameSize)
	data[offset+9] = byte(nameSize >> 8)
	data[offset+10] = byte(nameSize >> 16)
	data[offset+11] = byte(nameSize >> 24)

	// Data size
	dataSize := uint32(3)
	data[offset+12] = byte(dataSize)
	data[offset+13] = byte(dataSize >> 8)
	data[offset+14] = byte(dataSize >> 16)
	data[offset+15] = byte(dataSize >> 24)

	// GUID
	copy(data[offset+16:offset+32], EFIGlobalVariable.Bytes())

	// Name "Test" in UTF-16LE
	nameBytes := encodeUTF16LE("Test")
	copy(data[offset+32:offset+32+int(nameSize)], nameBytes)

	// Data
	data[offset+32+int(nameSize)] = 0x01
	data[offset+32+int(nameSize)+1] = 0x02
	data[offset+32+int(nameSize)+2] = 0x03

	err = nvram.parseVariables()
	require.NoError(t, err)
	assert.Len(t, nvram.variables, 1)
	assert.Equal(t, "Test", nvram.variables[0].variable.Name)
}

func TestParseVariable_Authenticated(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0

	// Write authenticated variable header
	data[offset] = 0xAA
	data[offset+1] = 0x55
	data[offset+2] = VarStateAdded
	data[offset+3] = 0x00

	// Attributes with authenticated flag
	attrs := AttrNonVolatile | AttrBootserviceAccess | AttrTimeBasedAuthWriteAccess
	data[offset+4] = byte(attrs)
	data[offset+5] = byte(attrs >> 8)
	data[offset+6] = byte(attrs >> 16)
	data[offset+7] = byte(attrs >> 24)

	// MonotonicCount (8 bytes)
	for i := 0; i < 8; i++ {
		data[offset+8+i] = 0x00
	}

	// Timestamp (16 bytes)
	for i := 0; i < 16; i++ {
		data[offset+16+i] = 0x00
	}

	// PubKeyIndex (4 bytes)
	for i := 0; i < 4; i++ {
		data[offset+32+i] = 0x00
	}

	// Name size
	nameSize := uint32(10)
	data[offset+36] = byte(nameSize)
	data[offset+37] = byte(nameSize >> 8)
	data[offset+38] = byte(nameSize >> 16)
	data[offset+39] = byte(nameSize >> 24)

	// Data size
	dataSize := uint32(3)
	data[offset+40] = byte(dataSize)
	data[offset+41] = byte(dataSize >> 8)
	data[offset+42] = byte(dataSize >> 16)
	data[offset+43] = byte(dataSize >> 24)

	// GUID
	copy(data[offset+44:offset+60], EFIGlobalVariable.Bytes())

	// Name "Test" in UTF-16LE
	nameBytes := encodeUTF16LE("Test")
	copy(data[offset+60:offset+60+int(nameSize)], nameBytes)

	// Data
	data[offset+60+int(nameSize)] = 0x01
	data[offset+60+int(nameSize)+1] = 0x02
	data[offset+60+int(nameSize)+2] = 0x03

	// The 60-byte authenticated header layout is a property of the STORE, not
	// of the variable's attributes, so the fixture must declare an
	// authenticated variable store.
	nvram := &NVRAM{data: data, authStore: true}
	entry, nextOffset, err := nvram.parseVariable(offset)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.True(t, entry.isAuth)
	assert.Equal(t, "Test", entry.variable.Name)
	assert.Greater(t, nextOffset, offset)
}

func TestParseVariable_InsufficientData(t *testing.T) {
	data := make([]byte, 10)

	nvram := &NVRAM{data: data}
	_, _, err := nvram.parseVariable(0)
	assert.Error(t, err)
}

func TestParseVariable_SizeOutOfBounds(t *testing.T) {
	data := make([]byte, 512)

	offset := 0
	data[offset] = 0xAA
	data[offset+1] = 0x55
	data[offset+2] = VarStateAdded
	data[offset+3] = 0x00

	attrs := AttrNonVolatile
	data[offset+4] = byte(attrs)
	data[offset+5] = byte(attrs >> 8)
	data[offset+6] = byte(attrs >> 16)
	data[offset+7] = byte(attrs >> 24)

	// Set absurdly large name size
	nameSize := uint32(10 * 1024 * 1024)
	data[offset+8] = byte(nameSize)
	data[offset+9] = byte(nameSize >> 8)
	data[offset+10] = byte(nameSize >> 16)
	data[offset+11] = byte(nameSize >> 24)

	nvram := &NVRAM{data: data}
	_, _, err := nvram.parseVariable(offset)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "variable size out of bounds")
}
