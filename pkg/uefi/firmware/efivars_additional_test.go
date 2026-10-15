package firmware

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/assert"
)

func TestVariablePath(t *testing.T) {
	guid := uefi.GUID{
		Data1: 0x12345678,
		Data2: 0x1234,
		Data3: 0x1234,
		Data4: [8]byte{0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
	}

	path := variablePath("TestVar", guid)
	assert.Contains(t, path, EfiVarsPath)
	assert.Contains(t, path, "TestVar")
	assert.Contains(t, path, "12345678-1234-1234-1234-123456789ABC")
}

func TestReadVariable_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	_, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestWriteVariable_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	err := WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("test"))
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestDeleteVariable_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	err := DeleteVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestListVariables_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	_, err := ListVariables()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestGetVariable_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	_, err := GetVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestSetVariable_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	v := &uefi.Variable{
		Name:       "TestVar",
		GUID:       TrustedPlatformGUID,
		Attributes: 0x07,
		Data:       []byte("test"),
	}
	err := SetVariable(v)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestSetTrustedPlatform_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	err := SetTrustedPlatform()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestClearTrustedPlatform_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	// ClearTrustedPlatform returns nil only for a missing variable, never
	// for missing efivarfs.
	err := ClearTrustedPlatform()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestGetTrustedPlatform_NotAvailable(t *testing.T) {
	useMissingEfiVars(t)

	result, err := GetTrustedPlatform()
	assert.ErrorIs(t, err, ErrNotAvailable)
	assert.False(t, result)
}

func TestEfiVarsPathConstant(t *testing.T) {
	assert.Equal(t, "/sys/firmware/efi/efivars", EfiVarsPath)
}

func TestTrustedPlatformVariableName(t *testing.T) {
	assert.Equal(t, "TRUSTED_PLATFORM", TrustedPlatformVariableName)
}

func TestVariableInfoStruct(t *testing.T) {
	info := VariableInfo{
		Name:       "TestVar",
		GUID:       TrustedPlatformGUID,
		Attributes: 0x07,
		Size:       100,
	}

	assert.Equal(t, "TestVar", info.Name)
	assert.Equal(t, uint32(0x07), info.Attributes)
	assert.Equal(t, 100, info.Size)
}
