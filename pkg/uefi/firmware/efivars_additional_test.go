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
	// On most dev systems, efivarfs is not available or is a real directory
	// that we should not modify. We test the not-available path.
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	_, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestWriteVariable_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	err := WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("test"))
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestDeleteVariable_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	err := DeleteVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestListVariables_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	_, err := ListVariables()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestGetVariable_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	_, err := GetVariable("TestVar", TrustedPlatformGUID)
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestSetVariable_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

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
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	err := SetTrustedPlatform()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestClearTrustedPlatform_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	// ClearTrustedPlatform returns nil for not-found, but ErrNotAvailable wraps differently
	err := ClearTrustedPlatform()
	assert.ErrorIs(t, err, ErrNotAvailable)
}

func TestGetTrustedPlatform_NotAvailable(t *testing.T) {
	if IsAvailable() {
		t.Skip("efivarfs is available, skipping not-available test")
	}

	result, err := GetTrustedPlatform()
	assert.Error(t, err)
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
