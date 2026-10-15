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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFakeChattr is the failure fakeChattr returns for its failing flag.
var errFakeChattr = &WrappedError{Msg: "fake chattr", Err: os.ErrPermission}

// fakeChattr records each chattr call as "flag path" and fails the flag
// named in fail.
type fakeChattr struct {
	calls []string
	fail  string
}

func (f *fakeChattr) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] == f.fail {
		return []byte("Operation not permitted"), errFakeChattr
	}
	return nil, nil
}

// useEfiVarsRoot points the package at root with a fake chattr and restores
// both seams when the test ends. The seams are package variables, so no test
// in this package runs in parallel.
func useEfiVarsRoot(t *testing.T, root string) *fakeChattr {
	t.Helper()
	chattr := &fakeChattr{}
	savedRoot, savedChattr := efiVarsRoot, runChattr
	efiVarsRoot, runChattr = root, chattr.run
	t.Cleanup(func() { efiVarsRoot, runChattr = savedRoot, savedChattr })
	return chattr
}

// useEfiVars points the package at an empty efivarfs in a temp dir and
// returns the directory with the fake chattr.
func useEfiVars(t *testing.T) (string, *fakeChattr) {
	t.Helper()
	root := t.TempDir()
	return root, useEfiVarsRoot(t, root)
}

// useMissingEfiVars points the package at an efivarfs that does not exist.
func useMissingEfiVars(t *testing.T) *fakeChattr {
	t.Helper()
	return useEfiVarsRoot(t, filepath.Join(t.TempDir(), "efivars"))
}

// writeRawVariable writes an efivarfs file with exactly content.
func writeRawVariable(t *testing.T, root, name string, guid uefi.GUID, content []byte) string {
	t.Helper()
	path := filepath.Join(root, variableFilename(name, guid))
	require.NoError(t, os.WriteFile(path, content, 0644))
	return path
}

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
	useMissingEfiVars(t)
	assert.False(t, IsAvailable())
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
	useMissingEfiVars(t)
	assert.False(t, IsTrustedPlatform())
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

func TestEfiVarsSeamDefaults(t *testing.T) {
	assert.Equal(t, EfiVarsPath, efiVarsRoot)
	assert.NotNil(t, runChattr)
}

// TestRunChattr_MissingBinary runs the default seam with an empty PATH, so
// the host chattr is never found or run.
func TestRunChattr_MissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "var")

	_, err := runChattr("-i", path)
	assert.ErrorIs(t, err, exec.ErrNotFound)

	err = removeImmutable(path)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Contains(t, wrapped.Msg, "chattr -i failed")
	assert.ErrorIs(t, err, exec.ErrNotFound)

	err = setImmutable(path)
	require.ErrorAs(t, err, &wrapped)
	assert.Contains(t, wrapped.Msg, "chattr +i failed")
}

func TestIsAvailable(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		useEfiVars(t)
		assert.True(t, IsAvailable())
	})

	t.Run("regular file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "efivars")
		require.NoError(t, os.WriteFile(root, nil, 0644))
		useEfiVarsRoot(t, root)
		assert.False(t, IsAvailable())
	})
}

func TestWriteReadVariable_RoundTrip(t *testing.T) {
	root, chattr := useEfiVars(t)
	path := filepath.Join(root, variableFilename("TestVar", TrustedPlatformGUID))

	require.NoError(t, WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("first")))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x07, 0, 0, 0, 'f', 'i', 'r', 's', 't'}, raw)
	assert.Equal(t, []string{"+i " + path}, chattr.calls, "a new variable is only made immutable")

	require.NoError(t, SetVariable(&uefi.Variable{
		Name: "TestVar", GUID: TrustedPlatformGUID, Attributes: 0x27, Data: []byte("second"),
	}))
	assert.Equal(t, []string{"+i " + path, "-i " + path, "+i " + path}, chattr.calls,
		"an existing variable is made mutable before the rewrite")

	data, attrs, err := ReadVariable("TestVar", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), data)
	assert.Equal(t, uint32(0x27), attrs)

	v, err := GetVariable("TestVar", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, &uefi.Variable{
		Name: "TestVar", GUID: TrustedPlatformGUID, Attributes: 0x27, Data: []byte("second"),
	}, v)
}

func TestWriteVariable_Errors(t *testing.T) {
	t.Run("remove immutable fails", func(t *testing.T) {
		root, chattr := useEfiVars(t)
		chattr.fail = "-i"
		path := writeRawVariable(t, root, "TestVar", TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 'o', 'l', 'd'})

		err := WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("new"))
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to remove immutable attribute", wrapped.Msg)
		assert.ErrorIs(t, err, errFakeChattr)

		raw, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, []byte{0x07, 0, 0, 0, 'o', 'l', 'd'}, raw, "the variable is untouched")
	})

	t.Run("set immutable fails after the write", func(t *testing.T) {
		_, chattr := useEfiVars(t)
		chattr.fail = "+i"

		require.NoError(t, WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("data")))

		data, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
		require.NoError(t, err)
		assert.Equal(t, []byte("data"), data)
	})

	t.Run("open fails", func(t *testing.T) {
		root, _ := useEfiVars(t)
		require.NoError(t, os.Mkdir(filepath.Join(root, variableFilename("TestVar", TrustedPlatformGUID)), 0755))

		err := WriteVariable("TestVar", TrustedPlatformGUID, 0x07, []byte("data"))
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to open variable for writing", wrapped.Msg)
	})
}

func TestReadVariable_Errors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		useEfiVars(t)
		_, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
		assert.ErrorIs(t, err, ErrVariableNotFound)

		_, err = GetVariable("TestVar", TrustedPlatformGUID)
		assert.ErrorIs(t, err, ErrVariableNotFound)
	})

	t.Run("shorter than the attributes", func(t *testing.T) {
		root, _ := useEfiVars(t)
		writeRawVariable(t, root, "TestVar", TrustedPlatformGUID, []byte{0x07, 0, 0})

		_, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
		assert.ErrorIs(t, err, ErrInvalidData)
	})

	t.Run("unreadable", func(t *testing.T) {
		root, _ := useEfiVars(t)
		require.NoError(t, os.Mkdir(filepath.Join(root, variableFilename("TestVar", TrustedPlatformGUID)), 0755))

		_, _, err := ReadVariable("TestVar", TrustedPlatformGUID)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to read variable", wrapped.Msg)
	})
}

func TestDeleteVariable(t *testing.T) {
	root, chattr := useEfiVars(t)
	path := writeRawVariable(t, root, "TestVar", TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 'x'})

	require.NoError(t, DeleteVariable("TestVar", TrustedPlatformGUID))

	assert.NoFileExists(t, path)
	assert.Equal(t, []string{"-i " + path}, chattr.calls)
}

func TestDeleteVariable_Errors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		_, chattr := useEfiVars(t)
		err := DeleteVariable("TestVar", TrustedPlatformGUID)
		assert.ErrorIs(t, err, ErrVariableNotFound)
		assert.Empty(t, chattr.calls)
	})

	t.Run("remove immutable fails", func(t *testing.T) {
		root, chattr := useEfiVars(t)
		chattr.fail = "-i"
		path := writeRawVariable(t, root, "TestVar", TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 'x'})

		err := DeleteVariable("TestVar", TrustedPlatformGUID)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to remove immutable attribute", wrapped.Msg)
		assert.ErrorIs(t, err, errFakeChattr)
		assert.FileExists(t, path)
	})

	t.Run("remove fails", func(t *testing.T) {
		root, _ := useEfiVars(t)
		path := filepath.Join(root, variableFilename("TestVar", TrustedPlatformGUID))
		require.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0755))

		err := DeleteVariable("TestVar", TrustedPlatformGUID)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to delete variable", wrapped.Msg)
	})
}

func TestListVariables(t *testing.T) {
	root, _ := useEfiVars(t)
	bootGUID, err := uefi.ParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
	require.NoError(t, err)

	writeRawVariable(t, root, "Boot0000", bootGUID, []byte{0x07, 0, 0, 0, 'b', 'o', 'o', 't'})
	writeRawVariable(t, root, TrustedPlatformVariableName, TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 't', 'r', 'u', 'e'})
	writeRawVariable(t, root, "Short", TrustedPlatformGUID, []byte{0x07, 0})
	// Not variables: a directory, a name with no GUID, and a malformed GUID.
	require.NoError(t, os.Mkdir(filepath.Join(root, variableFilename("Dir", TrustedPlatformGUID)), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "NoGUID"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Bad-ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ"), nil, 0644))

	variables, err := ListVariables()
	require.NoError(t, err)

	byName := make(map[string]VariableInfo, len(variables))
	for _, v := range variables {
		byName[v.Name] = v
	}
	assert.Len(t, byName, 3)
	assert.Equal(t, VariableInfo{Name: "Boot0000", GUID: bootGUID, Attributes: 0x07, Size: 4}, byName["Boot0000"])
	assert.Equal(t, VariableInfo{
		Name: TrustedPlatformVariableName, GUID: TrustedPlatformGUID, Attributes: 0x07, Size: 4,
	}, byName[TrustedPlatformVariableName])

	short, ok := byName["Short"]
	require.True(t, ok, "an unreadable variable is still listed")
	assert.Equal(t, TrustedPlatformGUID, short.GUID)
	assert.Zero(t, short.Attributes)
}

func TestListVariables_Empty(t *testing.T) {
	useEfiVars(t)
	variables, err := ListVariables()
	require.NoError(t, err)
	assert.Empty(t, variables)
}

// Note: Tests that actually write to efivarfs require root privileges
// and a real EFI system. Those should be in integration tests, not unit tests.
