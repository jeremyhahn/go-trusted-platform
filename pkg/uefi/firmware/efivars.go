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

// Package firmware provides access to UEFI firmware variables on bare metal
// systems via the Linux efivarfs interface at /sys/firmware/efi/efivars/
package firmware

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

const (
	// EfiVarsPath is the default path to the efivarfs mount point
	EfiVarsPath = "/sys/firmware/efi/efivars"
)

var (
	// ErrNotAvailable indicates efivarfs is not mounted/available
	ErrNotAvailable = errors.New("efivarfs not available")

	// ErrVariableNotFound indicates the requested variable does not exist
	ErrVariableNotFound = errors.New("variable not found")

	// ErrPermissionDenied indicates insufficient permissions to access variable
	ErrPermissionDenied = errors.New("permission denied")

	// ErrInvalidData indicates the variable data format is invalid
	ErrInvalidData = errors.New("invalid variable data")

	// ErrImmutable indicates the variable file has the immutable attribute set
	ErrImmutable = errors.New("variable is immutable")
)

// VariableInfo contains metadata about an EFI variable
type VariableInfo struct {
	Name       string
	GUID       uefi.GUID
	Attributes uint32
	Size       int
}

// IsAvailable returns true if efivarfs is mounted and accessible
func IsAvailable() bool {
	info, err := os.Stat(EfiVarsPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// variableFilename constructs the efivarfs filename for a variable
// Format: {name}-{guid} (e.g., "TRUSTED_PLATFORM-12345678-1234-1234-1234-123456789abc")
func variableFilename(name string, guid uefi.GUID) string {
	return fmt.Sprintf("%s-%s", name, guid.String())
}

// variablePath returns the full path to a variable file
func variablePath(name string, guid uefi.GUID) string {
	return filepath.Join(EfiVarsPath, variableFilename(name, guid))
}

// ReadVariable reads an EFI variable from efivarfs
// Returns the variable data, attributes, and any error
func ReadVariable(name string, guid uefi.GUID) ([]byte, uint32, error) {
	if !IsAvailable() {
		return nil, 0, ErrNotAvailable
	}

	path := variablePath(name, guid)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrVariableNotFound
		}
		if os.IsPermission(err) {
			return nil, 0, ErrPermissionDenied
		}
		return nil, 0, fmt.Errorf("failed to read variable: %w", err)
	}

	// efivarfs format: 4-byte attributes (little-endian) followed by data
	if len(data) < 4 {
		return nil, 0, ErrInvalidData
	}

	attrs := binary.LittleEndian.Uint32(data[:4])
	varData := data[4:]

	return varData, attrs, nil
}

// WriteVariable writes an EFI variable to efivarfs
// The variable file format is: 4-byte attributes (little-endian) + data
func WriteVariable(name string, guid uefi.GUID, attrs uint32, data []byte) error {
	if !IsAvailable() {
		return ErrNotAvailable
	}

	path := variablePath(name, guid)

	// Check if file exists and remove immutable attribute if needed
	if _, err := os.Stat(path); err == nil {
		// File exists, need to remove immutable attribute before writing
		if err := removeImmutable(path); err != nil {
			return fmt.Errorf("failed to remove immutable attribute: %w", err)
		}
	}

	// Prepare the data: 4-byte attributes + variable data
	varData := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(varData[:4], attrs)
	copy(varData[4:], data)

	// Write the variable
	// Use O_WRONLY|O_CREAT|O_TRUNC to create or overwrite
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		if os.IsPermission(err) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("failed to open variable for writing: %w", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(varData); err != nil {
		return fmt.Errorf("failed to write variable: %w", err)
	}

	// Set immutable attribute to protect the variable
	// This is a best practice for EFI variables
	if err := setImmutable(path); err != nil {
		// Log warning but don't fail - the variable was written successfully
		fmt.Fprintf(os.Stderr, "WARNING: failed to set immutable attribute on %s: %v\n", path, err)
	}

	return nil
}

// DeleteVariable deletes an EFI variable from efivarfs
func DeleteVariable(name string, guid uefi.GUID) error {
	if !IsAvailable() {
		return ErrNotAvailable
	}

	path := variablePath(name, guid)

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrVariableNotFound
	}

	// Remove immutable attribute before deleting
	if err := removeImmutable(path); err != nil {
		return fmt.Errorf("failed to remove immutable attribute: %w", err)
	}

	// Delete the file
	if err := os.Remove(path); err != nil {
		if os.IsPermission(err) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("failed to delete variable: %w", err)
	}

	return nil
}

// ListVariables returns information about all EFI variables
func ListVariables() ([]VariableInfo, error) {
	if !IsAvailable() {
		return nil, ErrNotAvailable
	}

	entries, err := os.ReadDir(EfiVarsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read efivarfs directory: %w", err)
	}

	var variables []VariableInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Parse the variable name and GUID from filename
		// Format: {name}-{guid}
		lastDash := strings.LastIndex(name, "-")
		if lastDash == -1 || lastDash < 36 {
			// Invalid format, skip
			continue
		}

		// GUID is the last 36 characters before any extension
		guidStr := name[len(name)-36:]
		varName := name[:len(name)-37] // name without "-guid"

		guid, err := uefi.ParseGUID(guidStr)
		if err != nil {
			// Skip invalid GUIDs
			continue
		}

		// Get file size for variable size
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Read attributes
		var attrs uint32
		if data, a, err := ReadVariable(varName, guid); err == nil {
			attrs = a
			variables = append(variables, VariableInfo{
				Name:       varName,
				GUID:       guid,
				Attributes: attrs,
				Size:       len(data),
			})
		} else {
			// Could not read, but include with size from stat
			variables = append(variables, VariableInfo{
				Name: varName,
				GUID: guid,
				Size: int(info.Size()) - 4, // subtract attributes size
			})
		}
	}

	return variables, nil
}

// removeImmutable removes the immutable attribute from a file using chattr
func removeImmutable(path string) error {
	cmd := exec.Command("chattr", "-i", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chattr -i failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// setImmutable sets the immutable attribute on a file using chattr
func setImmutable(path string) error {
	cmd := exec.Command("chattr", "+i", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chattr +i failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// GetVariable is a convenience function that reads a variable and returns a Variable struct
func GetVariable(name string, guid uefi.GUID) (*uefi.Variable, error) {
	data, attrs, err := ReadVariable(name, guid)
	if err != nil {
		return nil, err
	}

	return &uefi.Variable{
		Name:       name,
		GUID:       guid,
		Attributes: attrs,
		Data:       data,
	}, nil
}

// SetVariable is a convenience function that writes a variable from a Variable struct
func SetVariable(v *uefi.Variable) error {
	return WriteVariable(v.Name, v.GUID, v.Attributes, v.Data)
}
