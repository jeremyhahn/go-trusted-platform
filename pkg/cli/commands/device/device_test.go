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

package device

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Test helper functions

func getTestFlagsWithFormat(format cli.OutputFormat) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
		}
	}
}

// ============================================================================
// Root Command Tests
// ============================================================================

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "device", cmd.Use)
	assert.Equal(t, "Device management operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage devices registered with the platform")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4) // list, get, find-serial, delete

	// Verify key subcommands exist
	expectedCommands := map[string]bool{
		"list":                 false,
		"get <id>":             false,
		"find-serial <serial>": false,
		"delete <id>":          false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

func TestNewCommand_NilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "device", cmd.Use)
}

// ============================================================================
// List Command Tests
// ============================================================================

func TestNewListCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newListCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List devices", cmd.Short)
	assert.Contains(t, cmd.Long, "List all devices with pagination support")

	// Verify flags exist with correct defaults
	pageFlag := cmd.Flag("page")
	require.NotNil(t, pageFlag)
	assert.Equal(t, "1", pageFlag.DefValue)

	pageSizeFlag := cmd.Flag("page-size")
	require.NotNil(t, pageSizeFlag)
	assert.Equal(t, "20", pageSizeFlag.DefValue)
}

func TestNewListCommand_FlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPage string
		wantSize string
	}{
		{
			name:     "default values",
			args:     []string{},
			wantPage: "1",
			wantSize: "20",
		},
		{
			name:     "custom page",
			args:     []string{"--page", "5"},
			wantPage: "5",
			wantSize: "20",
		},
		{
			name:     "custom page size",
			args:     []string{"--page-size", "100"},
			wantPage: "1",
			wantSize: "100",
		},
		{
			name:     "both custom",
			args:     []string{"--page", "3", "--page-size", "50"},
			wantPage: "3",
			wantSize: "50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newListCommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
			cmd.SetArgs(tt.args)
			err := cmd.ParseFlags(tt.args)
			require.NoError(t, err)

			pageFlag := cmd.Flag("page")
			require.NotNil(t, pageFlag)
			assert.Equal(t, tt.wantPage, pageFlag.Value.String())

			pageSizeFlag := cmd.Flag("page-size")
			require.NotNil(t, pageSizeFlag)
			assert.Equal(t, tt.wantSize, pageSizeFlag.Value.String())
		})
	}
}

func TestBuildListOutput(t *testing.T) {
	tests := []struct {
		name      string
		page      int
		pageSize  int
		total     int
		devices   []deviceInfo
		wantPages int
	}{
		{
			name:      "single page",
			page:      1,
			pageSize:  20,
			total:     10,
			devices:   make([]deviceInfo, 10),
			wantPages: 1,
		},
		{
			name:      "multiple pages exact",
			page:      1,
			pageSize:  10,
			total:     30,
			devices:   make([]deviceInfo, 10),
			wantPages: 3,
		},
		{
			name:      "multiple pages with remainder",
			page:      2,
			pageSize:  10,
			total:     25,
			devices:   make([]deviceInfo, 10),
			wantPages: 3,
		},
		{
			name:      "empty devices",
			page:      1,
			pageSize:  20,
			total:     0,
			devices:   []deviceInfo{},
			wantPages: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := buildListOutput(tt.page, tt.pageSize, tt.total, tt.devices)

			assert.Equal(t, tt.page, output["page"])
			assert.Equal(t, tt.pageSize, output["page_size"])
			assert.Equal(t, tt.total, output["total"])
			assert.Equal(t, tt.wantPages, output["total_pages"])
			assert.Equal(t, tt.devices, output["devices"])
		})
	}
}

func TestPrintListTable_EmptyDevices(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)
	devices := []deviceInfo{}

	printListTable(printer, devices, 1, 20, 0)

	// Note: The function prints to stdout directly for "No devices found"
	// We're verifying the function doesn't panic with empty input
}

func TestPrintListTable_WithDevices(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)
	devices := []deviceInfo{
		{ID: 1, Serial: "ABC123", Model: "Device Model 1"},
		{ID: 2, Serial: "DEF456", Model: "Device Model 2"},
	}

	printListTable(printer, devices, 1, 20, 2)

	// The function prints to stdout, so we're mainly verifying no panic occurs
}

// ============================================================================
// Get Command Tests
// ============================================================================

func TestNewGetCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newGetCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "get <id>", cmd.Use)
	assert.Equal(t, "Get device by ID", cmd.Short)
	assert.Contains(t, cmd.Long, "Retrieve a device by its ID")
}

func TestRunGet_InvalidID(t *testing.T) {
	tests := []struct {
		name    string
		idStr   string
		wantErr bool
	}{
		{
			name:    "non-numeric ID",
			idStr:   "abc",
			wantErr: true,
		},
		{
			name:    "negative number",
			idStr:   "-1",
			wantErr: true,
		},
		{
			name:    "empty string",
			idStr:   "",
			wantErr: true,
		},
		{
			name:    "float number",
			idStr:   "1.5",
			wantErr: true,
		},
		{
			name:    "special characters",
			idStr:   "!@#",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatJSON,
			}

			err := runGet(flags, tt.idStr)

			if tt.wantErr {
				require.Error(t, err)
				var invalidErr ErrInvalidDeviceID
				require.ErrorAs(t, err, &invalidErr)
				assert.Equal(t, tt.idStr, invalidErr.ID)
			}
		})
	}
}

func TestBuildGetOutput(t *testing.T) {
	tests := []struct {
		name   string
		device deviceDetail
	}{
		{
			name: "basic device",
			device: deviceDetail{
				ID:         123,
				Serial:     "SN12345",
				Model:      "TestModel",
				HashAlgoID: 1,
			},
		},
		{
			name: "device with all optional fields",
			device: deviceDetail{
				ID:         456,
				Serial:     "SN67890",
				Model:      "AdvancedModel",
				HashAlgoID: 2,
				EKCert:     "-----BEGIN CERTIFICATE-----...",
				AttestPub:  "attestation-public-key",
				SigningPub: "signing-public-key",
			},
		},
		{
			name: "device with some optional fields",
			device: deviceDetail{
				ID:         789,
				Serial:     "SN11111",
				Model:      "PartialModel",
				HashAlgoID: 3,
				EKCert:     "some-cert",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := buildGetOutput(tt.device)

			assert.Equal(t, tt.device.ID, output["id"])
			assert.Equal(t, tt.device.Serial, output["serial"])
			assert.Equal(t, tt.device.Model, output["model"])
			assert.Equal(t, tt.device.HashAlgoID, output["hash_algo_id"])

			if tt.device.EKCert != "" {
				assert.Equal(t, tt.device.EKCert, output["ek_cert"])
			} else {
				_, exists := output["ek_cert"]
				assert.False(t, exists)
			}

			if tt.device.AttestPub != "" {
				assert.Equal(t, tt.device.AttestPub, output["attest_pub"])
			} else {
				_, exists := output["attest_pub"]
				assert.False(t, exists)
			}

			if tt.device.SigningPub != "" {
				assert.Equal(t, tt.device.SigningPub, output["signing_pub"])
			} else {
				_, exists := output["signing_pub"]
				assert.False(t, exists)
			}
		})
	}
}

func TestPrintDeviceDetails(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	tests := []struct {
		name   string
		device deviceDetail
	}{
		{
			name: "basic device",
			device: deviceDetail{
				ID:         1,
				Serial:     "SN001",
				Model:      "Model-A",
				HashAlgoID: 1,
			},
		},
		{
			name: "device with long fields",
			device: deviceDetail{
				ID:         2,
				Serial:     "SN002",
				Model:      "Model-B",
				HashAlgoID: 2,
				EKCert:     "this-is-a-very-long-ek-certificate-that-will-be-truncated-in-display",
				AttestPub:  "this-is-a-very-long-attest-pub-key-that-will-be-truncated-in-display",
				SigningPub: "this-is-a-very-long-signing-pub-key-that-will-be-truncated-in-display",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			printDeviceDetails(printer, tt.device)
			// Verify function executes without panic
			// Actual output goes to the writer
		})
	}
}

// ============================================================================
// Find Serial Command Tests
// ============================================================================

func TestNewFindSerialCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newFindSerialCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "find-serial <serial>", cmd.Use)
	assert.Equal(t, "Find device by serial number", cmd.Short)
	assert.Contains(t, cmd.Long, "Find a device by its serial number")
}

func TestRunFindSerial_EmptySerial(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runFindSerial(flags, "")

	require.Error(t, err)
	var serialErr ErrSerialNumberRequired
	require.ErrorAs(t, err, &serialErr)
}

// ============================================================================
// Delete Command Tests
// ============================================================================

func TestNewDeleteCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newDeleteCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "delete <id>", cmd.Use)
	assert.Equal(t, "Delete device by ID", cmd.Short)
	assert.Contains(t, cmd.Long, "WARNING: This operation is irreversible")
}

func TestRunDelete_InvalidID(t *testing.T) {
	tests := []struct {
		name  string
		idStr string
	}{
		{name: "non-numeric", idStr: "abc"},
		{name: "negative", idStr: "-5"},
		{name: "empty", idStr: ""},
		{name: "special chars", idStr: "id#123"},
		{name: "float", idStr: "3.14"},
		{name: "overflow", idStr: "99999999999999999999999999999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatJSON,
			}

			err := runDelete(flags, tt.idStr)

			require.Error(t, err)
			var invalidErr ErrInvalidDeviceID
			require.ErrorAs(t, err, &invalidErr)
			assert.Equal(t, tt.idStr, invalidErr.ID)
		})
	}
}

func TestBuildDeleteOutput(t *testing.T) {
	tests := []struct {
		name    string
		id      uint64
		success bool
		message string
	}{
		{
			name:    "successful deletion",
			id:      123,
			success: true,
			message: "Device deleted successfully",
		},
		{
			name:    "failed deletion",
			id:      456,
			success: false,
			message: "Device not found",
		},
		{
			name:    "deletion with empty message",
			id:      789,
			success: true,
			message: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := buildDeleteOutput(tt.id, tt.success, tt.message)

			assert.Equal(t, tt.id, output["id"])
			assert.Equal(t, tt.success, output["success"])
			assert.Equal(t, tt.message, output["message"])
		})
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{
			name:     "string shorter than max",
			input:    "hello",
			max:      10,
			expected: "hello",
		},
		{
			name:     "string equal to max",
			input:    "hello",
			max:      5,
			expected: "hello",
		},
		{
			name:     "string longer than max",
			input:    "hello world",
			max:      8,
			expected: "hello...",
		},
		{
			name:     "max of 3 - boundary case",
			input:    "hello",
			max:      3,
			expected: "hel",
		},
		{
			name:     "max less than 3",
			input:    "hello",
			max:      2,
			expected: "he",
		},
		{
			name:     "empty string",
			input:    "",
			max:      10,
			expected: "",
		},
		{
			name:     "max of 4",
			input:    "hello world",
			max:      4,
			expected: "h...",
		},
		{
			name:     "unicode string",
			input:    "hello\u4e16\u754c",
			max:      6,
			expected: "hel...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Error Type Tests
// ============================================================================

func TestErrInvalidDeviceID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "non-numeric ID",
			id:       "abc",
			expected: "invalid device ID: abc",
		},
		{
			name:     "empty ID",
			id:       "",
			expected: "invalid device ID: ",
		},
		{
			name:     "special characters",
			id:       "!@#$",
			expected: "invalid device ID: !@#$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidDeviceID{ID: tt.id}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrDeviceNotFound(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		expected string
	}{
		{
			name:     "device ID 123",
			id:       123,
			expected: "device not found: 123",
		},
		{
			name:     "device ID 0",
			id:       0,
			expected: "device not found: 0",
		},
		{
			name:     "large device ID",
			id:       18446744073709551615, // max uint64
			expected: "device not found: 18446744073709551615",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDeviceNotFound{ID: tt.id}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrDeviceNotFoundBySerial(t *testing.T) {
	tests := []struct {
		name     string
		serial   string
		expected string
	}{
		{
			name:     "normal serial",
			serial:   "ABC123",
			expected: "device not found with serial: ABC123",
		},
		{
			name:     "empty serial",
			serial:   "",
			expected: "device not found with serial: ",
		},
		{
			name:     "serial with special chars",
			serial:   "SN-001/ABC",
			expected: "device not found with serial: SN-001/ABC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDeviceNotFoundBySerial{Serial: tt.serial}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrSerialNumberRequired(t *testing.T) {
	err := ErrSerialNumberRequired{}
	assert.Equal(t, "serial number is required", err.Error())
}

func TestErrDeleteDeviceFailed(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		reason   string
		expected string
	}{
		{
			name:     "device in use",
			id:       123,
			reason:   "device is currently in use",
			expected: "failed to delete device 123: device is currently in use",
		},
		{
			name:     "permission denied",
			id:       456,
			reason:   "permission denied",
			expected: "failed to delete device 456: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDeleteDeviceFailed{ID: tt.id, Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrGetDeviceFailed(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		reason   string
		expected string
	}{
		{
			name:     "connection error",
			id:       123,
			reason:   "connection timeout",
			expected: "failed to get device 123: connection timeout",
		},
		{
			name:     "database error",
			id:       789,
			reason:   "database unavailable",
			expected: "failed to get device 789: database unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrGetDeviceFailed{ID: tt.id, Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrListDevicesFailed(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "timeout error",
			reason:   "operation timed out",
			expected: "failed to list devices: operation timed out",
		},
		{
			name:     "auth error",
			reason:   "authentication failed",
			expected: "failed to list devices: authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrListDevicesFailed{Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrFindDeviceBySerialFailed(t *testing.T) {
	tests := []struct {
		name     string
		serial   string
		reason   string
		expected string
	}{
		{
			name:     "connection error",
			serial:   "ABC123",
			reason:   "connection refused",
			expected: "failed to find device by serial ABC123: connection refused",
		},
		{
			name:     "internal error",
			serial:   "DEF456",
			reason:   "internal server error",
			expected: "failed to find device by serial DEF456: internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrFindDeviceBySerialFailed{Serial: tt.serial, Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

// ============================================================================
// Command Args Validation Tests
// ============================================================================

func TestGetCommand_RequiresExactlyOneArg(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newGetCommand(getFlags)

	// Test with no args
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)

	// Test with too many args
	cmd = newGetCommand(getFlags)
	cmd.SetArgs([]string{"123", "456"})
	err = cmd.Execute()
	require.Error(t, err)
}

func TestDeleteCommand_RequiresExactlyOneArg(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newDeleteCommand(getFlags)

	// Test with no args
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)

	// Test with too many args
	cmd = newDeleteCommand(getFlags)
	cmd.SetArgs([]string{"123", "456"})
	err = cmd.Execute()
	require.Error(t, err)
}

func TestFindSerialCommand_RequiresExactlyOneArg(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newFindSerialCommand(getFlags)

	// Test with no args
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)

	// Test with too many args
	cmd = newFindSerialCommand(getFlags)
	cmd.SetArgs([]string{"serial1", "serial2"})
	err = cmd.Execute()
	require.Error(t, err)
}

// ============================================================================
// Device Info Struct Tests
// ============================================================================

func TestDeviceInfoStruct(t *testing.T) {
	device := deviceInfo{
		ID:     1,
		Serial: "SN001",
		Model:  "Model-A",
	}

	assert.Equal(t, uint64(1), device.ID)
	assert.Equal(t, "SN001", device.Serial)
	assert.Equal(t, "Model-A", device.Model)
}

func TestDeviceDetailStruct(t *testing.T) {
	device := deviceDetail{
		ID:         1,
		Serial:     "SN001",
		Model:      "Model-A",
		HashAlgoID: 1,
		EKCert:     "ek-cert",
		AttestPub:  "attest-pub",
		SigningPub: "signing-pub",
	}

	assert.Equal(t, uint64(1), device.ID)
	assert.Equal(t, "SN001", device.Serial)
	assert.Equal(t, "Model-A", device.Model)
	assert.Equal(t, 1, device.HashAlgoID)
	assert.Equal(t, "ek-cert", device.EKCert)
	assert.Equal(t, "attest-pub", device.AttestPub)
	assert.Equal(t, "signing-pub", device.SigningPub)
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestBuildListOutput_EdgeCases(t *testing.T) {
	// Test with page size of 1
	output := buildListOutput(1, 1, 5, make([]deviceInfo, 1))
	assert.Equal(t, 5, output["total_pages"])

	// Test with page size equal to total
	output = buildListOutput(1, 10, 10, make([]deviceInfo, 10))
	assert.Equal(t, 1, output["total_pages"])

	// Test with page size greater than total
	output = buildListOutput(1, 100, 50, make([]deviceInfo, 50))
	assert.Equal(t, 1, output["total_pages"])
}
