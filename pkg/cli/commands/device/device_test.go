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

	"github.com/spf13/cobra"
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
	assert.Len(t, subcommands, 13) // list, get, find-serial, register, update, delete, profile, template, attest, attest-cert, disable, enable, boot

	// Verify key subcommands exist
	expectedCommands := map[string]bool{
		"list":                 false,
		"get <id>":             false,
		"find-serial <serial>": false,
		"register":             false,
		"update <id>":          false,
		"delete <id>":          false,
		"profile":              false,
		"template":             false,
		"attest <id>":          false,
		"attest-cert":          false,
		"disable <id>":         false,
		"enable <id>":          false,
		"boot":                 false,
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
				AttestCert: "-----BEGIN CERTIFICATE-----iak...",
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

			if tt.device.AttestCert != "" {
				assert.Equal(t, tt.device.AttestCert, output["attest_cert"])
			} else {
				_, exists := output["attest_cert"]
				assert.False(t, exists, "an absent certificate must not be emitted as an empty field")
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
				AttestCert: "-----BEGIN CERTIFICATE-----this-is-a-very-long-iak-certificate-that-will-be-truncated",
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

// ============================================================================
// Command Args Validation Tests
// ============================================================================

func TestIDCommands_RequireExactlyOneArg(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	tests := []struct {
		name       string
		newCommand func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"get", newGetCommand},
		{"delete", newDeleteCommand},
		{"find-serial", newFindSerialCommand},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, args := range [][]string{{}, {"123", "456"}} {
				cmd := tt.newCommand(getFlags)
				cmd.SetArgs(args)
				require.Error(t, cmd.Execute(), "args = %v", args)
			}
		})
	}
}

// ============================================================================
// Device Info Struct Tests
// ============================================================================

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestPrintDeviceDetails_ShowsAttestCert proves the table output names the
// enrolled attestation certificate beside the bare key (#404), truncated the
// same way, and stays silent when none is enrolled.
func TestPrintDeviceDetails_ShowsAttestCert(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	printDeviceDetails(printer, deviceDetail{
		ID: 1, Serial: "SN001", Model: "M", HashAlgoID: 11,
		AttestCert: "-----BEGIN CERTIFICATE-----\nthis-certificate-is-longer-than-fifty-characters-for-sure\n-----END CERTIFICATE-----",
	})
	out := buf.String()
	assert.Contains(t, out, "Attest Cert")
	assert.NotContains(t, out, "END CERTIFICATE", "the table view truncates long PEM blobs")

	buf.Reset()
	printDeviceDetails(printer, deviceDetail{ID: 2, Serial: "SN002", Model: "M", HashAlgoID: 11})
	assert.NotContains(t, buf.String(), "Attest Cert", "no certificate, no row")
}
