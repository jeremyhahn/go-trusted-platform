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
	"os"
	"path/filepath"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Register Command Creation Tests
// ============================================================================

func TestNewRegisterCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newRegisterCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "register", cmd.Use)
	assert.Equal(t, "Register a device with the control plane", cmd.Short)
	assert.Contains(t, cmd.Long, "Register a new device")

	// Verify all flags exist with correct defaults
	hostnameFlag := cmd.Flag("hostname")
	require.NotNil(t, hostnameFlag)
	assert.Equal(t, "", hostnameFlag.DefValue)

	macFlag := cmd.Flag("mac")
	require.NotNil(t, macFlag)
	assert.Equal(t, "", macFlag.DefValue)

	roleFlag := cmd.Flag("role")
	require.NotNil(t, roleFlag)
	assert.Equal(t, "", roleFlag.DefValue)

	templateFlag := cmd.Flag("template")
	require.NotNil(t, templateFlag)
	assert.Equal(t, "", templateFlag.DefValue)

	overrideFlag := cmd.Flag("override-file")
	require.NotNil(t, overrideFlag)
	assert.Equal(t, "", overrideFlag.DefValue)

	serverFlag := cmd.Flag("server")
	require.NotNil(t, serverFlag)
	assert.Equal(t, "", serverFlag.DefValue)

	caCertFlag := cmd.Flag("ca-cert")
	require.NotNil(t, caCertFlag)
	assert.Equal(t, "", caCertFlag.DefValue)
}

func TestNewRegisterCommand_FlagParsing(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newRegisterCommand(getFlags)

	args := []string{
		"--hostname", "gw-01",
		"--mac", "00:25:90:FF:AA:01",
		"--role", "gateway",
		"--template", "gateway-default",
		"--server", "https://198.18.1.140:8443",
		"--ca-cert", "/etc/platform/ca.pem",
		"--override-file", "/tmp/overrides.yaml",
	}

	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	assert.Equal(t, "gw-01", cmd.Flag("hostname").Value.String())
	assert.Equal(t, "00:25:90:FF:AA:01", cmd.Flag("mac").Value.String())
	assert.Equal(t, "gateway", cmd.Flag("role").Value.String())
	assert.Equal(t, "gateway-default", cmd.Flag("template").Value.String())
	assert.Equal(t, "https://198.18.1.140:8443", cmd.Flag("server").Value.String())
	assert.Equal(t, "/etc/platform/ca.pem", cmd.Flag("ca-cert").Value.String())
	assert.Equal(t, "/tmp/overrides.yaml", cmd.Flag("override-file").Value.String())
}

// ============================================================================
// Flag Validation Tests
// ============================================================================

func TestValidateRegisterFlags_AllValid(t *testing.T) {
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		template: "gateway-default",
		server:   "https://198.18.1.140:8443",
	}

	err := validateRegisterFlags(rf)
	assert.NoError(t, err)
}

func TestValidateRegisterFlags_AllRoles(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{name: "control-plane", role: "control-plane"},
		{name: "gateway", role: "gateway"},
		{name: "worker", role: "worker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := &registerFlags{
				hostname: "node-01",
				mac:      "00:25:90:FF:AA:01",
				role:     tt.role,
				template: "default",
				server:   "https://cp:8443",
			}
			err := validateRegisterFlags(rf)
			assert.NoError(t, err)
		})
	}
}

func TestValidateRegisterFlags_MissingHostname(t *testing.T) {
	rf := &registerFlags{
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		template: "gateway-default",
		server:   "https://cp:8443",
	}

	err := validateRegisterFlags(rf)
	require.Error(t, err)
	var hostnameErr ErrRegisterHostnameRequired
	require.ErrorAs(t, err, &hostnameErr)
}

func TestValidateRegisterFlags_MissingMAC(t *testing.T) {
	rf := &registerFlags{
		hostname: "gw-01",
		role:     "gateway",
		template: "gateway-default",
		server:   "https://cp:8443",
	}

	err := validateRegisterFlags(rf)
	require.Error(t, err)
	var macErr ErrRegisterMACRequired
	require.ErrorAs(t, err, &macErr)
}

func TestValidateRegisterFlags_InvalidMAC(t *testing.T) {
	tests := []struct {
		name string
		mac  string
	}{
		{name: "not a MAC", mac: "not-a-mac"},
		{name: "too short", mac: "00:25:90"},
		{name: "invalid chars", mac: "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"},
		{name: "too long", mac: "00:25:90:FF:AA:01:BB:CC:DD"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := &registerFlags{
				hostname: "gw-01",
				mac:      tt.mac,
				role:     "gateway",
				template: "gateway-default",
				server:   "https://cp:8443",
			}

			err := validateRegisterFlags(rf)
			require.Error(t, err)
			var macErr ErrRegisterInvalidMACAddress
			require.ErrorAs(t, err, &macErr)
			assert.Equal(t, tt.mac, macErr.MAC)
		})
	}
}

func TestValidateRegisterFlags_ValidMACFormats(t *testing.T) {
	tests := []struct {
		name string
		mac  string
	}{
		{name: "colon separated", mac: "00:25:90:FF:AA:01"},
		{name: "dash separated", mac: "00-25-90-FF-AA-01"},
		{name: "no separators", mac: "002590FFAA01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := &registerFlags{
				hostname: "gw-01",
				mac:      tt.mac,
				role:     "gateway",
				template: "gateway-default",
				server:   "https://cp:8443",
			}

			err := validateRegisterFlags(rf)
			assert.NoError(t, err)
		})
	}
}

func TestValidateRegisterFlags_MissingRole(t *testing.T) {
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		template: "gateway-default",
		server:   "https://cp:8443",
	}

	err := validateRegisterFlags(rf)
	require.Error(t, err)
	var roleErr ErrRegisterRoleRequired
	require.ErrorAs(t, err, &roleErr)
}

func TestValidateRegisterFlags_InvalidRole(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{name: "unknown role", role: "leader"},
		{name: "uppercase", role: "GATEWAY"},
		{name: "mixed case", role: "Control-Plane"},
		{name: "spaces", role: "  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := &registerFlags{
				hostname: "gw-01",
				mac:      "00:25:90:FF:AA:01",
				role:     tt.role,
				template: "gateway-default",
				server:   "https://cp:8443",
			}

			err := validateRegisterFlags(rf)
			require.Error(t, err)
			var roleErr ErrRegisterInvalidRole
			require.ErrorAs(t, err, &roleErr)
			assert.Equal(t, tt.role, roleErr.Role)
		})
	}
}

func TestValidateRegisterFlags_MissingTemplate(t *testing.T) {
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		server:   "https://cp:8443",
	}

	err := validateRegisterFlags(rf)
	require.Error(t, err)
	var templateErr ErrRegisterTemplateRequired
	require.ErrorAs(t, err, &templateErr)
}

func TestValidateRegisterFlags_MissingServer(t *testing.T) {
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		template: "gateway-default",
	}

	err := validateRegisterFlags(rf)
	require.Error(t, err)
	var serverErr ErrRegisterServerRequired
	require.ErrorAs(t, err, &serverErr)
}

// ============================================================================
// Override File Tests
// ============================================================================

func TestRunRegister_OverrideFileNotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
	rf := &registerFlags{
		hostname:     "gw-01",
		mac:          "00:25:90:FF:AA:01",
		role:         "gateway",
		template:     "gateway-default",
		server:       "https://cp:8443",
		overrideFile: "/nonexistent/path/overrides.yaml",
	}

	err := runRegister(flags, rf)
	require.Error(t, err)
	var readErr ErrRegisterReadOverrideFile
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "/nonexistent/path/overrides.yaml", readErr.Path)
}

func TestRunRegister_InvalidOverrideYAML(t *testing.T) {
	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "bad.yaml")
	err := os.WriteFile(overridePath, []byte("{{invalid yaml: ["), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
	rf := &registerFlags{
		hostname:     "gw-01",
		mac:          "00:25:90:FF:AA:01",
		role:         "gateway",
		template:     "gateway-default",
		server:       "https://cp:8443",
		overrideFile: overridePath,
	}

	err = runRegister(flags, rf)
	require.Error(t, err)
	var parseErr ErrRegisterParseOverrideFile
	require.ErrorAs(t, err, &parseErr)
	assert.Equal(t, overridePath, parseErr.Path)
}

// ============================================================================
// Context Builder Tests
// ============================================================================

func TestBuildRegisterContext_WithoutCACert(t *testing.T) {
	rf := &registerFlags{
		server: "https://198.18.1.140:8443",
	}

	getCtx := buildRegisterContext(rf)
	ctx, err := getCtx()

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "register", ctx.Name)
	assert.Equal(t, cli.ContextTypeRemote, ctx.Type)
	assert.Equal(t, "rest", ctx.Protocol)
	assert.Equal(t, "https://198.18.1.140:8443", ctx.Remote.Server)
	assert.Equal(t, "", ctx.Remote.CACert)
}

func TestBuildRegisterContext_WithCACert(t *testing.T) {
	rf := &registerFlags{
		server: "https://cp.example.com:8443",
		caCert: "/etc/platform/ca.pem",
	}

	getCtx := buildRegisterContext(rf)
	ctx, err := getCtx()

	require.NoError(t, err)
	require.NotNil(t, ctx)
	assert.Equal(t, "https://cp.example.com:8443", ctx.Remote.Server)
	assert.Equal(t, "/etc/platform/ca.pem", ctx.Remote.CACert)
}

// ============================================================================
// Output Builder Tests
// ============================================================================

func TestBuildRegisterOutput(t *testing.T) {
	profile := &platformv1.DeviceProfile{
		Id:   42,
		Name: "gw-01",
	}
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		template: "gateway-default",
	}

	output := buildRegisterOutput(profile, rf)

	assert.Equal(t, uint64(42), output["profile_id"])
	assert.Equal(t, "gw-01", output["hostname"])
	assert.Equal(t, "00:25:90:FF:AA:01", output["mac"])
	assert.Equal(t, "gateway", output["role"])
	assert.Equal(t, "gateway-default", output["template"])
	assert.Equal(t, "gw-01", output["name"])
}

func TestBuildRegisterOutput_AllRoles(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{name: "control-plane", role: "control-plane"},
		{name: "gateway", role: "gateway"},
		{name: "worker", role: "worker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &platformv1.DeviceProfile{Id: 1, Name: "node"}
			rf := &registerFlags{
				hostname: "node",
				mac:      "00:11:22:33:44:55",
				role:     tt.role,
				template: "tmpl",
			}

			output := buildRegisterOutput(profile, rf)
			assert.Equal(t, tt.role, output["role"])
		})
	}
}

// ============================================================================
// Print Result Tests
// ============================================================================

func TestPrintRegisterResult(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	profile := &platformv1.DeviceProfile{
		Id:   42,
		Name: "gw-01",
	}
	rf := &registerFlags{
		hostname: "gw-01",
		mac:      "00:25:90:FF:AA:01",
		role:     "gateway",
		template: "gateway-default",
	}

	// Verify function executes without panic
	printRegisterResult(printer, profile, rf)
}

func TestPrintRegisterResult_ZeroProfileID(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	profile := &platformv1.DeviceProfile{
		Id:   0,
		Name: "worker-01",
	}
	rf := &registerFlags{
		hostname: "worker-01",
		mac:      "AA:BB:CC:DD:EE:FF",
		role:     "worker",
		template: "worker-default",
	}

	printRegisterResult(printer, profile, rf)
}

// ============================================================================
// Role Mapping Tests
// ============================================================================

func TestValidRoles_Mapping(t *testing.T) {
	tests := []struct {
		label    string
		expected platformv1.DeviceRole
	}{
		{"control-plane", platformv1.DeviceRole_DEVICE_ROLE_SERVER},
		{"gateway", platformv1.DeviceRole_DEVICE_ROLE_GATEWAY},
		{"worker", platformv1.DeviceRole_DEVICE_ROLE_CLIENT},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			role, ok := validRoles[tt.label]
			require.True(t, ok, "role %q should be in validRoles", tt.label)
			assert.Equal(t, tt.expected, role)
		})
	}
}

func TestValidRoles_InvalidNotPresent(t *testing.T) {
	invalidRoles := []string{"leader", "primary", "master", "node", ""}
	for _, role := range invalidRoles {
		_, ok := validRoles[role]
		assert.False(t, ok, "role %q should not be in validRoles", role)
	}
}

// ============================================================================
// Register Error Type Tests
// ============================================================================

func TestErrRegisterHostnameRequired(t *testing.T) {
	err := ErrRegisterHostnameRequired{}
	assert.Equal(t, "device register: --hostname is required", err.Error())
}

func TestErrRegisterMACRequired(t *testing.T) {
	err := ErrRegisterMACRequired{}
	assert.Equal(t, "device register: --mac is required", err.Error())
}

func TestErrRegisterRoleRequired(t *testing.T) {
	err := ErrRegisterRoleRequired{}
	assert.Equal(t, "device register: --role is required", err.Error())
}

func TestErrRegisterInvalidRole(t *testing.T) {
	err := ErrRegisterInvalidRole{Role: "leader"}
	assert.Equal(t, `device register: invalid role "leader", must be one of: control-plane, gateway, worker`, err.Error())
}

func TestErrRegisterTemplateRequired(t *testing.T) {
	err := ErrRegisterTemplateRequired{}
	assert.Equal(t, "device register: --template is required", err.Error())
}

func TestErrRegisterServerRequired(t *testing.T) {
	err := ErrRegisterServerRequired{}
	assert.Equal(t, "device register: --server is required", err.Error())
}

func TestErrRegisterInvalidMACAddress(t *testing.T) {
	err := ErrRegisterInvalidMACAddress{MAC: "not-a-mac"}
	assert.Equal(t, `device register: invalid MAC address "not-a-mac"`, err.Error())
}

func TestErrRegisterReadOverrideFile(t *testing.T) {
	cause := os.ErrNotExist
	err := ErrRegisterReadOverrideFile{Path: "/tmp/missing.yaml", Cause: cause}
	assert.Contains(t, err.Error(), "failed to read override file /tmp/missing.yaml")
	assert.ErrorIs(t, err, cause)
}

func TestErrRegisterParseOverrideFile(t *testing.T) {
	cause := os.ErrInvalid
	err := ErrRegisterParseOverrideFile{Path: "/tmp/bad.yaml", Cause: cause}
	assert.Contains(t, err.Error(), "failed to parse override file /tmp/bad.yaml")
	assert.ErrorIs(t, err, cause)
}

func TestErrRegisterLoadCACert(t *testing.T) {
	cause := os.ErrNotExist
	err := ErrRegisterLoadCACert{Path: "/tmp/ca.pem", Cause: cause}
	assert.Contains(t, err.Error(), "failed to load CA certificate /tmp/ca.pem")
	assert.ErrorIs(t, err, cause)
}

func TestErrRegisterInvalidCACert(t *testing.T) {
	err := ErrRegisterInvalidCACert{Path: "/tmp/bad-ca.pem"}
	assert.Contains(t, err.Error(), "no valid PEM data")
	assert.Contains(t, err.Error(), "/tmp/bad-ca.pem")
}

func TestErrRegisterTemplateLookupFailed(t *testing.T) {
	cause := os.ErrNotExist
	err := ErrRegisterTemplateLookupFailed{Name: "gateway-default", Cause: cause}
	assert.Contains(t, err.Error(), `failed to look up template "gateway-default"`)
	assert.ErrorIs(t, err, cause)
}

func TestErrRegisterCreateProfileFailed(t *testing.T) {
	cause := os.ErrPermission
	err := ErrRegisterCreateProfileFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to create profile")
	assert.ErrorIs(t, err, cause)
}
