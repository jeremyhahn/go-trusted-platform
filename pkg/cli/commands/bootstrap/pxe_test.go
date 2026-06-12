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

package bootstrap

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// validBootstrapYAML is a minimal valid bootstrap config for testing.
const validBootstrapYAML = `deployer:
  target: linux
  host: 192.168.1.1
  user: admin
  ssh_key: /tmp/test-key
  container_runtime: docker
subnets:
  - name: provisioning
    role: provisioning
    cidr: 10.0.0.0/24
    gateway: 10.0.0.1
    dns:
      - 10.0.0.1
    dhcp:
      enabled: true
      range-start: 10.0.0.100
      range-end: 10.0.0.200
platform:
  domain: example.com
  internal_domain: internal.example.com
  tenant_id: tenant-1
  environment: production
templates:
  control-plane: /tmp/control-plane.yaml
nodes:
  - hostname: cp-01
    role: control-plane
    bmc_address: 192.168.1.10
    bmc_user: admin
    bmc_password: password
`

// defaultGetFlags returns a standard getFlags function for tests.
func defaultGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}
}

// writeTestConfig writes YAML content to a temp file and returns its path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.yaml")
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)
	return path
}

// =============================================================================
// Run Command Tests
// =============================================================================

func TestRunCommand_Structure(t *testing.T) {
	cmd := newRunCommand(defaultGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "run", cmd.Use)
	assert.Equal(t, "Run full PXE bootstrap", cmd.Short)
	assert.Contains(t, cmd.Long, "Execute the complete PXE bootstrap flow")
	assert.NotNil(t, cmd.RunE)

	// Verify config flag exists
	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)
	assert.NotEmpty(t, configFlag.Usage)
}

func TestRunCommand_MissingConfig(t *testing.T) {
	err := runBootstrap("", &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, false)
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestRunCommand_NonexistentConfig(t *testing.T) {
	err := runBootstrap("/nonexistent/bootstrap.yaml", &cli.CommonFlags{}, false)
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

func TestRunCommand_InvalidConfig(t *testing.T) {
	path := writeTestConfig(t, "not: valid: yaml: [")
	err := runBootstrap(path, &cli.CommonFlags{}, false)
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

func TestRunCommand_NilCommonFlags(t *testing.T) {
	// Should handle nil commonFlags gracefully (defaults to non-verbose).
	err := runBootstrap("", nil, false)
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

// =============================================================================
// Discover Command Tests
// =============================================================================

func TestDiscoverCommand_Structure(t *testing.T) {
	cmd := newDiscoverCommand(defaultGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "discover", cmd.Use)
	assert.Equal(t, "Discover node MAC addresses", cmd.Short)
	assert.Contains(t, cmd.Long, "Phase 0")
	assert.NotNil(t, cmd.RunE)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)
}

func TestDiscoverCommand_MissingConfig(t *testing.T) {
	err := runDiscover("", &cli.CommonFlags{})
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestDiscoverCommand_NonexistentConfig(t *testing.T) {
	err := runDiscover("/nonexistent/bootstrap.yaml", &cli.CommonFlags{})
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

// =============================================================================
// Deploy Command Tests
// =============================================================================

func TestDeployCommand_Structure(t *testing.T) {
	cmd := newDeployCommand(defaultGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "deploy", cmd.Use)
	assert.Equal(t, "Deploy bootstrap container", cmd.Short)
	assert.Contains(t, cmd.Long, "Phase 2")
	assert.NotNil(t, cmd.RunE)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)
}

func TestDeployCommand_MissingConfig(t *testing.T) {
	err := runDeploy("", &cli.CommonFlags{})
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestDeployCommand_NonexistentConfig(t *testing.T) {
	err := runDeploy("/nonexistent/bootstrap.yaml", &cli.CommonFlags{})
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

// =============================================================================
// Teardown Command Tests
// =============================================================================

func TestTeardownCommand_Structure(t *testing.T) {
	cmd := newTeardownCommand(defaultGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "teardown", cmd.Use)
	assert.Equal(t, "Teardown bootstrap container", cmd.Short)
	assert.Contains(t, cmd.Long, "Teardown the PXE bootstrap container")
	assert.NotNil(t, cmd.RunE)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)
}

func TestTeardownCommand_MissingConfig(t *testing.T) {
	err := runTeardown("", &cli.CommonFlags{})
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestTeardownCommand_NonexistentConfig(t *testing.T) {
	err := runTeardown("/nonexistent/bootstrap.yaml", &cli.CommonFlags{})
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

// =============================================================================
// Status Command Tests
// =============================================================================

func TestPXEStatusCommand_Structure(t *testing.T) {
	cmd := newStatusCommand(defaultGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "status", cmd.Use)
	assert.Equal(t, "Check bootstrap node status", cmd.Short)
	assert.Contains(t, cmd.Long, "health status")
	assert.NotNil(t, cmd.RunE)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)
}

func TestPXEStatusCommand_MissingConfig(t *testing.T) {
	err := runStatus("", &cli.CommonFlags{})
	require.Error(t, err)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestPXEStatusCommand_NonexistentConfig(t *testing.T) {
	err := runStatus("/nonexistent/bootstrap.yaml", &cli.CommonFlags{})
	require.Error(t, err)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

// =============================================================================
// Helper Tests
// =============================================================================

func TestLoadAndValidateConfig_EmptyPath(t *testing.T) {
	config, err := loadAndValidateConfig("")
	require.Error(t, err)
	assert.Nil(t, config)

	var configErr ErrPXEConfigRequired
	assert.ErrorAs(t, err, &configErr)
}

func TestLoadAndValidateConfig_FileNotFound(t *testing.T) {
	config, err := loadAndValidateConfig("/nonexistent/bootstrap.yaml")
	require.Error(t, err)
	assert.Nil(t, config)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

func TestLoadAndValidateConfig_InvalidYAML(t *testing.T) {
	path := writeTestConfig(t, "not: valid: yaml: [")
	config, err := loadAndValidateConfig(path)
	require.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadAndValidateConfig_ValidationFailure(t *testing.T) {
	// Config that parses but fails validation (no deployer host).
	path := writeTestConfig(t, `deployer:
  target: linux
  host: ""
subnets:
  - name: provisioning
    role: provisioning
    cidr: 10.0.0.0/24
platform:
  domain: example.com
nodes:
  - hostname: cp-01
    role: control-plane
    bmc_address: 192.168.1.10
`)
	config, err := loadAndValidateConfig(path)
	require.Error(t, err)
	assert.Nil(t, config)

	var validErr ErrPXEConfigValidationFailed
	assert.ErrorAs(t, err, &validErr)
}

func TestLoadAndValidateConfig_Valid(t *testing.T) {
	path := writeTestConfig(t, validBootstrapYAML)
	config, err := loadAndValidateConfig(path)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, "example.com", config.Platform.Domain)
	assert.Len(t, config.Nodes, 1)
}

func TestBoolStatus(t *testing.T) {
	assert.Equal(t, "done", boolStatus(true))
	assert.Equal(t, "pending", boolStatus(false))
}

// TestCheckNodeHealth_UnreachableHost verifies that an unreachable host returns
// "unreachable". The target 192.0.2.1 is TEST-NET-1 (RFC 5737) and is never
// routed, so the connection fails at TCP level before TLS is attempted.
func TestCheckNodeHealth_UnreachableHost(t *testing.T) {
	client := &http.Client{
		Timeout: 100 * time.Millisecond,
	}
	result := checkNodeHealth(t.Context(), client, "192.0.2.1") // TEST-NET, unreachable
	assert.Equal(t, "unreachable", result)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrPXEConfigRequired(t *testing.T) {
	err := ErrPXEConfigRequired{}
	assert.Equal(t, "bootstrap: --config flag is required", err.Error())
}

func TestErrPXEConfigLoadFailed(t *testing.T) {
	err := ErrPXEConfigLoadFailed{Path: "/path/to/config.yaml", Cause: assert.AnError}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrPXEConfigValidationFailed(t *testing.T) {
	err := ErrPXEConfigValidationFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "config validation failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrOrchestratorCreationFailed(t *testing.T) {
	err := ErrOrchestratorCreationFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "failed to create orchestrator")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrPXERunFailed(t *testing.T) {
	err := ErrPXERunFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "run failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrPXEDiscoveryFailed(t *testing.T) {
	err := ErrPXEDiscoveryFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "discovery failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrPXEDeployFailed(t *testing.T) {
	err := ErrPXEDeployFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "deploy failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrPXETeardownFailed(t *testing.T) {
	err := ErrPXETeardownFailed{Cause: assert.AnError}
	assert.Contains(t, err.Error(), "teardown failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}
