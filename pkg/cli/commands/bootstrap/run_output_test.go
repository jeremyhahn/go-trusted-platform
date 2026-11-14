package bootstrap

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container/containertest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// writeDeployerConfig writes a config whose deployer is a TEST-NET-1 host
// (RFC 5737) serving an x86_64 netboot build from t.TempDir(). Discovery and
// the dry run only report the deployer; they never dial it.
func writeDeployerConfig(t *testing.T, rest string) string {
	t.Helper()
	media := t.TempDir()
	require.NoError(t, containertest.WriteNetbootBuild(media, false, false, container.MediaSetX86_64))
	return writeTestConfig(t, "deployer:\n  host: 192.0.2.1\n  user: admin\n  ssh_key: /nonexistent/test-key\n"+
		"  netboot_media_dir: "+media+"\n"+rest)
}

// manualNodesYAML declares only operator-managed nodes, so no BMC is dialed
// and discovery and the dry run stay in process.
const manualNodesYAML = `environment:
  id: 4
platform:
  domain: example.com
  internal_domain: internal.example.com
  tenant_id: tenant-1
  environment: production
nodes:
  - hostname: cp-01
    role: control-plane
    macs: ["52:54:00:00:00:01"]
    interfaces:
      - name: eth0
        type: static
        ipv4-address: 192.0.2.140/24
        ipv4-gateway: 192.0.2.1
  - hostname: worker-01
    role: worker
    macs: ["52:54:00:00:00:02"]
`

func TestRunDiscover_ManualNodes(t *testing.T) {
	path := writeDeployerConfig(t, manualNodesYAML)

	var runErr error
	out := captureStdout(t, func() { runErr = runDiscover(path, nil) })
	require.NoError(t, runErr)

	assert.Contains(t, out, "Discovered Nodes (2)")
	assert.Regexp(t, `cp-01\s+control-plane\s+52:54:00:00:00:01\s+manual`, out)
	assert.Regexp(t, `worker-01\s+worker\s+52:54:00:00:00:02\s+manual`, out)
}

// A control plane's trust anchor is captured only from its static address,
// so discovery refuses a control plane that declares none.
func TestRunDiscover_ControlPlaneWithoutStaticAddress(t *testing.T) {
	path := writeDeployerConfig(t, `environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp-01
    role: control-plane
    macs: ["52:54:00:00:00:01"]
`)

	err := runDiscover(path, nil)
	var discoveryErr ErrPXEDiscoveryFailed
	require.ErrorAs(t, err, &discoveryErr)
	var staticErr bootstrap.ControlPlaneStaticIPRequiredError
	require.ErrorAs(t, err, &staticErr)
	assert.Equal(t, "cp-01", staticErr.Hostname)

	err = runStatus(path, nil)
	require.ErrorAs(t, err, &discoveryErr, "status discovers before it probes")

	out := captureStdout(t, func() { err = runBootstrap(path, nil, false) })
	var runErr ErrPXERunFailed
	require.ErrorAs(t, err, &runErr, "a run stops in its discovery phase")
	require.ErrorAs(t, err, &staticErr)
	assert.Contains(t, out, "Phase:     discovery", "the partial result names the phase that failed")
}

func TestRunDiscover_InvalidConfig(t *testing.T) {
	path := writeTestConfig(t, "nodes: [")
	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, runDiscover(path, nil), &loadErr)
	assert.ErrorAs(t, runBootstrapDryRun(path, nil), &loadErr)
	assert.ErrorAs(t, runStatus(path, nil), &loadErr)
}

func TestRunBootstrapDryRun_ManualNodes(t *testing.T) {
	path := writeDeployerConfig(t, manualNodesYAML)

	var runErr error
	out := captureStdout(t, func() { runErr = runBootstrapDryRun(path, nil) })
	require.NoError(t, runErr)

	assert.Contains(t, out, "Dry Run Result")
	assert.Contains(t, out, "Config:     valid")
	assert.Contains(t, out, "Phase 0: Discover MACs from 0 BMC-managed nodes")
	assert.Contains(t, out, "Phase 3: PXE boot 1 control-plane node(s)")
	assert.Contains(t, out, "Phase 5: PXE boot 1 remaining nodes (0 gateway, 1 worker)")
	assert.Regexp(t, `worker-01\s+worker\s+\s+\s+n/a\s+52:54:00:00:00:02`, out, "a manual node has no BMC to reach")
}

func TestPrintBootstrapResult(t *testing.T) {
	out := captureStdout(t, func() {
		printBootstrapResult(&bootstrap.BootstrapResult{
			Phase:             "workers",
			Duration:          90 * time.Second,
			SwitchConfigured:  true,
			ControlPlaneReady: true,
			Nodes: []bootstrap.NodeResult{
				{Hostname: "cp-01", Role: "control-plane", MACs: []string{"52:54:00:00:00:01"}, BMCManaged: true, Status: "ready"},
				{Hostname: "worker-01", Role: "worker", Status: "failed", Error: "pxe timeout"},
			},
		})
	})

	assert.Contains(t, out, "Phase:     workers")
	assert.Contains(t, out, "Duration:  1m30s")
	assert.Contains(t, out, "Switch:    "+boolStatus(true))
	assert.Contains(t, out, "Workers:   "+boolStatus(false))
	assert.Regexp(t, `cp-01\s+control-plane\s+52:54:00:00:00:01\s+yes\s+ready`, out)
	assert.Regexp(t, `worker-01\s+worker\s+no\s+failed\s+pxe timeout`, out, "a failed node shows its error")

	assert.Empty(t, captureStdout(t, func() { printBootstrapResult(nil) }), "a run that produced no result prints nothing")
}

func TestPrintDryRunResult(t *testing.T) {
	out := captureStdout(t, func() {
		printDryRunResult(&bootstrap.DryRunResult{
			ConfigValid:       false,
			DeployerHost:      "deploy-01",
			SwitchConfigured:  true,
			SwitchVendor:      "dell-os10",
			ControlPlaneCount: 1,
			GatewayCount:      1,
			WorkerCount:       2,
			Nodes: []bootstrap.DryRunNodeResult{
				{Hostname: "cp-01", Role: "control-plane", BMCManaged: true, BMCReachable: true, BMCAddress: "10.0.0.10",
					BMCProtocol: "redfish", MACs: []string{"52:54:00:00:00:01"}, DiscoveredMACs: []string{"b8:ca:3a:00:00:01"},
					Status: "ok", ResolvedConfig: "hostname: cp-01\ndomain: example.com\n"},
				{Hostname: "edge-01", Role: "gateway", BMCManaged: true, BMCAddress: "10.0.0.11", BMCProtocol: "ipmi", Status: "unreachable"},
			},
			Warnings: []string{"switch credentials from environment"},
			Errors:   []string{"edge-01: BMC unreachable"},
		})
	})

	assert.Contains(t, out, "Config:     INVALID")
	assert.Contains(t, out, "Switch:     dell-os10")
	assert.Contains(t, out, "Phase 0: Discover MACs from 2 BMC-managed nodes")
	assert.Contains(t, out, "Phase 1: Configure switch (dell-os10)")
	assert.Contains(t, out, "Phase 5: PXE boot 3 remaining nodes (1 gateway, 2 worker)")
	assert.Regexp(t, `cp-01\s+control-plane\s+10.0.0.10\s+redfish\s+yes\s+b8:ca:3a:00:00:01\s+ok`, out,
		"a discovered MAC replaces the declared one")
	assert.Regexp(t, `edge-01\s+gateway\s+10.0.0.11\s+ipmi\s+no\s+unreachable`, out)
	assert.Contains(t, out, "--- cp-01 (control-plane) ---")
	assert.Contains(t, out, "  domain: example.com")
	assert.Contains(t, out, "    - switch credentials from environment")
	assert.Contains(t, out, "    - edge-01: BMC unreachable")

	assert.Empty(t, captureStdout(t, func() { printDryRunResult(nil) }))
}

func TestPrintDryRunResult_NoSwitchNoFindings(t *testing.T) {
	out := captureStdout(t, func() {
		printDryRunResult(&bootstrap.DryRunResult{ConfigValid: true, DeployerHost: "deploy-01"})
	})

	assert.Contains(t, out, "Switch:     not configured")
	assert.Contains(t, out, "Phase 1: Skip switch configuration (not configured)")
	assert.Contains(t, out, "Warnings: (none)")
	assert.Contains(t, out, "Errors: (none)")
	assert.NotContains(t, out, "Nodes:", "an empty plan has no node table")
	assert.NotContains(t, out, "Resolved Device Configs", "no node resolved a config")
}

func TestPrintDiscoveredNodes(t *testing.T) {
	out := captureStdout(t, func() {
		printDiscoveredNodes([]bootstrap.DiscoveredNode{
			{Hostname: "cp-01", Role: "control-plane", BMCManaged: true, DiscoveredMACs: []string{"b8:ca:3a:00:00:01"},
				SystemInfo: &bmc.SystemInfo{Manufacturer: "Dell", Product: "R650"}},
		})
	})

	assert.Contains(t, out, "Discovered Nodes (1)")
	assert.Regexp(t, `cp-01\s+control-plane\s+b8:ca:3a:00:00:01\s+bmc\s+Dell R650`, out)
}

func TestRunBootstrap_InvalidConfig(t *testing.T) {
	path := writeTestConfig(t, "nodes: [")
	err := runBootstrap(path, nil, false)
	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, err, &loadErr)
}

func TestCanonicalDirect(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	caPEM := directTestCertPEM(t, true)
	require.NoError(t, os.WriteFile(bundle, caPEM, 0o600))

	run := func(args ...string) (string, error) {
		cmd := newCanonicalDirectCmd(nil)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}

	out, err := run("--bundle", bundle)
	require.NoError(t, err)
	assert.Contains(t, out, fmt.Sprintf("Direct CA bundle accepted: %s (%d bytes, 1 CA certificates)", bundle, len(caPEM)))

	var msgErr *MessageError
	_, err = run()
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Error(), "--bundle is required")

	_, err = run("--bundle", dir)
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Error(), "is a directory")

	var wrapped *WrappedError
	_, err = run("--bundle", filepath.Join(dir, "missing.pem"))
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// Without deployer.container_image there is no container to deploy, so the
// orchestrator refuses before any SSH session is opened.
func TestRunDeploy_WithoutContainerImage(t *testing.T) {
	path := writeDeployerConfig(t, manualNodesYAML)

	err := runDeploy(path, nil)
	var deployErr ErrPXEDeployFailed
	require.ErrorAs(t, err, &deployErr)
	var notConfigured bootstrap.ErrDeployerNotConfigured
	assert.ErrorAs(t, err, &notConfigured)

	var loadErr ErrPXEConfigLoadFailed
	assert.ErrorAs(t, runDeploy(writeTestConfig(t, "nodes: ["), nil), &loadErr)
}

func TestNodeTrustConfig(t *testing.T) {
	assert.Nil(t, nodeTrustConfig(&bootstrap.BootstrapConfig{
		Nodes: []bootstrap.NodeConfig{{Hostname: "cp-01"}},
	}), "no node pins a BMC strategy, so the resolver defaults apply")

	cfg := nodeTrustConfig(&bootstrap.BootstrapConfig{
		Nodes: []bootstrap.NodeConfig{
			{Hostname: "cp-01", BMCTrust: []trust.Strategy{trust.StrategyDANE, trust.StrategySPKI}},
			{Hostname: "cp-02", BMCTrust: []trust.Strategy{trust.StrategySPKI, trust.StrategyTOFU}},
		},
	})
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.BMC)
	assert.Equal(t, []trust.Strategy{trust.StrategyDANE, trust.StrategySPKI, trust.StrategyTOFU}, cfg.BMC.Strategies,
		"strategies keep first-seen order without duplicates")
}

// The deploy and status commands hand --config and the common flags to their
// run functions; an unloadable config surfaces through cobra unchanged.
func TestDeployAndStatusCommands_PassConfig(t *testing.T) {
	path := writeTestConfig(t, "nodes: [")
	for _, newCmd := range []func(func() *cli.CommonFlags) *cobra.Command{newDeployCommand, newStatusCommand} {
		cmd := newCmd(defaultGetFlags())
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--config", path})
		var loadErr ErrPXEConfigLoadFailed
		assert.ErrorAs(t, cmd.Execute(), &loadErr, cmd.Use)
	}
}
