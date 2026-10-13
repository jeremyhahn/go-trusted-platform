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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container/containertest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// validBootstrapYAML is a minimal valid bootstrap config for testing.
const validBootstrapYAML = `deployer:
  host: 192.168.1.1
  user: admin
  ssh_key: /tmp/test-key
  container_runtime: docker
  netboot_media_dir: netboot-media
environment:
  id: 4
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
// writeTestConfig writes content as bootstrap.yaml beside a netboot media
// build (netboot-media/: the x86_64 set) for its deployer to stage.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, containertest.WriteNetbootBuild(filepath.Join(dir, "netboot-media"), false, false, container.MediaSetX86_64))
	path := filepath.Join(dir, "bootstrap.yaml")
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)
	return path
}

// newTestCAPool mints an in-memory ECDSA P-256 CA and returns a *x509.CertPool
// containing its certificate. This produces an honest tls.Config — no
// InsecureSkipVerify required — for tests where no actual TLS handshake occurs
// (the connection fails at the network level before TLS is attempted).
func newTestCAPool(t *testing.T) *x509.CertPool {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-bootstrap-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool
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
  host: ""
environment:
  id: 4
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

func TestCheckNodeHealth_UnreachableHost(t *testing.T) {
	// Provide a real RootCAs pool from a minted test CA rather than
	// InsecureSkipVerify. The connection targets 192.0.2.1 (TEST-NET),
	// which is guaranteed unreachable, so no TLS handshake ever occurs —
	// the transport fails at TCP dial and the config is never exercised.
	// The pool makes the tls.Config honest without skipping verification.
	client := &http.Client{
		Timeout: 100 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "test-node",
				RootCAs:    newTestCAPool(t),
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	ports := (&bootstrap.BootstrapConfig{}).HealthProbePorts()
	result := checkNodeHealth(t.Context(), client, "192.0.2.1", ports) // TEST-NET, unreachable
	assert.Equal(t, "unreachable", result)
}

// newTestTLSHealthServer serves the health endpoint over TLS with a leaf
// issued for serverName only — no IP SAN, no hostname — and returns the
// loopback address to dial plus the pool that trusts the issuing CA. The
// health endpoint answers 200 unless the Host header names an address in
// unhealthyHosts, which answers 503; listening on every loopback address
// lets one server stand in for several candidates.
func newTestTLSHealthServer(t *testing.T, serverName string, unhealthyHosts ...string) (address string, pool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-status-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != healthEndpointPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		reqHost, _, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			reqHost = r.Host
		}
		for _, h := range unhealthyHosts {
			if h == reqHost {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		// A JSON body, because the probe grades on the body as well as the
		// status code (#235): an empty 200 is what a proxy or a static file
		// server returns, and is no longer accepted as a platform answer.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"payload":{"os":{"hostname":"test-node"}}}`))
	}))
	if len(unhealthyHosts) > 0 {
		require.NoError(t, srv.Listener.Close())
		l, lerr := net.Listen("tcp", "0.0.0.0:0")
		require.NoError(t, lerr)
		srv.Listener = l
	}
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return srv.Listener.Addr().String(), pool
}

// pointHealthPortAt splits a listener address into the host to probe and the
// candidate ports that reach it.
//
// The probe tries several ports because the webservice port depends on the
// node's role (#235); a test listener has exactly one, so it is the only
// candidate — otherwise every probe would spend three dial timeouts before
// reaching it.
func pointHealthPortAt(t *testing.T, address string) (host string, ports []int) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)
	return host, []int{p}
}

func TestCheckNodeHealth_ControlPlaneVerifiedByTLSNameNotAddress(t *testing.T) {
	address, pool := newTestTLSHealthServer(t, "cp.example.test")
	host, ports := pointHealthPortAt(t, address)

	// The status command reaches the control plane by address with the
	// control plane's TLS name; the certificate names only that.
	named := newHealthClient(pool, "cp.example.test")
	assert.Equal(t, "healthy", checkNodeHealth(t.Context(), named, host, ports))

	// With the pool but no expected name — what the command did before —
	// the same healthy node is reported unreachable.
	unnamed := newHealthClient(pool, "")
	assert.Equal(t, "unreachable", checkNodeHealth(t.Context(), unnamed, host, ports))
}

func TestCheckNodeHealthAny_FirstAnsweringAddressWins(t *testing.T) {
	// One listener on every loopback address: 127.0.0.1 answers 503,
	// 127.0.0.2 answers 200, so the candidate order decides the verdict.
	address, pool := newTestTLSHealthServer(t, "cp.example.test", "127.0.0.1")
	_, ports := pointHealthPortAt(t, address)
	named := newHealthClient(pool, "cp.example.test")

	// An unresolvable hostname first (a control plane's hostname commonly
	// does not resolve during bootstrap) is skipped; the first address
	// that answers is the verdict, even when it says unhealthy.
	assert.Equal(t, "unhealthy", checkNodeHealthAny(t.Context(), named, []string{"cp-none.invalid", "127.0.0.1", "127.0.0.2"}, ports))
	assert.Equal(t, "healthy", checkNodeHealthAny(t.Context(), named, []string{"127.0.0.2", "127.0.0.1"}, ports))
	assert.Equal(t, "unreachable", checkNodeHealthAny(t.Context(), named, []string{"cp-none.invalid"}, ports))
	assert.Equal(t, "unreachable", checkNodeHealthAny(t.Context(), named, nil, ports))
	assert.Equal(t, "unknown", checkNodeHealthAny(t.Context(), nil, []string{"127.0.0.2"}, ports))
}

func TestStatusProber_ControlPlaneUsesNameAndCandidates(t *testing.T) {
	address, pool := newTestTLSHealthServer(t, "cp.example.test")
	host, ports := pointHealthPortAt(t, address)
	prober := statusProber{
		nodeClient:  newHealthClient(pool, ""),
		cpClient:    newHealthClient(pool, "cp.example.test"),
		cpAddresses: func(*bootstrap.DiscoveredNode) []string { return []string{host} },
		ports:       ports,
	}
	// The node's hostname is not what the certificate names and does not
	// resolve; only the control-plane path — candidates plus the CP TLS
	// name — can reach and verify it.
	node := &bootstrap.DiscoveredNode{NodeConfig: bootstrap.NodeConfig{Hostname: "cp-01.invalid", Role: bootstrap.RoleControlPlane}}
	assert.Equal(t, "healthy", prober.health(t.Context(), node))

	// The same node as a worker is probed by hostname with no expected
	// name, and is unreachable — proving the role selects the path.
	node.Role = bootstrap.RoleWorker
	assert.Equal(t, "unreachable", prober.health(t.Context(), node))

	// Without a control-plane client (TLS name unknown) the verdict is
	// unknown rather than a probe over an unverified connection.
	node.Role = bootstrap.RoleControlPlane
	prober.cpClient = nil
	assert.Equal(t, "unknown", prober.health(t.Context(), node))
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

func TestErrDeployerCreationFailed(t *testing.T) {
	err := ErrDeployerCreationFailed{Host: "deploy-host", Cause: assert.AnError}
	assert.Contains(t, err.Error(), "deploy-host")
	assert.Contains(t, err.Error(), "failed to create the deployer")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

// =============================================================================
// Deploy / Teardown Tests
// =============================================================================

// TestRunDeployAndTeardown_NeedADeployer: both commands go through the
// orchestrator, which refuses with no deployer to drive (no
// container_image) before touching the network.
func TestRunDeployAndTeardown_NeedADeployer(t *testing.T) {
	path := writeTestConfig(t, validBootstrapYAML)
	var none bootstrap.ErrDeployerNotConfigured

	err := runDeploy(path, nil)
	var deployErr ErrPXEDeployFailed
	require.ErrorAs(t, err, &deployErr)
	assert.ErrorAs(t, err, &none)

	err = runTeardown(path, nil)
	var teardownErr ErrPXETeardownFailed
	require.ErrorAs(t, err, &teardownErr)
	assert.ErrorAs(t, err, &none)
}

// TestRunDeploy_InvalidConfig: a config that does not validate never
// reaches the orchestrator.
func TestRunDeploy_InvalidConfig(t *testing.T) {
	var invalid ErrPXEConfigValidationFailed
	assert.ErrorAs(t, runDeploy(writeTestConfig(t, "deployer:\n  host: \"\"\n"), nil), &invalid)
	assert.ErrorAs(t, runTeardown(writeTestConfig(t, "deployer:\n  host: \"\"\n"), nil), &invalid)
}

// =============================================================================
// Long Description Tests for PXE Commands
// =============================================================================

func TestPXECommandLongDescriptions(t *testing.T) {
	getFlags := defaultGetFlags()

	tests := []struct {
		name     string
		cmd      func() string
		contains string
	}{
		{
			name:     "run",
			cmd:      func() string { return newRunCommand(getFlags).Long },
			contains: "Phase 0",
		},
		{
			name:     "discover",
			cmd:      func() string { return newDiscoverCommand(getFlags).Long },
			contains: "Phase 0",
		},
		{
			name:     "deploy",
			cmd:      func() string { return newDeployCommand(getFlags).Long },
			contains: "Phase 2",
		},
		{
			name:     "teardown",
			cmd:      func() string { return newTeardownCommand(getFlags).Long },
			contains: "bootstrap container",
		},
		{
			name:     "status",
			cmd:      func() string { return newStatusCommand(getFlags).Long },
			contains: "health",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			long := tt.cmd()
			assert.NotEmpty(t, long)
			assert.Contains(t, long, tt.contains)
		})
	}
}
