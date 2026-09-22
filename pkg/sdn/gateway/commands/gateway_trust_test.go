// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// shippedGatewayTemplates are the platform templates that put a node in the
// gateway role. Their gatewayd sections are what firstboot projects into
// /etc/gatewayd/config.yaml (pkg/config.GatewaydConfigSections).
var shippedGatewayTemplates = []string{
	filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "supermicro", "x10", "gateway.yaml"),
	filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "dell", "r640", "gateway.yaml"),
}

// projectGatewaydSections reduces a platform template to the sections
// gatewayd decodes, exactly as firstboot's renderer does: the CLOSED
// whitelist in pkg/config, and nothing else. Reading the whole template
// instead would test a file gatewayd never sees.
func projectGatewaydSections(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "template must exist at %s", path)

	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))

	projected := map[string]any{}
	for _, section := range tpconfig.GatewaydConfigSections {
		if v, ok := doc[section]; ok && v != nil {
			projected[section] = v
		}
	}
	out, err := yaml.Marshal(projected)
	require.NoError(t, err)
	return out
}

// loadProjectedServeConfig decodes a projected gatewayd configuration the
// way `gatewayd serve` does.
func loadProjectedServeConfig(t *testing.T, projected []byte) *ServeConfig {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(projected)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	return cfg
}

// TestShippedGatewayTemplates_InternalClassResolvesInAGatewaydAssembly is
// the end-to-end guard for the internal trust class on a gateway node.
//
// The internal class authenticates gatewayd's session to the platform
// secret store, so it stands behind every kms:// and secret:// reference a
// gateway configuration carries — the BGP neighbour passwords, the TCP-AO
// master keys, the ipsec and wireguard keys. It permits exactly one
// strategy, platform-ca, and that strategy resolves through an injected
// CABundleProvider rather than from configuration.
//
// That is where this shipped combination went wrong: the templates set
// `internal: strategies: [platform-ca]`, gatewayd's assembly injected no
// provider (only platformd did, over its own CA), and so every resolution
// would have failed with ErrProviderCAUnavailable at the first dial. The
// assembly still succeeded and the secret resolver was still non-nil, so
// nothing short of a real resolution could catch it — a test that injects
// a provider by hand proves only that the resolver works when someone
// remembers to inject one.
//
// So this test injects nothing. It takes the shipped template through the
// firstboot projection and gatewayd's own decoder and assembly, and then
// completes a TLS handshake with the tls.Config the internal class
// produces. The only substitution is the bundle path: the template names
// /etc/gatewayd/cp-ca.pem, which belongs to a provisioned node, so the
// path is repointed at a test CA whose certificate actually signs the
// server dialled here, and gatewayd's --data-dir is a temp directory so
// the bmc class's tofu strategy has somewhere to keep its pins without
// writing to /var/lib/gatewayd.
func TestShippedGatewayTemplates_InternalClassResolvesInAGatewaydAssembly(t *testing.T) {
	for _, path := range shippedGatewayTemplates {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			cfg := loadProjectedServeConfig(t, projectGatewaydSections(t, path))

			require.NotNil(t, cfg.Trust, "a gateway template carries the trust: section")
			internal := cfg.Trust.Scope(trust.ClassInternal)
			require.NotNil(t, internal, "the secret store's session needs the internal class")
			assert.Contains(t, internal.Strategies, trust.StrategyPlatformCA)

			// The template must NAME a bundle source. gatewayd runs no CA,
			// so without this the class has nothing to verify against and
			// the whole secret store is a guard that cannot fire.
			require.NotEmpty(t, internal.CAFile,
				"the internal class names no platform CA bundle; every kms:// reference would fail at service start")

			// Stand up a TLS server whose leaf chains to a test CA, and put
			// that CA where the template says the platform bundle lives.
			bundle := testutil.GenerateTestTLSBundle(t)
			caFile := filepath.Join(t.TempDir(), filepath.Base(internal.CAFile))
			require.NoError(t, os.WriteFile(caFile, bundle.CACertPEM, 0o600))
			internal.CAFile = caFile
			endpoint := startInternalTLSServer(t, bundle)

			resolver, err := buildTrustResolver(cfg.Trust, t.TempDir(), testLogger())
			require.NoError(t, err, "the shipped trust section must assemble")
			require.NotNil(t, resolver)

			tlsCfg, err := resolver.TLSConfig(context.Background(), trust.ClassInternal, endpoint)
			require.NoError(t, err, "the internal class must resolve without a hand-injected provider")
			require.NotNil(t, tlsCfg.RootCAs, "platform-ca must produce a verification pool")
			assert.False(t, tlsCfg.InsecureSkipVerify, "the internal class always verifies")

			// The proof: a real handshake verified by the resolved config.
			conn, err := tls.Dial("tcp", endpoint, tlsCfg)
			require.NoError(t, err, "the resolved config must verify the platform-CA-signed peer")
			require.NoError(t, conn.Close())

			// And the consumer that motivated the class: the secret store
			// assembles against the same resolver instance.
			if cfg.Secrets != nil {
				host, err := buildHostRuntime(cfg, resolver, testLogger())
				require.NoError(t, err)
				require.NotNil(t, host.SecretResolver,
					"the secret-store section must produce a resolver")
			}
		})
	}
}

// startInternalTLSServer runs a TLS listener presenting the bundle's server
// certificate (no client auth — the class under test is server
// verification) and returns its host:port. The listener closes with the
// test.
func startInternalTLSServer(t *testing.T, bundle *testutil.TestTLSBundle) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{bundle.ServerCert},
		MinVersion:   tls.VersionTLS13,
	})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// The handshake is the assertion; the connection carries no
			// payload.
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

// TestBuildTrustResolver_PlatformCAWithoutBundleSourceIsRefused pins the
// other half of the contract: a configuration that asks for platform-ca on
// a node with no bundle source is refused AT ASSEMBLY, naming what is
// missing, instead of assembling into a daemon whose every internal-class
// resolution fails later with "no strategy succeeded".
func TestBuildTrustResolver_PlatformCAWithoutBundleSourceIsRefused(t *testing.T) {
	cfg := &trust.Config{
		Internal: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyPlatformCA}},
	}
	_, err := buildTrustResolver(cfg, t.TempDir(), testLogger())

	var missing *ErrPlatformCABundleSourceMissing
	require.ErrorAs(t, err, &missing, "got %v", err)
	assert.Contains(t, err.Error(), "ca-file")
}

// TestBuildTrustResolver_PlatformCAReadsTheBundleAtResolution proves the
// injected provider reads the file on each resolution rather than caching
// it at construction: a bundle delivered (or rotated) after gatewayd
// started takes effect without a restart, and a bundle not yet delivered
// reports the missing path.
func TestBuildTrustResolver_PlatformCAReadsTheBundleAtResolution(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "cp-ca.pem")
	cfg := &trust.Config{
		Internal: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyPlatformCA},
			CAFile:     caFile,
		},
	}
	resolver, err := buildTrustResolver(cfg, t.TempDir(), testLogger())
	require.NoError(t, err, "an undelivered bundle is a runtime condition, not a config error")

	ctx := context.Background()
	_, err = resolver.TLSConfig(ctx, trust.ClassInternal, "cp.example.internal:9443")
	require.Error(t, err, "no bundle on disk must fail closed")
	assert.Contains(t, err.Error(), caFile, "the failure must name the missing bundle")

	bundle := testutil.GenerateTestTLSBundle(t)
	require.NoError(t, os.WriteFile(caFile, bundle.CACertPEM, 0o600))

	tlsCfg, err := resolver.TLSConfig(ctx, trust.ClassInternal, "cp.example.internal:9443")
	require.NoError(t, err, "the delivered bundle must be picked up without a restart")
	require.NotNil(t, tlsCfg.RootCAs)
}

// TestBuildTrustResolver_NonInternalClassesNeedNoBundleSource keeps the
// refusal narrow: only the internal class resolves through the provider, so
// a bmc or default class must still assemble without one.
func TestBuildTrustResolver_NonInternalClassesNeedNoBundleSource(t *testing.T) {
	cfg := &trust.Config{
		BMC: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyCAFile}},
	}
	resolver, err := buildTrustResolver(cfg, t.TempDir(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, resolver)
}

// =============================================================================
// TOFU pin store
// =============================================================================

// TestNewGatewayTOFUPinStore_PersistsUnderDataDir is the point of the whole
// wiring: tofu pins a BMC's leaf on first contact and enforces it afterwards,
// which is only a guarantee if the pin outlives the process. An in-memory
// store would re-trust blindly after every restart. This asserts the store
// lands on disk under gatewayd's own state directory.
func TestNewGatewayTOFUPinStore_PersistsUnderDataDir(t *testing.T) {
	dataDir := t.TempDir()

	store, err := newGatewayTOFUPinStore(dataDir)
	require.NoError(t, err)
	require.NotNil(t, store)

	dir := filepath.Join(dataDir, gatewayTOFUPinDir)
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr, "the pin directory must exist on disk")
	require.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"a pin is not secret, but an attacker who can rewrite it redirects first-contact trust")
}

// TestNewGatewayTOFUPinStore_NoDataDir refuses rather than silently falling
// back to a store whose pins evaporate on restart.
func TestNewGatewayTOFUPinStore_NoDataDir(t *testing.T) {
	store, err := newGatewayTOFUPinStore("")
	require.Error(t, err)
	assert.Nil(t, store)

	var typed *ErrTOFUPinDirUnset
	assert.ErrorAs(t, err, &typed, "the caller must be able to tell this case apart")
}

// TestNewGatewayTOFUPinStore_UnusableDir covers the bad-input path: a plain
// file standing where the pin directory belongs.
func TestNewGatewayTOFUPinStore_UnusableDir(t *testing.T) {
	dataDir := t.TempDir()
	// Occupy the parent of the pin directory with a file so MkdirAll fails.
	blocker := filepath.Join(dataDir, "trust")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))

	store, err := newGatewayTOFUPinStore(dataDir)
	require.Error(t, err)
	assert.Nil(t, store)

	var typed *ErrTOFUPinDirUnusable
	require.ErrorAs(t, err, &typed)
	assert.Contains(t, typed.Error(), "TOFU pin store unusable")
}

// TestTofuScopes reports whether any class lists tofu, which is what decides
// if the store has to be built at all.
func TestTofuScopes(t *testing.T) {
	t.Run("bmc lists tofu", func(t *testing.T) {
		cfg := &trust.Config{BMC: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyDANE, trust.StrategyTOFU},
		}}
		assert.True(t, tofuScopes(cfg))
	})

	t.Run("no class lists tofu", func(t *testing.T) {
		cfg := &trust.Config{
			BMC:      &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyDANE}},
			Internal: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyPlatformCA}},
		}
		assert.False(t, tofuScopes(cfg))
	})
}
