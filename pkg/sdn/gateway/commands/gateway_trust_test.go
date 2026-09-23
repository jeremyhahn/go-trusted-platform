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

// TestShippedGatewayTemplates_PlatformAnchorResolvesInAGatewaydAssembly is
// the end-to-end guard for the platform anchor on a gateway node.
//
// The anchor authenticates gatewayd's session to the platform secret store,
// so it stands behind every kms:// and secret:// reference a gateway
// configuration carries — the BGP neighbour passwords, the TCP-AO master
// keys, the ipsec and wireguard keys — as well as the proxy's client CAs and
// the platformd grpc dial. gatewayd runs no CA, so its anchor is the platform
// CA bundle provisioning projects onto the node, named by `platform-ca-file:`.
//
// It replaced the `trust: internal:` class, whose platform-ca strategy
// needed an injected provider gatewayd first lacked entirely — assembly
// succeeded and the secret resolver was non-nil, yet every resolution would
// have failed at the first dial. So this test injects nothing. It takes the
// shipped template through the firstboot projection and gatewayd's own
// decoder and assembly, and completes a TLS handshake with the tls.Config
// the anchor produces. The only substitution is the bundle path: the
// template names /etc/gatewayd/cp-ca.pem, which belongs to a provisioned
// node, so the path is repointed at a test CA whose certificate actually
// signs the server dialled here.
func TestShippedGatewayTemplates_PlatformAnchorResolvesInAGatewaydAssembly(t *testing.T) {
	for _, path := range shippedGatewayTemplates {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			cfg := loadProjectedServeConfig(t, projectGatewaydSections(t, path))

			// The template must NAME the bundle, and firstboot must project
			// it. gatewayd runs no CA, so without this the secret store is a
			// guard that cannot fire.
			require.NotEmpty(t, cfg.PlatformCAFile,
				"the gateway template names no platform-ca-file; every kms:// reference would fail at service start")

			// Stand up a TLS server whose leaf chains to a test CA, and put
			// that CA where the template says the platform bundle lives.
			bundle := testutil.GenerateTestTLSBundle(t)
			cfg.PlatformCAFile = filepath.Join(t.TempDir(), filepath.Base(cfg.PlatformCAFile))
			require.NoError(t, os.WriteFile(cfg.PlatformCAFile, bundle.CACertPEM, 0o600))
			endpoint := startInternalTLSServer(t, bundle)

			anchor, err := buildPlatformAnchor(cfg)
			require.NoError(t, err)
			require.NotNil(t, anchor)

			tlsCfg, err := anchor.TLSConfig(context.Background())
			require.NoError(t, err, "the platform anchor must resolve from the projected bundle")
			require.NotNil(t, tlsCfg.RootCAs)
			assert.False(t, tlsCfg.InsecureSkipVerify, "the anchor always verifies")

			// The proof: a real handshake verified by the anchor.
			conn, err := tls.Dial("tcp", endpoint, tlsCfg)
			require.NoError(t, err, "the anchor must verify the platform-CA-signed peer")
			require.NoError(t, conn.Close())

			// The bmc class the template also carries must still assemble.
			if cfg.Trust != nil {
				_, err := buildTrustResolver(cfg.Trust, t.TempDir(), testLogger())
				require.NoError(t, err, "the shipped trust section must assemble")
			}

			// And the consumer that motivated it: the secret store assembles
			// against the same anchor.
			if cfg.Secrets != nil {
				host, err := buildHostRuntime(cfg, anchor, testLogger())
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

// TestBuildPlatformAnchor_ReadsTheBundleAtResolution proves gatewayd's anchor
// reads the file on each resolution rather than caching it at assembly: a
// bundle delivered (or rotated) after gatewayd started takes effect without
// a restart, and a bundle not yet delivered reports the missing path.
func TestBuildPlatformAnchor_ReadsTheBundleAtResolution(t *testing.T) {
	cfg := &ServeConfig{PlatformCAFile: filepath.Join(t.TempDir(), "cp-ca.pem")}
	anchor, err := buildPlatformAnchor(cfg)
	require.NoError(t, err, "an undelivered bundle is a runtime condition, not a config error")

	ctx := context.Background()
	_, err = anchor.TLSConfig(ctx)
	require.Error(t, err, "no bundle on disk must fail closed")
	assert.Contains(t, err.Error(), cfg.PlatformCAFile, "the failure must name the missing bundle")

	bundle := testutil.GenerateTestTLSBundle(t)
	require.NoError(t, os.WriteFile(cfg.PlatformCAFile, bundle.CACertPEM, 0o600))

	tlsCfg, err := anchor.TLSConfig(ctx)
	require.NoError(t, err, "the delivered bundle must be picked up without a restart")
	require.NotNil(t, tlsCfg.RootCAs)
}

// TestBuildPlatformAnchor_Unset covers a gateway with no platform-ca-file:
// no anchor, so every consumer that needs one refuses with its own error.
func TestBuildPlatformAnchor_Unset(t *testing.T) {
	for _, cfg := range []*ServeConfig{nil, {}} {
		anchor, err := buildPlatformAnchor(cfg)
		require.NoError(t, err)
		assert.Nil(t, anchor)
	}
}

// TestBuildTrustResolver_BMCNeedsNoPlatformBundle keeps the two apart: the
// bmc class verifies devices the platform did not issue and assembles with
// no platform CA bundle at all.
func TestBuildTrustResolver_BMCNeedsNoPlatformBundle(t *testing.T) {
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
			Bootstrap: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyDANE}},
			BMC:       &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategySPKI}},
		}
		assert.False(t, tofuScopes(cfg))
	})
}
