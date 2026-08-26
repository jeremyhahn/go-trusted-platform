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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xkmsbootstrap "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBMC stands in for a Redfish endpoint: TLS with a self-signed,
// non-WebPKI certificate, and — like every real BMC — no CA-bundle
// endpoint of any kind.
type fakeBMC struct {
	endpoint string
	spkiPin  string
}

func newFakeBMC(t *testing.T) *fakeBMC {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bmc.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A BMC serves Redfish, not a CA bundle. Everything else 404s,
		// which is the whole point of this fixture.
		if r.URL.Path == "/redfish/v1/" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"@odata.id":"/redfish/v1/"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	return &fakeBMC{
		endpoint: net.JoinHostPort(host, port),
		spkiPin:  hex.EncodeToString(sum[:]),
	}
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// bmcTLSConfigFor builds the provider the orchestrator would build for a
// node and asks it to verify the given endpoint — the exact Redfish TLS
// path that `bootstrap discover` and `--dry-run` never reach, because
// discovery speaks IPMI on 623 while virtual media speaks Redfish on 443.
func bmcTLSConfigFor(t *testing.T, node *NodeConfig, endpoint string) (*tls.Config, error) {
	t.Helper()
	cfg := nodeBMCTrustConfig(node, &trust.Config{})
	provider, _, err := NewBootstrapBMCTLSProvider(cfg, quietTestLogger())
	require.NoError(t, err)
	require.NotNil(t, provider, "a node declaring bmc_trust must get a provider")
	return provider.TLSConfig(context.Background(), endpoint)
}

// bmcTLSConfigForErr is bmcTLSConfigFor for chains that are expected to be
// rejected, where provider construction itself may be what fails.
func bmcTLSConfigForErr(t *testing.T, node *NodeConfig, endpoint string) (*tls.Config, error) {
	t.Helper()
	cfg := nodeBMCTrustConfig(node, &trust.Config{})
	provider, _, err := NewBootstrapBMCTLSProvider(cfg, quietTestLogger())
	if err != nil {
		return nil, err
	}
	if provider == nil {
		t.Fatal("expected either a provider or an error")
	}
	return provider.TLSConfig(context.Background(), endpoint)
}

// TestBMCTrustSPKIPinVerifiesRedfishEndpoint pins the strategy that does
// work end to end: an SPKI pin verifies the BMC's own leaf, with no bundle
// server involved. This is the path `bmc_spki_pin` takes, and it is the
// documented workaround for the tofu defect.
func TestBMCTrustSPKIPinVerifiesRedfishEndpoint(t *testing.T) {
	bmc := newFakeBMC(t)
	node := &NodeConfig{
		Hostname:   "node-07",
		BMCSPKIPin: bmc.spkiPin,
	}

	tlsCfg, err := bmcTLSConfigFor(t, node, bmc.endpoint)
	require.NoError(t, err, "an SPKI pin must verify the BMC's own certificate")
	require.NotNil(t, tlsCfg)

	// Prove it actually completes a handshake against the BMC.
	conn, err := tls.Dial("tcp", bmc.endpoint, tlsCfg)
	require.NoError(t, err, "the pinned TLS config must complete a Redfish handshake")
	require.NoError(t, conn.Close())
}

// TestBMCTrustSPKIPinRejectsWrongCertificate is the negative half: a pin
// that does not match must fail the handshake rather than fall through to
// an unverified connection.
func TestBMCTrustSPKIPinRejectsWrongCertificate(t *testing.T) {
	bmc := newFakeBMC(t)
	other := newFakeBMC(t)
	node := &NodeConfig{Hostname: "node-07", BMCSPKIPin: other.spkiPin}

	tlsCfg, err := bmcTLSConfigFor(t, node, bmc.endpoint)
	require.NoError(t, err)

	conn, err := tls.Dial("tcp", bmc.endpoint, tlsCfg)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a mismatched SPKI pin must not verify the BMC certificate")
	}
}

// TestBMCTrustTOFURejected is the #83 regression.
//
// `bmc_trust: [tofu]` used to validate cleanly and then fail deep inside a
// run with "trust bootstrap: server URL required". The obvious reading is
// that the per-node scope simply forgot to carry a ServerURL — but TOFU in
// this stack is a CA-bundle FETCH pinned on first contact (`pemTOFU`
// discards the caller's endpoint entirely and fetches from
// `scope.ServerURL`), not endpoint pinning. A BMC serves Redfish and no CA
// bundle, so no ServerURL can make it work; see
// TestTOFUIsABundleFetchNotEndpointPinning for that proof.
//
// tofu is therefore no longer allowed for the BMC class, and the rejection
// happens at configuration time where it is actionable.
func TestBMCTrustTOFURejected(t *testing.T) {
	node := &NodeConfig{Hostname: "node-07", BMCTrust: []trust.Strategy{trust.StrategyTOFU}}

	_, err := bmcTLSConfigForErr(t, node, "127.0.0.1:443")

	require.Error(t, err, "tofu can never verify a BMC endpoint and must not be accepted")
	assert.NotContains(t, err.Error(), "server URL required",
		"the failure must no longer be the opaque late one from #83")
}

// TestBMCTrustValidationRejectsTOFUWithGuidance pins the operator-facing
// half: the config error must explain why and name the working alternative,
// because "invalid strategy" alone would send someone hunting for a typo in
// a value the documentation told them to use.
func TestBMCTrustValidationRejectsTOFUWithGuidance(t *testing.T) {
	// Drive the real validator, so this fails if bmc_trust validation ever
	// stops rejecting tofu — not just if the message text changes.
	cfg := &BootstrapConfig{
		Deployer: DeployerConfig{Host: "deploy.example.com"},
		Subnets: []installer.SubnetConfig{
			{Name: "provisioning", CIDR: "10.100.0.0/24", Role: installer.SubnetRoleProvisioning},
		},
		Platform: PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{{
			Hostname:    "node-07",
			Role:        RoleControlPlane,
			BMCAddress:  "10.200.0.10",
			BMCUser:     "admin",
			BMCPassword: "secret",
			BMCTrust:    []trust.Strategy{trust.StrategyTOFU},
		}},
	}

	err := cfg.Validate()
	require.Error(t, err, "bmc_trust: [tofu] must be rejected at configuration time")

	var invalid ErrInvalidBMCTrust
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, string(trust.StrategyTOFU), invalid.Strategy)

	msg := err.Error()
	assert.Contains(t, msg, "node-07")
	assert.Contains(t, msg, "bmc_spki_pin",
		"the error must name the strategy that does work")
	assert.Contains(t, msg, "CA bundle",
		"the error must say why tofu cannot verify a BMC")

	// An genuinely unknown value keeps the plain allowlist message.
	other := ErrInvalidBMCTrust{Hostname: "node-07", Strategy: "nonsense"}
	assert.Contains(t, other.Error(), "allowed: dane, spki, ca-file")
	assert.NotContains(t, other.Error(), "tofu",
		"tofu must not be advertised as allowed for bmc")
}

// TestTOFUIsABundleFetchNotEndpointPinning proves the finding that decided
// the fix, using the default class (where tofu remains legitimate, because
// a control plane really does serve a CA bundle).
//
// Pointed at a BMC-shaped endpoint — TLS, self-signed, no bundle path —
// tofu fails even though ServerURL is supplied. That is what rules out the
// "just fill in ServerURL from the endpoint" fix: the endpoint is not the
// problem, the absence of a CA bundle is.
func TestTOFUIsABundleFetchNotEndpointPinning(t *testing.T) {
	bmc := newFakeBMC(t)

	cfg := &trust.Config{
		Default: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyTOFU},
			ServerURL:  "https://" + bmc.endpoint,
		},
	}
	resolver, err := trust.NewResolver(cfg, logging.NewFromSlog(quietTestLogger()),
		trust.WithTOFUPinStore(xkmsbootstrap.NewMemoryPinStore()))
	require.NoError(t, err)

	_, err = resolver.TLSConfig(context.Background(), trust.ClassDefault, bmc.endpoint)

	require.Error(t, err,
		"tofu fetches a CA bundle; an endpoint that serves none cannot satisfy it")
	assert.NotContains(t, err.Error(), "server URL required",
		"the server URL was accepted — the bundle fetch itself is what fails, "+
			"which is why supplying one cannot fix bmc_trust: [tofu]")
}
