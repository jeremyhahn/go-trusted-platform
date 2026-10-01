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

// TestBMCTrustTOFUIsAcceptedAsEndpointPinning is the inverse of the old #83
// regression, and the inversion is the point.
//
// Under #83, `bmc_trust: [tofu]` was rejected because tofu was implemented
// purely as a CA-bundle FETCH: it discarded the caller's endpoint and
// fetched from scope.ServerURL, and a BMC serves Redfish rather than a
// bundle, so no ServerURL could make it work. go-xkms#139 (v0.12.0-alpha)
// added the endpoint-pinning TLS path whose changelog names this exact
// case, so the reason for the rejection is gone.
//
// tofu for a BMC is now first-contact SPKI pinning that PERSISTS the pin —
// strictly better than a bmc_spki_pin an operator must obtain out of band.
func TestBMCTrustTOFUIsAcceptedAsEndpointPinning(t *testing.T) {
	node := &NodeConfig{Hostname: "node-07", BMCTrust: []trust.Strategy{trust.StrategyTOFU}}

	_, err := bmcTLSConfigForErr(t, node, "127.0.0.1:443")

	// It must no longer be refused by the allowlist. It may still fail for
	// a real reason — there is no pin store wired in this fixture — but the
	// failure must not be "tofu is not allowed here".
	if err != nil {
		assert.NotContains(t, err.Error(), "invalid bmc_trust strategy",
			"tofu must no longer be rejected by the bmc allowlist")
		assert.NotContains(t, err.Error(), "cannot verify a BMC",
			"the #83 rationale is obsolete and must not be quoted at operators")
	}
}

// TestBMCTrustValidationNamesTheAllowedSet pins the operator-facing half.
// The message must enumerate what IS allowed, and it must derive that set
// rather than restate it: the previous version hard-coded
// "dane, spki, ca-file" plus a tofu-specific explanation, and go-xkms#139
// made both wrong at once.
func TestBMCTrustValidationNamesTheAllowedSet(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer: DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
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
			BMCTrust:    []trust.Strategy{"nonsense"},
		}},
	}

	err := cfg.Validate()
	require.Error(t, err, "an unknown bmc_trust strategy must be rejected at configuration time")

	var invalid ErrInvalidBMCTrust
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "nonsense", invalid.Strategy)

	msg := err.Error()
	assert.Contains(t, msg, "node-07")
	// Derived from pkg/trust, so this assertion follows the allowlist
	// instead of freezing a snapshot of it.
	for _, allowed := range trust.AllowedStrategiesForClass(trust.ClassBMC) {
		assert.Contains(t, msg, string(allowed),
			"the error must name every strategy the bmc class allows")
	}
}

// TestBMCTrustValidationAcceptsTOFU proves the config layer agrees with the
// trust layer, so bmc_trust: [tofu] does not validate in one and fail in the
// other — the split that produced #83.
func TestBMCTrustValidationAcceptsTOFU(t *testing.T) {
	cfg := &BootstrapConfig{
		Deployer: DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
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

	require.NoError(t, cfg.Validate(),
		"bmc_trust: [tofu] must validate since go-xkms#139 made tofu an endpoint verifier")
}

// TestTOFUOnTheTLSPathPinsTheEndpoint replaces
// TestTOFUIsABundleFetchNotEndpointPinning, whose premise go-xkms#139
// deliberately removed.
//
// The old test asserted that tofu pointed at a BMC-shaped endpoint — TLS,
// self-signed, serving no bundle — must FAIL, because tofu was a CA-bundle
// fetch. v0.12.0-alpha split the strategy the way dane and spki already
// were: the TLS path pins the endpoint's SPKI, the PEM path still fetches a
// bundle. That endpoint is now exactly what tofu is for.
//
// What still needs pinning is that the TLS path really verifies: it must
// complete a handshake against the endpoint it captured.
func TestTOFUOnTheTLSPathPinsTheEndpoint(t *testing.T) {
	bmc := newFakeBMC(t)

	cfg := &trust.Config{
		Bootstrap: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyTOFU},
			ServerURL:  "https://" + bmc.endpoint,
		},
	}
	resolver, err := trust.NewResolver(cfg, logging.NewFromSlog(quietTestLogger()),
		trust.WithTOFUPinStore(xkmsbootstrap.NewMemoryPinStore()))
	require.NoError(t, err)

	tlsCfg, err := resolver.TLSConfig(context.Background(), trust.ClassBootstrap, bmc.endpoint)
	require.NoError(t, err,
		"tofu on the TLS path verifies the endpoint itself and needs no CA bundle (go-xkms#139)")
	require.NotNil(t, tlsCfg)

	conn, err := tls.Dial("tcp", bmc.endpoint, tlsCfg)
	require.NoError(t, err, "the pinned TLS config must complete a handshake with the pinned endpoint")
	require.NoError(t, conn.Close())
}

// TestTOFURequiresAPinStore is the other half: with nowhere to persist the
// captured pin, tofu is not trust-on-first-use at all — it would accept
// whatever key it was shown, every time. Construction must refuse.
func TestTOFURequiresAPinStore(t *testing.T) {
	cfg := &trust.Config{
		Bootstrap: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyTOFU}},
	}
	_, err := trust.NewResolver(cfg, logging.NewFromSlog(quietTestLogger()))
	require.Error(t, err, "tofu without a pin store must not construct")
}
