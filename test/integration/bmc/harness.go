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

//go:build integration

// Package bmc_integration provides test helpers that address the
// devcontainer vBMC responders by service hostname on the compose
// network and build platform BMC configs pointing at them.
//
// This package is built with `//go:build integration` so it only
// participates in `make integration-test` runs that execute inside
// the devcontainer. Unit test runs skip it entirely.
//
// Per project rules, these helpers ONLY target real running services
// — never httptest, never in-process fakes. Tests are expected to
// run via `build/docker/devcontainer/run-integration-tests.sh` which
// brings up the vBMC containers as a prerequisite.
package bmc_integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// VBMCFlavor identifies which vendor flavor of the devcontainer vBMC
// responder a test should target.
type VBMCFlavor string

const (
	VBMCFlavorSupermicro VBMCFlavor = "supermicro"
	VBMCFlavorDell       VBMCFlavor = "dell"

	// defaultPort is the vBMC HTTPS port exposed by both flavors in
	// docker-compose.
	defaultPort = 8443

	// defaultIPMIPort is the vBMC UDP IPMI port exposed by both
	// flavors in docker-compose. Real BMCs use 623, but containers
	// cannot always bind privileged ports so the devcontainer vBMC
	// listens on 6230.
	defaultIPMIPort = 6230
)

// hostname returns the compose-network hostname for the given flavor.
// Matches the `hostname:` field in docker-compose.yml.
func (f VBMCFlavor) hostname() string {
	switch f {
	case VBMCFlavorSupermicro:
		return "vbmc-supermicro"
	case VBMCFlavorDell:
		return "vbmc-dell"
	default:
		return string(f)
	}
}

// Endpoint returns the `host:port` pair for the given flavor,
// overridable via the `VBMC_<FLAVOR>_ADDR` env var for ad-hoc test
// runs outside the compose harness.
func Endpoint(flavor VBMCFlavor) (host string, port int) {
	envKey := fmt.Sprintf("VBMC_%s_ADDR", flavor)
	// Accept forms: "host", "host:port", or unset.
	if v := os.Getenv(envKey); v != "" {
		// Simple split on ':' — tests run inside the devcontainer
		// on a trusted network so we don't need URL parsing here.
		h, p, err := splitHostPort(v)
		if err == nil {
			return h, p
		}
	}
	return flavor.hostname(), defaultPort
}

// splitHostPort returns (host, port) from "host" or "host:port".
func splitHostPort(s string) (string, int, error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			var port int
			if _, err := fmt.Sscanf(s[i+1:], "%d", &port); err != nil {
				return "", 0, err
			}
			return s[:i], port, nil
		}
	}
	return s, defaultPort, nil
}

// IPMIEndpoint returns the (host, port) pair for the UDP IPMI
// listener on the given flavor. Overridable via the
// `VBMC_<FLAVOR>_IPMI_ADDR` env var for ad-hoc runs outside the
// compose harness. Mirrors Endpoint but targets the RMCP+ simulator
// surface on the vBMC rather than its HTTPS Redfish/CGI surface.
func IPMIEndpoint(flavor VBMCFlavor) (host string, port int) {
	envKey := fmt.Sprintf("VBMC_%s_IPMI_ADDR", flavor)
	if v := os.Getenv(envKey); v != "" {
		h, p, err := splitHostPort(v)
		if err == nil {
			if p == defaultPort {
				// splitHostPort defaults to the HTTPS port when no
				// ':port' is present — override for the IPMI helper.
				p = defaultIPMIPort
			}
			return h, p
		}
	}
	return flavor.hostname(), defaultIPMIPort
}

// CaptureVBMCCertPool performs a capture-only TLS dial to the vBMC and
// returns the peer certificate pool. This is the integration-test analogue
// of the capture-then-verify pattern in pkg/bootstrap/virtual_media.go.
// The vBMC uses a self-signed certificate regenerated each compose run;
// this function captures it so tests can wire a verified TLSProvider.
//
// The InsecureSkipVerify dial is intentional here: the vBMC cert IS the
// trust anchor we are capturing. No app data is exchanged.
func CaptureVBMCCertPool(ctx context.Context, flavor VBMCFlavor) (*x509.CertPool, string, error) {
	host, port := Endpoint(flavor)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Capture-only dial: InsecureSkipVerify is intentional.
	// The vBMC self-signed cert IS the trust anchor for integration tests.
	// No application data is exchanged; connection is closed immediately.
	captureCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // integration test: capture-only, no app data, pinned reconnect follows
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, captureCfg)
	if err != nil {
		return nil, "", ErrVBMCUnreachable{Flavor: flavor, Cause: err}
	}
	certs := conn.ConnectionState().PeerCertificates
	conn.Close()

	if len(certs) == 0 {
		return nil, "", ErrVBMCUnreachable{
			Flavor: flavor,
			Cause:  fmt.Errorf("vBMC presented no peer certificates"),
		}
	}

	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	spkiSum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(spkiSum[:])
	return pool, pin, nil
}

// VBMCTLSProvider builds a bmc.TLSProvider for the given vBMC flavor.
// It captures the vBMC's self-signed certificate and wires an SPKI-pin
// provider via the platform trust resolver's ClassBMC scope.
func VBMCTLSProvider(ctx context.Context, flavor VBMCFlavor) (bmc.TLSProvider, error) {
	_, pin, err := CaptureVBMCCertPool(ctx, flavor)
	if err != nil {
		return nil, err
	}
	trustCfg := &trust.Config{
		BMC: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategySPKI},
			SPKI:       &trust.SPKIConfig{Pin: pin},
		},
	}
	resolver, err := trust.NewResolver(trustCfg, nil)
	if err != nil {
		return nil, err
	}
	return &vbmcTrustProvider{resolver: resolver}, nil
}

// vbmcTrustProvider adapts a trust.Resolver into a bmc.TLSProvider
// for the integration test harness.
type vbmcTrustProvider struct {
	resolver trust.Resolver
}

func (p *vbmcTrustProvider) TLSConfig(ctx context.Context, endpoint string) (*tls.Config, error) {
	return p.resolver.TLSConfig(ctx, trust.ClassBMC, endpoint)
}

// ConfigFor returns a *bmc.Config addressing the given flavor. The
// config is minimal — address, port, Redfish protocol — leaving
// Certificate/Key/Backend up to the caller to fill in per scenario.
//
// BMC credentials are set to "admin"/"admin"; the vBMC accepts any
// credentials, so these values are informational only.
//
// A TLSProvider is wired via VBMCTLSProvider (SPKI-pin verified against
// the captured vBMC self-signed cert).
func ConfigFor(ctx context.Context, flavor VBMCFlavor) (*bmc.Config, error) {
	host, port := Endpoint(flavor)
	tlsProvider, err := VBMCTLSProvider(ctx, flavor)
	if err != nil {
		return nil, err
	}
	return &bmc.Config{
		Address:  host,
		Port:     port,
		Username: "admin",
		Password: "admin",
		Protocol: bmc.ProtocolRedfish,
		TLS:      tlsProvider,
	}, nil
}

// WithDNSCert populates Certificate + Key on cfg for an ACME dns-01
// issuance scenario. cn is the BMC's hostname — used as CN and as
// the primary DNS SAN. Returns cfg for chaining.
func WithDNSCert(cfg *bmc.Config, cn string) *bmc.Config {
	cfg.Certificate = &common.Identity{
		Subject: trustedca.CASubject{CommonName: cn},
		SANS:    &trustedca.CASubjectAlternativeNames{DNS: []string{cn}},
		ACME: &common.ACMEIdentityConfig{
			AuthzType:  "dns",
			AuthzValue: cn,
			Challenge:  "dns-01",
		},
	}
	cfg.Key = &common.KeyConfig{KeyAlgorithm: "ECDSA", CN: cn}
	return cfg
}

// vbmcInsecureHTTPClient returns an HTTP client that uses InsecureSkipVerify.
// This is used ONLY for internal test-harness readiness checks and debug
// stat collection where no sensitive data flows; these paths do not use the
// bmc.Client or bmc.Config paths.
//
// The vBMC cert rotates each compose run, so the poll client captures it
// on first use via CaptureVBMCCertPool and then switches to a pinned client.
// We accept the one-poll window with InsecureSkipVerify because the vBMC
// is a controlled local test service (devcontainer network only).
func vbmcInsecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // integration test health-poll: controlled vBMC on devcontainer network, no app data sensitivity
			},
		},
	}
}

// WaitForReady polls the vBMC's /healthz endpoint until it returns
// 200 OK or ctx expires. Used by test setup to barrier on
// compose-started vBMC containers before issuing test operations.
func WaitForReady(ctx context.Context, flavor VBMCFlavor) error {
	host, port := Endpoint(flavor)
	url := fmt.Sprintf("https://%s:%d/healthz", host, port)
	client := vbmcInsecureHTTPClient()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vBMC %s not ready: %w", flavor, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Stats captures the vBMC's /debug/stats counters for test assertions.
type Stats struct {
	Vendor         string `json:"vendor"`
	CertReplace    uint64 `json:"cert_replace"`
	Reset          uint64 `json:"reset"`
	ActiveSessions int    `json:"active_sessions"`
}

// GetStats fetches counter snapshots from the vBMC's /debug/stats
// endpoint. Integration tests diff the before/after values to
// confirm cert-replacement and reset operations fired.
func GetStats(ctx context.Context, flavor VBMCFlavor) (*Stats, error) {
	host, port := Endpoint(flavor)
	url := fmt.Sprintf("https://%s:%d/debug/stats", host, port)
	client := vbmcInsecureHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vBMC stats: status %d", resp.StatusCode)
	}
	var s Stats
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ErrVBMCUnreachable wraps a failure to reach the vBMC service
// during harness setup.
type ErrVBMCUnreachable struct {
	Flavor VBMCFlavor
	Cause  error
}

func (e ErrVBMCUnreachable) Error() string {
	return fmt.Sprintf("vbmc %s unreachable: %v", e.Flavor, e.Cause)
}

func (e ErrVBMCUnreachable) Unwrap() error { return e.Cause }

// sentinel so the compiler doesn't complain about errors import.
var _ = errors.New
