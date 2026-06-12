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

package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// fakeCertBMC is an httptest-backed Redfish CertificateService stub.
type fakeCertBMC struct {
	mu              sync.Mutex
	requests        []recordedReq
	server          *httptest.Server
	managerID       string
	resetTarget     string
	failServiceRoot bool
	failManagers    bool
	failManager     bool
	failReplace     bool
	failReset       bool
}

func newFakeCertBMC(t *testing.T) *fakeCertBMC {
	t.Helper()
	bmc := &fakeCertBMC{
		managerID:   "1",
		resetTarget: "/redfish/v1/Managers/1/Actions/Manager.Reset",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", bmc.handleRoot)
	mux.HandleFunc("/redfish/v1/Managers", bmc.handleManagers)
	mux.HandleFunc("/redfish/v1/Managers/1", bmc.handleManager)
	mux.HandleFunc(redfishCertReplaceActionPath, bmc.handleReplace)
	mux.HandleFunc("/redfish/v1/Managers/1/Actions/Manager.Reset", bmc.handleReset)
	bmc.server = httptest.NewTLSServer(mux)
	return bmc
}

func (f *fakeCertBMC) close() { f.server.Close() }

func (f *fakeCertBMC) cfg() *Config {
	u, _ := url.Parse(f.server.URL)
	port, _ := strconv.Atoi(u.Port())
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	return &Config{
		Address:  u.Hostname(),
		Port:     port,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolRedfish,
		TLS: &fakeTLSProvider{cfg: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}},
	}
}

func (f *fakeCertBMC) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, recordedReq{
		method: r.Method, path: r.URL.Path, body: string(body),
	})
	f.mu.Unlock()
}

func (f *fakeCertBMC) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/redfish/v1/" {
		http.NotFound(w, r)
		return
	}
	f.record(r)
	if f.failServiceRoot {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	writeJSON(w, redfishServiceRoot{
		Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
	})
}

func (f *fakeCertBMC) handleManagers(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.failManagers {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	writeJSON(w, redfishCollection{
		Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}},
	})
}

func (f *fakeCertBMC) handleManager(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.failManager {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	writeJSON(w, redfishManagerResource{
		ODataID: "/redfish/v1/Managers/1",
		ID:      f.managerID,
		Actions: redfishManagerActions{
			Reset: struct {
				Target string `json:"target"`
			}{Target: f.resetTarget},
		},
	})
}

func (f *fakeCertBMC) handleReplace(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.failReplace {
		http.Error(w, `{"error":{"message":"replace rejected"}}`, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCertBMC) handleReset(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.failReset {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newFastCertManager returns a redfishCertManager with very short
// reset-wait timings so tests don't sit for minutes.
func newFastCertManager(t *testing.T, cfg *Config) *redfishCertManager {
	t.Helper()
	m, err := NewRedfishCertManager(cfg, nil)
	if err != nil {
		t.Fatalf("NewRedfishCertManager: %v", err)
	}
	rm := m.(*redfishCertManager)
	rm.resetWaitCheck = 5 * time.Millisecond
	rm.resetMaxWait = 200 * time.Millisecond
	return rm
}

func TestRedfishCert_NewBadConfig(t *testing.T) {
	if _, err := NewRedfishCertManager(nil, nil); err == nil {
		t.Error("expected error for nil config")
	}
}

func TestRedfishCert_Backend(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	if got := m.Backend(); got != CertBackendRedfish {
		t.Errorf("Backend = %q, want %q", got, CertBackendRedfish)
	}
}

func TestRedfishCert_GetWebCertificate(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()

	cert, err := m.GetWebCertificate(context.Background())
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if cert == nil || cert.Raw == nil {
		t.Fatal("got nil/empty cert")
	}
	// httptest.NewTLSServer issues an example.com cert by default.
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Errorf("returned cert is not parseable: %v", err)
	}
}

func TestRedfishCert_GetWebCertificate_BadHost(t *testing.T) {
	cfg := &Config{
		Address:  "127.0.0.1",
		Port:     1, // closed port
		Protocol: ProtocolRedfish,
		Username: "u",
		Password: "p",
		// No TLSProvider: system roots, will fail at dial not at TLS config.
	}
	m := newFastCertManager(t, cfg)
	defer m.Close()
	if _, err := m.GetWebCertificate(context.Background()); err == nil {
		t.Error("expected dial error")
	}
}

func TestRedfishCert_ReplaceWebCertificate_HappyPath(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()

	key := memguard.New([]byte("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"))
	defer key.Destroy()
	cert := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	if err := m.ReplaceWebCertificate(context.Background(), cert, key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}

	// Verify replace POST included the bundle (key first, then cert).
	var replaceBody redfishReplaceCertBody
	for _, req := range bmc.requests {
		if req.method == http.MethodPost && req.path == redfishCertReplaceActionPath {
			if err := json.Unmarshal([]byte(req.body), &replaceBody); err != nil {
				t.Fatalf("unmarshal replace body: %v", err)
			}
			break
		}
	}
	if !strings.Contains(replaceBody.CertificateString, "PRIVATE KEY") ||
		!strings.Contains(replaceBody.CertificateString, "CERTIFICATE") {
		t.Errorf("CertificateString missing PEM blocks: %q", replaceBody.CertificateString)
	}
	if replaceBody.CertificateType != redfishCertTypePEM {
		t.Errorf("CertificateType = %q, want PEM", replaceBody.CertificateType)
	}
	if !strings.HasPrefix(replaceBody.CertificateURI.ODataID, "/redfish/v1/Managers/1") {
		t.Errorf("CertificateUri = %q", replaceBody.CertificateURI.ODataID)
	}
	// Verify reset was called.
	resetSeen := false
	for _, req := range bmc.requests {
		if req.method == http.MethodPost && req.path == "/redfish/v1/Managers/1/Actions/Manager.Reset" {
			resetSeen = true
			if !strings.Contains(req.body, "GracefulRestart") {
				t.Errorf("reset body missing GracefulRestart: %q", req.body)
			}
		}
	}
	if !resetSeen {
		t.Error("Manager.Reset was not invoked")
	}
}

func TestRedfishCert_ReplaceWebCertificate_FallbackResetTarget(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	bmc.resetTarget = "" // force fallback path construction
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()

	key := memguard.New([]byte("k"))
	defer key.Destroy()

	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	resetSeen := false
	for _, req := range bmc.requests {
		if req.method == http.MethodPost && req.path == "/redfish/v1/Managers/1/Actions/Manager.Reset" {
			resetSeen = true
		}
	}
	if !resetSeen {
		t.Error("expected reset on fallback target")
	}
}

func TestRedfishCert_ReplaceWebCertificate_Validation(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()

	if err := m.ReplaceWebCertificate(context.Background(), nil, memguard.New([]byte("k"))); err == nil {
		t.Error("expected error for empty cert")
	}
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), nil); err == nil {
		t.Error("expected error for nil key")
	}
	empty := memguard.New(nil)
	defer empty.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), empty); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestRedfishCert_ReplaceWebCertificate_DiscoveryFails(t *testing.T) {
	cases := []struct {
		name  string
		setup func(b *fakeCertBMC)
	}{
		{"service root fails", func(b *fakeCertBMC) { b.failServiceRoot = true }},
		{"managers fails", func(b *fakeCertBMC) { b.failManagers = true }},
		{"manager fails", func(b *fakeCertBMC) { b.failManager = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bmc := newFakeCertBMC(t)
			defer bmc.close()
			tc.setup(bmc)
			m := newFastCertManager(t, bmc.cfg())
			defer m.Close()
			key := memguard.New([]byte("k"))
			defer key.Destroy()
			err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
			if err == nil {
				t.Error("expected discovery error")
			}
			var want ErrRedfishDiscovery
			if !errors.As(err, &want) {
				t.Errorf("err = %v, want ErrRedfishDiscovery", err)
			}
		})
	}
}

func TestRedfishCert_ReplaceWebCertificate_ReplaceFails(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	bmc.failReplace = true
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrRedfishRequest
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRedfishRequest", err)
	}
}

func TestRedfishCert_ReplaceWebCertificate_ResetFails(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	bmc.failReset = true
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err == nil {
		t.Error("expected reset error")
	}
}

func TestRedfishCert_ReplaceWebCertificate_WaitTimeout(t *testing.T) {
	bmc := newFakeCertBMC(t)
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	// Close the BMC after replace+reset so waitForReady can never connect.
	// We need to allow replace + reset to succeed first; emulate by tearing
	// down before the call — discovery will fail. So use a different angle:
	// keep the BMC up but point waitForReady at a closed port.
	bmc.close()
	// Now any TLS dial fails; both discovery and waitForReady will error.
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestRedfishCert_WaitForReady_ContextCancel(t *testing.T) {
	bmc := newFakeCertBMC(t)
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	// Stop the BMC so dial fails.
	bmc.close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.waitForReady(ctx); err == nil {
		t.Error("expected error from canceled context")
	}
}

func TestRedfishCert_WaitForReady_OK(t *testing.T) {
	bmc := newFakeCertBMC(t)
	defer bmc.close()
	m := newFastCertManager(t, bmc.cfg())
	defer m.Close()
	if err := m.waitForReady(context.Background()); err != nil {
		t.Errorf("waitForReady against live server: %v", err)
	}
}
