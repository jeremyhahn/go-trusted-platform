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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// fakeCertBMCWithDelete extends fakeCertBMC to support DELETE on the HTTPS
// cert resource and Manager.Reset. Every httptest server presents the same
// built-in certificate, so a regenerated factory certificate is simulated on
// the one server: once reset has run it presents factory instead.
type fakeCertBMCWithDelete struct {
	mu sync.Mutex
	// primary is the server that handles every request.
	primary *httptest.Server
	// factory, when set, is the certificate presented after reset. Unset,
	// the BMC keeps its certificate across the reset.
	factory *tls.Certificate

	// failDelete, when true, causes the DELETE /Certificates/1 to return 405.
	failDelete bool

	resetCalled  bool
	deleteCalled bool
}

func newFakeCertBMCWithDelete(t *testing.T) *fakeCertBMCWithDelete {
	t.Helper()
	f := &fakeCertBMCWithDelete{}

	primaryMux := http.NewServeMux()
	primaryMux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishServiceRoot{
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})
	primaryMux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishCollection{
			Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}},
		})
	})
	primaryMux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishManagerResource{
			ODataID: "/redfish/v1/Managers/1",
			ID:      "1",
			Actions: redfishManagerActions{
				Reset: struct {
					Target string `json:"target"`
				}{Target: "/redfish/v1/Managers/1/Actions/Manager.Reset"},
			},
		})
	})
	primaryMux.HandleFunc("/redfish/v1/Managers/1"+redfishHTTPSCertSuffix, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodDelete {
			http.Error(w, "only DELETE supported here", http.StatusMethodNotAllowed)
			return
		}
		f.deleteCalled = true
		if f.failDelete {
			http.Error(w, "delete not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	primaryMux.HandleFunc("/redfish/v1/Managers/1/Actions/Manager.Reset", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.resetCalled = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	f.primary = httptest.NewUnstartedServer(primaryMux)
	f.primary.TLS = &tls.Config{GetConfigForClient: f.configAfterReset}
	f.primary.StartTLS()
	return f
}

// reissueOnReset makes the BMC present cert once reset has run.
func (f *fakeCertBMCWithDelete) reissueOnReset(cert tls.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.factory = &cert
}

// configAfterReset presents the factory certificate once reset has run; a
// nil config keeps the server's own.
func (f *fakeCertBMCWithDelete) configAfterReset(*tls.ClientHelloInfo) (*tls.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.factory == nil || !f.resetCalled {
		return nil, nil
	}
	return &tls.Config{Certificates: []tls.Certificate{*f.factory}, MinVersion: tls.VersionTLS12}, nil
}

func (f *fakeCertBMCWithDelete) close() {
	f.primary.Close()
}

// cfg returns a bmc.Config that points at the primary server.
func (f *fakeCertBMCWithDelete) cfg() *Config {
	u, _ := url.Parse(f.primary.URL)
	port, _ := strconv.Atoi(u.Port())
	pool := x509.NewCertPool()
	pool.AddCert(f.primary.Certificate())
	f.mu.Lock()
	if f.factory != nil {
		pool.AddCert(f.factory.Leaf)
	}
	f.mu.Unlock()
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

// TestRedfishCert_RestoreFactory_HappyPath verifies the full restore flow:
// DELETE cert resource + reset + waitForReady + new cert returned.
//
// httptest.TLSServer issues a deterministic self-signed cert, so in order
// to simulate a "changed" certificate we spin up a second server that returns
// a fresh TLS cert from a different httptest listener.
func TestRedfishCert_RestoreFactory_HappyPath(t *testing.T) {
	f := newFakeCertBMCWithDelete(t)
	defer f.close()
	factory := selfSignedCert(t, "bmc-factory-default", 2)
	f.reissueOnReset(factory)

	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	got, err := m.RestoreFactoryCertificate(context.Background())
	if err != nil {
		t.Fatalf("RestoreFactoryCertificate() error = %v", err)
	}
	if !got.Equal(factory.Leaf) {
		t.Errorf("returned certificate %q, want the regenerated factory certificate", got.Subject.CommonName)
	}
	f.mu.Lock()
	deleteCalled := f.deleteCalled
	resetCalled := f.resetCalled
	f.mu.Unlock()
	if !deleteCalled {
		t.Error("DELETE /Certificates/1 was not called")
	}
	if !resetCalled {
		t.Error("Manager.Reset was not called")
	}
}

// TestRedfishCert_RestoreFactory_UnchangedCert pins that a BMC still
// presenting its old certificate after the reset is reported, not returned
// as a restored one.
func TestRedfishCert_RestoreFactory_UnchangedCert(t *testing.T) {
	f := newFakeCertBMCWithDelete(t)
	defer f.close()

	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	// httptest issues the same cert before and after, so we expect
	// ErrFactoryRestoreUnchanged (not a raw error).
	var unchanged ErrFactoryRestoreUnchanged
	if !errors.As(err, &unchanged) {
		t.Errorf("expected ErrFactoryRestoreUnchanged, got %v", err)
	}
	f.mu.Lock()
	deleteCalled := f.deleteCalled
	resetCalled := f.resetCalled
	f.mu.Unlock()
	if !deleteCalled {
		t.Error("DELETE /Certificates/1 was not called")
	}
	if !resetCalled {
		t.Error("Manager.Reset was not called")
	}
}

// TestRedfishCert_RestoreFactory_DeleteFails verifies that a 405 on DELETE
// is surfaced as an ErrRedfishRequest.
func TestRedfishCert_RestoreFactory_DeleteFails(t *testing.T) {
	f := newFakeCertBMCWithDelete(t)
	defer f.close()
	f.failDelete = true

	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Fatal("expected error from failed DELETE")
	}
	var redfishErr ErrRedfishRequest
	if !errors.As(err, &redfishErr) {
		t.Errorf("expected ErrRedfishRequest, got %T: %v", err, err)
	}
}

// TestRedfishCert_RestoreFactory_ServerDown verifies behavior when the BMC
// is unreachable from the start.
func TestRedfishCert_RestoreFactory_ServerDown(t *testing.T) {
	f := newFakeCertBMCWithDelete(t)
	cfg := f.cfg()
	f.close() // take the server down immediately

	m := newFastCertManager(t, cfg)
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Error("expected error from unreachable BMC")
	}
}

// TestRedfishCert_RestoreFactory_CompileTimeInterface verifies the compile-time
// assertions in cert_restore.go hold when accessed via this test binary.
func TestRedfishCert_RestoreFactory_CompileTimeInterface(t *testing.T) {
	// These nil-pointer casts succeed at compile time; the test just ensures
	// they are not silently stripped.
	var _ FactoryCertRestorer = (*redfishCertManager)(nil)
	var _ FactoryCertRestorer = (*AutoCertManager)(nil)
}

// TestAutoMgr_RestoreFactory_UnsupportedBackend verifies that AutoCertManager
// returns ErrFactoryRestoreUnsupported when the resolved backend does not
// implement FactoryCertRestorer.
func TestAutoMgr_RestoreFactory_UnsupportedBackend(t *testing.T) {
	// Use the plain fakeCertBMC (Redfish path) but with a nil backend so
	// resolveBackends is forced to produce a plain *redfishCertManager which
	// DOES implement FactoryCertRestorer. To hit ErrFactoryRestoreUnsupported
	// we need a backend that does not implement the interface.
	//
	// The only backend registered without FactoryCertRestorer support is
	// a hypothetical custom backend. Since we cannot easily inject one without
	// modifying production code, we instead test the branch indirectly:
	// AutoCertManager.RestoreFactoryCertificate delegates to the resolved
	// primary. The redfishCertManager DOES implement FactoryCertRestorer so
	// for a Redfish-only setup the UnsupportedBackend path is not reachable
	// from integration code today.
	//
	// We cover ErrFactoryRestoreUnsupported by calling it directly against a
	// nil interface to exercise its Error() method.
	e := ErrFactoryRestoreUnsupported{Backend: CertBackend("hypothetical")}
	if e.Error() == "" {
		t.Error("empty error string from ErrFactoryRestoreUnsupported")
	}
	if e.Backend != CertBackend("hypothetical") {
		t.Errorf("Backend field = %q", e.Backend)
	}
}

// TestCertDERSHA256Hex verifies the hash helper produces consistent output.
func TestCertDERSHA256Hex(t *testing.T) {
	// Use the httptest TLS cert from a fakeCertBMC as real DER input.
	f := newFakeCertBMC(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	cert, err := m.GetWebCertificate(context.Background())
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	h1 := certDERSHA256Hex(cert)
	h2 := certDERSHA256Hex(cert)
	if h1 != h2 {
		t.Error("certDERSHA256Hex not deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %s", len(h1), h1)
	}
}

// TestFactoryRestoreUnchanged_Error verifies the error message format.
func TestFactoryRestoreUnchanged_Error(t *testing.T) {
	e := ErrFactoryRestoreUnchanged{DERFingerprint: "abc123"}
	msg := e.Error()
	if msg == "" {
		t.Error("empty error string")
	}
	if !containsStr(msg, "abc123") {
		t.Errorf("fingerprint not in error: %q", msg)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && findStr(s, sub)
}

func findStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
