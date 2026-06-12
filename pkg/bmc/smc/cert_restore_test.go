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

// Hardware validation status
//
// SSL_DEFAULT via op.cgi has been tested only against httptest fakes.
// See pkg/bmc/smc/cert_restore.go for details.

package smc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// fakeATENWithRestore extends fakeATEN's handleOp to also support the
// SSL_DEFAULT opcode needed by RestoreFactoryCertificate. A separate fake
// type avoids modifying the existing fakeATEN harness used by the replace tests.
type fakeATENWithRestore struct {
	mu sync.Mutex

	server          *httptest.Server
	sid             string
	useCookieHeader bool

	defaultSSLCalled bool
	failDefaultSSL   int  // non-zero HTTP status code to return for SSL_DEFAULT
	failLogin        int  // non-zero HTTP status code to return for login
	resetCalled      bool
	failReset        int
	loggedOut        bool
}

func newFakeATENWithRestore(t *testing.T) *fakeATENWithRestore {
	t.Helper()
	f := &fakeATENWithRestore{
		sid:             "RESTORE01",
		useCookieHeader: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(cgiLogin, f.handleLogin)
	mux.HandleFunc(cgiOp, f.handleOp)
	mux.HandleFunc(cgiBMCReset, f.handleReset)
	mux.HandleFunc(cgiLogout, f.handleLogout)
	f.server = httptest.NewTLSServer(mux)
	return f
}

func (f *fakeATENWithRestore) close() { f.server.Close() }

func (f *fakeATENWithRestore) cfg() *bmc.Config {
	u, _ := url.Parse(f.server.URL)
	port, _ := strconv.Atoi(u.Port())
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	return &bmc.Config{
		Address:  u.Hostname(),
		Port:     port,
		Username: "ADMIN",
		Password: "ADMIN",
		Protocol: bmc.ProtocolRedfish,
		TLS: &fakeBMCTLSProvider{cfg: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}},
	}
}

func (f *fakeATENWithRestore) handleLogin(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLogin > 0 {
		w.WriteHeader(f.failLogin)
		return
	}
	if f.useCookieHeader {
		http.SetCookie(w, &http.Cookie{Name: cookieSID, Value: f.sid, Path: "/"})
	}
	_, _ = io.WriteString(w, "ok")
}

func (f *fakeATENWithRestore) handleOp(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(string(body), "op="+opSSLDefault):
		f.defaultSSLCalled = true
		if f.failDefaultSSL > 0 {
			w.WriteHeader(f.failDefaultSSL)
			_, _ = io.WriteString(w, "default ssl rejected")
			return
		}
		w.WriteHeader(http.StatusOK)
	case strings.Contains(string(body), "op="+opSSLValidate):
		// SSL_VALIDATE: not needed for restore flow but tolerate it.
		_, _ = io.WriteString(w, `{"VALID":"1"}`)
	default:
		http.Error(w, "unsupported op", http.StatusBadRequest)
	}
}

func (f *fakeATENWithRestore) handleReset(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failReset > 0 {
		w.WriteHeader(f.failReset)
		return
	}
	f.resetCalled = true
	w.WriteHeader(http.StatusOK)
}

func (f *fakeATENWithRestore) handleLogout(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedOut = true
	w.WriteHeader(http.StatusOK)
}

func newFastRestoreMgr(t *testing.T, cfg *bmc.Config) *CertManager {
	t.Helper()
	m, err := NewCertManager(cfg, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	m.resetWaitCheck = 5 * time.Millisecond
	m.resetMaxWait = 200 * time.Millisecond
	return m
}

// TestSMCRestore_HappyPath verifies the full SSL_DEFAULT restore flow. The
// httptest server issues the same TLS cert before and after reset, so
// ErrRestoreUnchanged is the expected terminal error (the cert did not
// change). All intermediate steps (defaultSSL, reset, logout) are verified
// to have executed.
func TestSMCRestore_HappyPath(t *testing.T) {
	f := newFakeATENWithRestore(t)
	defer f.close()

	m := newFastRestoreMgr(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	// httptest issues the same TLS cert throughout, so ErrRestoreUnchanged
	// is expected — the flow completed but the fingerprint matched.
	var unchanged ErrRestoreUnchanged
	if !errors.As(err, &unchanged) {
		t.Errorf("expected ErrRestoreUnchanged, got %v", err)
	}

	f.mu.Lock()
	defaultSSLCalled := f.defaultSSLCalled
	resetCalled := f.resetCalled
	loggedOut := f.loggedOut
	f.mu.Unlock()

	if !defaultSSLCalled {
		t.Error("op.cgi SSL_DEFAULT was not called")
	}
	if !resetCalled {
		t.Error("BMC_reset.cgi was not called")
	}
	if !loggedOut {
		t.Error("logout.cgi was not called")
	}
}

// TestSMCRestore_DefaultSSLFails verifies ErrDefaultSSLFailed when the BMC
// returns a non-2xx on the SSL_DEFAULT op.
func TestSMCRestore_DefaultSSLFails(t *testing.T) {
	f := newFakeATENWithRestore(t)
	defer f.close()
	f.failDefaultSSL = http.StatusInternalServerError

	m := newFastRestoreMgr(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Fatal("expected error from failed SSL_DEFAULT")
	}
	var want ErrDefaultSSLFailed
	if !errors.As(err, &want) {
		t.Errorf("expected ErrDefaultSSLFailed, got %T: %v", err, err)
	}
}

// TestSMCRestore_LoginFails verifies that a login failure is surfaced before
// the SSL_DEFAULT op is attempted.
func TestSMCRestore_LoginFails(t *testing.T) {
	f := newFakeATENWithRestore(t)
	defer f.close()
	f.failLogin = http.StatusUnauthorized

	m := newFastRestoreMgr(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Fatal("expected error from failed login")
	}
	var want ErrLoginFailed
	if !errors.As(err, &want) {
		t.Errorf("expected ErrLoginFailed, got %T: %v", err, err)
	}

	f.mu.Lock()
	called := f.defaultSSLCalled
	f.mu.Unlock()
	if called {
		t.Error("SSL_DEFAULT should not be called when login fails")
	}
}

// TestSMCRestore_ResetFails verifies that a BMC reset failure after SSL_DEFAULT
// surfaces as ErrResetFailed.
func TestSMCRestore_ResetFails(t *testing.T) {
	f := newFakeATENWithRestore(t)
	defer f.close()
	f.failReset = http.StatusInternalServerError

	m := newFastRestoreMgr(t, f.cfg())
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Fatal("expected error from failed reset")
	}
	var want ErrResetFailed
	if !errors.As(err, &want) {
		t.Errorf("expected ErrResetFailed, got %T: %v", err, err)
	}
}

// TestSMCRestore_ServerDown verifies behavior when the BMC is unreachable.
func TestSMCRestore_ServerDown(t *testing.T) {
	f := newFakeATENWithRestore(t)
	cfg := f.cfg()
	f.close()

	m := newFastRestoreMgr(t, cfg)
	defer m.Close()

	_, err := m.RestoreFactoryCertificate(context.Background())
	if err == nil {
		t.Error("expected error from unreachable server")
	}
}

// TestSMCDefaultSSL_BadURL verifies that a malformed address surfaces as
// ErrTransport when building the SSL_DEFAULT request.
func TestSMCDefaultSSL_BadURL(t *testing.T) {
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00", Port: 443},
		httpClient: &http.Client{},
	}
	err := m.defaultSSL(context.Background(), "sid")
	var want ErrTransport
	if !errors.As(err, &want) {
		t.Errorf("expected ErrTransport, got %T: %v", err, err)
	}
}

// TestErrDefaultSSLFailed_Message verifies the error message format.
func TestErrDefaultSSLFailed_Message(t *testing.T) {
	e := ErrDefaultSSLFailed{StatusCode: 500, Body: "internal error"}
	msg := e.Error()
	if msg == "" {
		t.Error("empty error message")
	}
	if !strings.Contains(msg, "500") {
		t.Errorf("status code not in error: %q", msg)
	}
}

// TestErrRestoreUnchanged_Message verifies the error message format.
func TestErrRestoreUnchanged_Message(t *testing.T) {
	e := ErrRestoreUnchanged{DERFingerprint: "deadbeef"}
	msg := e.Error()
	if msg == "" {
		t.Error("empty error message")
	}
	if !strings.Contains(msg, "deadbeef") {
		t.Errorf("fingerprint not in error: %q", msg)
	}
}

// TestSMCCertDERSHA256Hex verifies the local hash helper.
func TestSMCCertDERSHA256Hex(t *testing.T) {
	f := newFakeATENWithRestore(t)
	defer f.close()
	m := newFastRestoreMgr(t, f.cfg())
	defer m.Close()

	cert, err := m.GetWebCertificate(context.Background())
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	h := certDERSHA256Hex(cert)
	if len(h) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %s", len(h), h)
	}
	// Idempotent.
	if certDERSHA256Hex(cert) != h {
		t.Error("certDERSHA256Hex not deterministic")
	}
}

// TestSMCRestore_CompileTimeInterface ensures CertManager implements
// bmc.FactoryCertRestorer at compile time.
func TestSMCRestore_CompileTimeInterface(t *testing.T) {
	var _ bmc.FactoryCertRestorer = (*CertManager)(nil)
}
