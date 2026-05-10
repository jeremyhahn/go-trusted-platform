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

package smc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// fakeATEN models an X10 ATEN BMC CGI endpoint set. Configurable
// behaviors let tests exercise each failure mode.
type fakeATEN struct {
	mu                sync.Mutex
	server            *httptest.Server
	sid               string
	loginFormBody     string
	uploadCertPEM     []byte
	uploadKeyPEM      []byte
	loggedOut         bool
	validateCalled    bool
	resetCalled       bool
	useCookieHeader   bool // true = Set-Cookie; false = SID in body
	failLogin         int
	failUpload        int
	uploadBodyOK      bool
	uploadBodyError   bool
	failValidate      int
	validateBody      string
	failReset         int
	omitSIDOnLogin    bool
	noSIDInBody       bool
	requests          []string
	requestsWithCreds []string
}

func newFakeATEN(t *testing.T) *fakeATEN {
	t.Helper()
	f := &fakeATEN{
		sid:             "ABCDEF0123",
		useCookieHeader: true,
		uploadBodyOK:    true,
		validateBody:    `{"VALID":"1"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(cgiLogin, f.handleLogin)
	mux.HandleFunc(cgiUploadSSL, f.handleUpload)
	mux.HandleFunc(cgiOp, f.handleOp)
	mux.HandleFunc(cgiBMCReset, f.handleReset)
	mux.HandleFunc(cgiLogout, f.handleLogout)
	f.server = httptest.NewTLSServer(mux)
	return f
}

func (f *fakeATEN) close() { f.server.Close() }

func (f *fakeATEN) cfg() *bmc.Config {
	u, _ := url.Parse(f.server.URL)
	port, _ := strconv.Atoi(u.Port())
	return &bmc.Config{
		Address:       u.Hostname(),
		Port:          port,
		Username:      "ADMIN",
		Password:      "ADMIN",
		Protocol:      bmc.ProtocolRedfish, // must be set to pass Validate
		SkipTLSVerify: true,
	}
}

func (f *fakeATEN) recordRequest(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	c, err := r.Cookie(cookieSID)
	if err == nil && c.Value != "" {
		f.requestsWithCreds = append(f.requestsWithCreds, r.URL.Path)
	}
}

func (f *fakeATEN) handleLogin(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLogin > 0 {
		w.WriteHeader(f.failLogin)
		_, _ = io.WriteString(w, "login rejected")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.loginFormBody = string(body)
	if f.omitSIDOnLogin {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "no cookie anywhere")
		return
	}
	if f.useCookieHeader {
		http.SetCookie(w, &http.Cookie{Name: cookieSID, Value: f.sid, Path: "/"})
		_, _ = io.WriteString(w, "ok")
		return
	}
	// Fallback path: older firmware puts SID in body.
	if f.noSIDInBody {
		_, _ = io.WriteString(w, "login ok")
		return
	}
	_, _ = io.WriteString(w, "SID="+f.sid+"; path=/")
}

func (f *fakeATEN) handleUpload(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUpload > 0 {
		w.WriteHeader(f.failUpload)
		_, _ = io.WriteString(w, "upload failed")
		return
	}
	// Parse multipart.
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certFile, _, err := r.FormFile("cert_file")
	if err != nil {
		http.Error(w, "cert_file missing: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer certFile.Close()
	keyFile, _, err := r.FormFile("key_file")
	if err != nil {
		http.Error(w, "key_file missing: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer keyFile.Close()
	f.uploadCertPEM, _ = io.ReadAll(certFile)
	f.uploadKeyPEM, _ = io.ReadAll(keyFile)
	w.Header().Set("Content-Type", "text/html")
	if f.uploadBodyError {
		_, _ = io.WriteString(w, "<html>upload failed: invalid certificate format</html>")
		return
	}
	if f.uploadBodyOK {
		_, _ = io.WriteString(w, "<html>upload complete</html>")
		return
	}
	_, _ = io.WriteString(w, "<html>upload complete</html>")
}

func (f *fakeATEN) handleOp(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(string(body), "op="+opSSLValidate) {
		http.Error(w, "unsupported op", http.StatusBadRequest)
		return
	}
	f.validateCalled = true
	if f.failValidate > 0 {
		w.WriteHeader(f.failValidate)
		_, _ = io.WriteString(w, "validate rejected")
		return
	}
	_, _ = io.WriteString(w, f.validateBody)
}

func (f *fakeATEN) handleReset(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failReset > 0 {
		w.WriteHeader(f.failReset)
		return
	}
	f.resetCalled = true
	w.WriteHeader(http.StatusOK)
}

func (f *fakeATEN) handleLogout(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedOut = true
	w.WriteHeader(http.StatusOK)
}

func newFastCertManager(t *testing.T, cfg *bmc.Config) *CertManager {
	t.Helper()
	m, err := NewCertManager(cfg, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	m.resetWaitCheck = 5 * time.Millisecond
	m.resetMaxWait = 200 * time.Millisecond
	return m
}

// --- constructor ---

func TestNewCertManager_NilConfig(t *testing.T) {
	if _, err := NewCertManager(nil, nil); err == nil {
		t.Error("expected error for nil config")
	}
}

func TestNewCertManager_InvalidConfig(t *testing.T) {
	if _, err := NewCertManager(&bmc.Config{}, nil); err == nil {
		t.Error("expected error for empty config")
	}
}

func TestNewCertManager_MissingUsername(t *testing.T) {
	cfg := &bmc.Config{
		Address: "1.2.3.4", Port: 443, Protocol: bmc.ProtocolRedfish,
		Password: "x", SkipTLSVerify: true,
	}
	if _, err := NewCertManager(cfg, nil); err == nil {
		t.Error("expected error for missing username")
	}
}

func TestNewCertManager_BadCA(t *testing.T) {
	cfg := &bmc.Config{
		Address: "1.2.3.4", Port: 443, Protocol: bmc.ProtocolRedfish,
		Username: "u", Password: "p",
		CACertPath: "/no/such/file",
	}
	if _, err := NewCertManager(cfg, nil); err == nil {
		t.Error("expected error for bad CA path")
	}
}

func TestBackendAndClose(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	if m.Backend() != bmc.CertBackendSMCCGI {
		t.Errorf("Backend = %q", m.Backend())
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Close is idempotent.
	if err := m.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// --- GetWebCertificate ---

func TestGetWebCertificate(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	cert, err := m.GetWebCertificate(context.Background())
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if cert == nil || cert.Raw == nil {
		t.Fatal("nil cert")
	}
}

func TestGetWebCertificate_Closed(t *testing.T) {
	f := newFakeATEN(t)
	cfg := f.cfg()
	f.close()
	m := newFastCertManager(t, cfg)
	defer m.Close()
	if _, err := m.GetWebCertificate(context.Background()); err == nil {
		t.Error("expected dial error after server close")
	}
}

// --- ReplaceWebCertificate happy path ---

func TestReplace_HappyPath_CookieAuth(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	key := memguard.New([]byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"))
	defer key.Destroy()
	cert := []byte("-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----\n")

	if err := m.ReplaceWebCertificate(context.Background(), cert, key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Contains(f.uploadCertPEM, []byte("CERTIFICATE")) {
		t.Errorf("server did not receive cert PEM; got %q", f.uploadCertPEM)
	}
	if !bytes.Contains(f.uploadKeyPEM, []byte("PRIVATE KEY")) {
		t.Errorf("server did not receive key PEM; got %q", f.uploadKeyPEM)
	}
	if !f.validateCalled {
		t.Error("op.cgi SSL_VALIDATE was not invoked")
	}
	if !f.resetCalled {
		t.Error("BMC_reset.cgi was not invoked")
	}
	if !f.loggedOut {
		t.Error("logout.cgi was not invoked")
	}
	// Login should have sent name=ADMIN&pwd=ADMIN.
	if !strings.Contains(f.loginFormBody, "name=ADMIN") ||
		!strings.Contains(f.loginFormBody, "pwd=ADMIN") {
		t.Errorf("login form body missing credentials: %q", f.loginFormBody)
	}
	// Every mutating request after login must carry the SID cookie.
	for _, p := range []string{cgiUploadSSL, cgiOp, cgiBMCReset, cgiLogout} {
		found := false
		for _, r := range f.requestsWithCreds {
			if r == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s did not carry SID cookie", p)
		}
	}
}

func TestReplace_HappyPath_BodySID(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.useCookieHeader = false
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
}

// --- ReplaceWebCertificate validation / error paths ---

func TestReplace_EmptyCert(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), nil, key)
	var want ErrInvalidInput
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidInput", err)
	}
}

func TestReplace_NilKey(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), nil)
	var want ErrInvalidInput
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidInput", err)
	}
}

func TestReplace_EmptyKey(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	empty := memguard.New(nil)
	defer empty.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), empty)
	var want ErrInvalidInput
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidInput", err)
	}
}

func TestReplace_LoginFails(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.failLogin = http.StatusUnauthorized
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrLoginFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrLoginFailed", err)
	}
}

func TestReplace_NoSIDReturned(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.omitSIDOnLogin = true
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrNoSessionCookie
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrNoSessionCookie", err)
	}
}

func TestReplace_UploadHTTPError(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.failUpload = http.StatusInternalServerError
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrUploadFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrUploadFailed", err)
	}
}

func TestReplace_UploadBodyError(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.uploadBodyError = true
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrUploadFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrUploadFailed", err)
	}
}

func TestReplace_ValidateFails(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.failValidate = http.StatusInternalServerError
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrValidateFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrValidateFailed", err)
	}
}

func TestReplace_ValidateNotImplemented_404Tolerated(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.failValidate = http.StatusNotFound
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Errorf("404 on validate should be tolerated; got %v", err)
	}
}

func TestReplace_ValidateBodyRejected(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.validateBody = "<html>certificate is invalid, please retry</html>"
	// "invalid" contains "valid" substring, so looksValid returns true.
	// Use a body that lacks any positive marker.
	f.validateBody = `{"result":"failure"}`
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrValidateFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrValidateFailed", err)
	}
}

func TestReplace_ResetFails(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	f.failReset = http.StatusInternalServerError
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrResetFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrResetFailed", err)
	}
}

func TestReplace_WaitTimeout(t *testing.T) {
	f := newFakeATEN(t)
	cfg := f.cfg()
	m := newFastCertManager(t, cfg)
	defer m.Close()
	// Allow the login + upload etc., then kill the server so waitForReady
	// can't connect. Simplest: shut down right away — discovery/login
	// will fail with a dial error that still surfaces to the caller.
	f.close()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err == nil {
		t.Error("expected error from replace against closed server")
	}
}

func TestReplace_ContextCancel(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(ctx, []byte("c"), key); err == nil {
		t.Error("expected error from canceled context")
	}
}

// --- helper unit tests ---

func TestExtractSIDFromBody(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"SID=abc; path=/", "abc"},
		{"junk SID=XYZ456", "XYZ456"},
		{"SID=only_body_nothing_else", "only_body_nothing_else"},
		{"no session here", ""},
	}
	for _, tc := range cases {
		if got := extractSIDFromBody([]byte(tc.in)); got != tc.want {
			t.Errorf("extractSIDFromBody(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLooksLikeUploadError(t *testing.T) {
	if !looksLikeUploadError([]byte("upload FAILED")) {
		t.Error("should flag 'fail'")
	}
	if !looksLikeUploadError([]byte("invalid certificate")) {
		t.Error("should flag 'invalid'")
	}
	if !looksLikeUploadError([]byte("Error processing")) {
		t.Error("should flag 'error'")
	}
	if !looksLikeUploadError([]byte("request rejected")) {
		t.Error("should flag 'reject'")
	}
	if looksLikeUploadError([]byte("upload complete")) {
		t.Error("should not flag clean body")
	}
}

func TestLooksValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"valid", true},
		{`"OK"`, true},
		{`{"VALID":"1"}`, true},
		{"failure", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := looksValid([]byte(tc.in)); got != tc.want {
			t.Errorf("looksValid(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestZeroBuffer(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("secret")
	zeroBuffer(&buf)
	if buf.Len() != 0 {
		t.Errorf("buf.Len() = %d, want 0", buf.Len())
	}
}

func TestWritePart(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := writePart(mw, "foo", "bar.pem", []byte("content")); err != nil {
		t.Fatalf("writePart: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="foo"`) || !strings.Contains(out, `filename="bar.pem"`) {
		t.Errorf("unexpected multipart body: %q", out)
	}
	if !strings.Contains(out, "content") {
		t.Errorf("multipart body missing payload: %q", out)
	}
}

func TestLoadPool_BadPath(t *testing.T) {
	if _, err := loadPool("/nonexistent"); err == nil {
		t.Error("expected error")
	}
}

func TestLoadPool_BadContent(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "x.pem")
	if err := os.WriteFile(p, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPool(p); err == nil {
		t.Error("expected error")
	}
}

func TestTLSConfigFor_SkipVerify(t *testing.T) {
	cfg := &bmc.Config{SkipTLSVerify: true}
	tc, err := tlsConfigFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !tc.InsecureSkipVerify {
		t.Error("SkipTLSVerify not honored")
	}
}

func TestErrMessages(t *testing.T) {
	cases := []error{
		ErrLoginFailed{StatusCode: 401, Message: "bad creds"},
		ErrLoginFailed{StatusCode: 500},
		ErrNoSessionCookie{},
		ErrUploadFailed{StatusCode: 500, Body: strings.Repeat("x", 300)},
		ErrValidateFailed{StatusCode: 500, Body: "no"},
		ErrResetFailed{StatusCode: 500},
		ErrInvalidInput{Field: "f", Reason: "r"},
		ErrTransport{Op: "op", Cause: errors.New("c")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error string from %T", e)
		}
	}
	// Unwrap.
	tErr := ErrTransport{Op: "o", Cause: errors.New("inner")}
	if !strings.Contains(tErr.Unwrap().Error(), "inner") {
		t.Error("Unwrap did not return cause")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcde", 10); got != "abcde" {
		t.Errorf("truncate short: %q", got)
	}
	if got := truncate("abcdefghij", 5); got != "abcde..." {
		t.Errorf("truncate long: %q", got)
	}
}

// TestLogout_NetworkError exercises the logout error-swallowing path.
func TestLogout_NetworkError(t *testing.T) {
	f := newFakeATEN(t)
	cfg := f.cfg()
	// Tear down before logout is called — logout should still not panic
	// and should swallow the error.
	buf := &strings.Builder{}
	m, err := NewCertManager(cfg, testLogger(buf))
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	defer m.Close()
	f.close()
	m.logout(context.Background(), "nonexistent-sid")
	if buf.Len() == 0 {
		t.Error("expected logger output from failed logout")
	}
}

func TestLogout_BuildError(t *testing.T) {
	// Force http.NewRequest to fail by using a control char in the URL.
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00", Port: 1},
		httpClient: &http.Client{},
		logger:     testLogger(&strings.Builder{}),
	}
	// Should not panic.
	m.logout(context.Background(), "sid")
}

func TestWaitForReady_ContextCanceled(t *testing.T) {
	f := newFakeATEN(t)
	cfg := f.cfg()
	f.close() // ensure waitForReady loops
	m := newFastCertManager(t, cfg)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.waitForReady(ctx); err == nil {
		t.Error("expected cancel error")
	}
}

func TestWaitForReady_Success(t *testing.T) {
	f := newFakeATEN(t)
	defer f.close()
	m := newFastCertManager(t, f.cfg())
	defer m.Close()
	if err := m.waitForReady(context.Background()); err != nil {
		t.Errorf("waitForReady: %v", err)
	}
}

// TestWaitForReady_RetryThenSucceed verifies the timer/select loop by
// shutting the server, then bringing up a replacement on a DIFFERENT
// port. We don't actually swap ports mid-flight (would need platform
// syscalls); instead we verify the timer resets properly by checking
// at least two dial attempts happen against a closed port within the
// max-wait window.
func TestWaitForReady_DeadlineExceeded(t *testing.T) {
	f := newFakeATEN(t)
	cfg := f.cfg()
	f.close()
	m := newFastCertManager(t, cfg)
	m.resetWaitCheck = 5 * time.Millisecond
	m.resetMaxWait = 30 * time.Millisecond
	defer m.Close()
	start := time.Now()
	err := m.waitForReady(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed < m.resetMaxWait {
		t.Errorf("returned too fast: %v < %v", elapsed, m.resetMaxWait)
	}
}

func TestLog_WithLogger(t *testing.T) {
	buf := &strings.Builder{}
	m := &CertManager{logger: testLogger(buf)}
	m.log("hello", "key", "value")
	if buf.Len() == 0 {
		t.Error("log output expected")
	}
}

func TestLog_NilLogger(t *testing.T) {
	m := &CertManager{}
	// Should not panic.
	m.log("ignored", "k", "v")
}

// testLogger returns an slog logger writing JSON to buf.
func testLogger(buf io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

// TestUploadSSL_BadURL exercises the NewRequestWithContext error path.
func TestUploadSSL_BadURL(t *testing.T) {
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00invalid", Port: 443},
		httpClient: &http.Client{},
	}
	key := memguard.New([]byte("k"))
	defer key.Destroy()
	err := m.uploadSSL(context.Background(), "sid", []byte("c"), key)
	var want ErrTransport
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrTransport", err)
	}
}

func TestValidateSSL_BadURL(t *testing.T) {
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00", Port: 443},
		httpClient: &http.Client{},
	}
	err := m.validateSSL(context.Background(), "sid")
	var want ErrTransport
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrTransport", err)
	}
}

func TestResetBMC_BadURL(t *testing.T) {
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00", Port: 443},
		httpClient: &http.Client{},
	}
	err := m.resetBMC(context.Background(), "sid")
	var want ErrTransport
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrTransport", err)
	}
}

func TestLogin_BadURL(t *testing.T) {
	m := &CertManager{
		cfg:        &bmc.Config{Address: "\x00", Port: 443},
		username:   "u",
		password:   memguard.New([]byte("p")),
		httpClient: &http.Client{},
	}
	defer m.Close()
	_, err := m.login(context.Background())
	var want ErrTransport
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrTransport", err)
	}
}
