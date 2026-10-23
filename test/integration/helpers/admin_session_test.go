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

package helpers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeAdminChallenge   = "admin-challenge-1"
	fakeClaimToken       = "claim-token-1"
	fakePasskeyChallenge = "cGFzc2tleS1jaGFsbGVuZ2U"
	fakeSessionID        = "session-1"
)

// fakeClaimServer plays the webservice's admin claim and refresh routes.
// It verifies what the real routes verify that the client controls: the
// signed challenge against the admin certificate, the claim and session
// headers, and the registration's client data.
type fakeClaimServer struct {
	t         *testing.T
	adminCert *x509.Certificate

	mu             sync.Mutex
	claimed        bool
	challengeFails int
	refreshFails   int
	issued         string
	refreshed      string
	calls          map[string]int
	lastAuth       string
}

func newFakeClaimServer(t *testing.T, adminCert *x509.Certificate) (*fakeClaimServer, *httptest.Server) {
	t.Helper()
	fake := &fakeClaimServer{
		t:         t,
		adminCert: adminCert,
		issued:    fakeJWT(time.Now().Add(time.Hour)),
		refreshed: fakeJWT(time.Now().Add(2 * time.Hour)),
		calls:     map[string]int{},
	}
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	return fake, server
}

func (f *fakeClaimServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.URL.Path]++
	switch r.URL.Path {
	case adminStatusPath:
		f.writeEnvelope(w, map[string]any{"claimed": f.claimed})
	case adminChallengePath:
		if f.challengeFails != 0 {
			w.WriteHeader(f.challengeFails)
			f.write(w, []byte(`{"error":"claim refused"}`))
			return
		}
		f.writeEnvelope(w, map[string]any{"challenge": fakeAdminChallenge})
	case adminVerifyPath:
		f.verify(w, r)
	case adminBeginPath:
		if r.Header.Get(adminClaimTokenHeader) != fakeClaimToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.write(w, []byte(`{"publicKey":{"challenge":"`+fakePasskeyChallenge+`","rp":{"id":"localhost","name":"Platform"},`+
			`"pubKeyCredParams":[{"type":"public-key","alg":-7}]},"session_id":"`+fakeSessionID+`"}`))
	case adminFinishPath:
		f.finish(w, r)
	case adminRefreshPath:
		if f.refreshFails != 0 {
			w.WriteHeader(f.refreshFails)
			f.write(w, []byte(`{"error":"token expired"}`))
			return
		}
		f.writeEnvelope(w, f.refreshed)
	default:
		f.lastAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}
}

func (f *fakeClaimServer) verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge      string `json:"challenge"`
		CertificatePEM string `json:"certificate_pem"`
		Signature      []byte `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	digest := sha256.Sum256([]byte(req.Challenge))
	publicKey, ok := f.adminCert.PublicKey.(*ecdsa.PublicKey)
	if req.Challenge != fakeAdminChallenge || block == nil || !bytes.Equal(block.Bytes, f.adminCert.Raw) ||
		!ok || !ecdsa.VerifyASN1(publicKey, digest[:], req.Signature) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.writeEnvelope(w, map[string]any{"claim_token": fakeClaimToken})
}

func (f *fakeClaimServer) finish(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(adminClaimTokenHeader) != fakeClaimToken || r.Header.Get(adminSessionIDHeader) != fakeSessionID {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var registration attestationResponse
	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(registration.Response.ClientDataJSON)
	var data clientData
	if err == nil {
		err = json.Unmarshal(raw, &data)
	}
	if err != nil || data.Type != "webauthn.create" || data.Challenge != fakePasskeyChallenge ||
		data.Origin != "https://"+r.Host || registration.Response.AttestationObject == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.claimed = true
	f.writeEnvelope(w, map[string]any{"token": f.issued, "tenant_id": "system"})
}

func (f *fakeClaimServer) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

// configure changes the server's behaviour under its lock.
func (f *fakeClaimServer) configure(change func(*fakeClaimServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// authorization is the Authorization header of the last gated request.
func (f *fakeClaimServer) authorization() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth
}

// writeEnvelope answers 200 with payload in the response envelope.
func (f *fakeClaimServer) writeEnvelope(w http.ResponseWriter, payload any) {
	raw, err := json.Marshal(map[string]any{"code": 200, "success": true, "payload": payload})
	if err != nil {
		f.t.Errorf("marshal envelope: %v", err)
		return
	}
	f.write(w, raw)
}

func (f *fakeClaimServer) write(w http.ResponseWriter, body []byte) {
	if _, err := w.Write(body); err != nil {
		f.t.Errorf("write response: %v", err)
	}
}

// fakeJWT is an unsigned three-part token carrying only exp.
func fakeJWT(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(exp.Unix(), 10) + `}`))
	return "eyJhbGciOiJub25lIn0." + payload + ".c2ln"
}

// writeAdminBundle writes a self-signed ECDSA admin bundle into a new
// directory and returns it with the certificate.
func writeAdminBundle(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, adminCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, filepath.Join(dir, adminKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return dir, cert
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeSessionCache writes a cached session for baseURL.
func writeSessionCache(t *testing.T, path, baseURL, token string) {
	t.Helper()
	raw, err := json.Marshal(adminSessionCache{BaseURL: baseURL, Token: token})
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	writeFile(t, path, raw)
}

func TestAdminSessionClaimsOnceAndCaches(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	sessionFile := filepath.Join(t.TempDir(), "admin-session.json")
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	token, err := session.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if token != fake.issued {
		t.Fatalf("token = %q, want the finish step's session", token)
	}
	for _, path := range []string{adminStatusPath, adminChallengePath, adminVerifyPath, adminBeginPath, adminFinishPath} {
		if got := fake.count(path); got != 1 {
			t.Errorf("%s called %d times, want 1", path, got)
		}
	}

	if again, err := session.Bearer(context.Background()); err != nil || again != token {
		t.Errorf("second Bearer = %q, %v; want the held token", again, err)
	}
	if got := fake.count(adminStatusPath); got != 1 {
		t.Errorf("held token still called status %d times", got)
	}

	info, err := os.Stat(sessionFile)
	if err != nil {
		t.Fatalf("stat session file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("session file mode = %o, want 600", mode)
	}

	// A later suite process starts from the file and never reaches the
	// server.
	next := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())
	if cached, err := next.Bearer(context.Background()); err != nil || cached != token {
		t.Errorf("cached Bearer = %q, %v; want %q", cached, err, token)
	}
	if got := fake.count(adminStatusPath); got != 1 {
		t.Errorf("cached session still called status: %d", got)
	}
}

func TestAdminSessionRefusedChallengeReportsStepAndBody(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) { f.challengeFails = http.StatusForbidden })
	session := NewAdminSession(server.URL, bundleDir, filepath.Join(t.TempDir(), "s.json"), server.Client())

	_, err := session.Bearer(context.Background())
	var stepErr ErrAdminClaimStep
	if !errors.As(err, &stepErr) {
		t.Fatalf("err = %v, want ErrAdminClaimStep", err)
	}
	if stepErr.Step != AdminStepChallenge || stepErr.Status != http.StatusForbidden || !strings.Contains(stepErr.Body, "claim refused") {
		t.Errorf("step error = %+v, want the challenge step's 403 and body", stepErr)
	}
	if !strings.Contains(err.Error(), "claim refused") {
		t.Errorf("message %q does not carry the server's body", err)
	}
}

func TestAdminSessionMissingBundleIsTyped(t *testing.T) {
	_, cert := writeAdminBundle(t)
	_, server := newFakeClaimServer(t, cert)
	session := NewAdminSession(server.URL, t.TempDir(), filepath.Join(t.TempDir(), "s.json"), server.Client())

	_, err := session.Bearer(context.Background())
	var bundleErr ErrAdminBundleUnreadable
	if !errors.As(err, &bundleErr) || !strings.HasSuffix(bundleErr.Path, adminCertFile) {
		t.Errorf("err = %v, want ErrAdminBundleUnreadable for %s", err, adminCertFile)
	}
}

func TestAdminSessionClaimedAdminWithoutCacheIsTyped(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) { f.claimed = true })
	session := NewAdminSession(server.URL, bundleDir, filepath.Join(t.TempDir(), "s.json"), server.Client())

	_, err := session.Bearer(context.Background())
	var claimedErr ErrAdminAlreadyClaimed
	if !errors.As(err, &claimedErr) {
		t.Fatalf("err = %v, want ErrAdminAlreadyClaimed", err)
	}
	if fake.count(adminChallengePath) != 0 {
		t.Errorf("a claimed admin was still challenged")
	}
}

func TestAdminSessionRefreshesNearExpiry(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) { f.claimed = true })
	sessionFile := filepath.Join(t.TempDir(), "s.json")
	writeSessionCache(t, sessionFile, server.URL, fakeJWT(time.Now().Add(10*time.Minute)))
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	token, err := session.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if token != fake.refreshed {
		t.Errorf("token = %q, want the refreshed one", token)
	}
	if fake.count(adminStatusPath) != 0 {
		t.Errorf("a refreshable session still checked the claim status")
	}
	next := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())
	if cached, err := next.Bearer(context.Background()); err != nil || cached != fake.refreshed {
		t.Errorf("cache after refresh = %q, %v; want the refreshed token", cached, err)
	}
}

func TestAdminSessionRefusedRefreshOnClaimedAdminIsTyped(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) {
		f.claimed = true
		f.refreshFails = http.StatusUnauthorized
	})
	sessionFile := filepath.Join(t.TempDir(), "s.json")
	writeSessionCache(t, sessionFile, server.URL, fakeJWT(time.Now().Add(10*time.Minute)))
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	_, err := session.Bearer(context.Background())
	var claimedErr ErrAdminAlreadyClaimed
	if !errors.As(err, &claimedErr) {
		t.Fatalf("err = %v, want ErrAdminAlreadyClaimed", err)
	}
	var stepErr ErrAdminClaimStep
	if !errors.As(err, &stepErr) || stepErr.Step != AdminStepRefresh || stepErr.Status != http.StatusUnauthorized {
		t.Errorf("err = %v, want it to carry the refresh step's 401", err)
	}
}

func TestAdminSessionStaleCacheOnFreshDaemonClaims(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	sessionFile := filepath.Join(t.TempDir(), "s.json")
	writeSessionCache(t, sessionFile, server.URL, fakeJWT(time.Now().Add(-time.Minute)))
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	token, err := session.Bearer(context.Background())
	if err != nil || token != fake.issued {
		t.Fatalf("Bearer = %q, %v; want a fresh claim", token, err)
	}
	if fake.count(adminRefreshPath) != 0 {
		t.Errorf("an expired session was offered for refresh")
	}
}

func TestAdminSessionIgnoresCacheOfAnotherWebservice(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	sessionFile := filepath.Join(t.TempDir(), "s.json")
	writeSessionCache(t, sessionFile, "https://elsewhere:8443", fakeJWT(time.Now().Add(time.Hour)))
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	token, err := session.Bearer(context.Background())
	if err != nil || token != fake.issued {
		t.Errorf("Bearer = %q, %v; want this webservice's claim", token, err)
	}
}

func TestAdminSessionCorruptCacheIsTyped(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	sessionFile := filepath.Join(t.TempDir(), "s.json")
	writeFile(t, sessionFile, []byte("not json"))
	session := NewAdminSession(server.URL, bundleDir, sessionFile, server.Client())

	_, err := session.Bearer(context.Background())
	var cacheErr ErrAdminSessionCache
	if !errors.As(err, &cacheErr) || cacheErr.Path != sessionFile {
		t.Errorf("err = %v, want ErrAdminSessionCache for %s", err, sessionFile)
	}
	if fake.count(adminStatusPath) != 0 {
		t.Errorf("a corrupt cache still reached the server")
	}
}

func TestAdminSessionBearerExpiryRejectsMalformedTokens(t *testing.T) {
	noExp := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + ".c2ln"
	notJSON := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte("plain")) + ".c2ln"
	for _, token := range []string{"", "a.b", "a.!!!.c", notJSON, noExp} {
		var malformed ErrAdminTokenMalformed
		if _, err := bearerExpiry(token); !errors.As(err, &malformed) {
			t.Errorf("bearerExpiry(%q) err = %v, want ErrAdminTokenMalformed", token, err)
		}
	}
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if got, err := bearerExpiry(fakeJWT(exp)); err != nil || !got.Equal(exp) {
		t.Errorf("bearerExpiry = %v, %v; want %v", got, err, exp)
	}
}

func TestAdminSessionSignAdminChallengeEd25519SignsTheMessage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature, err := signAdminChallenge(privateKey, fakeAdminChallenge)
	if err != nil {
		t.Fatalf("signAdminChallenge: %v", err)
	}
	if !ed25519.Verify(publicKey, []byte(fakeAdminChallenge), signature) {
		t.Errorf("Ed25519 signature does not verify over the challenge itself")
	}
}

func TestAdminSessionAdminBearerTransportAddsBearer(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	session := NewAdminSession(server.URL, bundleDir, filepath.Join(t.TempDir(), "s.json"), server.Client())
	client := &http.Client{Transport: &adminBearerTransport{session: session, base: server.Client().Transport}}

	resp, err := client.Get(server.URL + "/api/v1/iam/users")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if want := "Bearer " + fake.issued; fake.authorization() != want {
		t.Errorf("Authorization = %q, want %q", fake.authorization(), want)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/iam/users", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer caller-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET with own bearer: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if fake.authorization() != "Bearer caller-token" {
		t.Errorf("caller's Authorization replaced with %q", fake.authorization())
	}
}

func TestAdminSessionAdminBearerTransportFailsBeforeTheRequest(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) { f.challengeFails = http.StatusForbidden })
	session := NewAdminSession(server.URL, bundleDir, filepath.Join(t.TempDir(), "s.json"), server.Client())
	client := &http.Client{Transport: &adminBearerTransport{session: session, base: server.Client().Transport}}

	resp, err := client.Post(server.URL+"/api/v1/iam/users", "application/json", strings.NewReader("{}"))
	if err == nil {
		t.Fatalf("request without a session reached the server: HTTP %d", resp.StatusCode)
	}
	var stepErr ErrAdminClaimStep
	if !errors.As(err, &stepErr) || stepErr.Step != AdminStepChallenge {
		t.Errorf("err = %v, want the challenge step's ErrAdminClaimStep", err)
	}
	if fake.count("/api/v1/iam/users") != 0 {
		t.Errorf("the gated route was called without a bearer")
	}
}

// A Setup probe whose admin session failed reached the endpoint, so the
// message must name the claim step and its HTTP answer, not call the
// endpoint unreachable.
func TestAdminSessionSetupProbeFailureNamesTheStep(t *testing.T) {
	bundleDir, cert := writeAdminBundle(t)
	fake, server := newFakeClaimServer(t, cert)
	fake.configure(func(f *fakeClaimServer) { f.challengeFails = http.StatusForbidden })
	session := NewAdminSession(server.URL, bundleDir, filepath.Join(t.TempDir(), "s.json"), server.Client())
	client := &http.Client{Transport: &adminBearerTransport{session: session, base: server.Client().Transport}}

	resp, err := client.Get(server.URL + "/health")
	if err == nil {
		t.Fatalf("probe without a session reached the server: HTTP %d", resp.StatusCode)
	}
	got := SetupProbeFailure(err)
	want := "admin session: " + AdminStepChallenge + ": HTTP 403"
	if !strings.HasPrefix(got, want) {
		t.Errorf("SetupProbeFailure = %q, want prefix %q", got, want)
	}
	if strings.Contains(got, "not reachable") {
		t.Errorf("SetupProbeFailure = %q calls an answering endpoint unreachable", got)
	}
}

// A dial failure is still reported as an unreachable endpoint.
func TestAdminSessionSetupProbeFailureKeepsUnreachable(t *testing.T) {
	cause := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	got := SetupProbeFailure(cause)
	if got != "endpoint not reachable: "+cause.Error() {
		t.Errorf("SetupProbeFailure = %q, want the unreachable form", got)
	}
}
