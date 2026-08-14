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

package installer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeSignServer is a test double for the control-plane provisioning endpoints
// used by the install-time remote signer: it issues a nonce and signs digests,
// recording the request order and the last sign request for assertions.
type fakeSignServer struct {
	mu          sync.Mutex
	order       []string
	lastSign    remoteSignRequest
	signCount   int
	nonce       string
	signature   []byte
	certPEM     []byte
	signStatus  int // optional override; 0 => 200
	nonceStatus int // optional override; 0 => 200
}

func newFakeSignServer(t *testing.T, signature, certPEM []byte) (*httptest.Server, *fakeSignServer) {
	t.Helper()
	f := &fakeSignServer{nonce: "nonce-abc123", signature: signature, certPEM: certPEM}
	mux := http.NewServeMux()
	mux.HandleFunc(provisionNoncePath, func(w http.ResponseWriter, r *http.Request) {
		f.record("nonce")
		if f.nonceStatus != 0 {
			w.WriteHeader(f.nonceStatus)
			return
		}
		writeEnvelope(t, w, map[string]any{"nonce": f.nonce})
	})
	mux.HandleFunc(provisionSignPath, func(w http.ResponseWriter, r *http.Request) {
		f.record("sign")
		var req remoteSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.lastSign = req
		f.signCount++
		f.mu.Unlock()
		if f.signStatus != 0 {
			w.WriteHeader(f.signStatus)
			return
		}
		writeEnvelope(t, w, map[string]any{"signature": f.signature, "cert_pem": f.certPEM})
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, f
}

func (f *fakeSignServer) record(name string) {
	f.mu.Lock()
	f.order = append(f.order, name)
	f.mu.Unlock()
}

// writeEnvelope marshals the platform REST {code, success, payload} envelope so
// the client's decodeEnvelopePayload finds the data under .payload.
func writeEnvelope(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"code": 200, "success": true, "payload": payload}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
}

// genTestCert returns a self-signed RSA certificate (PEM) plus its public key for
// use as the control-plane DB certificate the fake server returns.
func genTestCert(t *testing.T, cn string) ([]byte, crypto.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, &key.PublicKey
}

func completeContext(serverURL string, client *http.Client) *RemoteSignContext {
	return &RemoteSignContext{
		ServerURL:  serverURL,
		EABKeyID:   "eab-kid-1",
		EABHMAC:    "eab-hmac-1",
		EKSerial:   "EK-SERIAL-123",
		MACAddress: "00:11:22:33:44:55",
		EKCertB64:  "ZHVtbXktZWstY2VydA==", // base64 of dummy-ek-cert
		HTTPClient: client,
	}
}

// TestRemoteSignClient_SignPostsWellFormedRequest verifies the install-time
// remote signer fetches a nonce FIRST, POSTs a well-formed SignRequest (auth
// fields populated, nonce threaded, digest base64-round-tripped, key_ref=db),
// returns the server signature, and caches the DB certificate so Public()
// matches it.
func TestRemoteSignClient_SignPostsWellFormedRequest(t *testing.T) {
	wantSig := []byte("known-signature-bytes")
	certPEM, wantPub := genTestCert(t, "remote-db-cn")
	ts, fake := newFakeSignServer(t, wantSig, certPEM)

	rsc := completeContext(ts.URL, ts.Client())
	client, err := newRemoteSignClient(rsc, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("newRemoteSignClient: %v", err)
	}

	digest := sha256.Sum256([]byte("uki-bytes"))
	sig, err := client.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != string(wantSig) {
		t.Errorf("signature = %q, want %q", sig, wantSig)
	}

	// Nonce must be fetched before the sign POST.
	if len(fake.order) < 2 || fake.order[0] != "nonce" || fake.order[1] != "sign" {
		t.Fatalf("call order = %v, want [nonce sign]", fake.order)
	}

	// The signed digest must round-trip via base64 in the JSON body.
	if string(fake.lastSign.Digest) != string(digest[:]) {
		t.Errorf("server received digest %x, want %x", fake.lastSign.Digest, digest[:])
	}
	// Auth identity fields must be populated from the context.
	if fake.lastSign.EABKeyID != rsc.EABKeyID || fake.lastSign.EABHMAC != rsc.EABHMAC {
		t.Errorf("EAB fields = %q/%q, want %q/%q", fake.lastSign.EABKeyID, fake.lastSign.EABHMAC, rsc.EABKeyID, rsc.EABHMAC)
	}
	if fake.lastSign.EKSerial != rsc.EKSerial || fake.lastSign.MACAddress != rsc.MACAddress {
		t.Errorf("EK/MAC = %q/%q, want %q/%q", fake.lastSign.EKSerial, fake.lastSign.MACAddress, rsc.EKSerial, rsc.MACAddress)
	}
	if fake.lastSign.EKCert != rsc.EKCertB64 {
		t.Errorf("EKCert = %q, want %q", fake.lastSign.EKCert, rsc.EKCertB64)
	}
	if fake.lastSign.Nonce != fake.nonce {
		t.Errorf("nonce = %q, want %q (the issued nonce)", fake.lastSign.Nonce, fake.nonce)
	}
	if fake.lastSign.KeyRef != "db" {
		t.Errorf("key_ref = %q, want db", fake.lastSign.KeyRef)
	}

	// Public() must reflect the certificate returned by the sign response.
	gotPub, ok := client.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *rsa.PublicKey", client.Public())
	}
	if !gotPub.Equal(wantPub) {
		t.Error("Public() does not match the DB certificate returned by the server")
	}
}

// TestRemoteSignClient_DigestIsBase64InWireBody verifies the JSON wire body
// encodes the digest as a base64 string (matching the server-side []byte field),
// not as a JSON array.
func TestRemoteSignClient_DigestIsBase64InWireBody(t *testing.T) {
	certPEM, _ := genTestCert(t, "db")
	ts, _ := newFakeSignServer(t, []byte("sig"), certPEM)

	rsc := completeContext(ts.URL, ts.Client())
	client, err := newRemoteSignClient(rsc, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("newRemoteSignClient: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))
	reqBody, err := json.Marshal(remoteSignRequest{Digest: digest[:]})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// encoding/json renders []byte as a quoted base64 string.
	var m map[string]any
	if err := json.Unmarshal(reqBody, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["digest"].(string); !ok {
		t.Fatalf("digest field is %T, want base64 string", m["digest"])
	}
	_ = client
}

// TestRemoteSignClient_IncompleteContext verifies an incomplete provisioning
// context is rejected with a typed Secure Boot error rather than producing a
// half-configured signer.
func TestRemoteSignClient_IncompleteContext(t *testing.T) {
	cases := []struct {
		name string
		rsc  *RemoteSignContext
	}{
		{"nil", nil},
		{"no server url", &RemoteSignContext{EABKeyID: "k", EABHMAC: "h", EKSerial: "e"}},
		{"no eab", &RemoteSignContext{ServerURL: "https://cp", EKSerial: "e"}},
		{"no device id", &RemoteSignContext{ServerURL: "https://cp", EABKeyID: "k", EABHMAC: "h"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := newRemoteSignClient(c.rsc, logging.DefaultLogger()); err == nil {
				t.Fatal("expected an error for an incomplete context, got nil")
			}
		})
	}
}

// TestRemoteSignClient_ServerError verifies a non-200 from the sign endpoint is
// surfaced as a typed ErrRemoteSign carrying the status.
func TestRemoteSignClient_ServerError(t *testing.T) {
	certPEM, _ := genTestCert(t, "db")
	ts, fake := newFakeSignServer(t, []byte("sig"), certPEM)
	fake.signStatus = http.StatusForbidden

	client, err := newRemoteSignClient(completeContext(ts.URL, ts.Client()), logging.DefaultLogger())
	if err != nil {
		t.Fatalf("newRemoteSignClient: %v", err)
	}

	digest := sha256.Sum256([]byte("x"))
	_, err = client.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("expected an error for a 403 sign response, got nil")
	}
	var rse *ErrRemoteSign
	if !errors.As(err, &rse) {
		t.Fatalf("expected *ErrRemoteSign, got %T: %v", err, err)
	}
	if rse.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rse.Status, http.StatusForbidden)
	}
	if !strings.Contains(rse.Error(), "403") {
		t.Errorf("ErrRemoteSign.Error() = %q, want it to mention status 403", rse.Error())
	}
}

// TestRemoteSignClient_EmptyNonceRejected verifies an empty nonce from the server
// is rejected before any sign attempt.
func TestRemoteSignClient_EmptyNonceRejected(t *testing.T) {
	certPEM, _ := genTestCert(t, "db")
	ts, fake := newFakeSignServer(t, []byte("sig"), certPEM)
	fake.nonce = "" // server returns an empty nonce

	client, err := newRemoteSignClient(completeContext(ts.URL, ts.Client()), logging.DefaultLogger())
	if err != nil {
		t.Fatalf("newRemoteSignClient: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := client.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("expected an error for an empty nonce, got nil")
	}
}

// TestInstallRemoteSignerResolver_ProbesCertificate verifies the resolver returns
// a usable signer plus the DB certificate up front (fetched via a probe sign),
// because resolveSecureBootSigner needs the certificate before any UKI signing.
func TestInstallRemoteSignerResolver_ProbesCertificate(t *testing.T) {
	certPEM, wantPub := genTestCert(t, "probe-db")
	ts, fake := newFakeSignServer(t, []byte("sig"), certPEM)

	resolver := installRemoteSignerResolver(completeContext(ts.URL, ts.Client()), logging.DefaultLogger())
	signer, cert, err := resolver(context.Background(), nil)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if signer == nil || cert == nil {
		t.Fatal("expected a non-nil signer and certificate")
	}
	// The probe must have signed exactly once to retrieve the certificate.
	if fake.signCount != 1 {
		t.Errorf("probe sign count = %d, want 1", fake.signCount)
	}
	gotPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !gotPub.Equal(wantPub) {
		t.Error("resolved certificate does not match the server DB certificate")
	}
	if sp, ok := signer.Public().(*rsa.PublicKey); !ok || !sp.Equal(wantPub) {
		t.Error("signer.Public() does not match the DB certificate")
	}
}

// TestNewInstaller_RemoteSignerWired verifies the constructor wires the remote
// signer seam ONLY when Secure Boot is in resign-mode remote AND a complete
// provisioning context is supplied; otherwise the seam stays nil and the
// installer falls through to on-node generation.
func TestNewInstaller_RemoteSignerWired(t *testing.T) {
	remoteSB := func() *SecureBootConfig {
		return &SecureBootConfig{
			Enabled:    true,
			ResignMode: SecureBootResignModeRemote,
			DB: SecureBootKeyRef{
				KeyConfig: common.KeyConfig{CN: "db", StoreType: "software"},
				KeyURI:    "kms://platform/secureboot/db",
			},
		}
	}

	t.Run("remote + context => seam wired", func(t *testing.T) {
		cfg := createTestConfig()
		cfg.SecureBoot = remoteSB()
		inst, err := NewInstaller(createTestLogger(), cfg,
			WithRemoteSignContext(completeContext("https://cp:8443", nil)))
		if err != nil {
			t.Fatalf("NewInstaller: %v", err)
		}
		if inst.(*installer).resolveRemoteSigner == nil {
			t.Fatal("expected resolveRemoteSigner to be wired for remote + context")
		}
	})

	t.Run("remote without context => seam nil (falls through)", func(t *testing.T) {
		cfg := createTestConfig()
		cfg.SecureBoot = remoteSB()
		inst, err := NewInstaller(createTestLogger(), cfg)
		if err != nil {
			t.Fatalf("NewInstaller: %v", err)
		}
		if inst.(*installer).resolveRemoteSigner != nil {
			t.Fatal("expected resolveRemoteSigner to be nil without a provisioning context")
		}
	})

	t.Run("local resign-mode => seam nil even with context", func(t *testing.T) {
		cfg := createTestConfig()
		sb := remoteSB()
		sb.ResignMode = SecureBootResignModeLocal
		cfg.SecureBoot = sb
		inst, err := NewInstaller(createTestLogger(), cfg,
			WithRemoteSignContext(completeContext("https://cp:8443", nil)))
		if err != nil {
			t.Fatalf("NewInstaller: %v", err)
		}
		if inst.(*installer).resolveRemoteSigner != nil {
			t.Fatal("expected resolveRemoteSigner to be nil for resign-mode local")
		}
	})
}

// TestRemoteSignContext_Ready exercises the readiness predicate that gates seam
// wiring.
func TestRemoteSignContext_Ready(t *testing.T) {
	if (&RemoteSignContext{}).ready() {
		t.Error("empty context should not be ready")
	}
	full := completeContext("https://cp", nil)
	if !full.ready() {
		t.Error("complete context should be ready")
	}
	macOnly := &RemoteSignContext{ServerURL: "https://cp", EABKeyID: "k", EABHMAC: "h", MACAddress: "aa:bb"}
	if !macOnly.ready() {
		t.Error("context with mac (no ek serial) should be ready")
	}
}
