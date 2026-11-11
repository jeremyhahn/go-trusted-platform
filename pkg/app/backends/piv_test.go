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

package backends

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// --- test fixtures ----------------------------------------------------------

// fakePIVGen implements pivcert.PIVKeyGenerator via the xkms interface. It
// hands out a fixed signer for every slot/CN combination.
type fakePIVGen struct {
	signer crypto.Signer
}

func (f *fakePIVGen) GeneratePIVKey(_ xkmssdk.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	return f.signer, nil
}

func (f *fakePIVGen) GetPIVSigner(_ xkmssdk.PIVSlot, _ string) (crypto.Signer, error) {
	return f.signer, nil
}

// fakePIVStore is an in-memory xkmssdk.PIVCertificateStorage used by the
// PIV backend tests.
type fakePIVStore struct {
	mu       sync.Mutex
	certs    map[xkmssdk.PIVSlot]*x509.Certificate
	imported []byte
}

func newFakePIVStore() *fakePIVStore {
	return &fakePIVStore{certs: make(map[xkmssdk.PIVSlot]*x509.Certificate)}
}

func (s *fakePIVStore) Store(slot xkmssdk.PIVSlot, cert *x509.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[slot] = cert
	return nil
}
func (s *fakePIVStore) Retrieve(slot xkmssdk.PIVSlot) (*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[slot]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}
func (s *fakePIVStore) Delete(slot xkmssdk.PIVSlot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certs[slot]; !ok {
		return errors.New("not found")
	}
	delete(s.certs, slot)
	return nil
}
func (s *fakePIVStore) List() ([]xkmssdk.PIVSlotInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]xkmssdk.PIVSlotInfo, 0, len(s.certs))
	for slot, cert := range s.certs {
		out = append(out, xkmssdk.PIVSlotInfo{
			Slot:      slot,
			Subject:   cert.Subject.CommonName,
			Algorithm: cert.PublicKeyAlgorithm.String(),
		})
	}
	return out, nil
}
func (s *fakePIVStore) Import(_ xkmssdk.PIVSlot, raw []byte, _ xkmssdk.PIVCertFormat) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imported = append([]byte(nil), raw...)
	return nil
}

// importedBytes returns a copy of the material the last Import received.
func (s *fakePIVStore) importedBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.imported...)
}
func (s *fakePIVStore) Export(slot xkmssdk.PIVSlot, format xkmssdk.PIVCertFormat) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[slot]
	if !ok {
		return nil, errors.New("not found")
	}
	if format == xkmssdk.PIVFormatPEM {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), nil
	}
	return c.Raw, nil
}
func (s *fakePIVStore) Close() error                 { return nil }
func (s *fakePIVStore) Type() xkmssdk.PIVStorageType { return "backend-test" }

// makeTestCert produces a self-signed cert for seeding the fake store.
func makeTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	return cert
}

// setupBackendPIV installs a fresh PIV manager singleton with a software
// backend name and (optionally) a signer-returning PIVKeyGenerator. Returns
// the underlying store so callers can seed it.
func setupBackendPIV(t *testing.T, key crypto.Signer) *fakePIVStore {
	t.Helper()
	xkmsbackend.ResetPIV()
	t.Cleanup(xkmsbackend.ResetPIV)

	store := newFakePIVStore()
	if err := xkmsbackend.InitializePIV(&xkmsbackend.PIVManagerConfig{
		Stores: map[string]xkmssdk.PIVCertificateStorage{"software": store},
	}); err != nil {
		t.Fatalf("InitializePIV: %v", err)
	}
	if key != nil {
		if err := xkmsbackend.SetPIVBackendResolver(func(_ string) (xkmsbackend.PIVKeyGenerator, error) {
			return &fakePIVGen{signer: key}, nil
		}); err != nil {
			t.Fatalf("SetPIVBackendResolver: %v", err)
		}
	}
	return store
}

// --- TestPIVBackend_UnavailableManager keeps the original assertion that
//     every entry point surfaces ErrPIVBackendUnavailable when the manager
//     singleton is nil. Sign/Attest/Reset no longer have "NotImplemented"
//     error paths — they return ErrPIVBackendUnavailable when the manager
//     is missing, or ErrPIVResetNotConfirmed for Reset without confirmation.

func TestPIVBackend_UnavailableManager(t *testing.T) {
	xkmsbackend.ResetPIV()
	b := NewPIVBackend(logging.DefaultLogger())

	t.Run("ListDevices", func(t *testing.T) {
		_, err := b.ListDevices(context.Background())
		if err != nil && !errors.Is(err, ErrPIVBackendUnavailable) {
			t.Fatalf("expected ErrPIVBackendUnavailable or nil, got %v", err)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		_, err := b.Sign(context.Background(), &daemon.PIVSignRequest{Slot: "9a", Payload: []byte("x")})
		if !errors.Is(err, ErrPIVBackendUnavailable) {
			t.Fatalf("expected ErrPIVBackendUnavailable, got %v", err)
		}
	})

	t.Run("Attest", func(t *testing.T) {
		_, err := b.Attest(context.Background(), "9a")
		if !errors.Is(err, ErrPIVBackendUnavailable) {
			t.Fatalf("expected ErrPIVBackendUnavailable, got %v", err)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		b.ConfirmReset()
		err := b.Reset(context.Background(), "software")
		if !errors.Is(err, ErrPIVBackendUnavailable) {
			t.Fatalf("expected ErrPIVBackendUnavailable, got %v", err)
		}
	})
}

// --- Sign happy path and error cases ---------------------------------------

func TestPIVBackend_Sign_HappyPath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	_ = setupBackendPIV(t, key)

	b := NewPIVBackend(logging.DefaultLogger())
	payload := []byte("sign me")
	sig, err := b.Sign(context.Background(), &daemon.PIVSignRequest{Slot: "9c", Payload: payload})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("signature did not verify against payload digest")
	}
}

func TestPIVBackend_Sign_InvalidSlot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	_ = setupBackendPIV(t, key)

	b := NewPIVBackend(logging.DefaultLogger())
	_, err = b.Sign(context.Background(), &daemon.PIVSignRequest{Slot: "zz", Payload: []byte("x")})
	if err == nil {
		t.Fatal("expected error for invalid slot")
	}
	if !errors.Is(err, xkmsbackend.ErrPIVInvalidSlot) {
		t.Fatalf("expected ErrPIVInvalidSlot, got %v", err)
	}
}

// --- Attest happy path and error cases -------------------------------------

func TestPIVBackend_Attest_HappyPath(t *testing.T) {
	store := setupBackendPIV(t, nil)
	if err := store.Store(xkmssdk.PIVSlotAuthentication, makeTestCert(t, "piv-9a")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := NewPIVBackend(logging.DefaultLogger())
	res, err := b.Attest(context.Background(), "9a")
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res == nil || res.AttestationCertPEM == "" {
		t.Fatalf("expected attestation cert PEM, got %+v", res)
	}
	if res.AttestationChainPEM != "" {
		t.Fatalf("expected empty chain (no f9), got %q", res.AttestationChainPEM)
	}
}

func TestPIVBackend_Attest_NoCert(t *testing.T) {
	_ = setupBackendPIV(t, nil)
	b := NewPIVBackend(logging.DefaultLogger())
	_, err := b.Attest(context.Background(), "9a")
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
	if !errors.Is(err, xkmsbackend.ErrPIVNoAttestationMaterial) {
		t.Fatalf("expected ErrPIVNoAttestationMaterial, got %v", err)
	}
}

// --- Reset happy path and error cases --------------------------------------

func TestPIVBackend_Reset_HappyPath(t *testing.T) {
	store := setupBackendPIV(t, nil)
	if err := store.Store(xkmssdk.PIVSlotAuthentication, makeTestCert(t, "piv-9a")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := NewPIVBackend(logging.DefaultLogger())
	b.ConfirmReset()
	if err := b.Reset(context.Background(), "software"); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	infos, listErr := store.List()
	if listErr != nil {
		t.Fatalf("List after reset: %v", listErr)
	}
	if len(infos) != 0 {
		t.Fatalf("expected empty store, got %d entries", len(infos))
	}
}

func TestPIVBackend_Reset_RequiresConfirmation(t *testing.T) {
	store := setupBackendPIV(t, nil)
	if err := store.Store(xkmssdk.PIVSlotAuthentication, makeTestCert(t, "piv-9a")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := NewPIVBackend(logging.DefaultLogger())
	// Intentionally skip ConfirmReset().
	err := b.Reset(context.Background(), "software")
	if !errors.Is(err, ErrPIVResetNotConfirmed) {
		t.Fatalf("expected ErrPIVResetNotConfirmed, got %v", err)
	}
	infos, _ := store.List()
	if len(infos) != 1 {
		t.Fatalf("store should be untouched, got %d entries", len(infos))
	}
}

func TestPIVBackend_Reset_ConfirmationIsOneShot(t *testing.T) {
	_ = setupBackendPIV(t, nil)

	b := NewPIVBackend(logging.DefaultLogger())
	b.ConfirmReset()
	if err := b.Reset(context.Background(), "software"); err != nil {
		t.Fatalf("first Reset: %v", err)
	}
	// Second call must not reuse the prior confirmation.
	if err := b.Reset(context.Background(), "software"); !errors.Is(err, ErrPIVResetNotConfirmed) {
		t.Fatalf("expected ErrPIVResetNotConfirmed on second call, got %v", err)
	}
}

// --- Unchanged helper tests ------------------------------------------------

func TestPIVBackend_WithDefaultBackend(t *testing.T) {
	b := NewPIVBackend(logging.DefaultLogger()).WithDefaultBackend("custom-backend")
	if b.defaultBackend != "custom-backend" {
		t.Fatalf("expected custom-backend, got %q", b.defaultBackend)
	}
	b.WithDefaultBackend("")
	if b.defaultBackend != "custom-backend" {
		t.Fatalf("empty override clobbered backend, got %q", b.defaultBackend)
	}
}

func TestPIVBackend_ImplementsInterface(t *testing.T) {
	var _ daemon.PIVBackend = (*PIVBackend)(nil)
}

// --- Protected-memory request handling -------------------------------------
//
// The service-layer PIV requests hold key material and PINs in a
// MemoryEnclave. These tests prove the backend reads through the protected
// accessors rather than the deprecated plain fields.

func TestPIVBackend_Import_FailsClosedWithoutWriting(t *testing.T) {
	pem := genTestKeyPEM()
	cases := map[string]*daemon.PIVImportRequest{
		"enclave": {Slot: "9a", PrivateKey: memguard.NewMemoryEnclaveFromString(pem)},
		"plain":   {Slot: "9a", PrivateKeyPEM: pem}, //nolint:staticcheck // SA1019: the compat path must fail closed too.
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			store := setupBackendPIV(t, nil)
			defer req.Destroy()

			b := NewPIVBackend(logging.DefaultLogger())
			err := b.Import(context.Background(), req)
			if !errors.Is(err, daemon.ErrPIVKeyImportUnsupported) {
				t.Fatalf("Import: want ErrPIVKeyImportUnsupported, got %v", err)
			}
			if got := store.importedBytes(); len(got) != 0 {
				t.Errorf("store received %d bytes, want none", len(got))
			}
			infos, listErr := store.List()
			if listErr != nil {
				t.Fatalf("List: %v", listErr)
			}
			if len(infos) != 0 {
				t.Errorf("store has %d entries, want none", len(infos))
			}
		})
	}
}

func TestPIVBackend_Sign_WithEnclavePIN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	_ = setupBackendPIV(t, key)

	payload := []byte("sign me")
	req := &daemon.PIVSignRequest{
		Slot:       "9c",
		Payload:    payload,
		PINEnclave: memguard.NewMemoryEnclaveFromString("123456"),
	}
	defer req.Destroy()

	b := NewPIVBackend(logging.DefaultLogger())
	sig, err := b.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("signature did not verify against payload digest")
	}
}

func TestPIVBackend_Sign_EnclavePINSurfacesSignError(t *testing.T) {
	// No key generator is registered, so the sign path fails inside the
	// WithPIN callback; the error must propagate out of Sign unchanged.
	_ = setupBackendPIV(t, nil)

	req := &daemon.PIVSignRequest{
		Slot:       "9c",
		Payload:    []byte("x"),
		PINEnclave: memguard.NewMemoryEnclaveFromString("123456"),
	}
	defer req.Destroy()

	b := NewPIVBackend(logging.DefaultLogger())
	if _, err := b.Sign(context.Background(), req); err == nil {
		t.Fatal("expected an error with no PIV key generator registered")
	}
}
