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
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestGenerateSecureBootSigner_Software verifies the on-node Secure Boot DB
// key generation path: with the "software" backend it produces a usable
// crypto.Signer + DB certificate, writes the keypair under the requested
// directory (NOT shipped, NOT on any ESP), and a second call reuses the
// existing keys rather than regenerating.
func TestGenerateSecureBootSigner_Software(t *testing.T) {
	logger := logging.DefaultLogger()
	keysDir := filepath.Join(t.TempDir(), "secure-boot")
	cn := "Trusted Platform Secure Boot DB - test-node"

	signer, cert, err := generateSecureBootSigner(context.Background(), logger, "software", keysDir, cn)
	if err != nil {
		t.Fatalf("generateSecureBootSigner(software) returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected a non-nil signing key")
	}
	if cert == nil {
		t.Fatal("expected a non-nil DB certificate")
	}
	if !strings.Contains(cert.Subject.CommonName, cn) {
		t.Errorf("cert CN = %q, want it to contain %q", cert.Subject.CommonName, cn)
	}

	// The returned key must be usable as a crypto.Signer (authenticode needs it).
	cs, ok := signer.(crypto.Signer)
	if !ok {
		t.Fatalf("signing key %T does not implement crypto.Signer", signer)
	}
	digest := sha256.Sum256([]byte("uki-bytes"))
	if _, err := cs.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	// The DB keypair must have landed under keysDir (on the encrypted root in
	// production), never shipped over the network.
	if _, err := os.Stat(filepath.Join(keysDir, "DB.crt")); err != nil {
		t.Errorf("expected DB.crt under %s: %v", keysDir, err)
	}
	if _, err := os.Stat(filepath.Join(keysDir, "DB.key")); err != nil {
		t.Errorf("expected DB.key under %s: %v", keysDir, err)
	}

	// A second call must reuse the existing keys (idempotent), returning the
	// same certificate.
	_, cert2, err := generateSecureBootSigner(context.Background(), logger, "software", keysDir, cn)
	if err != nil {
		t.Fatalf("second generateSecureBootSigner returned error: %v", err)
	}
	if cert2 == nil || !cert2.Equal(cert) {
		t.Error("expected the second call to reuse the existing DB certificate")
	}
}

// TestGenerateSecureBootSigner_InvalidBackend verifies an unsupported backend
// is rejected with a typed Secure Boot error rather than silently producing an
// unsigned install.
func TestGenerateSecureBootSigner_InvalidBackend(t *testing.T) {
	logger := logging.DefaultLogger()
	keysDir := filepath.Join(t.TempDir(), "secure-boot")

	if _, _, err := generateSecureBootSigner(context.Background(), logger, "not-a-backend", keysDir, "cn"); err == nil {
		t.Fatal("expected an error for an unsupported backend, got nil")
	}
}

// TestLoadISOSecureBootKeys_AbsentReturnsNil verifies that when no install
// media keys are present the loader returns (nil, nil) so the caller falls
// through to on-node generation instead of failing.
func TestLoadISOSecureBootKeys_AbsentReturnsNil(t *testing.T) {
	i := &installer{logger: logging.DefaultLogger()}
	key, cert := i.loadISOSecureBootKeys()
	if key != nil || cert != nil {
		t.Errorf("expected (nil, nil) when no install-media SB keys exist, got key=%v cert=%v", key, cert)
	}
}

// writeTestKeypairPEM generates an RSA keypair + self-signed certificate and
// writes them as PKCS#1 / PEM files at keyPath and certPath. It returns the
// generated certificate for equality assertions.
func writeTestKeypairPEM(t *testing.T, keyPath, certPath, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return cert
}

// TestResolveSecureBootSigner_FileURI verifies branch (a): a file:// DB KeyURI
// (with an explicit file:// CertURI) loads the PEM keypair locally.
func TestResolveSecureBootSigner_FileURI(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "DB.key")
	certPath := filepath.Join(dir, "DB.crt")
	want := writeTestKeypairPEM(t, keyPath, certPath, "file-uri-db")

	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{},
			SecureBoot: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeLocal,
				DB: SecureBootKeyRef{
					KeyURI:  "file://" + keyPath,
					CertURI: "file://" + certPath,
				},
			},
		},
	}

	key, cert, err := i.resolveSecureBootSigner(context.Background())
	if err != nil {
		t.Fatalf("resolveSecureBootSigner returned error: %v", err)
	}
	if key == nil {
		t.Fatal("expected a non-nil key from the file:// URI")
	}
	if cert == nil || !cert.Equal(want) {
		t.Fatal("expected the certificate read from the file:// CertURI")
	}
	if _, ok := key.(crypto.Signer); !ok {
		t.Fatalf("file:// key %T does not implement crypto.Signer", key)
	}
}

// TestResolveSecureBootSigner_FileURISiblingCert verifies branch (a) derives the
// sibling DB.crt next to the key when no CertURI is configured.
func TestResolveSecureBootSigner_FileURISiblingCert(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "DB.key")
	certPath := filepath.Join(dir, "DB.crt")
	want := writeTestKeypairPEM(t, keyPath, certPath, "sibling-db")

	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{},
			SecureBoot: &SecureBootConfig{
				Enabled: true,
				DB:      SecureBootKeyRef{KeyURI: "file://" + keyPath},
			},
		},
	}

	key, cert, err := i.resolveSecureBootSigner(context.Background())
	if err != nil {
		t.Fatalf("resolveSecureBootSigner returned error: %v", err)
	}
	if key == nil || cert == nil || !cert.Equal(want) {
		t.Fatal("expected the sibling DB.crt to be resolved alongside the key")
	}
}

// TestLoadFileURISecureBootKeys_Errors covers the helper's branches: a non
// file:// URI returns (nil, nil, nil); a missing key file returns a typed error.
func TestLoadFileURISecureBootKeys_Errors(t *testing.T) {
	// Non file:// URI -> not applicable, no error.
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{
			DB: SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
		}},
	}
	key, cert, err := i.loadFileURISecureBootKeys()
	if key != nil || cert != nil || err != nil {
		t.Fatalf("expected (nil,nil,nil) for non-file:// URI, got key=%v cert=%v err=%v", key, cert, err)
	}

	// A file:// URI naming a missing key yields a typed Secure Boot error.
	missing := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{
			DB: SecureBootKeyRef{KeyURI: "file://" + filepath.Join(t.TempDir(), "absent.key")},
		}},
	}
	_, _, err = missing.loadFileURISecureBootKeys()
	if err == nil {
		t.Fatal("expected an error for a missing file:// DB key")
	}
	var ierr *InstallerError
	if !errors.As(err, &ierr) || ierr.Type != ErrorTypeSecureBoot {
		t.Fatalf("expected a typed Secure Boot error, got %T: %v", err, err)
	}
}

// TestResolveSecureBootSigner_Remote verifies branch (b): with resign-mode
// "remote" and a constructible remote signer seam, the resolver returns the
// remote signer + certificate and passes the DB key attributes through.
func TestResolveSecureBootSigner_Remote(t *testing.T) {
	dir := t.TempDir()
	// Build a stand-in remote signer + certificate.
	keyPath := filepath.Join(dir, "remote.key")
	certPath := filepath.Join(dir, "remote.crt")
	wantCert := writeTestKeypairPEM(t, keyPath, certPath, "remote-db")
	rawKey, err := authenticode.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		t.Fatalf("parsePEMPrivateKey: %v", err)
	}
	remoteSigner := rawKey.(crypto.Signer)

	var gotCN string
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{},
			SecureBoot: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeRemote,
				DB: SecureBootKeyRef{
					KeyConfig: common.KeyConfig{CN: "platform-secureboot-db", StoreType: "software"},
					KeyURI:    "kms://platform/secureboot/db",
				},
			},
		},
		resolveRemoteSigner: func(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
			gotCN = attrs.CN
			return remoteSigner, wantCert, nil
		},
	}

	key, cert, err := i.resolveSecureBootSigner(context.Background())
	if err != nil {
		t.Fatalf("resolveSecureBootSigner returned error: %v", err)
	}
	if key == nil || cert == nil || !cert.Equal(wantCert) {
		t.Fatal("expected the remote signer's certificate")
	}
	if got, ok := key.(crypto.Signer); !ok || got.Public() == nil {
		t.Fatal("expected a usable remote crypto.Signer")
	}
	if gotCN != "platform-secureboot-db" {
		t.Errorf("seam received attrs.CN = %q, want %q (ToKeyAttributes integration)", gotCN, "platform-secureboot-db")
	}
}

// TestResolveSecureBootSigner_RemoteFallsThroughOnError verifies that when the
// remote seam errors, the resolver does NOT use it and proceeds to branch (c)
// on-node generation. A tpm2 backend makes generation fail fast (it needs a
// pre-configured key store) so the test never touches /mnt.
func TestResolveSecureBootSigner_RemoteFallsThroughOnError(t *testing.T) {
	seamCalled := false
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{Hostname: "test"},
			SecureBoot: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeRemote,
				DB: SecureBootKeyRef{
					KeyConfig: common.KeyConfig{StoreType: "tpm2"},
					KeyURI:    "kms://platform/secureboot/db",
				},
			},
		},
		resolveRemoteSigner: func(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
			seamCalled = true
			return nil, nil, ErrSecureBoot("remote unreachable", nil)
		},
	}

	_, _, err := i.resolveSecureBootSigner(context.Background())
	if !seamCalled {
		t.Fatal("expected the remote seam to be invoked")
	}
	// Branch (c) ran with a tpm2 backend that fails fast -> a typed error, and
	// importantly no key material was written to the host.
	if err == nil {
		t.Fatal("expected branch (c) on-node generation to fail fast for the tpm2 backend")
	}
}

// TestResolveSecureBootSigner_OnNodeGenSelected verifies branch (c) is selected
// when there is no file:// URI and resign-mode is not remote. A tpm2 backend
// fails fast so the test asserts routing without touching /mnt.
func TestResolveSecureBootSigner_OnNodeGenSelected(t *testing.T) {
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{Hostname: "test"},
			SecureBoot: &SecureBootConfig{
				Enabled: true,
				// No KeyURI, resign-mode local -> straight to on-node generation.
				ResignMode: SecureBootResignModeLocal,
				DB:         SecureBootKeyRef{KeyConfig: common.KeyConfig{StoreType: "tpm2"}},
			},
		},
	}

	if _, _, err := i.resolveSecureBootSigner(context.Background()); err == nil {
		t.Fatal("expected branch (c) on-node generation to be selected and fail fast for tpm2")
	}
}
