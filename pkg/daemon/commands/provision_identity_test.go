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

package commands

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasacme "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmscertstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// errFake is the typed error the fakes return for simulated failures.
type errFake struct{ op string }

func (e errFake) Error() string { return "fake: simulated " + e.op + " failure" }

// testRoot is a self-signed ECDSA root CA shared by the fakes.
type testRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestRoot builds a self-signed root CA.
func newTestRoot(t *testing.T) *testRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return &testRoot{cert: cert, key: key}
}

// pool returns a cert pool holding only the root.
func (r *testRoot) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(r.cert)
	return pool
}

// sign issues a leaf for pub signed by the root.
func (r *testRoot) sign(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, pub, r.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// keystoreSigner is the fake keystore's handle to a private key. Like a
// real keystore signer it exposes only Public and Sign, so a test can
// tell a keystore-held key apart from one parsed out of PEM bytes.
type keystoreSigner struct {
	key *ecdsa.PrivateKey
}

func (s *keystoreSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *keystoreSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

// fakeKeystoreCA is an in-memory stand-in for the platform CA and its
// keystore. It embeds the CA interface so it can sit in app.App.CA; only
// the methods the daemon identity path calls are implemented.
type fakeKeystoreCA struct {
	quicbaasca.CACertificateAuthority

	root        *testRoot
	notAfterOff time.Duration

	keys  map[string]*keystoreSigner
	certs map[string]*x509.Certificate

	unavailable  bool  // every keystore operation fails
	issueErr     error // IssueCertificate fails
	loadErr      error // TLSCertificate fails
	lookupErr    error // Certificate fails
	revokeErr    error // RevokeCert fails
	deleteKeyErr error // KeyStore().DeleteKey fails
	poolErr      error // CABundleCertPool fails
	bundleErr    error // CABundle fails

	// onDeleteKey, when set, runs as KeyStore().DeleteKey removes the key
	// of a slot, so a test can see what was serving at that moment.
	onDeleteKey func(cn string)

	issueCalls  int
	revokeCalls int
	revoked     []*big.Int // serials passed to a successful RevokeCert
	deletedKeys []string   // slots whose key KeyStore().DeleteKey removed
	nextSerial  int64
}

// newFakeKeystoreCA returns an empty keystore CA over a fresh root.
func newFakeKeystoreCA(t *testing.T) *fakeKeystoreCA {
	t.Helper()
	return &fakeKeystoreCA{
		root:        newTestRoot(t),
		notAfterOff: 365 * 24 * time.Hour,
		keys:        map[string]*keystoreSigner{},
		certs:       map[string]*x509.Certificate{},
		nextSerial:  100,
	}
}

func (f *fakeKeystoreCA) CABundleCertPool() (*x509.CertPool, error) {
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	return f.root.pool(), nil
}

func (f *fakeKeystoreCA) CABundle() ([]byte, error) {
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.cert.Raw}), nil
}

func (f *fakeKeystoreCA) TrustedIntermediate() (*x509.Certificate, error) {
	return nil, errFake{op: "intermediate lookup"}
}

// IssueCertificate mirrors the CA: it refuses a CN that already holds a
// certificate, reuses the keystore key for the CN or generates one, and
// returns no key material.
func (f *fakeKeystoreCA) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	f.issueCalls++
	if f.unavailable {
		return nil, errFake{op: "keystore issue"}
	}
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	cn := req.KeyAttributes.CN
	if _, exists := f.certs[cn]; exists {
		return nil, errFake{op: "certificate already exists"}
	}
	signer, ok := f.keys[cn]
	if !ok {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = &keystoreSigner{key: key}
		f.keys[cn] = signer
	}
	var ips []net.IP
	for _, s := range req.SANS.IPs {
		ips = append(ips, net.ParseIP(s))
	}
	f.nextSerial++
	now := time.Now()
	cert, err := f.root.sign(&x509.Certificate{
		SerialNumber: big.NewInt(f.nextSerial),
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		DNSNames:     req.SANS.DNS,
		IPAddresses:  ips,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(f.notAfterOff),
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
	}, signer.Public())
	if err != nil {
		return nil, err
	}
	f.certs[cn] = cert
	return &quicbaasca.IssuedCertificate{Certificate: cert, SerialNumber: cert.SerialNumber}, nil
}

// TLSCertificate returns the keystore signer and certificate for the CN.
// Leaf is left unset so the caller's leaf parsing is exercised.
func (f *fakeKeystoreCA) TLSCertificate(_ context.Context, attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	if f.unavailable {
		return tls.Certificate{}, errFake{op: "keystore load"}
	}
	if f.loadErr != nil {
		return tls.Certificate{}, f.loadErr
	}
	signer, hasKey := f.keys[attrs.CN]
	cert, hasCert := f.certs[attrs.CN]
	if !hasKey || !hasCert {
		return tls.Certificate{}, errFake{op: "tls certificate not found"}
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: signer}, nil
}

// RevokeCert records the revocation. Like the CA it refuses a serial it
// already recorded, and without DeleteKeys it deletes nothing; the daemon
// identity path never asks it to.
func (f *fakeKeystoreCA) RevokeCert(_ context.Context, cert *x509.Certificate, _ quicbaasca.RevokeOptions) error {
	f.revokeCalls++
	if f.revokeErr != nil {
		return f.revokeErr
	}
	if f.isRevoked(cert.SerialNumber) {
		return errFake{op: "already revoked"}
	}
	f.revoked = append(f.revoked, cert.SerialNumber)
	return nil
}

func (f *fakeKeystoreCA) IsRevoked(serial *big.Int) (bool, error) {
	return f.isRevoked(serial), nil
}

func (f *fakeKeystoreCA) isRevoked(serial *big.Int) bool {
	for _, revoked := range f.revoked {
		if revoked.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func (f *fakeKeystoreCA) KeyStore() xkmsbackend.Backend { return &fakeKeyBackend{ca: f} }

func (f *fakeKeystoreCA) CertStore() xkmscertstore.CertStore { return &fakeCertStore{ca: f} }

// fakeKeyBackend is the fake CA's keystore as KeyStore exposes it. Only the
// calls a slot retirement makes are implemented. Like a real keystore it
// finds a key only under the attributes it was generated with, so a delete
// that names the key by CN alone finds nothing.
type fakeKeyBackend struct {
	xkmsbackend.Backend
	ca *fakeKeystoreCA
}

func (b *fakeKeyBackend) GetKey(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	signer, ok := b.ca.keys[attrs.CN]
	if !ok || attrs.KeyType != xkmssdk.KeyTypeTLS || attrs.StoreType != xkmssdk.StoreSoftware {
		return nil, errFake{op: "key not found"}
	}
	return signer, nil
}

func (b *fakeKeyBackend) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	if b.ca.deleteKeyErr != nil {
		return b.ca.deleteKeyErr
	}
	if _, err := b.GetKey(ctx, attrs); err != nil {
		return err
	}
	if b.ca.onDeleteKey != nil {
		b.ca.onDeleteKey(attrs.CN)
	}
	delete(b.ca.keys, attrs.CN)
	b.ca.deletedKeys = append(b.ca.deletedKeys, attrs.CN)
	return nil
}

// GetCert and DeleteCert find nothing: the fake keystore keeps no
// certificates of its own, as a keystore that left them to the cert store.
func (b *fakeKeyBackend) GetCert(context.Context, string) (*x509.Certificate, error) {
	return nil, errFake{op: "keystore certificate not found"}
}

func (b *fakeKeyBackend) DeleteCert(context.Context, string) error {
	return errFake{op: "keystore certificate not found"}
}

// fakeCertStore is the fake CA's cert store as CertStore exposes it.
type fakeCertStore struct {
	xkmscertstore.CertStore
	ca *fakeKeystoreCA
}

func (s *fakeCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	cert, ok := s.ca.certs[cn]
	if !ok {
		return nil, errFake{op: "certificate not found"}
	}
	return cert, nil
}

func (s *fakeCertStore) DeleteCertificate(cn string) error {
	if _, ok := s.ca.certs[cn]; !ok {
		return errFake{op: "certificate not found"}
	}
	delete(s.ca.certs, cn)
	return nil
}

// SignCSR signs a CSR with the root; localCACertIssuer uses it for the
// admin bootstrap certificate.
func (f *fakeKeystoreCA) SignCSR(_ context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errFake{op: "csr decode"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	f.nextSerial++
	now := time.Now()
	cert, err := f.root.sign(&x509.Certificate{
		SerialNumber: big.NewInt(f.nextSerial),
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}, csr.PublicKey)
	if err != nil {
		return nil, err
	}
	// Like the real CA, SignCSR persists the certificate in the cert store
	// under its CN. The key stays wherever the CSR's author keeps it.
	f.certs[cert.Subject.CommonName] = cert
	return cert, nil
}

// Certificate reads the cert store alone, as the real CA does: it never
// needs the private key. A missing entry is the CA's not-found sentinel.
func (f *fakeKeystoreCA) Certificate(_ context.Context, attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	cert, ok := f.certs[attrs.CN]
	if !ok {
		return nil, quicbaasacme.CAErrCertificateNotFound
	}
	return cert, nil
}

// signerOf returns the keystore signer held for the slot leaf names.
func (f *fakeKeystoreCA) signerOf(leaf *x509.Certificate) *keystoreSigner {
	return f.keys[leaf.Subject.CommonName]
}

// =============================================================================
// Helpers
// =============================================================================

// newTestLogger returns a logger that discards output so tests stay quiet.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

// readFile reads a file the test expects to exist.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// provisionFixture is a fresh CA and output directory.
type provisionFixture struct {
	ca   *fakeKeystoreCA
	dir  string
	sans daemonSANs
}

func newProvisionFixture(t *testing.T) *provisionFixture {
	t.Helper()
	ca := newFakeKeystoreCA(t)
	return &provisionFixture{
		ca:   ca,
		dir:  t.TempDir(),
		sans: daemonSANs{DNS: []string{"unit-test.example"}},
	}
}

func (p *provisionFixture) provision(t *testing.T) (*ProvisionedIdentity, error) {
	t.Helper()
	return provisionDaemonIdentity(context.Background(), newTestLogger(), p.ca, p.dir, p.sans)
}

// assertNoServerKeyOnDisk fails when any file under dir holds a private
// key whose public half is the daemon server key's.
func assertNoServerKeyOnDisk(t *testing.T, dir string, serverPub crypto.PublicKey) {
	t.Helper()
	want, ok := serverPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("server public key is %T, want *ecdsa.PublicKey", serverPub)
	}
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if d.Name() == "server-bundle.pem" {
			t.Errorf("server bundle written to disk: %s", path)
		}
		rest := readFile(t, path)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil
			}
			if key, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil && key.PublicKey.Equal(want) {
				t.Errorf("daemon server private key written to %s", path)
			}
			if key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
				if ec, isEC := key.(*ecdsa.PrivateKey); isEC && ec.PublicKey.Equal(want) {
					t.Errorf("daemon server private key written to %s", path)
				}
			}
		}
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", dir, walkErr)
	}
}

// =============================================================================
// provisionDaemonIdentity
// =============================================================================

func TestProvisionDaemonIdentity_ServerKeyStaysInKeystore(t *testing.T) {
	p := newProvisionFixture(t)

	id, err := p.provision(t)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Reused {
		t.Error("expected Reused=false for fresh issuance")
	}
	if id.ServerCert.Leaf == nil {
		t.Fatal("expected a server leaf")
	}
	if cn := id.ServerCert.Leaf.Subject.CommonName; cn != daemonServerCN && cn != daemonServerAltCN {
		t.Fatalf("server leaf CN %q names no keystore slot", cn)
	}
	signer := p.ca.signerOf(id.ServerCert.Leaf)
	if signer == nil {
		t.Fatal("keystore holds no daemon server key after issuance")
	}
	if id.ServerCert.PrivateKey != crypto.PrivateKey(signer) {
		t.Errorf("server certificate key is %T, want the keystore signer", id.ServerCert.PrivateKey)
	}
	if !certCoversDNSNames(id.ServerCert.Leaf, []string{"localhost", daemonServerCN, "unit-test.example"}) {
		t.Errorf("server leaf DNS SANs = %v", id.ServerCert.Leaf.DNSNames)
	}
	if id.AdminTrustPool == nil {
		t.Error("expected AdminTrustPool populated")
	}
	wantBundle, err := p.ca.CABundle()
	if err != nil {
		t.Fatalf("ca bundle: %v", err)
	}
	if !bytes.Equal(readFile(t, id.CABundlePath), wantBundle) {
		t.Error("ca-bundle.crt does not hold the CA bundle")
	}
	assertNoServerKeyOnDisk(t, p.dir, signer.Public())
	if p.ca.issueCalls != 1 {
		t.Errorf("server issue calls = %d, want 1", p.ca.issueCalls)
	}
}

func TestProvisionDaemonIdentity_ReusesKeystoreIdentity(t *testing.T) {
	p := newProvisionFixture(t)

	first, err := p.provision(t)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	second, err := p.provision(t)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if !second.Reused {
		t.Error("expected Reused=true on second provision")
	}
	if p.ca.issueCalls != 1 {
		t.Errorf("server issue calls after reuse = %d, want 1", p.ca.issueCalls)
	}
	if p.ca.revokeCalls != 0 {
		t.Errorf("a reused identity must not be revoked, revoke calls = %d", p.ca.revokeCalls)
	}
	if second.ServerCert.Leaf.SerialNumber.Cmp(first.ServerCert.Leaf.SerialNumber) != 0 {
		t.Error("server certificate changed across reuse")
	}
}

func TestProvisionDaemonIdentity_RenewsNearExpiryIntoTheOtherSlot(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.notAfterOff = 10 * 24 * time.Hour // inside the 30-day renewal window

	first, err := p.provision(t)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	staleCN := first.ServerCert.Leaf.Subject.CommonName
	p.ca.notAfterOff = 365 * 24 * time.Hour

	second, err := p.provision(t)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if second.Reused {
		t.Error("expected Reused=false when the held cert is near expiry")
	}
	if second.ServerCert.Leaf.Subject.CommonName != otherDaemonServerSlot(staleCN) {
		t.Errorf("renewed into slot %q, want the other slot %q",
			second.ServerCert.Leaf.Subject.CommonName, otherDaemonServerSlot(staleCN))
	}
	if p.ca.revokeCalls != 1 || p.ca.issueCalls != 2 {
		t.Errorf("revoke %d / issue %d calls, want 1 / 2", p.ca.revokeCalls, p.ca.issueCalls)
	}
	if !p.ca.isRevoked(first.ServerCert.Leaf.SerialNumber) {
		t.Error("the stale certificate was not revoked")
	}
	if p.ca.keys[staleCN] != nil || p.ca.certs[staleCN] != nil {
		t.Error("the stale slot must be emptied: its key and certificate deleted")
	}
	if second.ServerCert.PrivateKey != crypto.PrivateKey(p.ca.signerOf(second.ServerCert.Leaf)) {
		t.Error("re-issued certificate does not use the keystore signer")
	}
}

func TestProvisionDaemonIdentity_SupersedesWhenSANsChange(t *testing.T) {
	p := newProvisionFixture(t)
	if _, err := p.provision(t); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	p.sans = daemonSANs{DNS: []string{"unit-test.example", "new-host.example"}}
	second, err := p.provision(t)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if second.Reused {
		t.Error("expected Reused=false when required SANs grew")
	}
	if !certCoversDNSNames(second.ServerCert.Leaf, []string{"new-host.example"}) {
		t.Errorf("re-issued SANs = %v", second.ServerCert.Leaf.DNSNames)
	}
}

// TestProvisionDaemonIdentity_WritesNoAdminCredential asserts the daemon
// leaves only the public CA bundle on disk: the /init reply is the one
// admin credential (docs/bootstrap/cli.md §1a).
func TestProvisionDaemonIdentity_WritesNoAdminCredential(t *testing.T) {
	p := newProvisionFixture(t)
	if _, err := p.provision(t); err != nil {
		t.Fatalf("provision: %v", err)
	}
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca-bundle.crt" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("tls dir holds %v, want only ca-bundle.crt", names)
	}
}

func TestDaemonTLSDir_UnderPlatformDir(t *testing.T) {
	for _, platformDir := range []string{"/var/lib/trusted-platform", "/srv/tp"} {
		want := filepath.Join(platformDir, "tls")
		if got := daemonTLSDir(platformDir); got != want {
			t.Errorf("daemonTLSDir(%q) = %q, want %q", platformDir, got, want)
		}
	}
}

func TestProvisionDaemonIdentity_KeystoreUnavailable(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.unavailable = true

	id, err := p.provision(t)
	var typed ErrTLSIdentityKeystore
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityKeystore, got %T (%v)", err, err)
	}
	if typed.Op != "issue" {
		t.Errorf("Op = %q, want issue", typed.Op)
	}
	if id != nil {
		t.Error("expected no identity when the keystore is unavailable")
	}
	entries, readErr := os.ReadDir(p.dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("a keystore failure must write nothing, found %d files", len(entries))
	}
}

func TestProvisionDaemonIdentity_KeystoreLoadFails(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.loadErr = errFake{op: "keystore load"}

	_, err := p.provision(t)
	var typed ErrTLSIdentityKeystore
	if !errors.As(err, &typed) || typed.Op != "load" {
		t.Fatalf("expected ErrTLSIdentityKeystore{Op: load}, got %T (%v)", err, err)
	}
	if !errors.Is(err, p.ca.loadErr) {
		t.Error("ErrTLSIdentityKeystore must unwrap to the keystore cause")
	}
}

// TestProvisionDaemonIdentity_RetireFailureServesTheNewIdentity asserts a
// stale slot that cannot be retired does not fail boot: the new identity is
// already issued, and the next provision retires the stale slot.
func TestProvisionDaemonIdentity_RetireFailureServesTheNewIdentity(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.notAfterOff = 10 * 24 * time.Hour
	first, err := p.provision(t)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	staleCN := first.ServerCert.Leaf.Subject.CommonName
	staleSigner := p.ca.signerOf(first.ServerCert.Leaf)
	p.ca.notAfterOff = 365 * 24 * time.Hour
	p.ca.revokeErr = errFake{op: "revoke"}

	second, err := p.provision(t)
	if err != nil {
		t.Fatalf("a stale slot that cannot be retired must not fail boot: %v", err)
	}
	if second.ServerCert.Leaf.Subject.CommonName == staleCN {
		t.Fatal("the stale identity was served instead of the new one")
	}
	if p.ca.keys[staleCN] != staleSigner {
		t.Error("a failed retirement must leave the stale key in place")
	}

	p.ca.revokeErr = nil
	third, err := p.provision(t)
	if err != nil {
		t.Fatalf("third provision: %v", err)
	}
	if !third.Reused {
		t.Error("expected the new identity to be reused")
	}
	if p.ca.keys[staleCN] != nil || p.ca.certs[staleCN] != nil {
		t.Error("the next provision must retire the stale slot")
	}
}

// seedLegacyIdentity leaves the CA the way the pre-#33 provisioner did: the
// server key was generated outside the keystore and kept only in a PEM
// bundle, and SignCSR persisted its certificate in the CA cert store.
func seedLegacyIdentity(t *testing.T, ca *fakeKeystoreCA) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("legacy key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: daemonServerCN},
		DNSNames: []string{"localhost", daemonServerCN},
	}, key)
	if err != nil {
		t.Fatalf("legacy csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	cert, err := ca.SignCSR(context.Background(), csrPEM, &quicbaasca.SignOptions{
		ValidityDays: 365,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("legacy SignCSR: %v", err)
	}
	return cert
}

func TestProvisionDaemonIdentity_MigratesLegacyPEMIdentity(t *testing.T) {
	p := newProvisionFixture(t)
	legacy := seedLegacyIdentity(t, p.ca)

	id, err := p.provision(t)
	if err != nil {
		t.Fatalf("provision over a legacy identity: %v", err)
	}
	if id.Reused {
		t.Error("a legacy identity has no keystore key and must not be reused")
	}
	if len(p.ca.revoked) != 1 || p.ca.revoked[0].Cmp(legacy.SerialNumber) != 0 {
		t.Errorf("revoked serials = %v, want the legacy serial %v", p.ca.revoked, legacy.SerialNumber)
	}
	signer := p.ca.signerOf(id.ServerCert.Leaf)
	if signer == nil {
		t.Fatal("keystore holds no daemon server key after migration")
	}
	if id.ServerCert.PrivateKey != crypto.PrivateKey(signer) {
		t.Errorf("server certificate key is %T, want the keystore signer", id.ServerCert.PrivateKey)
	}
	leafKey, ok := id.ServerCert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(signer.Public()) {
		t.Error("issued certificate does not carry the keystore key")
	}
	if id.ServerCert.Leaf.SerialNumber.Cmp(legacy.SerialNumber) == 0 {
		t.Error("the legacy certificate was served instead of a fresh one")
	}
	assertNoServerKeyOnDisk(t, p.dir, signer.Public())

	again, err := p.provision(t)
	if err != nil {
		t.Fatalf("provision after migration: %v", err)
	}
	if !again.Reused || p.ca.issueCalls != 1 || p.ca.revokeCalls != 1 {
		t.Errorf("after migration: reused=%v issue=%d revoke=%d; want true, 1, 1",
			again.Reused, p.ca.issueCalls, p.ca.revokeCalls)
	}
}

func TestProvisionDaemonIdentity_LegacyRetireFailureServesTheNewIdentity(t *testing.T) {
	p := newProvisionFixture(t)
	legacy := seedLegacyIdentity(t, p.ca)
	p.ca.revokeErr = errFake{op: "revoke"}

	id, err := p.provision(t)
	if err != nil {
		t.Fatalf("a legacy certificate that cannot be retired must not fail boot: %v", err)
	}
	if id.ServerCert.Leaf.SerialNumber.Cmp(legacy.SerialNumber) == 0 {
		t.Fatal("the legacy certificate was served instead of a fresh one")
	}
	if id.ServerCert.PrivateKey != crypto.PrivateKey(p.ca.signerOf(id.ServerCert.Leaf)) {
		t.Error("the fresh identity does not use the keystore signer")
	}
	if p.ca.certs[daemonServerCN] != legacy {
		t.Error("a failed retirement must leave the legacy certificate in place")
	}

	p.ca.revokeErr = nil
	again, err := p.provision(t)
	if err != nil {
		t.Fatalf("provision after the failed retirement: %v", err)
	}
	if !again.Reused || p.ca.certs[daemonServerCN] != nil {
		t.Errorf("the next provision must reuse the fresh identity and retire the legacy one: reused=%v", again.Reused)
	}
}

func TestProvisionDaemonIdentity_CertificateLookupFails(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.lookupErr = errFake{op: "cert store read"}

	_, err := p.provision(t)
	var typed ErrTLSIdentityKeystore
	if !errors.As(err, &typed) || typed.Op != "retire" {
		t.Fatalf("expected ErrTLSIdentityKeystore{Op: retire}, got %T (%v)", err, err)
	}
	if !errors.Is(err, p.ca.lookupErr) {
		t.Error("ErrTLSIdentityKeystore must unwrap to the lookup cause")
	}
	if p.ca.issueCalls != 0 {
		t.Errorf("a failed lookup must issue nothing, issue calls = %d", p.ca.issueCalls)
	}
}

func TestProvisionDaemonIdentity_ErrorsWhenCANil(t *testing.T) {
	_, err := provisionDaemonIdentity(context.Background(), newTestLogger(), nil, t.TempDir(), daemonSANs{})
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA, got %T (%v)", err, err)
	}
}

func TestProvisionDaemonIdentity_TrustPoolError(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.poolErr = errFake{op: "trust pool"}

	_, err := p.provision(t)
	var typed ErrProvisionIssue
	if !errors.As(err, &typed) || typed.Role != "trust-pool" {
		t.Fatalf("expected ErrProvisionIssue{Role: trust-pool}, got %T (%v)", err, err)
	}
}

func TestProvisionDaemonIdentity_CABundleError(t *testing.T) {
	p := newProvisionFixture(t)
	p.ca.bundleErr = errFake{op: "ca bundle"}

	_, err := p.provision(t)
	var typed ErrProvisionIssue
	if !errors.As(err, &typed) || typed.Role != "ca-bundle" {
		t.Fatalf("expected ErrProvisionIssue{Role: ca-bundle}, got %T (%v)", err, err)
	}
}

func TestProvisionDaemonIdentity_PersistFailureSurfaced(t *testing.T) {
	// The output "directory" is a regular file, so no bundle can be written.
	p := newProvisionFixture(t)
	p.dir = filepath.Join(t.TempDir(), "ro")
	if err := os.WriteFile(p.dir, []byte("x"), 0600); err != nil {
		t.Fatalf("seed not-a-dir: %v", err)
	}

	_, err := p.provision(t)
	var typed ErrProvisionPersist
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionPersist, got %T (%v)", err, err)
	}
}

// =============================================================================
// Helpers of provisionDaemonIdentity
// =============================================================================

func TestDaemonServerCertRequest_KeyGeneratedInKeystore(t *testing.T) {
	req := daemonServerCertRequest(daemonServerCN, []string{"a.example"}, []string{"10.0.0.1"})
	if req.KeyAttributes == nil {
		t.Fatal("the request must carry KeyAttributes so the CA generates the key in its keystore")
	}
	if req.Signer != nil {
		t.Error("the request must not carry a caller-held signer")
	}
	if req.KeyAttributes.CN != daemonServerCN || req.Subject.CommonName != daemonServerCN {
		t.Errorf("CN mismatch: attrs %q, subject %q", req.KeyAttributes.CN, req.Subject.CommonName)
	}
	if req.KeyAttributes.KeyType != xkmssdk.KeyTypeTLS {
		t.Errorf("KeyType = %v, want TLS", req.KeyAttributes.KeyType)
	}
	if len(req.SANS.IPs) != 1 || req.SANS.IPs[0] != "10.0.0.1" {
		t.Errorf("IP SANs = %v", req.SANS.IPs)
	}
}

// provisionedSlot provisions a fresh identity and returns the slot it is in.
func provisionedSlot(t *testing.T, p *provisionFixture) (string, *x509.Certificate) {
	t.Helper()
	id, err := p.provision(t)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	return id.ServerCert.Leaf.Subject.CommonName, id.ServerCert.Leaf
}

func TestRetireDaemonServerSlot_RevokesAndDeletesTheKeyUnderItsOwnID(t *testing.T) {
	p := newProvisionFixture(t)
	cn, leaf := provisionedSlot(t, p)

	if err := retireDaemonServerSlot(context.Background(), newTestLogger(), p.ca, cn); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if !p.ca.isRevoked(leaf.SerialNumber) {
		t.Error("the retired certificate was not revoked")
	}
	// The fake keystore finds the key only under the attributes it was
	// generated with, as RevokeCert's DeleteKeys does not name it.
	if p.ca.keys[cn] != nil || len(p.ca.deletedKeys) != 1 || p.ca.deletedKeys[0] != cn {
		t.Errorf("the slot key was not deleted under its own ID: deleted %v", p.ca.deletedKeys)
	}
	if p.ca.certs[cn] != nil {
		t.Error("the retired certificate is still in the cert store")
	}
	if err := retireDaemonServerSlot(context.Background(), newTestLogger(), p.ca, cn); err != nil {
		t.Errorf("retiring an empty slot must succeed: %v", err)
	}
}

func TestRetireDaemonServerSlot_FinishesARetirementAlreadyRevoked(t *testing.T) {
	p := newProvisionFixture(t)
	cn, leaf := provisionedSlot(t, p)
	p.ca.revoked = append(p.ca.revoked, leaf.SerialNumber)

	if err := retireDaemonServerSlot(context.Background(), newTestLogger(), p.ca, cn); err != nil {
		t.Fatalf("a slot revoked by an earlier attempt must still be emptied: %v", err)
	}
	if p.ca.revokeCalls != 0 {
		t.Errorf("a recorded revocation must not be recorded again, revoke calls = %d", p.ca.revokeCalls)
	}
	if p.ca.keys[cn] != nil || p.ca.certs[cn] != nil {
		t.Error("the slot was not emptied")
	}
}

func TestRetireDaemonServerSlot_KeyDeleteFailureKeepsTheSlotForTheRetry(t *testing.T) {
	p := newProvisionFixture(t)
	cn, _ := provisionedSlot(t, p)
	p.ca.deleteKeyErr = errFake{op: "delete key"}

	err := retireDaemonServerSlot(context.Background(), newTestLogger(), p.ca, cn)
	var typed ErrTLSIdentityKeystore
	if !errors.As(err, &typed) || typed.Op != "retire" || !errors.Is(err, p.ca.deleteKeyErr) {
		t.Fatalf("expected ErrTLSIdentityKeystore{Op: retire} wrapping the delete failure, got %v", err)
	}
	if p.ca.certs[cn] == nil {
		t.Error("the cert-store entry must stay so the next attempt finds the slot")
	}
}

func TestRemoveSlotItem(t *testing.T) {
	failure := errFake{op: "remove"}
	present := func() error { return nil }
	absent := func() error { return errFake{op: "not found"} }

	if err := removeSlotItem(func() error { return nil }, present); err != nil {
		t.Errorf("a successful remove must succeed: %v", err)
	}
	if err := removeSlotItem(func() error { return failure }, absent); err != nil {
		t.Errorf("a failed remove of an absent item is done: %v", err)
	}
	if err := removeSlotItem(func() error { return failure }, present); !errors.Is(err, failure) {
		t.Errorf("a failed remove of an item still present must fail, got %v", err)
	}
}

func TestDaemonServerCertCurrent(t *testing.T) {
	root := newTestRoot(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	leaf, err := root.sign(&x509.Certificate{
		SerialNumber: big.NewInt(7),
		DNSNames:     []string{"a.example"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	logger := newTestLogger()

	if !daemonServerCertCurrent(logger, leaf, root.pool(), []string{"a.example"}) {
		t.Error("a valid, covering, chaining certificate must be current")
	}
	if daemonServerCertCurrent(logger, nil, root.pool(), nil) {
		t.Error("a missing leaf must not be current")
	}
	if daemonServerCertCurrent(logger, leaf, root.pool(), []string{"b.example"}) {
		t.Error("a certificate missing a required SAN must not be current")
	}
	if daemonServerCertCurrent(logger, leaf, newTestRoot(t).pool(), nil) {
		t.Error("a certificate from a foreign root must not be current")
	}
}

func TestTLSCertificateLeaf(t *testing.T) {
	root := newTestRoot(t)
	populated := tls.Certificate{Leaf: root.cert}
	if tlsCertificateLeaf(populated) != root.cert {
		t.Error("a populated Leaf must be returned as is")
	}
	parsed := tlsCertificateLeaf(tls.Certificate{Certificate: [][]byte{root.cert.Raw}})
	if parsed == nil || !parsed.Equal(root.cert) {
		t.Error("the leaf must be parsed from the first chain entry")
	}
	if tlsCertificateLeaf(tls.Certificate{}) != nil {
		t.Error("an empty chain has no leaf")
	}
	if tlsCertificateLeaf(tls.Certificate{Certificate: [][]byte{[]byte("not der")}}) != nil {
		t.Error("an unparseable chain has no leaf")
	}
}

// fakeIntermediate is an intermediateProvider returning a fixed result.
type fakeIntermediate struct {
	cert *x509.Certificate
	err  error
}

func (f fakeIntermediate) TrustedIntermediate() (*x509.Certificate, error) { return f.cert, f.err }

func TestAppendTrustedIntermediate(t *testing.T) {
	inter := newTestRoot(t).cert
	leafOnly := tls.Certificate{Certificate: [][]byte{[]byte("leaf")}}

	got := appendTrustedIntermediate(fakeIntermediate{cert: inter}, leafOnly)
	if len(got.Certificate) != 2 || !bytes.Equal(got.Certificate[1], inter.Raw) {
		t.Errorf("expected the intermediate appended, chain length %d", len(got.Certificate))
	}
	got = appendTrustedIntermediate(fakeIntermediate{err: errFake{op: "intermediate"}}, leafOnly)
	if len(got.Certificate) != 1 {
		t.Error("a pure-root CA must leave the chain unchanged")
	}
	full := tls.Certificate{Certificate: [][]byte{[]byte("leaf"), []byte("inter")}}
	if len(appendTrustedIntermediate(fakeIntermediate{cert: inter}, full).Certificate) != 2 {
		t.Error("a chain that already carries an intermediate must be left unchanged")
	}
}

func TestErrTLSIdentityKeystore_Unwraps(t *testing.T) {
	cause := errFake{op: "keystore"}
	err := ErrTLSIdentityKeystore{Op: "issue", Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("ErrTLSIdentityKeystore must unwrap to its cause")
	}
	if err.Error() == "" || (ErrTLSIdentityRequiresPlatformDir{}).Error() == "" {
		t.Error("typed errors must describe themselves")
	}
}

func TestCertWithinRenewalWindow(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"already expired", now.Add(-time.Hour), false},
		{"inside renewal window", now.Add(10 * 24 * time.Hour), false},
		{"outside renewal window", now.Add(60 * 24 * time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := &x509.Certificate{NotAfter: tc.notAfter}
			got := certWithinRenewalWindow(leaf, renewalThreshold)
			if got != tc.want {
				t.Errorf("certWithinRenewalWindow(%v) = %v, want %v", tc.notAfter, got, tc.want)
			}
		})
	}
}

func TestCertCoversDNSNames(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"a.example", "b.example"}}
	if !certCoversDNSNames(leaf, []string{"a.example"}) {
		t.Error("expected required subset to be covered")
	}
	if !certCoversDNSNames(leaf, nil) {
		t.Error("empty required slice should always be covered")
	}
	if certCoversDNSNames(leaf, []string{"c.example"}) {
		t.Error("missing required name should not be covered")
	}
}

func TestDaemonCertSANs_AddsLoopback(t *testing.T) {
	dns, ips := daemonCertSANs(daemonSANs{DNS: []string{"node-01"}, IPs: []string{"10.0.0.1"}})
	wantDNS := []string{"localhost", "platformd.localhost", "node-01"}
	if len(dns) != len(wantDNS) {
		t.Fatalf("dns len = %d, want %d", len(dns), len(wantDNS))
	}
	for i, n := range wantDNS {
		if dns[i] != n {
			t.Errorf("dns[%d] = %s, want %s", i, dns[i], n)
		}
	}
	wantIPs := []string{"127.0.0.1", "::1", "10.0.0.1"}
	if len(ips) != len(wantIPs) {
		t.Fatalf("ips len = %d, want %d", len(ips), len(wantIPs))
	}
	for i, n := range wantIPs {
		if ips[i] != n {
			t.Errorf("ips[%d] = %s, want %s", i, ips[i], n)
		}
	}
}
