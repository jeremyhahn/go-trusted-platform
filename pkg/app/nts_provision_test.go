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

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ntsTestApp() *App {
	return &App{
		Logger:   logging.DefaultLogger(),
		Hostname: "cp-test",
		Domain:   "example.test",
		NTPConfig: &ntp.Config{
			Enabled: true,
			Serve: &ntp.ServeConfig{
				NTS: &ntp.NTSConfig{
					Enabled: true,
					CertURI: "kms://platform/ntp/nts-cert",
					KeyURI:  "kms://platform/ntp/nts-key",
				},
			},
		},
	}
}

// TestProvisionNTSKeys_Generates asserts the NTS keypair and self-signed
// certificate land in the KMS with parseable PEM material — the kms:// refs
// carry no ?ensure=true, so this pre-walk provisioning is the only thing
// standing between the fail-closed config walk and a daemon that never
// starts (#55).
func TestProvisionNTSKeys_Generates(t *testing.T) {
	app := ntsTestApp()
	store := newFakeSecretStore()

	require.NoError(t, app.provisionNTSKeys(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert"))

	certPEM, ok := store.get("platform/ntp/nts-cert")
	require.True(t, ok)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "cp-test.example.test", cert.Subject.CommonName)
	assert.Contains(t, cert.DNSNames, "cp-test")
	assert.Contains(t, cert.DNSNames, "cp-test.example.test")

	keyPEM, ok := store.get("platform/ntp/nts-key")
	require.True(t, ok)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
}

// TestProvisionNTSKeys_Idempotent asserts an existing key is left untouched.
func TestProvisionNTSKeys_Idempotent(t *testing.T) {
	app := ntsTestApp()
	store := newFakeSecretStore()

	require.NoError(t, app.provisionNTSKeys(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert"))
	first, _ := store.get("platform/ntp/nts-key")

	require.NoError(t, app.provisionNTSKeys(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert"))
	second, _ := store.get("platform/ntp/nts-key")
	assert.Equal(t, first, second, "existing key must not be regenerated")
	assert.Equal(t, 1, store.writes["platform/ntp/nts-key"])
}

// TestProvisionNTSKeys_CertOnlyStateReprovisions asserts a half-written
// pair — certificate present, key missing after a crash between the
// bootstrap writes — regenerates both.
func TestProvisionNTSKeys_CertOnlyStateReprovisions(t *testing.T) {
	app := ntsTestApp()
	store := newFakeSecretStore()

	// Simulate the crash window: certificate landed, key did not.
	_, err := store.StoreSecret(context.Background(), &baasservice.StoreSecretRequest{
		Name: "platform/ntp/nts-cert",
		Data: []byte("stale-cert-from-crashed-boot"),
	})
	require.NoError(t, err)

	require.NoError(t, app.provisionNTSKeys(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert"))

	keyPEM, ok := store.get("platform/ntp/nts-key")
	require.True(t, ok, "key must be provisioned")
	require.NotEmpty(t, keyPEM)
	certPEM, _ := store.get("platform/ntp/nts-cert")
	assert.NotEqual(t, []byte("stale-cert-from-crashed-boot"), certPEM,
		"the stale certificate must be replaced together with the new key")
}

// TestProvisionNTSKeys_Gates asserts the no-op and error gates of the outer
// entry point: disabled NTP/NTS and non-KMS URIs provision nothing; a mixed
// kms://-and-not pair is a typed error.
func TestProvisionNTSKeys_Gates(t *testing.T) {
	t.Run("nil NTP config is a no-op", func(t *testing.T) {
		app := ntsTestApp()
		app.NTPConfig = nil
		require.NoError(t, app.ProvisionNTSKeys(context.Background()))
	})

	t.Run("disabled NTP is a no-op", func(t *testing.T) {
		app := ntsTestApp()
		app.NTPConfig.Enabled = false
		require.NoError(t, app.ProvisionNTSKeys(context.Background()))
	})

	t.Run("disabled NTS is a no-op", func(t *testing.T) {
		app := ntsTestApp()
		app.NTPConfig.Serve.NTS.Enabled = false
		require.NoError(t, app.ProvisionNTSKeys(context.Background()))
	})

	t.Run("non-KMS URIs are a no-op", func(t *testing.T) {
		app := ntsTestApp()
		app.NTPConfig.Serve.NTS.CertURI = "file:///etc/nts.pem"
		app.NTPConfig.Serve.NTS.KeyURI = "file:///etc/nts.key"
		require.NoError(t, app.ProvisionNTSKeys(context.Background()))
	})

	t.Run("mixed KMS and non-KMS is a typed error", func(t *testing.T) {
		app := ntsTestApp()
		app.NTPConfig.Serve.NTS.CertURI = "file:///etc/nts.pem"
		err := app.ProvisionNTSKeys(context.Background())
		require.Error(t, err)
		var typed *ErrNTSProvision
		assert.ErrorAs(t, err, &typed)
	})
}

// TestRegisterNTSCertTarget asserts the renewal target registers with the
// upgrade semantics: Current reads the certificate chronyd actually serves,
// a self-signed current certificate is due immediately (the bootstrap→
// CA-issued upgrade), an unreadable NTS-KE endpoint is due for redeploy,
// and reissue without a CA is the typed error.
func TestRegisterNTSCertTarget(t *testing.T) {
	app := ntsTestApp()
	app.RegisterNTSCertTarget(context.Background())

	target, ok := app.certTargets().Get("nts-server")
	require.True(t, ok, "nts-server target must be registered")
	require.Equal(t, CertKindNTS, target.Kind)

	t.Run("self-signed current is due immediately", func(t *testing.T) {
		// Provision the bootstrap self-signed material and read it back
		// through the target's own Current... Current needs the live
		// SecretsService; assert the DueOverride contract directly with a
		// self-signed certificate instead.
		store := newFakeSecretStore()
		require.NoError(t, app.provisionNTSKeys(context.Background(), store,
			"platform/ntp/nts-key", "platform/ntp/nts-cert"))
		certPEM, _ := store.get("platform/ntp/nts-cert")
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)

		due, reason := target.DueOverride(context.Background(), cert, nil)
		require.True(t, due, "a self-signed bootstrap certificate must be due for CA upgrade")
		require.Contains(t, reason, "self-signed")
	})

	t.Run("unreadable NTS-KE endpoint is due for redeploy", func(t *testing.T) {
		// The target registers only when NTS serving is enabled, so an
		// endpoint that serves nothing readable means the identity never
		// deployed (or a torn KMS pair broke chronyd's TLS stack) — the
		// sweep must repair it, not re-fail forever.
		due, reason := target.DueOverride(context.Background(), nil, context.DeadlineExceeded)
		require.True(t, due)
		require.Contains(t, reason, "redeploying")
	})

	t.Run("reissue without a CA is the typed error", func(t *testing.T) {
		err := target.Reissue(context.Background())
		require.Error(t, err)
		var typed *ErrNTSProvision
		require.ErrorAs(t, err, &typed)
	})

	t.Run("disabled NTS registers nothing", func(t *testing.T) {
		app2 := ntsTestApp()
		app2.NTPConfig.Serve.NTS.Enabled = false
		app2.RegisterNTSCertTarget(context.Background())
		_, ok := app2.certTargets().Get("nts-server")
		require.False(t, ok)
	})
}

// TestRegisterNTSCertTarget_SurvivesSecretResolution reproduces the actual
// App.Init ordering (#57): ProvisionNTSKeys captures the kms:// object paths,
// then ProcessSecrets resolves the config fields in place to PEM, and only
// afterwards does initCertManagement register the target. Registration must
// come from the captured snapshot — deriving from the resolved config would
// silently register nothing.
func TestRegisterNTSCertTarget_SurvivesSecretResolution(t *testing.T) {
	app := ntsTestApp()

	// No secrets backend in a unit test: provisioning fails at the store
	// stage, but the path snapshot is captured first — the same state
	// App.Init reaches before ProcessSecrets runs.
	err := app.ProvisionNTSKeys(context.Background())
	var typed *ErrNTSProvision
	require.ErrorAs(t, err, &typed)

	// ProcessSecrets replaces the kms:// URIs with resolved PEM in place.
	app.NTPConfig.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	app.NTPConfig.Serve.NTS.KeyURI = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"

	app.RegisterNTSCertTarget(context.Background())
	_, ok := app.certTargets().Get("nts-server")
	require.True(t, ok, "registration must survive in-place secret resolution")
}

// TestNTSServedCertificate asserts Current's authority is the certificate
// the live NTS-KE endpoint serves, not the KMS copy.
func TestNTSServedCertificate(t *testing.T) {
	app := ntsTestApp()
	store := newFakeSecretStore()
	require.NoError(t, app.provisionNTSKeys(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert"))
	certPEM, _ := store.get("platform/ntp/nts-cert")
	keyPEM, _ := store.get("platform/ntp/nts-key")
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{ntsKEALPN},
	})
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	previous := ntsKEDialAddr
	ntsKEDialAddr = listener.Addr().String()
	defer func() { ntsKEDialAddr = previous }()

	served, err := ntsServedCertificate(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cp-test.example.test", served.Subject.CommonName)

	t.Run("unreachable endpoint is the typed error", func(t *testing.T) {
		listener.Close()
		_, err := ntsServedCertificate(context.Background())
		var typed *ErrNTSProvision
		require.ErrorAs(t, err, &typed)
	})
}

// fakeNTPApplier records deployment requests from certificate renewal.
type fakeNTPApplier struct {
	applies             int
	rotations           int
	rotatedKey          []byte
	rotatedCert         []byte
	rotatedEnclaveAlive bool
	err                 error
}

func (f *fakeNTPApplier) Apply(context.Context) error { f.applies++; return f.err }

// RotateNTSMaterial records what renewal handed the service. The key is
// read through the enclave's scoped borrow, exactly as the real service
// does, so the test exercises the protected-memory contract rather than
// working around it.
func (f *fakeNTPApplier) RotateNTSMaterial(_ context.Context, key *memguard.MemoryEnclave, certPEM []byte) error {
	f.rotations++
	f.rotatedEnclaveAlive = key.IsAlive()
	_ = key.Open(func(keyPEM []byte) error {
		f.rotatedKey = append([]byte(nil), keyPEM...)
		return nil
	})
	f.rotatedCert = append([]byte(nil), certPEM...)
	return f.err
}

func (f *fakeNTPApplier) WaitForSync(context.Context) error { return nil }

// TestDeployNTSMaterial asserts renewal deployment hands the new pair to
// the NTP service's serialized rotation — never mutating the shared
// NTPConfig — and that a deployment that cannot happen is a renewal
// failure, never a silent success.
func TestDeployNTSMaterial(t *testing.T) {
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n")
	// The enclave wipes the slice it is handed, so each subtest builds its
	// own from an untouched copy.
	newKeyEnclave := func() *memguard.MemoryEnclave {
		return memguard.NewMemoryEnclave(append([]byte(nil), keyPEM...))
	}

	t.Run("rotates through the service without touching config", func(t *testing.T) {
		app := ntsTestApp()
		applier := &fakeNTPApplier{}
		app.ntpApplier = applier

		enclave := newKeyEnclave()
		defer enclave.Destroy()
		require.NoError(t, app.deployNTSMaterial(context.Background(), enclave, certPEM))
		assert.Equal(t, 1, applier.rotations)
		assert.True(t, applier.rotatedEnclaveAlive,
			"renewal must hand the service a live enclave, not a destroyed one")
		assert.Equal(t, keyPEM, applier.rotatedKey)
		assert.Equal(t, certPEM, applier.rotatedCert)
		// The shared config must NOT be mutated: readers of NTPConfig
		// (API handlers, health) would otherwise race the renewal sweep.
		assert.Equal(t, "kms://platform/ntp/nts-key", app.NTPConfig.Serve.NTS.KeyURI)
		assert.Equal(t, "kms://platform/ntp/nts-cert", app.NTPConfig.Serve.NTS.CertURI)
	})

	t.Run("nil applier is a typed renewal failure", func(t *testing.T) {
		app := ntsTestApp()
		enclave := newKeyEnclave()
		defer enclave.Destroy()
		err := app.deployNTSMaterial(context.Background(), enclave, certPEM)
		var typed *ErrNTSProvision
		require.ErrorAs(t, err, &typed)
	})

	t.Run("rotation failure is a typed renewal failure", func(t *testing.T) {
		app := ntsTestApp()
		app.ntpApplier = &fakeNTPApplier{err: context.DeadlineExceeded}
		enclave := newKeyEnclave()
		defer enclave.Destroy()
		err := app.deployNTSMaterial(context.Background(), enclave, certPEM)
		var typed *ErrNTSProvision
		require.ErrorAs(t, err, &typed)
	})
}

// TestEnclaveNTSKey asserts the generated key ends up intact in protected
// memory. It deliberately does NOT assert that the caller's
// *ecdsa.PrivateKey was scrubbed: under Go 1.26 the scalar lives in an
// internal FIPS representation behind a package cache with no zeroization
// API, so that residue is a registered upstream gap (go-quicbaas#136 / #60),
// not something this layer can close.
func TestEnclaveNTSKey(t *testing.T) {
	t.Run("captures the generated key intact", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		want, err := key.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, want)

		enclave, err := enclaveNTSKey(key)
		require.NoError(t, err)
		defer enclave.Destroy()

		require.True(t, enclave.IsAlive())
		require.NoError(t, enclave.Open(func(keyPEM []byte) error {
			block, _ := pem.Decode(keyPEM)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, parseErr)
			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			require.True(t, ok)
			// The enclave must hold the key that was generated, byte for
			// byte — an enclave over the wrong or a truncated key would
			// fail the deployment far from here.
			got, bytesErr := ecKey.Bytes()
			require.NoError(t, bytesErr)
			assert.Equal(t, want, got)
			return nil
		}))
	})

	// The secret store may retain the Data slice it is handed — the fake
	// here does, and the SDK's retention is not this layer's to assume.
	// Handing it a view of locked memory therefore leaves it referencing
	// a region Destroy frees, which faults on the next read. The store
	// gets a copy; this test fails (segfault or corruption) if that
	// regresses to passing the borrow through.
	t.Run("the stored key outlives the enclave that produced it", func(t *testing.T) {
		store := newFakeSecretStore()
		enclave := memguard.NewMemoryEnclave(
			[]byte("-----BEGIN PRIVATE KEY-----\nSTORED\n-----END PRIVATE KEY-----\n"))
		meta := map[string]string{"kind": "private-key"}

		require.NoError(t, storeNTSKey(context.Background(), store,
			"platform/ntp/nts-key", "NTS server private key", enclave, meta))
		enclave.Destroy()

		data, ok := store.get("platform/ntp/nts-key")
		require.True(t, ok)
		assert.Equal(t,
			"-----BEGIN PRIVATE KEY-----\nSTORED\n-----END PRIVATE KEY-----\n",
			string(data))
	})

	t.Run("a key that cannot be marshalled is an error, not a dead enclave", func(t *testing.T) {
		// An unknown curve fails PKCS#8 marshalling, so the caller gets a
		// typed provisioning failure rather than an enclave holding
		// nothing.
		bad := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: nil, X: big.NewInt(1), Y: big.NewInt(2)},
			D:         big.NewInt(3), //nolint:staticcheck // SA1019: hand-building a deliberately invalid key
		}
		enclave, err := enclaveNTSKey(bad)
		require.Error(t, err)
		assert.Nil(t, enclave)
	})
}

// pathFailStore fails writes to one specific path, for torn-write tests.
type pathFailStore struct {
	*fakeSecretStore
	failPath string
}

func (p *pathFailStore) StoreSecret(ctx context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error) {
	if req.Name == p.failPath {
		return nil, errors.New("injected write failure")
	}
	return p.fakeSecretStore.StoreSecret(ctx, req)
}

// TestStoreNTSPair_KeyFirstTornWrite asserts the renewal pair is written key
// FIRST: a failure on the second (certificate) write leaves the served — and
// KMS — certificate stale, which keeps the renewal target due so the next
// sweep regenerates and redeploys the whole pair. Certificate-first would
// leave a fresh CA-issued certificate over the old key, which the sweep
// would wrongly consider healthy.
func TestStoreNTSPair_KeyFirstTornWrite(t *testing.T) {
	store := &pathFailStore{fakeSecretStore: newFakeSecretStore(), failPath: "platform/ntp/nts-cert"}
	meta := func(kind string) map[string]string { return map[string]string{"kind": kind} }

	keyEnclave := memguard.NewMemoryEnclave([]byte("new-key"))
	defer keyEnclave.Destroy()
	err := storeNTSPair(context.Background(), store,
		"platform/ntp/nts-key", "platform/ntp/nts-cert",
		keyEnclave, []byte("new-cert"), meta)
	var typed *ErrNTSProvision
	require.ErrorAs(t, err, &typed)

	keyData, keyStored := store.get("platform/ntp/nts-key")
	assert.True(t, keyStored, "the key write precedes the certificate write")
	// The enclave lends the store call a borrowed view; what the store
	// keeps must be the real key, not a buffer the borrow later wiped.
	assert.Equal(t, []byte("new-key"), keyData)
	_, certStored := store.get("platform/ntp/nts-cert")
	assert.False(t, certStored, "the certificate must not land before the key")
}

// fakeNTSCA satisfies the CA surface ntsServedCertInvalid touches. The
// interface is embedded (nil) so any other method panics loudly.
type fakeNTSCA struct {
	quicbaasca.CACertificateAuthority
	root *x509.Certificate
}

func (f *fakeNTSCA) TrustedRoot() (*x509.Certificate, error) { return f.root, nil }

func (f *fakeNTSCA) TrustedRootCertPool(*x509.Certificate) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	return pool, nil
}

func (f *fakeNTSCA) TrustedIntermediate() (*x509.Certificate, error) {
	return nil, errors.New("no intermediate")
}

// mintTestCA generates a CA certificate and a signer for leaf issuance.
func mintTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// mintLeaf issues a server-auth leaf for dnsName from the given CA.
func mintLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestNTSServedCertVerification asserts the sweep's health decision is a
// real trust decision (#57): only a platform-CA-issued certificate valid
// for the NTS hostname counts as healthy; wrong-host, foreign-CA and
// crafted self-signed identities are all due for repair.
func TestNTSServedCertVerification(t *testing.T) {
	caCert, caKey := mintTestCA(t, "platform-root")
	app := ntsTestApp()
	app.CA = &fakeNTSCA{root: caCert}
	app.RegisterNTSCertTarget(context.Background())
	target, ok := app.certTargets().Get("nts-server")
	require.True(t, ok)

	t.Run("platform-CA-issued cert for this host is healthy", func(t *testing.T) {
		leaf := mintLeaf(t, caCert, caKey, "cp-test.example.test")
		due, reason := target.DueOverride(context.Background(), leaf, nil)
		require.False(t, due, "valid identity must not be due: %s", reason)
	})

	t.Run("wrong hostname is due", func(t *testing.T) {
		leaf := mintLeaf(t, caCert, caKey, "other-host.example.test")
		due, reason := target.DueOverride(context.Background(), leaf, nil)
		require.True(t, due)
		require.Contains(t, reason, "not a valid platform identity")
	})

	t.Run("foreign CA is due", func(t *testing.T) {
		foreignCA, foreignKey := mintTestCA(t, "foreign-root")
		leaf := mintLeaf(t, foreignCA, foreignKey, "cp-test.example.test")
		due, reason := target.DueOverride(context.Background(), leaf, nil)
		require.True(t, due)
		require.Contains(t, reason, "not a valid platform identity")
	})

	t.Run("self-signed with crafted differing names is due for upgrade", func(t *testing.T) {
		// Subject and Issuer differ, but the signature verifies under the
		// certificate's own key: a name comparison would misclassify this
		// as CA-issued.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		issuerTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "pretend-issuer"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "cp-test.example.test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"cp-test.example.test"},
		}
		der, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &key.PublicKey, key)
		require.NoError(t, err)
		crafted, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		require.NotEqual(t, crafted.Subject.String(), crafted.Issuer.String())

		due, reason := target.DueOverride(context.Background(), crafted, nil)
		require.True(t, due)
		require.Contains(t, reason, "self-signed")
	})

	t.Run("nil platform CA is due", func(t *testing.T) {
		app2 := ntsTestApp()
		leaf := mintLeaf(t, caCert, caKey, "cp-test.example.test")
		reason, invalid := app2.ntsServedCertInvalid(leaf)
		require.True(t, invalid)
		require.Contains(t, reason, "platform CA unavailable")
	})
}

// requireCoherentNTSPair parses the stored pair and asserts the certificate
// public key matches the private key.
func requireCoherentNTSPair(t *testing.T, store *fakeSecretStore) {
	t.Helper()
	keyPEM, ok := store.get("platform/ntp/nts-key")
	require.True(t, ok)
	certPEM, ok := store.get("platform/ntp/nts-cert")
	require.True(t, ok)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	require.Equal(t, key.(*ecdsa.PrivateKey).PublicKey, *cert.PublicKey.(*ecdsa.PublicKey),
		"stored pair must be coherent")
}

// TestProvisionNTSKeys_TornStateReprovisions asserts the pair-coherence
// probe (#57): after a torn RENEWAL — the key-first write order means a
// failed certificate write leaves a new key beside the old certificate —
// the next daemon start re-provisions a coherent pair instead of resolving
// the mismatch into chronyd.
func TestProvisionNTSKeys_TornStateReprovisions(t *testing.T) {
	t.Run("mismatched pair after torn renewal", func(t *testing.T) {
		app := ntsTestApp()
		store := newFakeSecretStore()
		require.NoError(t, app.provisionNTSKeys(context.Background(), store,
			"platform/ntp/nts-key", "platform/ntp/nts-cert"))

		// Torn renewal: a NEW key landed, the certificate write failed.
		strayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		strayDER, err := x509.MarshalPKCS8PrivateKey(strayKey)
		require.NoError(t, err)
		_, err = store.StoreSecret(context.Background(), &baasservice.StoreSecretRequest{
			Name: "platform/ntp/nts-key",
			Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: strayDER}),
		})
		require.NoError(t, err)

		require.NoError(t, app.provisionNTSKeys(context.Background(), store,
			"platform/ntp/nts-key", "platform/ntp/nts-cert"))
		requireCoherentNTSPair(t, store)
	})

	t.Run("key without certificate", func(t *testing.T) {
		app := ntsTestApp()
		store := newFakeSecretStore()
		strayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		strayDER, err := x509.MarshalPKCS8PrivateKey(strayKey)
		require.NoError(t, err)
		_, err = store.StoreSecret(context.Background(), &baasservice.StoreSecretRequest{
			Name: "platform/ntp/nts-key",
			Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: strayDER}),
		})
		require.NoError(t, err)

		require.NoError(t, app.provisionNTSKeys(context.Background(), store,
			"platform/ntp/nts-key", "platform/ntp/nts-cert"))
		requireCoherentNTSPair(t, store)
	})

	t.Run("unparseable key material", func(t *testing.T) {
		app := ntsTestApp()
		store := newFakeSecretStore()
		for _, name := range []string{"platform/ntp/nts-key", "platform/ntp/nts-cert"} {
			_, err := store.StoreSecret(context.Background(), &baasservice.StoreSecretRequest{
				Name: name, Data: []byte("corrupted"),
			})
			require.NoError(t, err)
		}
		require.NoError(t, app.provisionNTSKeys(context.Background(), store,
			"platform/ntp/nts-key", "platform/ntp/nts-cert"))
		requireCoherentNTSPair(t, store)
	})
}
