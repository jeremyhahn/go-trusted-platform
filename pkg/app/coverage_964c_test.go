package app

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// errCARefused is the failure a faultingCA injects.
type errCARefused struct{ op string }

func (e errCARefused) Error() string { return "ca refused " + e.op }

// faultingCA wraps a working CA and fails the operations a test names. It
// records the requests it was handed so a test can assert what was asked.
type faultingCA struct {
	quicbaasca.CACertificateAuthority
	issueErr, csrErr, pemErr error

	csrRequests []*quicbaasca.CACertificateRequest
	issued      int
}

func (c *faultingCA) IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	if c.issueErr != nil {
		return nil, c.issueErr
	}
	c.issued++
	return c.CACertificateAuthority.IssueCertificate(ctx, req)
}

func (c *faultingCA) CreateCSR(ctx context.Context, req *quicbaasca.CACertificateRequest) ([]byte, error) {
	c.csrRequests = append(c.csrRequests, req)
	if c.csrErr != nil {
		return nil, c.csrErr
	}
	return c.CACertificateAuthority.CreateCSR(ctx, req)
}

func (c *faultingCA) PEM(ctx context.Context, attrs *xkmssdk.KeyAttributes) ([]byte, error) {
	if c.pemErr != nil {
		return nil, c.pemErr
	}
	return c.CACertificateAuthority.PEM(ctx, attrs)
}

// webServiceKeyAttrs builds the dedicated TLS key attributes
// initWebServiceKeyAttributes derives for a webservice without an IDevID.
func webServiceKeyAttrs(t *testing.T, a *App, ws *v1.Config) *xkmssdk.KeyAttributes {
	t.Helper()
	attrs, err := ws.Key.ToKeyAttributes()
	require.NoError(t, err)
	attrs.Parent = a.PlatformKS.SRKAttributes()
	attrs.CN = ws.Certificate.Subject.CommonName
	attrs.KeyType = xkmssdk.KeyTypeTLS
	attrs.TPMAttributes = &xkmssdk.TPMAttributes{}
	return attrs
}

func TestCoverage964c_IssueWebServiceCertificate(t *testing.T) {
	ctx := context.Background()
	a := newCAHarness(t)
	realCA := a.CA
	t.Cleanup(func() { a.CA = realCA })

	t.Run("local CA refusal is returned with its cause", func(t *testing.T) {
		refused := errCARefused{op: "issue"}
		ca := &faultingCA{CACertificateAuthority: realCA, issueErr: refused}
		a.CA = ca
		ws := harnessWebService("refused", "refused.coverage.internal")

		err := a.issueWebServiceCertificate(ctx, "refused", ws, webServiceKeyAttrs(t, a, ws), installOptional)
		require.ErrorAs(t, err, new(*WrappedError))
		require.ErrorIs(t, err, refused)
		require.Empty(t, ca.csrRequests, "no cross-sign CSR without an issued certificate")
	})

	t.Run("public ACME CSR refusal names the default SANs", func(t *testing.T) {
		refused := errCARefused{op: "csr"}
		ca := &faultingCA{CACertificateAuthority: realCA, csrErr: refused}
		a.CA = ca
		a.Hostmaster = "hostmaster@example.test"
		a.ACMEClient = &trustedca.ACMEClient{}
		a.ACMEConfig = &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{DirectoryURL: "https://acme.example/directory"}}
		t.Cleanup(func() { a.ACMEClient, a.ACMEConfig = nil, nil })
		ws := harnessWebService("public", "public.coverage.internal")
		ws.Certificate.ACME = &common.ACMEIdentityConfig{Challenge: "http-01"}

		err := a.issueWebServiceCertificate(ctx, "public", ws, webServiceKeyAttrs(t, a, ws), installOptional)
		require.ErrorAs(t, err, new(*WrappedError))
		require.ErrorIs(t, err, refused)
		require.Len(t, ca.csrRequests, 1)
		req := ca.csrRequests[0]
		assert.Equal(t, "public.coverage.internal", req.Subject.CommonName)
		assert.Equal(t, []string{"public.coverage.internal"}, req.SANS.DNS)
		assert.Equal(t, []string{"hostmaster@example.test"}, req.SANS.Email)
		assert.Zero(t, ca.issued, "the public ACME path never issues from the local CA")
	})

	t.Run("cross-sign CSR refusal keeps the local certificate", func(t *testing.T) {
		ca := &faultingCA{CACertificateAuthority: realCA, csrErr: errCARefused{op: "csr"}}
		a.CA = ca
		ws := harnessWebService("xsign", "xsign.coverage.internal")
		ws.Certificate.ACME = &common.ACMEIdentityConfig{CrossSign: &trustedca.ACMECrossSignConfig{DirectoryURL: "https://xsign.example/directory"}}
		attrs := webServiceKeyAttrs(t, a, ws)

		require.NoError(t, a.issueWebServiceCertificate(ctx, "xsign", ws, attrs, installOptional))
		assert.Equal(t, 1, ca.issued)
		require.Len(t, ca.csrRequests, 1, "the cross-sign CSR was attempted")
		_, err := realCA.PEM(ctx, attrs)
		require.NoError(t, err, "the locally issued certificate is stored")
	})

	t.Run("renewal without an installer fails", func(t *testing.T) {
		a.CA = realCA
		ws := harnessWebService("renew", "renew.coverage.internal")

		err := a.issueWebServiceCertificate(ctx, "renew", ws, webServiceKeyAttrs(t, a, ws), installRequired)
		var missing ErrCertInstallerMissing
		require.ErrorAs(t, err, &missing)
		assert.Equal(t, "renew", missing.Webservice)
	})
}

func TestCoverage964c_InitWebServiceKeyAttributes(t *testing.T) {
	ctx := context.Background()
	a := newCAHarness(t)
	realCA := a.CA
	t.Cleanup(func() { a.CA = realCA })

	for name, platformPolicy := range map[string]bool{"plain key": false, "platform policy key": true} {
		t.Run(name+": a lookup failure that is not not-found is fatal", func(t *testing.T) {
			refused := errCARefused{op: "pem"}
			a.CA = &faultingCA{CACertificateAuthority: realCA, pemErr: refused}
			ws := harnessWebService("lookup", "lookup.coverage.internal")
			ws.Key.PlatformPolicy = platformPolicy

			err := a.initWebServiceKeyAttributes(ctx, ws)
			require.ErrorAs(t, err, new(*WrappedError))
			require.ErrorIs(t, err, refused)
			assert.NotContains(t, a.WebServiceKeyAttributes, "lookup")
		})
	}

	t.Run("an unparseable key configuration is refused", func(t *testing.T) {
		a.CA = realCA
		ws := harnessWebService("badkey", "badkey.coverage.internal")
		ws.Key.KeyAlgorithm = "ROT13"

		require.Error(t, a.initWebServiceKeyAttributes(ctx, ws))
		assert.NotContains(t, a.WebServiceKeyAttributes, "badkey")
	})
}

func TestCoverage964c_CompletePlatformIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("a CA section without identities is refused", func(t *testing.T) {
		a := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)
		a.CAConfig = &trustedca.CAConfig{}

		attrs, err := a.CompletePlatformIdentity(ctx, nil, nil, &AppInitParams{})
		assert.Nil(t, attrs)
		require.ErrorIs(t, err, trustedca.CAErrInvalidConfig)
	})

	t.Run("a refused ACME enrollment keeps its typed error", func(t *testing.T) {
		a := newCAHarness(t)
		so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
		require.NoError(t, err)
		require.NoError(t, a.provisionTPMHierarchies(so))
		provisionHarnessEKCert(t, a)
		enrolling, _, _ := enrollingApp(t, "enroll-01")
		a.ACMEClient = &trustedca.ACMEClient{}
		a.ACMEConfig = enrolling.ACMEConfig
		a.ACMEConfig.Client.DirectoryURL = "https://acme.example/directory"
		var asked *trustedca.ACMEEnrollmentConfig
		a.enrollDevice = func(_ context.Context, cfg *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
			asked = cfg
			return nil, enrollmentRefused{reason: "EAB rejected"}
		}

		attrs, err := a.CompletePlatformIdentity(ctx, so, user, &AppInitParams{PlatformCA: 1})
		assert.Nil(t, attrs)
		require.ErrorAs(t, err, &enrollmentRefused{})
		require.NotNil(t, asked)
		assert.Equal(t, "enroll-01", asked.Challenge)
	})
}

func TestCoverage964c_EnrollIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("CA import refusals are logged, the TPM store still receives both", func(t *testing.T) {
		platform, tpm, ca := enrollingApp(t, "enroll-01")
		ca.refuse = errCARefused{op: "import"}
		issued := enrolledCerts(t)
		platform.enrollDevice = func(context.Context, *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
			return issued, nil
		}

		idevid, err := platform.EnrollIdentity(ctx)
		require.NoError(t, err)
		assert.Same(t, issued.idevid, idevid)
		assert.Equal(t, []*x509.Certificate{issued.chain[0], issued.iak, issued.idevid}, ca.imported)
		assert.Same(t, issued.iak, tpm.storedIAK)
		assert.Same(t, issued.idevid, tpm.storedIDevID)
	})

	t.Run("no chain and no IAK still stores the IDevID", func(t *testing.T) {
		platform, tpm, ca := enrollingApp(t, "enroll-01")
		issued := enrolledCerts(t)
		issued.chain, issued.iak = nil, nil
		platform.enrollDevice = func(context.Context, *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
			return issued, nil
		}

		idevid, err := platform.EnrollIdentity(ctx)
		require.NoError(t, err)
		assert.Same(t, issued.idevid, idevid)
		assert.Equal(t, []*x509.Certificate{issued.idevid}, ca.imported)
		assert.Nil(t, tpm.storedIAK)
	})

	t.Run("the preferred-IP macro is resolved before enrollment", func(t *testing.T) {
		platform, _, _ := enrollingApp(t, "enroll-01")
		platform.ACMEConfig.Client.Enrollment.IPAddress = "${PREFERRED_IP}"
		var asked *trustedca.ACMEEnrollmentConfig
		platform.enrollDevice = func(_ context.Context, cfg *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
			asked = cfg
			return nil, enrollmentRefused{reason: "stop after the request"}
		}

		_, err := platform.EnrollIdentity(ctx)
		require.ErrorAs(t, err, &enrollmentRefused{})
		require.NotNil(t, asked)
		assert.Equal(t, util.PreferredIPv4().String(), asked.IPAddress)
		assert.NotEqual(t, "${PREFERRED_IP}", asked.IPAddress)
	})
}

// bootServer is a loopback control plane for the diskless fetch. It answers
// the boot certificate request with chainPEM and refuses the delivery, and
// records what each request carried.
type bootServer struct {
	mu        sync.Mutex
	certReqs  []provisioning.BootCertificateRequest
	delivered int
}

func startBootServer(t *testing.T, chainPEM string) (*bootServer, *httptest.Server, *x509.CertPool) {
	t.Helper()
	recorder := &bootServer{}
	bundle := testutil.GenerateTestTLSBundle(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		switch r.URL.Path {
		case provisioning.BootCertificatePath:
			var req provisioning.BootCertificateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			recorder.certReqs = append(recorder.certReqs, req)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(provisioning.BootCertificateResponse{Identity: req.Identity, IDevIDChain: chainPEM}); err != nil {
				t.Errorf("encode: %v", err)
			}
		case provisioning.BootDeliveryPath:
			recorder.delivered++
			http.Error(w, "quote not accepted", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{bundle.ServerCert}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return recorder, server, bundle.CAPool
}

func TestCoverage964c_FetchDisklessIdentity(t *testing.T) {
	app := newIDevIDApp(t, newSimulatedIDevID(t))
	idevidPub, err := residentPublicKey(app.TPM, app.TPMConfig.IDevID.Handle)
	require.NoError(t, err)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer := issueTestCert(t, 1, "cp-intermediate", true, caKey.Public(), nil, caKey)
	leaf := issueTestCert(t, 2, "node-1-idevid", false, idevidPub, issuer, caKey)

	cases := map[string]struct {
		chainPEM  string
		sentinel  error
		delivered int
	}{
		"the recorded chain is not a certificate": {
			chainPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
			sentinel: provisioning.ErrCertificateChainInvalid,
		},
		"the attested delivery is refused": {
			chainPEM:  string(pemChain(leaf, issuer)),
			sentinel:  provisioning.ErrServerError,
			delivered: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			recorder, server, roots := startBootServer(t, tc.chainPEM)
			target := disklessBootTarget{serverURL: server.URL, identity: "node-1.example"}

			resp, err := app.fetchDisklessIdentity(context.Background(), target, roots)
			assert.Nil(t, resp)
			require.ErrorIs(t, err, tc.sentinel)
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			require.Len(t, recorder.certReqs, 1)
			assert.Equal(t, "node-1.example", recorder.certReqs[0].Identity)
			assert.NotEmpty(t, recorder.certReqs[0].Signature, "the request proves possession of the IDevID key")
			assert.Equal(t, tc.delivered, recorder.delivered, "delivery is attempted only with a valid chain")
		})
	}
}

func TestCoverage964c_RecoverDisklessIdentity(t *testing.T) {
	ctx := context.Background()
	configure := func(a *App) {
		a.nodeIdentity = "ek-00112233445566778899aabbccddeeff"
		a.ACMEConfig = &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{DirectoryURL: "https://127.0.0.1:1/acme/directory"}}
		a.ConfigDir = filepath.Join(os.TempDir(), "absent-config-dir")
	}
	outer := func(t *testing.T, err error) ErrDisklessIdentityUnavailable {
		t.Helper()
		var unavailable ErrDisklessIdentityUnavailable
		require.ErrorAs(t, err, &unavailable)
		return unavailable
	}

	t.Run("an image bundle without certificates", func(t *testing.T) {
		a := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)
		configure(a)
		a.ConfigDir = t.TempDir()
		a.PlatformDir = t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(a.ConfigDir, "ca-bundle.pem"), []byte("not a certificate"), 0o600))

		err := a.recoverDisklessIdentity(ctx, nil, nil, &AppInitParams{})
		assert.Equal(t, "no trust anchor for the control plane", outer(t, err).Reason)
		require.ErrorAs(t, err, &ErrDisklessBootMaterialInvalid{})
	})

	t.Run("a CA section without identities", func(t *testing.T) {
		a := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)
		configure(a)
		a.ConfigDir, a.PlatformDir = t.TempDir(), t.TempDir()
		a.CAConfig = &trustedca.CAConfig{}

		err := a.recoverDisklessIdentity(ctx, nil, nil, &AppInitParams{})
		assert.Equal(t, "platform CA did not initialize", outer(t, err).Reason)
		require.ErrorIs(t, err, trustedca.CAErrInvalidConfig)
	})

	t.Run("the delivery fails once the CA is up", func(t *testing.T) {
		a := newCAHarness(t)
		configure(a)
		a.ConfigDir = t.TempDir()
		a.TPMConfig.IDevID = nil
		so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
		require.NoError(t, err)

		err = a.recoverDisklessIdentity(ctx, so, user, &AppInitParams{PlatformCA: 1})
		unavailable := outer(t, err)
		assert.Equal(t, "attested boot delivery failed", unavailable.Reason)
		var inner ErrDisklessIdentityUnavailable
		require.ErrorAs(t, unavailable.Cause, &inner)
		assert.Equal(t, "the TPM configuration has no IDevID section", inner.Reason)
	})
}

// errSecretBackendDown is a secret store failure that is not "not found".
type errSecretBackendDown struct{}

func (errSecretBackendDown) Error() string { return "kms backend unavailable" }

// scriptedSecretStore fails the nth read of a path, so a test can fail the
// existence check or the later content read independently.
type scriptedSecretStore struct {
	*fakeSecretStore
	failAt map[string]int
	reads  map[string]int
}

func (s *scriptedSecretStore) GetSecret(ctx context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error) {
	s.reads[req.SecretID]++
	if s.failAt[req.SecretID] == s.reads[req.SecretID] {
		return nil, errSecretBackendDown{}
	}
	return s.fakeSecretStore.GetSecret(ctx, req)
}

func TestCoverage964c_NTSPairHealthy(t *testing.T) {
	const keyPath, certPath = "nts/key", "nts/cert"
	pemOf := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	key := newKey()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pemOf("PRIVATE KEY", keyDER)
	certPEM := pemOf("CERTIFICATE", issueTestCert(t, 1, "nts", false, key.Public(), nil, key).Raw)
	other := newKey()
	otherCertPEM := pemOf("CERTIFICATE", issueTestCert(t, 2, "other", false, other.Public(), nil, other).Raw)
	type pairCase struct {
		key, cert []byte
		failAt    map[string]int
		healthy   bool
		failedOn  string
	}
	cases := map[string]pairCase{
		"matching pair":             {key: keyPEM, cert: certPEM, healthy: true},
		"key absent":                {cert: certPEM},
		"certificate absent":        {key: keyPEM},
		"key existence unknown":     {key: keyPEM, cert: certPEM, failAt: map[string]int{keyPath: 1}, failedOn: keyPath},
		"cert existence unknown":    {key: keyPEM, cert: certPEM, failAt: map[string]int{certPath: 1}, failedOn: certPath},
		"key unreadable":            {key: keyPEM, cert: certPEM, failAt: map[string]int{keyPath: 2}},
		"certificate unreadable":    {key: keyPEM, cert: certPEM, failAt: map[string]int{certPath: 2}},
		"key is not PEM":            {key: []byte("raw"), cert: certPEM},
		"key is not PKCS#8":         {key: pemOf("PRIVATE KEY", []byte{1, 2, 3}), cert: certPEM},
		"certificate is not PEM":    {key: keyPEM, cert: []byte("raw")},
		"certificate is not DER":    {key: keyPEM, cert: pemOf("CERTIFICATE", []byte{1, 2, 3})},
		"certificate is for a peer": {key: keyPEM, cert: otherCertPEM},
	}
	// The one PKCS#8 key that is not a crypto.Signer is X25519, which
	// FIPS 140-only mode neither generates nor parses: the case runs only
	// outside FIPS mode.
	if !fips140.Enabled() {
		x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		x25519DER, err := x509.MarshalPKCS8PrivateKey(x25519)
		require.NoError(t, err)
		cases["key cannot sign"] = pairCase{key: pemOf("PRIVATE KEY", x25519DER), cert: certPEM}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := &scriptedSecretStore{fakeSecretStore: newFakeSecretStore(), failAt: tc.failAt, reads: map[string]int{}}
			if tc.key != nil {
				store.data[keyPath] = tc.key
			}
			if tc.cert != nil {
				store.data[certPath] = tc.cert
			}

			healthy, err := ntsPairHealthy(context.Background(), store, keyPath, certPath)
			assert.Equal(t, tc.healthy, healthy)
			if tc.failAt == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, errSecretBackendDown{})
			if tc.failedOn != "" {
				var existence *ErrSecureBootExistenceCheck
				require.ErrorAs(t, err, &existence)
				assert.Equal(t, tc.failedOn, existence.Path)
			}
		})
	}
}

func TestCoverage964c_InitStores(t *testing.T) {
	t.Run("an unknown QuicBaaS transport is refused", func(t *testing.T) {
		a := newTemplateApp(t, EnvTest)
		a.QuicBaaSConfig.TransportStr = "carrier-pigeon"

		err := a.initStores()
		require.ErrorAs(t, err, new(*WrappedError))
		var invalid quicbaas.ErrInvalidTransport
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "carrier-pigeon", invalid.Value)
		assert.Nil(t, a.ObjectStore, "no store is built without a factory")
	})
}

func TestCoverage964c_InitXKMSServiceWithoutSoftwareBackend(t *testing.T) {
	t.Cleanup(func() { restoreXKMSService(t) })
	xkmssdk.ServiceReset()
	backend, err := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{KeyStorage: xkmssdk.NewStorageMemory()})
	require.NoError(t, err)
	other, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{Backend: backend, CertStorage: xkmssdk.NewStorageMemory()})
	require.NoError(t, err)
	require.NoError(t, xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends:       map[string]xkmssdk.ServiceBackend{"other": other},
		DefaultBackend: "other",
	}))

	a := &App{Logger: logging.DefaultLogger(), Environment: EnvTest}
	ks, err := a.initXKMSService("", nil, nil)
	require.NoError(t, err)
	software, err := xkmssdk.ServiceGetBackend("software")
	require.NoError(t, err)
	assert.Same(t, ks, software, "the service was re-initialized with a software backend")
	_, err = xkmssdk.ServiceGetBackend("other")
	assert.Error(t, err, "the foreign backend did not survive the re-initialization")
}
