package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// errHarnessTLS is the trust failure the fake resolver reports, so the BMC
// ceremonies stop at their first network step.
var errHarnessTLS = errors.New("harness: no BMC trust")

// writeSelfSignedPair writes a self-signed ECDSA client certificate and its
// key as PEM files in dir and returns the certificate and both paths.
func writeSelfSignedPair(t *testing.T, dir, cn string) (*x509.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certFile := filepath.Join(dir, cn+".crt")
	keyFile := filepath.Join(dir, cn+".key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return cert, certFile, keyFile
}

// newDANEHarness is the stores harness with the template's internal zone
// served by the DNS service and DANE publishing enabled.
func newDANEHarness(t *testing.T) *App {
	t.Helper()
	a := newStoresHarness(t)
	a.DNSConfig.DANE = &dns.DANEConfig{Enabled: true, AutoGenerate: true}
	_, err := a.ServiceRegistry()
	require.NoError(t, err)
	require.NotNil(t, a.DNSService)
	return a
}

// harnessBMCConfig is a valid Redfish BMC on a closed local port with
// dns-01 certificate management, so the ceremonies build every collaborator
// and fail at their first connection.
func harnessBMCConfig() *bmc.Config {
	return &bmc.Config{
		Address:     "127.0.0.1",
		Port:        1,
		Protocol:    bmc.ProtocolRedfish,
		Certificate: &common.Identity{Valid: 30, ACME: &common.ACMEIdentityConfig{Challenge: "dns-01"}},
		Key:         harnessWebService("bmc", "bmc.integration.internal").Key,
	}
}

func TestCoverage964b_EnrollBMC(t *testing.T) {
	ctx := context.Background()

	t.Run("nil config", func(t *testing.T) {
		_, err := (&App{}).EnrollBMC(ctx, 1, nil, nil)
		require.ErrorAs(t, err, new(bmc.ErrNilConfig))
	})
	t.Run("no trust resolver", func(t *testing.T) {
		_, err := (&App{Logger: logging.DefaultLogger()}).EnrollBMC(ctx, 1, &bmc.Config{Address: "127.0.0.1"}, nil)
		require.ErrorAs(t, err, new(ErrBMCEnrollNoTrustResolver))
	})
	t.Run("trust failure stops the ceremony at its first step", func(t *testing.T) {
		a := newDANEHarness(t)
		a.trustResolver = &fakeResolver{tlsErr: errHarnessTLS}
		cfg := harnessBMCConfig()
		result, err := a.EnrollBMC(ctx, 7, cfg, nil)
		require.ErrorIs(t, err, errHarnessTLS)
		require.NotNil(t, result)
		require.Equal(t, uint64(7), result.DeviceID)
		require.NotEmpty(t, result.Steps)
		require.Equal(t, "trust", result.Steps[0].Name)
		require.False(t, result.Steps[0].OK)
		_, wired := cfg.TLS.(*resolverTLSProvider)
		require.True(t, wired, "the BMC connections use the resolver's BMC trust chain")
	})
}

func TestCoverage964b_RestoreBMC(t *testing.T) {
	ctx := context.Background()

	t.Run("nil config", func(t *testing.T) {
		_, err := (&App{}).RestoreBMC(ctx, 1, nil)
		require.ErrorAs(t, err, new(bmc.ErrNilConfig))
	})
	t.Run("no trust resolver", func(t *testing.T) {
		_, err := (&App{Logger: logging.DefaultLogger()}).RestoreBMC(ctx, 1, &bmc.Config{Address: "127.0.0.1"})
		require.ErrorAs(t, err, new(ErrBMCEnrollNoTrustResolver))
	})
	t.Run("unreachable BMC fails the restore-cert step", func(t *testing.T) {
		a := newDANEHarness(t)
		a.trustResolver = &fakeResolver{tlsErr: errHarnessTLS}
		cfg := harnessBMCConfig()
		result, err := a.RestoreBMC(ctx, 9, cfg)
		var certErr ErrBMCRestoreCert
		require.ErrorAs(t, err, &certErr)
		require.Equal(t, uint64(9), certErr.DeviceID)
		require.Len(t, result.Steps, 1)
		require.Equal(t, "restore-cert", result.Steps[0].Name)
		require.False(t, result.Steps[0].OK)
	})
}

func TestCoverage964b_FileHeartbeatClient(t *testing.T) {
	dir := t.TempDir()
	_, certFile, keyFile := writeSelfSignedPair(t, dir, "client")
	_, caFile, _ := writeSelfSignedPair(t, dir, "server-ca")
	badPEM := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badPEM, []byte("not a certificate"), 0o600))

	tests := []struct {
		name    string
		cfg     HeartbeatConfig
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "cert without key",
			cfg:  HeartbeatConfig{CertFile: certFile},
			wantErr: func(t *testing.T, err error) {
				var incomplete ErrHeartbeatIdentityIncomplete
				require.ErrorAs(t, err, &incomplete)
				require.Equal(t, certFile, incomplete.CertFile)
				require.Empty(t, incomplete.KeyFile)
			},
		},
		{
			name: "mismatched key pair",
			cfg:  HeartbeatConfig{CertFile: certFile, KeyFile: badPEM},
			wantErr: func(t *testing.T, err error) {
				require.ErrorAs(t, err, new(*WrappedError))
			},
		},
		{
			name: "missing CA bundle",
			cfg:  HeartbeatConfig{CertFile: certFile, KeyFile: keyFile, CAFile: filepath.Join(dir, "absent.pem")},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, os.ErrNotExist)
			},
		},
		{
			name: "CA bundle without certificates",
			cfg:  HeartbeatConfig{CertFile: certFile, KeyFile: keyFile, CAFile: badPEM},
			wantErr: func(t *testing.T, err error) {
				var invalid ErrHeartbeatCABundleInvalid
				require.ErrorAs(t, err, &invalid)
				require.Equal(t, badPEM, invalid.Path)
			},
		},
		{name: "explicit CA bundle", cfg: HeartbeatConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}},
		{name: "operating-system trust store", cfg: HeartbeatConfig{CertFile: certFile, KeyFile: keyFile}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			a := &App{Logger: logging.DefaultLogger(), HeartbeatConfig: &cfg}
			client, err := a.newHeartbeatClient("https://127.0.0.1:1")
			if tt.wantErr != nil {
				tt.wantErr(t, err)
				require.Nil(t, client)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, client)
		})
	}
}

func TestCoverage964b_HeartbeatIDevIDClient(t *testing.T) {
	_, err := (&App{Logger: logging.DefaultLogger(), HeartbeatConfig: &HeartbeatConfig{}}).newHeartbeatClient("https://127.0.0.1:1")
	require.ErrorIs(t, err, provisioning.ErrMissingCertificate, "no TPM, no IDevID identity")

	a := newCAHarness(t)
	a.HeartbeatConfig = &HeartbeatConfig{}
	_, err = a.newHeartbeatClient("https://127.0.0.1:1")
	require.ErrorAs(t, err, new(*WrappedError), "the harness TPM holds no IDevID certificate")

	root, err := a.CA.TrustedRoot()
	require.NoError(t, err)
	pool, err := a.heartbeatServerPool(root)
	require.NoError(t, err)
	_, err = root.Verify(x509.VerifyOptions{Roots: pool})
	require.NoError(t, err, "a certificate the platform CA issued is verified against the CA store")

	stranger, _, _ := writeSelfSignedPair(t, t.TempDir(), "stranger")
	pool, err = a.heartbeatServerPool(stranger)
	require.NoError(t, err)
	_, err = stranger.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown, "an unknown issuer falls back to the OS store, which does not trust it")
}

func TestCoverage964b_ParsePINsFromConfig(t *testing.T) {
	a := &App{
		Logger:           logging.DefaultLogger(),
		DebugFlag:        true,
		DebugSecretsFlag: true,
		PlatformConfig:   &PlatformInitConfig{SOPin: "config-so-pin", UserPin: xkmssdk.DEFAULT_PASSWORD},
	}
	so, user, err := a.ParsePINs(nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("config-so-pin"), so.Bytes())
	require.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), user.Bytes(), "the default user PIN is replaced")
	require.NotEmpty(t, user.Bytes())
}

func TestCoverage964b_InitConfig(t *testing.T) {
	t.Cleanup(viper.Reset)
	t.Setenv("HOME", t.TempDir())

	t.Run("no config file", func(t *testing.T) {
		viper.Reset()
		a := &App{PlatformDir: t.TempDir(), ConfigDir: t.TempDir()}
		err := a.initConfig("unit")
		require.ErrorAs(t, err, new(viper.ConfigFileNotFoundError))
	})
	t.Run("malformed config file", func(t *testing.T) {
		viper.Reset()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("platform: [unterminated\n"), 0o600))
		a := &App{PlatformDir: t.TempDir(), ConfigDir: dir}
		err := a.initConfig("unit")
		require.ErrorAs(t, err, new(viper.ConfigParseError))
	})
}

func TestCoverage964b_SetupSecretResolvers(t *testing.T) {
	a := newStoresHarness(t)
	require.NotNil(t, a.QuicBaaSSDKClient())
	registry, err := a.SetupSecretResolvers(context.Background(), &SecretsConfig{
		Encrypted:      true,
		File:           true,
		DynamicSecrets: true,
		XKMS:           true,
	})
	require.NoError(t, err)
	require.NotNil(t, registry)
	for _, uri := range []string{"file:///etc/secret", "dynamic://role/1h", "xkms://software/key"} {
		require.True(t, registry.IsSecretURI(uri), uri)
	}
}

func TestCoverage964b_BMCRenewalHooks(t *testing.T) {
	ctx := context.Background()
	a := newDANEHarness(t)
	// No BMC address: the pin update is keyed by host and is skipped.
	a.BMCConfig = &bmc.Config{}
	leaf, _, _ := writeSelfSignedPair(t, t.TempDir(), "bmc")

	onIssued, onDeployed := a.buildBMCRenewalHooks()
	require.NoError(t, onIssued(ctx, leaf), "no enrolled DNS name, nothing pre-published")
	require.NoError(t, onDeployed(ctx, leaf, leaf), "no enrolled DNS name, no TLSA re-published")
}

func TestCoverage964b_BuildTOFUResolverOpts(t *testing.T) {
	a := newStoresHarness(t)
	require.Nil(t, a.buildTOFUResolverOpts(), "the template's trust chain has no tofu")

	a.TrustConfig = &trust.Config{BMC: &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyTOFU}}}
	require.Len(t, a.buildTOFUResolverOpts(), 2, "pin store and confirm hook")

	noStore := &App{Logger: logging.DefaultLogger(), TrustConfig: a.TrustConfig}
	require.Nil(t, noStore.buildTOFUResolverOpts(), "no QuicBaaS factory, no pin store")
}

func TestCoverage964b_NewDNSService(t *testing.T) {
	var msgErr *MessageError
	_, err := (&App{Logger: logging.DefaultLogger(), DNSConfig: &dns.Config{}}).newDNSService()
	require.ErrorAs(t, err, &msgErr, "DNS requires the QuicBaaS factory")

	a := newStoresHarness(t)
	a.DNSConfig.DNSSEC = &dns.DNSSECConfig{Enabled: true}
	svc, err := a.newDNSService()
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// restoreXKMSService leaves the process-wide XKMS service initialized with
// memory storage, the state the stores harness starts the QuicBaaS KMS on.
func restoreXKMSService(t *testing.T) {
	t.Helper()
	xkmssdk.ServiceReset()
	_, err := (&App{Logger: logging.DefaultLogger(), Environment: EnvTest}).initXKMSService("", nil, nil)
	require.NoError(t, err)
}

func TestCoverage964b_InitXKMSService(t *testing.T) {
	t.Cleanup(func() { restoreXKMSService(t) })

	t.Run("file storage under a regular file", func(t *testing.T) {
		xkmssdk.ServiceReset()
		t.Cleanup(func() { restoreXKMSService(t) })
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		a := &App{Logger: logging.DefaultLogger(), Environment: EnvDev}
		_, err := a.initXKMSService(filepath.Join(blocker, "ca"), nil, nil)
		require.ErrorAs(t, err, new(*WrappedError))
		require.False(t, xkmssdk.ServiceIsInitialized())
	})
	t.Run("TPM backend is registered", func(t *testing.T) {
		a := newCAHarness(t)
		xkmssdk.ServiceReset()
		ks, err := a.initXKMSService(t.TempDir(), nil, nil)
		require.NoError(t, err)
		require.NotNil(t, ks)
		_, err = xkmssdk.ServiceGetBackend("tpm2")
		require.NoError(t, err)
		again, err := a.initXKMSService(t.TempDir(), nil, nil)
		require.NoError(t, err)
		require.Same(t, ks, again, "an initialized service is reused")
	})
}

func TestCoverage964b_XKMSFromConfig(t *testing.T) {
	a := newCAHarness(t)
	so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
	require.NoError(t, err)
	cfg := &platform.XKMSConfig{CN: "coverage", DefaultBackend: "software", SoftwareConfig: &xkmssdk.SoftwareBackendConfig{}}

	kc, err := a.XKMSFromConfig(cfg, t.TempDir(), so, user, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, kc.Close()) })
	require.Equal(t, "coverage", kc.Config().CN)

	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	_, err = a.XKMSFromConfig(cfg, filepath.Join(blocker, "keys"), so, user, nil)
	require.Error(t, err)
}

// TestCoverage964b_IssueWebServiceCertificate issues a webservice certificate
// from the local CA with configured and localhost SANs; a configured
// cross-sign that cannot run leaves the local certificate in service.
func TestCoverage964b_IssueWebServiceCertificate(t *testing.T) {
	ctx := context.Background()
	a := newCAHarness(t)
	a.DebugFlag = true
	a.CAConfig.IncludeLocalhostSANS = true
	a.ACMEConfig = &trustedca.ACMEConfig{}

	ws := harnessWebService("web", "web.coverage.internal")
	ws.ACME = &v1.ACMEConfig{Enabled: true}
	ws.Certificate.SANS = &quicbaasca.CASubjectAlternativeNames{DNS: []string{"web.coverage.internal", "alt.coverage.internal"}}
	ws.Certificate.ACME = &common.ACMEIdentityConfig{CrossSign: &trustedca.ACMECrossSignConfig{DirectoryURL: "https://127.0.0.1:1/directory"}}
	require.NoError(t, a.initWebServiceKeyAttributes(ctx, ws))

	issued, err := a.CA.PEM(ctx, a.WebServiceKeyAttributes["web"])
	require.NoError(t, err)
	block, _ := pem.Decode(issued)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Subset(t, cert.DNSNames, []string{"web.coverage.internal", "alt.coverage.internal", "localhost", "localhost.localdomain"})
	require.Contains(t, cert.EmailAddresses, "root@localhost")
}

// newTemplateApp is the integration template with in-memory QuicBaaS and no
// stores started yet.
func newTemplateApp(t *testing.T, env Environment) *App {
	t.Helper()
	a := loadTemplate(t, integrationConfig)
	a.Logger = logging.DefaultLogger()
	a.PlatformDir = t.TempDir()
	a.Environment = env
	a.WebServiceKeyAttributes = map[string]*xkmssdk.KeyAttributes{}
	a.QuicBaaSConfig = quicbaas.MemoryTestConfig(t)
	return a
}

// TestCoverage964b_InitStoresFileBackedXKMS runs initStores outside the test
// environment, where the XKMS service is pre-initialized on file storage
// under the issuing CA's directory before QuicBaaS starts.
func TestCoverage964b_InitStoresFileBackedXKMS(t *testing.T) {
	t.Run("file storage in the CA directory", func(t *testing.T) {
		a := newTemplateApp(t, EnvDev)
		xkmssdk.ServiceReset()
		t.Cleanup(func() { restoreXKMSService(t) })
		require.NoError(t, a.initStores())
		t.Cleanup(func() { require.NoError(t, a.Close(context.Background())) })

		_, err := xkmssdk.ServiceGetBackend("software")
		require.NoError(t, err)
		issuer := a.CAConfig.Identity[1].Subject.CommonName
		require.DirExists(t, filepath.Join(a.PlatformDir, "ca", issuer))
	})
	t.Run("platform directory under a regular file", func(t *testing.T) {
		a := newTemplateApp(t, EnvDev)
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		a.PlatformDir = blocker
		require.ErrorAs(t, a.initStores(), new(*WrappedError))
	})
}

// TestCoverage964b_ServiceRegistryStartsFactory builds the registry on an app
// with no DAO factory: the registry starts QuicBaaS itself and adopts the
// operating tenant.
func TestCoverage964b_ServiceRegistryStartsFactory(t *testing.T) {
	a := newTemplateApp(t, EnvTest)
	reg, err := a.ServiceRegistry()
	t.Cleanup(func() { require.NoError(t, a.Close(context.Background())) })
	require.NoError(t, err)
	require.NotNil(t, reg)
	require.NotNil(t, a.QuicBaaSSDKClient(), "the registry started the QuicBaaS factory")
	require.NotNil(t, a.KMS())
}

// TestCoverage964b_InitBarrierWithoutConfig asserts that a barrier manager is
// never created without its configuration.
func TestCoverage964b_InitBarrierWithoutConfig(t *testing.T) {
	a := newStoresHarness(t)
	err := a.initBarrier(context.Background())
	require.ErrorAs(t, err, new(ErrBarrierInit))
	require.Nil(t, a.barrier)
}
