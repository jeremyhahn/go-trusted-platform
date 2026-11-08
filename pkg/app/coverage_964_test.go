package app

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	localcertstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// newStoresHarness is the integration template's App with the QuicBaaS
// embedded server on its memory backend: initStores brings up the SDK, the
// object store and the certificate store entirely in process.
func newStoresHarness(t *testing.T) *App {
	t.Helper()
	a := loadTemplate(t, integrationConfig)
	a.Logger = logging.DefaultLogger()
	a.PlatformDir = t.TempDir()
	a.Environment = EnvTest
	a.WebServiceKeyAttributes = map[string]*xkmssdk.KeyAttributes{}
	a.QuicBaaSConfig = quicbaas.MemoryTestConfig(t)
	require.NoError(t, a.initStores())
	t.Cleanup(func() { require.NoError(t, a.Close(context.Background())) })
	return a
}

// newCAHarness adds the simulator TPM and the template's software CA to the
// stores harness. The TPM is built the way OpenTPM builds it, with the blob
// and certificate stores on the platform object store, then brought up
// through the same InitTPM / InitPlatformKeyStore / InitCA path platformd runs.
func newCAHarness(t *testing.T) *App {
	t.Helper()
	a := newStoresHarness(t)
	restore := disklessCmdlinePath
	t.Cleanup(func() { disklessCmdlinePath = restore })
	disklessCmdlinePath = filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(disklessCmdlinePath, []byte("console=ttyS0\n"), 0o600))

	partition := "objects/tpm2"
	objects, err := object.NewObjectStore(a.Logger, a.Storage, a.PlatformDir, &partition)
	require.NoError(t, err)
	cs, csStorage, err := localcertstore.NewCertificateStoreWithStorage(a.Logger, objects)
	require.NoError(t, err)
	a.TPMCertStore = localcertstore.NewTPM2CertStoreAdapterWithStorage(a.Logger, cs, csStorage)

	tpmDir := filepath.Join(a.PlatformDir, "tpm")
	require.NoError(t, os.MkdirAll(tpmDir, 0o700))
	backendStorage, err := xkmssdk.NewFileStorageBackend(tpmDir)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a.TPM, err = xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(logger, backendStorage),
		BlobStore: object.NewXKMSObjectAdapter(objects),
		CertStore: a.TPMCertStore,
		Config:    &a.TPMConfig,
		Logger:    logger,
		Transport: newHarnessSwtpmState(t),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.TPM.Close()) })

	so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
	require.NoError(t, err)
	require.NoError(t, a.InitTPM(context.Background(), so, user, &AppInitParams{}))
	require.NoError(t, a.InitPlatformKeyStore(so, user))
	// The IAK and IDevID sections are set once the platform is up: InitTPM
	// reads a configured but absent IAK as an unprovisioned TPM.
	iak, idevid := *xkmssdk.DefaultTPMConfig.IAK, *xkmssdk.DefaultTPMConfig.IDevID
	a.TPMConfig.IAK, a.TPMConfig.IDevID = &iak, &idevid
	applyCertHandleNVInterim(&a.TPMConfig, a.Logger)
	// Ownership was taken after InitTPM mirrored the hierarchy auth.
	_, err = a.applyTPMHierarchyAuth(so)
	require.NoError(t, err)
	_, err = a.InitCA(context.Background(), so, user, &AppInitParams{PlatformCA: 1})
	require.NoError(t, err)
	return a
}

func TestCoverage964_InitStores(t *testing.T) {
	a := newStoresHarness(t)
	require.NotNil(t, a.Storage)
	require.NotNil(t, a.ObjectStore)
	require.NotNil(t, a.ManagedCertStore)
}

// provisionHarnessEKCert has the harness CA issue an EK certificate for the
// simulator's EK and writes it to the TPM, as a manufacturer would.
func provisionHarnessEKCert(t *testing.T, a *App) *x509.Certificate {
	t.Helper()
	ctx := context.Background()
	ekAttrs, err := a.TPM.EKAttributes()
	require.NoError(t, err)
	ekPub, err := a.TPM.EKRSA()
	require.NoError(t, err)
	ekCert, err := a.CA.IssueEKCertificate(ctx, &quicbaasca.CACertificateRequest{
		KeyAttributes: ekAttrs,
		Subject:       quicbaasca.CASubject{CommonName: ekAttrs.CN},
	}, ekPub)
	require.NoError(t, err)
	require.NoError(t, a.TPM.ProvisionEKCert([]byte(harnessSOPIN), ekCert.Raw))
	return ekCert
}

// harnessWebService is a webservice whose TLS key the CA's software
// keystore holds, so InitWebServer issues it a certificate from the CA.
func harnessWebService(name, cn string) *v1.Config {
	return &v1.Config{
		Name: name,
		Certificate: v1.Identity{
			Valid:   365,
			Subject: quicbaasca.CASubject{CommonName: cn, Organization: "Coverage"},
		},
		Key: &common.KeyConfig{
			CN:                 cn,
			KeyAlgorithm:       "ECDSA",
			ECCConfig:          &common.ECCConfig{Curve: "P-256"},
			SignatureAlgorithm: "ECDSA-SHA256",
			Hash:               "SHA-256",
			StoreType:          "software",
		},
	}
}

func TestCoverage964_InitCA(t *testing.T) {
	a := newCAHarness(t)
	require.NotNil(t, a.CA)
	require.Equal(t, 1, a.CAConfig.SelectedCA, "the intermediate issues")
	require.Equal(t, a.PlatformDir, a.CAConfig.HomeDir)
}

func TestCoverage964_ImportEndorsementKeyCertificate(t *testing.T) {
	t.Run("missing certificate is issued by the local CA and written", func(t *testing.T) {
		a := newCAHarness(t)
		_, err := a.TPM.EKCertificate()
		require.ErrorIs(t, err, xkmssdk.ErrTPMEndorsementCertNotFound)
		// The NV write authorizes with the configured hierarchy auth: the
		// harness took ownership with the SO PIN.
		a.TPMConfig.EK.HierarchyAuth = harnessSOPIN
		got, err := a.ImportEndorsementKeyCertificate(context.Background())
		require.NoError(t, err)
		stored, err := a.TPM.EKCertificate()
		require.NoError(t, err)
		require.Equal(t, got.Raw, stored.Raw)
	})
	t.Run("manufacturer certificate is imported", func(t *testing.T) {
		a := newCAHarness(t)
		want := provisionHarnessEKCert(t, a)
		got, err := a.ImportEndorsementKeyCertificate(context.Background())
		require.NoError(t, err)
		require.Equal(t, want.Raw, got.Raw)
	})
	t.Run("no CA config", func(t *testing.T) {
		_, err := (&App{}).ImportEndorsementKeyCertificate(context.Background())
		require.ErrorIs(t, err, ErrMissingEKWithoutEnabledCA)
	})
}

// TestCoverage964_ProvisionPlatformIdentity provisions the TPM hierarchies,
// lets the CA issue the EK certificate a manufacturer would, then runs the
// local-CA identity flow: IDevID CSR, credential activation, IAK and IDevID
// certificates, the local quote and the webservice certificate.
func TestCoverage964_ProvisionPlatformIdentity(t *testing.T) {
	a := newCAHarness(t)
	a.WebServices = []*v1.Config{harnessWebService("web", "web.coverage.internal")}
	so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
	require.NoError(t, err)

	require.NoError(t, a.provisionTPMHierarchies(so))
	require.Equal(t, harnessSOPIN, a.TPMConfig.EK.HierarchyAuth, "the endorsement hierarchy auth is mirrored")
	provisionHarnessEKCert(t, a)
	require.False(t, platformIdentityComplete(a.TPM))

	attrs, err := a.provisionPlatformIdentity(context.Background(), so, user, &AppInitParams{PlatformCA: 1})
	require.NoError(t, err)
	require.NotNil(t, attrs)
	require.True(t, platformIdentityComplete(a.TPM), "the IAK and IDevID certificates are in the TPM store")
	require.Contains(t, a.WebServiceKeyAttributes, "web")

}

func TestCoverage964_ServiceRegistry(t *testing.T) {
	require.Nil(t, (&App{Logger: logging.DefaultLogger()}).KMS(), "no DAO factory, no KMS")

	a := newStoresHarness(t)
	reg, err := a.ServiceRegistry()
	require.NoError(t, err)
	require.NotNil(t, reg)
	require.NotNil(t, a.DNSService, "the template's internal zone brings up the DNS service")
	again, err := a.ServiceRegistry()
	require.NoError(t, err)
	require.Same(t, reg, again, "the registry is built once")
	require.NotNil(t, a.KMS())
}

func TestCoverage964_LoadOrInitCA(t *testing.T) {
	ctx := context.Background()
	params := &AppInitParams{SOPin: []byte(harnessSOPIN), Pin: []byte("123456"), PlatformCA: 1}

	a := newCAHarness(t)
	ca := a.CA
	require.NoError(t, a.LoadOrInitCA(ctx, params))
	require.Same(t, ca, a.CA, "a loaded CA is kept")

	want, err := a.CA.TrustedRoot()
	require.NoError(t, err)
	a.CA = nil
	require.NoError(t, a.LoadOrInitCA(ctx, params))
	got, err := a.CA.TrustedRoot()
	require.NoError(t, err)
	require.Equal(t, want.Raw, got.Raw, "the original root certificate survives the reload")

	so, user, err := a.ParsePINs([]byte(harnessSOPIN), []byte("123456"))
	require.NoError(t, err)
	empty := *a.CAConfig
	empty.Identity = nil
	a.CAConfig = &empty
	require.ErrorIs(t, a.LoadCA(ctx, so, user), trustedca.CAErrInvalidConfig)

	var notConfigured ErrCANotConfigured
	require.ErrorAs(t, (&App{}).LoadOrInitCA(ctx, params), &notConfigured)
}

func TestCoverage964_InitWebServiceKeyAttributes(t *testing.T) {
	ctx := context.Background()

	t.Run("restart reuses the issued certificate", func(t *testing.T) {
		a := newCAHarness(t)
		ws := harnessWebService("web", "web.coverage.internal")
		a.WebServices = []*v1.Config{ws}
		require.NoError(t, a.InitWebServer(ctx))
		issued, err := a.CA.PEM(ctx, a.WebServiceKeyAttributes["web"])
		require.NoError(t, err)

		delete(a.WebServiceKeyAttributes, "web")
		require.NoError(t, a.initWebServiceKeyAttributes(ctx, ws))
		reloaded, err := a.CA.PEM(ctx, a.WebServiceKeyAttributes["web"])
		require.NoError(t, err)
		require.Equal(t, issued, reloaded)
	})
	t.Run("unprovisioned IDevID falls back to a dedicated key", func(t *testing.T) {
		a := newCAHarness(t)
		a.TPMConfig.IDevID.CN = "device.coverage.internal"
		ws := harnessWebService("device", a.TPMConfig.IDevID.CN)
		require.NoError(t, a.initWebServiceKeyAttributes(ctx, ws))
		require.Equal(t, xkmssdk.KeyTypeTLS, a.WebServiceKeyAttributes["device"].KeyType)
	})
	t.Run("platform policy seals the key password", func(t *testing.T) {
		a := newCAHarness(t)
		ws := harnessWebService("sealed", "sealed.coverage.internal")
		ws.Key.PlatformPolicy = true
		ws.Key.Password = "web-key-secret"
		require.NoError(t, a.initWebServiceKeyAttributes(ctx, ws))
		_, sealed := a.WebServiceKeyAttributes["sealed"].Password.(*xkmssdk.PlatformPassword)
		require.True(t, sealed, "the key password is the TPM-sealed platform password")
	})
	t.Run("missing key", func(t *testing.T) {
		ws := harnessWebService("", "web.coverage.internal")
		ws.Key = nil
		err := (&App{Logger: logging.DefaultLogger()}).initWebServiceKeyAttributes(ctx, ws)
		var keyErr ErrWebServiceKeyRequired
		require.ErrorAs(t, err, &keyErr)
		require.Equal(t, "default", keyErr.Name, "an unnamed webservice is the default one")
	})
	t.Run("no platform keystore", func(t *testing.T) {
		err := (&App{Logger: logging.DefaultLogger()}).initWebServiceKeyAttributes(ctx, harnessWebService("web", "web.coverage.internal"))
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
	})
}

// TestCoverage964_PublishDANETLSA issues a webservice certificate in the
// template's internal zone with DANE enabled and finds its TLSA records in
// the DNS service.
func TestCoverage964_PublishDANETLSA(t *testing.T) {
	ctx := context.Background()
	a := newCAHarness(t)
	a.DNSConfig.DANE = &dns.DANEConfig{Enabled: true, AutoGenerate: true}
	_, err := a.ServiceRegistry()
	require.NoError(t, err)
	// platformd's DNS server stores its configured zones when it starts.
	require.NoError(t, a.DNSService.Save(ctx, &a.DNSConfig.InternalServer.Zone))
	a.WebServices = []*v1.Config{harnessWebService("web", "web.integration.internal")}
	require.NoError(t, a.InitWebServer(ctx))
	zone, err := a.DNSService.Zone(ctx, a.DNSConfig.InternalServer.Zone.Name)
	require.NoError(t, err)
	require.NotEmpty(t, zone.RecordSet.TLSARecords)

	var parseErr *ErrDANECertParse
	require.ErrorAs(t, a.publishDANETLSA("web", []byte("not DER"), nil), &parseErr)

	root, err := a.CA.TrustedRoot()
	require.NoError(t, err)
	var zoneErr *ErrDANENoZone
	require.ErrorAs(t, a.publishDANETLSA("root", root.Raw, nil), &zoneErr, "the root CA's host is in no served zone")

	a.DNSConfig.DANE.AutoGenerate = false
	require.NoError(t, a.publishDANETLSA("web", []byte("not DER"), nil), "nothing is published without auto-generate")
}

func TestCoverage964_ResolveDANEZone(t *testing.T) {
	a := &App{DNSConfig: &dns.Config{
		InternalServer: &dns.InternalServer{Zone: entities.Zone{Name: "internal.example."}},
		PublicServer:   &dns.PublicServer{Zone: entities.Zone{Name: "example.com."}},
	}}
	tests := []struct {
		name, tlsa, want string
	}{
		{"internal zone", "_443._tcp.web.internal.example.", "internal.example."},
		{"public zone", "www.example.com", "example.com."},
		{"bare host", "_443._tcp.localhost", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.resolveDANEZoneFromTLSA(tt.tlsa)
			if tt.want == "" {
				var zoneErr *ErrDANENoZone
				require.ErrorAs(t, err, &zoneErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
	var zoneErr *ErrDANENoZone
	_, err := (&App{}).resolveDANEZone("web.internal.example")
	require.ErrorAs(t, err, &zoneErr, "no DNS config, no zone")
}

func TestCoverage964_DNSResolverForService(t *testing.T) {
	configured := &App{DNSConfig: &dns.Config{Resolver: &dns.ResolverConfig{
		Servers: []dns.ResolverServer{{Address: "10.0.0.53", Port: 53}},
	}}}
	tests := []struct {
		name     string
		app      *App
		override string
		wantNil  bool
		primary  string
	}{
		{"service override wins", configured, "10.9.9.9:53", false, "10.9.9.9:53"},
		{"platform resolver", configured, "", false, "10.0.0.53:53"},
		{"system resolver", &App{}, "", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := tt.app.DNSResolverForService(tt.override)
			if tt.wantNil {
				require.Nil(t, resolver)
			} else {
				require.NotNil(t, resolver)
				require.True(t, resolver.PreferGo)
			}
			require.Equal(t, tt.primary, tt.app.PrimaryDNSServer(tt.override))
		})
	}
}
