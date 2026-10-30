package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// errQuoteRefused is the failure quoteCA reports for a refused step.
type errQuoteRefused struct{ step string }

func (e errQuoteRefused) Error() string { return "quote refused at " + e.step }

// quoteCA verifies and imports local attestations, recording what it was
// given and failing the step it is told to fail.
type quoteCA struct {
	quicbaasca.CACertificateAuthority
	verifyErr, importErr error

	verifiedNonces [][]byte
	imported       []*xkmssdk.Quote
}

func (c *quoteCA) VerifyQuote(_ *xkmssdk.KeyAttributes, _ *xkmssdk.Quote, nonce []byte) error {
	c.verifiedNonces = append(c.verifiedNonces, nonce)
	return c.verifyErr
}

func (c *quoteCA) ImportLocalAttestation(_ context.Context, _ *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	c.imported = append(c.imported, quote)
	return c.importErr
}

// propertiesTPM answers FixedProperties and counts how often it is asked.
type propertiesTPM struct {
	xkmssdk.TrustedPlatformModule
	props *xkmssdk.PropertiesFixed
	err   error
	calls int
}

func (p *propertiesTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	p.calls++
	return p.props, p.err
}

// trustedOnlyCA is a TrustedCA that is not a TCG CA.
type trustedOnlyCA struct{ quicbaasca.TrustedCA }

// foreignFactory is a datastore factory that is not the QuicBaaS one.
type foreignFactory struct{ datastore.Factory }

func TestCoverage964d_AssertNoUnresolvedKMSURI(t *testing.T) {
	assert.NoError(t, assertNoUnresolvedKMSURI("tpm.password", ""))
	assert.NoError(t, assertNoUnresolvedKMSURI("tpm.password", "plain-secret"))

	err := assertNoUnresolvedKMSURI("tpm.password", "KMS://vault/so-pin")
	var msg *MessageError
	require.ErrorAs(t, err, &msg)
	assert.Contains(t, msg.Msg, "tpm.password")
	assert.Contains(t, msg.Msg, `"KMS://vault/so-pin"`, "the scheme match is case-insensitive")
}

func TestCoverage964d_SelectIssuingCA(t *testing.T) {
	root := &faultingCA{}
	intermediate := &faultingCA{}

	assert.Nil(t, selectIssuingCA(nil, root, intermediate))
	assert.Same(t, root, selectIssuingCA(&trustedca.CAConfig{SelectedCA: 0}, root, intermediate))
	assert.Same(t, intermediate, selectIssuingCA(&trustedca.CAConfig{SelectedCA: 1}, root, intermediate))
	assert.Same(t, root, selectIssuingCA(&trustedca.CAConfig{SelectedCA: 1}, root, nil),
		"without an intermediate the root issues")
}

func TestCoverage964d_MustTCGCA(t *testing.T) {
	tcg := &faultingCA{}
	assert.Same(t, tcg, mustTCGCA(tcg))
	assert.Nil(t, mustTCGCA(trustedOnlyCA{}))
}

func TestCoverage964d_TPMManufacturerCode(t *testing.T) {
	t.Run("cached code wins over the TPM", func(t *testing.T) {
		tpm := &propertiesTPM{props: &xkmssdk.PropertiesFixed{ManufacturerCode: "IBM"}}
		a := &App{Logger: logging.DefaultLogger(), TPM: tpm, tpmManufacturerCode: "STM"}
		assert.Equal(t, "STM", a.TPMManufacturerCode())
		assert.Zero(t, tpm.calls)
	})
	t.Run("no TPM", func(t *testing.T) {
		assert.Empty(t, (&App{}).TPMManufacturerCode())
	})
	t.Run("read once and cached", func(t *testing.T) {
		tpm := &propertiesTPM{props: &xkmssdk.PropertiesFixed{ManufacturerCode: "IBM"}}
		a := &App{Logger: logging.DefaultLogger(), TPM: tpm}
		assert.Equal(t, "IBM", a.TPMManufacturerCode())
		assert.Equal(t, "IBM", a.TPMManufacturerCode())
		assert.Equal(t, 1, tpm.calls)
	})
	t.Run("properties unavailable", func(t *testing.T) {
		tpm := &propertiesTPM{err: errQuoteRefused{step: "properties"}}
		a := &App{Logger: logging.DefaultLogger(), TPM: tpm}
		assert.Empty(t, a.TPMManufacturerCode())
		assert.Empty(t, a.TPMManufacturerCode())
		assert.Equal(t, 2, tpm.calls, "a failed read is not cached")
	})
	t.Run("no properties and no error", func(t *testing.T) {
		tpm := &propertiesTPM{}
		a := &App{Logger: logging.DefaultLogger(), TPM: tpm}
		assert.Empty(t, a.TPMManufacturerCode())
		assert.Equal(t, 1, tpm.calls)
	})
}

func TestCoverage964d_VerifyLocalQuote(t *testing.T) {
	ctx := context.Background()
	nonce := []byte("nonce-1")
	quote := xkmssdk.Quote{Nonce: nonce}

	t.Run("verified and imported", func(t *testing.T) {
		ca := &quoteCA{}
		a := &App{CA: ca}
		require.NoError(t, a.VerifyLocalQuote(ctx, &xkmssdk.KeyAttributes{}, quote, nonce))
		assert.Equal(t, [][]byte{nonce}, ca.verifiedNonces)
		require.Len(t, ca.imported, 1)
		assert.Equal(t, nonce, ca.imported[0].Nonce)
	})
	t.Run("a bad signature is not imported", func(t *testing.T) {
		refused := errQuoteRefused{step: "verify"}
		ca := &quoteCA{verifyErr: refused}
		a := &App{CA: ca}
		err := a.VerifyLocalQuote(ctx, &xkmssdk.KeyAttributes{}, quote, nonce)
		require.ErrorIs(t, err, ErrInvalidLocalAttestationSignature)
		require.ErrorIs(t, err, refused)
		assert.Contains(t, err.Error(), "quote refused at verify")
		assert.Empty(t, ca.imported)
	})
	t.Run("the import fails", func(t *testing.T) {
		refused := errQuoteRefused{step: "import"}
		ca := &quoteCA{importErr: refused}
		a := &App{CA: ca}
		err := a.VerifyLocalQuote(ctx, &xkmssdk.KeyAttributes{}, quote, nonce)
		require.ErrorAs(t, err, new(*WrappedError))
		require.ErrorIs(t, err, refused)
		assert.NotErrorIs(t, err, ErrInvalidLocalAttestationSignature)
		assert.Len(t, ca.imported, 1)
	})
}

func TestCoverage964d_FactoryAccessors(t *testing.T) {
	t.Run("no factory", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger()}
		assert.Nil(t, a.KMS())
		assert.Nil(t, a.CryptoService())
		assert.NoError(t, a.SetQuicBaaSCA(&faultingCA{}))
	})
	t.Run("a foreign factory", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), daoFactory: foreignFactory{}}
		assert.Nil(t, a.KMS())
		assert.Nil(t, a.CryptoService())
		assert.NoError(t, a.SetQuicBaaSCA(&faultingCA{}))
	})
	t.Run("a nil CA is ignored", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), daoFactory: foreignFactory{}}
		assert.NoError(t, a.SetQuicBaaSCA(nil))
	})
	t.Run("the started QuicBaaS factory", func(t *testing.T) {
		a := newStoresHarness(t)
		svc := a.QuicBaaSService()
		require.NotNil(t, svc)
		assert.Equal(t, svc.KMS(), a.KMS())
		assert.Equal(t, svc.Crypto(), a.CryptoService())
	})
}

func TestCoverage964d_FetchDisklessIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("the IDevID handle holds no key", func(t *testing.T) {
		app := newIDevIDApp(t, newSimulatedIDevID(t))
		idevid := *app.TPMConfig.IDevID
		idevid.Handle = 0x81000FF0
		app.TPMConfig.IDevID = &idevid

		resp, err := app.fetchDisklessIdentity(ctx, disklessBootTarget{serverURL: "https://127.0.0.1:1"}, nil)
		assert.Nil(t, resp)
		var unavailable ErrDisklessIdentityUnavailable
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, "the IDevID key cannot be read", unavailable.Reason)
		assert.Error(t, unavailable.Cause)
	})
	t.Run("the control plane has no recorded certificate", func(t *testing.T) {
		app := newIDevIDApp(t, newSimulatedIDevID(t))
		_, server, roots := startBootServer(t, "")
		var paths []string
		missing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			http.Error(w, "no such node", http.StatusInternalServerError)
		}))
		missing.TLS = server.TLS
		missing.StartTLS()
		t.Cleanup(missing.Close)

		target := disklessBootTarget{serverURL: missing.URL, identity: "node-1.example"}
		resp, err := app.fetchDisklessIdentity(ctx, target, roots)
		assert.Nil(t, resp)
		require.ErrorIs(t, err, provisioning.ErrServerError)
		assert.Equal(t, []string{provisioning.BootCertificatePath}, paths,
			"no delivery is attempted without a recorded certificate")
	})
}

// rootCA reports a trusted root, or the error it is told to report.
type rootCA struct {
	quicbaasca.CACertificateAuthority
	root    *x509.Certificate
	rootErr error
}

func (c *rootCA) TrustedRoot() (*x509.Certificate, error) { return c.root, c.rootErr }

func TestCoverage964d_SecureBootCurve(t *testing.T) {
	cases := map[string]struct {
		curve     elliptic.Curve
		algorithm string
	}{
		"":           {elliptic.P256(), "ECDSA-P256"},
		"prime256v1": {elliptic.P256(), "ECDSA-P256"},
		"p384":       {elliptic.P384(), "ECDSA-P384"},
		"SECP521R1":  {elliptic.P521(), "ECDSA-P521"},
	}
	for name, tc := range cases {
		ref := &installer.SecureBootKeyRef{KeyConfig: common.KeyConfig{ECCConfig: &common.ECCConfig{Curve: name}}}
		curve, algorithm, err := secureBootCurve(ref)
		require.NoError(t, err, name)
		assert.Equal(t, tc.curve, curve, name)
		assert.Equal(t, tc.algorithm, algorithm, name)
	}

	curve, algorithm, err := secureBootCurve(&installer.SecureBootKeyRef{})
	require.NoError(t, err)
	assert.Equal(t, elliptic.P256(), curve, "no ecc section defaults to P-256")
	assert.Equal(t, "ECDSA-P256", algorithm)

	ref := &installer.SecureBootKeyRef{KeyConfig: common.KeyConfig{ECCConfig: &common.ECCConfig{Curve: "brainpool"}}}
	curve, algorithm, err = secureBootCurve(ref)
	var msg *MessageError
	require.ErrorAs(t, err, &msg)
	assert.Equal(t, "unsupported secure boot ECC curve: BRAINPOOL", msg.Msg)
	assert.Nil(t, curve)
	assert.Empty(t, algorithm)
}

func TestCoverage964d_BMCTrustRoots(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root := issueTestCert(t, 7, "platform-root", true, key.Public(), nil, key)
	system, err := x509.SystemCertPool()
	require.NoError(t, err)
	withRoot := system.Clone()
	withRoot.AddCert(root)

	t.Run("no CA", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger()}
		assert.True(t, system.Equal(a.bmcTrustRoots()))
	})
	t.Run("the platform root joins the system roots", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), CA: &rootCA{root: root}}
		pool := a.bmcTrustRoots()
		assert.True(t, withRoot.Equal(pool))
		assert.False(t, system.Equal(pool))
	})
	t.Run("an unreadable root leaves the system roots", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), CA: &rootCA{rootErr: errQuoteRefused{step: "root"}}}
		assert.True(t, system.Equal(a.bmcTrustRoots()))
	})
	t.Run("a CA without a root leaves the system roots", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), CA: &rootCA{}}
		assert.True(t, system.Equal(a.bmcTrustRoots()))
	})
}

func TestCoverage964d_CertManagementScheduler(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).CertManagementScheduler())
	assert.Nil(t, (&App{Logger: logging.DefaultLogger(), daoFactory: foreignFactory{}}).CertManagementScheduler())
}

func TestCoverage964d_UpdateTOFUPin(t *testing.T) {
	ctx := context.Background()
	sum := sha256.Sum256([]byte("bmc spki"))
	spki := hex.EncodeToString(sum[:])

	t.Run("without the QuicBaaS factory nothing is stored", func(t *testing.T) {
		a := &App{Logger: logging.DefaultLogger(), daoFactory: foreignFactory{}}
		assert.NoError(t, a.updateTOFUPin(ctx, "bmc-1.example", 443, spki, "fp"))
	})
	t.Run("a pin-store failure is returned", func(t *testing.T) {
		// The memory harness's embedded transport has no parameter store,
		// so the put is refused; the refusal must reach the caller.
		a := newStoresHarness(t)
		err := a.updateTOFUPin(ctx, "bmc-1.example", 443, spki, "cert-fp")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trust/tofu/pins/bmc-1.example:443")
	})
}
