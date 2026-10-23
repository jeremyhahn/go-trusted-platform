// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/hostquote"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// bootingDisklessTPM is the strict diskless TPM plus the operations a boot
// delivery uses: quoting with the IAK and storing the recovered
// certificates. Anything else still panics through the nil embedded TPM.
type bootingDisklessTPM struct {
	*strictDisklessTPM
	iak      *ecdsa.PrivateKey
	iakErr   error
	quoteErr error
	storeErr error

	storedIAK    *x509.Certificate
	storedIDevID *x509.Certificate
}

func newBootingDisklessTPM(t *testing.T) *bootingDisklessTPM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &bootingDisklessTPM{strictDisklessTPM: &strictDisklessTPM{t: t}, iak: key}
}

func (b *bootingDisklessTPM) IAK() (crypto.PublicKey, error) {
	if b.iakErr != nil {
		return nil, b.iakErr
	}
	return b.iak.Public(), nil
}

func (b *bootingDisklessTPM) ProvisionIAKCert(cert *x509.Certificate) error {
	if b.storeErr != nil {
		return b.storeErr
	}
	b.storedIAK = cert
	return nil
}

func (b *bootingDisklessTPM) ProvisionIDevIDCert(cert *x509.Certificate) error {
	if b.storeErr != nil {
		return b.storeErr
	}
	b.storedIDevID = cert
	return nil
}

// errNoStoredCertificate is the fake TPM certificate store's empty slot.
var errNoStoredCertificate = errors.New("no certificate stored")

func (b *bootingDisklessTPM) IAKCertificate() (*x509.Certificate, error) {
	if b.storedIAK == nil {
		return nil, errNoStoredCertificate
	}
	return b.storedIAK, nil
}

func (b *bootingDisklessTPM) IDevIDCertificate() (*x509.Certificate, error) {
	if b.storedIDevID == nil {
		return nil, errNoStoredCertificate
	}
	return b.storedIDevID, nil
}

// pcrValue is the SHA-256 value the fake TPM reports for a register.
func pcrValue(idx uint) []byte {
	v := sha256.Sum256([]byte{byte(idx)})
	return v[:]
}

// Quote signs a real TPMS_ATTEST over the selected registers with the IAK,
// so hostquote's structural checks run against it unchanged.
func (b *bootingDisklessTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	if b.quoteErr != nil {
		return xkmssdk.Quote{}, b.quoteErr
	}
	sorted := append([]uint(nil), pcrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	h := sha256.New()
	for _, idx := range sorted {
		h.Write(pcrValue(idx))
	}
	quoted := libtpm2.Marshal(libtpm2.TPMSAttest{
		Magic:     libtpm2.TPMGeneratedValue,
		Type:      libtpm2.TPMSTAttestQuote,
		ExtraData: libtpm2.TPM2BData{Buffer: nonce},
		Attested: libtpm2.NewTPMUAttest(libtpm2.TPMSTAttestQuote, &libtpm2.TPMSQuoteInfo{
			PCRSelect: libtpm2.TPMLPCRSelection{PCRSelections: []libtpm2.TPMSPCRSelection{{
				Hash: libtpm2.TPMAlgSHA256, PCRSelect: libtpm2.PCClientCompatible.PCRs(pcrs...),
			}}},
			PCRDigest: libtpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	})
	digest := sha256.Sum256(quoted)
	sig, err := ecdsa.SignASN1(rand.Reader, b.iak, digest[:])
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	return xkmssdk.Quote{Quoted: quoted, Signature: sig, Nonce: nonce}, nil
}

func (b *bootingDisklessTPM) ReadPCRs(pcrs []uint) ([]xkmssdk.PCRBank, error) {
	bank := xkmssdk.PCRBank{Algorithm: "SHA256"}
	for _, idx := range pcrs {
		bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(idx), Value: pcrValue(idx)})
	}
	return []xkmssdk.PCRBank{bank}, nil
}

// importingCA records what the CA certificate store was given, in order.
type importingCA struct {
	quicbaasca.CACertificateAuthority
	refuse   error
	imported []*x509.Certificate
}

func (c *importingCA) ImportCertificate(_ context.Context, cert *x509.Certificate) error {
	c.imported = append(c.imported, cert)
	return c.refuse
}

// disklessPKI is a platform CA (root and intermediate) that issued a node's
// IDevID and an IAK certificate for the TPM's IAK.
type disklessPKI struct {
	root, intermediate, idevid, iak *x509.Certificate
}

func issueTestCert(t *testing.T, serial int64, cn string, isCA bool, pub crypto.PublicKey,
	parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newDisklessPKI(t *testing.T, iak crypto.PublicKey) *disklessPKI {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	rootKey, intermediateKey, idevidKey := newKey(), newKey(), newKey()
	root := issueTestCert(t, 1, "Platform Root CA", true, rootKey.Public(), nil, rootKey)
	intermediate := issueTestCert(t, 2, "Platform Intermediate CA", true, intermediateKey.Public(), root, rootKey)
	return &disklessPKI{
		root:         root,
		intermediate: intermediate,
		idevid:       issueTestCert(t, 3, "node-1.example", false, idevidKey.Public(), intermediate, intermediateKey),
		iak:          issueTestCert(t, 4, "node-1.example IAK", false, iak, intermediate, intermediateKey),
	}
}

func pemChain(certs ...*x509.Certificate) string {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(out)
}

// delivery is what a control plane that knows this node hands back.
func (p *disklessPKI) delivery() *provisioning.BootDeliveryResponse {
	return &provisioning.BootDeliveryResponse{
		Serial:      "SN-42",
		IDevIDChain: pemChain(p.idevid, p.intermediate),
		AttestCert:  pemChain(p.iak),
		CABundle:    pemChain(p.root, p.intermediate),
	}
}

func TestDisklessBootTarget(t *testing.T) {
	configured := func() *App {
		return &App{
			Hostname:     "node-1.example",
			nodeIdentity: "ek-00112233445566778899aabbccddeeff",
			ACMEConfig:   &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{DirectoryURL: "https://cp.example:8443/acme/directory"}},
		}
	}

	target, err := configured().disklessBootTarget()
	require.NoError(t, err)
	assert.Equal(t, "https://cp.example:8443", target.serverURL, "the provisioning API is served beside the ACME directory")
	assert.Equal(t, "ek-00112233445566778899aabbccddeeff", target.identity,
		"the IDevID is enrolled under the EK-derived identity, never the image's hostname")

	t.Run("the hostname is cosmetic", func(t *testing.T) {
		app := configured()
		app.Hostname = ""
		target, err := app.disklessBootTarget()
		require.NoError(t, err)
		assert.Equal(t, "ek-00112233445566778899aabbccddeeff", target.identity)
	})

	t.Run("no EK-derived identity", func(t *testing.T) {
		app := configured()
		app.nodeIdentity = ""
		_, err := app.disklessBootTarget()
		var unavailable ErrDisklessIdentityUnavailable
		require.ErrorAs(t, err, &unavailable)
	})

	cases := map[string]struct {
		mutate  func(*App)
		setting string
	}{
		"no ACME section":  {func(a *App) { a.ACMEConfig = nil }, "acme.client.directory-url"},
		"no ACME client":   {func(a *App) { a.ACMEConfig.Client = nil }, "acme.client.directory-url"},
		"no directory URL": {func(a *App) { a.ACMEConfig.Client.DirectoryURL = "" }, "acme.client.directory-url"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			app := configured()
			tc.mutate(app)
			_, err := app.disklessBootTarget()
			var unconfigured ErrDisklessBootUnconfigured
			require.ErrorAs(t, err, &unconfigured)
			assert.Equal(t, tc.setting, unconfigured.Setting)
		})
	}
}

func TestDisklessServerRoots_TrustsTheImageCABundle(t *testing.T) {
	pki := newDisklessPKI(t, newBootingDisklessTPM(t).iak.Public())
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca-bundle.pem"), []byte(pemChain(pki.root)), 0o600))
	app := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)
	app.ConfigDir = dir
	app.PlatformDir = t.TempDir()

	roots, err := app.disklessServerRoots()
	require.NoError(t, err)
	_, err = pki.intermediate.Verify(x509.VerifyOptions{Roots: roots})
	assert.NoError(t, err, "a control plane issued by the image's CA must verify")
}

func TestDisklessServerRoots_RefusesABundleWithoutCertificates(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca-bundle.pem"), []byte("not a certificate"), 0o600))
	app := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)
	app.ConfigDir = dir
	app.PlatformDir = t.TempDir()

	_, err := app.disklessServerRoots()
	var invalid ErrDisklessBootMaterialInvalid
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Reason, filepath.Join(dir, "ca-bundle.pem"))
}

func TestCheckDisklessIdentity_AcceptsMaterialCertifyingTheTPMKeys(t *testing.T) {
	tpm := newBootingDisklessTPM(t)
	pki := newDisklessPKI(t, tpm.iak.Public())
	app := disklessApp(tpm.strictDisklessTPM)
	app.TPM = tpm

	identity, err := app.checkDisklessIdentity(pki.delivery())
	require.NoError(t, err)
	assert.Equal(t, pki.idevid.Raw, identity.idevid[0].Raw)
	assert.Equal(t, pki.iak.Raw, identity.iak.Raw)
	assert.Equal(t, []*x509.Certificate{pki.intermediate, pki.root}, identity.issuers,
		"the intermediate is in both the chain and the bundle; it is imported once")
}

func TestCheckDisklessIdentity_RefusesMaterialNotForThisTPM(t *testing.T) {
	tpmFault := errors.New("tpm offline")
	cases := map[string]struct {
		mutate func(*provisioning.BootDeliveryResponse, *bootingDisklessTPM)
		cause  error
	}{
		"IAK certificate for another key": {mutate: func(d *provisioning.BootDeliveryResponse, tpm *bootingDisklessTPM) {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			tpm.iak = other
		}},
		"no IAK certificate recorded": {mutate: func(d *provisioning.BootDeliveryResponse, _ *bootingDisklessTPM) {
			d.AttestCert = ""
		}},
		"IAK certificate unparsable": {mutate: func(d *provisioning.BootDeliveryResponse, _ *bootingDisklessTPM) {
			d.AttestCert = "garbage"
		}, cause: provisioning.ErrCertificateChainInvalid},
		"IDevID chain unparsable": {mutate: func(d *provisioning.BootDeliveryResponse, _ *bootingDisklessTPM) {
			d.IDevIDChain = "garbage"
		}, cause: provisioning.ErrCertificateChainInvalid},
		"CA bundle unparsable": {mutate: func(d *provisioning.BootDeliveryResponse, _ *bootingDisklessTPM) {
			d.CABundle = "garbage"
		}, cause: provisioning.ErrCertificateChainInvalid},
		"TPM IAK unreadable": {mutate: func(_ *provisioning.BootDeliveryResponse, tpm *bootingDisklessTPM) {
			tpm.iakErr = tpmFault
		}, cause: tpmFault},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newBootingDisklessTPM(t)
			pki := newDisklessPKI(t, tpm.iak.Public())
			app := disklessApp(tpm.strictDisklessTPM)
			app.TPM = tpm
			delivery := pki.delivery()
			tc.mutate(delivery, tpm)

			_, err := app.checkDisklessIdentity(delivery)
			var invalid ErrDisklessBootMaterialInvalid
			require.ErrorAs(t, err, &invalid)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
		})
	}
}

func TestInstallDisklessIdentity_StoresWhereEnrollmentDoes(t *testing.T) {
	tpm := newBootingDisklessTPM(t)
	pki := newDisklessPKI(t, tpm.iak.Public())
	ca := &importingCA{}
	app := disklessApp(tpm.strictDisklessTPM)
	app.TPM = tpm
	app.CA = ca
	identity, err := app.checkDisklessIdentity(pki.delivery())
	require.NoError(t, err)

	require.NoError(t, app.installDisklessIdentity(context.Background(), identity))
	assert.Equal(t, []*x509.Certificate{pki.intermediate, pki.root, identity.iak, identity.idevid[0]}, ca.imported,
		"issuers land before the leaves they issued")
	assert.Equal(t, pki.iak.Raw, tpm.storedIAK.Raw)
	assert.Equal(t, pki.idevid.Raw, tpm.storedIDevID.Raw)
	assert.True(t, platformIdentityComplete(app.TPM), "the stored certificates complete the platform identity")
}

func TestInstallDisklessIdentity_CARefusalIsLoggedTPMRefusalIsFatal(t *testing.T) {
	tpm := newBootingDisklessTPM(t)
	pki := newDisklessPKI(t, tpm.iak.Public())
	app := disklessApp(tpm.strictDisklessTPM)
	app.TPM = tpm
	app.CA = &importingCA{refuse: errors.New("already imported")}
	identity, err := app.checkDisklessIdentity(pki.delivery())
	require.NoError(t, err)

	require.NoError(t, app.installDisklessIdentity(context.Background(), identity),
		"a certificate the CA store already holds must not stop the boot")

	tpm.storeErr = errors.New("nv full")
	err = app.installDisklessIdentity(context.Background(), identity)
	require.ErrorIs(t, err, tpm.storeErr)
}

func TestDisklessBootQuote_IsEvidenceOverTheConnectionNonce(t *testing.T) {
	tpm := newBootingDisklessTPM(t)
	app := disklessApp(tpm.strictDisklessTPM)
	app.TPM = tpm
	nonce := []byte("exported-keying-material-32bytes")

	raw, err := app.disklessBootQuote(context.Background(), nonce)
	require.NoError(t, err)
	var evidence vm.QuoteEvidence
	require.NoError(t, json.Unmarshal(raw, &evidence))
	assert.Equal(t, nonce, evidence.Nonce)
	assert.NotEmpty(t, evidence.Signature)
	assert.NotEmpty(t, evidence.PCRs, "the verifier needs the PCR values the quote digests")

	tpm.quoteErr = errors.New("tpm busy")
	_, err = app.disklessBootQuote(context.Background(), nonce)
	var collect hostquote.ErrCollectFailed
	require.ErrorAs(t, err, &collect)
	assert.ErrorIs(t, err, tpm.quoteErr)
}

func TestPresentedChain_LeafFirstWithIntermediates(t *testing.T) {
	pki := newDisklessPKI(t, newBootingDisklessTPM(t).iak.Public())
	signer := newBootingDisklessTPM(t).iak

	cert := presentedChain([]*x509.Certificate{pki.idevid, pki.intermediate}, signer)
	assert.Equal(t, [][]byte{pki.idevid.Raw, pki.intermediate.Raw}, cert.Certificate)
	assert.Same(t, pki.idevid, cert.Leaf)
	assert.Equal(t, signer, cert.PrivateKey)
}

// startCertificateOnlyControlPlane serves the anonymous certificate route
// and fails the test if the delivery route is reached.
// startUnreachedControlPlane is a control plane a node that cannot prove its
// IDevID key must never contact.
func startUnreachedControlPlane(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s %s: a node without its IDevID key must not ask", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{bundle.ServerCert}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, bundle.CAPool
}

// TestFetchDisklessIdentity_FailsClosed covers the node's side up to the
// signature: the proof and the exchange are covered in pkg/provisioning and,
// against the real handler, in pkg/webservice/v1/device.
func TestFetchDisklessIdentity_FailsClosed(t *testing.T) {
	server, roots := startUnreachedControlPlane(t)
	target := disklessBootTarget{serverURL: server.URL, identity: "node-1.example"}
	idevidKey := newEK(t)

	cases := map[string]struct {
		mutate func(app *App, tpm *bootingDisklessTPM)
		check  func(t *testing.T, err error)
	}{
		"IDevID not configured": {
			mutate: func(app *App, _ *bootingDisklessTPM) { app.TPMConfig.IDevID = nil },
			check: func(t *testing.T, err error) {
				require.ErrorAs(t, err, &ErrDisklessIdentityUnavailable{})
			},
		},
		"IDevID handle empty": {
			mutate: func(_ *App, tpm *bootingDisklessTPM) {
				delete(tpm.objects, libtpm2.TPMHandle(testIDevIDHandle))
			},
			check: func(t *testing.T, err error) {
				require.ErrorAs(t, err, &ErrDisklessIdentityUnavailable{})
			},
		},
		"no platform key store to sign with": {
			mutate: func(app *App, _ *bootingDisklessTPM) { app.PlatformKS = nil },
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, provisioning.ErrMissingCertificate)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newBootingDisklessTPM(t)
			tpm.objects = map[libtpm2.TPMHandle]libtpm2.TPMTPublic{
				libtpm2.TPMHandle(testIDevIDHandle): eccObject(t, idevidKey, false, false, true),
			}
			app := disklessApp(tpm.strictDisklessTPM)
			app.TPM = tpm
			tc.mutate(app, tpm)

			resp, err := app.fetchDisklessIdentity(context.Background(), target, roots)
			assert.Nil(t, resp)
			tc.check(t, err)
		})
	}
}

func TestRecoverDisklessIdentity_UnconfiguredFailsBeforeTouchingAnything(t *testing.T) {
	// The strict TPM panics on any call: an unconfigured node must refuse
	// before it initializes the CA, dials, or quotes.
	app := disklessApp(newBootingDisklessTPM(t).strictDisklessTPM)

	err := app.recoverDisklessIdentity(context.Background(), nil, nil, nil)
	var unavailable ErrDisklessIdentityUnavailable
	require.ErrorAs(t, err, &unavailable)
	var unconfigured ErrDisklessBootUnconfigured
	assert.ErrorAs(t, err, &unconfigured)
}
