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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	localcertstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
)

var errInjectedTransport = errors.New("injected transport failure")

// failingTransport is a TPM whose every command fails.
type failingTransport struct{}

func (failingTransport) Send([]byte) ([]byte, error) { return nil, errInjectedTransport }

// failingTransportTPM is a simulator-backed TPM whose transport fails, so
// the platform cannot read TPM_PT_NV_INDEX_MAX through it.
type failingTransportTPM struct {
	xkmssdk.TrustedPlatformModule
}

func (failingTransportTPM) Transport() transport.TPM { return failingTransport{} }

// ekPlacementFixture is an App over the in-memory TPM simulator with the
// production TPM certificate store, the pieces ImportEndorsementKeyCertificate
// persists the EK certificate through.
type ekPlacementFixture struct {
	app       *App
	transport transport.TPM
	ekAttrs   *xkmssdk.KeyAttributes
	ekPub     crypto.PublicKey
}

func newEKPlacementFixture(t *testing.T, certHandle uint32) *ekPlacementFixture {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })
	tr := transport.FromReadWriter(sim)

	logger := logging.DefaultLogger()
	objStore, err := object.NewObjectStore(logger, object.NewMemoryClient(), t.TempDir(), nil)
	require.NoError(t, err)
	cs, csStorage, err := localcertstore.NewCertificateStoreWithStorage(logger, objStore)
	require.NoError(t, err)
	certStore := localcertstore.NewTPM2CertStoreAdapterWithStorage(logger, cs, csStorage)

	app := &App{Logger: logger, TPMConfig: *simulatedIDevIDConfig(), TPMCertStore: certStore}
	app.TPMConfig.EK.CertHandle = certHandle

	slogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	storage, err := xkmssdk.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(slogger, storage),
		CertStore: certStore,
		Config:    &app.TPMConfig,
		Logger:    slogger,
		Transport: tr,
	})
	if err == xkmssdk.ErrTPMNotInitialized {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, tpm.Close()) })
	app.TPM = tpm

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	ekPub, err := tpm.EKRSA()
	require.NoError(t, err)
	return &ekPlacementFixture{app: app, transport: tr, ekAttrs: ekAttrs, ekPub: ekPub}
}

// ekCertOfAtLeast issues a certificate for pub whose DER encoding is at least
// size bytes; padding of zero yields an ordinary, small certificate.
func ekCertOfAtLeast(t *testing.T, pub crypto.PublicKey, size int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "simulated EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if size > 0 {
		// An unknown non-critical extension is ignored by every consumer and
		// sets the encoded length.
		template.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: make([]byte, size),
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(der), size)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// nvDataSize returns the data size of the NV index, or the TPM's error when
// the index is not defined.
func nvDataSize(t *testing.T, tr transport.TPM, index uint32) (uint16, error) {
	t.Helper()
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tr)
	if err != nil {
		return 0, err
	}
	pub, err := rsp.NVPublic.Contents()
	require.NoError(t, err)
	return pub.DataSize, nil
}

func TestNVLimits(t *testing.T) {
	t.Run("reads both properties from the TPM", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		indexMax, err := nvIndexMax(f.transport)
		require.NoError(t, err)
		bufferMax, err := nvBufferMax(f.transport)
		require.NoError(t, err)
		assert.Positive(t, bufferMax)
		assert.Greater(t, indexMax, bufferMax,
			"the reference simulator's index limit exceeds its write limit")
	})

	t.Run("a failing TPM is a typed error naming the property", func(t *testing.T) {
		for name, read := range map[string]func(transport.TPM) (uint32, error){
			"TPM_PT_NV_INDEX_MAX":  nvIndexMax,
			"TPM_PT_NV_BUFFER_MAX": nvBufferMax,
		} {
			_, err := read(failingTransport{})
			var limitErr *NVLimitError
			require.ErrorAs(t, err, &limitErr)
			assert.Equal(t, name, limitErr.Property)
			assert.ErrorIs(t, err, errInjectedTransport)
		}
	})
}

func TestProvisionEKCertificate(t *testing.T) {
	t.Run("a certificate that fits goes to NV at the EK Credential Profile index", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		cert := ekCertOfAtLeast(t, f.ekPub, 0)

		require.NoError(t, f.app.provisionEKCertificate(nil, f.ekAttrs, cert))

		size, err := nvDataSize(t, f.transport, ekCertIndexRSA2048)
		require.NoError(t, err, "the EK certificate index must be defined")
		assert.Equal(t, len(cert.Raw), int(size))
		_, err = f.app.TPMCertStore.Get(f.ekAttrs)
		assert.Error(t, err, "a certificate that fits must not also go to the store")

		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw, "the read must find the certificate in NV")
	})

	t.Run("a certificate larger than TPM_PT_NV_INDEX_MAX goes to the store", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		indexMax, err := nvIndexMax(f.transport)
		require.NoError(t, err)
		cert := ekCertOfAtLeast(t, f.ekPub, int(indexMax)+128)

		require.NoError(t, f.app.provisionEKCertificate(nil, f.ekAttrs, cert))

		_, err = nvDataSize(t, f.transport, ekCertIndexRSA2048)
		assert.Error(t, err, "no NV index may be defined for a certificate that cannot fit one")
		stored, err := f.app.TPMCertStore.Get(f.ekAttrs)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, stored.Raw)

		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw, "the read must find the certificate in the store")
	})

	// go-xkms ProvisionEKCert writes the certificate in one TPM2_NV_Write,
	// so a certificate that fits an index but not one write must go to the
	// store (1500 bytes between the simulator's 1024 and 2048, #1152).
	t.Run("a certificate between TPM_PT_NV_BUFFER_MAX and TPM_PT_NV_INDEX_MAX goes to the store", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		indexMax, err := nvIndexMax(f.transport)
		require.NoError(t, err)
		bufferMax, err := nvBufferMax(f.transport)
		require.NoError(t, err)
		cert := ekCertOfAtLeast(t, f.ekPub, int(bufferMax)+128)
		require.LessOrEqual(t, len(cert.Raw), int(indexMax), "the certificate must fit one NV index")

		require.NoError(t, f.app.provisionEKCertificate(nil, f.ekAttrs, cert))

		_, err = nvDataSize(t, f.transport, ekCertIndexRSA2048)
		assert.Error(t, err, "no NV index may be defined for a certificate one write cannot carry")
		stored, err := f.app.TPMCertStore.Get(f.ekAttrs)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, stored.Raw)

		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw, "the read must find the certificate in the store")
	})

	t.Run("an NV write error is typed and never falls back to the store", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		first := ekCertOfAtLeast(t, f.ekPub, 0)
		require.NoError(t, f.app.provisionEKCertificate(nil, f.ekAttrs, first))

		// The index is now defined, so the TPM rejects a second define.
		second := ekCertOfAtLeast(t, f.ekPub, 0)
		err := f.app.provisionEKCertificate(nil, f.ekAttrs, second)

		var writeErr *EKCertNVWriteError
		require.ErrorAs(t, err, &writeErr)
		assert.Equal(t, len(second.Raw), writeErr.Size)
		_, err = f.app.TPMCertStore.Get(f.ekAttrs)
		assert.Error(t, err, "a failed NV write must not be downgraded to the store")
		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, first.Raw, got.Raw)
	})

	t.Run("without a cert-handle the certificate goes to the store", func(t *testing.T) {
		f := newEKPlacementFixture(t, 0)
		cert := ekCertOfAtLeast(t, f.ekPub, 0)

		require.NoError(t, f.app.provisionEKCertificate(nil, f.ekAttrs, cert))

		_, err := nvDataSize(t, f.transport, ekCertIndexRSA2048)
		assert.Error(t, err)
		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw)
	})

	t.Run("an oversized certificate without a store is a typed error", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		indexMax, err := nvIndexMax(f.transport)
		require.NoError(t, err)
		f.app.TPMCertStore = nil

		err = f.app.provisionEKCertificate(nil, f.ekAttrs, ekCertOfAtLeast(t, f.ekPub, int(indexMax)+128))
		assert.ErrorIs(t, err, ErrTPMCertStoreNotConfigured)
	})

	t.Run("an unreadable NV limit is a typed error", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		f.app.TPM = failingTransportTPM{TrustedPlatformModule: f.app.TPM}

		err := f.app.provisionEKCertificate(nil, f.ekAttrs, ekCertOfAtLeast(t, f.ekPub, 0))
		var limitErr *NVLimitError
		require.ErrorAs(t, err, &limitErr)
		_, err = f.app.TPMCertStore.Get(f.ekAttrs)
		assert.Error(t, err)
	})
}

// errInjectedEKRead is an EKCertificate failure that is not the
// missing-certificate case.
var errInjectedEKRead = errors.New("injected EK certificate read failure")

// ekIssuingCA issues a preset EK certificate and records the key it was
// asked to certify.
type ekIssuingCA struct {
	quicbaasca.CACertificateAuthority
	cert   *x509.Certificate
	issued []crypto.PublicKey
}

func (ca *ekIssuingCA) IssueEKCertificate(_ context.Context, _ *quicbaasca.CACertificateRequest, pub crypto.PublicKey) (*x509.Certificate, error) {
	ca.issued = append(ca.issued, pub)
	return ca.cert, nil
}

// ekCertReadErrorTPM fails every EKCertificate read with err.
type ekCertReadErrorTPM struct {
	xkmssdk.TrustedPlatformModule
	err error
}

func (tpm ekCertReadErrorTPM) EKCertificate() (*x509.Certificate, error) {
	return nil, tpm.err
}

// withIssuingCA enables the local CA on the fixture's app, issuing cert, and
// sets the owner hierarchy auth to the configured EK hierarchy auth the
// importer presents, as the platform's TPM.Provision(soPIN) does.
func (f *ekPlacementFixture) withIssuingCA(t *testing.T, cert *x509.Certificate) *ekIssuingCA {
	t.Helper()
	_, err := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte(f.app.TPMConfig.EK.HierarchyAuth)},
	}.Execute(f.transport)
	require.NoError(t, err)

	ca := &ekIssuingCA{cert: cert}
	f.app.CA = ca
	f.app.CAConfig = &trustedca.CAConfig{}
	return ca
}

// TestImportEndorsementKeyCertificate drives the EK placement through the
// production importer. The SDK's EKCertificate wraps
// ErrTPMEndorsementCertNotFound after its NV lookups fail (Codex 8532), so
// the importer must match it with errors.Is to reach the placement.
func TestImportEndorsementKeyCertificate(t *testing.T) {
	t.Run("the missing certificate is the SDK's wrapped not-found error", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)

		_, err := f.app.TPM.EKCertificate()
		require.ErrorIs(t, err, xkmssdk.ErrTPMEndorsementCertNotFound)
	})

	t.Run("a missing certificate that fits is issued and placed in NV", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		cert := ekCertOfAtLeast(t, f.ekPub, 0)
		ca := f.withIssuingCA(t, cert)

		imported, err := f.app.ImportEndorsementKeyCertificate(context.Background())
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, imported.Raw)
		assert.Equal(t, []crypto.PublicKey{f.ekPub}, ca.issued, "the CA must certify the EK public key")

		size, err := nvDataSize(t, f.transport, ekCertIndexRSA2048)
		require.NoError(t, err, "the EK certificate index must be defined")
		assert.Equal(t, len(cert.Raw), int(size))
		_, err = f.app.TPMCertStore.Get(f.ekAttrs)
		assert.Error(t, err, "a certificate that fits must not also go to the store")

		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw, "the read must find the certificate in NV")
	})

	t.Run("a missing oversized certificate is issued and placed in the store", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		indexMax, err := nvIndexMax(f.transport)
		require.NoError(t, err)
		cert := ekCertOfAtLeast(t, f.ekPub, int(indexMax)+128)
		f.withIssuingCA(t, cert)

		imported, err := f.app.ImportEndorsementKeyCertificate(context.Background())
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, imported.Raw)

		_, err = nvDataSize(t, f.transport, ekCertIndexRSA2048)
		assert.Error(t, err, "no NV index may be defined for a certificate that cannot fit one")
		stored, err := f.app.TPMCertStore.Get(f.ekAttrs)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, stored.Raw)

		got, err := f.app.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got.Raw, "the read must find the certificate in the store")
	})

	t.Run("any other EKCertificate error is returned unchanged and nothing is provisioned", func(t *testing.T) {
		f := newEKPlacementFixture(t, ekCertIndexRSA2048)
		ca := f.withIssuingCA(t, ekCertOfAtLeast(t, f.ekPub, 0))
		f.app.TPM = ekCertReadErrorTPM{TrustedPlatformModule: f.app.TPM, err: errInjectedEKRead}

		imported, err := f.app.ImportEndorsementKeyCertificate(context.Background())
		assert.Nil(t, imported)
		assert.Same(t, errInjectedEKRead, err)
		assert.Empty(t, ca.issued, "no certificate may be issued")

		_, err = nvDataSize(t, f.transport, ekCertIndexRSA2048)
		assert.Error(t, err, "no NV index may be defined")
		_, err = f.app.TPMCertStore.Get(f.ekAttrs)
		assert.Error(t, err, "nothing may go to the store")
	})
}

func TestEKCertErrorMessages(t *testing.T) {
	cause := errors.New("TPM_RC_NV_DEFINED")
	writeErr := &EKCertNVWriteError{Size: 900, Err: cause}
	assert.Contains(t, writeErr.Error(), "900-byte EK certificate")
	assert.ErrorIs(t, writeErr, cause)

	limitErr := &NVLimitError{Property: "TPM_PT_NV_BUFFER_MAX", Err: cause}
	assert.Contains(t, limitErr.Error(), "TPM_PT_NV_BUFFER_MAX")
	assert.ErrorIs(t, limitErr, cause)
}
