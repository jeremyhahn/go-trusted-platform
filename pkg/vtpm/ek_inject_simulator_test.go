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

package vtpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newSimulatorTransport returns a started in-process TPM simulator.
func newSimulatorTransport(t *testing.T) transport.TPM {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })
	return transport.FromReadWriter(sim)
}

// newSimulatorTPMOperations returns TPMOperations over a provisioned
// simulator, the state service.injectEKCertificate reaches before it
// injects the certificate.
func newSimulatorTPMOperations(t *testing.T, algorithm EKAlgorithm) (*TPMOperations, transport.TPM) {
	t.Helper()

	tpmTransport := newSimulatorTransport(t)
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Config:    tpmOperationsConfig("", algorithm, "vm-01"),
		Transport: tpmTransport,
	})
	if err != nil {
		require.ErrorIs(t, err, xkmssdk.ErrTPMNotInitialized)
	}
	ops := &TPMOperations{tpm: tpm, algorithm: algorithm, logger: logging.DefaultLogger()}
	require.NoError(t, ops.Provision(""))
	return ops, tpmTransport
}

// eKCertificateOfSize issues a certificate for publicKey padded with a
// private, non-critical extension so that its DER is at least minSize bytes.
func eKCertificateOfSize(t *testing.T, publicKey crypto.PublicKey, minSize int) *x509.Certificate {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vm-01"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: make([]byte, minSize),
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(cert.Raw), minSize)
	return cert
}

// TestTPMOperations_InjectEKCertificate_LargerThanNVBufferMax injects an EK
// certificate larger than the TPM's TPM_PT_NV_BUFFER_MAX after a full
// provisioning cycle — the CI failure, where swtpm answered the single
// TPM2_NV_Write with TPM_RC_SIZE — and reads it back from its TCG index.
func TestTPMOperations_InjectEKCertificate_LargerThanNVBufferMax(t *testing.T) {
	for _, algorithm := range []EKAlgorithm{EKAlgorithmRSA, EKAlgorithmECC} {
		t.Run(string(algorithm), func(t *testing.T) {
			ops, tpmTransport := newSimulatorTPMOperations(t, algorithm)

			reader := NewEKCertInjector("", nil)
			reader.SetNVBufferMax(0)
			bufferMax, err := reader.chunkSize(tpmTransport)
			require.NoError(t, err)

			ekPub, err := ops.GetEKPublicKey()
			require.NoError(t, err)
			cert := eKCertificateOfSize(t, ekPub, int(bufferMax)+1)

			require.NoError(t, ops.InjectEKCertificate(cert))

			stored, err := reader.readCertificate(tpmTransport, algorithm.NVIndex())
			require.NoError(t, err)
			require.Equal(t, cert.Raw, stored.Raw)
		})
	}
}

// TestEKCertInjector_WriteCertificate_SmallNVBufferMax bounds every NV
// transfer to 64 bytes so a certificate takes many chunks at increasing
// offsets, and reads it back with the same bound.
func TestEKCertInjector_WriteCertificate_SmallNVBufferMax(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := eKCertificateOfSize(t, &key.PublicKey, 200)

	injector := NewEKCertInjector("", nil)
	injector.SetNVBufferMax(64)
	require.NoError(t, injector.writeCertificate(tpmTransport, cert, EKAlgorithmRSA))

	stored, err := injector.readCertificate(tpmTransport, NVIndexRSAEKCert)
	require.NoError(t, err)
	require.Equal(t, cert.Raw, stored.Raw)
}

// TestEKCertInjector_ChunkSize takes the smaller of the injector's bound and
// the TPM's TPM_PT_NV_BUFFER_MAX, and the TPM's alone when the bound is zero.
func TestEKCertInjector_ChunkSize(t *testing.T) {
	tpmTransport := newSimulatorTransport(t)
	injector := NewEKCertInjector("", nil)

	injector.SetNVBufferMax(0)
	tpmMax, err := injector.chunkSize(tpmTransport)
	require.NoError(t, err)
	require.NotZero(t, tpmMax)

	injector.SetNVBufferMax(tpmMax - 1)
	got, err := injector.chunkSize(tpmTransport)
	require.NoError(t, err)
	require.Equal(t, tpmMax-1, got)

	injector.SetNVBufferMax(^uint16(0))
	got, err = injector.chunkSize(tpmTransport)
	require.NoError(t, err)
	require.Equal(t, tpmMax, got)
}

// TestEKCertInjector_WriteCertificate_TPMUnavailable fails with a typed
// error, before defining any NV index, when the TPM cannot report its NV
// buffer maximum.
func TestEKCertInjector_WriteCertificate_TPMUnavailable(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	require.NoError(t, sim.Close())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := eKCertificateOfSize(t, &key.PublicKey, 1)

	err = NewEKCertInjector("", nil).writeCertificate(transport.FromReadWriter(sim), cert, EKAlgorithmRSA)
	var unavailable ErrNVBufferMaxUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	var writeFailed ErrNVRAMWriteFailed
	require.True(t, errors.As(err, &writeFailed), "got %v", err)
	require.Equal(t, NVIndexRSAEKCert, writeFailed.NVIndex)
}

// TestEKCertInjector_WriteCertificate_NilCertificate rejects a nil
// certificate without touching the TPM.
func TestEKCertInjector_WriteCertificate_NilCertificate(t *testing.T) {
	err := NewEKCertInjector("", nil).writeCertificate(nil, nil, EKAlgorithmRSA)
	var injectFailed ErrEKCertInjectionFailed
	require.True(t, errors.As(err, &injectFailed), "got %v", err)
}
