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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVMQuoteTPM is a test double for the VMQuoteTPM seam.
type fakeVMQuoteTPM struct {
	quoteFunc    func(pcrs []uint, nonce []byte) (xkmssdk.Quote, error)
	readPCRsFunc func(pcrList []uint) ([]xkmssdk.PCRBank, error)
	iakFunc      func() (crypto.PublicKey, error)
	ekCertFunc   func() (*x509.Certificate, error)

	lastQuotePCRs  []uint
	lastQuoteNonce []byte
}

func (f *fakeVMQuoteTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	f.lastQuotePCRs = pcrs
	f.lastQuoteNonce = nonce
	if f.quoteFunc != nil {
		return f.quoteFunc(pcrs, nonce)
	}
	return xkmssdk.Quote{
		Quoted:    []byte("quoted-data"),
		Signature: []byte("signature-data"),
		Nonce:     nonce,
	}, nil
}

func (f *fakeVMQuoteTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	if f.readPCRsFunc != nil {
		return f.readPCRsFunc(pcrList)
	}
	pcrs := make([]xkmssdk.PCR, 0, len(pcrList))
	for _, pcr := range pcrList {
		pcrs = append(pcrs, xkmssdk.PCR{ID: int32(pcr), Value: []byte{byte(pcr), 0xAA}})
	}
	return []xkmssdk.PCRBank{{Algorithm: "SHA256", PCRs: pcrs}}, nil
}

func (f *fakeVMQuoteTPM) IAK() (crypto.PublicKey, error) {
	if f.iakFunc != nil {
		return f.iakFunc()
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

func (f *fakeVMQuoteTPM) EKCertificate() (*x509.Certificate, error) {
	if f.ekCertFunc != nil {
		return f.ekCertFunc()
	}
	return newSelfSignedTestCert()
}

// newSelfSignedTestCert generates a minimal self-signed certificate.
func newSelfSignedTestCert() (*x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vm:test@host:test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func TestNewVMAttestorDevice_NilTPM(t *testing.T) {
	device, err := NewVMAttestorDevice(nil, nil)
	require.Error(t, err)
	assert.Nil(t, device)
	var tpmErr ErrVMAttestorDeviceTPMRequired
	assert.True(t, errors.As(err, &tpmErr))
}

func TestVMAttestorDevice_GenerateQuote(t *testing.T) {
	fake := &fakeVMQuoteTPM{}
	device, err := NewVMAttestorDevice(fake, nil)
	require.NoError(t, err)

	quote, signature, err := device.GenerateQuote(context.Background(), []byte("nonce"), []int{0, 7}, vm.HashAlgorithmSHA256)
	require.NoError(t, err)
	assert.Equal(t, []byte("quoted-data"), quote)
	assert.Equal(t, []byte("signature-data"), signature)
	assert.Equal(t, []uint{0, 7}, fake.lastQuotePCRs)
	assert.Equal(t, []byte("nonce"), fake.lastQuoteNonce)
}

func TestVMAttestorDevice_GenerateQuote_Errors(t *testing.T) {
	t.Run("unsupported algorithm", func(t *testing.T) {
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
		require.NoError(t, err)

		_, _, err = device.GenerateQuote(context.Background(), []byte("n"), []int{0}, vm.HashAlgorithmSHA1)
		require.Error(t, err)
		var algErr ErrUnsupportedQuoteAlgorithm
		assert.True(t, errors.As(err, &algErr))
	})

	t.Run("invalid PCR index", func(t *testing.T) {
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
		require.NoError(t, err)

		_, _, err = device.GenerateQuote(context.Background(), []byte("n"), []int{24}, vm.HashAlgorithmSHA256)
		require.Error(t, err)
		var idxErr ErrInvalidPCRIndex
		assert.True(t, errors.As(err, &idxErr))
	})

	t.Run("TPM quote failure", func(t *testing.T) {
		fake := &fakeVMQuoteTPM{
			quoteFunc: func(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
				return xkmssdk.Quote{}, errors.New("tpm unavailable")
			},
		}
		device, err := NewVMAttestorDevice(fake, nil)
		require.NoError(t, err)

		_, _, err = device.GenerateQuote(context.Background(), []byte("n"), []int{0}, vm.HashAlgorithmSHA256)
		require.Error(t, err)
		var quoteErr ErrVMQuoteFailed
		assert.True(t, errors.As(err, &quoteErr))
	})

	t.Run("canceled context", func(t *testing.T) {
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err = device.GenerateQuote(ctx, []byte("n"), []int{0}, vm.HashAlgorithmSHA256)
		require.Error(t, err)
	})
}

func TestVMAttestorDevice_ReadPCR(t *testing.T) {
	device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
	require.NoError(t, err)

	value, err := device.ReadPCR(context.Background(), 7, vm.HashAlgorithmSHA256)
	require.NoError(t, err)
	assert.Equal(t, []byte{7, 0xAA}, value)
}

func TestVMAttestorDevice_ReadPCR_Errors(t *testing.T) {
	t.Run("invalid index", func(t *testing.T) {
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
		require.NoError(t, err)

		_, err = device.ReadPCR(context.Background(), -1, vm.HashAlgorithmSHA256)
		require.Error(t, err)
		var idxErr ErrInvalidPCRIndex
		assert.True(t, errors.As(err, &idxErr))
	})

	t.Run("bank not found", func(t *testing.T) {
		fake := &fakeVMQuoteTPM{
			readPCRsFunc: func(pcrList []uint) ([]xkmssdk.PCRBank, error) {
				return []xkmssdk.PCRBank{{Algorithm: "SHA1", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte{1}}}}}, nil
			},
		}
		device, err := NewVMAttestorDevice(fake, nil)
		require.NoError(t, err)

		_, err = device.ReadPCR(context.Background(), 0, vm.HashAlgorithmSHA256)
		require.Error(t, err)
		var bankErr ErrPCRBankValueNotFound
		assert.True(t, errors.As(err, &bankErr))
	})

	t.Run("TPM read failure", func(t *testing.T) {
		fake := &fakeVMQuoteTPM{
			readPCRsFunc: func(pcrList []uint) ([]xkmssdk.PCRBank, error) {
				return nil, errors.New("read failed")
			},
		}
		device, err := NewVMAttestorDevice(fake, nil)
		require.NoError(t, err)

		_, err = device.ReadPCR(context.Background(), 0, vm.HashAlgorithmSHA256)
		require.Error(t, err)
		var readErr ErrPCRReadFailedVM
		assert.True(t, errors.As(err, &readErr))
	})
}

func TestVMAttestorDevice_GetAIKPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fake := &fakeVMQuoteTPM{
		iakFunc: func() (crypto.PublicKey, error) { return &key.PublicKey, nil },
	}
	device, err := NewVMAttestorDevice(fake, nil)
	require.NoError(t, err)

	der, err := device.GetAIKPublicKey(context.Background())
	require.NoError(t, err)

	parsed, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(parsed.(*rsa.PublicKey)))
}

func TestVMAttestorDevice_GetAIKPublicKey_Error(t *testing.T) {
	fake := &fakeVMQuoteTPM{
		iakFunc: func() (crypto.PublicKey, error) { return nil, errors.New("no IAK") },
	}
	device, err := NewVMAttestorDevice(fake, nil)
	require.NoError(t, err)

	_, err = device.GetAIKPublicKey(context.Background())
	require.Error(t, err)
	var aikErr ErrAIKPublicKeyUnavailable
	assert.True(t, errors.As(err, &aikErr))
}

func TestVMAttestorDevice_GetEKCertificate(t *testing.T) {
	device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
	require.NoError(t, err)

	der, err := device.GetEKCertificate(context.Background())
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, "vm:test@host:test", cert.Subject.CommonName)
}

func TestVMAttestorDevice_GetEKCertificate_Errors(t *testing.T) {
	t.Run("TPM error", func(t *testing.T) {
		fake := &fakeVMQuoteTPM{
			ekCertFunc: func() (*x509.Certificate, error) { return nil, errors.New("no cert") },
		}
		device, err := NewVMAttestorDevice(fake, nil)
		require.NoError(t, err)

		_, err = device.GetEKCertificate(context.Background())
		require.Error(t, err)
		var ekErr ErrEKCertificateUnavailable
		assert.True(t, errors.As(err, &ekErr))
	})

	t.Run("nil certificate", func(t *testing.T) {
		fake := &fakeVMQuoteTPM{
			ekCertFunc: func() (*x509.Certificate, error) { return nil, nil },
		}
		device, err := NewVMAttestorDevice(fake, nil)
		require.NoError(t, err)

		_, err = device.GetEKCertificate(context.Background())
		require.Error(t, err)
		var ekErr ErrEKCertificateUnavailable
		assert.True(t, errors.As(err, &ekErr))
	})
}

func TestVMAttestorDevice_Close(t *testing.T) {
	t.Run("without release", func(t *testing.T) {
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
		require.NoError(t, err)
		require.NoError(t, device.Close())
	})

	t.Run("with release", func(t *testing.T) {
		released := false
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, func() error {
			released = true
			return nil
		})
		require.NoError(t, err)
		require.NoError(t, device.Close())
		assert.True(t, released)
	})

	t.Run("release error propagates", func(t *testing.T) {
		releaseErr := errors.New("release failed")
		device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, func() error {
			return releaseErr
		})
		require.NoError(t, err)
		assert.ErrorIs(t, device.Close(), releaseErr)
	})
}

// The adapter satisfies the vm.VTPMDevice contract end-to-end with the VM
// attestor.
func TestVMAttestorDevice_WorksWithVMAttestor(t *testing.T) {
	device, err := NewVMAttestorDevice(&fakeVMQuoteTPM{}, nil)
	require.NoError(t, err)

	attestor := vm.NewVMAttestor(vm.WithVTPMDevice(device))
	t.Cleanup(func() { _ = attestor.Close() })

	require.NoError(t, attestor.Initialize(context.Background(), &vm.AttestorConfig{
		VTPMDevicePath:       "/tmp/fake-swtpm.sock",
		DefaultHashAlgorithm: vm.HashAlgorithmSHA256,
	}))

	quote, err := attestor.GenerateQuote(context.Background(), &vm.QuoteRequest{
		Nonce:         []byte("nonce"),
		PCRIndices:    []int{0, 7},
		HashAlgorithm: vm.HashAlgorithmSHA256,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("quoted-data"), quote.QuoteData)
	assert.Equal(t, []byte("signature-data"), quote.Signature)
	assert.Len(t, quote.PCRs, 2) // PCRs 0 and 7 (workload PCR not enabled)
}
