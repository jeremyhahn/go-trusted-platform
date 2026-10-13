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
	"crypto/x509"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// VMQuoteTPM is the subset of the go-xkms TrustedPlatformModule surface the
// VM attestor device requires. xkmssdk.TrustedPlatformModule satisfies it.
type VMQuoteTPM interface {
	// Quote generates a TPM quote over the selected PCRs signed by the IAK.
	Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error)

	// ReadPCRs reads the requested PCR values from all banks.
	ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error)

	// IAK returns the Initial Attestation Key public key.
	IAK() (crypto.PublicKey, error)

	// IAKAttributes returns the IAK's key attributes, whose
	// SignatureAlgorithm names the scheme every quote is signed under.
	IAKAttributes() (*xkmssdk.KeyAttributes, error)

	// EKCertificate returns the Endorsement Key certificate.
	EKCertificate() (*x509.Certificate, error)
}

// Compile-time proof that the go-xkms SDK TPM satisfies VMQuoteTPM.
var _ VMQuoteTPM = (xkmssdk.TrustedPlatformModule)(nil)

// VMAttestorDevice adapts a go-xkms TrustedPlatformModule (connected to a
// per-instance swtpm socket) to the pkg/attestation/vm VTPMDevice interface
// so the VM attestor can generate quotes against a running VM's vTPM.
type VMAttestorDevice struct {
	tpm     VMQuoteTPM
	release func() error
}

// Compile-time proof that VMAttestorDevice satisfies vm.VTPMDevice.
var _ vm.VTPMDevice = (*VMAttestorDevice)(nil)

// NewVMAttestorDevice creates a VM attestor device over the provided TPM.
// The optional release func is invoked on Close to return the underlying
// TPM connection to its provider (for example TPMProvider.CloseTPM).
func NewVMAttestorDevice(tpm VMQuoteTPM, release func() error) (*VMAttestorDevice, error) {
	if tpm == nil {
		return nil, ErrVMAttestorDeviceTPMRequired{}
	}
	return &VMAttestorDevice{
		tpm:     tpm,
		release: release,
	}, nil
}

// GenerateQuote generates a TPM quote signed by the vTPM's IAK. Only SHA-256
// is supported: the go-xkms quote path signs with the TPM's configured
// SHA-256 hash, so any other algorithm is rejected with a typed error rather
// than silently producing a quote in the wrong bank.
func (d *VMAttestorDevice) GenerateQuote(
	ctx context.Context,
	nonce []byte,
	pcrIndices []int,
	algorithm vm.HashAlgorithm,
) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, ErrVMQuoteFailed{Cause: err}
	}
	if algorithm != vm.HashAlgorithmSHA256 {
		return nil, nil, ErrUnsupportedQuoteAlgorithm{Algorithm: algorithm.String()}
	}

	pcrs := make([]uint, 0, len(pcrIndices))
	for _, idx := range pcrIndices {
		if idx < 0 || idx > 23 {
			return nil, nil, ErrInvalidPCRIndex{PCRIndex: idx}
		}
		pcrs = append(pcrs, uint(idx))
	}

	quote, err := d.tpm.Quote(pcrs, nonce)
	if err != nil {
		return nil, nil, ErrVMQuoteFailed{Cause: err}
	}

	return quote.Quoted, quote.Signature, nil
}

// ReadPCR reads the current value of the specified PCR from the requested
// hash bank.
func (d *VMAttestorDevice) ReadPCR(ctx context.Context, pcr int, algorithm vm.HashAlgorithm) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrPCRReadFailedVM{PCR: pcr, Cause: err}
	}
	if pcr < 0 || pcr > 23 {
		return nil, ErrInvalidPCRIndex{PCRIndex: pcr}
	}

	banks, err := d.tpm.ReadPCRs([]uint{uint(pcr)})
	if err != nil {
		return nil, ErrPCRReadFailedVM{PCR: pcr, Cause: err}
	}

	want := strings.ToUpper(algorithm.String())
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, want) {
			continue
		}
		for _, value := range bank.PCRs {
			if int(value.ID) == pcr {
				return value.Value, nil
			}
		}
	}

	return nil, ErrPCRBankValueNotFound{PCR: pcr, Algorithm: want}
}

// GetAIKPublicKey returns the DER (PKIX) encoding of the vTPM's IAK public
// key.
func (d *VMAttestorDevice) GetAIKPublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrAIKPublicKeyUnavailable{Cause: err}
	}

	pub, err := d.tpm.IAK()
	if err != nil {
		return nil, ErrAIKPublicKeyUnavailable{Cause: err}
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, ErrAIKPublicKeyUnavailable{Cause: err}
	}

	return der, nil
}

// GetAIKSignatureAlgorithm returns the x509.SignatureAlgorithm name of the
// scheme the vTPM IAK signs quotes under, read from the IAK's attributes.
func (d *VMAttestorDevice) GetAIKSignatureAlgorithm(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", ErrAIKSignatureAlgorithmUnavailable{Cause: err}
	}

	algorithm, err := vm.QuoteSignatureAlgorithm(d.tpm)
	if err != nil {
		return "", ErrAIKSignatureAlgorithmUnavailable{Cause: err}
	}
	return algorithm, nil
}

// GetEKCertificate returns the DER encoding of the vTPM EK certificate.
func (d *VMAttestorDevice) GetEKCertificate(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrEKCertificateUnavailable{Cause: err}
	}

	cert, err := d.tpm.EKCertificate()
	if err != nil {
		return nil, ErrEKCertificateUnavailable{Cause: err}
	}
	if cert == nil {
		return nil, ErrEKCertificateUnavailable{Cause: ErrVMAttestorDeviceNoEKCert{}}
	}

	return cert.Raw, nil
}

// Close releases the device's underlying TPM connection via the release
// callback (when configured). The TPM instance itself is owned by its
// provider; the device never closes it directly.
func (d *VMAttestorDevice) Close() error {
	if d.release != nil {
		return d.release()
	}
	return nil
}
