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

package container

import (
	"context"
	"crypto"
	"crypto/x509"
	"strconv"
	"strings"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// HostTPMDevicePath is the host TPM character device exposed inside
// containers when TPM passthrough is enabled.
const HostTPMDevicePath = "/dev/tpm0"

// sha256BankName is the PCR bank / hash algorithm name used for all
// container workload measurements.
const sha256BankName = "SHA256"

// QuoteTPM is the subset of the go-xkms TrustedPlatformModule surface the
// host TPM provider requires. The platform's host TPM (App.TPM) satisfies
// it, as does any per-container /dev/tpm0 passthrough TPM opened through
// the xkms SDK.
type QuoteTPM interface {
	// ExtendPCR extends the PCR in the named hash bank with data.
	ExtendPCR(pcrIndex int, hashAlg string, data []byte) error

	// ReadPCRs reads the requested PCR values from all banks.
	ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error)

	// Quote generates a TPM quote over the selected PCRs signed by the IAK.
	Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error)

	// IAK returns the Initial Attestation Key public key.
	IAK() (crypto.PublicKey, error)
}

// Compile-time proof that the go-xkms SDK TPM satisfies QuoteTPM.
var _ QuoteTPM = (xkmssdk.TrustedPlatformModule)(nil)

// ErrHostTPMRequired is returned when a HostTPMProvider is constructed
// without a TPM.
type ErrHostTPMRequired struct{}

func (e ErrHostTPMRequired) Error() string {
	return "container host TPM provider: TPM is required"
}

// ErrHostTPMOperationFailed is returned when a host TPM operation fails.
type ErrHostTPMOperationFailed struct {
	Op    string
	Cause error
}

func (e ErrHostTPMOperationFailed) Error() string {
	return "container host TPM " + e.Op + " failed: " + e.Cause.Error()
}

func (e ErrHostTPMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrPCRValueNotFound is returned when the requested PCR is not present in
// the SHA-256 bank returned by the TPM.
type ErrPCRValueNotFound struct {
	PCRIndex int
}

func (e ErrPCRValueNotFound) Error() string {
	return "container host TPM: SHA-256 value for PCR " +
		strconv.Itoa(e.PCRIndex) + " not found"
}

// HostTPMProvider adapts a go-xkms TrustedPlatformModule (the platform's
// host TPM, or a container's /dev/tpm0 passthrough TPM) to the TPMProvider
// interface required by the ContainerAttestor. All measurements use the
// SHA-256 bank; quote signatures are produced by the TPM's IAK and verified
// against the IAK public key.
type HostTPMProvider struct {
	tpm QuoteTPM
}

// Compile-time proof that HostTPMProvider satisfies TPMProvider.
var _ TPMProvider = (*HostTPMProvider)(nil)

// NewHostTPMProvider creates a TPMProvider backed by the provided TPM.
func NewHostTPMProvider(tpm QuoteTPM) (*HostTPMProvider, error) {
	if tpm == nil {
		return nil, ErrHostTPMRequired{}
	}
	return &HostTPMProvider{tpm: tpm}, nil
}

// ExtendPCR extends the specified PCR in the SHA-256 bank with the given
// hash. The hash must be a SHA-256 digest (32 bytes).
func (p *HostTPMProvider) ExtendPCR(ctx context.Context, pcrIndex int, hash []byte) error {
	if err := ctx.Err(); err != nil {
		return ErrHostTPMOperationFailed{Op: "extend", Cause: err}
	}
	if pcrIndex < 0 || pcrIndex > 23 {
		return ErrInvalidSpec
	}
	if len(hash) != SHA256Size {
		return ErrMeasurementLogInvalid
	}

	if err := p.tpm.ExtendPCR(pcrIndex, strings.ToLower(sha256BankName), hash); err != nil {
		return ErrHostTPMOperationFailed{Op: "extend", Cause: err}
	}
	return nil
}

// ReadPCR reads the current SHA-256 value of the specified PCR.
func (p *HostTPMProvider) ReadPCR(ctx context.Context, pcrIndex int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "read", Cause: err}
	}
	if pcrIndex < 0 || pcrIndex > 23 {
		return nil, ErrInvalidSpec
	}

	banks, err := p.tpm.ReadPCRs([]uint{uint(pcrIndex)})
	if err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "read", Cause: err}
	}

	value, ok := sha256PCRValue(banks, pcrIndex)
	if !ok {
		return nil, ErrPCRValueNotFound{PCRIndex: pcrIndex}
	}
	return value, nil
}

// GenerateQuote generates an IAK-signed TPM quote over the specified PCR
// indices with the provided nonce as qualifying data.
func (p *HostTPMProvider) GenerateQuote(ctx context.Context, pcrIndices []int, nonce []byte) (*Quote, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "quote", Cause: err}
	}
	if len(pcrIndices) == 0 {
		return nil, ErrInvalidSpec
	}

	pcrs := make([]uint, 0, len(pcrIndices))
	for _, idx := range pcrIndices {
		if idx < 0 || idx > 23 {
			return nil, ErrInvalidSpec
		}
		pcrs = append(pcrs, uint(idx))
	}

	tpmQuote, err := p.tpm.Quote(pcrs, nonce)
	if err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "quote", Cause: err}
	}

	pcrValues := make(map[int][]byte, len(pcrIndices))
	if len(tpmQuote.PCRs) > 0 {
		banks, decodeErr := xkmssdk.DecodePCRs(tpmQuote.PCRs)
		if decodeErr != nil {
			return nil, ErrHostTPMOperationFailed{Op: "quote", Cause: decodeErr}
		}
		for _, idx := range pcrIndices {
			if value, ok := sha256PCRValue(banks, idx); ok {
				pcrValues[idx] = value
			}
		}
	}

	return &Quote{
		QuoteData: tpmQuote.Quoted,
		Signature: tpmQuote.Signature,
		PCRs:      pcrValues,
		Nonce:     nonce,
		Timestamp: time.Now(),
	}, nil
}

// VerifyQuote verifies the quote's IAK signature over the TPMS_ATTEST
// structure using the TPM's IAK public key.
func (p *HostTPMProvider) VerifyQuote(ctx context.Context, quote *Quote) error {
	if err := ctx.Err(); err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}
	if quote == nil {
		return ErrInvalidQuote
	}

	iak, err := p.tpm.IAK()
	if err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}

	iakDER, err := x509.MarshalPKIXPublicKey(iak)
	if err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}

	if err := vm.VerifyQuoteSignature(iakDER, quote.QuoteData, quote.Signature); err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}
	return nil
}

// sha256PCRValue extracts the SHA-256 value for the given PCR index from a
// set of PCR banks. The second return value reports whether it was found.
func sha256PCRValue(banks []xkmssdk.PCRBank, pcrIndex int) ([]byte, bool) {
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, sha256BankName) {
			continue
		}
		for _, pcr := range bank.PCRs {
			if int(pcr.ID) == pcrIndex {
				return pcr.Value, true
			}
		}
	}
	return nil, false
}
