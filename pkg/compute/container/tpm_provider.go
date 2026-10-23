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
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// HostTPMDevicePath is the host TPM character device exposed inside
// containers when TPM passthrough is enabled.
const HostTPMDevicePath = "/dev/tpm0"

// QuoteTPM is the platform's host TPM: the SDK HostTPM seam plus the IAK
// accessors the Tier-3 quote verifier needs. The platform's host TPM (App.TPM)
// satisfies it, as does any per-container /dev/tpm0 passthrough TPM opened
// through the xkms SDK.
type QuoteTPM interface {
	orchestration.HostTPM

	// IAKAttributes names the IAK's signature scheme, the one every quote
	// it signs is checked under.
	vm.IAKSource

	// IAK returns the Initial Attestation Key public key.
	IAK() (crypto.PublicKey, error)
}

// QuoteVerifier is the platform's Tier-3 extension of the SDK HostTPM seam.
//
// The SDK produces quotes and compares golden PCR sets; it has no opinion on
// who signed a quote because a standalone agent verifies its own TPM's output
// implicitly. A fleet verifier does not: it must confirm the quote was signed
// by the IAK of the device it believes it is talking to. That check lives
// here, on top of the SDK, rather than as a fork of it.
type QuoteVerifier interface {
	// IAK returns the Initial Attestation Key public key.
	IAK() (crypto.PublicKey, error)

	// VerifyQuote verifies an IAK signature over a TPMS_ATTEST structure.
	VerifyQuote(ctx context.Context, quoted, signature []byte) error
}

// Compile-time proof that the go-xkms SDK TPM satisfies QuoteTPM, and hence
// the SDK HostTPM seam, with no adapter in between.
var (
	_ QuoteTPM              = (xkmssdk.TrustedPlatformModule)(nil)
	_ orchestration.HostTPM = (xkmssdk.TrustedPlatformModule)(nil)
)

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

// HostTPMProvider adapts a go-xkms TrustedPlatformModule (the platform's host
// TPM, or a container's /dev/tpm0 passthrough TPM) to the go-quicbaas SDK
// HostTPM seam, and adds the Tier-3 QuoteVerifier extension.
//
// It is an adapter, not an implementation: the three HostTPM primitives are
// forwarded to the TPM after input validation, with failures wrapped in a
// typed error that names the operation. Quote signatures are verified against
// the TPM's IAK public key.
type HostTPMProvider struct {
	tpm QuoteTPM
}

// Compile-time proof that HostTPMProvider fills the SDK seam and the
// platform's extension of it.
var (
	_ orchestration.HostTPM = (*HostTPMProvider)(nil)
	_ QuoteVerifier         = (*HostTPMProvider)(nil)
)

// NewHostTPMProvider creates a HostTPM backed by the provided TPM.
func NewHostTPMProvider(tpm QuoteTPM) (*HostTPMProvider, error) {
	if tpm == nil {
		return nil, ErrHostTPMRequired{}
	}
	return &HostTPMProvider{tpm: tpm}, nil
}

// ExtendPCR hashes data with hashAlg and extends the result into the PCR at
// pcrIndex. An empty hashAlg selects the SDK's default measurement bank.
func (p *HostTPMProvider) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	if pcrIndex < 0 || pcrIndex > orchestration.MaxPCRIndex {
		return ErrInvalidSpec
	}
	if len(data) == 0 {
		return ErrMeasurementLogInvalid
	}
	if hashAlg == "" {
		hashAlg = orchestration.DefaultMeasurementBank
	}

	if err := p.tpm.ExtendPCR(pcrIndex, strings.ToLower(hashAlg), data); err != nil {
		return ErrHostTPMOperationFailed{Op: "extend", Cause: err}
	}
	return nil
}

// ReadPCRs reads the current value of the supplied PCR indices across the
// TPM's active banks.
func (p *HostTPMProvider) ReadPCRs(pcrList []uint) ([]orchestration.PCRBank, error) {
	for _, index := range pcrList {
		if index > orchestration.MaxPCRIndex {
			return nil, ErrInvalidSpec
		}
	}

	banks, err := p.tpm.ReadPCRs(pcrList)
	if err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "read", Cause: err}
	}
	return banks, nil
}

// Quote produces an IAK-signed TPM 2.0 quote over the supplied PCR indices,
// bound to nonce as qualifying data.
func (p *HostTPMProvider) Quote(pcrs []uint, nonce []byte) (orchestration.TPMQuote, error) {
	if len(pcrs) == 0 {
		return orchestration.TPMQuote{}, ErrInvalidSpec
	}
	for _, index := range pcrs {
		if index > orchestration.MaxPCRIndex {
			return orchestration.TPMQuote{}, ErrInvalidSpec
		}
	}

	quote, err := p.tpm.Quote(pcrs, nonce)
	if err != nil {
		return orchestration.TPMQuote{}, ErrHostTPMOperationFailed{Op: "quote", Cause: err}
	}
	return quote, nil
}

// IAK returns the Initial Attestation Key public key.
func (p *HostTPMProvider) IAK() (crypto.PublicKey, error) {
	iak, err := p.tpm.IAK()
	if err != nil {
		return nil, ErrHostTPMOperationFailed{Op: "iak", Cause: err}
	}
	return iak, nil
}

// VerifyQuote verifies an IAK signature over the TPMS_ATTEST structure using
// the TPM's IAK public key, under the signature scheme the IAK declares. An
// IAK that names no scheme fails verification rather than have one guessed
// from its key type.
func (p *HostTPMProvider) VerifyQuote(ctx context.Context, quoted, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}
	if len(quoted) == 0 || len(signature) == 0 {
		return ErrInvalidQuote
	}

	iak, err := p.IAK()
	if err != nil {
		return err
	}

	iakDER, err := x509.MarshalPKIXPublicKey(iak)
	if err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}

	scheme, err := vm.QuoteSignatureAlgorithm(p.tpm)
	if err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}

	if err := vm.VerifyQuoteSignatureWithAlgorithm(iakDER, quoted, signature, scheme); err != nil {
		return ErrHostTPMOperationFailed{Op: "verify", Cause: err}
	}
	return nil
}
