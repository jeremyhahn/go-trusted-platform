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

package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/hostquote"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// HostQuoter is the narrow slice of a TPM the attestation service needs to
// produce a host quote. It is an interface rather than the full
// TrustedPlatformModule so the service depends on five methods, not sixty,
// and so a test can stand in a fake that produces real TPMS_ATTEST
// structures without a TPM. The daemon's TrustedPlatformModule satisfies
// it as-is.
type HostQuoter interface {
	// Quote produces a TPM2_Quote over the selected PCRs with the caller's
	// nonce as qualifying data, signed by the IAK — the Restricted
	// attestation key TCG assigns to attestation.
	Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error)
	// ReadPCRs returns the current values of the selected PCRs, per bank.
	ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error)
	// IAK returns the public half of the attestation key that signs quotes.
	IAK() (crypto.PublicKey, error)
	// IAKAttributes describes that key, including its signature algorithm.
	IAKAttributes() (*xkmssdk.KeyAttributes, error)
}

// Compile-time proof the daemon's TPM handle is a HostQuoter, so the wiring
// in attestation_init.go cannot silently stop satisfying this seam.
var _ HostQuoter = (xkmssdk.TrustedPlatformModule)(nil)

// ServiceOption configures a Service at construction.
type ServiceOption func(*Service)

// WithTPM gives the service the node's TPM so the quote-producing operations
// — CollectHostAttestation and GetQuote — work. Without it they answer
// ErrTPMSessionNotConfigured, which is honest but means the node cannot
// attest (#387).
func WithTPM(tpm HostQuoter) ServiceOption {
	return func(s *Service) { s.tpm = tpm }
}

// hostQuote is the one implementation behind CollectHostAttestation and
// GetQuote. Both are the same act — ask the TPM to quote the caller's nonce
// over a PCR selection and report the values that quote covers — differing
// only in the shape they return, and one implementation is what keeps the
// two from disagreeing. The quote itself is hostquote.Collect, which a
// diskless node's boot-time attestation shares (#690).
func (s *Service) hostQuote(ctx context.Context, config *daemon.QuoteConfig, nonce []byte, op string) (*hostQuote, error) {
	if s.tpm == nil {
		return nil, ErrTPMSessionNotConfigured{Op: op}
	}

	var requested []int
	var hashAlg manifest.HashAlgorithm
	if config != nil {
		requested = config.PCRIndices
		hashAlg = config.HashAlgorithm
	}
	collected, err := hostquote.Collect(ctx, s.tpm, requested, hashAlg, nonce)
	if err != nil {
		var failed hostquote.ErrCollectFailed
		if errors.As(err, &failed) {
			return nil, ErrHostQuoteFailed{Op: op, Reason: failed.Reason, Cause: failed.Cause}
		}
		return nil, ErrHostQuoteFailed{Op: op, Reason: "TPM quote failed", Cause: err}
	}

	akPub, err := s.tpm.IAK()
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "IAK public key unavailable", Cause: err}
	}
	akDER, err := x509.MarshalPKIXPublicKey(akPub)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "IAK public key not encodable", Cause: err}
	}
	attrs, err := s.tpm.IAKAttributes()
	if err != nil || attrs == nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "IAK attributes unavailable", Cause: err}
	}

	return &hostQuote{
		quote:    collected.Quote,
		values:   collected.Values,
		digest:   collected.Digest,
		akPublic: akDER,
		sigAlg:   attrs.SignatureAlgorithm.String(),
		quotedAt: time.Now().UTC(),
	}, nil
}

// hostQuote is the verified-consistent output of hostQuote, shaped by the
// two public entry points.
type hostQuote struct {
	quote    xkmssdk.Quote
	values   []manifest.PCRValue
	digest   []byte
	akPublic []byte
	sigAlg   string
	quotedAt time.Time
}

func (h *hostQuote) attestation(nonce []byte) *manifest.HostAttestation {
	return &manifest.HostAttestation{
		QuoteData:          h.quote.Quoted,
		Signature:          h.quote.Signature,
		SignatureAlgorithm: h.sigAlg,
		PCRs:               h.values,
		PCRDigest:          h.digest,
		Nonce:              nonce,
		Timestamp:          h.quotedAt,
		AKPublicKey:        h.akPublic,
	}
}

func (h *hostQuote) result(nonce []byte) *daemon.QuoteResult {
	return &daemon.QuoteResult{
		QuoteData:          h.quote.Quoted,
		Signature:          h.quote.Signature,
		PCRValues:          h.values,
		Nonce:              nonce,
		EventLog:           h.quote.EventLog,
		SignatureAlgorithm: h.sigAlg,
	}
}
