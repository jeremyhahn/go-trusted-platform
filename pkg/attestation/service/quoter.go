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
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
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

// maxPCRIndex is the highest PCR a TPM 2.0 exposes.
const maxPCRIndex = 23

// hostQuote is the one implementation behind CollectHostAttestation and
// GetQuote. Both are the same act — ask the TPM to quote the caller's nonce
// over a PCR selection and report the values that quote covers — differing
// only in the shape they return, and one implementation is what keeps the
// two from disagreeing.
//
// The nonce is the CALLER's, passed to the TPM unmodified. A quote over a
// nonce the node chose proves nothing about freshness; the verifier
// generated it, and the verifier checks it comes back.
//
// Before returning, the values are checked against the digest the TPM
// signed. A node must never emit evidence its own verifier would reject:
// a mismatch here is a defect in this node (wrong bank, racing PCR extend),
// and it is reported as one rather than handed to the verifier to discover.
func (s *Service) hostQuote(ctx context.Context, config *daemon.QuoteConfig, nonce []byte, op string) (*hostQuote, error) {
	if s.tpm == nil {
		return nil, ErrTPMSessionNotConfigured{Op: op}
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "context done", Cause: err}
	}
	if len(nonce) == 0 {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "a caller nonce is required; a quote over a nonce the node chose proves nothing about freshness"}
	}

	indices, err := quoteIndices(config)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "invalid PCR selection", Cause: err}
	}
	hashAlg := quoteHashAlgorithm(config)

	pcrs := make([]uint, len(indices))
	for i, idx := range indices {
		pcrs[i] = uint(idx)
	}

	q, err := s.tpm.Quote(pcrs, nonce)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "TPM quote failed", Cause: err}
	}
	if !bytes.Equal(q.Nonce, nonce) {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "TPM did not echo the caller's nonce"}
	}

	digest, signedIndices, err := vm.QuotePCRDigest(q.Quoted)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "quote structure unreadable", Cause: err}
	}
	if !equalInts(signedIndices, indices) {
		return nil, ErrHostQuoteFailed{Op: op, Reason: fmt.Sprintf("TPM quoted PCRs %v, caller selected %v", signedIndices, indices)}
	}

	banks, err := s.tpm.ReadPCRs(pcrs)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "PCR read failed", Cause: err}
	}
	values, err := bankValues(banks, hashAlg, indices)
	if err != nil {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "PCR bank", Cause: err}
	}

	// The values reported must be the ones the TPM signed. Anything else is
	// evidence a verifier will — correctly — reject.
	h := sha256.New()
	for _, v := range values {
		h.Write(v.Value)
	}
	if !bytes.Equal(h.Sum(nil), digest) {
		return nil, ErrHostQuoteFailed{Op: op, Reason: "reported PCR values do not hash to the digest the TPM signed"}
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
		quote:    q,
		values:   values,
		digest:   digest,
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
		QuoteData: h.quote.Quoted,
		Signature: h.quote.Signature,
		PCRValues: h.values,
		Nonce:     nonce,
		EventLog:  h.quote.EventLog,
	}
}

// quoteIndices resolves the PCR selection: the caller's, or the manifest
// default (TCG PC Client boot chain 0–7 plus the workload PCR) when none
// is given. Indices are validated and returned ascending, which is also
// the order the TPM hashes them into the quote digest.
func quoteIndices(config *daemon.QuoteConfig) ([]int, error) {
	var indices []int
	if config != nil && len(config.PCRIndices) > 0 {
		indices = append(indices, config.PCRIndices...)
	} else {
		indices = append(indices, manifest.DefaultManifestConfig().DefaultPCRIndices...)
	}
	seen := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx > maxPCRIndex {
			return nil, fmt.Errorf("pcr index %d out of range 0-%d", idx, maxPCRIndex)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("pcr index %d selected twice", idx)
		}
		seen[idx] = struct{}{}
	}
	sortInts(indices)
	return indices, nil
}

// quoteHashAlgorithm is the PCR bank to report; SHA-256 unless the caller
// names another. The bank label is the same lowercase string the manifest
// package and the TPM layer both use ("sha256").
func quoteHashAlgorithm(config *daemon.QuoteConfig) manifest.HashAlgorithm {
	if config != nil && config.HashAlgorithm != "" {
		return config.HashAlgorithm
	}
	return manifest.HashAlgorithmSHA256
}

// bankValues picks the requested bank and returns its values for exactly the
// selected indices, ascending. A missing bank or a missing register is an
// error, never a partial answer.
func bankValues(banks []xkmssdk.PCRBank, alg manifest.HashAlgorithm, indices []int) ([]manifest.PCRValue, error) {
	for _, bank := range banks {
		if !bankMatches(bank.Algorithm, alg) {
			continue
		}
		byIndex := make(map[int][]byte, len(bank.PCRs))
		for _, p := range bank.PCRs {
			byIndex[int(p.ID)] = p.Value
		}
		out := make([]manifest.PCRValue, 0, len(indices))
		for _, idx := range indices {
			v, ok := byIndex[idx]
			if !ok || len(v) == 0 {
				return nil, fmt.Errorf("bank %s has no value for pcr %d", alg, idx)
			}
			out = append(out, manifest.PCRValue{Index: idx, Value: v, Algorithm: alg})
		}
		return out, nil
	}
	return nil, fmt.Errorf("TPM returned no %s bank", alg)
}

// bankMatches compares a TPM bank label with the manifest's hash-algorithm
// name regardless of case and hyphenation. go-xkms labels banks the way the
// TPM spec spells them ("SHA256"); the manifest vocabulary is lowercase
// ("sha256"); operators write "SHA-256". Comparing the raw strings refused
// the SHA-256 bank of every real TPM on the fleet ("TPM returned no sha256
// bank", Infineon SLB9665, 2026-09-05) while the tests' fake quoter, which
// used the lowercase label, passed.
func bankMatches(label string, alg manifest.HashAlgorithm) bool {
	norm := func(v string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), "-", "")
	}
	return norm(label) != "" && norm(label) == norm(string(alg))
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortInts is an insertion sort: selections are at most 24 entries, and it
// keeps this file free of a sort import for one call.
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
