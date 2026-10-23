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

// Package hostquote produces a TPM quote over a verifier's nonce together
// with the PCR values it covers, checked to be the values the TPM signed.
//
// It is the one implementation of that act. The attestation service answers
// a collector with it, and a diskless node's platformd answers the control
// plane with it at boot (#690); a second copy is how the two would come to
// emit evidence the one verifier reads differently. The package is a leaf
// so both can import it.
package hostquote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// MaxPCRIndex is the highest PCR a TPM 2.0 exposes.
const MaxPCRIndex = 23

// TPM is the slice of a TPM a quote needs. The daemon's
// TrustedPlatformModule satisfies it as-is.
type TPM interface {
	// Quote produces a TPM2_Quote over the selected PCRs with the caller's
	// nonce as qualifying data, signed by the IAK.
	Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error)
	// ReadPCRs returns the current values of the selected PCRs, per bank.
	ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error)
}

var _ TPM = (xkmssdk.TrustedPlatformModule)(nil)

// Result is a quote whose reported values hash to the digest it signed.
type Result struct {
	// Quote is the TPM's quote, signature and echoed nonce.
	Quote xkmssdk.Quote
	// Values are the selected PCRs of the requested bank, ascending.
	Values []manifest.PCRValue
	// Digest is the PCR digest the TPM signed.
	Digest []byte
}

// Evidence shapes the result as the JSON evidence the device quote
// verifier reads, with the nonce the quote was made over.
func (r *Result) Evidence(nonce []byte) vm.QuoteEvidence {
	pcrs := make(map[int][]byte, len(r.Values))
	for _, v := range r.Values {
		pcrs[v.Index] = v.Value
	}
	return vm.QuoteEvidence{
		Quote:     r.Quote.Quoted,
		Signature: r.Quote.Signature,
		Nonce:     nonce,
		PCRs:      pcrs,
	}
}

// Indices resolves a PCR selection: the requested one, or the manifest
// default (TCG PC Client boot chain 0–7 plus the workload PCR) when none is
// given. Indices are validated and returned ascending, which is also the
// order the TPM hashes them into the quote digest.
func Indices(requested []int) ([]int, error) {
	var indices []int
	if len(requested) > 0 {
		indices = append(indices, requested...)
	} else {
		indices = append(indices, manifest.DefaultManifestConfig().DefaultPCRIndices...)
	}
	seen := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx > MaxPCRIndex {
			return nil, ErrPCRIndexOutOfRange{Index: idx}
		}
		if _, dup := seen[idx]; dup {
			return nil, ErrPCRIndexDuplicate{Index: idx}
		}
		seen[idx] = struct{}{}
	}
	sortInts(indices)
	return indices, nil
}

// Collect quotes the caller's nonce over the selected PCRs and reads the
// values of the requested bank.
//
// The nonce is the CALLER's, passed to the TPM unmodified. A quote over a
// nonce the node chose proves nothing about freshness; the verifier
// generated it, and the verifier checks it comes back.
//
// Before returning, the values are checked against the digest the TPM
// signed. A node must never emit evidence its own verifier would reject: a
// mismatch here is a defect in this node (wrong bank, racing PCR extend),
// and it is reported as one rather than handed to the verifier to discover.
func Collect(ctx context.Context, tpm TPM, requested []int, alg manifest.HashAlgorithm, nonce []byte) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrCollectFailed{Reason: "context done", Cause: err}
	}
	if len(nonce) == 0 {
		return nil, ErrCollectFailed{Reason: "a caller nonce is required; a quote over a nonce the node chose proves nothing about freshness"}
	}
	indices, err := Indices(requested)
	if err != nil {
		return nil, ErrCollectFailed{Reason: "invalid PCR selection", Cause: err}
	}
	if alg == "" {
		alg = manifest.HashAlgorithmSHA256
	}

	pcrs := make([]uint, len(indices))
	for i, idx := range indices {
		pcrs[i] = uint(idx)
	}

	q, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		return nil, ErrCollectFailed{Reason: "TPM quote failed", Cause: err}
	}
	if !bytes.Equal(q.Nonce, nonce) {
		return nil, ErrCollectFailed{Reason: "TPM did not echo the caller's nonce"}
	}

	digest, signedIndices, err := vm.QuotePCRDigest(q.Quoted)
	if err != nil {
		return nil, ErrCollectFailed{Reason: "quote structure unreadable", Cause: err}
	}
	if !equalInts(signedIndices, indices) {
		return nil, ErrCollectFailed{Reason: "TPM quoted a PCR selection other than the one the caller selected",
			Cause: ErrQuotedSelectionMismatch{Quoted: signedIndices, Selected: indices}}
	}

	banks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		return nil, ErrCollectFailed{Reason: "PCR read failed", Cause: err}
	}
	values, err := BankValues(banks, alg, indices)
	if err != nil {
		return nil, ErrCollectFailed{Reason: "PCR bank", Cause: err}
	}

	h := sha256.New()
	for _, v := range values {
		h.Write(v.Value)
	}
	if !bytes.Equal(h.Sum(nil), digest) {
		return nil, ErrCollectFailed{Reason: "reported PCR values do not hash to the digest the TPM signed"}
	}

	return &Result{Quote: q, Values: values, Digest: digest}, nil
}

// BankValues picks the requested bank and returns its values for exactly
// the selected indices, ascending. A missing bank or a missing register is
// an error, never a partial answer.
func BankValues(banks []xkmssdk.PCRBank, alg manifest.HashAlgorithm, indices []int) ([]manifest.PCRValue, error) {
	for _, bank := range banks {
		if !BankMatches(bank.Algorithm, alg) {
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
				return nil, ErrPCRValueMissing{Algorithm: alg, Index: idx}
			}
			out = append(out, manifest.PCRValue{Index: idx, Value: v, Algorithm: alg})
		}
		return out, nil
	}
	return nil, ErrPCRBankMissing{Algorithm: alg}
}

// BankMatches compares a TPM bank label with the manifest's hash-algorithm
// name regardless of case and hyphenation. go-xkms labels banks the way the
// TPM spec spells them ("SHA256"); the manifest vocabulary is lowercase
// ("sha256"); operators write "SHA-256". Comparing the raw strings refused
// the SHA-256 bank of every real TPM on the fleet ("TPM returned no sha256
// bank", Infineon SLB9665, 2026-09-05) while the tests' fake quoter, which
// used the lowercase label, passed.
func BankMatches(label string, alg manifest.HashAlgorithm) bool {
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
