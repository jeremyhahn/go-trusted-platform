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

package hostquote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sort"
	"testing"

	"github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// quotingTPM produces REAL TPMS_ATTEST structures signed with a real key,
// so a collected result can be checked by the vm verifier the control plane
// runs — the round trip, not two fakes agreeing.
type quotingTPM struct {
	key        *ecdsa.PrivateKey
	values     map[int][]byte
	bankLabel  string
	echo       []byte
	quoteErr   error
	readErr    error
	readValues map[int][]byte
	quotes     int
	// quotedPCRs, when set, is the selection the TPM signs in place of
	// the one it was asked for.
	quotedPCRs []uint
	// quoted, when set, replaces the TPMS_ATTEST body the TPM signs.
	quoted []byte
}

func newQuotingTPM(t *testing.T) *quotingTPM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	values := map[int][]byte{}
	for idx := 0; idx <= MaxPCRIndex; idx++ {
		v := sha256.Sum256([]byte{byte(idx)})
		values[idx] = v[:]
	}
	return &quotingTPM{key: key, values: values, bankLabel: "SHA256"}
}

func (f *quotingTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	f.quotes++
	if f.quoteErr != nil {
		return xkmssdk.Quote{}, f.quoteErr
	}
	if f.quotedPCRs != nil {
		pcrs = f.quotedPCRs
	}
	idx := make([]int, 0, len(pcrs))
	for _, p := range pcrs {
		idx = append(idx, int(p))
	}
	sort.Ints(idx)
	h := sha256.New()
	for _, i := range idx {
		h.Write(f.values[i])
	}
	quoted := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	})
	if f.quoted != nil {
		quoted = f.quoted
	}
	digest := sha256.Sum256(quoted)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	echo := nonce
	if f.echo != nil {
		echo = f.echo
	}
	return xkmssdk.Quote{Quoted: quoted, Signature: sig, Nonce: echo}, nil
}

func (f *quotingTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	src := f.values
	if f.readValues != nil {
		src = f.readValues
	}
	bank := xkmssdk.PCRBank{Algorithm: f.bankLabel}
	for _, p := range pcrList {
		if v, ok := src[int(p)]; ok {
			bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(p), Value: v})
		}
	}
	return []xkmssdk.PCRBank{bank}, nil
}

func TestCollect_ProducesEvidenceTheVerifierAccepts(t *testing.T) {
	tpm := newQuotingTPM(t)
	nonce := []byte("verifier-nonce")

	result, err := Collect(context.Background(), tpm, nil, "", nonce)
	require.NoError(t, err)

	evidence := result.Evidence(nonce)
	assert.Equal(t, nonce, evidence.Nonce)
	assert.Len(t, evidence.PCRs, len(manifest.DefaultManifestConfig().DefaultPCRIndices),
		"no selection means the manifest default selection")

	akDER, err := x509.MarshalPKIXPublicKey(&tpm.key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, vm.VerifyQuoteSignatureWithAlgorithm(akDER, evidence.Quote, evidence.Signature, x509.ECDSAWithSHA256.String()))
	require.NoError(t, vm.VerifyQuoteNonce(evidence.Quote, nonce))
	require.NoError(t, vm.VerifyQuotePCRDigest(evidence.Quote, evidence.PCRs))
}

func TestCollect_RefusesWhatItsOwnVerifierWouldReject(t *testing.T) {
	cases := map[string]struct {
		mutate func(*quotingTPM)
		reason string
	}{
		"nonce not echoed": {func(f *quotingTPM) { f.echo = []byte("other") }, "echo"},
		"values do not hash to the digest": {func(f *quotingTPM) {
			f.readValues = map[int][]byte{}
			for k, v := range f.values {
				f.readValues[k] = v
			}
			f.readValues[7] = make([]byte, sha256.Size)
		}, "do not hash to the digest"},
		"no bank of the algorithm": {func(f *quotingTPM) { f.bankLabel = "SHA1" }, "PCR bank"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newQuotingTPM(t)
			tc.mutate(tpm)
			_, err := Collect(context.Background(), tpm, []int{0, 7}, manifest.HashAlgorithmSHA256, []byte("n"))
			var failed ErrCollectFailed
			require.ErrorAs(t, err, &failed)
			assert.Contains(t, failed.Reason, tc.reason)
		})
	}
}

func TestCollect_RefusesBadInputBeforeTouchingTheTPM(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := map[string]struct {
		ctx      context.Context
		selected []int
		nonce    []byte
	}{
		"no nonce":         {context.Background(), nil, nil},
		"cancelled":        {cancelled, nil, []byte("n")},
		"out of range pcr": {context.Background(), []int{24}, []byte("n")},
		"duplicate pcr":    {context.Background(), []int{7, 7}, []byte("n")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newQuotingTPM(t)
			_, err := Collect(tc.ctx, tpm, tc.selected, "", tc.nonce)
			require.ErrorAs(t, err, &ErrCollectFailed{})
			assert.Zero(t, tpm.quotes)
		})
	}
}

func TestCollect_SurfacesTPMFailuresUnwrappable(t *testing.T) {
	tpm := newQuotingTPM(t)
	tpm.quoteErr = errors.New("TPM_RC_FAILURE")
	_, err := Collect(context.Background(), tpm, nil, "", []byte("n"))
	assert.ErrorIs(t, err, tpm.quoteErr)

	tpm.quoteErr, tpm.readErr = nil, errors.New("read failed")
	_, err = Collect(context.Background(), tpm, nil, "", []byte("n"))
	assert.ErrorIs(t, err, tpm.readErr)
}

// A TPM that signs a selection other than the one the caller asked for
// must not have its quote passed on: the verifier would appraise PCRs
// the caller never selected.
func TestCollect_RefusesAQuoteOverAnotherSelection(t *testing.T) {
	cases := map[string]struct {
		quoted []uint
		want   []int
	}{
		"fewer PCRs":            {[]uint{0}, []int{0}},
		"same count, other PCR": {[]uint{0, 8}, []int{0, 8}},
		"more PCRs":             {[]uint{0, 7, 14}, []int{0, 7, 14}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newQuotingTPM(t)
			tpm.quotedPCRs = tc.quoted
			_, err := Collect(context.Background(), tpm, []int{7, 0}, manifest.HashAlgorithmSHA256, []byte("n"))
			var mismatch ErrQuotedSelectionMismatch
			require.ErrorAs(t, err, &mismatch)
			assert.Equal(t, tc.want, mismatch.Quoted)
			assert.Equal(t, []int{0, 7}, mismatch.Selected)
		})
	}
}

func TestCollect_RefusesAnUnreadableQuote(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},
		"truncated": {0xff, 0x54, 0x43},
	}
	for name, quoted := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newQuotingTPM(t)
			tpm.quoted = quoted
			_, err := Collect(context.Background(), tpm, []int{0, 7}, manifest.HashAlgorithmSHA256, []byte("n"))
			var failed ErrCollectFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, "quote structure unreadable", failed.Reason)
			assert.ErrorAs(t, err, &vm.ErrQuoteVerificationFailed{})
		})
	}
}

// The error text is what an operator reads in the daemon log and the CLI;
// each must name the register, bank or selection at fault.
func TestErrorMessages(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"collect failed without cause": {
			ErrCollectFailed{Reason: "a caller nonce is required"},
			"hostquote: a caller nonce is required",
		},
		"collect failed with cause": {
			ErrCollectFailed{Reason: "invalid PCR selection", Cause: ErrPCRIndexDuplicate{Index: 7}},
			"hostquote: invalid PCR selection: pcr index 7 selected twice",
		},
		"index out of range": {
			ErrPCRIndexOutOfRange{Index: 24},
			"pcr index 24 out of range 0-23",
		},
		"quoted selection mismatch": {
			ErrQuotedSelectionMismatch{Quoted: []int{0}, Selected: []int{0, 7}},
			"TPM quoted PCRs [0], caller selected [0 7]",
		},
		"bank missing": {
			ErrPCRBankMissing{Algorithm: manifest.HashAlgorithmSHA256},
			"TPM returned no " + string(manifest.HashAlgorithmSHA256) + " bank",
		},
		"value missing": {
			ErrPCRValueMissing{Algorithm: manifest.HashAlgorithmSHA256, Index: 7},
			"bank " + string(manifest.HashAlgorithmSHA256) + " has no value for pcr 7",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.EqualError(t, tc.err, tc.want)
		})
	}
}

func TestIndices(t *testing.T) {
	got, err := Indices([]int{14, 0, 7})
	require.NoError(t, err)
	assert.Equal(t, []int{0, 7, 14}, got, "ascending: the order the TPM hashes them")

	_, err = Indices([]int{-1})
	assert.ErrorAs(t, err, &ErrPCRIndexOutOfRange{})
	_, err = Indices([]int{3, 3})
	assert.ErrorAs(t, err, &ErrPCRIndexDuplicate{})
}

func TestBankValues_MissingRegisterIsAnError(t *testing.T) {
	banks := []xkmssdk.PCRBank{{Algorithm: "SHA256", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte{1}}}}}
	_, err := BankValues(banks, manifest.HashAlgorithmSHA256, []int{0, 7})
	assert.ErrorAs(t, err, &ErrPCRValueMissing{})

	_, err = BankValues(banks, manifest.HashAlgorithmSHA384, []int{0})
	assert.ErrorAs(t, err, &ErrPCRBankMissing{})
}

func TestBankMatches(t *testing.T) {
	cases := []struct {
		label string
		alg   manifest.HashAlgorithm
		want  bool
	}{
		{"SHA256", manifest.HashAlgorithmSHA256, true},
		{"sha256", manifest.HashAlgorithmSHA256, true},
		{"SHA-256", manifest.HashAlgorithmSHA256, true},
		{" sha-256 ", manifest.HashAlgorithmSHA256, true},
		{"SHA1", manifest.HashAlgorithmSHA256, false},
		{"SHA384", manifest.HashAlgorithmSHA256, false},
		{"", manifest.HashAlgorithmSHA256, false},
		{"SHA256", manifest.HashAlgorithm(""), false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, BankMatches(tc.label, tc.alg), "%q vs %q", tc.label, tc.alg)
	}
}
