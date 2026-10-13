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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sort"
	"testing"

	"github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// fakeQuoter stands in for the TPM. It produces REAL TPMS_ATTEST structures
// and real ECDSA signatures over them, so what the service emits can be
// checked by the same vm verifier the control plane uses — the test proves
// the round trip, not that two fakes agree with each other.
type fakeQuoter struct {
	key    crypto.Signer           // the IAK
	opts   crypto.SignerOpts       // the IAK's signing scheme
	sigAlg x509.SignatureAlgorithm // what IAKAttributes declares
	values map[int][]byte          // the "TPM's" PCR values, sha256 bank

	// knobs
	echoNonce    []byte // when non-nil, returned instead of the caller's nonce
	quoteErr     error
	readErr      error
	bankLabel    string         // defaults to "sha256"
	reportValues map[int][]byte // when non-nil, ReadPCRs reports these instead
	quoteIndices []uint         // when non-nil, the quote covers these instead
	quotes       int
}

func newFakeQuoter(t *testing.T) *fakeQuoter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	values := map[int][]byte{}
	for _, idx := range []int{0, 1, 2, 3, 4, 5, 6, 7, 14} {
		v := sha256.Sum256([]byte{byte(idx)})
		values[idx] = v[:]
	}
	// "SHA256" is the label go-xkms actually puts on the bank (the TPM spec
	// spelling); the manifest vocabulary is lowercase. The default fake uses
	// the real label so the suite exercises the same shape the fleet does.
	return &fakeQuoter{key: key, opts: crypto.SHA256, sigAlg: x509.ECDSAWithSHA256, values: values, bankLabel: "SHA256"}
}

// newRSAPSSFakeQuoter is a fakeQuoter whose IAK is an RSA key that signs its
// quotes RSASSA-PSS, as an IAK with an RSA-PSS signature algorithm does.
func newRSAPSSFakeQuoter(t *testing.T) *fakeQuoter {
	t.Helper()
	q := newFakeQuoter(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	q.key = key
	q.opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	q.sigAlg = x509.SHA256WithRSAPSS
	return q
}

func (f *fakeQuoter) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	f.quotes++
	if f.quoteErr != nil {
		return xkmssdk.Quote{}, f.quoteErr
	}
	sel := pcrs
	if f.quoteIndices != nil {
		sel = f.quoteIndices
	}
	idx := make([]int, 0, len(sel))
	for _, p := range sel {
		idx = append(idx, int(p))
	}
	sort.Ints(idx)
	h := sha256.New()
	for _, i := range idx {
		h.Write(f.values[i])
	}
	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("fake-iak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(sel...),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	}
	quoted := tpm2.Marshal(attest)
	digest := f.opts.HashFunc().New()
	digest.Write(quoted)
	sig, err := f.key.Sign(rand.Reader, digest.Sum(nil), f.opts)
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	echo := nonce
	if f.echoNonce != nil {
		echo = f.echoNonce
	}
	return xkmssdk.Quote{Quoted: quoted, Signature: sig, Nonce: echo, EventLog: []byte("evlog")}, nil
}

func (f *fakeQuoter) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	src := f.values
	if f.reportValues != nil {
		src = f.reportValues
	}
	bank := xkmssdk.PCRBank{Algorithm: f.bankLabel}
	for _, p := range pcrList {
		if v, ok := src[int(p)]; ok {
			bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(p), Value: v})
		}
	}
	return []xkmssdk.PCRBank{bank}, nil
}

func (f *fakeQuoter) IAK() (crypto.PublicKey, error) { return f.key.Public(), nil }

func (f *fakeQuoter) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{SignatureAlgorithm: f.sigAlg}, nil
}

// newTestStore is a real file store on a temp dir: the service package has
// no in-memory store, and a fake would only prove the fake agrees with the
// service.
func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.NewFileStore(t.TempDir())
	require.NoError(t, err)
	return s
}

func newQuoteService(t *testing.T, q HostQuoter) *Service {
	t.Helper()
	if q == nil {
		return NewService(newTestStore(t))
	}
	return NewService(newTestStore(t), WithTPM(q))
}

func TestCollectHostAttestation_ProducesEvidenceTheVerifierAccepts(t *testing.T) {
	q := newFakeQuoter(t)
	svc := newQuoteService(t, q)
	nonce := []byte("verifier-chosen-nonce-0123456789")

	att, err := svc.CollectHostAttestation(context.Background(), &daemon.QuoteConfig{PCRIndices: []int{0, 7, 14}}, nonce)
	require.NoError(t, err)

	// The same three checks the control plane's verifier runs.
	require.NoError(t, vm.VerifyQuoteSignatureWithAlgorithm(att.AKPublicKey, att.QuoteData, att.Signature, att.SignatureAlgorithm), "signature over the quote")
	require.NoError(t, vm.VerifyQuoteNonce(att.QuoteData, nonce), "the caller's nonce, embedded")
	reported := map[int][]byte{}
	for _, p := range att.PCRs {
		reported[p.Index] = p.Value
	}
	require.NoError(t, vm.VerifyQuotePCRDigest(att.QuoteData, reported), "reported values hash to the signed digest")

	assert.Equal(t, []int{0, 7, 14}, indicesOf(att.PCRs))
	assert.Equal(t, "ECDSA-SHA256", att.SignatureAlgorithm)
	assert.Equal(t, nonce, att.Nonce)
	assert.NotEmpty(t, att.PCRDigest)
	assert.False(t, att.Timestamp.IsZero())
	assert.Equal(t, manifest.HashAlgorithmSHA256, att.PCRs[0].Algorithm)
	assert.Equal(t, 1, q.quotes, "exactly one TPM quote per collection")
}

func TestGetQuote_IsTheSameQuoteShapedForTheDaemon(t *testing.T) {
	q := newFakeQuoter(t)
	svc := newQuoteService(t, q)
	nonce := []byte("n")
	res, err := svc.GetQuote(context.Background(), nil, nonce)
	require.NoError(t, err)
	require.NoError(t, vm.VerifyQuoteNonce(res.QuoteData, nonce))
	// No selection given: the manifest default (boot chain + workload PCR).
	assert.Equal(t, manifest.DefaultManifestConfig().DefaultPCRIndices, indicesOf(res.PCRValues))
	assert.Equal(t, []byte("evlog"), res.EventLog)
	assert.Equal(t, "ECDSA-SHA256", res.SignatureAlgorithm, "the quote declares the IAK's signing scheme")
}

// boundQuote has the fake TPM quote nonce bound to binding, as a node does
// over a TLS connection, and returns the quote with its AK public key.
func boundQuote(t *testing.T, svc *Service, nonce, binding []byte) (*daemon.QuoteResult, []byte) {
	t.Helper()
	qualifying, err := channelbind.ExpectedQualifyingData(nonce, binding)
	require.NoError(t, err)
	att, err := svc.CollectHostAttestation(context.Background(), &daemon.QuoteConfig{PCRIndices: []int{7}}, qualifying)
	require.NoError(t, err)
	return &daemon.QuoteResult{
		QuoteData:          att.QuoteData,
		Signature:          att.Signature,
		PCRValues:          att.PCRs,
		SignatureAlgorithm: att.SignatureAlgorithm,
	}, att.AKPublicKey
}

func TestVerifyQuote_AcceptsTheBoundEcho(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	nonce := []byte("verifier-chosen-nonce-0123456789")
	binding := []byte("connection-A-exporter-0123456789")
	quote, ak := boundQuote(t, svc, nonce, binding)
	expected, err := channelbind.ExpectedQualifyingData(nonce, binding)
	require.NoError(t, err)

	res, err := svc.VerifyQuote(context.Background(), quote, ak, expected, quote.PCRValues)

	require.NoError(t, err)
	assert.True(t, res.Verified, res.Message)
}

// TestVerifyQuote_RejectsAQuoteBoundToAnotherConnection is #482 on the
// verifier side: a quote a relay obtained over its own connection carries
// that connection's binding, and neither the bare nonce nor the caller's
// own binding matches it.
func TestVerifyQuote_RejectsAQuoteBoundToAnotherConnection(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	nonce := []byte("verifier-chosen-nonce-0123456789")
	quote, ak := boundQuote(t, svc, nonce, []byte("connection-B-exporter-0123456789"))
	callers, err := channelbind.ExpectedQualifyingData(nonce, []byte("connection-A-exporter-0123456789"))
	require.NoError(t, err)

	for name, expected := range map[string][]byte{"the caller's binding": callers, "the bare nonce": nonce} {
		t.Run(name, func(t *testing.T) {
			res, err := svc.VerifyQuote(context.Background(), quote, ak, expected, nil)
			require.NoError(t, err)
			assert.False(t, res.Verified)
			assert.Contains(t, res.Message, "nonce")
		})
	}
}

func TestVerifyQuote_RejectsASignatureTheAKDidNotMake(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	quote, _ := boundQuote(t, svc, []byte("n"), nil)
	_, otherAK := boundQuote(t, newQuoteService(t, newFakeQuoter(t)), []byte("n"), nil)

	res, err := svc.VerifyQuote(context.Background(), quote, otherAK, nil, nil)

	require.NoError(t, err)
	assert.False(t, res.Verified)
	assert.Contains(t, res.Message, "signature")
}

// An RSA IAK whose signature algorithm is RSA-PSS signs its quotes RSASSA-PSS.
// VerifyQuote must accept the quote GetQuote produced, which it cannot do by
// checking every RSA signature as PKCS#1 v1.5.
func TestVerifyQuote_AcceptsAnRSAPSSQuote(t *testing.T) {
	svc := newQuoteService(t, newRSAPSSFakeQuoter(t))
	quote, ak := boundQuote(t, svc, []byte("n"), nil)
	require.Equal(t, "SHA256-RSAPSS", quote.SignatureAlgorithm)

	res, err := svc.VerifyQuote(context.Background(), quote, ak, nil, quote.PCRValues)

	require.NoError(t, err)
	assert.True(t, res.Verified, res.Message)
}

// The declared scheme is the one checked, and a quote that declares none or
// one the verifier has no scheme for is rejected rather than guessed at.
func TestVerifyQuote_RejectsAQuoteUnderAnyOtherScheme(t *testing.T) {
	svc := newQuoteService(t, newRSAPSSFakeQuoter(t))

	tests := []struct {
		algorithm   string
		wantMessage string
	}{
		{"SHA256-RSA", "RSA signature verification failed"},
		{"ECDSA-SHA256", "cannot be verified"},
		{"", "unsupported quote signature algorithm"},
		{"SHA1-RSA", "unsupported quote signature algorithm"},
	}
	for _, tt := range tests {
		t.Run("declared "+tt.algorithm, func(t *testing.T) {
			quote, ak := boundQuote(t, svc, []byte("n"), nil)
			quote.SignatureAlgorithm = tt.algorithm

			res, err := svc.VerifyQuote(context.Background(), quote, ak, nil, nil)

			require.NoError(t, err)
			assert.False(t, res.Verified)
			assert.Contains(t, res.Message, tt.wantMessage)
		})
	}
}

func TestHostQuote_WithoutATPMStaysHonest(t *testing.T) {
	svc := newQuoteService(t, nil)
	_, err := svc.CollectHostAttestation(context.Background(), nil, []byte("n"))
	var notCfg ErrTPMSessionNotConfigured
	require.ErrorAs(t, err, &notCfg)
	assert.Equal(t, "CollectHostAttestation", notCfg.Op)
}

// TestHostQuote_AcceptsEveryStandardSpellingOfTheBank pins the fleet finding
// of 2026-09-05: with the TPM's "SHA256" label and the manifest's "sha256"
// compared as raw strings, every real node answered "TPM returned no sha256
// bank". Case and hyphenation must not decide whether a quote can be made.
func TestHostQuote_AcceptsEveryStandardSpellingOfTheBank(t *testing.T) {
	for _, label := range []string{"SHA256", "sha256", "SHA-256", "Sha-256"} {
		t.Run(label, func(t *testing.T) {
			q := newFakeQuoter(t)
			q.bankLabel = label
			svc := newQuoteService(t, q)
			att, err := svc.CollectHostAttestation(context.Background(), nil, []byte("nonce-bank"))
			require.NoError(t, err, "bank label %q must be recognised as sha256", label)
			require.Len(t, att.PCRs, 9)
		})
	}
}

func TestHostQuote_RefusesABankOfAnotherAlgorithm(t *testing.T) {
	q := newFakeQuoter(t)
	q.bankLabel = "SHA1"
	svc := newQuoteService(t, q)
	_, err := svc.CollectHostAttestation(context.Background(), nil, []byte("nonce-bank"))
	require.Error(t, err, "a SHA-1 bank must not satisfy a sha256 request")
	assert.Contains(t, err.Error(), "no sha256 bank")
}

func TestHostQuote_RefusesWithoutACallerNonce(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	for name, nonce := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GetQuote(context.Background(), nil, nonce)
			var qerr ErrHostQuoteFailed
			require.ErrorAs(t, err, &qerr)
			assert.Contains(t, qerr.Reason, "nonce")
		})
	}
}

// TestHostQuote_RefusesEvidenceItsOwnVerifierWouldReject is the consistency
// guard: if the values the node is about to report do not hash to the
// digest its TPM signed, the node must refuse rather than emit them. The
// fake reports a bank whose PCR 7 differs from what was quoted.
func TestHostQuote_RefusesEvidenceItsOwnVerifierWouldReject(t *testing.T) {
	q := newFakeQuoter(t)
	bad := map[int][]byte{}
	for k, v := range q.values {
		bad[k] = v
	}
	tampered := sha256.Sum256([]byte("not what the TPM signed"))
	bad[7] = tampered[:]
	q.reportValues = bad

	_, err := newQuoteService(t, q).CollectHostAttestation(context.Background(), &daemon.QuoteConfig{PCRIndices: []int{0, 7}}, []byte("n"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.Contains(t, qerr.Reason, "do not hash to the digest")
}

func TestHostQuote_RefusesAQuoteThatDidNotEchoTheNonce(t *testing.T) {
	q := newFakeQuoter(t)
	q.echoNonce = []byte("something-else")
	_, err := newQuoteService(t, q).GetQuote(context.Background(), nil, []byte("mine"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.Contains(t, qerr.Reason, "echo")
}

func TestHostQuote_RefusesAQuoteOverTheWrongSelection(t *testing.T) {
	q := newFakeQuoter(t)
	q.quoteIndices = []uint{0, 1} // TPM quoted something other than what was asked
	_, err := newQuoteService(t, q).GetQuote(context.Background(), &daemon.QuoteConfig{PCRIndices: []int{0, 7}}, []byte("n"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.Contains(t, qerr.Reason, "caller selected")
}

func TestHostQuote_RequiresTheRequestedBank(t *testing.T) {
	q := newFakeQuoter(t)
	q.bankLabel = "sha1"
	_, err := newQuoteService(t, q).GetQuote(context.Background(), nil, []byte("n"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.Contains(t, err.Error(), "no sha256 bank")
}

func TestHostQuote_RejectsBadSelections(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	for name, sel := range map[string][]int{"out of range": {0, 24}, "negative": {-1}, "duplicate": {7, 7}} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GetQuote(context.Background(), &daemon.QuoteConfig{PCRIndices: sel}, []byte("n"))
			var qerr ErrHostQuoteFailed
			require.ErrorAs(t, err, &qerr)
			assert.Equal(t, "invalid PCR selection", qerr.Reason)
		})
	}
}

func TestHostQuote_SurfacesTPMFailuresTyped(t *testing.T) {
	q := newFakeQuoter(t)
	q.quoteErr = errors.New("TPM_RC_FAILURE")
	svc := newQuoteService(t, q)
	_, err := svc.GetQuote(context.Background(), nil, []byte("n"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.ErrorIs(t, err, q.quoteErr, "the TPM error must be unwrappable")

	q.quoteErr, q.readErr = nil, errors.New("read failed")
	_, err = svc.GetQuote(context.Background(), nil, []byte("n"))
	assert.ErrorIs(t, err, q.readErr)
}

func TestHostQuote_HonoursContextCancellation(t *testing.T) {
	q := newFakeQuoter(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newQuoteService(t, q).GetQuote(ctx, nil, []byte("n"))
	var qerr ErrHostQuoteFailed
	require.ErrorAs(t, err, &qerr)
	assert.Equal(t, 0, q.quotes, "a cancelled request must not touch the TPM")
}

func indicesOf(values []manifest.PCRValue) []int {
	out := make([]int, 0, len(values))
	for _, v := range values {
		out = append(out, v.Index)
	}
	return out
}
