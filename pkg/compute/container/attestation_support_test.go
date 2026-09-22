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

package container

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// testImageDigest is a canonical OCI content digest used across the
// attestation tests.
const testImageDigest = "sha256:" +
	"1111111111111111111111111111111111111111111111111111111111111111"

// testImageRef is a pinned image reference matching testImageDigest.
const testImageRef = "docker.io/library/alpine:3.20"

// digestOf renders an arbitrary string as a canonical OCI content digest, so
// tests can produce distinct but well-formed digests without hard-coding hex.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sha256BankName is the PCR bank name go-xkms reports for the SHA-256 bank.
// go-xkms reports bank names upper-case while the SDK names them lower-case,
// so every comparison against it is case-insensitive.
const sha256BankName = "SHA256"

// =============================================================================
// TPMS_ATTEST synthesis
// =============================================================================
//
// The SDK's TPMAttestingRuntime does not trust a bare TPM2_PCR_Read: it
// re-derives TPMS_QUOTE_INFO.pcrDigest from the values it read, in the order
// the signed TPML_PCR_SELECTION names them, and requires the result to equal
// the digest inside the signed body and the body's extraData to equal the
// nonce it generated. A test double that returns a placeholder byte string as
// the quote body therefore cannot attest at all — and, worse, could never have
// caught a binding failure.
//
// The encoding below is not hand-rolled. syntheticQuote populates go-tpm's
// TPMS_ATTEST / TPMS_QUOTE_INFO structures and hands them to tpm2.Marshal, the
// same TPM 2.0 structure marshaller a real quote is produced with, so the
// bytes the SDK parses are the bytes a physical TPM emits.

// pcrSelectionBytes is the size of a TPMS_PCR_SELECTION bitmap covering PCR 0
// through the highest index a TCG PC Client TPM exposes.
const pcrSelectionBytes = (orchestration.MaxPCRIndex + 8) / 8

// pcrBankParams pairs a PCR bank with the two TPM facts a quote over it needs:
// the algorithm identifier that names the bank inside TPML_PCR_SELECTION, and
// the hash its pcrDigest is computed with.
type pcrBankParams struct {
	algID tpm2.TPMAlgID
	hash  crypto.Hash
}

// pcrBankParamsByName maps the upper-case bank names go-xkms reports onto
// their TPM parameters. These are the four banks a PC Client TPM can expose.
var pcrBankParamsByName = map[string]pcrBankParams{
	"SHA1":   {algID: tpm2.TPMAlgSHA1, hash: crypto.SHA1},
	"SHA256": {algID: tpm2.TPMAlgSHA256, hash: crypto.SHA256},
	"SHA384": {algID: tpm2.TPMAlgSHA384, hash: crypto.SHA384},
	"SHA512": {algID: tpm2.TPMAlgSHA512, hash: crypto.SHA512},
}

// UnsupportedPCRBankError indicates a test double was asked to quote a PCR
// bank no TPM 2.0 PC Client platform exposes, so no algorithm identifier or
// digest exists for it.
type UnsupportedPCRBankError struct {
	// Bank is the bank name that could not be resolved.
	Bank string
}

// Error implements the error interface.
func (e UnsupportedPCRBankError) Error() string {
	return "container attestation: unsupported PCR bank: " + strconv.Quote(e.Bank)
}

// PCRIndexOutOfRangeError indicates a PCR index that no TPMS_PCR_SELECTION
// bitmap over the PC Client register range can name.
type PCRIndexOutOfRangeError struct {
	// Index is the offending PCR index.
	Index uint32
}

// Error implements the error interface.
func (e PCRIndexOutOfRangeError) Error() string {
	return "container attestation: PCR index " + strconv.FormatUint(uint64(e.Index), 10) +
		" exceeds the maximum of " + strconv.Itoa(orchestration.MaxPCRIndex)
}

// syntheticQuote is the TPM2_Quote a test double is about to produce: the PCRs
// its signed selection names, the values its pcrDigest commits to, and the
// nonce it carries as qualifying data.
type syntheticQuote struct {
	// bank is the PCR bank the signed selection names. It must be the bank
	// the double's ReadPCRs reports, or the SDK cannot bind the two.
	bank string

	// indices are the selected PCR indices in ascending order, which is the
	// order a TPM's pcrDigest concatenates the registers in.
	indices []uint32

	// values are the selected PCR values in the same order as indices.
	values [][]byte

	// nonce is the qualifying data the runtime asked the TPM to sign.
	nonce []byte

	// pcrDigest, when non-nil, replaces the digest computed over values.
	// Only a negative test sets it: a signed digest that disagrees with the
	// reported PCR values must be refused, and a double that can produce
	// only passing quotes cannot prove that.
	pcrDigest []byte
}

// newSyntheticQuote prepares a quote over the PCRs in reported that requested
// names. Indices reported does not carry are dropped — exactly as a test
// double's ReadPCRs drops them — so the signed selection never names a
// register the read cannot supply.
func newSyntheticQuote(bank string, reported map[int][]byte, requested []uint, nonce []byte) syntheticQuote {
	seen := make(map[uint32]struct{}, len(requested))
	indices := make([]uint32, 0, len(requested))
	for _, index := range requested {
		key := uint32(index)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if _, ok := reported[int(index)]; !ok {
			continue
		}
		seen[key] = struct{}{}
		indices = append(indices, key)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	values := make([][]byte, 0, len(indices))
	for _, index := range indices {
		values = append(values, append([]byte(nil), reported[int(index)]...))
	}

	return syntheticQuote{
		bank:    bank,
		indices: indices,
		values:  values,
		nonce:   append([]byte(nil), nonce...),
	}
}

// quoted marshals the signed body of the quote: a TPMS_ATTEST bearing
// TPM_GENERATED_VALUE and TPM_ST_ATTEST_QUOTE, carrying the nonce as
// extraData, whose TPMS_QUOTE_INFO names the selected PCRs and commits to
// their values in selection order.
func (q syntheticQuote) quoted() ([]byte, error) {
	params, ok := pcrBankParamsByName[strings.ToUpper(q.bank)]
	if !ok {
		return nil, UnsupportedPCRBankError{Bank: q.bank}
	}

	bitmap := make([]byte, pcrSelectionBytes)
	for _, index := range q.indices {
		if index > orchestration.MaxPCRIndex {
			return nil, PCRIndexOutOfRangeError{Index: index}
		}
		bitmap[index/8] |= 1 << (index % 8)
	}

	digest := q.pcrDigest
	if digest == nil {
		hash := params.hash.New()
		for _, value := range q.values {
			// hash.Hash never returns a write error (documented in the
			// hash package), so the result is discarded deliberately.
			_, _ = hash.Write(value)
		}
		digest = hash.Sum(nil)
	}

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("test-attestation-key")},
		ExtraData:       tpm2.TPM2BData{Buffer: q.nonce},
		ClockInfo: tpm2.TPMSClockInfo{
			Clock:        1,
			ResetCount:   1,
			RestartCount: 0,
			Safe:         true,
		},
		FirmwareVersion: 1,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      tpm2.TPMIAlgHash(params.algID),
					PCRSelect: bitmap,
				}},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: digest},
		}),
	}
	return tpm2.Marshal(&attest), nil
}

// staleQuoteNonce is the qualifying data a replayed quote carries: a value the
// runtime never generated for this attestation.
var staleQuoteNonce = []byte("a-nonce-from-an-earlier-attestation")

// divergentPCRDigest is a well-formed SHA-256 pcrDigest over a host state the
// mock TPM does not report. It is the wrong digest for any PCR read the mock
// can produce, which is precisely what the SDK's quote binding must catch.
func divergentPCRDigest() []byte {
	sum := sha256.Sum256([]byte("PCR values this host never had"))
	return sum[:]
}

// extendCall records a single PCR extension performed against the mock TPM.
type extendCall struct {
	pcrIndex int
	bank     string
	data     []byte
}

// mockHostTPM implements the go-quicbaas SDK HostTPM seam plus the platform's
// QuoteVerifier extension. It simulates real PCR extension semantics
// (new = SHA256(old || data)) so a measurement-log replay can be checked
// against it, and it emits a real TPMS_ATTEST so the SDK's binding of the PCR
// read to the signed quote is genuinely exercised.
type mockHostTPM struct {
	mu          sync.RWMutex
	pcrs        map[int][]byte
	extendCalls []extendCall
	quoteCalls  int
	verifyCalls int
	readCalls   int

	extendErr error
	readErr   error
	quoteErr  error
	verifyErr error
	iakErr    error

	// tamperQuoteDigest makes the signed body commit to a pcrDigest that no
	// PCR read from this TPM can reproduce, modelling a tampered read path.
	tamperQuoteDigest bool

	// tamperQuoteNonce makes the signed body carry qualifying data other
	// than the nonce the runtime generated, modelling a replayed quote.
	tamperQuoteNonce bool

	// extendAfterQuote, when set, extends a PCR after the quote is signed
	// and before ReadPCRs runs. That is the TOCTOU window the quote binding
	// exists to close: the read reports a value the quote never covered.
	extendAfterQuote *extendCall
}

// Compile-time proof the mock fills both seams under test.
var (
	_ orchestration.HostTPM = (*mockHostTPM)(nil)
	_ QuoteVerifier         = (*mockHostTPM)(nil)
	_ QuoteTPM              = (*mockHostTPM)(nil)
)

func newMockHostTPM() *mockHostTPM {
	m := &mockHostTPM{
		pcrs:        make(map[int][]byte, orchestration.MaxPCRIndex+1),
		extendCalls: make([]extendCall, 0),
	}
	for i := 0; i <= orchestration.MaxPCRIndex; i++ {
		m.pcrs[i] = make([]byte, SHA256Size)
	}
	return m
}

func (m *mockHostTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.extendErr != nil {
		return m.extendErr
	}

	m.extendCalls = append(m.extendCalls, extendCall{
		pcrIndex: pcrIndex,
		bank:     hashAlg,
		data:     append([]byte(nil), data...),
	})

	m.extendLocked(pcrIndex, data)
	return nil
}

// extendLocked applies the TPM extend rule, new = SHA256(old || data), to one
// register. The caller must hold m.mu.
func (m *mockHostTPM) extendLocked(pcrIndex int, data []byte) {
	h := sha256.New()
	h.Write(m.pcrs[pcrIndex])
	h.Write(data)
	m.pcrs[pcrIndex] = h.Sum(nil)
}

func (m *mockHostTPM) ReadPCRs(pcrList []uint) ([]orchestration.PCRBank, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.readCalls++
	if m.readErr != nil {
		return nil, m.readErr
	}

	pcrs := make([]orchestration.PCR, 0, len(pcrList))
	for _, index := range pcrList {
		value, ok := m.pcrs[int(index)]
		if !ok {
			continue
		}
		pcrs = append(pcrs, orchestration.PCR{
			ID:    int32(index),
			Value: append([]byte(nil), value...),
		})
	}
	// A single active bank keeps the SDK's bank selection unambiguous.
	return []orchestration.PCRBank{{Algorithm: sha256BankName, PCRs: pcrs}}, nil
}

func (m *mockHostTPM) Quote(pcrs []uint, nonce []byte) (orchestration.TPMQuote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.quoteCalls++
	if m.quoteErr != nil {
		return orchestration.TPMQuote{}, m.quoteErr
	}

	quote := newSyntheticQuote(sha256BankName, m.pcrs, pcrs, nonce)
	if m.tamperQuoteNonce {
		quote.nonce = staleQuoteNonce
	}
	if m.tamperQuoteDigest {
		quote.pcrDigest = divergentPCRDigest()
	}

	quoted, err := quote.quoted()
	if err != nil {
		return orchestration.TPMQuote{}, err
	}

	// The quote is signed at this instant; anything that changes a PCR from
	// here on is invisible to it and must not survive the SDK's binding.
	if m.extendAfterQuote != nil {
		m.extendLocked(m.extendAfterQuote.pcrIndex, m.extendAfterQuote.data)
	}

	return orchestration.TPMQuote{
		Quoted:    quoted,
		Signature: []byte("mock-signature"),
		Nonce:     append([]byte(nil), nonce...),
	}, nil
}

func (m *mockHostTPM) IAK() (crypto.PublicKey, error) {
	if m.iakErr != nil {
		return nil, m.iakErr
	}
	return []byte("mock-iak"), nil
}

func (m *mockHostTPM) VerifyQuote(_ context.Context, quoted, signature []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.verifyCalls++
	if m.verifyErr != nil {
		return m.verifyErr
	}
	if len(quoted) == 0 || len(signature) == 0 {
		return ErrInvalidQuote
	}
	return nil
}

func (m *mockHostTPM) getExtendCalls() []extendCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]extendCall, len(m.extendCalls))
	copy(out, m.extendCalls)
	return out
}

func (m *mockHostTPM) pcrValue(index int) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.pcrs[index]...)
}

// resetExtendCalls clears the recorded PCR extensions without disturbing the
// simulated PCR state.
func (m *mockHostTPM) resetExtendCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendCalls = m.extendCalls[:0]
}

// newTestAttestingRuntime builds the real SDK attesting runtime over tpm.
func newTestAttestingRuntime(t *testing.T, tpm orchestration.HostTPM) *orchestration.TPMAttestingRuntime {
	t.Helper()
	rt, err := orchestration.NewTPMAttestingRuntime(&stubContainerRuntime{}, tpm, newSDKLogger(slog.Default()))
	if err != nil {
		t.Fatalf("NewTPMAttestingRuntime: %v", err)
	}
	return rt
}

// stubContainerRuntime is a Tier 0 runtime that does nothing. It exists so
// tests can build the real orchestration.TPMAttestingRuntime — the SDK code
// actually under test — without a docker or podman binary.
type stubContainerRuntime struct {
	digests   map[string]string
	digestErr error
}

var _ orchestration.ContainerRuntime = (*stubContainerRuntime)(nil)

func (r *stubContainerRuntime) Run(context.Context, *orchestration.ContainerSpec) (string, error) {
	return "stub-container", nil
}

func (r *stubContainerRuntime) RunInteractive(context.Context, *orchestration.ContainerSpec) (*orchestration.InteractiveProcess, error) {
	return nil, errors.New("not supported")
}

func (r *stubContainerRuntime) Stop(context.Context, string) error   { return nil }
func (r *stubContainerRuntime) Remove(context.Context, string) error { return nil }

func (r *stubContainerRuntime) Logs(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (r *stubContainerRuntime) IsRunning(context.Context, string) (bool, error) { return true, nil }

// Exec joined ContainerRuntime in go-quicbaas v0.8.0. This Tier 0 stub runs
// nothing, so it reports a zero-status result rather than pretending a
// command executed.
func (r *stubContainerRuntime) Exec(context.Context, string, *orchestration.ExecSpec) (*orchestration.ExecResult, error) {
	return &orchestration.ExecResult{}, nil
}
func (r *stubContainerRuntime) IsAvailable() bool                  { return true }
func (r *stubContainerRuntime) Pull(context.Context, string) error { return nil }

// ResolveImageDigest fills the ImageDigestResolver seam for orchestrator
// tests that must measure a launch without a container runtime installed.
func (r *stubContainerRuntime) ResolveImageDigest(_ context.Context, image string) (string, error) {
	if r.digestErr != nil {
		return "", r.digestErr
	}
	if digest, ok := r.digests[image]; ok {
		return digest, nil
	}
	return "", &orchestration.ImageDigestUnresolvedError{
		Image: image,
		Cause: errors.New("no digest configured for image"),
	}
}

// fixedDigestResolver resolves any image reference to a deterministic
// canonical content digest, so orchestrator tests can measure a launch
// without a container runtime binary.
type fixedDigestResolver struct {
	err error
}

var _ ImageDigestResolver = fixedDigestResolver{}

func (r fixedDigestResolver) ResolveImageDigest(_ context.Context, image string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return digestOf(image), nil
}

// newTestAttestor builds an attestor wired to the real SDK attesting runtime
// over the mock TPM, which is the production composition minus the container
// runtime binary.
func newTestAttestor(t *testing.T, opts ...ContainerAttestorOption) (*ContainerAttestor, *mockHostTPM) {
	t.Helper()

	tpm := newMockHostTPM()
	attesting, err := orchestration.NewTPMAttestingRuntime(
		&stubContainerRuntime{}, tpm, newSDKLogger(slog.Default()))
	if err != nil {
		t.Fatalf("NewTPMAttestingRuntime: %v", err)
	}

	all := append([]ContainerAttestorOption{WithAttestingRuntime(attesting)}, opts...)
	attestor, err := NewContainerAttestor(tpm, all...)
	if err != nil {
		t.Fatalf("NewContainerAttestor: %v", err)
	}
	return attestor, tpm
}
