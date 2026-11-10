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

package barrier

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// fakeBarrierClient is a hand-rolled fake for the QRDBBarrierClient
// surface. Each call records the request and returns a configurable
// response/error. We keep the fake hand-written (not generated) so the
// tests document exactly which fields flow over the wire.
type fakeBarrierClient struct {
	// Recorded requests.
	initReq         *quicbaassdk.QRDBBarrierInitializeRequest
	initShamirReq   *quicbaassdk.QRDBBarrierInitializeShamirRequest
	unsealReq       *quicbaassdk.QRDBBarrierUnsealRequest
	unsealSharesReq *quicbaassdk.QRDBBarrierUnsealSharesRequest
	rekeyReq        *quicbaassdk.QRDBBarrierRekeyRequest
	recoveryGenReq  *quicbaassdk.QRDBBarrierGenerateRecoveryKeysRequest
	recoveryRecReq  *quicbaassdk.QRDBBarrierRecoverWithKeysRequest

	// Counters for parameter-less calls.
	sealCalls   int
	statusCalls int

	// Canned responses.
	statusResp         *quicbaassdk.QRDBBarrierStatusResponse
	initShamirResp     *quicbaassdk.QRDBBarrierInitializeShamirResponse
	rekeyResp          *quicbaassdk.QRDBBarrierRekeyResponse
	recoveryGenResp    *quicbaassdk.QRDBBarrierRecoveryKeysResponse
	hasRecoveryKeyResp *quicbaassdk.QRDBBarrierHasRecoveryKeysResponse
	rootTokenResp      *quicbaassdk.QRDBBarrierRootTokenResponse
	unsealShareResp    *quicbaassdk.QRDBBarrierUnsealShareResponse

	// Canned errors.
	initErr            error
	initShamirErr      error
	unsealErr          error
	unsealSharesErr    error
	statusErr          error
	sealErr            error
	rekeyErr           error
	recoveryGenErr     error
	recoveryRecoverErr error
}

// Compile-time conformance — keeps the fake honest when the SDK adds
// methods.
var _ qrdbBarrierClient = (*fakeBarrierClient)(nil)

// qrdbBarrierClient is a local alias for the subset of the BarrierClient
// surface we exercise. We declare the full surface anyway so the fake
// implements the upstream interface verbatim.
type qrdbBarrierClient = interface {
	BarrierInitialize(ctx context.Context, req *quicbaassdk.QRDBBarrierInitializeRequest) error
	BarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBBarrierUnsealRequest) error
	BarrierSeal(ctx context.Context) error
	BarrierStatus(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error)
	BarrierInitializeShamir(ctx context.Context, req *quicbaassdk.QRDBBarrierInitializeShamirRequest) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error)
	BarrierUnsealWithShare(ctx context.Context, req *quicbaassdk.QRDBBarrierUnsealShareRequest) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error)
	BarrierUnsealWithShares(ctx context.Context, req *quicbaassdk.QRDBBarrierUnsealSharesRequest) error
	BarrierRekey(ctx context.Context, req *quicbaassdk.QRDBBarrierRekeyRequest) (*quicbaassdk.QRDBBarrierRekeyResponse, error)
	BarrierGenerateRecoveryKeys(ctx context.Context, req *quicbaassdk.QRDBBarrierGenerateRecoveryKeysRequest) (*quicbaassdk.QRDBBarrierRecoveryKeysResponse, error)
	BarrierRecoverWithKeys(ctx context.Context, req *quicbaassdk.QRDBBarrierRecoverWithKeysRequest) error
	BarrierDeleteRecoveryKeys(ctx context.Context) error
	BarrierHasRecoveryKeys(ctx context.Context) (*quicbaassdk.QRDBBarrierHasRecoveryKeysResponse, error)
	BarrierGenerateRootToken(ctx context.Context, req *quicbaassdk.QRDBBarrierGenerateRootTokenRequest) (*quicbaassdk.QRDBBarrierRootTokenResponse, error)
	OfficerClaimStatus(ctx context.Context) ([]*quicbaassdk.QRDBOfficerStatus, error)
	OfficerRegister(ctx context.Context, req *quicbaassdk.QRDBOfficerRegisterRequest) (*quicbaassdk.QRDBOfficerRegisterResponse, error)
	OfficerList(ctx context.Context) ([]*quicbaassdk.QRDBOfficerStatus, error)
	ShareClaimBegin(ctx context.Context, req *quicbaassdk.QRDBShareClaimBeginRequest) (*quicbaassdk.QRDBShareClaimBeginResponse, error)
	ShareClaimComplete(ctx context.Context, req *quicbaassdk.QRDBShareClaimCompleteRequest) (*quicbaassdk.QRDBShareClaimCompleteResponse, error)
	ShamirSealVote(ctx context.Context, req *quicbaassdk.QRDBShamirSealVoteRequest) (*quicbaassdk.QRDBShamirSealVoteResponse, error)
	RecoveryOfficerRegister(ctx context.Context, req *quicbaassdk.QRDBOfficerRegisterRequest) (*quicbaassdk.QRDBOfficerRegisterResponse, error)
	RecoveryShareClaimBegin(ctx context.Context, req *quicbaassdk.QRDBShareClaimBeginRequest) (*quicbaassdk.QRDBShareClaimBeginResponse, error)
	RecoveryShareClaimComplete(ctx context.Context, req *quicbaassdk.QRDBShareClaimCompleteRequest) (*quicbaassdk.QRDBShareClaimCompleteResponse, error)
	BarrierEnableEncryption(ctx context.Context, req *quicbaassdk.QRDBBarrierEnableEncryptionRequest) (*quicbaassdk.QRDBBarrierEnableEncryptionResponse, error)
}

func (f *fakeBarrierClient) BarrierInitialize(_ context.Context, req *quicbaassdk.QRDBBarrierInitializeRequest) error {
	f.initReq = cloneInitReq(req)
	return f.initErr
}
func (f *fakeBarrierClient) BarrierUnseal(_ context.Context, req *quicbaassdk.QRDBBarrierUnsealRequest) error {
	f.unsealReq = cloneUnsealReq(req)
	return f.unsealErr
}
func (f *fakeBarrierClient) BarrierSeal(_ context.Context) error {
	f.sealCalls++
	return f.sealErr
}
func (f *fakeBarrierClient) BarrierStatus(_ context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	f.statusCalls++
	return f.statusResp, f.statusErr
}
func (f *fakeBarrierClient) BarrierInitializeShamir(_ context.Context, req *quicbaassdk.QRDBBarrierInitializeShamirRequest) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error) {
	f.initShamirReq = cloneInitShamirReq(req)
	return f.initShamirResp, f.initShamirErr
}
func (f *fakeBarrierClient) BarrierUnsealWithShare(_ context.Context, _ *quicbaassdk.QRDBBarrierUnsealShareRequest) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error) {
	return f.unsealShareResp, nil
}
func (f *fakeBarrierClient) BarrierUnsealWithShares(_ context.Context, req *quicbaassdk.QRDBBarrierUnsealSharesRequest) error {
	f.unsealSharesReq = req
	return f.unsealSharesErr
}
func (f *fakeBarrierClient) BarrierRekey(_ context.Context, req *quicbaassdk.QRDBBarrierRekeyRequest) (*quicbaassdk.QRDBBarrierRekeyResponse, error) {
	f.rekeyReq = req
	return f.rekeyResp, f.rekeyErr
}
func (f *fakeBarrierClient) BarrierGenerateRecoveryKeys(_ context.Context, req *quicbaassdk.QRDBBarrierGenerateRecoveryKeysRequest) (*quicbaassdk.QRDBBarrierRecoveryKeysResponse, error) {
	f.recoveryGenReq = req
	return f.recoveryGenResp, f.recoveryGenErr
}
func (f *fakeBarrierClient) BarrierRecoverWithKeys(_ context.Context, req *quicbaassdk.QRDBBarrierRecoverWithKeysRequest) error {
	f.recoveryRecReq = req
	return f.recoveryRecoverErr
}
func (f *fakeBarrierClient) BarrierDeleteRecoveryKeys(_ context.Context) error { return nil }
func (f *fakeBarrierClient) BarrierHasRecoveryKeys(_ context.Context) (*quicbaassdk.QRDBBarrierHasRecoveryKeysResponse, error) {
	return f.hasRecoveryKeyResp, nil
}
func (f *fakeBarrierClient) BarrierGenerateRootToken(_ context.Context, _ *quicbaassdk.QRDBBarrierGenerateRootTokenRequest) (*quicbaassdk.QRDBBarrierRootTokenResponse, error) {
	return f.rootTokenResp, nil
}
func (f *fakeBarrierClient) OfficerClaimStatus(_ context.Context) ([]*quicbaassdk.QRDBOfficerStatus, error) {
	return nil, nil
}
func (f *fakeBarrierClient) OfficerRegister(_ context.Context, _ *quicbaassdk.QRDBOfficerRegisterRequest) (*quicbaassdk.QRDBOfficerRegisterResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) OfficerList(_ context.Context) ([]*quicbaassdk.QRDBOfficerStatus, error) {
	return nil, nil
}
func (f *fakeBarrierClient) ShareClaimBegin(_ context.Context, _ *quicbaassdk.QRDBShareClaimBeginRequest) (*quicbaassdk.QRDBShareClaimBeginResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) ShareClaimComplete(_ context.Context, _ *quicbaassdk.QRDBShareClaimCompleteRequest) (*quicbaassdk.QRDBShareClaimCompleteResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) ShamirSealVote(_ context.Context, _ *quicbaassdk.QRDBShamirSealVoteRequest) (*quicbaassdk.QRDBShamirSealVoteResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) RecoveryOfficerRegister(_ context.Context, _ *quicbaassdk.QRDBOfficerRegisterRequest) (*quicbaassdk.QRDBOfficerRegisterResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) RecoveryShareClaimBegin(_ context.Context, _ *quicbaassdk.QRDBShareClaimBeginRequest) (*quicbaassdk.QRDBShareClaimBeginResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) RecoveryShareClaimComplete(_ context.Context, _ *quicbaassdk.QRDBShareClaimCompleteRequest) (*quicbaassdk.QRDBShareClaimCompleteResponse, error) {
	return nil, nil
}
func (f *fakeBarrierClient) BarrierEnableEncryption(_ context.Context, _ *quicbaassdk.QRDBBarrierEnableEncryptionRequest) (*quicbaassdk.QRDBBarrierEnableEncryptionResponse, error) {
	return nil, nil
}

// newTestDispatcher builds a dispatcher backed by an in-memory printer
// that the test can introspect.
func newTestDispatcher(format cli.OutputFormat, fake *fakeBarrierClient) (*dispatcher, *bytes.Buffer) {
	out := &bytes.Buffer{}
	p := cli.NewPrinterWithWriter(format, true, out)
	d := &dispatcher{
		Client:  fake,
		Ctx:     context.Background(),
		Output:  format,
		Printer: p,
	}
	return d, out
}

// ---------------------------------------------------------------------------
// dispatchInit
// ---------------------------------------------------------------------------

func TestDispatchInit_Table_Success(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)

	err := dispatchInit(d, &initFlags{strategy: "passphrase", secret: "p", soPin: "so", userPin: "u"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.initReq == nil {
		t.Fatal("expected BarrierInitialize to be called")
	}
	if string(fake.initReq.Secret) != "p" || fake.initReq.SOPin != "so" || fake.initReq.UserPin != "u" {
		t.Errorf("unexpected request payload: %+v", fake.initReq)
	}
	if fake.initReq.BarrierStrategy != "passphrase" {
		t.Errorf("expected strategy=passphrase, got %q", fake.initReq.BarrierStrategy)
	}
	if !strings.Contains(out.String(), "initialized successfully") {
		t.Errorf("unexpected output: %q", out.String())
	}
}

func TestDispatchInit_JSON_Success(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)

	err := dispatchInit(d, &initFlags{strategy: "none"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "\"strategy\"") || !strings.Contains(out.String(), "\"none\"") {
		t.Errorf("expected JSON output with strategy, got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// dispatchInitShamir
// ---------------------------------------------------------------------------

func TestDispatchInitShamir_Table_RendersShareCount(t *testing.T) {
	fake := &fakeBarrierClient{initShamirResp: &quicbaassdk.QRDBBarrierInitializeShamirResponse{
		ShareCount:  3,
		Threshold:   2,
		TotalShares: 3,
	}}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	err := dispatchInitShamir(d, &initShamirFlags{secret: "p", threshold: 2, total: 3, soPin: "so", userPin: "u"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"Threshold", "Total Shares", "Shares Sealed", "share-claim", "Shamir"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected output to contain %q, got %q", want, out.String())
		}
	}
	if string(fake.initShamirReq.Secret) != "p" {
		t.Errorf("unexpected secret %q", fake.initShamirReq.Secret)
	}
	if fake.initShamirReq.Threshold != 2 || fake.initShamirReq.TotalShares != 3 {
		t.Errorf("threshold/total not propagated: %+v", fake.initShamirReq)
	}
}

func TestDispatchInitShamir_NilResponseHandled(t *testing.T) {
	fake := &fakeBarrierClient{initShamirResp: nil}
	d, _ := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchInitShamir(d, &initShamirFlags{secret: "p", threshold: 2, total: 3}); err != nil {
		t.Errorf("nil response must not propagate error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dispatchStatus
// ---------------------------------------------------------------------------

func TestDispatchStatus_Table(t *testing.T) {
	fake := &fakeBarrierClient{statusResp: &quicbaassdk.QRDBBarrierStatusResponse{
		Sealed:         false,
		Strategy:       "passphrase",
		HardwareBacked: true,
		InitializedAt:  "2026-01-01T00:00:00Z",
	}}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchStatus(d); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	for _, want := range []string{"Sealed", "passphrase", "Hardware Backed", "Initialized At"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %q", want, out.String())
		}
	}
}

func TestDispatchStatus_JSON(t *testing.T) {
	fake := &fakeBarrierClient{statusResp: &quicbaassdk.QRDBBarrierStatusResponse{
		Sealed: true, Strategy: "shamir",
	}}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchStatus(d); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"shamir\"") {
		t.Errorf("expected JSON strategy=shamir, got %q", out.String())
	}
}

func TestDispatchStatus_NilResponse(t *testing.T) {
	fake := &fakeBarrierClient{statusResp: nil}
	d, _ := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchStatus(d); err != nil {
		t.Errorf("nil response must render without error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// dispatchUnseal / dispatchUnsealShares
// ---------------------------------------------------------------------------

func TestDispatchUnsealShares_PropagatesShares(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchUnsealShares(d, []string{"a", "b", "c"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.unsealSharesReq == nil || len(fake.unsealSharesReq.Shares) != 3 {
		t.Fatalf("expected 3 shares forwarded, got %+v", fake.unsealSharesReq)
	}
	if !strings.Contains(out.String(), "unsealed successfully") {
		t.Errorf("expected success output, got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// dispatchSeal
// ---------------------------------------------------------------------------

func TestDispatchSeal_Calls(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchSeal(d); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.sealCalls != 1 {
		t.Errorf("expected sealCalls=1, got %d", fake.sealCalls)
	}
	if !strings.Contains(out.String(), "sealed successfully") {
		t.Errorf("expected output, got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// dispatchRekey
// ---------------------------------------------------------------------------

func TestDispatchRekey_NoShamir(t *testing.T) {
	fake := &fakeBarrierClient{rekeyResp: &quicbaassdk.QRDBBarrierRekeyResponse{}}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRekey(d, &rekeyFlags{}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.rekeyReq == nil {
		t.Fatal("expected rekey request recorded")
	}
	if fake.rekeyReq.SOPin != "" || fake.rekeyReq.Threshold != 0 || fake.rekeyReq.Total != 0 {
		t.Errorf("expected zero-value share-free request, got %+v", fake.rekeyReq)
	}
	if !strings.Contains(out.String(), "rekeyed successfully") {
		t.Errorf("expected success output, got %q", out.String())
	}
}

func TestDispatchRekey_WithShamir(t *testing.T) {
	fake := &fakeBarrierClient{rekeyResp: &quicbaassdk.QRDBBarrierRekeyResponse{
		ShareCount: 2, Threshold: 2, TotalShares: 2,
	}}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRekey(d, &rekeyFlags{threshold: 2, total: 2, soPin: "so"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.rekeyReq.SOPin != "so" || fake.rekeyReq.Threshold != 2 || fake.rekeyReq.Total != 2 {
		t.Errorf("expected so-pin/threshold/total propagated, got %+v", fake.rekeyReq)
	}
	for _, w := range []string{"Threshold", "Shares Sealed", "share-claim"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output missing %q: %q", w, out.String())
		}
	}
}

// ---------------------------------------------------------------------------
// dispatchRecoveryGenerate / dispatchRecoveryRecover
// ---------------------------------------------------------------------------

func TestDispatchRecoveryGenerate_Table(t *testing.T) {
	fake := &fakeBarrierClient{recoveryGenResp: &quicbaassdk.QRDBBarrierRecoveryKeysResponse{
		ShareCount: 2,
		Threshold:  2,
		Total:      2,
	}}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRecoveryGenerate(d, &recoveryGenerateFlags{threshold: 2, total: 2, soPin: "so"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.recoveryGenReq.SOPin != "so" {
		t.Errorf("expected so-pin propagated, got %+v", fake.recoveryGenReq)
	}
	for _, w := range []string{"Shares Sealed", "recovery officers", "share-claim"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output missing %q: %q", w, out.String())
		}
	}
}

func TestDispatchRecoveryRecover_Propagates(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRecoveryRecover(d, []string{"x", "y"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if fake.recoveryRecReq == nil || len(fake.recoveryRecReq.Keys) != 2 {
		t.Errorf("expected 2 keys propagated, got %+v", fake.recoveryRecReq)
	}
	if !strings.Contains(out.String(), "recovered successfully") {
		t.Errorf("expected success output, got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// Invalid output format paths
// ---------------------------------------------------------------------------

func TestDispatch_RejectsInvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{statusResp: &quicbaassdk.QRDBBarrierStatusResponse{}}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchStatus(d)
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// The credential on these requests is a BORROW: the dispatcher wipes it once
// the call returns, so a double that kept the slice header would assert
// against zeros. go-qrdb#184 typed the fields []byte for exactly that reason.
func cloneInitReq(req *quicbaassdk.QRDBBarrierInitializeRequest) *quicbaassdk.QRDBBarrierInitializeRequest {
	if req == nil {
		return nil
	}
	out := *req
	out.Secret = bytes.Clone(req.Secret)
	return &out
}

func cloneUnsealReq(req *quicbaassdk.QRDBBarrierUnsealRequest) *quicbaassdk.QRDBBarrierUnsealRequest {
	if req == nil {
		return nil
	}
	out := *req
	out.Secret = bytes.Clone(req.Secret)
	return &out
}

func cloneInitShamirReq(req *quicbaassdk.QRDBBarrierInitializeShamirRequest) *quicbaassdk.QRDBBarrierInitializeShamirRequest {
	if req == nil {
		return nil
	}
	out := *req
	out.Secret = bytes.Clone(req.Secret)
	return &out
}
