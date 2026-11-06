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
	"errors"
	"strings"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestDispatchSeal_JSON exercises the JSON rendering branch.
func TestDispatchSeal_JSON(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchSeal(d); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"sealed\"") {
		t.Errorf("expected JSON sealed key in %q", out.String())
	}
}

// TestDispatchUnseal_JSON exercises the JSON rendering branch.
func TestDispatchUnseal_JSON(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchUnseal(d, "x"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"ok\"") {
		t.Errorf("expected JSON ok=true in %q", out.String())
	}
}

// TestDispatchUnsealShares_JSON exercises the JSON rendering branch.
func TestDispatchUnsealShares_JSON(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchUnsealShares(d, []string{"a", "b"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"shares_submitted\"") {
		t.Errorf("expected JSON shares_submitted, got %q", out.String())
	}
}

// TestDispatchRekey_JSON exercises the JSON rendering branch.
func TestDispatchRekey_JSON(t *testing.T) {
	fake := &fakeBarrierClient{rekeyResp: &quicbaassdk.QRDBBarrierRekeyResponse{ShareCount: 1, Threshold: 1, TotalShares: 1}}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchRekey(d, &rekeyFlags{}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"share_count\"") {
		t.Errorf("expected JSON share_count, got %q", out.String())
	}
}

// TestDispatchRekey_NilResponseHandled covers the nil-resp guard.
func TestDispatchRekey_NilResponseHandled(t *testing.T) {
	fake := &fakeBarrierClient{rekeyResp: nil}
	d, _ := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRekey(d, &rekeyFlags{}); err != nil {
		t.Errorf("nil rekey response must not propagate, got %v", err)
	}
}

// TestDispatchRecoveryGenerate_JSON exercises the JSON branch.
func TestDispatchRecoveryGenerate_JSON(t *testing.T) {
	fake := &fakeBarrierClient{recoveryGenResp: &quicbaassdk.QRDBBarrierRecoveryKeysResponse{ShareCount: 1, Threshold: 2, Total: 3}}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchRecoveryGenerate(d, &recoveryGenerateFlags{threshold: 2, total: 3}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"share_count\"") {
		t.Errorf("expected JSON share_count, got %q", out.String())
	}
}

// TestDispatchRecoveryGenerate_NilResponseHandled covers the nil-resp guard.
func TestDispatchRecoveryGenerate_NilResponseHandled(t *testing.T) {
	fake := &fakeBarrierClient{recoveryGenResp: nil}
	d, _ := newTestDispatcher(cli.OutputFormatTable, fake)
	if err := dispatchRecoveryGenerate(d, &recoveryGenerateFlags{threshold: 2, total: 3}); err != nil {
		t.Errorf("nil response must not propagate, got %v", err)
	}
}

// TestDispatchRecoveryRecover_JSON exercises the JSON branch.
func TestDispatchRecoveryRecover_JSON(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, out := newTestDispatcher(cli.OutputFormatJSON, fake)
	if err := dispatchRecoveryRecover(d, []string{"a", "b"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out.String(), "\"shares_submitted\"") {
		t.Errorf("expected JSON shares_submitted, got %q", out.String())
	}
}

// TestDispatchInit_InvalidOutputFormat covers the default branch in
// renderInitOKDispatch.
func TestDispatchInit_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchInit(d, &initFlags{strategy: "none"})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchInitShamir_InvalidOutputFormat covers the default branch.
func TestDispatchInitShamir_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{initShamirResp: &quicbaassdk.QRDBBarrierInitializeShamirResponse{}}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchInitShamir(d, &initShamirFlags{secret: "p", threshold: 2, total: 3})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchUnsealShares_InvalidOutputFormat covers the default branch.
func TestDispatchUnsealShares_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchUnsealShares(d, []string{"a"})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchSeal_InvalidOutputFormat covers the default branch.
func TestDispatchSeal_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchSeal(d)
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchRekey_InvalidOutputFormat covers the default branch.
func TestDispatchRekey_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{rekeyResp: &quicbaassdk.QRDBBarrierRekeyResponse{}}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchRekey(d, &rekeyFlags{})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchRecoveryGenerate_InvalidOutputFormat covers the default branch.
func TestDispatchRecoveryGenerate_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{recoveryGenResp: &quicbaassdk.QRDBBarrierRecoveryKeysResponse{}}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchRecoveryGenerate(d, &recoveryGenerateFlags{threshold: 2, total: 2})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

// TestDispatchRecoveryRecover_InvalidOutputFormat covers the default branch.
func TestDispatchRecoveryRecover_InvalidOutputFormat(t *testing.T) {
	fake := &fakeBarrierClient{}
	d, _ := newTestDispatcher(cli.OutputFormat("xml"), fake)
	err := dispatchRecoveryRecover(d, []string{"a"})
	var typed cli.ErrInvalidOutputFormat
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}
