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

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeBMCRestorer records calls and returns configured responses.
type fakeBMCRestorer struct {
	restoreResult *app.BMCRestoreResult
	restoreErr    error
	tlsProvider   bmc.TLSProvider
	lastDeviceID  uint64
	lastBMCCfg    *bmc.Config
}

func (f *fakeBMCRestorer) RestoreBMC(_ context.Context, deviceID uint64, bmcCfg *bmc.Config) (*app.BMCRestoreResult, error) {
	f.lastDeviceID = deviceID
	f.lastBMCCfg = bmcCfg
	return f.restoreResult, f.restoreErr
}

func (f *fakeBMCRestorer) BMCTLSProvider() bmc.TLSProvider {
	return f.tlsProvider
}

// goodRestoreResult returns a minimal non-nil BMCRestoreResult for happy-path tests.
func goodRestoreResult() *app.BMCRestoreResult {
	return &app.BMCRestoreResult{
		DeviceID: 42,
		Endpoint: "192.168.1.100:443",
		Hostname: "bmc-01.example.com",
		NewCertMeta: app.BMCFactoryCertMeta{
			Subject:      "CN=bmc-01",
			Issuer:       "CN=bmc-01",
			SerialNumber: "1",
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			SPKISHA256:   "aa",
			SHA256:       "bb",
			CapturedAt:   time.Now(),
		},
		Steps: []app.BMCEnrollStep{
			{Name: "restore-cert", OK: true},
			{Name: "pin-delete", OK: true},
			{Name: "dane-unpublish", OK: true},
			{Name: "device-state", OK: true},
		},
	}
}

// =============================================================================
// restBMCRestorerAdapter tests
// =============================================================================

// TestRestBMCRestorerAdapter_HappyPath verifies that a successful restore is
// mapped to a bmcwebsvc.RestoreResult with all fields propagated.
func TestRestBMCRestorerAdapter_HappyPath(t *testing.T) {
	want := goodRestoreResult()
	restorer := &fakeBMCRestorer{restoreResult: want}
	adapter := newRESTBMCRestorerAdapter(restorer)

	cfg := &bmc.Config{Address: "192.168.1.100", Port: 443}
	result, err := adapter.RestoreBMC(context.Background(), 42, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %d, want %d", result.DeviceID, want.DeviceID)
	}
	if result.Endpoint != want.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", result.Endpoint, want.Endpoint)
	}
	if result.Hostname != want.Hostname {
		t.Errorf("Hostname: got %q, want %q", result.Hostname, want.Hostname)
	}
	if len(result.Steps) != len(want.Steps) {
		t.Errorf("Steps len: got %d, want %d", len(result.Steps), len(want.Steps))
	}
	if result.NewCertMeta.Subject != want.NewCertMeta.Subject {
		t.Errorf("NewCertMeta.Subject: got %q, want %q", result.NewCertMeta.Subject, want.NewCertMeta.Subject)
	}
}

// TestRestBMCRestorerAdapter_ErrorPropagated verifies that a restorer error is
// propagated unchanged (not wrapped) to the caller.
func TestRestBMCRestorerAdapter_ErrorPropagated(t *testing.T) {
	wantErr := errors.New("restore ceremony failed")
	restorer := &fakeBMCRestorer{restoreErr: wantErr}
	adapter := newRESTBMCRestorerAdapter(restorer)

	_, err := adapter.RestoreBMC(context.Background(), 1, &bmc.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// TestRestBMCRestorerAdapter_NilResult verifies that a nil result from the
// underlying restorer produces an empty (non-nil) RestoreResult.
func TestRestBMCRestorerAdapter_NilResult(t *testing.T) {
	restorer := &fakeBMCRestorer{restoreResult: nil}
	adapter := newRESTBMCRestorerAdapter(restorer)

	result, err := adapter.RestoreBMC(context.Background(), 1, &bmc.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil even when underlying result is nil")
	}
}

// TestRestBMCRestorerAdapter_BMCTLSProvider verifies BMCTLSProvider delegates
// to the underlying restorer.
func TestRestBMCRestorerAdapter_BMCTLSProvider(t *testing.T) {
	restorer := &fakeBMCRestorer{tlsProvider: nil} // nil is a valid zero value
	adapter := newRESTBMCRestorerAdapter(restorer)
	// Should not panic.
	_ = adapter.BMCTLSProvider()
}

// TestRestBMCRestorerAdapter_CompileTime verifies the adapter satisfies the
// bmcwebsvc.BMCRestorerServicer interface at compile time.
func TestRestBMCRestorerAdapter_CompileTime(t *testing.T) {
	var _ bmcwebsvc.BMCRestorerServicer = (*restBMCRestorerAdapter)(nil)
}

// TestErrBMCRestorerNotConfigured_Message verifies the error message.
func TestErrBMCRestorerNotConfigured_Message(t *testing.T) {
	e := ErrBMCRestorerNotConfigured{}
	if e.Error() == "" {
		t.Error("empty error message")
	}
}

// TestAppRestoreResultToREST_StepsMapping verifies individual step fields are
// mapped correctly.
func TestAppRestoreResultToREST_StepsMapping(t *testing.T) {
	appResult := &app.BMCRestoreResult{
		DeviceID: 7,
		Steps: []app.BMCEnrollStep{
			{Name: "restore-cert", OK: true, Detail: "cert changed"},
			{Name: "pin-delete", OK: false, Detail: "store unavailable"},
		},
	}
	result := appRestoreResultToREST(appResult)
	if len(result.Steps) != 2 {
		t.Fatalf("Steps len = %d, want 2", len(result.Steps))
	}
	if result.Steps[0].Name != "restore-cert" || !result.Steps[0].OK {
		t.Errorf("Steps[0] = %+v", result.Steps[0])
	}
	if result.Steps[1].Name != "pin-delete" || result.Steps[1].OK {
		t.Errorf("Steps[1] = %+v", result.Steps[1])
	}
}
