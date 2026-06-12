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

package bmc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeRESTRestorer implements BMCRestorerServicer for unit tests.
type fakeRESTRestorer struct {
	result  *RestoreResult
	err     error
	tlsProv bmcpkg.TLSProvider
}

func (f *fakeRESTRestorer) RestoreBMC(_ context.Context, _ uint64, _ *bmcpkg.Config) (*RestoreResult, error) {
	return f.result, f.err
}

func (f *fakeRESTRestorer) BMCTLSProvider() bmcpkg.TLSProvider {
	return f.tlsProv
}

// goodRESTRestoreResult returns a minimal non-nil RestoreResult for tests.
func goodRESTRestoreResult() *RestoreResult {
	return &RestoreResult{
		DeviceID: 77,
		Endpoint: "192.168.1.50:443",
		Hostname: "bmc-02.example.com",
		NewCertMeta: FactoryCertMeta{
			Subject:    "CN=bmc-02",
			Issuer:     "CN=bmc-02",
			NotBefore:  time.Now().Add(-time.Minute),
			NotAfter:   time.Now().Add(365 * 24 * time.Hour),
			CapturedAt: time.Now(),
		},
		Steps: []EnrollStep{
			{Name: "restore-cert", OK: true},
			{Name: "pin-delete", OK: true},
		},
	}
}

// newRestoreTestHandler builds a handler with restorer and profile-lookup wired.
func newRestoreTestHandler(restorer BMCRestorerServicer, lookup ProfileLookup) (RestHandler, *mockResponseWriter, error) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		return nil, nil, err
	}
	h.SetRestorer(restorer, lookup)
	return h, rw, nil
}

// =============================================================================
// RestoreBMC handler tests
// =============================================================================

// TestRestoreBMC_NoRestorerReturns500 verifies that a 500 is returned when
// the restorer has not been injected.
func TestRestoreBMC_NoRestorerReturns500(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}
	// SetRestorer NOT called.

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/cert/restore", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router := newTestRouter("POST", "/bmc/{profileID}/cert/restore", h.RestoreBMC)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rw.lastStatus)
	}
}

// TestRestoreBMC_HappyPathReturns200 verifies the full happy path returns 200
// with the restore result in the response body.
func TestRestoreBMC_HappyPathReturns200(t *testing.T) {
	want := goodRESTRestoreResult()
	h, rw, err := newRestoreTestHandler(
		&fakeRESTRestorer{result: want},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "192.168.1.50"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/cert/restore", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/cert/restore", h.RestoreBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.lastStatus)
	}
	resp, ok := rw.lastBody.(*RestoreResponse)
	if !ok {
		t.Fatalf("expected *RestoreResponse, got %T", rw.lastBody)
	}
	if resp.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %d, want %d", resp.DeviceID, want.DeviceID)
	}
	if resp.Endpoint != want.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", resp.Endpoint, want.Endpoint)
	}
	if len(resp.Steps) != len(want.Steps) {
		t.Errorf("Steps len: got %d, want %d", len(resp.Steps), len(want.Steps))
	}
}

// TestRestoreBMC_InvalidProfileIDReturns400 verifies that a non-numeric
// profile ID in the URL produces a 400.
func TestRestoreBMC_InvalidProfileIDReturns400(t *testing.T) {
	h, rw, err := newRestoreTestHandler(
		&fakeRESTRestorer{result: goodRESTRestoreResult()},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/notanumber/cert/restore", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/cert/restore", h.RestoreBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected 400 for non-numeric profileID, got %d", rw.lastStatus)
	}
}

// TestRestoreBMC_ProfileLookupErrorReturns verifies a profile lookup error
// produces a non-200 response.
func TestRestoreBMC_ProfileLookupErrorReturns(t *testing.T) {
	h, rw, err := newRestoreTestHandler(
		&fakeRESTRestorer{result: goodRESTRestoreResult()},
		&fakeProfileLookup{err: bmcpkg.ErrProfileNotFound{ProfileID: 1}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/cert/restore", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/cert/restore", h.RestoreBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus == http.StatusOK {
		t.Error("expected non-200 when profile lookup fails")
	}
}

// TestRestoreBMC_RestorerErrorReturns verifies a restorer error produces a
// non-200 response.
func TestRestoreBMC_RestorerErrorReturns(t *testing.T) {
	h, rw, err := newRestoreTestHandler(
		&fakeRESTRestorer{err: errors.New("restore ceremony failed")},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/cert/restore", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/cert/restore", h.RestoreBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus == http.StatusOK {
		t.Error("expected non-200 when restorer returns error")
	}
}

// =============================================================================
// restoreResultToJSON tests
// =============================================================================

// TestRestoreResultToJSON_NilInput verifies that a nil input produces a
// non-nil empty response (defensive guard).
func TestRestoreResultToJSON_NilInput(t *testing.T) {
	resp := restoreResultToJSON(nil)
	if resp == nil {
		t.Fatal("expected non-nil response for nil input")
	}
}

// TestRestoreResultToJSON_PEMPopulated verifies that NewCertPEM bytes are
// serialized to the response string field.
func TestRestoreResultToJSON_PEMPopulated(t *testing.T) {
	src := goodRESTRestoreResult()
	src.NewCertPEM = []byte("CERT PEM DATA")

	resp := restoreResultToJSON(src)
	if resp.NewCertPEM != "CERT PEM DATA" {
		t.Errorf("NewCertPEM: got %q, want %q", resp.NewCertPEM, "CERT PEM DATA")
	}
}

// TestRestoreResultToJSON_StepsMapping verifies step fields are mapped.
func TestRestoreResultToJSON_StepsMapping(t *testing.T) {
	src := &RestoreResult{
		Steps: []EnrollStep{
			{Name: "restore-cert", OK: true, Detail: "changed"},
			{Name: "pin-delete", OK: false, Detail: "timeout"},
		},
	}
	resp := restoreResultToJSON(src)
	if len(resp.Steps) != 2 {
		t.Fatalf("Steps len = %d, want 2", len(resp.Steps))
	}
	if resp.Steps[0].Name != "restore-cert" || !resp.Steps[0].OK {
		t.Errorf("Steps[0] = %+v", resp.Steps[0])
	}
	if resp.Steps[1].Name != "pin-delete" || resp.Steps[1].OK {
		t.Errorf("Steps[1] = %+v", resp.Steps[1])
	}
}

// TestErrBMCRestorerNotAvailable_Message verifies the error message.
func TestErrBMCRestorerNotAvailable_Message(t *testing.T) {
	e := ErrBMCRestorerNotAvailable{}
	if e.Error() == "" {
		t.Error("empty error message")
	}
}
