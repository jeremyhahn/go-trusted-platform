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
	"encoding/json"
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

// fakeRESTEnroller implements BMCEnrollerServicer for unit tests.
type fakeRESTEnroller struct {
	result   *EnrollResult
	err      error
	tlsProv  bmcpkg.TLSProvider
	lastOpts *EnrollOptions
	lastCfg  *bmcpkg.Config
}

func (f *fakeRESTEnroller) EnrollBMC(_ context.Context, _ uint64, cfg *bmcpkg.Config, opts *EnrollOptions) (*EnrollResult, error) {
	f.lastCfg = cfg
	f.lastOpts = opts
	return f.result, f.err
}

func (f *fakeRESTEnroller) BMCTLSProvider() bmcpkg.TLSProvider {
	return f.tlsProv
}

// fakeProfileLookup implements ProfileLookup for unit tests.
type fakeProfileLookup struct {
	cfg *bmcpkg.Config
	err error
}

func (f *fakeProfileLookup) BMCConfig(_ context.Context, _ uint64, _ bmcpkg.TLSProvider) (*bmcpkg.Config, error) {
	return f.cfg, f.err
}

// goodRESTEnrollResult returns a non-nil EnrollResult for happy-path tests.
func goodRESTEnrollResult() *EnrollResult {
	return &EnrollResult{
		DeviceID:      99,
		Endpoint:      "10.0.0.1:443",
		Hostname:      "bmc.example.com",
		PinSPKISHA256: "sha256/xyz",
		FactoryCertMeta: FactoryCertMeta{
			Subject:    "CN=bmc",
			Issuer:     "CN=ca",
			NotBefore:  time.Now().Add(-time.Hour),
			NotAfter:   time.Now().Add(time.Hour * 24 * 365),
			CapturedAt: time.Now(),
		},
		Steps: []EnrollStep{
			{Name: "trust", OK: true},
			{Name: "factory_cert", OK: true},
		},
	}
}

// newEnrollTestHandler builds a handler with enroller and profile-lookup
// wired so EnrollBMC tests can drive the full path.
func newEnrollTestHandler(enroller BMCEnrollerServicer, lookup ProfileLookup) (RestHandler, *mockResponseWriter, error) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		return nil, nil, err
	}
	h.SetEnroller(enroller, lookup)
	return h, rw, nil
}

// =============================================================================
// Tests
// =============================================================================

func TestEnrollBMC_NoEnrollerReturns503(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}
	// SetEnroller not called — enrollDeps.enroller is nil.

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/enroll", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rw.lastStatus)
	}
	if _, ok := rw.lastErr.(ErrBMCEnrollerNotAvailable); !ok {
		t.Errorf("err = %T, want ErrBMCEnrollerNotAvailable", rw.lastErr)
	}
}

func TestEnrollBMC_InvalidProfileIDReturns400(t *testing.T) {
	h, rw, err := newEnrollTestHandler(
		&fakeRESTEnroller{result: goodRESTEnrollResult()},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	// "abc" is not a numeric profile ID
	req := httptest.NewRequest(http.MethodPost, "/bmc/abc/enroll", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	// Use a router that does NOT constrain the path variable to numbers.
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected 400 for non-numeric profileID, got %d", rw.lastStatus)
	}
}

func TestEnrollBMC_InvalidJSONBodyReturns400(t *testing.T) {
	h, rw, err := newEnrollTestHandler(
		&fakeRESTEnroller{result: goodRESTEnrollResult()},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/enroll", bytes.NewReader([]byte("{invalid")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rw.lastStatus)
	}
}

func TestEnrollBMC_ProfileLookupErrorReturns(t *testing.T) {
	h, rw, err := newEnrollTestHandler(
		&fakeRESTEnroller{result: goodRESTEnrollResult()},
		&fakeProfileLookup{err: bmcpkg.ErrProfileNotFound{ProfileID: 1}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/enroll", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus == http.StatusOK {
		t.Error("expected non-200 when profile lookup fails")
	}
}

func TestEnrollBMC_EnrollerErrorReturns(t *testing.T) {
	h, rw, err := newEnrollTestHandler(
		&fakeRESTEnroller{err: errors.New("enrollment failed")},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/1/enroll", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus == http.StatusOK {
		t.Error("expected non-200 when enroller returns error")
	}
}

func TestEnrollBMC_HappyPathReturns200(t *testing.T) {
	want := goodRESTEnrollResult()
	h, rw, err := newEnrollTestHandler(
		&fakeRESTEnroller{result: want},
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/bmc/42/enroll", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.lastStatus)
	}
	resp, ok := rw.lastBody.(*EnrollResponse)
	if !ok {
		t.Fatalf("expected *EnrollResponse, got %T", rw.lastBody)
	}
	if resp.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %d, want %d", resp.DeviceID, want.DeviceID)
	}
	if resp.Endpoint != want.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", resp.Endpoint, want.Endpoint)
	}
}

func TestEnrollBMC_OptionalFlagsForwarded(t *testing.T) {
	want := goodRESTEnrollResult()
	enroller := &fakeRESTEnroller{result: want}
	h, rw, err := newEnrollTestHandler(
		enroller,
		&fakeProfileLookup{cfg: &bmcpkg.Config{Address: "10.0.0.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	tval := true
	body, _ := json.Marshal(EnrollRequest{ReplaceCertificate: &tval, DANEPublish: &tval})
	req := httptest.NewRequest(http.MethodPost, "/bmc/5/enroll", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r := newTestRouter("POST", "/bmc/{profileID}/enroll", h.EnrollBMC)
	r.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.lastStatus)
	}
	if enroller.lastOpts.ReplaceCertificate == nil || !*enroller.lastOpts.ReplaceCertificate {
		t.Error("expected ReplaceCertificate=true to be forwarded")
	}
	if enroller.lastOpts.DANEPublish == nil || !*enroller.lastOpts.DANEPublish {
		t.Error("expected DANEPublish=true to be forwarded")
	}
	if enroller.lastOpts.RotatePassword != nil {
		t.Error("expected RotatePassword to be nil (not set)")
	}
}

// =============================================================================
// enrollResultToJSON tests
// =============================================================================

func TestEnrollResultToJSON_NilInput(t *testing.T) {
	resp := enrollResultToJSON(nil)
	if resp == nil {
		t.Fatal("expected non-nil response for nil input")
	}
}

func TestEnrollResultToJSON_WithPEMFields(t *testing.T) {
	src := goodRESTEnrollResult()
	src.FactoryCertPEM = []byte("CERT PEM")
	src.NewCertPEM = []byte("NEW PEM")
	src.CACertPEM = []byte("CA PEM")

	resp := enrollResultToJSON(src)

	if resp.FactoryCertPEM != "CERT PEM" {
		t.Errorf("FactoryCertPEM: got %q", resp.FactoryCertPEM)
	}
	if resp.NewCertPEM != "NEW PEM" {
		t.Errorf("NewCertPEM: got %q", resp.NewCertPEM)
	}
	if resp.CACertPEM != "CA PEM" {
		t.Errorf("CACertPEM: got %q", resp.CACertPEM)
	}
	if resp.FactoryCertMeta.Subject != src.FactoryCertMeta.Subject {
		t.Errorf("Subject: got %q", resp.FactoryCertMeta.Subject)
	}
	if len(resp.Steps) != len(src.Steps) {
		t.Errorf("Steps: got %d, want %d", len(resp.Steps), len(src.Steps))
	}
}
