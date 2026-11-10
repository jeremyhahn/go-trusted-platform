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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// errFakeBMC is the generic BMC failure the fakes return to drive the
// handlers' 500 path.
type errFakeBMC struct{}

func (errFakeBMC) Error() string { return "fake bmc failure" }

// serveBMC routes one request through a fresh handler built on svc and
// returns the response writer that recorded the outcome.
func serveBMC(t *testing.T, svc *mockBMCService, method, route, path, body string,
	pick func(RestHandler) http.HandlerFunc) *mockResponseWriter {
	t.Helper()
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     svc,
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	var reader io.Reader
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, reader)
	newTestRouter(method, route, pick(h)).ServeHTTP(httptest.NewRecorder(), req)
	return rw
}

// assertErrAs fails unless got matches the type of target.
func assertErrAs[T error](t *testing.T, got error) T {
	t.Helper()
	var target T
	if !errors.As(got, &target) {
		t.Fatalf("expected error of type %T, got %T (%v)", target, got, got)
	}
	return target
}

func TestGetWebCertificate_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.GetWebCertificate }
	route := "/bmc/{profileID}/certificate"

	t.Run("success", func(t *testing.T) {
		var gotID uint64
		svc := &mockBMCService{getWebCertificateFn: func(_ context.Context, id uint64) (*bmcpkg.CertificateInfo, error) {
			gotID = id
			return &bmcpkg.CertificateInfo{Subject: "CN=bmc-42"}, nil
		}}
		rw := serveBMC(t, svc, http.MethodGet, route, "/bmc/42/certificate", "", pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		if gotID != 42 {
			t.Errorf("profile id = %d, want 42", gotID)
		}
		info, ok := rw.lastBody.(*bmcpkg.CertificateInfo)
		if !ok || info.Subject != "CN=bmc-42" {
			t.Errorf("body = %#v, want certificate info for CN=bmc-42", rw.lastBody)
		}
	})

	t.Run("invalid_profile_id", func(t *testing.T) {
		rw := serveBMC(t, &mockBMCService{}, http.MethodGet, route, "/bmc/abc/certificate", "", pick)
		if rw.lastStatus != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rw.lastStatus)
		}
		if e := assertErrAs[ErrInvalidProfileID](t, rw.lastErr); e.ID != "abc" {
			t.Errorf("ID = %q, want abc", e.ID)
		}
	})

	t.Run("profile_not_found", func(t *testing.T) {
		svc := &mockBMCService{getWebCertificateFn: func(_ context.Context, id uint64) (*bmcpkg.CertificateInfo, error) {
			return nil, bmcpkg.ErrProfileNotFound{ProfileID: id}
		}}
		rw := serveBMC(t, svc, http.MethodGet, route, "/bmc/7/certificate", "", pick)
		if rw.lastStatus != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rw.lastStatus)
		}
		if e := assertErrAs[bmcpkg.ErrProfileNotFound](t, rw.lastErr); e.ProfileID != 7 {
			t.Errorf("ProfileID = %d, want 7", e.ProfileID)
		}
	})

	t.Run("service_error", func(t *testing.T) {
		svc := &mockBMCService{getWebCertificateFn: func(context.Context, uint64) (*bmcpkg.CertificateInfo, error) {
			return nil, errFakeBMC{}
		}}
		rw := serveBMC(t, svc, http.MethodGet, route, "/bmc/7/certificate", "", pick)
		if rw.lastStatus != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rw.lastStatus)
		}
		e := assertErrAs[ErrServiceError](t, rw.lastErr)
		if e.Operation != "get web certificate" || !errors.Is(e.Cause, errFakeBMC{}) {
			t.Errorf("service error = %+v, want get web certificate caused by fake failure", e)
		}
	})
}

func TestReplaceWebCertificate_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.ReplaceWebCertificate }
	route := "/bmc/{profileID}/certificate"

	t.Run("success_passes_pem_to_service", func(t *testing.T) {
		var gotID uint64
		var gotCert, gotKey []byte
		svc := &mockBMCService{replaceWebCertFn: func(_ context.Context, id uint64, certPEM, keyPEM []byte) error {
			gotID, gotCert, gotKey = id, certPEM, keyPEM
			return nil
		}}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/9/certificate",
			`{"cert_pem":"CERT","key_pem":"KEY"}`, pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		if gotID != 9 || string(gotCert) != "CERT" || string(gotKey) != "KEY" {
			t.Errorf("service got id=%d cert=%q key=%q", gotID, gotCert, gotKey)
		}
	})

	badRequests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, err error)
	}{
		{"invalid_profile_id", "/bmc/x/certificate", `{}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidProfileID](t, err) }},
		{"invalid_json", "/bmc/9/certificate", `{`, func(t *testing.T, err error) { assertErrAs[ErrInvalidRequestBody](t, err) }},
		{"missing_cert", "/bmc/9/certificate", `{"key_pem":"KEY"}`, func(t *testing.T, err error) { assertErrAs[ErrMissingCertPEM](t, err) }},
		{"missing_key", "/bmc/9/certificate", `{"cert_pem":"CERT"}`, func(t *testing.T, err error) { assertErrAs[ErrMissingKeyPEM](t, err) }},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := &mockBMCService{replaceWebCertFn: func(context.Context, uint64, []byte, []byte) error {
				called = true
				return nil
			}}
			rw := serveBMC(t, svc, http.MethodPut, route, tc.path, tc.body, pick)
			if rw.lastStatus != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rw.lastStatus)
			}
			tc.check(t, rw.lastErr)
			if called {
				t.Error("service called for a rejected request")
			}
		})
	}

	t.Run("service_error", func(t *testing.T) {
		svc := &mockBMCService{replaceWebCertFn: func(context.Context, uint64, []byte, []byte) error {
			return errFakeBMC{}
		}}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/9/certificate",
			`{"cert_pem":"CERT","key_pem":"KEY"}`, pick)
		if rw.lastStatus != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rw.lastStatus)
		}
		if e := assertErrAs[ErrServiceError](t, rw.lastErr); e.Operation != "replace web certificate" {
			t.Errorf("Operation = %q", e.Operation)
		}
	})
}

func TestListUsers_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.ListUsers }
	route := "/bmc/{profileID}/users"

	t.Run("success", func(t *testing.T) {
		want := []bmcpkg.User{{Slot: 2, Username: "admin", Enabled: true, Privilege: bmcpkg.PrivilegeAdministrator, Channel: 1}}
		svc := &mockBMCService{listUsersFn: func(context.Context, uint64) ([]bmcpkg.User, error) { return want, nil }}
		rw := serveBMC(t, svc, http.MethodGet, route, "/bmc/3/users", "", pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		got, ok := rw.lastBody.([]bmcpkg.User)
		if !ok || len(got) != 1 || got[0] != want[0] {
			t.Errorf("body = %#v, want %#v", rw.lastBody, want)
		}
	})

	t.Run("invalid_profile_id", func(t *testing.T) {
		rw := serveBMC(t, &mockBMCService{}, http.MethodGet, route, "/bmc/-1/users", "", pick)
		if rw.lastStatus != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rw.lastStatus)
		}
		assertErrAs[ErrInvalidProfileID](t, rw.lastErr)
	})

	t.Run("profile_not_found", func(t *testing.T) {
		svc := &mockBMCService{listUsersFn: func(_ context.Context, id uint64) ([]bmcpkg.User, error) {
			return nil, bmcpkg.ErrProfileNotFound{ProfileID: id}
		}}
		rw := serveBMC(t, svc, http.MethodGet, route, "/bmc/3/users", "", pick)
		if rw.lastStatus != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rw.lastStatus)
		}
	})
}

func TestCreateUser_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.CreateUser }
	route := "/bmc/{profileID}/users"

	t.Run("success_maps_request_to_user", func(t *testing.T) {
		var gotUser bmcpkg.User
		var gotPassword string
		svc := &mockBMCService{createUserFn: func(_ context.Context, _ uint64, user bmcpkg.User, password string) error {
			gotUser, gotPassword = user, password
			return nil
		}}
		rw := serveBMC(t, svc, http.MethodPost, route, "/bmc/5/users",
			`{"slot":3,"username":"ops","enabled":true,"privilege":"operator","channel":1,"password":"s3cret"}`, pick)
		if rw.lastStatus != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rw.lastStatus)
		}
		want := bmcpkg.User{Slot: 3, Username: "ops", Enabled: true, Privilege: bmcpkg.PrivilegeOperator, Channel: 1}
		if gotUser != want || gotPassword != "s3cret" {
			t.Errorf("service got user=%+v password=%q, want %+v s3cret", gotUser, gotPassword, want)
		}
		if body, ok := rw.lastBody.(bmcpkg.User); !ok || body != want {
			t.Errorf("body = %#v, want %#v", rw.lastBody, want)
		}
	})

	badRequests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, err error)
	}{
		{"invalid_profile_id", "/bmc/z/users", `{}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidProfileID](t, err) }},
		{"invalid_json", "/bmc/5/users", `not json`, func(t *testing.T, err error) { assertErrAs[ErrInvalidRequestBody](t, err) }},
		{"missing_username", "/bmc/5/users", `{"password":"p","privilege":"user"}`, func(t *testing.T, err error) { assertErrAs[ErrMissingUsername](t, err) }},
		{"missing_password", "/bmc/5/users", `{"username":"u","privilege":"user"}`, func(t *testing.T, err error) { assertErrAs[ErrMissingPassword](t, err) }},
		{"missing_privilege", "/bmc/5/users", `{"username":"u","password":"p"}`, func(t *testing.T, err error) { assertErrAs[ErrMissingPrivilege](t, err) }},
		{"invalid_privilege", "/bmc/5/users", `{"username":"u","password":"p","privilege":"root"}`, func(t *testing.T, err error) {
			if e := assertErrAs[ErrInvalidPrivilege](t, err); e.Privilege != "root" {
				t.Errorf("Privilege = %q, want root", e.Privilege)
			}
		}},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := &mockBMCService{createUserFn: func(context.Context, uint64, bmcpkg.User, string) error {
				called = true
				return nil
			}}
			rw := serveBMC(t, svc, http.MethodPost, route, tc.path, tc.body, pick)
			if rw.lastStatus != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rw.lastStatus)
			}
			tc.check(t, rw.lastErr)
			if called {
				t.Error("service called for a rejected request")
			}
		})
	}

	t.Run("service_error", func(t *testing.T) {
		svc := &mockBMCService{createUserFn: func(context.Context, uint64, bmcpkg.User, string) error { return errFakeBMC{} }}
		rw := serveBMC(t, svc, http.MethodPost, route, "/bmc/5/users",
			`{"username":"u","password":"p","privilege":"user"}`, pick)
		if rw.lastStatus != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rw.lastStatus)
		}
		if e := assertErrAs[ErrServiceError](t, rw.lastErr); e.Operation != "create user" {
			t.Errorf("Operation = %q", e.Operation)
		}
	})
}

func TestDeleteUser_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.DeleteUser }
	route := "/bmc/{profileID}/users/{slot}"

	t.Run("success_passes_slot", func(t *testing.T) {
		var gotID uint64
		var gotSlot uint8
		svc := &mockBMCService{deleteUserFn: func(_ context.Context, id uint64, slot uint8) error {
			gotID, gotSlot = id, slot
			return nil
		}}
		rw := serveBMC(t, svc, http.MethodDelete, route, "/bmc/4/users/255", "", pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		if gotID != 4 || gotSlot != 255 {
			t.Errorf("service got id=%d slot=%d, want 4 255", gotID, gotSlot)
		}
	})

	badRequests := []struct {
		name  string
		route string
		path  string
		check func(t *testing.T, err error)
	}{
		{"invalid_profile_id", route, "/bmc/q/users/2", func(t *testing.T, err error) { assertErrAs[ErrInvalidProfileID](t, err) }},
		{"slot_overflows_uint8", route, "/bmc/4/users/256", func(t *testing.T, err error) {
			if e := assertErrAs[ErrInvalidUserSlot](t, err); e.Slot != "256" {
				t.Errorf("Slot = %q, want 256", e.Slot)
			}
		}},
		{"slot_not_numeric", route, "/bmc/4/users/one", func(t *testing.T, err error) { assertErrAs[ErrInvalidUserSlot](t, err) }},
		{"slot_missing_from_route", "/bmc/{profileID}/users", "/bmc/4/users", func(t *testing.T, err error) {
			if e := assertErrAs[ErrInvalidUserSlot](t, err); e.Slot != "" {
				t.Errorf("Slot = %q, want empty", e.Slot)
			}
		}},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := &mockBMCService{deleteUserFn: func(context.Context, uint64, uint8) error {
				called = true
				return nil
			}}
			rw := serveBMC(t, svc, http.MethodDelete, tc.route, tc.path, "", pick)
			if rw.lastStatus != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rw.lastStatus)
			}
			tc.check(t, rw.lastErr)
			if called {
				t.Error("service called for a rejected request")
			}
		})
	}

	t.Run("profile_not_found", func(t *testing.T) {
		svc := &mockBMCService{deleteUserFn: func(_ context.Context, id uint64, _ uint8) error {
			return bmcpkg.ErrProfileNotFound{ProfileID: id}
		}}
		rw := serveBMC(t, svc, http.MethodDelete, route, "/bmc/4/users/2", "", pick)
		if rw.lastStatus != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rw.lastStatus)
		}
	})
}

func TestSetUserPassword_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.SetUserPassword }
	route := "/bmc/{profileID}/users/{slot}/password"

	t.Run("success_passes_password", func(t *testing.T) {
		var gotSlot uint8
		var gotPassword string
		svc := &mockBMCService{setUserPasswordFn: func(_ context.Context, _ uint64, slot uint8, password string) error {
			gotSlot, gotPassword = slot, password
			return nil
		}}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/4/users/3/password", `{"password":"n3w"}`, pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		if gotSlot != 3 || gotPassword != "n3w" {
			t.Errorf("service got slot=%d password=%q, want 3 n3w", gotSlot, gotPassword)
		}
	})

	badRequests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, err error)
	}{
		{"invalid_profile_id", "/bmc/q/users/3/password", `{"password":"p"}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidProfileID](t, err) }},
		{"invalid_slot", "/bmc/4/users/x/password", `{"password":"p"}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidUserSlot](t, err) }},
		{"invalid_json", "/bmc/4/users/3/password", `[`, func(t *testing.T, err error) { assertErrAs[ErrInvalidRequestBody](t, err) }},
		{"missing_password", "/bmc/4/users/3/password", `{}`, func(t *testing.T, err error) { assertErrAs[ErrMissingPassword](t, err) }},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := &mockBMCService{setUserPasswordFn: func(context.Context, uint64, uint8, string) error {
				called = true
				return nil
			}}
			rw := serveBMC(t, svc, http.MethodPut, route, tc.path, tc.body, pick)
			if rw.lastStatus != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rw.lastStatus)
			}
			tc.check(t, rw.lastErr)
			if called {
				t.Error("service called for a rejected request")
			}
		})
	}

	t.Run("service_error", func(t *testing.T) {
		svc := &mockBMCService{setUserPasswordFn: func(context.Context, uint64, uint8, string) error { return errFakeBMC{} }}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/4/users/3/password", `{"password":"p"}`, pick)
		if rw.lastStatus != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rw.lastStatus)
		}
		if e := assertErrAs[ErrServiceError](t, rw.lastErr); e.Operation != "set user password" {
			t.Errorf("Operation = %q", e.Operation)
		}
	})
}

func TestSetUserPrivilege_964(t *testing.T) {
	pick := func(h RestHandler) http.HandlerFunc { return h.SetUserPrivilege }
	route := "/bmc/{profileID}/users/{slot}/privilege"

	t.Run("success_passes_channel_and_privilege", func(t *testing.T) {
		var gotSlot, gotChannel uint8
		var gotPriv bmcpkg.Privilege
		svc := &mockBMCService{setUserPrivilegeFn: func(_ context.Context, _ uint64, slot, channel uint8, priv bmcpkg.Privilege) error {
			gotSlot, gotChannel, gotPriv = slot, channel, priv
			return nil
		}}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/4/users/2/privilege",
			`{"privilege":"callback","channel":8}`, pick)
		if rw.lastStatus != http.StatusOK {
			t.Fatalf("status = %d, want 200", rw.lastStatus)
		}
		if gotSlot != 2 || gotChannel != 8 || gotPriv != bmcpkg.PrivilegeCallback {
			t.Errorf("service got slot=%d channel=%d priv=%v", gotSlot, gotChannel, gotPriv)
		}
	})

	badRequests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, err error)
	}{
		{"invalid_profile_id", "/bmc/q/users/2/privilege", `{"privilege":"user"}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidProfileID](t, err) }},
		{"invalid_slot", "/bmc/4/users/999/privilege", `{"privilege":"user"}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidUserSlot](t, err) }},
		{"invalid_json", "/bmc/4/users/2/privilege", `{"privilege":`, func(t *testing.T, err error) { assertErrAs[ErrInvalidRequestBody](t, err) }},
		{"missing_privilege", "/bmc/4/users/2/privilege", `{"channel":1}`, func(t *testing.T, err error) { assertErrAs[ErrMissingPrivilege](t, err) }},
		{"invalid_privilege", "/bmc/4/users/2/privilege", `{"privilege":"Administrator"}`, func(t *testing.T, err error) { assertErrAs[ErrInvalidPrivilege](t, err) }},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := &mockBMCService{setUserPrivilegeFn: func(context.Context, uint64, uint8, uint8, bmcpkg.Privilege) error {
				called = true
				return nil
			}}
			rw := serveBMC(t, svc, http.MethodPut, route, tc.path, tc.body, pick)
			if rw.lastStatus != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rw.lastStatus)
			}
			tc.check(t, rw.lastErr)
			if called {
				t.Error("service called for a rejected request")
			}
		})
	}

	t.Run("profile_not_found", func(t *testing.T) {
		svc := &mockBMCService{setUserPrivilegeFn: func(_ context.Context, id uint64, _, _ uint8, _ bmcpkg.Privilege) error {
			return bmcpkg.ErrProfileNotFound{ProfileID: id}
		}}
		rw := serveBMC(t, svc, http.MethodPut, route, "/bmc/4/users/2/privilege", `{"privilege":"user"}`, pick)
		if rw.lastStatus != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rw.lastStatus)
		}
	})
}

func TestParsePrivilege_964(t *testing.T) {
	cases := []struct {
		name    string
		want    bmcpkg.Privilege
		wantErr bool
	}{
		{"no-access", bmcpkg.PrivilegeNoAccess, false},
		{"callback", bmcpkg.PrivilegeCallback, false},
		{"user", bmcpkg.PrivilegeUser, false},
		{"operator", bmcpkg.PrivilegeOperator, false},
		{"administrator", bmcpkg.PrivilegeAdministrator, false},
		{"admin", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePrivilege(tc.name)
			if tc.wantErr {
				if e := assertErrAs[ErrInvalidPrivilege](t, err); e.Privilege != tc.name {
					t.Errorf("Privilege = %q, want %q", e.Privilege, tc.name)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("parsePrivilege(%q) = %v, %v; want %v", tc.name, got, err, tc.want)
			}
		})
	}
}

func TestErrorMessages_964(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrInvalidUserSlot{Slot: "300"}, "bmc: invalid user slot: 300"},
		{ErrInvalidUserSlot{}, "bmc: invalid user slot"},
		{ErrMissingCertPEM{}, "bmc: cert_pem is required"},
		{ErrMissingKeyPEM{}, "bmc: key_pem is required"},
		{ErrMissingUsername{}, "bmc: username is required"},
		{ErrMissingPassword{}, "bmc: password is required"},
		{ErrMissingPrivilege{}, "bmc: privilege is required"},
		{ErrInvalidPrivilege{Privilege: "root"}, "bmc: invalid privilege: root"},
		{ErrBMCEnrollerNotAvailable{}, "bmc: enroller not available (daemon started without App)"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%T.Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestFactoryCertMetaZero_964(t *testing.T) {
	meta := FactoryCertMetaZero()
	if !meta.NotBefore.IsZero() || !meta.NotAfter.IsZero() || !meta.CapturedAt.IsZero() {
		t.Errorf("FactoryCertMetaZero times = %v %v %v, want all zero", meta.NotBefore, meta.NotAfter, meta.CapturedAt)
	}
	if meta != (FactoryCertMeta{}) {
		t.Errorf("FactoryCertMetaZero = %+v, want the zero value", meta)
	}
}
