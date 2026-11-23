package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
)

// TestProvision_ISOURL checks that POST /bmc/{profileID}/provision refuses
// an iso_url the BMC cannot fetch before the asynchronous workflow starts,
// and that an omitted iso_url stays optional (#2039).
func TestProvision_ISOURL(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCalled bool
		wantISOURL string
	}{
		{
			name:       "ftp_scheme_refused",
			body:       `{"iso_url":"ftp://iso.example.com/os.iso"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no_scheme_refused",
			body:       `{"iso_url":"os.iso"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing_host_refused",
			body:       `{"iso_url":"https://"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "opaque_url_refused",
			body:       `{"iso_url":"https:installer.iso"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty_host_with_path_refused",
			body:       `{"iso_url":"http:///x.iso"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "https_accepted",
			body:       `{"iso_url":"https://iso.example.com/os.iso"}`,
			wantStatus: http.StatusCreated,
			wantCalled: true,
			wantISOURL: "https://iso.example.com/os.iso",
		},
		{
			name:       "omitted_iso_url_optional",
			body:       `{}`,
			wantStatus: http.StatusCreated,
			wantCalled: true,
			wantISOURL: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			var got baremetal.ProvisionRequest
			bmSvc := &mockBaremetalService{
				provisionFn: func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
					called = true
					got = req
					return &baremetal.ProvisionResult{ProvisionID: "prov-1"}, nil
				},
			}
			rw := &mockResponseWriter{}
			h, err := NewHandler(HandlerParams{
				Logger:           newTestLogger(),
				BMCService:       &mockBMCService{},
				BaremetalService: bmSvc,
				ResponseWriter:   rw,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			req := httptest.NewRequest("POST", "/bmc/42/provision", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
			router.ServeHTTP(rec, req)

			if rw.lastStatus != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.lastStatus, tc.wantStatus)
			}
			if called != tc.wantCalled {
				t.Fatalf("provision called = %v, want %v", called, tc.wantCalled)
			}
			if tc.wantStatus == http.StatusBadRequest {
				e, ok := rw.lastErr.(ErrInvalidRequestBody)
				if !ok {
					t.Fatalf("err = %T, want ErrInvalidRequestBody", rw.lastErr)
				}
				if !strings.Contains(e.Reason, "iso_url") {
					t.Errorf("reason = %q, want it to name iso_url", e.Reason)
				}
				return
			}
			if got.ISOURL != tc.wantISOURL {
				t.Errorf("ISOURL = %q, want %q", got.ISOURL, tc.wantISOURL)
			}
			if got.ProfileID != 42 {
				t.Errorf("ProfileID = %d, want 42", got.ProfileID)
			}
		})
	}
}
