//go:build integration

package iam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsRESTUserTotalUnknown pins the one reply the ListUsers subtest skips
// on: the 503 pkg/webservice/v1/rest/iam answers with ErrIAMUserTotalUnknown
// when the embedded go-quicbaas IAM lists a full page of 100 users with no
// total. Any other status or body stays a failure.
func TestIsRESTUserTotalUnknown(t *testing.T) {
	const unknown = `{"code":503,"error":"rest/iam: IAM listed 100 users for tenant \"system\" with no total, so the tenant's user count is unknown","success":false}`
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"TotalUnknown", http.StatusServiceUnavailable, unknown, true},
		{"OtherUnavailable", http.StatusServiceUnavailable, `{"code":503,"error":"rest/iam: IAM unavailable","success":false}`, false},
		{"SameTextOtherStatus", http.StatusInternalServerError, unknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			a := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
			_, err := a.ListUsers(context.Background(), ListUsersOptions{TenantID: "system", Limit: 10})
			if err == nil {
				t.Fatal("ListUsers returned no error for a failed reply")
			}
			if got := isRESTUserTotalUnknown(err); got != tc.want {
				t.Fatalf("isRESTUserTotalUnknown(%v) = %v, want %v", err, got, tc.want)
			}
		})
	}
	if isRESTUserTotalUnknown(nil) {
		t.Fatal("isRESTUserTotalUnknown(nil) = true")
	}
}
