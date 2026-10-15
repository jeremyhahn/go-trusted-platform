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

package rest

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIdentityKeyDelete_RefusalIsFailedPrecondition pins #304 on the SDK REST
// transport: the IDevID and IAK key deletes reach the daemon's routes, and
// its 412 refusal comes back as FailedPrecondition with the daemon's message.
func TestIdentityKeyDelete_RefusalIsFailedPrecondition(t *testing.T) {
	const refusal = "idevid: the key is TPM-resident and is not evicted by this service; nothing was deleted"
	calls := map[string]struct {
		path  string
		req   any
		reply any
	}{
		platformv1.IDevIDService_DeleteIDevID_FullMethodName: {"/api/v1/tpm/idevid", &platformv1.DeleteIDevIDRequest{}, &platformv1.DeleteIDevIDResponse{}},
		platformv1.IDevIDService_DeleteIAK_FullMethodName:    {"/api/v1/tpm/iak", &platformv1.DeleteIAKRequest{}, &platformv1.DeleteIAKResponse{}},
	}

	for method, call := range calls {
		t.Run(method, func(t *testing.T) {
			var gotMethod, gotPath string
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":"` + refusal + `","code":412}`))
			})

			err := a.Connection().Invoke(context.Background(), method, call.req, call.reply)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("Invoke error = %v, want FailedPrecondition", err)
			}
			if msg := status.Convert(err).Message(); msg != refusal {
				t.Errorf("message = %q, want %q", msg, refusal)
			}
			if gotMethod != http.MethodDelete || gotPath != call.path {
				t.Errorf("request = %s %s, want DELETE %s", gotMethod, gotPath, call.path)
			}
		})
	}
}

// TestIdentityKeyDelete_OtherFailureKeepsItsClass guards the mapping from
// turning every failure into a refusal: a 503 stays Unavailable.
func TestIdentityKeyDelete_OtherFailureKeepsItsClass(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"TPM service not available"}`))
	})

	err := a.Connection().Invoke(context.Background(), platformv1.IDevIDService_DeleteIDevID_FullMethodName,
		&platformv1.DeleteIDevIDRequest{}, &platformv1.DeleteIDevIDResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Invoke error = %v, want Unavailable", err)
	}
}
