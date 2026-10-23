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

//go:build integration

package compute_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// restCallCountingServer counts the requests it serves and answers 200 with
// an empty JSON message, so a call that survives client-side refusal reaches
// it and decodes without a real daemon behind.
func restCallCountingServer(t *testing.T, count *atomic.Int32) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestRESTAdapter(server *httptest.Server) *RESTAdapter {
	return &RESTAdapter{
		endpoint:   server.URL,
		httpClient: &http.Client{},
	}
}

// TestRESTAdapterCallRefusesEmptyPathSegment holds that a route with an empty
// path segment is refused before the request leaves the adapter: it carries
// the typed error with InvalidArgument, and the server never sees it.
func TestRESTAdapterCallRefusesEmptyPathSegment(t *testing.T) {
	count := atomic.Int32{}
	adapter := newTestRESTAdapter(restCallCountingServer(t, &count))

	// The two routes the empty-VM-id leaves of TestComputeMultiProtocol
	// (VMSnapshots, VMAttestation) build when the id is absent.
	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "empty VM id in snapshots path", path: computeVMsPath + "//snapshots"},
		{name: "empty VM id in attest path", path: computeVMsPath + "//attest"},
		{name: "trailing slash", path: computeVMsPath + "/vm-1/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := adapter.call(context.Background(), http.MethodGet, tc.path, nil, nil, nil)
			if err == nil {
				t.Fatalf("call with %q: got nil error, want ErrRESTEmptyPathSegment", tc.path)
			}
			var wantErr ErrRESTEmptyPathSegment
			if !errors.As(err, &wantErr) {
				t.Fatalf("call with %q: got %T (%v), want ErrRESTEmptyPathSegment", tc.path, err, err)
			}
			if wantErr.Path != tc.path {
				t.Errorf("error path = %q, want %q", wantErr.Path, tc.path)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("status.Code = %v, want InvalidArgument", got)
			}
			if got := count.Load(); got != 0 {
				t.Errorf("server saw %d requests, want 0: the refusal must not leave the client", got)
			}
		})
	}
}

// TestRESTAdapterCallSendsValidPath holds that a well-formed route reaches
// the server and its 200 reply decodes.
func TestRESTAdapterCallSendsValidPath(t *testing.T) {
	count := atomic.Int32{}
	adapter := newTestRESTAdapter(restCallCountingServer(t, &count))

	out := &pb.GetVMResponse{}
	if err := adapter.call(context.Background(), http.MethodGet, computeVMsPath+"/vm-1", nil, nil, out); err != nil {
		t.Fatalf("call with a valid path: %v", err)
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}
