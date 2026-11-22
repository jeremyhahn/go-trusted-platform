// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// registryDeleteCapture records the requests the capture server saw.
type registryDeleteCapture struct {
	mu       sync.Mutex
	method   string
	rawPath  string
	requests int
}

func (c *registryDeleteCapture) seen() (method, rawPath string, requests int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method, c.rawPath, c.requests
}

// registryDeleteAdapter connects an adapter to a TLS server that records
// every /api/ request and answers it with reply inside the webservice
// envelope.
func registryDeleteAdapter(t *testing.T, reply string) (*Adapter, *registryDeleteCapture) {
	t.Helper()
	capture := &registryDeleteCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		capture.mu.Lock()
		capture.method = r.Method
		capture.rawPath = r.URL.EscapedPath()
		capture.requests++
		capture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":` + reply + `}`))
	}))
	t.Cleanup(server.Close)

	a, err := Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer(server)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter), capture
}

func TestRegistryDelete_ResolvesToTheServedRoute(t *testing.T) {
	a, capture := registryDeleteAdapter(t, `{"Digest":"sha256:abc","BytesFreed":1,"Timestamp":"2026-11-16T10:00:00Z"}`)

	req := &platformv1.DeleteArtifactRequest{Repository: "team/app", Reference: "v1"}
	if err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_Delete_FullMethodName, req, &platformv1.DeleteArtifactResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	method, rawPath, _ := capture.seen()
	if method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", method)
	}
	if want := "/api/v1/compute/images/team%2Fapp:v1"; rawPath != want {
		t.Errorf("path = %q, want %q", rawPath, want)
	}
}

func TestRegistryDelete_EmptyRefNeverReachesTheWire(t *testing.T) {
	cases := map[string]*platformv1.DeleteArtifactRequest{
		"empty repository": {Reference: "v1"},
		"empty reference":  {Repository: "team/app"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			a, capture := registryDeleteAdapter(t, `{}`)
			err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_Delete_FullMethodName, req, &platformv1.DeleteArtifactResponse{})
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", got, err)
			}
			if _, _, n := capture.seen(); n != 0 {
				t.Errorf("server saw %d requests, want none", n)
			}
		})
	}
}

func TestRegistryDelete_DecodesTheServedReply(t *testing.T) {
	a, _ := registryDeleteAdapter(t, `{"Digest":"sha256:abc","BytesFreed":4096,"Timestamp":"2026-11-16T10:00:00Z"}`)

	reply := &platformv1.DeleteArtifactResponse{}
	req := &platformv1.DeleteArtifactRequest{Repository: "team/app", Reference: "v1"}
	if err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_Delete_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if reply.GetDigest() != "sha256:abc" {
		t.Errorf("digest = %q, want sha256:abc", reply.GetDigest())
	}
	if reply.GetBytesFreed() != 4096 {
		t.Errorf("bytes_freed = %d, want 4096", reply.GetBytesFreed())
	}
	want := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	if got := reply.GetTimestamp().AsTime(); !got.Equal(want) {
		t.Errorf("timestamp = %v, want %v", got, want)
	}
	if !reply.GetStatus().GetSuccess() {
		t.Errorf("status.success = false, want true")
	}
}
