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

package platform

import (
	"context"
	"net/http"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeShutdowner records the request the handler hands it, so a test
// can assert what PlatformDaemon.Shutdown would have received.
type fakeShutdowner struct {
	got chan *platformv1.ShutdownRequest
	err error
}

func newFakeShutdowner() *fakeShutdowner {
	return &fakeShutdowner{got: make(chan *platformv1.ShutdownRequest, 1)}
}

func (f *fakeShutdowner) Shutdown(_ context.Context, req *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error) {
	f.got <- req
	return &platformv1.ShutdownResponse{Status: &platformv1.Status{Success: true}}, f.err
}

func waitShutdown(t *testing.T, f *fakeShutdowner) *platformv1.ShutdownRequest {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case req := <-f.got:
		return req
	case <-timer.C:
		t.Fatal("Shutdown was not called within 2s")
		return nil
	}
}

const shutdownPath = "/api/v1/platform/shutdown"

func TestShutdown_UnwiredIs503(t *testing.T) {
	_, root := newMountedRouter(t)
	rec := serve(root, http.MethodPost, shutdownPath, "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestShutdown_EmptyBodyIsGraceful(t *testing.T) {
	pr, root := newMountedRouter(t)
	f := newFakeShutdowner()
	pr.SetShutdowner(f)

	rec := serve(root, http.MethodPost, shutdownPath, "", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	var got struct {
		Status struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
		} `json:"status"`
	}
	payloadOf(t, rec, &got)
	if !got.Status.Success || got.Status.Message != "shutdown started" {
		t.Fatalf("payload status = %+v, want success and \"shutdown started\"", got.Status)
	}

	req := waitShutdown(t, f)
	if !req.GetGraceful() || req.GetTimeoutSeconds() != 0 {
		t.Fatalf("request = graceful %v timeout %d, want graceful true timeout 0",
			req.GetGraceful(), req.GetTimeoutSeconds())
	}
}

func TestShutdown_BodyIsDecoded(t *testing.T) {
	pr, root := newMountedRouter(t)
	f := newFakeShutdowner()
	pr.SetShutdowner(f)

	rec := serve(root, http.MethodPost, shutdownPath, `{"graceful":false,"timeoutSeconds":5}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	req := waitShutdown(t, f)
	if req.GetGraceful() || req.GetTimeoutSeconds() != 5 {
		t.Fatalf("request = graceful %v timeout %d, want graceful false timeout 5",
			req.GetGraceful(), req.GetTimeoutSeconds())
	}
}

func TestShutdown_BadJSONIs400(t *testing.T) {
	pr, root := newMountedRouter(t)
	f := newFakeShutdowner()
	pr.SetShutdowner(f)

	rec := serve(root, http.MethodPost, shutdownPath, `{"graceful":`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	select {
	case req := <-f.got:
		t.Fatalf("Shutdown called on a bad body: %v", req)
	default:
	}
}

func TestShutdown_GetIs405(t *testing.T) {
	pr, root := newMountedRouter(t)
	f := newFakeShutdowner()
	pr.SetShutdowner(f)

	rec := serve(root, http.MethodGet, shutdownPath, "", nil)
	if rec.Code == http.StatusAccepted {
		t.Fatalf("GET answered 202; only POST may shut the daemon down")
	}
}
