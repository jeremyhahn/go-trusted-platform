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

package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// initServer answers POST /init like the daemon's pre-unseal mux and
// records the decoded request.
func initServer(t *testing.T, status int, reply any, got *InitRequest) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/init", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(reply); err != nil {
			t.Errorf("encode reply: %v", err)
		}
	})
	return mux
}

func bundleReply() *InitResponse {
	return &InitResponse{
		CeremonyID: "c1", State: StateUnsealed, SPKIPin: "PIN",
		AdminCertPEM: "ADMIN-CERT", AdminKeyPEM: "ADMIN-KEY",
	}
}

func TestClient_InitOverUnixSocket(t *testing.T) {
	var got InitRequest
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: initServer(t, http.StatusOK, bundleReply(), &got)}}
	srv.Start()
	t.Cleanup(srv.Close)

	client, err := NewClient(UnixScheme + sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := client.Init(context.Background(), &InitRequest{SOPIN: "so", UserPIN: "user", Shares: 5, Threshold: 3})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got.SOPIN != "so" || got.UserPIN != "user" || got.Shares != 5 || got.Threshold != 3 {
		t.Errorf("request not sent intact: %+v", got)
	}
	if resp.AdminCertPEM != "ADMIN-CERT" || resp.AdminKeyPEM != "ADMIN-KEY" || resp.SPKIPin != "PIN" || resp.State != StateUnsealed {
		t.Errorf("response not decoded: %+v", resp)
	}
}

func TestClient_InitOverLoopback(t *testing.T) {
	var got InitRequest
	srv := httptest.NewServer(initServer(t, http.StatusOK, bundleReply(), &got))
	t.Cleanup(srv.Close)

	client, err := NewClient(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := client.Init(context.Background(), &InitRequest{Hostname: "cp-01"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got.Hostname != "cp-01" || resp.CeremonyID != "c1" {
		t.Errorf("got request %+v, response %+v", got, resp)
	}
}

func TestClient_InitRejectedCarriesStatusAndMessage(t *testing.T) {
	var got InitRequest
	srv := httptest.NewServer(initServer(t, http.StatusConflict, map[string]string{"error": "init not permitted"}, &got))
	t.Cleanup(srv.Close)

	client, err := NewClient(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Init(context.Background(), &InitRequest{})
	var rejected *ErrInitRejected
	if !errors.As(err, &rejected) {
		t.Fatalf("expected ErrInitRejected, got %v", err)
	}
	if rejected.StatusCode != http.StatusConflict || rejected.Message != "init not permitted" {
		t.Errorf("rejection = %+v", rejected)
	}
}

// redirectingServer answers every request with a 307 to target and counts the
// requests target receives.
func redirectingServer(t *testing.T) (redirect http.Handler, targetHits *atomic.Int32) {
	t.Helper()
	targetHits = &atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	redirect = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/init", http.StatusTemporaryRedirect)
	})
	return redirect, targetHits
}

// TestClient_InitDoesNotFollowRedirectOverLoopback covers a loopback gate that
// answers 307 to another host: the PINs are not resent, and the redirect is
// reported as a rejection.
func TestClient_InitDoesNotFollowRedirectOverLoopback(t *testing.T) {
	redirect, targetHits := redirectingServer(t)
	srv := httptest.NewServer(redirect)
	t.Cleanup(srv.Close)

	client, err := NewClient(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Init(context.Background(), &InitRequest{SOPIN: "so", UserPIN: "user"})
	var rejected *ErrInitRejected
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected ErrInitRejected with 307, got %v", err)
	}
	if hits := targetHits.Load(); hits != 0 {
		t.Errorf("redirect target received %d requests, want 0", hits)
	}
}

// TestClient_InitDoesNotFollowRedirectOverUnixSocket covers the same 307 on
// the Unix socket client. That client dials the socket whatever the host, so a
// followed redirect would land on the socket again: exactly one request there
// proves none was followed.
func TestClient_InitDoesNotFollowRedirectOverUnixSocket(t *testing.T) {
	var socketHits atomic.Int32
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socketHits.Add(1)
		http.Redirect(w, r, "http://192.0.2.1/init", http.StatusTemporaryRedirect)
	})
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: redirect}}
	srv.Start()
	t.Cleanup(srv.Close)

	client, err := NewClient(UnixScheme + sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Init(context.Background(), &InitRequest{SOPIN: "so", UserPIN: "user"})
	var rejected *ErrInitRejected
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected ErrInitRejected with 307, got %v", err)
	}
	if hits := socketHits.Load(); hits != 1 {
		t.Errorf("socket received %d requests, want 1", hits)
	}
}

func TestClient_InitUnreachableIsInitFailed(t *testing.T) {
	client, err := NewClient(UnixScheme + filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Init(context.Background(), nil)
	var failed *ErrInitFailed
	if !errors.As(err, &failed) {
		t.Fatalf("expected ErrInitFailed, got %v", err)
	}
}

func TestClient_InitMalformedReplyIsInitFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("{not json")); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Init(context.Background(), &InitRequest{})
	var failed *ErrInitFailed
	if !errors.As(err, &failed) {
		t.Fatalf("expected ErrInitFailed, got %v", err)
	}
}

// TestNewClient_RefusesNonLocalEndpoints keeps the PINs on the host: the
// pre-unseal mux is never bound off-host.
func TestNewClient_RefusesNonLocalEndpoints(t *testing.T) {
	// localhost is refused too: a name resolves through /etc/hosts and DNS,
	// which need not map it to loopback.
	for _, endpoint := range []string{"", "unix://", "10.0.0.5:9446", "platform.example.com:9446", "http://127.0.0.1:9446", "127.0.0.1", "localhost:9446"} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := NewClient(endpoint)
			var invalid *ErrInvalidEndpoint
			if !errors.As(err, &invalid) {
				t.Errorf("NewClient(%q) = %v, want ErrInvalidEndpoint", endpoint, err)
			}
		})
	}
}

func TestNewClient_AcceptsLocalEndpoints(t *testing.T) {
	for _, endpoint := range []string{DefaultHTTPAddr, "127.0.0.2:9446", "[::1]:9446", "unix:///run/platformd.sock"} {
		if _, err := NewClient(endpoint); err != nil {
			t.Errorf("NewClient(%q): %v", endpoint, err)
		}
	}
}

func TestErrors_Messages(t *testing.T) {
	cases := map[string]error{
		"invalid endpoint": &ErrInvalidEndpoint{Endpoint: "x", Reason: "r"},
		"init failed":      &ErrInitFailed{Cause: errors.New("boom")},
		"HTTP 409: busy":   &ErrInitRejected{StatusCode: 409, Message: "busy"},
	}
	for want, err := range cases {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%T message %q does not contain %q", err, err.Error(), want)
		}
	}
	if (&ErrInitRejected{StatusCode: 503}).Error() != "gate: init rejected with HTTP 503" {
		t.Error("rejection without a message should not end in a colon")
	}
}
