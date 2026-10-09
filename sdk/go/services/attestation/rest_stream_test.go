// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package attestation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sseServer answers the verdict stream route with body and records the
// request's Authorization header.
func sseServer(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1"+verdictStreamPath {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, &auth
}

func verdictEventJSON(t *testing.T, tenant string) string {
	t.Helper()
	data, err := protojson.Marshal(&platformv1.DeviceVerdictEvent{EventId: "ev-1", TenantId: tenant, Reason: "bad quote"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

func TestStreamDeviceVerdictsREST_ReceivesVerdictsAndSkipsComments(t *testing.T) {
	body := ": subscribed\n\n: heartbeat\n\nid: ev-1\nevent: verdict\ndata: " + verdictEventJSON(t, "t1") + "\n\n"
	server, auth := sseServer(t, http.StatusOK, body)

	stream, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{
		BaseURL: server.URL + "/api/v1/", AuthToken: "tok"})
	if err != nil {
		t.Fatalf("StreamDeviceVerdictsREST: %v", err)
	}
	defer stream.Close()
	var _ DeviceVerdictStream = stream

	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if event.GetEventId() != "ev-1" || event.GetTenantId() != "t1" || event.GetReason() != "bad quote" {
		t.Fatalf("event = %v", event)
	}
	if *auth != "Bearer tok" {
		t.Fatalf("Authorization = %q", *auth)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("Recv after the last event = %v, want io.EOF", err)
	}
}

func TestStreamDeviceVerdictsREST_ServerEndIsATypedError(t *testing.T) {
	server, _ := sseServer(t, http.StatusOK, "event: error\ndata: \"the device verdict stream is closed\"\n\n")
	stream, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{BaseURL: server.URL + "/api/v1"})
	if err != nil {
		t.Fatalf("StreamDeviceVerdictsREST: %v", err)
	}
	defer stream.Close()
	var ended *ErrVerdictStreamEnded
	if _, err := stream.Recv(); !errors.As(err, &ended) || ended.Reason != "the device verdict stream is closed" {
		t.Fatalf("Recv = %v, want ErrVerdictStreamEnded with the server's reason", err)
	}
}

func TestStreamDeviceVerdictsREST_RefusalIsATypedError(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		server, _ := sseServer(t, status, `{"error":"denied"}`)
		_, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{BaseURL: server.URL + "/api/v1"})
		var failed *ErrStreamDeviceVerdictsFailed
		var refused *ErrVerdictStreamRefused
		if !errors.As(err, &failed) || !errors.As(err, &refused) || refused.StatusCode != status {
			t.Fatalf("status %d: err = %v, want a refusal carrying the status", status, err)
		}
	}
}

func TestStreamDeviceVerdictsREST_BadEventsAreDecodeErrors(t *testing.T) {
	for name, body := range map[string]string{
		"malformed verdict": "event: verdict\ndata: {not json\n\n",
		"unknown event":     "event: surprise\ndata: x\n\n",
	} {
		server, _ := sseServer(t, http.StatusOK, body)
		stream, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{BaseURL: server.URL + "/api/v1"})
		if err != nil {
			t.Fatalf("%s: StreamDeviceVerdictsREST: %v", name, err)
		}
		var decode *ErrDecodeDeviceVerdictFailed
		if _, err := stream.Recv(); !errors.As(err, &decode) {
			t.Errorf("%s: Recv = %v, want ErrDecodeDeviceVerdictFailed", name, err)
		}
		stream.Close()
	}
}

func TestStreamDeviceVerdictsREST_UnreachableServer(t *testing.T) {
	server, _ := sseServer(t, http.StatusOK, "")
	url := server.URL
	server.Close()
	var failed *ErrStreamDeviceVerdictsFailed
	if _, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{BaseURL: url + "/api/v1"}); !errors.As(err, &failed) {
		t.Fatalf("err = %v, want ErrStreamDeviceVerdictsFailed", err)
	}
	if _, err := StreamDeviceVerdictsREST(context.Background(), RESTStreamConfig{BaseURL: "://bad"}); !errors.As(err, &failed) {
		t.Fatalf("bad URL: err = %v, want ErrStreamDeviceVerdictsFailed", err)
	}
}

func TestStreamDeviceVerdictsREST_ContextEndsTheStream(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := StreamDeviceVerdictsREST(ctx, RESTStreamConfig{BaseURL: server.URL + "/api/v1"})
	if err != nil {
		t.Fatalf("StreamDeviceVerdictsREST: %v", err)
	}
	defer stream.Close()
	cancel()
	if _, err := stream.Recv(); err == nil {
		t.Fatal("Recv must fail once ctx is cancelled")
	}
}
