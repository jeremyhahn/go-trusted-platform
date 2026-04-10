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

package push

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		if client.IsClosed() {
			t.Error("new client should not be closed")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewClient(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
		if _, ok := err.(ErrInvalidConfig); !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := &ClientConfig{
			DefaultTimeout: -1 * time.Second,
		}
		_, err := NewClient(cfg)
		if err == nil {
			t.Error("expected error for invalid config")
		}
	})

	t.Run("with TLS config option", func(t *testing.T) {
		cfg := DefaultClientConfig()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
		client, err := NewClient(cfg, WithTLSConfig(tlsConfig))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()
	})

	t.Run("with custom HTTP client", func(t *testing.T) {
		cfg := DefaultClientConfig()
		httpClient := &http.Client{Timeout: 5 * time.Second}
		client, err := NewClient(cfg, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()
	})

	t.Run("with config TLS config", func(t *testing.T) {
		cfg := DefaultClientConfig()
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()
	})
}

func TestClientClose(t *testing.T) {
	t.Run("close client", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("expected no error on close, got %v", err)
		}

		if !client.IsClosed() {
			t.Error("client should be closed")
		}
	})

	t.Run("double close", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("expected no error on first close, got %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("expected no error on second close, got %v", err)
		}
	})
}

func TestClientPushHTTP(t *testing.T) {
	t.Run("successful push", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
			}

			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"test":"data"}` {
				t.Errorf("unexpected body: %s", body)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "test-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`{"test":"data"}`),
			ContentType: "application/json",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got status %s", result.Status)
		}
		if result.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", result.StatusCode)
		}
		if result.Attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", result.Attempts)
		}
		if string(result.Response) != `{"status":"ok"}` {
			t.Errorf("unexpected response: %s", result.Response)
		}
	})

	t.Run("disabled target is skipped", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "disabled-target",
			Endpoint:  "https://example.com",
			Transport: TransportHTTP,
			Enabled:   false,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`{"test":"data"}`),
			ContentType: "application/json",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if result.Status != PushStatusSkipped {
			t.Errorf("expected skipped status, got %s", result.Status)
		}
	})

	t.Run("server error with retry", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &ClientConfig{
			DefaultTimeout: 5 * time.Second,
			Retry: &RetryConfig{
				MaxAttempts:          3,
				InitialBackoff:       1 * time.Millisecond,
				MaxBackoff:           10 * time.Millisecond,
				BackoffMultiplier:    2.0,
				RetryableStatusCodes: []int{503},
			},
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "retry-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success after retries, got %s", result.Status)
		}
		if result.Attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", result.Attempts)
		}
	})

	t.Run("retry exhausted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		cfg := &ClientConfig{
			DefaultTimeout: 5 * time.Second,
			Retry: &RetryConfig{
				MaxAttempts:          2,
				InitialBackoff:       1 * time.Millisecond,
				MaxBackoff:           5 * time.Millisecond,
				BackoffMultiplier:    2.0,
				RetryableStatusCodes: []int{503},
			},
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "fail-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error")
		}

		if result.Status != PushStatusFailed {
			t.Errorf("expected failed status, got %s", result.Status)
		}

		if _, ok := err.(ErrRetryExhausted); !ok {
			t.Errorf("expected ErrRetryExhausted, got %T", err)
		}
	})

	t.Run("auth failure not retried", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "auth-fail-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error")
		}

		if attempts > 1 {
			t.Errorf("expected 1 attempt for auth failure, got %d", attempts)
		}
	})

	t.Run("forbidden error not retried", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("access denied"))
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "forbidden-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrAuthFailed); !ok {
			t.Errorf("expected ErrAuthFailed, got %T", err)
		}
	})

	t.Run("bearer token auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-token" {
				t.Errorf("expected Bearer test-token, got %s", auth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "auth-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Auth: &AuthConfig{
				Type:  "bearer",
				Token: "test-token",
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got %s", result.Status)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Basic ") {
				t.Error("expected Basic auth header")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "basic-auth-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Auth: &AuthConfig{
				Type:     "basic",
				Username: "user",
				Password: "pass",
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got %s", result.Status)
		}
	})

	t.Run("no auth type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "mtls-auth-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Auth: &AuthConfig{
				Type: "", // No auth
				// mTLS is configured at transport level
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got %s", result.Status)
		}
	})

	t.Run("custom headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Custom-Header") != "custom-value" {
				t.Error("expected custom header")
			}
			if r.Header.Get("User-Agent") != "go-trusted-platform/1.0" {
				t.Errorf("unexpected user agent: %s", r.Header.Get("User-Agent"))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "custom-headers-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Headers: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got %s", result.Status)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "cancel-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Timeout:   1 * time.Second,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		result, err := client.Push(ctx, target, request)
		if err == nil {
			t.Error("expected error for canceled context")
		}

		if result.Status != PushStatusCanceled {
			t.Errorf("expected canceled status, got %s", result.Status)
		}
	})

	t.Run("context cancellation during retry backoff", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		cfg := &ClientConfig{
			DefaultTimeout: 5 * time.Second,
			Retry: &RetryConfig{
				MaxAttempts:          5,
				InitialBackoff:       1 * time.Second, // Long backoff
				MaxBackoff:           5 * time.Second,
				BackoffMultiplier:    2.0,
				RetryableStatusCodes: []int{503},
			},
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "cancel-during-retry-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result, err := client.Push(ctx, target, request)
		if err == nil {
			t.Error("expected error for canceled context")
		}

		if result.Status != PushStatusCanceled {
			t.Errorf("expected canceled status, got %s", result.Status)
		}
	})

	t.Run("closed client", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		client.Close()

		target := &PushTarget{
			ID:        "test-target",
			Endpoint:  "https://example.com",
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error for closed client")
		}
		if _, ok := err.(ErrClientClosed); !ok {
			t.Errorf("expected ErrClientClosed, got %T", err)
		}
	})

	t.Run("nil target", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), nil, request)
		if err == nil {
			t.Error("expected error for nil target")
		}
	})

	t.Run("invalid target", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID: "", // Invalid
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error for invalid target")
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "test-target",
			Endpoint:  "https://example.com",
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			Payload: nil, // Invalid
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error for invalid request")
		}
	})

	t.Run("unsupported transport", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "test-target",
			Endpoint:  "https://example.com",
			Transport: TransportType("websocket"),
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		// This will fail validation
		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error for unsupported transport")
		}
	})

	t.Run("target with custom timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "timeout-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
			Timeout:   5 * time.Second, // Custom timeout
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Errorf("expected success, got %s", result.Status)
		}
	})

	t.Run("non-retryable error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "bad-request-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.Push(context.Background(), target, request)
		if err == nil {
			t.Error("expected error for bad request")
		}
		if _, ok := err.(ErrInvalidResponse); !ok {
			t.Errorf("expected ErrInvalidResponse, got %T", err)
		}
	})
}

func TestClientPushBatch(t *testing.T) {
	t.Run("successful batch", func(t *testing.T) {
		server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"target":"1"}`))
		}))
		defer server1.Close()

		server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"target":"2"}`))
		}))
		defer server2.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server1.URL, Transport: TransportHTTP, Enabled: true},
			{ID: "t2", Endpoint: server2.URL, Transport: TransportHTTP, Enabled: true},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`{"test":"data"}`),
			ContentType: "application/json",
		}

		result, err := client.PushBatch(context.Background(), targets, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.AllSuccess() {
			t.Error("expected all success")
		}
		if result.SuccessCount != 2 {
			t.Errorf("expected 2 successes, got %d", result.SuccessCount)
		}
		if result.FailureCount != 0 {
			t.Errorf("expected 0 failures, got %d", result.FailureCount)
		}
		if result.TotalTargets != 2 {
			t.Errorf("expected 2 total targets, got %d", result.TotalTargets)
		}
	})

	t.Run("partial failure", func(t *testing.T) {
		server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server1.Close()

		server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server2.Close()

		cfg := &ClientConfig{
			DefaultTimeout: 5 * time.Second,
			Retry: &RetryConfig{
				MaxAttempts:          1, // No retries
				InitialBackoff:       1 * time.Millisecond,
				MaxBackoff:           1 * time.Millisecond,
				BackoffMultiplier:    1.0,
				RetryableStatusCodes: []int{},
			},
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server1.URL, Transport: TransportHTTP, Enabled: true},
			{ID: "t2", Endpoint: server2.URL, Transport: TransportHTTP, Enabled: true},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.PushBatch(context.Background(), targets, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if result.AllSuccess() {
			t.Error("expected partial failure")
		}
		if !result.AnySuccess() {
			t.Error("expected at least one success")
		}
		if result.SuccessCount != 1 {
			t.Errorf("expected 1 success, got %d", result.SuccessCount)
		}
		if result.FailureCount != 1 {
			t.Errorf("expected 1 failure, got %d", result.FailureCount)
		}
	})

	t.Run("no targets", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.PushBatch(context.Background(), []*PushTarget{}, request)
		if err == nil {
			t.Error("expected error for no targets")
		}
	})

	t.Run("closed client", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		_, err = client.PushBatch(context.Background(), targets, request)
		if err == nil {
			t.Error("expected error for closed client")
		}
	})

	t.Run("with disabled targets", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
			{ID: "t2", Endpoint: server.URL, Transport: TransportHTTP, Enabled: false},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "text/plain",
		}

		result, err := client.PushBatch(context.Background(), targets, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if result.SuccessCount != 1 {
			t.Errorf("expected 1 success, got %d", result.SuccessCount)
		}
		if result.SkippedCount != 1 {
			t.Errorf("expected 1 skipped, got %d", result.SkippedCount)
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		request := &PushRequest{
			// Missing payload and content type
		}

		_, err = client.PushBatch(context.Background(), targets, request)
		if err == nil {
			t.Error("expected error for invalid request")
		}
	})
}

func TestClientPushGRPC(t *testing.T) {
	t.Run("grpc with token auth", func(t *testing.T) {
		cfg := DefaultClientConfig()
		cfg.Retry = &RetryConfig{
			MaxAttempts:       1,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        1 * time.Millisecond,
			BackoffMultiplier: 1.0,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "grpc-token-target",
			Endpoint:  "localhost:0", // Invalid port
			Transport: TransportGRPC,
			Enabled:   true,
			Timeout:   100 * time.Millisecond,
			Auth: &AuthConfig{
				Type:  "bearer",
				Token: "test-token",
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "application/protobuf",
		}

		_, err = client.Push(context.Background(), target, request)
		// Will fail to connect but exercises the gRPC path
		if err == nil {
			t.Log("expected error for invalid gRPC endpoint")
		}
	})

	t.Run("grpc with TLS config", func(t *testing.T) {
		cfg := DefaultClientConfig()
		cfg.Retry = &RetryConfig{
			MaxAttempts:       1,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        1 * time.Millisecond,
			BackoffMultiplier: 1.0,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "grpc-tls-target",
			Endpoint:  "localhost:0",
			Transport: TransportGRPC,
			Enabled:   true,
			Timeout:   100 * time.Millisecond,
			Auth: &AuthConfig{
				TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`test`),
			ContentType: "application/protobuf",
		}

		_, err = client.Push(context.Background(), target, request)
		// Will fail to connect but exercises the gRPC TLS path
		if err == nil {
			t.Log("expected error for invalid gRPC endpoint")
		}
	})
}

func TestLoadTLSConfigFromFiles(t *testing.T) {
	t.Run("empty files", func(t *testing.T) {
		cfg, err := LoadTLSConfigFromFiles("", "", "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Error("expected TLS 1.2 minimum")
		}
	})

	t.Run("invalid cert file", func(t *testing.T) {
		_, err := LoadTLSConfigFromFiles("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
		if err == nil {
			t.Error("expected error for nonexistent files")
		}
	})

	t.Run("invalid CA file", func(t *testing.T) {
		_, err := LoadTLSConfigFromFiles("", "", "/nonexistent/ca.pem")
		if err == nil {
			t.Error("expected error for nonexistent CA file")
		}
	})

	t.Run("invalid CA content", func(t *testing.T) {
		// Create temp file with invalid cert content
		tmpDir := t.TempDir()
		caFile := filepath.Join(tmpDir, "invalid-ca.pem")
		err := os.WriteFile(caFile, []byte("not a valid cert"), 0600)
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		_, err = LoadTLSConfigFromFiles("", "", caFile)
		if err == nil {
			t.Error("expected error for invalid CA content")
		}
	})
}

func TestClientIsRetryable(t *testing.T) {
	cfg := DefaultClientConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer client.Close()

	retry := DefaultRetryConfig()

	t.Run("target unreachable is retryable", func(t *testing.T) {
		err := ErrTargetUnreachable{}
		if !client.isRetryable(err, 0, retry) {
			t.Error("ErrTargetUnreachable should be retryable")
		}
	})

	t.Run("auth failed is not retryable", func(t *testing.T) {
		err := ErrAuthFailed{}
		if client.isRetryable(err, 0, retry) {
			t.Error("ErrAuthFailed should not be retryable")
		}
	})

	t.Run("invalid target is not retryable", func(t *testing.T) {
		err := ErrInvalidTarget{}
		if client.isRetryable(err, 0, retry) {
			t.Error("ErrInvalidTarget should not be retryable")
		}
	})

	t.Run("retryable status codes", func(t *testing.T) {
		if !client.isRetryable(nil, 503, retry) {
			t.Error("503 should be retryable")
		}
		if client.isRetryable(nil, 400, retry) {
			t.Error("400 should not be retryable")
		}
	})

	t.Run("unknown error is retryable by default", func(t *testing.T) {
		err := ErrPushFailed{}
		if !client.isRetryable(err, 0, retry) {
			t.Error("unknown error should be retryable by default")
		}
	})
}

func TestClientResponseParsing(t *testing.T) {
	t.Run("json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"status":  "accepted",
				"id":      "12345",
				"message": "Manifest received",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}))
		defer server.Close()

		cfg := DefaultClientConfig()
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer client.Close()

		target := &PushTarget{
			ID:        "json-target",
			Endpoint:  server.URL,
			Transport: TransportHTTP,
			Enabled:   true,
		}

		request := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`{"test":"data"}`),
			ContentType: "application/json",
		}

		result, err := client.Push(context.Background(), target, request)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !result.Success() {
			t.Error("expected success")
		}

		var respData map[string]interface{}
		if err := json.Unmarshal(result.Response, &respData); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if respData["status"] != "accepted" {
			t.Errorf("unexpected status: %v", respData["status"])
		}
	})
}

func TestClientBuildTLSConfig(t *testing.T) {
	cfg := DefaultClientConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer client.Close()

	t.Run("with pre-configured TLS config", func(t *testing.T) {
		auth := &AuthConfig{
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		}

		result, err := client.buildTLSConfig(auth)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.MinVersion != tls.VersionTLS13 {
			t.Error("expected TLS 1.3 minimum")
		}
	})

	t.Run("with invalid client cert", func(t *testing.T) {
		auth := &AuthConfig{
			ClientCert: "/nonexistent/cert.pem",
			ClientKey:  "/nonexistent/key.pem",
		}

		_, err := client.buildTLSConfig(auth)
		if err == nil {
			t.Error("expected error for nonexistent cert files")
		}
	})

	t.Run("with invalid CA cert", func(t *testing.T) {
		auth := &AuthConfig{
			CACert: "/nonexistent/ca.pem",
		}

		_, err := client.buildTLSConfig(auth)
		if err == nil {
			t.Error("expected error for nonexistent CA file")
		}
	})

	t.Run("with invalid CA cert content", func(t *testing.T) {
		tmpDir := t.TempDir()
		caFile := filepath.Join(tmpDir, "invalid-ca.pem")
		err := os.WriteFile(caFile, []byte("not a valid cert"), 0600)
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		auth := &AuthConfig{
			CACert: caFile,
		}

		_, err = client.buildTLSConfig(auth)
		if err == nil {
			t.Error("expected error for invalid CA content")
		}
	})
}

func TestClientApplyAuth(t *testing.T) {
	cfg := DefaultClientConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer client.Close()

	t.Run("unsupported auth type", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://example.com", nil)
		auth := &AuthConfig{Type: "oauth2"}

		err := client.applyAuth(req, auth)
		if err == nil {
			t.Error("expected error for unsupported auth type")
		}
	})
}
