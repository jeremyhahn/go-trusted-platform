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

package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// retryTestMaxRetries is the retry budget every client in these tests has,
// so a retried answer shows up as more than one attempt.
const retryTestMaxRetries = 3

// countingServer answers each request with the next handler in answers,
// repeating the last one, and counts the requests it receives.
func countingServer(t *testing.T, answers ...http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(attempts.Add(1))
		answers[min(n, len(answers))-1](w, r)
	}))
	t.Cleanup(server.Close)
	return server, &attempts
}

// rpcAnswer answers a JSON-RPC request with the given result or error.
func rpcAnswer(t *testing.T, result interface{}, rpcErr *JSONRPCError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}
}

// okToolResult is the CallToolResult of a tool whose output is {"ok": true}.
func okToolResult(t *testing.T) *CallToolResult {
	t.Helper()
	result, err := NewCallToolResult(map[string]interface{}{"ok": true})
	if err != nil {
		t.Fatalf("NewCallToolResult: %v", err)
	}
	return result
}

// statusAnswer answers with a bare HTTP status and the given headers.
func statusAnswer(code int, header ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		http.Error(w, http.StatusText(code), code)
	}
}

// retryTestClient builds a client with retryTestMaxRetries retries and the
// given delay between them.
func retryTestClient(t *testing.T, addr string, delay time.Duration) *Client {
	t.Helper()
	client, err := NewClient(&ClientConfig{
		ServerAddr: addr,
		Timeout:    5 * time.Second,
		MaxRetries: retryTestMaxRetries,
		RetryDelay: delay,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestClient_AnswersOnPurposeAreNotRetried(t *testing.T) {
	toolErrorResult := map[string]interface{}{
		"isError": true,
		"content": []interface{}{map[string]interface{}{"type": "text", "text": "refused"}},
	}

	tests := []struct {
		name   string
		answer func(t *testing.T) http.HandlerFunc
		check  func(t *testing.T, result interface{}, err error)
	}{
		{
			name: "JSON-RPC error",
			answer: func(t *testing.T) http.HandlerFunc {
				return rpcAnswer(t, nil, &JSONRPCError{Code: PermissionDenied, Message: "permission denied"})
			},
			check: func(t *testing.T, _ interface{}, err error) {
				var mcpErr *MCPError
				if !errors.As(err, &mcpErr) || mcpErr.Code != PermissionDenied {
					t.Errorf("err = %v, want MCPError with code PermissionDenied", err)
				}
			},
		},
		{
			name: "tool error result",
			answer: func(t *testing.T) http.HandlerFunc {
				return rpcAnswer(t, toolErrorResult, nil)
			},
			check: func(t *testing.T, result interface{}, err error) {
				var toolErr *ErrToolFailed
				if !errors.As(err, &toolErr) || toolErr.Message != "refused" {
					t.Errorf("err = %v, want ErrToolFailed with message refused", err)
				}
				if result != nil {
					t.Errorf("result = %v, want nil for a failed tool", result)
				}
			},
		},
	}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		tests = append(tests, struct {
			name   string
			answer func(t *testing.T) http.HandlerFunc
			check  func(t *testing.T, result interface{}, err error)
		}{
			name:   "HTTP " + strconv.Itoa(code),
			answer: func(*testing.T) http.HandlerFunc { return statusAnswer(code) },
			check: func(t *testing.T, _ interface{}, err error) {
				var statusErr *HTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != code {
					t.Errorf("err = %v, want HTTPStatusError with status %d", err, code)
				}
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, attempts := countingServer(t, tt.answer(t))
			client := retryTestClient(t, server.URL, time.Millisecond)

			result, err := client.CallTool(context.Background(), "iam_create_user", nil)

			tt.check(t, result, err)
			if got := attempts.Load(); got != 1 {
				t.Errorf("attempts = %d, want 1", got)
			}
		})
	}
}

func TestClient_RetriesWhenTheServerAsks(t *testing.T) {
	for _, code := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run("HTTP "+strconv.Itoa(code), func(t *testing.T) {
			server, attempts := countingServer(t,
				statusAnswer(code),
				rpcAnswer(t, okToolResult(t), nil))
			client := retryTestClient(t, server.URL, time.Millisecond)

			if _, err := client.CallTool(context.Background(), "iam_create_user", nil); err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if got := attempts.Load(); got != 2 {
				t.Errorf("attempts = %d, want 2", got)
			}
		})
	}

	t.Run("gives up after MaxRetries retries", func(t *testing.T) {
		server, attempts := countingServer(t, statusAnswer(http.StatusServiceUnavailable))
		client := retryTestClient(t, server.URL, time.Millisecond)

		_, err := client.CallTool(context.Background(), "iam_create_user", nil)

		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("err = %v, want HTTPStatusError with status 503", err)
		}
		if got := attempts.Load(); got != retryTestMaxRetries+1 {
			t.Errorf("attempts = %d, want %d", got, retryTestMaxRetries+1)
		}
	})
}

// TestClient_HonoursRetryAfter configures an hour between retries: the call
// finishes only because the server's Retry-After of zero seconds replaced it.
func TestClient_HonoursRetryAfter(t *testing.T) {
	server, attempts := countingServer(t,
		statusAnswer(http.StatusTooManyRequests, "Retry-After", "0"),
		rpcAnswer(t, okToolResult(t), nil))
	client := retryTestClient(t, server.URL, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.CallTool(ctx, "iam_create_user", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

// countingTransport counts the requests the client tries to send.
type countingTransport struct {
	sends atomic.Int32
	next  http.RoundTripper
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.sends.Add(1)
	return c.next.RoundTrip(req)
}

func TestClient_RetriesDialFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	client := retryTestClient(t, addr, time.Millisecond)
	transport := &countingTransport{next: http.DefaultTransport}
	client.httpClient.Transport = transport

	_, err = client.CallTool(context.Background(), "iam_create_user", nil)

	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Errorf("err = %v, want a dial error", err)
	}
	if got := transport.sends.Load(); got != retryTestMaxRetries+1 {
		t.Errorf("sends = %d, want %d", got, retryTestMaxRetries+1)
	}
}

func TestClient_CancelledContextStopsAtOnce(t *testing.T) {
	t.Run("cancelled before the call", func(t *testing.T) {
		server, attempts := countingServer(t, statusAnswer(http.StatusServiceUnavailable))
		client := retryTestClient(t, server.URL, time.Hour)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.CallTool(ctx, "iam_create_user", nil)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if got := attempts.Load(); got != 0 {
			t.Errorf("attempts = %d, want 0", got)
		}
	})

	t.Run("cancelled while the server asks for a retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server, attempts := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			cancel()
			statusAnswer(http.StatusServiceUnavailable)(w, r)
		})
		client := retryTestClient(t, server.URL, time.Hour)

		_, err := client.CallTool(ctx, "iam_create_user", nil)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if got := attempts.Load(); got != 1 {
			t.Errorf("attempts = %d, want 1", got)
		}
	})
}

// timeoutError is a net.Error that timed out.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestIsRetryable(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	live := context.Background()

	dialErr := &WrappedError{Msg: "request failed", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	readErr := &WrappedError{Msg: "request failed", Err: &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset")}}
	timeout := &WrappedError{Msg: "request failed", Err: timeoutError{}}

	tests := []struct {
		name   string
		ctx    context.Context
		method string
		err    error
		want   bool
	}{
		{"no error", live, "tools/call", nil, false},
		{"JSON-RPC error", live, "tools/call", &MCPError{Code: InternalError}, false},
		{"HTTP 400", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusBadRequest}, false},
		{"HTTP 401", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusUnauthorized}, false},
		{"HTTP 403", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusForbidden}, false},
		{"HTTP 404", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusNotFound}, false},
		{"HTTP 500", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusInternalServerError}, false},
		{"HTTP 429", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusTooManyRequests}, true},
		{"HTTP 502", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusBadGateway}, true},
		{"HTTP 503", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusServiceUnavailable}, true},
		{"HTTP 504", live, "tools/call", &HTTPStatusError{StatusCode: http.StatusGatewayTimeout}, true},
		{"dial failure", live, "tools/call", dialErr, true},
		{"connection reset after sending", live, "tools/call", readErr, false},
		{"timeout on a read", live, "tools/list", timeout, true},
		{"timeout on a client deadline for a read", live, "resources/read", context.DeadlineExceeded, true},
		{"timeout on a tool call", live, "tools/call", timeout, false},
		{"cancelled error", live, "ping", &WrappedError{Msg: "request failed", Err: context.Canceled}, false},
		{"caller context cancelled", cancelled, "ping", dialErr, false},
		{"unparseable answer", live, "ping", &WrappedError{Msg: "failed to parse response", Err: errors.New("bad json")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.ctx, tt.method, tt.err); got != tt.want {
				t.Errorf("IsRetryable = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{"seconds", "7", 7 * time.Second, true},
		{"zero seconds", "0", 0, true},
		{"HTTP date ahead", now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{"HTTP date passed", now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
		{"absent", "", 0, false},
		{"negative seconds", "-3", 0, false},
		{"seconds past the duration range", strconv.FormatInt(math.MaxInt64/int64(time.Second)+1, 10), 0, false},
		{"garbage", "soon", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", tt.value, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRetryAfterBackoff(t *testing.T) {
	backoff := &retryAfterBackoff{base: &quicbaas.ConstantBackoff{Delay: time.Hour}}

	backoff.observe(&HTTPStatusError{StatusCode: http.StatusTooManyRequests, RetryAfter: 2 * time.Second, HasRetryAfter: true})
	if got := backoff.Next(0); got != 2*time.Second {
		t.Errorf("Next after Retry-After = %v, want 2s", got)
	}
	if got := backoff.Next(1); got != time.Hour {
		t.Errorf("Next with the hint spent = %v, want the configured 1h", got)
	}

	backoff.observe(&HTTPStatusError{StatusCode: http.StatusServiceUnavailable})
	if got := backoff.Next(2); got != time.Hour {
		t.Errorf("Next without Retry-After = %v, want the configured 1h", got)
	}

	backoff.observe(&HTTPStatusError{StatusCode: http.StatusTooManyRequests, RetryAfter: time.Second, HasRetryAfter: true})
	backoff.observe(&WrappedError{Msg: "request failed", Err: errors.New("dial")})
	if got := backoff.Next(3); got != time.Hour {
		t.Errorf("Next after an error without a hint = %v, want the configured 1h", got)
	}
}

func TestHTTPStatusError(t *testing.T) {
	err := &HTTPStatusError{StatusCode: http.StatusForbidden}
	if got, want := err.Error(), "MCP server answered HTTP 403 Forbidden"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := err.Class().String(); got != "PermissionDenied" {
		t.Errorf("Class() = %s, want PermissionDenied", got)
	}
	if got := (&HTTPStatusError{StatusCode: http.StatusTeapot}).Class().String(); got != "Unknown" {
		t.Errorf("Class() of an unlisted status = %s, want Unknown", got)
	}
}

func TestNewHTTPStatusError(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	answer := func(code int, retryAfter string) *http.Response {
		header := http.Header{}
		header.Set("Retry-After", retryAfter)
		return &http.Response{StatusCode: code, Header: header}
	}

	busy := newHTTPStatusError(answer(http.StatusServiceUnavailable, "5"), now)
	if !busy.HasRetryAfter || busy.RetryAfter != 5*time.Second {
		t.Errorf("503 Retry-After = %v, %v; want 5s, true", busy.RetryAfter, busy.HasRetryAfter)
	}

	refused := newHTTPStatusError(answer(http.StatusForbidden, "5"), now)
	if refused.HasRetryAfter {
		t.Errorf("403 kept a Retry-After of %v; a refusal is not retried", refused.RetryAfter)
	}
}
