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
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// idempotentMethods are the MCP methods that only read: sending one twice
// has the effect of sending it once. tools/call is not listed because the
// client cannot tell a tool that reads from one that changes state.
var idempotentMethods = map[string]bool{
	"initialize":     true,
	"ping":           true,
	"tools/list":     true,
	"resources/list": true,
	"resources/read": true,
}

// retryableStatus are the HTTP answers in which the server, or a proxy in
// front of it, says it did not run the request and asks for another try.
var retryableStatus = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusBadGateway:         true,
	http.StatusServiceUnavailable: true,
	http.StatusGatewayTimeout:     true,
}

// IsRetryable reports whether a failed MCP request may be sent again.
//
// A request is retried only when it provably never reached the server, or
// the server asked for a retry: a dial failure, a 429, 502, 503 or 504, or a
// timeout on a method that only reads. Anything else may have been applied
// by the server, and sending a state-changing call twice can apply it twice;
// an answer the server gave on purpose (a JSON-RPC error, a refusal, any
// other 4xx) is the same answer on every try. A cancelled or expired caller
// context ends the call.
func IsRetryable(ctx context.Context, method string, err error) bool {
	if err == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return false
	}

	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return retryableStatus[statusErr.StatusCode]
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}

	if isTimeout(err) {
		return idempotentMethods[method]
	}
	return false
}

// isTimeout reports whether err is a request that ran out of time, which
// says nothing about whether the server received it.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// retryAfterBackoff waits as long as the last answer's Retry-After asked
// for, and otherwise as long as the configured backoff. It belongs to one
// call: each attempt records its error with observe before the retry loop
// asks Next for the wait.
type retryAfterBackoff struct {
	base   quicbaas.Backoff
	wait   time.Duration
	hinted bool
}

// observe takes the Retry-After of an HTTP status error for the next wait.
func (b *retryAfterBackoff) observe(err error) {
	var statusErr *HTTPStatusError
	b.hinted = errors.As(err, &statusErr) && statusErr.HasRetryAfter
	if b.hinted {
		b.wait = statusErr.RetryAfter
	}
}

// Next returns the server's requested wait when the last answer carried
// one, and the configured backoff otherwise.
func (b *retryAfterBackoff) Next(attempt int) time.Duration {
	if b.hinted {
		b.hinted = false
		return b.wait
	}
	return b.base.Next(attempt)
}

// parseRetryAfter reads a Retry-After header (RFC 9110 §10.2.3): a number
// of seconds or an HTTP date. A date in the past is a wait of zero; an
// empty or unreadable value is no hint.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 || time.Duration(seconds) > math.MaxInt64/time.Second {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(at.Sub(now), 0), true
}

// newHTTPStatusError builds the error for a non-2xx answer, keeping the
// Retry-After hint of an answer that asks for a retry.
func newHTTPStatusError(resp *http.Response, now time.Time) *HTTPStatusError {
	statusErr := &HTTPStatusError{StatusCode: resp.StatusCode}
	if retryableStatus[resp.StatusCode] {
		statusErr.RetryAfter, statusErr.HasRetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), now)
	}
	return statusErr
}
