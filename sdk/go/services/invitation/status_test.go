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

package invitation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// errBodyRead is the failure the broken response body reports.
var errBodyRead = errors.New("connection reset mid-body")

// failingBody is a response body whose read always fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errBodyRead }
func (failingBody) Close() error             { return nil }

// statusTransport answers every request with a fixed status and body.
type statusTransport struct {
	status int
	body   io.ReadCloser
}

func (s statusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.status, Body: s.body, Header: http.Header{}}, nil
}

func newStatusClient(t *testing.T, status int, body io.ReadCloser) *Client {
	t.Helper()
	c, err := NewClient(&ClientConfig{
		Transport:   TransportREST,
		RESTBaseURL: "https://invitations.test/api/v1",
		HTTPClient:  &http.Client{Transport: statusTransport{status: status, body: body}},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestErrorStatus_UnreadableBodyIsReported proves a non-2xx response whose
// body cannot be read surfaces the read failure instead of a bare status.
func TestErrorStatus_UnreadableBodyIsReported(t *testing.T) {
	c := newStatusClient(t, http.StatusBadGateway, failingBody{})

	err := c.Revoke(context.Background(), 7)

	var readErr *ErrResponseReadFailed
	if !errors.As(err, &readErr) || readErr.StatusCode != http.StatusBadGateway || readErr.Operation != "revoke invitation" {
		t.Errorf("err = %v, want ErrResponseReadFailed for revoke invitation 502", err)
	}
	if !errors.Is(err, errBodyRead) {
		t.Errorf("err = %v, want it to wrap the body read failure", err)
	}
}

func TestErrorStatus_ServerMessageIsCarried(t *testing.T) {
	tests := map[string]struct {
		body string
		want string
	}{
		"error field":   {body: `{"error":"tenant is suspended"}`, want: "tenant is suspended"},
		"message field": {body: `{"message":"tenant is suspended"}`, want: "tenant is suspended"},
		"not json":      {body: "upstream down", want: ""},
	}
	for name, tt := range tests {
		c := newStatusClient(t, http.StatusConflict, io.NopCloser(strings.NewReader(tt.body)))

		_, err := c.List(context.Background())

		var statusErr *ErrUnexpectedStatus
		if !errors.As(err, &statusErr) {
			t.Fatalf("%s: err = %v, want ErrUnexpectedStatus", name, err)
		}
		if statusErr.StatusCode != http.StatusConflict || statusErr.Operation != "list invitations" || statusErr.Message != tt.want {
			t.Errorf("%s: err = %+v, want 409 list invitations carrying %q", name, statusErr, tt.want)
		}
	}
}

func TestStatusErrorMessages(t *testing.T) {
	tests := map[string]struct {
		err  error
		want string
	}{
		"with server message": {
			err:  &ErrUnexpectedStatus{Operation: "op", StatusCode: 409, Message: "busy"},
			want: "op failed: busy (status 409)",
		},
		"without server message": {
			err:  &ErrUnexpectedStatus{Operation: "op", StatusCode: 500},
			want: "op failed: status 500",
		},
		"unreadable body": {
			err:  &ErrResponseReadFailed{Operation: "op", StatusCode: 502, Cause: errBodyRead},
			want: "op failed: status 502, failed to read response body: connection reset mid-body",
		},
	}
	for name, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("%s: Error() = %q, want %q", name, got, tt.want)
		}
	}
}
