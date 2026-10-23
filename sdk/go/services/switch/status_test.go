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

package switchsdk

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
	c, err := NewClient("https://switch.test", &http.Client{Transport: statusTransport{status: status, body: body}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestErrorStatus_UnreadableBodyIsReported proves a non-2xx response whose
// body cannot be read surfaces the read failure instead of an empty body.
func TestErrorStatus_UnreadableBodyIsReported(t *testing.T) {
	calls := map[string]func(*Client) error{
		"GET": func(c *Client) error {
			_, err := c.GetPortStatus(context.Background(), "sw1", "Eth1/1")
			return err
		},
		"POST": func(c *Client) error {
			return c.EnablePort(context.Background(), "sw1", "Eth1/1")
		},
	}
	for name, call := range calls {
		err := call(newStatusClient(t, http.StatusBadGateway, failingBody{}))

		var readErr ErrResponseReadFailed
		if !errors.As(err, &readErr) || readErr.StatusCode != http.StatusBadGateway {
			t.Errorf("%s: err = %v, want ErrResponseReadFailed for 502", name, err)
		}
		if !errors.Is(err, errBodyRead) {
			t.Errorf("%s: err = %v, want it to wrap the body read failure", name, err)
		}
	}
}

func TestErrorStatus_ReadableBodyIsCarried(t *testing.T) {
	c := newStatusClient(t, http.StatusConflict, io.NopCloser(strings.NewReader("port is locked")))

	err := c.DisablePort(context.Background(), "sw1", "Eth1/1")

	var statusErr ErrUnexpectedStatus
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusConflict || statusErr.Body != "port is locked" {
		t.Errorf("err = %v, want ErrUnexpectedStatus 409 carrying the body", err)
	}
}
