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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	// DefaultHTTPAddr is the loopback address platformd binds the
	// pre-unseal mux on.
	DefaultHTTPAddr = "127.0.0.1:9446"

	// UnixScheme prefixes an endpoint that names a Unix socket path.
	UnixScheme = "unix://"

	initPath = "/init"

	// unixBaseURL is the URL used over a Unix socket; the dialer ignores
	// the host.
	unixBaseURL = "http://platformd"

	// maxResponseBytes caps the /init reply (an admin bundle is ~2 KiB).
	maxResponseBytes = 1 << 20
)

// Client talks to the pre-unseal mux over a Unix socket or loopback HTTP.
type Client struct {
	http    *http.Client
	baseURL string
}

// NewClient returns a client for endpoint, which is either "unix://<path>"
// or a literal loopback "ip:port". Any other endpoint is refused: the mux is never
// reachable off-host, and the request carries the PINs in clear.
func NewClient(endpoint string) (*Client, error) {
	if path, ok := strings.CutPrefix(endpoint, UnixScheme); ok {
		if path == "" {
			return nil, &ErrInvalidEndpoint{Endpoint: endpoint, Reason: "empty socket path"}
		}
		dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", path)
		}
		return &Client{http: newHTTPClient(&http.Transport{DialContext: dial}), baseURL: unixBaseURL}, nil
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, &ErrInvalidEndpoint{Endpoint: endpoint, Reason: "want unix://<path> or host:port"}
	}
	if !isLoopback(host) {
		return nil, &ErrInvalidEndpoint{Endpoint: endpoint, Reason: "not a loopback address"}
	}
	// A zero Transport has no Proxy: the PINs must never go via a proxy.
	return &Client{http: newHTTPClient(&http.Transport{}), baseURL: "http://" + endpoint}, nil
}

// newHTTPClient returns an HTTP client over transport that never follows a
// redirect. The init request carries the PINs, and a redirect would resend
// them to wherever the Location header points — possibly off the host. The
// redirect response itself is returned, so Init reports it as ErrInitRejected.
func newHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// isLoopback accepts only a literal loopback IP. A name such as "localhost"
// is refused: it resolves through /etc/hosts and DNS, which need not map it
// to loopback, and the request carries the PINs in clear.
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Init sends POST /init. An identical retry of an init the daemon already
// completed returns the same admin bundle while the pre-unseal mux is up.
func (c *Client) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	if req == nil {
		req = &InitRequest{}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+initPath, bytes.NewReader(body))
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ErrInitRejected{StatusCode: resp.StatusCode, Message: errorMessage(data)}
	}
	var out InitResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	return &out, nil
}

// errorMessage extracts the {"error": "..."} message the mux returns, or
// "" when the body is not in that shape.
func errorMessage(data []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &body) != nil {
		return ""
	}
	return body.Error
}
