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

package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// redfishTransport is the HTTP/JSON plumbing shared by Redfish-backed
// managers built in slices 3+ (AccountService, CertificateService, etc.).
//
// It intentionally duplicates a small amount of logic with the existing
// redfishClient.doGET/doPOST/doPATCH; a follow-up cleanup task will
// consolidate the two by having redfishClient embed *redfishTransport.
type redfishTransport struct {
	httpClient *http.Client
	baseURL    string
	username   string
	password   *memguard.MemoryEnclave
	logger     *slog.Logger
}

// redfishTransportOption adjusts the TLS configuration a transport connects
// with, for callers that need more than the TLSProvider's policy.
type redfishTransportOption func(*tls.Config)

// withPinnedPeer requires every connection the transport makes to present
// the same leaf certificate as the first one did.
//
// It is for conversations whose first exchange establishes who the peer is —
// the unauthenticated service-root read that identifies a BMC before it is
// authenticated to. Connection reuse is an optimisation, not a guarantee:
// a "Connection: close", a drained-body error or a pool eviction sends the
// next request down a fresh connection, which resolves and dials again. The
// pin is what makes the endpoint that was identified and the endpoint that
// receives the operator's credentials the same endpoint.
//
// The pin lives as long as the transport, which is one discovery.
func withPinnedPeer() redfishTransportOption {
	return func(cfg *tls.Config) {
		var pinned atomic.Pointer[[]byte]
		verify := cfg.VerifyConnection
		// VerifyConnection, not VerifyPeerCertificate: the latter is
		// skipped on a resumed session, which is exactly the connection a
		// pin has to hold for.
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if verify != nil {
				if err := verify(state); err != nil {
					return err
				}
			}
			if len(state.PeerCertificates) == 0 {
				return ErrPeerPinMismatch{}
			}
			leaf := state.PeerCertificates[0].Raw
			if pinned.CompareAndSwap(nil, &leaf) {
				return nil
			}
			if !bytes.Equal(*pinned.Load(), leaf) {
				return ErrPeerPinMismatch{}
			}
			return nil
		}
	}
}

// newRedfishTransport builds a transport from a *Config.
//
// password is taken from cfg.Password and wrapped into a memguard.MemoryEnclave
// owned by the transport. The cfg.Password string is not zeroed (Go
// strings cannot be), but no further references to it are kept here.
func newRedfishTransport(ctx context.Context, cfg *Config, logger *slog.Logger, opts ...redfishTransportOption) (*redfishTransport, error) {
	if cfg == nil {
		return nil, ErrNilConfig{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	providerConfig, err := BuildTLSConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// Clone before applying options: the TLSProvider may hand the same
	// *tls.Config to every caller, and one transport's options are not
	// another's.
	tlsConfig := providerConfig.Clone()
	for _, opt := range opts {
		opt(tlsConfig)
	}
	return &redfishTransport{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		baseURL:  fmt.Sprintf("https://%s:%d", cfg.Address, cfg.Port),
		username: cfg.Username,
		password: memguard.NewMemoryEnclaveFromString(cfg.Password),
		logger:   logger,
	}, nil
}

// HTTPClient returns the underlying HTTP client for paths that need
// raw request control (e.g., SMC CGI virtual media). Prefer doJSON
// for standard Redfish operations.
func (t *redfishTransport) HTTPClient() *http.Client {
	return t.httpClient
}

// BaseURL returns the base URL for raw request construction.
func (t *redfishTransport) BaseURL() string {
	return t.baseURL
}

// Close releases the transport's password material.
func (t *redfishTransport) Close() error {
	if t.password != nil {
		t.password.Destroy()
	}
	return nil
}

// applyAuth attaches HTTP Basic credentials to req. The password bytes
// are accessed only inside the WithBytes scope so the value lives in
// locked memory until http.Request.SetBasicAuth copies it into a header.
func (t *redfishTransport) applyAuth(req *http.Request) error {
	return t.password.Open(func(pw []byte) error {
		req.SetBasicAuth(t.username, string(pw))
		return nil
	})
}

// doRequest issues an authenticated HTTP request and returns the raw
// response. Caller closes resp.Body. body may be nil. Non-2xx responses
// are still returned (no error) so the caller can inspect the status.
func (t *redfishTransport) doRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, ErrRedfishRequest{Method: method, Path: path, Cause: err}
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.baseURL+path, reader)
	if err != nil {
		return nil, ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	if err := t.applyAuth(req); err != nil {
		return nil, ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	return resp, nil
}

// doJSON issues a request, decodes a JSON response into out (if non-nil),
// and translates non-2xx responses into a typed error. Returns the
// status code on success so callers can branch on 201 vs 204 etc.
func (t *redfishTransport) doJSON(ctx context.Context, method, path string, body, out any) (int, error) {
	resp, err := t.doRequest(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, parseRedfishError(resp, method, path)
	}
	if out != nil && resp.ContentLength != 0 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			// Empty body on 204 is fine; only error if body was expected.
			if err != io.EOF {
				return resp.StatusCode, ErrRedfishRequest{Method: method, Path: path, Cause: err}
			}
		}
	}
	return resp.StatusCode, nil
}

// peerCertificate performs a TLS handshake against host:port and returns
// the leaf certificate the server presented. Used by GetWebCertificate
// to read whatever cert the BMC is currently serving without going
// through Redfish (which doesn't expose the leaf cert directly).
func peerCertificate(ctx context.Context, host string, port int, tlsCfg *tls.Config) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), tlsCfg)
	if err != nil {
		return nil, ErrConnectionFailed{Address: host, Cause: err}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

// redfishServiceRootPath is the Redfish service root, the one resource
// DSP0266 requires a service to expose without authentication.
const redfishServiceRootPath = "/redfish/v1/"

// unauthenticatedServiceRoot fetches the Redfish service root over the
// transport's own connection and WITHOUT credentials.
//
// It is how a caller finds out whether an endpoint is a Redfish service
// before offering it the operator's BMC password. Callers that already know
// the endpoint is Redfish — because the operator configured it that way —
// have no reason to use it and go straight through doJSON.
func (t *redfishTransport) unauthenticatedServiceRoot(ctx context.Context) (*redfishServiceRoot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+redfishServiceRootPath, nil)
	if err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: redfishServiceRootPath, Cause: err}
	}
	// Identification must attest the endpoint that is about to be given the
	// operator's credentials, so this request does not follow redirects: a
	// service that answers the service root path with "look over there"
	// would otherwise be vouched for by whatever it points at. The redirect
	// arrives as a 3xx response and is rejected below. The transport, and
	// with it the connection, is shared with the authenticated walk.
	identify := *t.httpClient
	identify.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := identify.Do(req)
	if err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: redfishServiceRootPath, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, parseRedfishError(resp, http.MethodGet, redfishServiceRootPath)
	}

	var root redfishServiceRoot
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: redfishServiceRootPath, Cause: err}
	}
	// Drain whatever the decoder left so the connection goes back to the
	// pool and the authenticated walk reuses it.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.logger.Debug("bmc: draining Redfish service root response",
			slog.String("error", err.Error()))
	}

	if !isRedfishServiceRoot(&root) {
		return nil, ErrRedfishNotServiceRoot{Address: t.baseURL}
	}
	return &root, nil
}

// isRedfishServiceRoot reports whether root carries what DSP0266 requires of
// a ServiceRoot: its own @odata.id, the protocol version, and the Systems
// collection every later request depends on. Successful JSON alone proves
// nothing — a health endpoint answering "{}" on the same path is not a BMC,
// and must not be handed the operator's credentials.
func isRedfishServiceRoot(root *redfishServiceRoot) bool {
	if root.RedfishVersion == "" || root.Systems.ODataID == "" {
		return false
	}
	// Firmware writes the service root link both with and without the
	// trailing slash; both are the same resource.
	return strings.TrimSuffix(root.ODataID, "/") == strings.TrimSuffix(redfishServiceRootPath, "/")
}

// parseRedfishError decodes a Redfish-style error body into a typed
// error. Falls back to the raw body if the JSON shape doesn't match.
func parseRedfishError(resp *http.Response, method, path string) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRedfishRequest{
			Method: method, Path: path,
			StatusCode: resp.StatusCode, Message: resp.Status,
		}
	}
	var rerr redfishError
	if json.Unmarshal(body, &rerr) == nil && rerr.Error.Message != "" {
		msg := rerr.Error.Message
		// Append ExtendedInfo so Supermicro's generic "A general error has
		// occurred. See ExtendedInfo for more information." surfaces the
		// real cause + resolution.
		for _, ei := range rerr.Error.ExtendedInfo {
			if ei.Message != "" {
				msg += " [" + ei.MessageId + ": " + ei.Message
				if ei.Resolution != "" {
					msg += " (Resolution: " + ei.Resolution + ")"
				}
				msg += "]"
			}
		}
		return ErrRedfishRequest{
			Method: method, Path: path,
			StatusCode: resp.StatusCode, Message: msg,
		}
	}
	msg := string(body)
	if msg == "" {
		msg = resp.Status
	}
	return ErrRedfishRequest{
		Method: method, Path: path,
		StatusCode: resp.StatusCode, Message: msg,
	}
}
