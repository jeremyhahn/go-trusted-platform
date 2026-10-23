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

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// maxResponseBytes bounds every admission listener response the agent reads.
const maxResponseBytes = 1 << 20

// defaultGatewayTimeout bounds one admission listener round trip.
const defaultGatewayTimeout = 30 * time.Second

// HTTPGateway is the client of a gateway's admission listener: HTTPS with the
// device's IDevID as the client certificate (docs/vpn/api.md §5).
type HTTPGateway struct {
	addr   string
	client *http.Client
}

// NewHTTPGateway returns a client for the admission listener at addr
// (host:port). The server must chain to roots; nil roots means the system
// pool. The server name verified is addr's host.
func NewHTTPGateway(addr string, cert tls.Certificate, roots *x509.CertPool) (*HTTPGateway, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, &ErrInvalidOptions{Field: "gateway", Reason: "want host:port, got " + strconv.Quote(addr)}
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, &ErrInvalidOptions{Field: "device certificate", Reason: "no certificate or key"}
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   host,
	}
	return &HTTPGateway{
		addr: addr,
		client: &http.Client{
			Timeout:   defaultGatewayTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true},
		},
	}, nil
}

// DialHTTPGateway is the GatewayDialer for the admission listener, verifying
// the gateway against roots.
func DialHTTPGateway(roots *x509.CertPool) GatewayDialer {
	return func(addr string, cert tls.Certificate) (Gateway, error) {
		return NewHTTPGateway(addr, cert, roots)
	}
}

// Challenge asks the gateway for a nonce and its data planes.
func (g *HTTPGateway) Challenge(ctx context.Context) (*gwvpn.ChallengeWire, error) {
	var challenge gwvpn.ChallengeWire
	if err := g.do(ctx, http.MethodPost, gwvpn.PathChallenges, nil, &challenge); err != nil {
		return nil, err
	}
	if len(challenge.Nonce) == 0 {
		return nil, &ErrInvalidResponse{Gateway: g.addr, Reason: "challenge carries no nonce"}
	}
	return &challenge, nil
}

// Admit presents the evidence and returns the lease.
func (g *HTTPGateway) Admit(ctx context.Context, req *gwvpn.AdmissionRequestWire) (*gwvpn.LeaseWire, error) {
	var lease gwvpn.LeaseWire
	if err := g.do(ctx, http.MethodPost, gwvpn.PathAdmissions, req, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

// Renew presents fresh evidence for lease id and returns the renewed lease.
func (g *HTTPGateway) Renew(ctx context.Context, id gwvpn.LeaseID, req *gwvpn.RenewalRequestWire) (*gwvpn.LeaseWire, error) {
	var lease gwvpn.LeaseWire
	if err := g.do(ctx, http.MethodPost, gwvpn.LeaseRenewPath(id), req, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

// Revoke ends lease id.
func (g *HTTPGateway) Revoke(ctx context.Context, id gwvpn.LeaseID) error {
	return g.do(ctx, http.MethodDelete, gwvpn.LeasePath(id), nil, nil)
}

// do sends body as JSON and decodes a 2xx response into out (when out is not
// nil); any other status is decoded as the gateway's refusal.
func (g *HTTPGateway) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return &ErrInvalidOptions{Field: "request", Reason: err.Error()}
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+g.addr+path, reader)
	if err != nil {
		return &ErrInvalidOptions{Field: "gateway", Reason: err.Error()}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return &ErrGatewayUnreachable{Gateway: g.addr, Cause: err}
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err := errors.Join(readErr, resp.Body.Close()); err != nil {
		return &ErrGatewayUnreachable{Gateway: g.addr, Cause: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return g.refusal(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &ErrInvalidResponse{Gateway: g.addr, Reason: err.Error()}
	}
	return nil
}

// refusal decodes a non-2xx body. A body that is not a refusal (a proxy's
// error page, say) is an invalid response, not a refusal class the agent
// would print as if the gateway had named it.
func (g *HTTPGateway) refusal(status int, raw []byte) error {
	var refusal gwvpn.RefusalWire
	if err := json.Unmarshal(raw, &refusal); err != nil || refusal.Reason == "" {
		return &ErrInvalidResponse{Gateway: g.addr, Reason: "status " + strconv.Itoa(status) + " without a refusal"}
	}
	return &RefusedError{Status: status, Class: refusal.Reason, Rules: refusal.Rules}
}
