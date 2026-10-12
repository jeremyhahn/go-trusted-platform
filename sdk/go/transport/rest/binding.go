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

package rest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// defaultHTTPSPort is the port a bound call dials when the REST address
// names none, matching what net/http dials for an https URL.
const defaultHTTPSPort = "443"

// boundConnection is one TLS connection dedicated to one bound call, and
// the HTTP client that sends that call's request on it and nothing else.
type boundConnection struct {
	conn   *tls.Conn
	client *http.Client
	used   atomic.Bool
}

// dial hands the bound connection to the HTTP transport exactly once; a
// second dial would mean the request left on a connection its proof was
// not computed for, so it is refused.
func (b *boundConnection) dial(context.Context, string, string) (net.Conn, error) {
	if b.used.Swap(true) {
		return nil, &ErrBoundConnectionReused{}
	}
	return b.conn, nil
}

// release closes the connection if the HTTP transport never took it; once
// taken, the transport closes it after the response (keep-alives are off).
func (b *boundConnection) release() error {
	if b.used.Load() {
		return nil
	}
	return b.conn.Close()
}

// bindChannel opens a dedicated TLS 1.3 connection to the daemon, hands
// its channel binding to bind, and returns the connection with a one-shot
// HTTP client that sends the bound request on it. The daemon's REST
// handler reads the exporter from the connection that carries the
// request, so the proof bind computes here is the one it checks.
func (a *Adapter) bindChannel(ctx context.Context, bind transport.BindFunc) (*boundConnection, error) {
	if a.closed.Load() {
		return nil, ErrClientClosed{}
	}
	address, err := a.boundAddress()
	if err != nil {
		return nil, err
	}

	config := a.tlsConfig.Clone()
	// HTTP/1.1 only: the one-shot client writes the request itself on
	// this connection, which an HTTP/2 negotiation would not allow.
	config.NextProtos = []string{"http/1.1"}
	dialer := &tls.Dialer{Config: config}
	start := time.Now()
	conn, err := a.dialBound(ctx, dialer, address)
	if err != nil {
		if transport.IsTimeout(err) {
			err = platform.ErrTimeout{Operation: "REST bound dial", Elapsed: time.Since(start), Err: err}
		}
		return nil, &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolREST.String(),
			Reason:    "dialing " + address + " failed",
			Cause:     err,
		}
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolREST.String(),
			Reason:    "the dialed connection is not a TLS connection",
		}
	}

	state := tlsConn.ConnectionState()
	if err := transport.BindChannel(ctx, platform.ProtocolREST.String(), &state, bind); err != nil {
		if closeErr := tlsConn.Close(); closeErr != nil {
			return nil, &transport.ErrChannelBindingUnavailable{
				Transport: platform.ProtocolREST.String(),
				Reason:    "closing the unbound connection failed",
				Cause:     closeErr,
			}
		}
		return nil, err
	}

	bound := &boundConnection{conn: tlsConn}
	bound.client = &http.Client{
		Transport: &http.Transport{
			DialTLSContext:    bound.dial,
			DisableKeepAlives: true,
		},
		Timeout: a.httpClient.Timeout,
	}
	return bound, nil
}

// dialBound dials address and completes the TLS handshake within the
// adapter's timeout. A daemon that accepts TCP and never answers TLS would
// otherwise hold a call whose context has no deadline forever; a deadline
// on ctx that comes earlier still wins.
func (a *Adapter) dialBound(ctx context.Context, dialer *tls.Dialer, address string) (net.Conn, error) {
	if timeout := a.httpClient.Timeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return dialer.DialContext(ctx, "tcp", address)
}

// boundAddress returns the host:port a bound call dials. Only an https
// base URL can carry a channel binding.
func (a *Adapter) boundAddress() (string, error) {
	base, err := url.Parse(a.baseURL)
	if err != nil {
		return "", &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolREST.String(),
			Reason:    "the REST address is not a URL",
			Cause:     err,
		}
	}
	if base.Scheme != "https" {
		return "", &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolREST.String(),
			Reason:    "the REST address is not https, so there is no TLS connection to bind to",
		}
	}
	port := base.Port()
	if port == "" {
		port = defaultHTTPSPort
	}
	return net.JoinHostPort(base.Hostname(), port), nil
}

// ErrBoundConnectionReused is returned when the HTTP transport asks for a
// second connection during a bound call; the request may only travel on
// the connection its proof was computed for.
type ErrBoundConnectionReused struct{}

func (e *ErrBoundConnectionReused) Error() string {
	return "a bound REST call may only use the connection its proof was computed for"
}
