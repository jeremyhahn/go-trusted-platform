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

//go:build integration

// Package quic provides integration tests for the QUIC protocol handlers.
package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestClient is a QUIC test client for integration tests.
// It provides methods to send binary protocol requests to the QUIC server
// and parse responses for testing all service opcodes.
type TestClient struct {
	serverAddr string
	tlsConfig  *tls.Config
	token      string
	logger     *logging.Logger
	timeout    time.Duration

	mu     sync.RWMutex
	conn   *quicgo.Conn
	closed bool
}

// TestClientOption configures the test client
type TestClientOption func(*TestClient)

// WithTestClientLogger sets a custom logger for the test client.
func WithTestClientLogger(l *logging.Logger) TestClientOption {
	return func(c *TestClient) {
		c.logger = l
	}
}

// WithTestClientToken sets the authentication token.
func WithTestClientToken(token string) TestClientOption {
	return func(c *TestClient) {
		c.token = token
	}
}

// WithTestClientTimeout sets the connection/request timeout.
func WithTestClientTimeout(timeout time.Duration) TestClientOption {
	return func(c *TestClient) {
		c.timeout = timeout
	}
}

// WithTestClientTLSConfig sets a custom TLS configuration.
func WithTestClientTLSConfig(cfg *tls.Config) TestClientOption {
	return func(c *TestClient) {
		c.tlsConfig = cfg
	}
}

// NewTestClient creates a new QUIC test client for integration tests.
// serverAddr should be in the form "host:port" (e.g., "localhost:9444").
func NewTestClient(serverAddr string, opts ...TestClientOption) *TestClient {
	c := &TestClient{
		serverAddr: serverAddr,
		timeout:    30 * time.Second,
		logger:     logging.DefaultLogger(),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.tlsConfig == nil {
		c.tlsConfig = helpers.QUICTLSConfig([]string{"platform-quic"})
	}

	return c
}

// NewTestClientWithCerts creates a test client with certificate-based TLS.
func NewTestClientWithCerts(serverAddr, certFile, keyFile, caFile string, opts ...TestClientOption) (*TestClient, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, ErrTestSetupFailed{Component: "client certificate", Cause: err}
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, ErrTestSetupFailed{Component: "CA certificate", Cause: err}
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, ErrTestSetupFailed{Component: "CA certificate pool", Cause: err}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		NextProtos:   []string{"platform-quic"},
		MinVersion:   tls.VersionTLS13,
	}

	c := NewTestClient(serverAddr, opts...)
	c.tlsConfig = tlsConfig

	return c, nil
}

// Connect establishes a connection to the QUIC server.
func (c *TestClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil && !c.closed {
		return nil
	}

	connCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, c.serverAddr, c.tlsConfig, quicConfig)
	if err != nil {
		return ErrConnectionFailed{Address: c.serverAddr, Cause: err}
	}

	c.conn = conn
	c.closed = false
	c.logger.Debug("Test client connected to %s", c.serverAddr)

	return nil
}

// Close closes the QUIC connection.
func (c *TestClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.conn == nil {
		return nil
	}

	c.closed = true
	err := c.conn.CloseWithError(0, "test client closing")
	c.conn = nil
	c.logger.Debug("Test client disconnected")

	return err
}

// SetToken sets the authentication token for subsequent requests.
func (c *TestClient) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// SendRequest sends a raw QUIC request and returns the response.
func (c *TestClient) SendRequest(ctx context.Context, opcode byte, payload []byte) (*quic.Response, error) {
	c.mu.RLock()
	if c.closed || c.conn == nil {
		c.mu.RUnlock()
		return nil, ErrConnectionFailed{Address: c.serverAddr, Cause: quic.ErrClientClosed}
	}
	conn := c.conn
	token := c.token
	c.mu.RUnlock()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrRequestFailed{Opcode: opcode, Cause: err}
	}
	defer stream.Close()

	req := &quic.Request{
		Opcode:  opcode,
		Token:   token,
		Payload: payload,
	}

	if err := quic.WriteRequest(stream, req); err != nil {
		return nil, ErrRequestFailed{Opcode: opcode, Cause: err}
	}

	resp, err := quic.ReadResponse(stream)
	if err != nil {
		return nil, ErrRequestFailed{Opcode: opcode, Cause: err}
	}

	return resp, nil
}

// Send encodes the request, sends it, and decodes the response.
func (c *TestClient) Send(ctx context.Context, opcode byte, reqData, respData interface{}) error {
	var payload []byte
	var err error

	if reqData != nil {
		payload, err = quic.EncodePayload(reqData)
		if err != nil {
			return ErrEncodeFailed{Cause: err}
		}
	}

	resp, err := c.SendRequest(ctx, opcode, payload)
	if err != nil {
		return err
	}

	if resp.Status != quic.StatusOK {
		return ErrUnexpectedStatus{
			Expected: quic.StatusOK,
			Actual:   resp.Status,
			Message:  string(resp.Payload),
		}
	}

	if respData != nil && len(resp.Payload) > 0 {
		if err := quic.DecodePayload(resp.Payload, respData); err != nil {
			return ErrDecodeFailed{Cause: err}
		}
	}

	return nil
}

// SendExpectStatus sends a request and expects a specific status code.
func (c *TestClient) SendExpectStatus(ctx context.Context, opcode byte, reqData interface{}, expectedStatus byte) (*quic.Response, error) {
	var payload []byte
	var err error

	if reqData != nil {
		payload, err = quic.EncodePayload(reqData)
		if err != nil {
			return nil, ErrEncodeFailed{Cause: err}
		}
	}

	resp, err := c.SendRequest(ctx, opcode, payload)
	if err != nil {
		return nil, err
	}

	if resp.Status != expectedStatus {
		return resp, ErrUnexpectedStatus{
			Expected: expectedStatus,
			Actual:   resp.Status,
			Message:  string(resp.Payload),
		}
	}

	return resp, nil
}

// IsConnected returns true if the client is connected.
func (c *TestClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.closed && c.conn != nil
}

// ServerAddr returns the server address.
func (c *TestClient) ServerAddr() string {
	return c.serverAddr
}

// Health sends a health check request.
func (c *TestClient) Health(ctx context.Context) error {
	_, err := c.SendRequest(ctx, quic.OpHealth, nil)
	return err
}

// Liveness sends a liveness probe request.
func (c *TestClient) Liveness(ctx context.Context) error {
	_, err := c.SendRequest(ctx, quic.OpLiveness, nil)
	return err
}

// Readiness sends a readiness probe request.
func (c *TestClient) Readiness(ctx context.Context) error {
	_, err := c.SendRequest(ctx, quic.OpReadiness, nil)
	return err
}
