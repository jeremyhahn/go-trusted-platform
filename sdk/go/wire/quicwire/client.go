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

package quicwire

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// Client is a QUIC client for the Trusted Platform
type Client struct {
	config     *ClientConfig
	conn       *quicgo.Conn
	logger     *slog.Logger
	ctx        context.Context
	cancelFunc context.CancelFunc

	mu        sync.RWMutex
	connected bool
	closed    bool

	// Authentication token
	token string
}

// ClientOption configures the QUIC client
type ClientOption func(*clientOptions)

type clientOptions struct {
	logger *slog.Logger
	token  string
}

// WithClientLogger sets a custom logger
func WithClientLogger(l *slog.Logger) ClientOption {
	return func(o *clientOptions) {
		o.logger = l
	}
}

// WithToken sets the authentication token
func WithToken(token string) ClientOption {
	return func(o *clientOptions) {
		o.token = token
	}
}

// NewClient creates a new QUIC client
func NewClient(config *ClientConfig, opts ...ClientOption) (*Client, error) {
	if config == nil {
		return nil, ErrInvalidConfig{Field: "config", Reason: "cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	options := &clientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.logger == nil {
		options.logger = slog.Default()
	}

	// Setup TLS configuration — TLS 1.3 minimum enforced, no insecure fallback.
	tlsConf := config.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{
			NextProtos: config.NextProtos,
			MinVersion: tls.VersionTLS13,
			RootCAs:    config.RootCAs, // nil → system roots
		}
	} else {
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = config.NextProtos
		}
		if tlsConf.MinVersion < tls.VersionTLS13 {
			tlsConf.MinVersion = tls.VersionTLS13
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		config:     config,
		logger:     options.logger,
		ctx:        ctx,
		cancelFunc: cancel,
		token:      options.token,
	}

	// Establish connection
	connCtx, connCancel := context.WithTimeout(ctx, config.Timeout)
	defer connCancel()

	quicConf := &quicgo.Config{
		MaxIdleTimeout:  config.MaxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, config.ServerAddr, tlsConf, quicConf)
	if err != nil {
		cancel()
		return nil, err
	}

	c.conn = conn
	c.connected = true

	c.logger.Debug("QUIC client connected", slog.String("server", config.ServerAddr))

	return c, nil
}

// Close closes the QUIC connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.connected = false
	c.cancelFunc()

	if c.conn != nil {
		err := c.conn.CloseWithError(0, "client closing")
		c.logger.Debug("QUIC client closed")
		return err
	}

	return nil
}

// SetToken sets the authentication token for requests
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// SendRequest sends a request and returns the response
func (c *Client) SendRequest(ctx context.Context, opcode byte, payload []byte) (*Response, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClientClosed
	}
	conn := c.conn
	token := c.token
	c.mu.RUnlock()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	req := &Request{
		Opcode:  opcode,
		Token:   token,
		Payload: payload,
	}

	if err := WriteRequest(stream, req); err != nil {
		return nil, err
	}

	resp, err := ReadResponse(stream)
	if err != nil {
		return nil, err
	}

	if resp.Status != StatusOK {
		return nil, StatusError(resp.Status, string(resp.Payload))
	}

	return resp, nil
}

// Send sends an encoded request and decodes the response
func (c *Client) Send(ctx context.Context, opcode byte, reqData, respData interface{}) error {
	var payload []byte
	var err error

	if reqData != nil {
		payload, err = EncodePayload(reqData)
		if err != nil {
			return err
		}
	}

	resp, err := c.SendRequest(ctx, opcode, payload)
	if err != nil {
		return err
	}

	if respData != nil {
		return DecodePayload(resp.Payload, respData)
	}

	return nil
}

// Health checks server health
func (c *Client) Health(ctx context.Context) error {
	_, err := c.SendRequest(ctx, OpHealth, nil)
	return err
}

// IsConnected returns true if the client is connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && !c.closed
}

// ServerAddr returns the server address
func (c *Client) ServerAddr() string {
	return c.config.ServerAddr
}
