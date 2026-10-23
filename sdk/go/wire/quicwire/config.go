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
	"crypto/tls"
	"crypto/x509"
	"time"
)

// ALPNProtocol is the single ALPN protocol name the platform QUIC listener
// negotiates. A client offering any other name fails the TLS handshake with
// no_application_protocol before a stream is opened, which is a connection
// error rather than a protocol error and is easy to misread as "the daemon
// is down". Both the server TLS config and the client config below derive
// from this constant so the two cannot drift; callers outside this package
// should reference it rather than repeating the string (#480).
const ALPNProtocol = "platform-quic"

// ClientConfig contains configuration for the QUIC client.
// TLS 1.3 with certificate verification is always enforced.
type ClientConfig struct {
	// ServerAddr is the address of the QUIC server
	ServerAddr string

	// TLSConfig is the TLS configuration. When non-nil it is used as-is
	// (with TLS 1.3 minimum and NextProtos filled in if absent). When nil,
	// a minimal tls.Config is built from NextProtos and RootCAs.
	TLSConfig *tls.Config

	// RootCAs anchors the fallback TLS configuration to the given pool
	// instead of the operating-system trust store. Ignored when TLSConfig
	// is non-nil (the caller's TLS config is used as-is). Set to nil to
	// preserve existing system-roots behavior.
	RootCAs *x509.CertPool

	// Timeout is the connection timeout
	Timeout time.Duration

	// MaxIdleTimeout is the maximum idle timeout for the connection
	MaxIdleTimeout time.Duration

	// NextProtos is the list of ALPN protocols
	NextProtos []string
}

// DefaultClientConfig returns a ClientConfig with sensible defaults
func DefaultClientConfig(serverAddr string) *ClientConfig {
	return &ClientConfig{
		ServerAddr:     serverAddr,
		Timeout:        10 * time.Second,
		MaxIdleTimeout: 30 * time.Second,
		NextProtos:     []string{ALPNProtocol},
	}
}

// Validate validates the client configuration
func (c *ClientConfig) Validate() error {
	if c.ServerAddr == "" {
		return ErrInvalidConfig{Field: "ServerAddr", Reason: "cannot be empty"}
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	// Enforce TLS 1.3 minimum when TLS config is provided
	if c.TLSConfig != nil && c.TLSConfig.MinVersion < tls.VersionTLS13 {
		c.TLSConfig.MinVersion = tls.VersionTLS13
	}
	return nil
}
