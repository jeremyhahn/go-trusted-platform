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

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// NoneProvider implements no authentication.
// This is useful for testing or local Unix socket connections where
// the transport itself provides security (e.g., file permissions).
type NoneProvider struct {
	tlsConfig *tls.Config
}

// NoneOption configures a NoneProvider.
type NoneOption func(*NoneProvider)

// WithNoneTLSConfig sets a minimal TLS configuration.
// This is useful when TLS is required but not client authentication.
func WithNoneTLSConfig(config *tls.Config) NoneOption {
	return func(p *NoneProvider) {
		p.tlsConfig = config
	}
}

// WithMinimalTLS configures minimal TLS (TLS 1.3, no client cert).
func WithMinimalTLS() NoneOption {
	return func(p *NoneProvider) {
		p.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
}

// WithTLSFromCA creates a TLS configuration with a CA certificate pool
// from the provided PEM data, enforcing TLS 1.3 minimum. This replaces
// the insecure skip verify pattern with proper CA-based verification.
func WithTLSFromCA(caPEM []byte) NoneOption {
	return func(p *NoneProvider) {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			p.tlsConfig = &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			}
		}
	}
}

// NewNoneProvider creates a new no-authentication provider.
func NewNoneProvider(opts ...NoneOption) *NoneProvider {
	p := &NoneProvider{}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// GetToken returns an empty string since no authentication is used.
// This does not return an error to allow unauthenticated requests.
func (p *NoneProvider) GetToken(ctx context.Context) (string, error) {
	return "", nil
}

// GetTLSConfig returns the TLS configuration.
// Returns nil if no TLS is configured.
func (p *NoneProvider) GetTLSConfig() *tls.Config {
	return p.tlsConfig
}

// Refresh is a no-op for NoneProvider.
// Returns nil since there's nothing to refresh.
func (p *NoneProvider) Refresh(ctx context.Context) error {
	return nil
}

// IsExpired always returns false since there are no credentials.
func (p *NoneProvider) IsExpired() bool {
	return false
}

// Type returns AuthTypeNone.
func (p *NoneProvider) Type() AuthType {
	return AuthTypeNone
}

// Ensure NoneProvider implements Provider interface.
var _ Provider = (*NoneProvider)(nil)
