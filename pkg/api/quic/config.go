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

package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// ServerConfig contains configuration for the QUIC server
type ServerConfig struct {
	// ListenAddr is the address to listen on (e.g., "0.0.0.0:9444")
	ListenAddr string

	// TLSConfig is the TLS configuration for QUIC (TLS 1.3 required)
	TLSConfig *tls.Config

	// MaxStreams is the maximum number of concurrent streams per connection
	MaxStreams int

	// MaxIdleTimeout is the maximum idle timeout for connections
	MaxIdleTimeout time.Duration

	// MaxIncomingStreams limits incoming streams
	MaxIncomingStreams int64

	// MaxIncomingUniStreams limits incoming unidirectional streams
	MaxIncomingUniStreams int64

	// KeepAlivePeriod is the period for sending keep-alive pings
	KeepAlivePeriod time.Duration

	// HandshakeIdleTimeout is the timeout for completing the handshake
	HandshakeIdleTimeout time.Duration

	// MaxReceiveBufferSize is the maximum receive buffer size
	MaxReceiveBufferSize uint64

	// InitialStreamReceiveWindow is the initial stream receive window
	InitialStreamReceiveWindow uint64

	// MaxStreamReceiveWindow is the maximum stream receive window
	MaxStreamReceiveWindow uint64

	// EnableMetrics enables request/error metrics collection
	EnableMetrics bool
}

// DefaultServerConfig returns a ServerConfig with sensible defaults
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:                 tpconfig.DefaultDaemonListeners().QUIC.Address(),
		MaxStreams:                 1000,
		MaxIdleTimeout:             30 * time.Second,
		MaxIncomingStreams:         1000,
		MaxIncomingUniStreams:      100,
		KeepAlivePeriod:            15 * time.Second,
		HandshakeIdleTimeout:       5 * time.Second,
		MaxReceiveBufferSize:       1 * 1024 * 1024, // 1MB
		InitialStreamReceiveWindow: 512 * 1024,      // 512KB
		MaxStreamReceiveWindow:     6 * 1024 * 1024, // 6MB
		EnableMetrics:              true,
	}
}

// DefaultServerConfigWithTLS returns a ServerConfig with sensible defaults
// including a self-signed TLS configuration. This is suitable for development
// and testing. For production, use CA-signed certificates.
func DefaultServerConfigWithTLS() (*ServerConfig, error) {
	tlsConfig, err := GenerateSelfSignedTLSConfig()
	if err != nil {
		return nil, err
	}

	config := DefaultServerConfig()
	config.TLSConfig = tlsConfig
	return config, nil
}

// GenerateSelfSignedTLSConfig creates a self-signed TLS configuration for QUIC.
// This generates an ECDSA P-256 key pair and a self-signed certificate valid
// for 365 days. The certificate includes localhost and 127.0.0.1 as valid names.
//
// This function is suitable for development and testing environments.
// For production use, provide certificates signed by a trusted CA.
func GenerateSelfSignedTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrTLSConfigGeneration{Reason: "failed to generate ECDSA key", Err: err}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrTLSConfigGeneration{Reason: "failed to generate serial number", Err: err}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Trusted Platform"},
			CommonName:   "QUIC Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, ErrTLSConfigGeneration{Reason: "failed to create certificate", Err: err}
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicwire.ALPNProtocol},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Validate validates the server configuration
func (c *ServerConfig) Validate() error {
	if c.ListenAddr == "" {
		return quicwire.ErrInvalidConfig{Field: "ListenAddr", Reason: "cannot be empty"}
	}
	if c.TLSConfig == nil {
		return quicwire.ErrInvalidConfig{Field: "TLSConfig", Reason: "QUIC requires TLS configuration"}
	}
	// Enforce TLS 1.3 minimum
	if c.TLSConfig.MinVersion < tls.VersionTLS13 {
		c.TLSConfig.MinVersion = tls.VersionTLS13
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 1000
	}
	if c.MaxIdleTimeout <= 0 {
		c.MaxIdleTimeout = 30 * time.Second
	}
	return nil
}
