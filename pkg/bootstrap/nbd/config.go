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

package nbd

import (
	"crypto/tls"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// DefaultHandshakeTimeout bounds the negotiation phase of one connection.
const DefaultHandshakeTimeout = 30 * time.Second

// maxIdentityLength is the longest DNS name.
const maxIdentityLength = 253

// Config is the export server's configuration.
type Config struct {
	// Certificate is the server's TLS certificate.
	Certificate tls.Certificate
	// Anchor is the platform anchor every client certificate must chain to.
	Anchor *trust.Anchor
	// Identities are the hostnames of the diskless-nbd nodes this server
	// exports a volume for.
	Identities []string
	// VolumeDir holds one volume file per identity.
	VolumeDir string
	// VolumeSize is the size, in bytes, a volume is created at.
	VolumeSize int64
	// HandshakeTimeout bounds negotiation; zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Logger receives connection outcomes; nil means slog.Default().
	Logger *slog.Logger
}

// Validate reports the first field the server cannot run with.
func (c *Config) Validate() error {
	if len(c.Certificate.Certificate) == 0 || c.Certificate.PrivateKey == nil {
		return ErrInvalidConfig{Field: "Certificate", Reason: "a server certificate and key are required"}
	}
	if c.Anchor == nil {
		return ErrInvalidConfig{Field: "Anchor", Reason: "the platform anchor is required"}
	}
	if len(c.Identities) == 0 {
		return ErrInvalidConfig{Field: "Identities", Reason: "at least one diskless-nbd identity is required"}
	}
	for _, identity := range c.Identities {
		if !validIdentity(identity) {
			return ErrInvalidConfig{Field: "Identities", Reason: "not a DNS hostname: " + identity}
		}
	}
	if c.VolumeDir == "" {
		return ErrInvalidConfig{Field: "VolumeDir", Reason: "a volume directory is required"}
	}
	if c.VolumeSize <= 0 || c.VolumeSize%sectorSize != 0 {
		return ErrInvalidConfig{Field: "VolumeSize", Reason: "must be a positive multiple of 512 bytes"}
	}
	if c.HandshakeTimeout < 0 {
		return ErrInvalidConfig{Field: "HandshakeTimeout", Reason: "must not be negative"}
	}
	return nil
}

// validIdentity accepts a DNS hostname: dot-separated labels of letters,
// digits and hyphens, no label empty or starting or ending with a hyphen.
// That shape is what keeps an identity from naming a path outside the
// volume directory.
func validIdentity(identity string) bool {
	if identity == "" || len(identity) > maxIdentityLength {
		return false
	}
	for _, label := range strings.Split(identity, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isLetter && !isDigit && r != '-' {
			return false
		}
	}
	return true
}
