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

package trust

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// AnchorSource supplies the certificates of the platform's own certificate
// authority: the CA certificates every platform-issued certificate chains to.
//
// Each node type has exactly one source. The control plane's is its own CA;
// an enrolled node's is the issuing chain of its IDevID, persisted at
// enrollment; a node that runs no CA of its own (gatewayd) reads the bundle
// provisioning places on it (FileAnchorSource).
type AnchorSource interface {
	AnchorCertificates(ctx context.Context) ([]*x509.Certificate, error)
}

// AnchorSourceFunc adapts a function to AnchorSource.
type AnchorSourceFunc func(ctx context.Context) ([]*x509.Certificate, error)

// AnchorCertificates implements AnchorSource.
func (f AnchorSourceFunc) AnchorCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	return f(ctx)
}

// Anchor is the platform's own certificate authority as a verification
// anchor. Every platform service that verifies another platform service —
// attestation collection, caller admission, heartbeat, provisioning, the
// gateway's control-plane reporter, proxy backends that are platform
// services — verifies against it.
//
// It is deliberately not configurable: a platform-issued certificate chains
// to the platform CA and to nothing else, so there is no second answer an
// operator could choose. The source is read on every call rather than
// cached, so a rotated CA or a node that enrolls after start-up takes effect
// on the next verification instead of at the next restart.
type Anchor struct {
	source AnchorSource
}

// NewAnchor returns the Anchor fed by source.
func NewAnchor(source AnchorSource) (*Anchor, error) {
	if source == nil {
		return nil, ErrNilAnchorSource{}
	}
	return &Anchor{source: source}, nil
}

// Certificates returns the anchor's CA certificates. Certificates that are
// not CA certificates are dropped: a leaf in a provisioned bundle is not a
// trust anchor. Returns *ErrAnchorUnavailable when the source cannot answer
// and ErrAnchorEmpty when it answers with no CA certificate.
func (a *Anchor) Certificates(ctx context.Context) ([]*x509.Certificate, error) {
	certs, err := a.source.AnchorCertificates(ctx)
	if err != nil {
		return nil, &ErrAnchorUnavailable{Cause: err}
	}
	anchors := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if cert != nil && cert.IsCA {
			anchors = append(anchors, cert)
		}
	}
	if len(anchors) == 0 {
		return nil, ErrAnchorEmpty{}
	}
	return anchors, nil
}

// CAPool returns a certificate pool holding the anchor's CA certificates.
func (a *Anchor) CAPool(ctx context.Context) (*x509.CertPool, error) {
	certs, err := a.Certificates(ctx)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

// TLSConfig returns a client *tls.Config that verifies the server against
// the anchor. ServerName is left to the caller's transport, which derives it
// from the URL it dials.
func (a *Anchor) TLSConfig(ctx context.Context) (*tls.Config, error) {
	pool, err := a.CAPool(ctx)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// FileAnchorSource reads the platform CA bundle from a PEM file: the source
// for a node that runs no CA of its own, such as gatewayd, whose bundle the
// provisioning flow projects onto the node.
//
// The file is read on every call, so a rotated bundle takes effect on the
// next verification, and a verification that happens before the bundle is
// delivered reports the missing path instead of an empty pool.
type FileAnchorSource struct {
	path string
}

// Compile-time interface check.
var _ AnchorSource = (*FileAnchorSource)(nil)

// NewFileAnchorSource returns an AnchorSource reading the PEM bundle at path.
func NewFileAnchorSource(path string) *FileAnchorSource {
	return &FileAnchorSource{path: path}
}

// Path returns the configured bundle path.
func (s *FileAnchorSource) Path() string { return s.path }

// AnchorCertificates implements AnchorSource.
func (s *FileAnchorSource) AnchorCertificates(_ context.Context) ([]*x509.Certificate, error) {
	if s.path == "" {
		return nil, ErrAnchorFileUnset{}
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, &ErrCAFileRead{Path: s.path, Err: err}
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCABundleParse{}
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
