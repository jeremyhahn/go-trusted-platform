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

package ipsec

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
)

// TunnelIdentity is what charon needs to authenticate this node: the
// tunnel certificate and its chain, and the token key that signs for it.
type TunnelIdentity struct {
	// Chain is the tunnel certificate, then the CA certificates peer
	// certificates chain to: the tunnel intermediate and the root, which
	// must come last.
	Chain []*x509.Certificate
	// Token locates the IKE key.
	Token TokenKey
	// PIN logs in to the token; nil when the token needs none. It is
	// owned by the provider.
	PIN *secure.Secret
}

// IdentityProvider supplies the tunnel identity. The controller asks for
// it on every attach, so a renewed certificate is loaded by the next one.
type IdentityProvider interface {
	TunnelIdentity(ctx context.Context) (*TunnelIdentity, error)
}

// validate checks the identity can authenticate local: a certificate whose
// IP subject alternative names include local, a key to sign with, and a
// chain that ends in its root. Every CA a pushed CRL may come from is then
// in the chain, the root included.
func (id *TunnelIdentity) validate(local netip.Addr) error {
	if id == nil || len(id.Chain) == 0 || id.Chain[0] == nil {
		return ErrNoCertificate
	}
	if len(id.Token.KeyID) == 0 {
		return ErrNoKeyID
	}
	if !slices.ContainsFunc(id.Chain[0].IPAddresses, func(ip net.IP) bool {
		addr, ok := netip.AddrFromSlice(ip)
		return ok && addr.Unmap() == local
	}) {
		return ErrCertificateAddress
	}
	if len(id.Chain) < 2 || !isRoot(id.Chain[len(id.Chain)-1]) {
		return ErrNoRoot
	}
	return nil
}

// isRoot reports whether cert is a self-signed CA certificate.
func isRoot(cert *x509.Certificate) bool {
	return cert != nil && bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
}

// FileIdentity is the IdentityProvider of the overlay.ipsec section: the
// chain from certificate-file, the key from token, and the PIN from
// token.pin-file. The chain is read on every call, so a certificate
// replaced on disk is loaded at the next attach; the PIN is read once,
// into an enclave.
type FileIdentity struct {
	chainFile string
	key       TokenKey
	pin       *secure.Secret
}

// NewFileIdentity builds the provider for an enabled section that names a
// certificate file. Close releases the PIN.
func NewFileIdentity(cfg *Config) (*FileIdentity, error) {
	if _, err := enabledLocal(cfg); err != nil {
		return nil, err
	}
	if cfg.CertificateFile == "" {
		return nil, &ConfigError{Field: "certificate-file", Err: ErrRequired}
	}
	keyID, err := hex.DecodeString(cfg.Token.Handle)
	if err != nil {
		return nil, &ConfigError{Field: "token.handle", Err: ErrInvalidHandle}
	}
	f := &FileIdentity{
		chainFile: cfg.CertificateFile,
		key:       TokenKey{Module: cfg.EffectiveTokenModule(), Slot: cfg.Token.Slot, KeyID: keyID},
	}
	if cfg.Token.PINFile != "" {
		if f.pin, err = readPIN(cfg.Token.PINFile); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// readPIN seals the first line of path into an enclave and wipes what it
// read.
func readPIN(path string) (*secure.Secret, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{Field: "token.pin-file", Err: err}
	}
	defer secure.Wipe(raw)
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) == 0 {
		return nil, &ConfigError{Field: "token.pin-file", Err: ErrRequired}
	}
	pin, err := secure.NewSecret(line)
	if err != nil {
		return nil, &ConfigError{Field: "token.pin-file", Err: err}
	}
	return pin, nil
}

// TunnelIdentity reads the chain and returns the identity.
func (f *FileIdentity) TunnelIdentity(_ context.Context) (*TunnelIdentity, error) {
	chain, err := readChain(f.chainFile)
	if err != nil {
		return nil, err
	}
	return &TunnelIdentity{Chain: chain, Token: f.key, PIN: f.pin}, nil
}

// Close destroys the PIN.
func (f *FileIdentity) Close() {
	if f.pin != nil {
		f.pin.Destroy()
	}
}

// readChain parses the PEM certificates in path, in file order.
func readChain(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{Field: "certificate-file", Err: err}
	}
	var chain []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &ConfigError{Field: "certificate-file", Err: err}
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, &ConfigError{Field: "certificate-file", Err: ErrNoCertificate}
	}
	return chain, nil
}

// CertificateStatus is the renewal state of the loaded tunnel certificate.
// Renewal is due at half its lifetime and an alert is raised at three
// quarters, so a node that misses renewals is seen well before expiry.
type CertificateStatus struct {
	// Serial is the certificate serial number in hex.
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	// TimeToExpiry is NotAfter less now; negative once expired.
	TimeToExpiry time.Duration
	// RenewAt is the half-lifetime mark; RenewalDue is set from it on.
	RenewAt    time.Time
	RenewalDue bool
	// AlertAt is the three-quarter mark; Alert is set from it on.
	AlertAt time.Time
	Alert   bool
}

// certificateStatus computes cert's renewal state at now.
func certificateStatus(cert *x509.Certificate, now time.Time) *CertificateStatus {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewAt := cert.NotBefore.Add(lifetime / 2)
	alertAt := cert.NotAfter.Add(-lifetime / 4)
	return &CertificateStatus{
		Serial:       cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		TimeToExpiry: cert.NotAfter.Sub(now),
		RenewAt:      renewAt,
		RenewalDue:   !now.Before(renewAt),
		AlertAt:      alertAt,
		Alert:        !now.Before(alertAt),
	}
}
