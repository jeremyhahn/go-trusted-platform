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

package quicbaas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// ErrCeremonyCANotAvailable indicates the ceremony CA backend (the platform
// CA injected via SetCA) has not been wired yet. This typically means the
// caller invoked a ceremony operation before App.LoadCA() / App.InitCA()
// completed.
type ErrCeremonyCANotAvailable struct{}

// Error implements the error interface.
func (ErrCeremonyCANotAvailable) Error() string {
	return "ceremony CA backend not available (platform CA has not been loaded yet)"
}

// CeremonyCAProvider is the lazy accessor the adapter consults on every
// call to fetch the live platform CA. It returns nil when the CA has not
// been wired yet so the adapter can surface a typed error instead of
// dereferencing a nil receiver.
type CeremonyCAProvider func() xkmssdk.TrustedCA

// CeremonyCAAdapter satisfies the qrdb-side ceremony.CeremonyCA contract by
// delegating each call to the platform's go-xkms TrustedCA. It resolves the
// underlying CA lazily through a CeremonyCAProvider so the qrdb embedded
// transport can be wired at SDK-construction time (before the platform CA
// is loaded) and start dispatching as soon as the CA becomes available.
//
// Thread-safe: the provider is read via atomic load on every call so
// SetProvider can be invoked concurrently with in-flight ceremony
// operations. The underlying TrustedCA is responsible for its own
// concurrency guarantees (the contract documents them as safe).
type CeremonyCAAdapter struct {
	provider atomic.Pointer[CeremonyCAProvider]
}

// Compile-time check that the adapter satisfies the qrdb interface.
var _ quicbaas.QRDBCeremonyCA = (*CeremonyCAAdapter)(nil)

// NewCeremonyCAAdapter constructs an adapter bound to the supplied provider.
// Passing a nil provider is allowed and yields ErrCeremonyCANotAvailable on
// every method call until SetProvider installs one.
func NewCeremonyCAAdapter(provider CeremonyCAProvider) *CeremonyCAAdapter {
	a := &CeremonyCAAdapter{}
	if provider != nil {
		a.provider.Store(&provider)
	}
	return a
}

// SetProvider atomically swaps the underlying CA provider. Calls in flight
// against the previous provider complete normally; calls made after the
// swap see the new provider. Passing nil clears the provider so subsequent
// calls return ErrCeremonyCANotAvailable.
func (a *CeremonyCAAdapter) SetProvider(provider CeremonyCAProvider) {
	if a == nil {
		return
	}
	if provider == nil {
		a.provider.Store(nil)
		return
	}
	a.provider.Store(&provider)
}

// resolve fetches the current TrustedCA from the provider, returning a
// typed error when the provider is unset or yields nil.
func (a *CeremonyCAAdapter) resolve() (xkmssdk.TrustedCA, error) {
	if a == nil {
		return nil, ErrCeremonyCANotAvailable{}
	}
	provPtr := a.provider.Load()
	if provPtr == nil {
		return nil, ErrCeremonyCANotAvailable{}
	}
	prov := *provPtr
	if prov == nil {
		return nil, ErrCeremonyCANotAvailable{}
	}
	ca := prov()
	if ca == nil {
		return nil, ErrCeremonyCANotAvailable{}
	}
	return ca, nil
}

// SignCSR delegates to the platform CA's SignCSR with options translated
// from the qrdb ceremony struct into the go-xkms equivalent.
func (a *CeremonyCAAdapter) SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaas.QRDBCeremonySignCSROptions) (*x509.Certificate, error) {
	ca, err := a.resolve()
	if err != nil {
		return nil, err
	}
	signOpts := translateSignCSROptions(opts)
	return ca.SignCSR(ctx, csrPEM, signOpts)
}

// CACertificate returns the platform CA's own certificate.
func (a *CeremonyCAAdapter) CACertificate() (*x509.Certificate, error) {
	ca, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return ca.CACertificate()
}

// CABundle returns the PEM-encoded CA certificate chain.
func (a *CeremonyCAAdapter) CABundle() ([]byte, error) {
	ca, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return ca.CABundle()
}

// IssueCertificate generates a new key pair and issues a certificate via the
// platform CA. The qrdb-side request is translated into a go-xkms
// CertificateRequest and the resulting IssuedCertificate is rendered back
// as the qrdb-side IssuedCert (cert/key PEM bytes plus parsed cert).
//
// The platform CA stores the generated key in its keystore as a side
// effect; the qrdb ceremony only needs the PEM bytes returned here so the
// share envelope it builds carries the private key out to the operator.
func (a *CeremonyCAAdapter) IssueCertificate(ctx context.Context, req *quicbaas.QRDBCeremonyIssueCertRequest) (*quicbaas.QRDBCeremonyIssuedCert, error) {
	ca, err := a.resolve()
	if err != nil {
		return nil, err
	}
	xkmsReq := translateIssueCertRequest(req)
	issued, err := ca.IssueCertificate(ctx, xkmsReq)
	if err != nil {
		return nil, err
	}
	out := &quicbaas.QRDBCeremonyIssuedCert{
		Certificate: issued.Certificate,
		CertPEM:     issued.CertificatePEM,
		KeyPEM:      issued.PrivateKeyPEM,
	}
	// Some keystore backends (TPM2 / PKCS11) intentionally withhold the
	// PEM key bytes so the key stays on the hardware boundary. The qrdb
	// ceremony tolerates a nil KeyPEM (it just won't deliver the key to
	// the operator); we do not synthesize one here.
	if out.CertPEM == nil && issued.Certificate != nil {
		out.CertPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: issued.Certificate.Raw,
		})
	}
	return out, nil
}

// translateSignCSROptions converts the qrdb ceremony SignCSROptions value
// into the go-xkms SignOptions counterpart. Returns nil when the input is
// nil so the CA falls back to its profile defaults.
//
// The ceremony's Profile names an officer role ("security-officer",
// "administrator", ...), not a profile in the platform CA's registry, which
// holds only the CA's own built-ins (server, client, ...). Forwarding the name
// makes the CA refuse every ceremony CSR as an unknown profile. The role is
// fully described by the key usage, extended key usage and validity the
// ceremony sends with it, so those are what the CA receives: with no profile
// named, it issues a leaf carrying exactly that usage.
func translateSignCSROptions(opts *quicbaas.QRDBCeremonySignCSROptions) *xkmsca.SignOptions {
	if opts == nil {
		return nil
	}
	return &xkmsca.SignOptions{
		ValidityDays: opts.ValidityDays,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}
}

// translateIssueCertRequest converts the qrdb ceremony IssueCertRequest
// into the go-xkms CertificateRequest. SANs are partitioned into DNS,
// email, IP and URI buckets using net.ParseIP and a literal-IP test so a
// caller can pass mixed-form SANs and have them routed correctly.
func translateIssueCertRequest(req *quicbaas.QRDBCeremonyIssueCertRequest) *xkmsca.CACertificateRequest {
	if req == nil {
		return nil
	}
	out := &xkmsca.CACertificateRequest{
		Subject: xkmsca.CASubject{
			CommonName: req.CommonName,
		},
		Valid:       req.ValidityDays,
		KeyUsage:    req.KeyUsage,
		ExtKeyUsage: req.ExtKeyUsage,
	}
	if len(req.SANs) > 0 {
		sans := &xkmsca.CASubjectAlternativeNames{}
		for _, s := range req.SANs {
			if ip := net.ParseIP(s); ip != nil {
				sans.IPs = append(sans.IPs, ip.String())
				continue
			}
			// Naïve email vs DNS split: presence of an '@' implies an
			// email SAN; everything else is treated as a DNS SAN. The
			// qrdb ceremony only emits hostnames and IPs in practice,
			// so this fallback is mostly defensive.
			if isEmailSAN(s) {
				sans.Email = append(sans.Email, s)
				continue
			}
			sans.DNS = append(sans.DNS, s)
		}
		out.SANS = sans
	}
	return out
}

// isEmailSAN reports whether s looks like an email SAN. It avoids importing
// net/mail to keep the dependency surface small — an '@' followed by any
// non-empty user/domain segment is a sufficient signal for the ceremony's
// fixed SAN set.
func isEmailSAN(s string) bool {
	at := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			at = i
			break
		}
	}
	return at > 0 && at < len(s)-1
}
