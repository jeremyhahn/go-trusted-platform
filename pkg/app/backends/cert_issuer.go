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

package backends

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// ErrCertRequestNil indicates IssueCertificate was called without a request.
type ErrCertRequestNil struct{}

// Error returns a human-readable description.
func (e *ErrCertRequestNil) Error() string {
	return "certificate issuer: request is nil"
}

// ErrCertIssue indicates the platform CA could not issue a certificate.
type ErrCertIssue struct {
	// Usage is the requested certificate usage ("client" or "server").
	Usage string
	Cause error
}

// Error returns a human-readable description.
func (e *ErrCertIssue) Error() string {
	return "certificate issuer: issue " + e.Usage + " certificate: " + e.Cause.Error()
}

// Unwrap returns the underlying failure.
func (e *ErrCertIssue) Unwrap() error {
	return e.Cause
}

// CertIssuer is the certificate surface the daemon mints the admin client
// certificate through, with the CA bundle that trusts it. The daemon's TLS
// server certificate is not issued here: its key is generated in, and never
// leaves, the platform CA keystore (#33).
type CertIssuer interface {
	IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error)
	GetCABundle(ctx context.Context, req *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error)
}

// PlatformCertIssuer selects the issuer for daemon-minted identities: the
// in-process platform CA when it is loaded, otherwise the SDK Certificate
// service. The embedded transport does not register a Certificate service,
// so the local CA keeps the /init admin bundle working there. Returns nil when neither is available.
func PlatformCertIssuer(ca quicbaasca.CACertificateAuthority, client quicbaassdk.Client) CertIssuer {
	if ca != nil {
		return &localCACertIssuer{ca: ca}
	}
	if client != nil {
		return &sdkCertIssuer{client: client}
	}
	return nil
}

// AdminCertificateRequest is the request for the platform's root admin
// client certificate. The /init admin bundle and the integration harness
// bundle share it so both paths mint the same identity.
func AdminCertificateRequest() *certclient.IssueCertificateRequest {
	return &certclient.IssueCertificateRequest{
		CommonName:   common.AdminUsername,
		Organization: "Trusted Platform",
		Usage:        "client",
		KeyAlgorithm: "ecdsa",
		ValidityDays: 365,
	}
}

// ErrAdminIdentityIncomplete is returned when the admin bundle is requested
// without the trust domain or tenant its SPIFFE identity is built from.
type ErrAdminIdentityIncomplete struct {
	// Field names the missing part: "trust domain" or "tenant".
	Field string
}

// Error implements the error interface.
func (e *ErrAdminIdentityIncomplete) Error() string {
	return "admin bundle: the system-admin SPIFFE identity has no " + e.Field
}

// AdminIdentity is the tenant-scoped SPIFFE identity the system admin
// certificate is issued for. The CA synthesizes the URI SAN
// spiffe://<TrustDomain>/tenant/<TenantID>/user/<common.AdminUsername> from
// it; admin-claim refuses an admin certificate that does not carry it.
type AdminIdentity struct {
	// TrustDomain is the operator-configured SPIFFE trust domain
	// (quicbaas.spiffe-trust-domain).
	TrustDomain string
	// TenantID is the tenant the system admin belongs to.
	TenantID string
}

func (id AdminIdentity) validate() error {
	if id.TrustDomain == "" {
		return &ErrAdminIdentityIncomplete{Field: "trust domain"}
	}
	if id.TenantID == "" {
		return &ErrAdminIdentityIncomplete{Field: "tenant"}
	}
	return nil
}

// NewAdminBundleIssuer wraps issuer for ceremony init. Returns nil when
// issuer is nil so the ceremony backend rejects init with its typed error
// instead of panicking.
func NewAdminBundleIssuer(issuer CertIssuer, identity AdminIdentity) AdminBundleIssuer {
	if issuer == nil {
		return nil
	}
	return &adminBundleIssuer{issuer: issuer, identity: identity}
}

// adminBundleIssuer mints the admin bundle through a CertIssuer.
type adminBundleIssuer struct {
	issuer   CertIssuer
	identity AdminIdentity
}

// IssueAdminBundle issues the admin client certificate and key, carrying the
// system-admin SPIFFE identity.
func (a *adminBundleIssuer) IssueAdminBundle(ctx context.Context) (*AdminBundle, error) {
	if err := a.identity.validate(); err != nil {
		return nil, err
	}
	var resp *certclient.IssueCertificateResponse
	var err error
	if local, ok := a.issuer.(*localCACertIssuer); ok {
		resp, err = local.issue(ctx, AdminCertificateRequest(), &a.identity)
	} else {
		// The SDK certificate request has no identity field. The server's CA
		// adapter stamps the SAN only when it has a trust domain configured
		// and the call carries a tenant.
		resp, err = a.issuer.IssueCertificate(ctx, AdminCertificateRequest())
	}
	if err != nil {
		return nil, err
	}
	return &AdminBundle{CertPEM: resp.CertificatePEM, KeyPEM: resp.PrivateKeyPEM}, nil
}

// sdkCertIssuer delegates to the SDK's Certificate service.
type sdkCertIssuer struct {
	client quicbaassdk.Client
}

// IssueCertificate delegates to Security().Certificate().IssueCertificate.
func (i *sdkCertIssuer) IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	return i.client.Security().Certificate().IssueCertificate(ctx, req)
}

// GetCABundle delegates to Security().Certificate().GetCABundle.
func (i *sdkCertIssuer) GetCABundle(ctx context.Context, req *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	return i.client.Security().Certificate().GetCABundle(ctx, req)
}

// localCACertIssuer issues certificates by calling the platform's loaded CA
// directly, bypassing the SDK: the embedded transport does not register a
// Certificate service.
type localCACertIssuer struct {
	ca quicbaasca.CACertificateAuthority
}

// IssueCertificate generates a fresh ECDSA P-256 key locally, builds a CSR,
// and asks the platform CA to sign it. The admin bundle is handed to the
// operator, so its key must exist as PEM; this is the one daemon key that
// leaves a keystore. Returns the certificate and the PEM-encoded key.
func (i *localCACertIssuer) IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	return i.issue(ctx, req, nil)
}

// issue signs req with the local CA. A non-nil identity has the CA
// synthesize the tenant-scoped SPIFFE URI SAN for req.CommonName.
func (i *localCACertIssuer) issue(ctx context.Context, req *certclient.IssueCertificateRequest, identity *AdminIdentity) (*certclient.IssueCertificateResponse, error) {
	if req == nil {
		return nil, &ErrCertRequestNil{}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &ErrCertIssue{Usage: req.Usage, Cause: err}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, &ErrCertIssue{Usage: req.Usage, Cause: err}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Build a CSR carrying the requested subject, DNS SANs, and IP SANs.
	ips := make([]net.IP, 0, len(req.IPAddresses))
	for _, s := range req.IPAddresses {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	csrTpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
		},
		DNSNames:    req.DNSNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTpl, priv)
	if err != nil {
		return nil, &ErrCertIssue{Usage: req.Usage, Cause: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	usage := strings.ToLower(strings.TrimSpace(req.Usage))
	signOpts := &quicbaasca.SignOptions{
		ValidityDays: int(req.ValidityDays),
	}
	switch usage {
	case "client":
		signOpts.KeyUsage = x509.KeyUsageDigitalSignature
		signOpts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default: // "server"
		signOpts.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		signOpts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if identity != nil {
		// The kind defaults to "user" when a SPIFFE SAN is requested.
		signOpts.SPIFFETrustDomain = identity.TrustDomain
		signOpts.TenantID = identity.TenantID
		signOpts.SPIFFEName = req.CommonName
	}

	cert, err := i.ca.SignCSR(ctx, csrPEM, signOpts)
	if err != nil {
		return nil, &ErrCertIssue{Usage: req.Usage, Cause: err}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	serial := ""
	if cert.SerialNumber != nil {
		serial = cert.SerialNumber.String()
	}
	return &certclient.IssueCertificateResponse{
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		SerialNumber:   serial,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
	}, nil
}

// GetCABundle returns the platform CA's bundle PEM.
func (i *localCACertIssuer) GetCABundle(_ context.Context, _ *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	pemData, err := i.ca.CABundle()
	if err != nil {
		return nil, err
	}
	return &certclient.GetCABundleResponse{
		BundlePEM: string(pemData),
	}, nil
}
