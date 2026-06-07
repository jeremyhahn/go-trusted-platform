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

// provision_identity.go implements milestone M5 from
// docs/08-bootstrap-auth-architecture.md: replace the local mTLS
// cert-generation pipeline with quicbaas SDK delegation. The public entry
// point is provisionDaemonIdentity(); the inner SDK call surface is
// abstracted behind daemonCertIssuer so unit tests can drive the existence-
// check / re-issue logic without spinning up a full SDK transport.

package commands

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
)

// daemonCertIssuer is the minimum surface of the quicbaas
// CertificateService that provisionDaemonIdentity exercises. Tests
// substitute their own implementation; production wiring is provided by
// sdkCertIssuer (which delegates to a quicbaassdk.Client).
type daemonCertIssuer interface {
	IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error)
	GetCABundle(ctx context.Context, req *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error)
}

// sdkCertIssuer adapts a quicbaassdk.Client into the daemonCertIssuer
// surface. This keeps provisionDaemonIdentity decoupled from the wider
// SDK interface (and from the SDK construction quirks of any specific
// transport).
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

// newSDKCertIssuer wraps a quicbaassdk.Client. Returns nil when the SDK
// client is missing so callers can fall through to a typed error
// (ErrProvisionMissingSDK).
func newSDKCertIssuer(client quicbaassdk.Client) daemonCertIssuer {
	if client == nil {
		return nil
	}
	return &sdkCertIssuer{client: client}
}

// localCACertIssuer issues daemon TLS certificates by calling the
// platform's loaded CA directly, bypassing the QuicBaaS SDK / embedded
// transport. The QuicBaaS embedded transport does not register a
// Certificate service, so the SDK-based issuer returns
// "UNAVAILABLE: embedded: service not configured: Certificate" at
// startup. The platform CA is already loaded in App.CA at the moment
// applyDaemonTLSIdentity runs, so we use it directly to mint the
// daemon's gRPC TCP / QUIC server cert and admin client cert.
type localCACertIssuer struct {
	ca quicbaasca.CACertificateAuthority
}

// IssueCertificate generates a fresh ECDSA P-256 key locally, builds a
// CSR, and asks the platform CA to sign it. This avoids depending on
// CA-side key generation (which may store keys in TPM/HSM and not
// return PEM) so the daemon's TLS listeners can use the resulting
// cert + key directly. Returns the certificate and the freshly-minted
// PEM-encoded EC private key.
func (i *localCACertIssuer) IssueCertificate(_ context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	if req == nil {
		return nil, ErrProvisionMissingCA{}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrProvisionIssue{Role: req.Usage, Cause: err}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, ErrProvisionIssue{Role: req.Usage, Cause: err}
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
		return nil, ErrProvisionIssue{Role: req.Usage, Cause: err}
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

	cert, err := i.ca.SignCSR(csrPEM, signOpts)
	if err != nil {
		return nil, ErrProvisionIssue{Role: req.Usage, Cause: err}
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

// GetCABundle returns the platform CA's bundle PEM. Used by
// provisionDaemonIdentity to populate the on-disk ca-bundle.crt file.
func (i *localCACertIssuer) GetCABundle(_ context.Context, _ *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	pemData, err := i.ca.CABundle()
	if err != nil {
		return nil, err
	}
	return &certclient.GetCABundleResponse{
		BundlePEM: string(pemData),
	}, nil
}

// newLocalCACertIssuer returns an issuer that delegates to the platform
// CA directly. Returns nil when the CA is missing so the caller can
// surface ErrProvisionMissingCA.
func newLocalCACertIssuer(ca quicbaasca.CACertificateAuthority) daemonCertIssuer {
	if ca == nil {
		return nil
	}
	return &localCACertIssuer{ca: ca}
}

// stringIPsFromAddrs filters out unparsable entries so the SDK request
// only carries valid IP literals. Currently unused — kept here for
// callers who need to massage net.Addr → []string before constructing
// IssueCertificateRequest.
func stringIPsFromAddrs(addrs []net.IP) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.String())
	}
	return out
}

// _ keeps the pem import live for future direct-PEM helpers.
var _ = pem.Block{}
