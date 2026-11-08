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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
)

var errSDKCertificate = errors.New("sdk certificate failure")

// certSecurityClient routes Security().Certificate() to a recording
// certificate client; nothing else on the SDK is used by sdkCertIssuer.
type certSecurityClient struct {
	quicbaassdk.Client
	cert *recordingCertClient
}

func (c *certSecurityClient) Security() quicbaassdk.SecurityService {
	return &certSecurity{cert: c.cert}
}

type certSecurity struct {
	quicbaassdk.SecurityService
	cert *recordingCertClient
}

func (s *certSecurity) Certificate() quicbaassdk.CertificateClient { return s.cert }

type recordingCertClient struct {
	quicbaassdk.CertificateClient
	err       error
	issueReq  *certclient.IssueCertificateRequest
	bundleReq *certclient.GetCABundleRequest
}

func (r *recordingCertClient) IssueCertificate(_ context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	r.issueReq = req
	if r.err != nil {
		return nil, r.err
	}
	return &certclient.IssueCertificateResponse{CertificatePEM: "CERT", SerialNumber: "7"}, nil
}

func (r *recordingCertClient) GetCABundle(_ context.Context, req *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	r.bundleReq = req
	if r.err != nil {
		return nil, r.err
	}
	return &certclient.GetCABundleResponse{BundlePEM: "BUNDLE"}, nil
}

func TestSDKCertIssuer_DelegatesToTheSDKCertificateService(t *testing.T) {
	rec := &recordingCertClient{}
	issuer := PlatformCertIssuer(nil, &certSecurityClient{cert: rec})

	issueReq := &certclient.IssueCertificateRequest{CommonName: "node-1"}
	resp, err := issuer.IssueCertificate(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if rec.issueReq != issueReq || resp.CertificatePEM != "CERT" || resp.SerialNumber != "7" {
		t.Fatalf("IssueCertificate forwarded %p, returned %+v", rec.issueReq, resp)
	}

	bundleReq := &certclient.GetCABundleRequest{}
	bundle, err := issuer.GetCABundle(context.Background(), bundleReq)
	if err != nil {
		t.Fatalf("GetCABundle: %v", err)
	}
	if rec.bundleReq != bundleReq || bundle.BundlePEM != "BUNDLE" {
		t.Fatalf("GetCABundle forwarded %p, returned %+v", rec.bundleReq, bundle)
	}
}

func TestSDKCertIssuer_PropagatesSDKErrors(t *testing.T) {
	issuer := PlatformCertIssuer(nil, &certSecurityClient{cert: &recordingCertClient{err: errSDKCertificate}})
	if _, err := issuer.IssueCertificate(context.Background(), &certclient.IssueCertificateRequest{}); !errors.Is(err, errSDKCertificate) {
		t.Errorf("IssueCertificate err = %v, want the SDK error", err)
	}
	if _, err := issuer.GetCABundle(context.Background(), &certclient.GetCABundleRequest{}); !errors.Is(err, errSDKCertificate) {
		t.Errorf("GetCABundle err = %v, want the SDK error", err)
	}
}

func TestLocalCACertIssuer_IssueCertificate_BuildsTheCSRAndReturnsAMatchingKey(t *testing.T) {
	ca := newSigningCA(t)
	resp, err := PlatformCertIssuer(ca, nil).IssueCertificate(context.Background(), &certclient.IssueCertificateRequest{
		CommonName:   "node-1",
		Organization: "tenant-a",
		DNSNames:     []string{"node-1.local"},
		IPAddresses:  []string{"10.0.0.5", "not-an-ip", "::1"},
		Usage:        "server",
		ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if ca.csr.Subject.CommonName != "node-1" || !slices.Equal(ca.csr.Subject.Organization, []string{"tenant-a"}) {
		t.Errorf("CSR subject = %v", ca.csr.Subject)
	}
	if !slices.Equal(ca.csr.DNSNames, []string{"node-1.local"}) {
		t.Errorf("CSR DNS names = %v", ca.csr.DNSNames)
	}
	var ips []string
	for _, ip := range ca.csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	if !slices.Equal(ips, []string{"10.0.0.5", "::1"}) {
		t.Errorf("CSR IPs = %v, want the unparseable entry dropped", ips)
	}
	if ca.opts.ValidityDays != 30 || ca.opts.SPIFFETrustDomain != "" || ca.opts.SPIFFEName != "" {
		t.Errorf("sign options = %+v, want 30 days and no SPIFFE SAN", *ca.opts)
	}

	certBlock, _ := pem.Decode([]byte(resp.CertificatePEM))
	keyBlock, _ := pem.Decode([]byte(resp.PrivateKeyPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("response PEM blocks: cert %v, key %v", certBlock, keyBlock)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if !key.(*ecdsa.PrivateKey).PublicKey.Equal(cert.PublicKey) {
		t.Error("returned key does not match the certificate")
	}
	if resp.SerialNumber != "2" || !resp.NotBefore.Equal(cert.NotBefore) || !resp.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("response metadata = serial %q, %v..%v", resp.SerialNumber, resp.NotBefore, resp.NotAfter)
	}
}

func TestLocalCACertIssuer_IssueCertificate_UsageSelectsKeyUsage(t *testing.T) {
	server := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	serverExt := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	tests := []struct {
		usage   string
		wantKU  x509.KeyUsage
		wantEKU []x509.ExtKeyUsage
	}{
		{"client", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{" Client ", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"server", server, serverExt},
		{"", server, serverExt},
	}
	for _, tt := range tests {
		t.Run(tt.usage, func(t *testing.T) {
			ca := newSigningCA(t)
			if _, err := PlatformCertIssuer(ca, nil).IssueCertificate(context.Background(), &certclient.IssueCertificateRequest{
				CommonName: "n", Usage: tt.usage,
			}); err != nil {
				t.Fatalf("IssueCertificate: %v", err)
			}
			if ca.opts.KeyUsage != tt.wantKU || !slices.Equal(ca.opts.ExtKeyUsage, tt.wantEKU) {
				t.Errorf("usage %q: key usage %v ext %v, want %v ext %v", tt.usage, ca.opts.KeyUsage, ca.opts.ExtKeyUsage, tt.wantKU, tt.wantEKU)
			}
		})
	}
}

func TestLocalCACertIssuer_IssueCertificate_SigningFailureIsTyped(t *testing.T) {
	ca := newSigningCA(t)
	ca.err = errSDKCertificate
	_, err := PlatformCertIssuer(ca, nil).IssueCertificate(context.Background(), &certclient.IssueCertificateRequest{Usage: "client"})
	var issueErr *ErrCertIssue
	if !errors.As(err, &issueErr) || issueErr.Usage != "client" || !errors.Is(err, errSDKCertificate) {
		t.Fatalf("err = %v, want ErrCertIssue{Usage: client} wrapping the CA error", err)
	}
}
