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

// provision_identity.go provisions the daemon's TLS identity. The public
// entry point is provisionDaemonIdentity(). The server certificate's key is
// generated in, and never leaves, the platform CA keystore (#33): the
// listeners get a tls.Certificate whose PrivateKey is the keystore's
// crypto.Signer. The admin bootstrap client certificate is issued behind
// daemonCertIssuer so unit tests can drive the reuse / re-issue logic
// without spinning up a full SDK transport.

package commands

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasacme "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// daemonServerCN is the subject CN of the daemon's TLS server certificate
// and the keystore ID of its private key.
const daemonServerCN = "platformd.localhost"

// daemonIdentityCA is the CA surface the daemon TLS identity needs. The
// server key is generated in the CA keystore by IssueCertificate and is
// only ever reached through TLSCertificate, which returns the keystore's
// crypto.Signer — never key bytes. App.CA satisfies it.
type daemonIdentityCA interface {
	caTrustPoolProvider
	intermediateProvider
	CABundle() ([]byte, error)
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
	TLSCertificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (tls.Certificate, error)
	Certificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error)
	RevokeCert(ctx context.Context, cert *x509.Certificate, opts quicbaasca.RevokeOptions) error
}

// intermediateProvider is the CA surface that names the platform
// intermediate certificate.
type intermediateProvider interface {
	TrustedIntermediate() (*x509.Certificate, error)
}

// daemonCertIssuer is the minimum surface of the quicbaas
// CertificateService used to issue the admin bootstrap client certificate.
// Tests substitute their own implementation; production wiring is provided
// by sdkCertIssuer or localCACertIssuer.
type daemonCertIssuer interface {
	IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error)
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

// newSDKCertIssuer wraps a quicbaassdk.Client. Returns nil when the SDK
// client is missing so callers can fall through to a typed error
// (ErrProvisionMissingSDK).
func newSDKCertIssuer(client quicbaassdk.Client) daemonCertIssuer {
	if client == nil {
		return nil
	}
	return &sdkCertIssuer{client: client}
}

// localCACertIssuer issues the admin bootstrap client certificate by
// calling the platform's loaded CA directly, bypassing the QuicBaaS SDK /
// embedded transport. The QuicBaaS embedded transport does not register a
// Certificate service, so the SDK-based issuer returns
// "UNAVAILABLE: embedded: service not configured: Certificate" at
// startup. The platform CA is already loaded in App.CA at the moment
// applyDaemonTLSIdentity runs, so we use it directly.
type localCACertIssuer struct {
	ca quicbaasca.CACertificateAuthority
}

// IssueCertificate generates a fresh ECDSA P-256 key locally, builds a
// CSR, and asks the platform CA to sign it. The admin bootstrap bundle is
// handed to the operator as a file, so its key must exist as PEM; this is
// the one daemon key that leaves a keystore. Returns the certificate and
// the freshly-minted PEM-encoded EC private key.
func (i *localCACertIssuer) IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
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

	cert, err := i.ca.SignCSR(ctx, csrPEM, signOpts)
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

// newLocalCACertIssuer returns an issuer that delegates to the platform
// CA directly. Returns nil when the CA is missing so the caller can
// surface ErrProvisionMissingCA.
func newLocalCACertIssuer(ca quicbaasca.CACertificateAuthority) daemonCertIssuer {
	if ca == nil {
		return nil
	}
	return &localCACertIssuer{ca: ca}
}

// provisionDaemonIdentity returns the daemon's TLS material:
//   - the server certificate, held in the CA keystore under daemonServerCN.
//     A current certificate is reused; a stale one is superseded (its key
//     deleted) and re-issued. The key is never encoded or written.
//   - <dir>/client-bundle.pem, the admin bootstrap cert + key (mode 0600),
//     reused while current (§8 #7).
//   - <dir>/ca-bundle.crt, the public CA trust bundle (mode 0644).
//
// The server identity is provisioned first, so a keystore failure writes
// nothing. The daemon caller wires ServerCert into config.TLSCertificate /
// QUICConfig.TLSConfig.Certificates and AdminTrustPool into
// config.MTLSClientCAPool.
func provisionDaemonIdentity(
	ctx context.Context,
	logger *logging.Logger,
	ca daemonIdentityCA,
	issuer daemonCertIssuer,
	outputDir string,
	sans daemonSANs,
) (*ProvisionedIdentity, error) {

	if ca == nil {
		return nil, ErrProvisionMissingCA{}
	}

	trustPool, err := ca.CABundleCertPool()
	if err != nil {
		return nil, ErrProvisionIssue{Role: "trust-pool", Cause: err}
	}

	dnsNames, ipStrings := daemonCertSANs(sans)

	serverCert, reused, err := daemonServerIdentity(ctx, logger, ca, trustPool, dnsNames, ipStrings)
	if err != nil {
		return nil, err
	}

	adminBundlePath := filepath.Join(outputDir, "client-bundle.pem")
	if err := provisionAdminBundle(ctx, logger, issuer, adminBundlePath, trustPool); err != nil {
		return nil, err
	}

	caBundlePath := filepath.Join(outputDir, "ca-bundle.crt")
	caPEM, err := ca.CABundle()
	if err != nil {
		return nil, ErrProvisionIssue{Role: "ca-bundle", Cause: err}
	}
	if err := os.WriteFile(caBundlePath, caPEM, 0644); err != nil {
		return nil, ErrProvisionPersist{Path: caBundlePath, Cause: err}
	}

	return &ProvisionedIdentity{
		ServerCert:      serverCert,
		AdminTrustPool:  trustPool,
		AdminBundlePath: adminBundlePath,
		CABundlePath:    caBundlePath,
		Reused:          reused,
	}, nil
}

// daemonServerKeyAttributes identifies the daemon's server key in the CA
// keystore. The software store is the CA keystore's default leaf store,
// the same one the CA renewal handlers use, so it exists on nodes without
// a TPM.
func daemonServerKeyAttributes() *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            daemonServerCN,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       xkmssdk.KeyTypeTLS,
		StoreType:     xkmssdk.StoreSoftware,
		ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		Hash:          crypto.SHA256,
	}
}

// daemonServerCertRequest is the CA request for the daemon's server
// certificate. Its KeyAttributes make the CA generate the key in its
// keystore rather than return it.
func daemonServerCertRequest(dnsNames, ipStrings []string) *quicbaasca.CACertificateRequest {
	return &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:   daemonServerCN,
			Organization: "Trusted Platform",
		},
		SANS: &quicbaasca.CASubjectAlternativeNames{
			DNS: dnsNames,
			IPs: ipStrings,
		},
		Valid:         365,
		KeyUsage:      x509.KeyUsageDigitalSignature,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyAttributes: daemonServerKeyAttributes(),
	}
}

// daemonCertSANs composes the loopback + caller-supplied SAN sets into the
// request shape (DNS names and string-form IP addresses).
func daemonCertSANs(extra daemonSANs) (dnsNames []string, ipStrings []string) {
	dnsNames = append(dnsNames, "localhost", daemonServerCN)
	dnsNames = append(dnsNames, extra.DNS...)
	ipStrings = append(ipStrings, "127.0.0.1", "::1")
	ipStrings = append(ipStrings, extra.IPs...)
	return
}

// daemonServerIdentity returns the keystore-held server certificate,
// issuing it when the keystore holds none and superseding it when it is
// expiring, no longer covers dnsNames, or no longer chains to trustPool.
// The bool reports reuse. Any keystore failure is an ErrTLSIdentityKeystore.
func daemonServerIdentity(
	ctx context.Context,
	logger *logging.Logger,
	ca daemonIdentityCA,
	trustPool *x509.CertPool,
	dnsNames, ipStrings []string,
) (tls.Certificate, bool, error) {

	attrs := daemonServerKeyAttributes()

	held, err := ca.TLSCertificate(ctx, attrs)
	if err != nil {
		logger.Debug("provisionDaemonIdentity: keystore holds no server identity, will issue",
			"cn", daemonServerCN, "error", err.Error())
	} else {
		leaf := tlsCertificateLeaf(held)
		if daemonServerCertCurrent(logger, leaf, trustPool, dnsNames) {
			held.Leaf = leaf
			logger.Info("provisionDaemonIdentity: reusing keystore-held server identity",
				"cn", daemonServerCN,
				"not_after", leaf.NotAfter.Format(time.RFC3339))
			return appendTrustedIntermediate(ca, held), true, nil
		}
	}

	if err := supersedeDaemonServerCert(ctx, logger, ca, attrs); err != nil {
		return tls.Certificate{}, false, err
	}

	if _, err := ca.IssueCertificate(ctx, daemonServerCertRequest(dnsNames, ipStrings)); err != nil {
		return tls.Certificate{}, false, ErrTLSIdentityKeystore{Op: "issue", Cause: err}
	}

	issued, err := ca.TLSCertificate(ctx, attrs)
	if err != nil {
		return tls.Certificate{}, false, ErrTLSIdentityKeystore{Op: "load", Cause: err}
	}
	issued.Leaf = tlsCertificateLeaf(issued)
	if issued.Leaf == nil {
		return tls.Certificate{}, false, ErrTLSIdentityKeystore{Op: "load", Cause: ErrTLSIdentityNotProvisioned{}}
	}

	logger.Info("provisionDaemonIdentity: issued keystore-held server identity",
		"cn", daemonServerCN,
		"serial", issued.Leaf.SerialNumber.String(),
		"not_after", issued.Leaf.NotAfter.Format(time.RFC3339))

	return appendTrustedIntermediate(ca, issued), false, nil
}

// supersedeDaemonServerCert revokes the certificate the CA store holds for
// the daemon CN, if any, so IssueCertificate can mint a fresh keystore key
// instead of failing with ErrCertificateAlreadyExists. DeleteKeys removes
// the cert-store entry and any keystore key.
//
// The certificate is looked up on its own, not through TLSCertificate. The
// pre-#33 provisioner signed an external CSR for the daemon CN: SignCSR
// stored the certificate, but its key lived only in a PEM bundle, so the
// keystore has no signer for it and TLSCertificate fails. That stale or
// legacy certificate still has to be superseded.
func supersedeDaemonServerCert(ctx context.Context, logger *logging.Logger, ca daemonIdentityCA, attrs *xkmssdk.KeyAttributes) error {
	stored, err := ca.Certificate(ctx, attrs)
	if errors.Is(err, quicbaasacme.CAErrCertificateNotFound) {
		return nil
	}
	if err != nil {
		return ErrTLSIdentityKeystore{Op: "supersede", Cause: err}
	}
	if err := ca.RevokeCert(ctx, stored, quicbaasca.RevokeOptions{DeleteKeys: true}); err != nil {
		return ErrTLSIdentityKeystore{Op: "supersede", Cause: err}
	}
	logger.Info("provisionDaemonIdentity: superseded stored server certificate",
		"cn", daemonServerCN,
		"serial", stored.SerialNumber.String())
	return nil
}

// daemonServerCertCurrent reports whether a keystore-held server
// certificate can be reused: outside the renewal window, covering every
// required DNS name, and chaining to the CA trust pool.
func daemonServerCertCurrent(logger *logging.Logger, leaf *x509.Certificate, trustPool *x509.CertPool, dnsNames []string) bool {
	if !certWithinRenewalWindow(leaf, renewalThreshold) {
		logger.Debug("provisionDaemonIdentity: server certificate missing, expired or near-expiry, will reissue")
		return false
	}
	if !certCoversDNSNames(leaf, dnsNames) {
		logger.Debug("provisionDaemonIdentity: server certificate SANs no longer cover required hostnames, will reissue",
			"required", dnsNames,
			"present", leaf.DNSNames)
		return false
	}
	if err := verifyChain(leaf, trustPool); err != nil {
		logger.Debug("provisionDaemonIdentity: server certificate chain invalid, will reissue",
			"error", err.Error())
		return false
	}
	return true
}

// tlsCertificateLeaf returns the parsed leaf of cert, parsing the first
// chain entry when the keystore did not populate Leaf. Returns nil when
// the chain is empty or unparseable.
func tlsCertificateLeaf(cert tls.Certificate) *x509.Certificate {
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

// appendTrustedIntermediate adds the platform intermediate to a leaf-only
// chain, so a peer anchored only on the platform root can verify it. A
// pure-root CA has no intermediate, and the chain is returned unchanged.
func appendTrustedIntermediate(ca intermediateProvider, cert tls.Certificate) tls.Certificate {
	if len(cert.Certificate) != 1 {
		return cert
	}
	inter, err := ca.TrustedIntermediate()
	if err != nil || inter == nil {
		return cert
	}
	cert.Certificate = append(cert.Certificate, inter.Raw)
	return cert
}

// provisionAdminBundle keeps a current admin bootstrap bundle at path,
// issuing and writing a fresh one only when the existing bundle is
// missing, expiring or no longer chains to trustPool.
func provisionAdminBundle(
	ctx context.Context,
	logger *logging.Logger,
	issuer daemonCertIssuer,
	path string,
	trustPool *x509.CertPool,
) error {

	if adminBundleCurrent(logger, path, trustPool) {
		return nil
	}
	if issuer == nil {
		return ErrProvisionMissingSDK{}
	}

	resp, err := issuer.IssueCertificate(ctx, &certclient.IssueCertificateRequest{
		CommonName:   "admin",
		Organization: "Trusted Platform",
		Usage:        "client",
		KeyAlgorithm: "ecdsa",
		ValidityDays: 365,
	})
	if err != nil {
		return ErrProvisionIssue{Role: "admin", Cause: err}
	}
	if err := writeBundle(path, resp.CertificatePEM, resp.PrivateKeyPEM, 0600); err != nil {
		return ErrProvisionPersist{Path: path, Cause: err}
	}

	logger.Info("provisionDaemonIdentity: issued admin bootstrap bundle",
		"path", path,
		"serial", resp.SerialNumber,
		"not_after", resp.NotAfter.Format(time.RFC3339))
	return nil
}

// adminBundleCurrent reports whether the admin bootstrap bundle at path
// can be reused: present, parseable, outside the renewal window, and
// chaining to the CA trust pool.
func adminBundleCurrent(logger *logging.Logger, path string, trustPool *x509.CertPool) bool {
	adminCert, err := tlsCertificateFromFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Debug("provisionDaemonIdentity: admin bundle invalid, will reissue",
				"path", path, "error", err.Error())
		}
		return false
	}
	if !certWithinRenewalWindow(adminCert.Leaf, renewalThreshold) {
		logger.Debug("provisionDaemonIdentity: admin bundle expired or near-expiry, will reissue",
			"path", path,
			"not_after", adminCert.Leaf.NotAfter.Format(time.RFC3339))
		return false
	}
	if err := verifyChain(adminCert.Leaf, trustPool); err != nil {
		logger.Debug("provisionDaemonIdentity: admin bundle chain invalid, will reissue",
			"path", path, "error", err.Error())
		return false
	}
	return true
}
