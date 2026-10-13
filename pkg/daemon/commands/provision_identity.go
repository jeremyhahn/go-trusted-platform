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
// crypto.Signer. The daemon mints no admin client certificate: the
// one-shot /init bundle is the only admin credential.

package commands

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"time"

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

// provisionDaemonIdentity returns the daemon's TLS material:
//   - the server certificate, held in the CA keystore under daemonServerCN.
//     A current certificate is reused; a stale one is superseded (its key
//     deleted) and re-issued. The key is never encoded or written.
//   - <dir>/ca-bundle.crt, the public CA trust bundle (mode 0644).
//
// It issues no admin client certificate: the one-shot /init bundle is the
// only admin credential (docs/bootstrap/cli.md §1a). The server identity is
// provisioned first, so a keystore failure writes nothing. The daemon caller
// wires ServerCert into config.TLSCertificate /
// QUICConfig.TLSConfig.Certificates and AdminTrustPool into
// config.MTLSClientCAPool.
func provisionDaemonIdentity(
	ctx context.Context,
	logger *logging.Logger,
	ca daemonIdentityCA,
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

	caBundlePath := filepath.Join(outputDir, "ca-bundle.crt")
	caPEM, err := ca.CABundle()
	if err != nil {
		return nil, ErrProvisionIssue{Role: "ca-bundle", Cause: err}
	}
	if err := os.WriteFile(caBundlePath, caPEM, 0644); err != nil {
		return nil, ErrProvisionPersist{Path: caBundlePath, Cause: err}
	}

	return &ProvisionedIdentity{
		ServerCert:     serverCert,
		AdminTrustPool: trustPool,
		CABundlePath:   caBundlePath,
		Reused:         reused,
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
