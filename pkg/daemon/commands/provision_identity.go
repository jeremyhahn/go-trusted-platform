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
	"math/big"
	"os"
	"path/filepath"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasacme "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmscertstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The daemon's server identity lives in one of two keystore slots. The CA
// keys a certificate and its keystore key by the subject CN and refuses to
// issue for a CN that already holds one, so a renewal issues into the slot
// that is not serving and the serving slot stays untouched until the new
// identity is presented. Both slots carry the same DNS SANs; the CN only
// names the slot.
const (
	// daemonServerCN is the first slot, and the DNS SAN every daemon server
	// certificate carries.
	daemonServerCN = "platformd.localhost"
	// daemonServerAltCN is the second slot.
	daemonServerAltCN = "platformd-alt.localhost"
)

// daemonServerSlots lists the two slots in the order boot looks them up.
var daemonServerSlots = [2]string{daemonServerCN, daemonServerAltCN}

// daemonIdentityCA is the CA surface the daemon TLS identity needs. The
// server key is generated in the CA keystore by IssueCertificate and is
// only ever reached through TLSCertificate, which returns the keystore's
// crypto.Signer — never key bytes. KeyStore and CertStore are used only to
// delete a retired slot. App.CA satisfies it.
type daemonIdentityCA interface {
	caTrustPoolProvider
	intermediateProvider
	CABundle() ([]byte, error)
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
	TLSCertificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (tls.Certificate, error)
	Certificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error)
	RevokeCert(ctx context.Context, cert *x509.Certificate, opts quicbaasca.RevokeOptions) error
	IsRevoked(serial *big.Int) (bool, error)
	KeyStore() xkmsbackend.Backend
	CertStore() xkmscertstore.CertStore
}

// intermediateProvider is the CA surface that names the platform
// intermediate certificate.
type intermediateProvider interface {
	TrustedIntermediate() (*x509.Certificate, error)
}

// provisionDaemonIdentity returns the daemon's TLS material:
//   - the server certificate, held in one of the two CA keystore slots. A
//     current certificate is reused; a stale one is re-issued into the other
//     slot, and only then is the stale slot revoked and its key deleted. The
//     key is never encoded or written.
//   - <dir>/ca-bundle.crt, the public CA trust bundle (mode 0644).
//
// It issues no admin client certificate: the one-shot /init bundle is the
// only admin credential (docs/bootstrap/cli.md §1a). The server identity is
// provisioned first, so a keystore failure writes nothing. The daemon caller
// wires ServerCert into config.TLSIdentity (and the QUIC GetCertificate hook),
// registers it with the renewal sweep (#36), and wires AdminTrustPool into
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

// daemonServerKeyAttributes identifies the daemon's server key in slot cn
// of the CA keystore. The software store is the CA keystore's default leaf
// store, the same one the CA renewal handlers use, so it exists on nodes
// without a TPM.
func daemonServerKeyAttributes(cn string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       xkmssdk.KeyTypeTLS,
		StoreType:     xkmssdk.StoreSoftware,
		ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		Hash:          crypto.SHA256,
	}
}

// otherDaemonServerSlot returns the slot that is not cn.
func otherDaemonServerSlot(cn string) string {
	if cn == daemonServerCN {
		return daemonServerAltCN
	}
	return daemonServerCN
}

// daemonServerCertRequest is the CA request for the daemon's server
// certificate in slot cn. Its KeyAttributes make the CA generate the key in
// its keystore rather than return it.
func daemonServerCertRequest(cn string, dnsNames, ipStrings []string) *quicbaasca.CACertificateRequest {
	return &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:   cn,
			Organization: "Trusted Platform",
		},
		SANS: &quicbaasca.CASubjectAlternativeNames{
			DNS: dnsNames,
			IPs: ipStrings,
		},
		Valid:         365,
		KeyUsage:      x509.KeyUsageDigitalSignature,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyAttributes: daemonServerKeyAttributes(cn),
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

// daemonServerIdentity returns the keystore-held server certificate. The
// latest identity either slot holds is reused while it is current. When it
// is expiring, no longer covers dnsNames or no longer chains to trustPool,
// or when neither slot holds one, a fresh identity is issued into the other
// slot and only then is the stale slot retired. The bool reports reuse. Any
// keystore failure is an ErrTLSIdentityKeystore.
func daemonServerIdentity(
	ctx context.Context,
	logger *logging.Logger,
	ca daemonIdentityCA,
	trustPool *x509.CertPool,
	dnsNames, ipStrings []string,
) (tls.Certificate, bool, error) {

	active, held, found := heldDaemonServerIdentity(ctx, logger, ca)
	if found && daemonServerCertCurrent(logger, held.Leaf, trustPool, dnsNames) {
		logger.Info("provisionDaemonIdentity: reusing keystore-held server identity",
			"cn", active,
			"not_after", held.Leaf.NotAfter.Format(time.RFC3339))
		// A renewal that swapped identities but could not retire the old
		// slot left it behind; boot retires it, as the next sweep would.
		retireReplacedDaemonServerSlot(ctx, logger, ca, otherDaemonServerSlot(active))
		return appendTrustedIntermediate(ca, held), true, nil
	}

	issued, err := issueDaemonServerIdentity(ctx, logger, ca, active, dnsNames, ipStrings)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	retireReplacedDaemonServerSlot(ctx, logger, ca, active)
	return issued, false, nil
}

// heldDaemonServerIdentity returns the slot holding the latest keystore-held
// server identity, that identity with its Leaf set, and whether one was
// found. With none found it returns the first slot, where a pre-#33
// certificate without a keystore key lives, so issuance goes to the other
// slot and that certificate is retired after it.
func heldDaemonServerIdentity(ctx context.Context, logger *logging.Logger, ca daemonIdentityCA) (string, tls.Certificate, bool) {
	active, found := daemonServerCN, false
	var held tls.Certificate
	for _, cn := range daemonServerSlots {
		cert, err := ca.TLSCertificate(ctx, daemonServerKeyAttributes(cn))
		if err != nil {
			logger.Debug("provisionDaemonIdentity: keystore holds no server identity in this slot",
				"cn", cn, "error", err.Error())
			continue
		}
		leaf := tlsCertificateLeaf(cert)
		if leaf == nil {
			logger.Debug("provisionDaemonIdentity: server identity in this slot has no parseable leaf",
				"cn", cn)
			continue
		}
		if found && !leaf.NotAfter.After(held.Leaf.NotAfter) {
			continue
		}
		cert.Leaf = leaf
		active, held, found = cn, cert, true
	}
	return active, held, found
}

// issueDaemonServerIdentity issues a fresh daemon server certificate into
// the slot that is not active, with a key the CA's keystore generates and
// holds, and returns it with the trusted intermediate appended. Boot
// provisioning and the running renewal (#36) both issue through it, so the
// two paths cannot drift apart.
//
// The active slot is never touched here: if anything fails, the identity it
// holds keeps serving, and the error is returned. The caller retires the
// active slot only after the new identity has replaced it.
func issueDaemonServerIdentity(
	ctx context.Context,
	logger *logging.Logger,
	ca daemonIdentityCA,
	active string,
	dnsNames, ipStrings []string,
) (tls.Certificate, error) {

	next := otherDaemonServerSlot(active)
	// The next slot is normally empty. A renewal that failed before its
	// swap, or a retirement not yet done, can leave an identity there that
	// nothing serves, and the CA will not issue over it.
	if err := retireDaemonServerSlot(ctx, logger, ca, next); err != nil {
		return tls.Certificate{}, err
	}

	if _, err := ca.IssueCertificate(ctx, daemonServerCertRequest(next, dnsNames, ipStrings)); err != nil {
		return tls.Certificate{}, ErrTLSIdentityKeystore{Op: "issue", Cause: err}
	}

	issued, err := ca.TLSCertificate(ctx, daemonServerKeyAttributes(next))
	if err != nil {
		return tls.Certificate{}, ErrTLSIdentityKeystore{Op: "load", Cause: err}
	}
	issued.Leaf = tlsCertificateLeaf(issued)
	if issued.Leaf == nil {
		return tls.Certificate{}, ErrTLSIdentityKeystore{Op: "load", Cause: ErrTLSIdentityNotProvisioned{}}
	}

	logger.Info("daemon TLS identity: issued keystore-held server identity",
		"cn", next,
		"serial", issued.Leaf.SerialNumber.String(),
		"not_after", issued.Leaf.NotAfter.Format(time.RFC3339))

	return appendTrustedIntermediate(ca, issued), nil
}

// retireDaemonServerSlot revokes the certificate slot cn holds and deletes
// it and its key, leaving the slot empty for the next issuance. An empty
// slot is already retired, and every step is safe to repeat: a revocation
// already recorded is not recorded again, and a deletion is done once the
// item is gone.
//
// The deletions are made here, not through RevokeCert's DeleteKeys:
// RevokeCert names the key by CN and algorithm alone, which is not the ID
// the slot's key is stored under, and discards every deletion error, so the
// slot could stay filled with nothing reported. The cert-store entry goes
// last: while it remains the slot is not retired, and the next attempt
// finds it and finishes.
//
// The certificate is looked up on its own, not through TLSCertificate: a
// pre-#33 certificate was stored by SignCSR with its key in a PEM bundle,
// so the keystore has no signer for it, and it still has to be retired.
func retireDaemonServerSlot(ctx context.Context, logger *logging.Logger, ca daemonIdentityCA, cn string) error {
	attrs := daemonServerKeyAttributes(cn)
	stored, err := ca.Certificate(ctx, attrs)
	if errors.Is(err, quicbaasacme.CAErrCertificateNotFound) {
		return nil
	}
	if err != nil {
		return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
	}

	revoked, err := ca.IsRevoked(stored.SerialNumber)
	if err != nil {
		return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
	}
	if !revoked {
		if err := ca.RevokeCert(ctx, stored, quicbaasca.RevokeOptions{}); err != nil {
			return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
		}
	}

	if keys := ca.KeyStore(); keys != nil {
		err := removeSlotItem(
			func() error { return keys.DeleteKey(ctx, attrs) },
			func() error { _, lookupErr := keys.GetKey(ctx, attrs); return lookupErr })
		if err != nil {
			return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
		}
		err = removeSlotItem(
			func() error { return keys.DeleteCert(ctx, cn) },
			func() error { _, lookupErr := keys.GetCert(ctx, cn); return lookupErr })
		if err != nil {
			return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
		}
	}
	if certs := ca.CertStore(); certs != nil {
		err := removeSlotItem(
			func() error { return certs.DeleteCertificate(cn) },
			func() error { _, lookupErr := certs.GetCertificate(cn); return lookupErr })
		if err != nil {
			return ErrTLSIdentityKeystore{Op: "retire", Cause: err}
		}
	}

	logger.Info("daemon TLS identity: retired server identity slot",
		"cn", cn,
		"serial", stored.SerialNumber.String())
	return nil
}

// removeSlotItem runs remove and returns its failure only while lookup still
// finds the item. The SDK re-exports no not-found error for keystore
// deletions, and an absent item is normal (a pre-#33 certificate never had
// a keystore key), so a failed delete is told apart from a deleted item by
// looking it up again.
func removeSlotItem(remove, lookup func() error) error {
	removeErr := remove()
	if removeErr == nil || lookup() != nil {
		return nil
	}
	return removeErr
}

// retireReplacedDaemonServerSlot retires slot cn after the identity it held
// has been replaced. A failure is logged, never returned: the new identity
// is already serving, and the next renewal sweep retries the retirement.
func retireReplacedDaemonServerSlot(ctx context.Context, logger *logging.Logger, ca daemonIdentityCA, cn string) {
	if err := retireDaemonServerSlot(ctx, logger, ca, cn); err != nil {
		logger.Warn("daemon TLS identity: the replaced server identity could not be retired; the next renewal sweep retries",
			"cn", cn, "error", err.Error())
	}
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
