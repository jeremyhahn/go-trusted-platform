package issuance

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// caProfileName is the registry name of the go-xkms CA certificate profile:
// go-xkms v0.17.0-alpha pkg/ca.ProfileNameCA, which the quicbaas SDK does not
// re-export. TestIssue_CARequestReturnsCACertificate issues through a real CA
// and fails if this name stops selecting the CA profile.
const caProfileName = "ca"

// caProfileKeyUsage is the key usage the pinned go-xkms ca.NewCAProfile
// writes into every CA certificate, whatever the request asks for: its Apply
// replaces the request's KeyUsage with this mask (RFC 5280 §4.2.1.3).
const caProfileKeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature

// ErrNilCertificateRequest is returned by Issue when it is given no request.
type ErrNilCertificateRequest struct{}

func (ErrNilCertificateRequest) Error() string {
	return "issuance: no certificate request to issue"
}

// Issuer is the part of a go-xkms CA that issues a certificate on a key it
// generates.
type Issuer interface {
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
	IssueCertificateWithProfile(ctx context.Context, req *quicbaasca.CACertificateRequest, profile string) (*quicbaasca.IssuedCertificate, error)
	// CACertificate is the certificate the CA signs with, whose path length
	// bounds the subordinate CAs it may issue.
	CACertificate() (*x509.Certificate, error)
	// CABundle is the CA's chain in PEM, the issuing certificate first and
	// the root last. Every certificate above the issuing one bounds the
	// subordinate CAs as well (checkAncestorPathLen).
	CABundle() ([]byte, error)
}

// Issue issues the certificate req describes. go-xkms IssueCertificate picks
// an unnamed leaf profile that ignores req.IsCA, so a CA request is signed with
// the CA profile instead, which sets basicConstraints cA=TRUE and keyCertSign.
//
// The wire requests carry a single path length, so for a CA request a
// MaxPathLen of 0 means pathLenConstraint 0 (no subordinate CA below it), the
// meaning go-xkms gives it; a negative MaxPathLen leaves the path unlimited.
func Issue(ctx context.Context, ca Issuer, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	if err := preflight(ca, req); err != nil {
		return nil, err
	}
	if !req.IsCA {
		return ca.IssueCertificate(ctx, req)
	}
	caReq := *req
	caReq.MaxPathLenZero = caReq.MaxPathLen == 0
	if caReq.MaxPathLen < 0 {
		// The SDK refuses a negative MaxPathLen (ErrInvalidPathLength).
		// MaxPathLen 0 with MaxPathLenZero false is crypto/x509's form for
		// a basicConstraints with no pathLenConstraint: no limit.
		caReq.MaxPathLen = 0
	}
	return ca.IssueCertificateWithProfile(ctx, &caReq, caProfileName)
}

// preflight runs the checks a request must pass against its issuer before
// anything is signed. Issue runs it, and Renew runs it before it revokes the
// certificate it replaces, so both refuse the same requests. An isCA request
// may carry no extended key usage restriction (ErrCAExtKeyUsageUnsupported)
// and must fit the issuer's path length (checkIssuerPathLen) and every path
// length above the issuer (checkAncestorPathLen).
func preflight(ca Issuer, req *quicbaasca.CACertificateRequest) error {
	if req == nil {
		return ErrNilCertificateRequest{}
	}
	if !req.IsCA {
		return nil
	}
	if len(req.ExtKeyUsage) > 0 {
		return ErrCAExtKeyUsageUnsupported{}
	}
	// A zero KeyUsage asks for the profile's default; any other mask must be
	// the profile's, or the CA would come out with authority it was not given.
	if req.KeyUsage != 0 && req.KeyUsage != caProfileKeyUsage {
		return &CAKeyUsageUnsupportedError{Requested: req.KeyUsage, Profile: caProfileKeyUsage}
	}
	issuer, err := ca.CACertificate()
	if err != nil {
		return &IssuerCertificateError{Err: err}
	}
	if err := checkIssuerPathLen(issuer, req.MaxPathLen); err != nil {
		return err
	}
	return checkAncestorPathLen(ca, issuer, req.MaxPathLen)
}

// checkIssuerPathLen refuses a subordinate CA the issuer's pathLenConstraint
// does not allow (RFC 5280 §4.2.1.9): an issuer with pathLen 0 may issue no
// CA certificate, and beneath an issuer with pathLen n the subordinate's own
// pathLen is at most n-1. A requested pathLen below zero asks for no limit,
// which a limited issuer cannot grant. An issuer without a pathLenConstraint
// (MaxPathLen -1, or 0 without MaxPathLenZero) does not bound the request.
func checkIssuerPathLen(issuer *x509.Certificate, requested int) error {
	if issuer == nil {
		return &IssuerCertificateError{}
	}
	limited := issuer.MaxPathLen > 0 || (issuer.MaxPathLen == 0 && issuer.MaxPathLenZero)
	if !limited {
		return nil
	}
	subject := issuer.Subject.String()
	if issuer.MaxPathLen == 0 {
		return &IssuerPathLenExhaustedError{Issuer: subject}
	}
	allowed := issuer.MaxPathLen - 1
	if requested < 0 || requested > allowed {
		return &SubordinatePathLenError{Issuer: subject, Requested: requested, Allowed: allowed}
	}
	return nil
}

// pathLenLimited reports whether cert carries a pathLenConstraint: crypto/x509
// reads a certificate without one as MaxPathLen -1, or 0 without
// MaxPathLenZero.
func pathLenLimited(cert *x509.Certificate) bool {
	return cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero)
}

// selfIssued reports whether cert's issuer and subject are the same name
// (RFC 5280 §3.2). Equal names do not make cert the top of its chain: a
// key-rollover CA certificate is self-issued but signed by an older key.
func selfIssued(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// selfSigned reports whether cert is self-issued and verifies under its own
// key: the top of its chain.
func selfSigned(cert *x509.Certificate) bool {
	return selfIssued(cert) && cert.CheckSignatureFrom(cert) == nil
}

// checkAncestorPathLen refuses a subordinate CA that a pathLenConstraint above
// the issuer does not allow (RFC 5280 §6.1.4). Only a certificate that is not
// self-issued counts toward an ancestor's limit (§6.1.4 (l)): an ancestor
// with pathLen n that has steps such CA certificates beneath it, from the
// issuer up to the ancestor, leaves the subordinate a pathLen of at most
// n-steps-1, and below zero no subordinate CA fits at all. The chain is read
// from the CA's bundle and walked by signature up to a self-signed
// certificate; a self-issued certificate signed by another key (a key
// rollover) does not end the walk. If the chain does not lead from the issuer
// up to a self-signed certificate the request is refused (IssuerChainError),
// because an ancestor that cannot be seen may carry a limit. A self-signed
// issuer has no certificate above it, and the bundle is not read.
func checkAncestorPathLen(ca Issuer, issuer *x509.Certificate, requested int) error {
	if selfSigned(issuer) {
		return nil
	}
	issuerName := issuer.Subject.String()
	bundle, err := ca.CABundle()
	if err != nil {
		return &IssuerChainError{Subject: issuerName, Err: err}
	}
	chain, err := bundleCertificates(bundle)
	if err != nil {
		return &IssuerChainError{Subject: issuerName, Err: err}
	}
	current := issuer
	steps := 0
	for depth := 1; !selfSigned(current); depth++ {
		parent := issuerOf(current, chain)
		// depth beyond the bundle's length means its certificates form a loop.
		if parent == nil || depth > len(chain) {
			return &IssuerChainError{Subject: current.Subject.String()}
		}
		if !selfIssued(current) {
			steps++
		}
		if pathLenLimited(parent) {
			allowed := parent.MaxPathLen - steps - 1
			if allowed < 0 || requested < 0 || requested > allowed {
				return &AncestorPathLenError{
					Issuer:    issuerName,
					Ancestor:  parent.Subject.String(),
					Requested: requested,
					Allowed:   allowed,
				}
			}
		}
		current = parent
	}
	return nil
}

// bundleCertificates parses the certificates of a PEM bundle, in order.
func bundleCertificates(bundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			return certs, nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
}

// issuerOf returns the certificate of chain that issued cert: its subject is
// cert's issuer, it is not cert itself, and cert's signature verifies under
// its key. It returns nil when chain holds none.
func issuerOf(cert *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	for _, candidate := range chain {
		if !bytes.Equal(candidate.RawSubject, cert.RawIssuer) || bytes.Equal(candidate.Raw, cert.Raw) {
			continue
		}
		if cert.CheckSignatureFrom(candidate) == nil {
			return candidate
		}
	}
	return nil
}
