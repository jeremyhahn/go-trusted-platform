package issuance

import (
	"context"
	"crypto/x509"

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
// and must fit the issuer's path length (checkIssuerPathLen).
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
	return checkIssuerPathLen(issuer, req.MaxPathLen)
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
