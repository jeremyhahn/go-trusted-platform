package issuance

import (
	"context"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// caProfileName is the registry name of the go-xkms CA certificate profile:
// go-xkms v0.17.0-alpha pkg/ca.ProfileNameCA, which the quicbaas SDK does not
// re-export. TestIssue_CARequestReturnsCACertificate issues through a real CA
// and fails if this name stops selecting the CA profile.
const caProfileName = "ca"

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
}

// Issue issues the certificate req describes. go-xkms IssueCertificate picks
// an unnamed leaf profile that ignores req.IsCA, so a CA request is signed with
// the CA profile instead, which sets basicConstraints cA=TRUE and keyCertSign.
//
// The wire requests carry a single path length, so for a CA request a
// MaxPathLen of 0 means pathLenConstraint 0 (no subordinate CA below it), the
// meaning go-xkms gives it; a negative MaxPathLen leaves the path unlimited.
func Issue(ctx context.Context, ca Issuer, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	if req == nil {
		return nil, ErrNilCertificateRequest{}
	}
	if !req.IsCA {
		return ca.IssueCertificate(ctx, req)
	}
	caReq := *req
	caReq.MaxPathLenZero = caReq.MaxPathLen == 0
	return ca.IssueCertificateWithProfile(ctx, &caReq, caProfileName)
}
