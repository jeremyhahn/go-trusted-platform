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

package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	dbfactory "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// digestSigner is the minimal slice of the go-quicbaas crypto client the remote
// UKI signer needs: sign a pre-computed digest with a CP-KMS-resident key. The
// SDK crypto client (Security().Crypto()) satisfies it structurally; tests
// inject a fake. PreHashed is always set so the KMS signs the supplied digest
// rather than re-hashing it.
type digestSigner interface {
	Sign(ctx context.Context, req *cryptoclient.SignRequest) (*cryptoclient.SignResponse, error)
}

// certResolver returns a stored certificate by common name. The platform CA
// certificate store (CACertificateAuthority.CertStore()) satisfies it; tests
// inject a fake.
type certResolver interface {
	GetCertificate(cn string) (*x509.Certificate, error)
}

// RemoteDBKeySigner implements configdelivery.DBKeySigner using the server-side
// platform KMS in-process. SignDigest round-trips only the digest through the
// go-quicbaas crypto client with PreHashed=true, so the Secure Boot DB private
// key never leaves the control plane; Certificate returns the companion DB
// certificate from the platform CA certificate store so the node can embed it
// in the UKI Authenticode signature and enroll it into the firmware database.
type RemoteDBKeySigner struct {
	signer digestSigner
	certs  certResolver
	logger *logging.Logger
}

var _ configdelivery.DBKeySigner = (*RemoteDBKeySigner)(nil)

// NewRemoteDBKeySigner builds a signer from explicit collaborators. Production
// passes the SDK crypto client and the CA certificate store; tests pass fakes.
func NewRemoteDBKeySigner(signer digestSigner, certs certResolver, logger *logging.Logger) *RemoteDBKeySigner {
	return &RemoteDBKeySigner{signer: signer, certs: certs, logger: logger}
}

// NewRemoteDBKeySignerFromApp resolves the server-side KMS crypto client and the
// platform CA certificate store from the running application and returns a
// production configdelivery.DBKeySigner. It returns ErrDBSignerUnavailable when
// either collaborator is not yet available so the caller can still wire config
// delivery (without the sign endpoint) rather than failing daemon startup.
func NewRemoteDBKeySignerFromApp(application *app.App, logger *logging.Logger) (*RemoteDBKeySigner, error) {
	if application == nil {
		return nil, ErrDBSignerUnavailable{Reason: "application is nil"}
	}
	factory, ok := application.DAOFactory().(*dbfactory.Factory)
	if !ok {
		return nil, ErrDBSignerUnavailable{Reason: "datastore is not QuicBaaS"}
	}
	sdkClient := factory.SDK()
	if sdkClient == nil {
		return nil, ErrDBSignerUnavailable{Reason: "QuicBaaS SDK client unavailable"}
	}
	cryptoCl := sdkClient.Security().Crypto()
	if cryptoCl == nil {
		return nil, ErrDBSignerUnavailable{Reason: "crypto client unavailable"}
	}
	if application.CA == nil {
		return nil, ErrDBSignerUnavailable{Reason: "certificate authority unavailable"}
	}
	store := application.CA.CertStore()
	if store == nil {
		return nil, ErrDBSignerUnavailable{Reason: "certificate store unavailable"}
	}
	return NewRemoteDBKeySigner(cryptoCl, store, logger), nil
}

// SignDigest signs digest with the CP-KMS key referenced by keyURI (a kms://
// reference whose path is the KMS key identifier). The hash algorithm is
// inferred from the digest length; PreHashed instructs the KMS to sign the
// supplied digest directly so the private key never leaves the control plane.
// A KMS not-found (sdkerrors.IsNotFound) means the profile names a DB key the
// KMS does not hold and returns configdelivery.ErrRemoteSignNotConfigured.
func (s *RemoteDBKeySigner) SignDigest(ctx context.Context, keyURI string, digest []byte) ([]byte, error) {
	keyID := stripKMSScheme(keyURI)
	if keyID == "" {
		return nil, ErrDBSignerKeyRef{Ref: keyURI}
	}
	hashAlg, err := hashAlgForDigest(digest)
	if err != nil {
		return nil, err
	}
	resp, err := s.signer.Sign(ctx, &cryptoclient.SignRequest{
		KeyID:     keyID,
		Data:      digest,
		HashAlg:   hashAlg,
		PreHashed: true,
	})
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			return nil, configdelivery.ErrRemoteSignNotConfigured{
				Reason: fmt.Sprintf("db key %q is not provisioned in the KMS", keyID),
			}
		}
		return nil, ErrDBSign{KeyID: keyID, Cause: err}
	}
	if resp == nil || len(resp.Signature) == 0 {
		return nil, ErrDBSign{KeyID: keyID, Cause: errEmptySignature}
	}
	return resp.Signature, nil
}

// Certificate returns the PEM-encoded certificate stored under certRef (its
// common name) in the platform CA certificate store.
func (s *RemoteDBKeySigner) Certificate(_ context.Context, certRef string) ([]byte, error) {
	if certRef == "" {
		return nil, ErrDBCert{Ref: certRef, Cause: errEmptyCertRef}
	}
	cert, err := s.certs.GetCertificate(certRef)
	if err != nil {
		return nil, ErrDBCert{Ref: certRef, Cause: err}
	}
	if cert == nil {
		return nil, ErrDBCert{Ref: certRef, Cause: errNilCertificate}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// stripKMSScheme removes a leading kms:// scheme (case-insensitive) from ref,
// yielding the bare KMS key identifier. A ref without that scheme is returned
// unchanged so a bare key id also works.
func stripKMSScheme(ref string) string {
	const scheme = "kms://"
	if len(ref) >= len(scheme) && strings.EqualFold(ref[:len(scheme)], scheme) {
		return ref[len(scheme):]
	}
	return ref
}

// hashAlgForDigest maps a digest length to the SDK hash algorithm. Authenticode
// UKI signing uses SHA-256; SHA-384/512 are accepted for completeness.
func hashAlgForDigest(digest []byte) (cryptoclient.HashAlgorithm, error) {
	switch len(digest) {
	case sha256.Size:
		return cryptoclient.HashSHA256, nil
	case sha512.Size384:
		return cryptoclient.HashSHA384, nil
	case sha512.Size:
		return cryptoclient.HashSHA512, nil
	default:
		return 0, ErrUnsupportedDigest{Len: len(digest)}
	}
}

// Sentinel causes used by the remote DB signer.
var (
	errEmptySignature = &MessageError{Msg: "kms returned an empty signature"}
	errNilCertificate = &MessageError{Msg: "certificate store returned a nil certificate"}
	errEmptyCertRef   = &MessageError{Msg: "certificate reference is empty"}
)

// ErrDBSignerUnavailable indicates the server-side KMS crypto client or CA
// certificate store could not be resolved to back remote signing.
type ErrDBSignerUnavailable struct {
	Reason string
}

// Error returns the error message.
func (e ErrDBSignerUnavailable) Error() string {
	return "daemon: remote db key signer unavailable: " + e.Reason
}

// ErrDBSignerKeyRef indicates the supplied key reference is empty or unusable.
type ErrDBSignerKeyRef struct {
	Ref string
}

// Error returns the error message.
func (e ErrDBSignerKeyRef) Error() string {
	return fmt.Sprintf("daemon: invalid db key reference %q", e.Ref)
}

// ErrUnsupportedDigest indicates the digest length does not map to a supported
// hash algorithm (SHA-256/384/512).
type ErrUnsupportedDigest struct {
	Len int
}

// Error returns the error message.
func (e ErrUnsupportedDigest) Error() string {
	return fmt.Sprintf("daemon: unsupported digest length %d (want 32, 48, or 64)", e.Len)
}

// ErrDBSign indicates the KMS failed to sign the digest.
type ErrDBSign struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrDBSign) Error() string {
	return fmt.Sprintf("daemon: db key %q signing failed: %v", e.KeyID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrDBSign) Unwrap() error {
	return e.Cause
}

// ErrDBCert indicates the companion DB certificate could not be resolved.
type ErrDBCert struct {
	Ref   string
	Cause error
}

// Error returns the error message.
func (e ErrDBCert) Error() string {
	return fmt.Sprintf("daemon: db certificate %q unavailable: %v", e.Ref, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrDBCert) Unwrap() error {
	return e.Cause
}
