package registry

import (
	"context"
	"crypto/sha256"
	"fmt"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

// Signature algorithm names the registry records on a signed manifest.
// The signed value is the SHA-256 digest of the manifest signing payload;
// an ECDSA signature is ASN.1 DER, as a crypto.Signer returns it.
const (
	SignatureAlgorithmECDSAP256SHA256 = "ECDSA-P256-SHA256"
	SignatureAlgorithmECDSAP384SHA256 = "ECDSA-P384-SHA256"
)

// sdkSignatureAlgorithms maps the SDK key algorithms the registry signs
// manifests with to the algorithm name recorded on the manifest. Any other
// algorithm (a symmetric key, RSA, Ed25519) is refused.
var sdkSignatureAlgorithms = map[kms.KeyAlgorithm]string{
	kms.AlgorithmECDSAP256: SignatureAlgorithmECDSAP256SHA256,
	kms.AlgorithmECDSAP384: SignatureAlgorithmECDSAP384SHA256,
}

// SDKKeyReader is the part of the quicbaas SDK KMS client the signer needs:
// the metadata of the key a push names.
type SDKKeyReader interface {
	GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error)
}

// SDKSignClient is the part of the quicbaas SDK crypto client the signer
// needs: a signature by a KMS-held key.
type SDKSignClient interface {
	Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error)
}

// SDKSigner is the registry's SigningKMSClient over the quicbaas SDK. It
// signs with the KMS key a push names (PushOptions.SigningKeyID), so the
// key's own policies and lifecycle govern every manifest signature. It
// never creates a key: a push that names a missing key, or a key that is
// not an ECDSA P-256 or P-384 key, is refused.
type SDKSigner struct {
	keys   SDKKeyReader
	crypto SDKSignClient
}

// NewSDKSigner returns a signer over the SDK's KMS and crypto clients,
// usually client.Security().KMS() and client.Security().Crypto().
func NewSDKSigner(keys SDKKeyReader, crypto SDKSignClient) (*SDKSigner, error) {
	if keys == nil || crypto == nil {
		return nil, ErrSigningClientRequired{}
	}
	return &SDKSigner{keys: keys, crypto: crypto}, nil
}

// Sign signs a SHA-256 digest with the SDK KMS key keyID and returns the
// signature with the algorithm name it was made with.
func (s *SDKSigner) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if keyID == "" {
		return nil, "", ErrInvalidSigningRequest{Reason: "signing key ID cannot be empty"}
	}
	if len(digest) != sha256.Size {
		return nil, "", ErrInvalidSigningRequest{Reason: fmt.Sprintf("signing digest must be %d bytes, got %d", sha256.Size, len(digest))}
	}
	info, err := s.keys.GetKey(ctx, keyID)
	if err != nil {
		return nil, "", ErrSigningKeyUnavailable{KeyID: keyID, Err: err}
	}
	if info == nil {
		return nil, "", ErrSigningKeyUnavailable{KeyID: keyID}
	}
	algorithm, ok := sdkSignatureAlgorithms[info.Algorithm]
	if !ok {
		return nil, "", ErrSigningKeyUnsupported{KeyID: keyID, Reason: fmt.Sprintf("algorithm %v cannot sign manifests", info.Algorithm)}
	}
	resp, err := s.crypto.Sign(ctx, &quicbaas.SignRequest{
		KeyID:     keyID,
		Data:      digest,
		HashAlg:   quicbaas.HashSHA256,
		PreHashed: true,
	})
	if err != nil {
		return nil, "", &WrappedError{Msg: fmt.Sprintf("registry: sign with key %s", keyID), Err: err}
	}
	if resp == nil || len(resp.Signature) == 0 {
		return nil, "", &MessageError{Msg: fmt.Sprintf("registry: SDK returned no signature for key %s", keyID)}
	}
	return resp.Signature, algorithm, nil
}
