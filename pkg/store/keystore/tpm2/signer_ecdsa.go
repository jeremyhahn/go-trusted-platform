package tpm2

import (
	"crypto"
	"io"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type SignerECDSA struct {
	keyStore      keystore.KeyStorer
	signerStore   keystore.SignerStorer
	blobStore     blobstore.BlobStorer
	keyAttributes *keystore.KeyAttributes
	pub           crypto.PublicKey
	tpm           tpm2.TrustedPlatformModule
	crypto.Signer
}

// Signer that uses the Elliptical Curve Cryptography Digital Signature
// Algorithm (ECDSA).
//
// Signs the requested data using the Certificate Authority Private Key, or,
// optionally, the private key provided via SignerOpts during the call to Sign.
func NewSignerECDSA(
	keyStore keystore.KeyStorer,
	signerStore keystore.SignerStorer,
	keyAttributes *keystore.KeyAttributes,
	publicKey crypto.PublicKey,
	tpm tpm2.TrustedPlatformModule) crypto.Signer {

	return SignerECDSA{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
		tpm:           tpm,
	}
}

// Returns the public half of the signing key
func (signer SignerECDSA) Public() crypto.PublicKey {
	return signer.pub
}

// Signs the requested digest using the PKCS #8 private key
func (signer SignerECDSA) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	// Try to parse as platform blob signer opts
	signerOpts, ok := opts.(*keystore.SignerOpts)
	if ok {

		opts.(*keystore.SignerOpts).Backend = signer.keyStore.Backend()

		signature, err = signer.tpm.Sign(rand, digest, opts)
		if err != nil {
			return nil, err
		}

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(signerOpts, signature, digest); err != nil {
				return nil, err
			}
		}
	}

	// The TPM sign method needs the key attributes to
	// for authorization
	keyOpts := keystore.NewSignerOpts(signer.keyAttributes, digest)
	keyOpts.Backend = signer.keyStore.Backend()
	return signer.tpm.Sign(rand, digest, keyOpts)
}
