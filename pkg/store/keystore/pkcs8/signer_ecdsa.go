package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type SignerECDSA struct {
	keyStore      keystore.KeyStorer
	signerStore   store.SignerStorer
	blobStore     blobstore.BlobStorer
	keyAttributes keystore.KeyAttributes
	pub           crypto.PublicKey
	crypto.Signer
}

// Signer that uses the Elliptical Curve Cryptography Digital Signature
// Algorithm (ECDSA).
//
// Signs the requested data using the Certificate Authority Private Key, or,
// optionally, the private key provided via SignerOpts during the call to Sign.
func NewSignerECDSA(
	keyStore keystore.KeyStorer,
	signerStore store.SignerStorer,
	keyAttributes keystore.KeyAttributes,
	publicKey crypto.PublicKey) crypto.Signer {

	return SignerECDSA{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
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
	signerOpts, ok := opts.(keystore.SignerOpts)
	if ok {

		// Load the blob signing key
		blobSigner, err := signer.keyStore.Key(signerOpts.KeyAttributes)
		if err != nil {
			return nil, err
		}

		ecdsaPriv, ok := blobSigner.(*ecdsa.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyECDSA
		}

		// Sign the digest
		signature, err = ecdsa.SignASN1(rand, ecdsaPriv, signerOpts.Digest())
		if err != nil {
			return nil, err
		}

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(signerOpts, signature, digest); err != nil {
				return nil, err
			}
		}

		return signature, nil
	}

	// No key store / blob opts, sign using the key attributes
	// provided to the signer.
	privateKey, err := signer.keyStore.Key(signer.keyAttributes)
	if err != nil {
		return nil, err
	}

	eccPriv, isECDSA := privateKey.(*ecdsa.PrivateKey)
	if !isECDSA {
		return nil, keystore.ErrInvalidPrivateKeyECDSA
	}

	// Sign the digest
	signature, err = ecdsa.SignASN1(rand, eccPriv, digest)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
