package pkcs11

import (
	"crypto"
	"io"

	"github.com/ThalesIgnite/crypto11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type SignerECDSA struct {
	keyStore      keystore.KeyStorer
	signerStore   keystore.SignerStorer
	keyAttributes *keystore.KeyAttributes
	pub           crypto.PublicKey
	ctx           *crypto11.Context
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
	ctx *crypto11.Context,
	publicKey crypto.PublicKey) crypto.Signer {

	return SignerECDSA{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
		ctx:           ctx,
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

	pkcs11Signer, err := signer.ctx.FindKeyPair(
		createID(signer.keyAttributes), nil)
	if err != nil {
		return nil, err
	}

	signature, err = pkcs11Signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	// Try to parse as platform blob signer opts
	signerOpts, ok := opts.(*keystore.SignerOpts)
	if ok {

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(signerOpts, signature, digest); err != nil {
				return nil, err
			}
		}

		return signature, nil
	}

	return signature, nil
}
