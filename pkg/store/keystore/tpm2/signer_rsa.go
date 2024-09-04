package tpm2

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type SignerRSA struct {
	keyStore      keystore.KeyStorer
	signerStore   keystore.SignerStorer
	keyAttributes *keystore.KeyAttributes
	pub           crypto.PublicKey
	tpm           tpm2.TrustedPlatformModule
	crypto.Signer
}

func NewSignerRSA(
	keyStore keystore.KeyStorer,
	signerStore keystore.SignerStorer,
	keyAttributes *keystore.KeyAttributes,
	publicKey crypto.PublicKey,
	tpm tpm2.TrustedPlatformModule) crypto.Signer {

	return SignerRSA{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
		tpm:           tpm,
	}
}

// Returns the public half of the signing key
// implements crypto.Signer
func (signer SignerRSA) Public() crypto.PublicKey {
	return signer.pub
}

// Signs the requested digest using underlying key store
// implements crypto.Signer
func (signer SignerRSA) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	// Try to parse as key store signer opts
	signerOpts, ok := opts.(*keystore.SignerOpts)
	if ok {

		opts.(*keystore.SignerOpts).Backend = signer.keyStore.Backend()

		// signature, err := signer.keyStore.(*KeyStore).Sign(rand, digest, opts)
		signature, err := signer.tpm.Sign(rand, digest, opts)
		if err != nil {
			return nil, err
		}

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(
				signerOpts, signature, digest); err != nil {

				return nil, err
			}
		}

		return signature, nil
	}

	// The TPM sign method needs the key attributes to
	// for authorization
	keyOpts := keystore.NewSignerOpts(signer.keyAttributes, digest)
	switch opts.(type) {
	case *rsa.PSSOptions:
		keyOpts.PSSOptions = opts.(*rsa.PSSOptions)
	}

	keyOpts.Backend = signer.keyStore.Backend()

	return signer.tpm.Sign(rand, digest, keyOpts)
}
