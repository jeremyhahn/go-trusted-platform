package pkcs8

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type SignerRSA struct {
	keyStore      keystore.KeyStorer
	signerStore   store.SignerStorer
	keyAttributes keystore.KeyAttributes
	pub           crypto.PublicKey
	crypto.Signer
}

func NewSignerRSA(
	keyStore keystore.KeyStorer,
	signerStore store.SignerStorer,
	keyAttributes keystore.KeyAttributes,
	publicKey crypto.PublicKey) crypto.Signer {

	return SignerRSA{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
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
	signerOpts, ok := opts.(keystore.SignerOpts)
	if ok {

		hashFunc := signerOpts.HashFunc()

		// Load the signer opts private key
		privateKey, err := signer.keyStore.Key(signerOpts.KeyAttributes)
		if err != nil {
			return nil, err
		}

		// Cast blob signer to RSA private key
		rsaPriv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyRSA
		}

		// Sign using PSS if options provided
		if signerOpts.PSSOptions != nil {
			signature, err = rsa.SignPSS(
				rand, rsaPriv, hashFunc, signerOpts.Digest(), signerOpts.PSSOptions)
		} else {
			// Sign using PKCS1v15
			signature, err = rsa.SignPKCS1v15(
				rand, rsaPriv, hashFunc, signerOpts.Digest())
		}
		if err != nil {
			return nil, err
		}

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(
				signerOpts, signature, signerOpts.Digest()); err != nil {

				return nil, err
			}
		}

		return signature, nil
	}

	// No key store / blob opts, sign using the key attributes,
	// hash function, and opts provided to the signer.
	privateKey, err := signer.keyStore.Key(signer.keyAttributes)
	if err != nil {
		return nil, err
	}

	rsaPriv, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, keystore.ErrInvalidPrivateKeyRSA
	}

	// Sign using RSA PSS if provided PSS options
	switch opts.(type) {
	case *rsa.PSSOptions:
		// RSA-PSS
		signature, err = rsa.SignPSS(
			rand, rsaPriv, opts.HashFunc(), digest, opts.(*rsa.PSSOptions))
	default:
		// Default to PKCS1v15
		if opts == nil {
			opts = signer.keyAttributes.Hash
		}
		signature, err = rsa.SignPKCS1v15(
			rand, rsaPriv, opts.HashFunc(), digest)
	}
	if err != nil {
		return nil, err
	}

	return signature, nil
}
