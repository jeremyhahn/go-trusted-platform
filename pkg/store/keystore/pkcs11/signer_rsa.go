package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/ThalesIgnite/crypto11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type SignerRSA struct {
	keyStore      keystore.KeyStorer
	signerStore   keystore.SignerStorer
	keyAttributes *keystore.KeyAttributes
	pub           crypto.PublicKey
	ctx           *crypto11.Context
	crypto.Signer
}

func NewSignerRSA(
	signerStore keystore.SignerStorer,
	keyAttributes *keystore.KeyAttributes,
	publicKey crypto.PublicKey,
	ctx *crypto11.Context,
	keyStore keystore.KeyStorer) crypto.Signer {

	return SignerRSA{
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
		ctx:           ctx,
		keyStore:      keyStore,
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

	var pssOpts *rsa.PSSOptions

	pkcs11Signer, err := signer.ctx.FindKeyPair(
		createID(signer.keyAttributes), nil)
	if err != nil {
		return nil, err
	}

	switch opts.(type) {
	case *keystore.SignerOpts:
		pssOpts = opts.(*keystore.SignerOpts).PSSOptions
		if pssOpts == nil {
			signature, err = pkcs11Signer.Sign(rand, digest, opts.HashFunc())
		} else {
			signature, err = pkcs11Signer.Sign(rand, digest, pssOpts)
		}
		if opts.(*keystore.SignerOpts).BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(
				opts, signature, digest); err != nil {

				return nil, err
			}
		}
	case *rsa.PSSOptions:
		signature, err = pkcs11Signer.Sign(rand, digest, opts)
	default:
		signature, err = pkcs11Signer.Sign(rand, digest, signer.keyAttributes.Hash)
	}
	if err != nil {
		return nil, err
	}

	return signature, nil
}
