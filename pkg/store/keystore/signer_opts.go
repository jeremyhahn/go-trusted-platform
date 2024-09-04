package keystore

import (
	"crypto"
	"crypto/rsa"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

type SignerOpts struct {
	Backend       KeyBackend
	KeyAttributes *KeyAttributes

	// Optional PSS Salt Length when using RSA PSS.
	// Default rsa.PSSSaltLengthAuto
	PSSOptions *rsa.PSSOptions
	BlobCN     []byte
	BlobData   []byte

	blobStore blobstore.BlobStorer
	crypto.SignerOpts
}

func NewSignerOpts(
	attrs *KeyAttributes,
	data []byte) *SignerOpts {

	return &SignerOpts{
		KeyAttributes: attrs,
		BlobData:      data,
	}
}

func (opts SignerOpts) HashFunc() crypto.Hash {
	return opts.KeyAttributes.Hash
}

func (opts SignerOpts) Digest() ([]byte, error) {
	digest, err := Digest(opts.KeyAttributes.Hash, opts.BlobData)
	if err != nil {
		return nil, err
	}
	return digest, nil
}
