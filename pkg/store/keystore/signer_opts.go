package keystore

import (
	"crypto"
	"crypto/rsa"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

type SignerOpts struct {
	KeyAttributes KeyAttributes

	// Optional PSS Salt Length when using RSA PSS.
	// Default rsa.PSSSaltLengthAuto
	PSSOptions *rsa.PSSOptions
	BlobCN     *string
	BlobData   []byte

	digest    []byte
	blobStore blobstore.BlobStorer
	crypto.SignerOpts
}

func NewSignerOpts(
	attrs KeyAttributes,
	data []byte) (SignerOpts, error) {

	digest, err := Digest(attrs.Hash, data)
	if err != nil {
		return SignerOpts{}, err
	}
	return SignerOpts{
		KeyAttributes: attrs,
		digest:        digest,
	}, nil
}

func (opts SignerOpts) HashFunc() crypto.Hash {
	return opts.KeyAttributes.Hash
}

func (opts SignerOpts) Digest() []byte {
	return opts.digest
}
