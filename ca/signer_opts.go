package ca

import (
	"crypto"
	"fmt"
)

type SigningOpts struct {
	// Optional PSS Salt Length when using RSA PSS.
	// Default rsa.PSSSaltLengthAuto
	PSSSaltLength  int
	KeyCN          *string
	KeyName        *string
	BlobKey        *string
	BlobData       []byte
	StoreSignature bool

	hash   crypto.Hash
	data   []byte
	digest []byte
}

func NewSigningOpts(hash crypto.Hash, data []byte) (SigningOpts, error) {
	hasher := hash.New()
	n, err := hasher.Write(data)
	if n != len(data) {
		return SigningOpts{}, fmt.Errorf("signer-opts: bytes written doesnt match data length")
	}
	if err != nil {
		return SigningOpts{}, err
	}
	digest := hasher.Sum(nil)
	return SigningOpts{
		hash:   hash,
		data:   data,
		digest: digest[:],
	}, nil
}

func (opts SigningOpts) HashFunc() crypto.Hash {
	return opts.hash
}

func (opts SigningOpts) Digest() []byte {
	return opts.digest
}
