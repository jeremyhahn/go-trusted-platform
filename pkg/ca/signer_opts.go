package ca

import (
	"crypto"
	"fmt"
)

type SignerOpts struct {
	// Optional PSS Salt Length when using RSA PSS.
	// Default rsa.PSSSaltLengthAuto
	PSSSaltLength  int
	KeyCN          *string
	KeyName        *string
	BlobKey        *string
	BlobData       []byte
	StoreSignature bool
	Password       []byte

	hash   crypto.Hash
	data   []byte
	digest []byte
}

func NewSigningOpts(hash crypto.Hash, data []byte) (SignerOpts, error) {
	hasher := hash.New()
	n, err := hasher.Write(data)
	if n != len(data) {
		return SignerOpts{}, fmt.Errorf("signer-opts: bytes written doesnt match data length")
	}
	if err != nil {
		return SignerOpts{}, err
	}
	digest := hasher.Sum(nil)
	return SignerOpts{
		hash:   hash,
		data:   data,
		digest: digest[:],
	}, nil
}

func (opts SignerOpts) HashFunc() crypto.Hash {
	return opts.hash
}

func (opts SignerOpts) Digest() []byte {
	return opts.digest
}
