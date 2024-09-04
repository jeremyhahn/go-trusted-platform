package keystore

import (
	"crypto"
	"io"
)

type OpaqueKey interface {
	Digest(data []byte) ([]byte, error)
	KeyAttributes() *KeyAttributes
	crypto.PrivateKey
	crypto.Signer
	crypto.Decrypter
}

type Opaque struct {
	keyStore KeyStorer
	attrs    *KeyAttributes
	pub      crypto.PublicKey
}

// Create an opaque private key backed by the underlying key store
func NewOpaqueKey(
	keyStore KeyStorer,
	attrs *KeyAttributes,
	pub crypto.PublicKey) OpaqueKey {

	return &Opaque{
		keyStore: keyStore,
		attrs:    attrs,
		pub:      pub,
	}
}

// Returns the public half of the opaque key
// Implements crypto.Signer
// https://pkg.go.dev/crypto#Signer
func (opaque *Opaque) Public() crypto.PublicKey {
	return opaque.pub
}

// Implements crypto.Signer
// https://pkg.go.dev/crypto#Signer
func (opaque *Opaque) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	var signer crypto.Signer
	signerOpts, ok := opts.(SignerOpts)
	if ok {
		// Sign using the provided signing key
		signer, err = opaque.keyStore.Signer(signerOpts.KeyAttributes)
	} else {
		// Sign using the CA's private key
		signer, err = opaque.keyStore.Signer(opaque.attrs)
	}
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, opts)
}

// Implements crypto.Decrypter
// https://pkg.go.dev/crypto#Decrypter
func (opaque *Opaque) Decrypt(
	rand io.Reader,
	msg []byte,
	opts crypto.DecrypterOpts) (plaintext []byte, err error) {

	var decrypter crypto.Decrypter
	decrypterOpts, ok := opts.(DecrypterOpts)
	if ok {
		decrypter, err = opaque.keyStore.Decrypter(
			decrypterOpts.EncryptAttributes)
	} else {
		decrypter, err = opaque.keyStore.Decrypter(opaque.attrs)
	}
	if err != nil {
		return nil, err
	}
	return decrypter.Decrypt(rand, msg, opts)
}

// Implements crypto.PrivateKey
// https://pkg.go.dev/crypto#PrivateKey
func (opaque *Opaque) Equal(x crypto.PrivateKey) bool {
	return opaque.keyStore.Equal(*opaque, x)
}

// Creates a digest using the hash function defined by the key's
// signing attributes
func (opaque *Opaque) Digest(data []byte) ([]byte, error) {
	return Digest(opaque.attrs.Hash, data)
}

// Returns the opaque key's attributes
func (opaque *Opaque) KeyAttributes() *KeyAttributes {
	return opaque.attrs
}
