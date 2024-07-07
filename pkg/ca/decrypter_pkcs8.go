package ca

import (
	"crypto"
	"crypto/rsa"
	"io"
)

type PKCS8Decrypter struct {
	rand       io.Reader
	hash       crypto.Hash
	ca         CertificateAuthority
	privateKey *rsa.PrivateKey
	crypto.Decrypter
}

// Decrypts the requested ciphtertext using a PKCS8 Private Key
func NewPKCS8Decrypter(
	rand io.Reader,
	hash crypto.Hash,
	ca CertificateAuthority,
	privateKey *rsa.PrivateKey) PKCS8Decrypter {

	return PKCS8Decrypter{
		rand:       rand,
		hash:       hash,
		ca:         ca,
		privateKey: privateKey,
	}
}

// Returns the public key used to sign
func (decrypter PKCS8Decrypter) Public() crypto.PublicKey {
	return decrypter.privateKey.PublicKey
}

// Decrypts cipthertext created by a RSA PKCS #8 private key
func (decrypter PKCS8Decrypter) Decrypt(
	rand io.Reader,
	msg []byte,
	opts crypto.DecrypterOpts) (plaintext []byte, err error) {

	return rsa.DecryptOAEP(
		decrypter.hash.New(),
		decrypter.rand,
		decrypter.privateKey,
		msg,
		nil)
}
