package ca

import "crypto"

type PKCS8DecrypterOpts struct {
	cn       string
	name     string
	password []byte
	hash     crypto.Hash
	crypto.DecrypterOpts
}

func NewPKCS8DecrypterOpts(cn, name string, password []byte) (PKCS8DecrypterOpts, error) {
	return PKCS8DecrypterOpts{
		cn:       cn,
		name:     name,
		password: password}, nil
}

func (pkcs8 PKCS8DecrypterOpts) HashFunc() crypto.Hash {
	return pkcs8.hash
}
