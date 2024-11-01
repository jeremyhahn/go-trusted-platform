package acme

import "github.com/go-jose/go-jose/v4"

type NonceSource struct {
	value string
	jose.NonceSource
}

func NewNonce(value []byte) NonceSource {
	return NonceSource{value: string(value)}
}

func (nonce NonceSource) Nonce() (string, error) {
	return nonce.value, nil
}
