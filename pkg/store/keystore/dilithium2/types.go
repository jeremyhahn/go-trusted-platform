//go:build quantum_safe

package dilithium2

import "crypto/x509"

type Dilithium2KeyAlgorithm x509.PublicKeyAlgorithm

func (pka Dilithium2KeyAlgorithm) String() string {
	return "Dilithium2"
}

type Dilithium2SignatureAlgorithm int

func (pka Dilithium2SignatureAlgorithm) String() string {
	return "Dilithium2"
}
