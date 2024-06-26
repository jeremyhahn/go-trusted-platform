package tpm2

import (
	"crypto"
	"log"

	"github.com/google/go-tpm/tpm2"
)

// HashAlg identifies a hashing Algorithm.
type HashAlg uint8

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(tpm2.TPMAlgSHA1)
	HashSHA256 = HashAlg(tpm2.TPMAlgSHA256)
)

func (a HashAlg) cryptoHash() crypto.Hash {
	switch a {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	default:
		log.Fatalf("unsupported algorithm: %+v", a)
	}
	return 0
}

// func (a HashAlg) tpmAlg() tpm2.TPMAlgID {
// 	switch a {
// 	case HashSHA1:
// 		return tpm2.TPMAlgSHA1
// 	case HashSHA256:
// 		return tpm2.TPMAlgSHA256
// 	default:
// 		log.Fatalf("unsupported algorithm: %+v", a)
// 	}
// 	return 0
// }

// // String returns a human-friendly representation of the hash algorithm.
// func (a HashAlg) String() string {
// 	switch a {
// 	case HashSHA1:
// 		return "SHA1"
// 	case HashSHA256:
// 		return "SHA256"
// 	}
// 	return fmt.Sprintf("HashAlg<%d>", int(a))
// }
