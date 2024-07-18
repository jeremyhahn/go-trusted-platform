package store

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type FSExtension string
type Partition string

const (
	PARTITION_CA                   Partition = ""
	PARTITION_TRUSTED_ROOT         Partition = "trusted-root"
	PARTITION_TRUSTED_INTERMEDIATE Partition = "trusted-intermediate"
	PARTITION_TLS                  Partition = "issued"
	PARTITION_REVOKED              Partition = "revoked"
	PARTITION_CRL                  Partition = "crl"
	PARTITION_SIGNED_BLOB          Partition = "blobs"
	PARTITION_ENCRYPTION_KEYS      Partition = "encryption-keys"
	PARTITION_SIGNING_KEYS         Partition = "signing-keys"

	FSEXT_CA_BUNDLE_PEM     FSExtension = ".bundle.crt"
	FSEXT_PRIVATE_PKCS8     FSExtension = ".pkcs8"
	FSEXT_PRIVATE_PKCS8_PEM FSExtension = ".pkcs8.crt"
	FSEXT_PUBLIC_PKCS1      FSExtension = ".pub.pkcs1"
	FSEXT_PUBLIC_PEM        FSExtension = ".pub.crt"
	FSEXT_CSR               FSExtension = ".csr"
	FSEXT_PEM               FSExtension = ".crt"
	FSEXT_DER               FSExtension = ".cer"
	FSEXT_CRL               FSExtension = ".crl"
	FSEXT_SIG               FSExtension = ".signature"
	FSEXT_DIGEST            FSExtension = ".digest"
	FSEXT_BLOB              FSExtension = ""
)

var (
	ErrInvalidPassword      = errors.New("store: invalid password")
	ErrInvalidKeyPartition  = errors.New("store: invalid key partition")
	ErrInvalidX509Partition = errors.New("store: invalid x509 partition")
	ErrInvalidEncodingPEM   = errors.New("store: invalid PEM encoding")
)

func FSHashName(hash crypto.Hash) string {
	name := strings.ToLower(hash.String())
	name = strings.ReplaceAll(name, "-", "")
	return strings.ReplaceAll(name, "/", "")
}

func FSEXTKeyAlgorithm(algo x509.PublicKeyAlgorithm) string {
	return fmt.Sprintf(".%s", strings.ToLower(algo.String()))
}

func FSKeyExtension(attrs keystore.KeyAttributes, ext FSExtension) string {
	return fmt.Sprintf("%s%s", FSEXTKeyAlgorithm(attrs.KeyAlgorithm), ext)
}

// Converts a hash function name to a file extension. Used to
// save a signed digest file with an appropriate file extension
// to the blob store.
func HashFileExtension(hash crypto.Hash) string {
	return fmt.Sprintf(".%s", FSHashName(hash))
}
