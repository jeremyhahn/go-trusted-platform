package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
)

type FSExtension string
type Partition string

const (
	PARTITION_CA                   Partition = ""
	PARTITION_TRUSTED_ROOT                   = "trusted-root"
	PARTITION_TRUSTED_INTERMEDIATE           = "trusted-intermediate"
	PARTITION_PUBLIC_KEYS                    = "public-keys"
	PARTITION_ISSUED                         = "issued"
	PARTITION_REVOKED                        = "revoked"
	PARTITION_CRL                            = "crl"
	PARTITION_SIGNED_BLOB                    = "blobs"
	PARTITION_ENCRYPTION_KEYS                = "encryption-keys"
	PARTITION_SIGNING_KEYS                   = "signing-keys"
)

const (
	FSEXT_BLOB          FSExtension = ""
	FSEXT_CA_BUNDLE_PEM             = ".bundle.crt"
	FSEXT_PRIVATE_PKCS8             = ".key.pkcs8"
	FSEXT_PRIVATE_PEM               = ".key"
	FSEXT_PUBLIC_PKCS1              = ".pub.pkcs1"
	FSEXT_PUBLIC_PEM                = ".pub"
	FSEXT_CSR                       = ".csr"
	FSEXT_PEM                       = ".crt"
	FSEXT_DER                       = ".cer"
	FSEXT_CRL                       = ".crl"
	FSEXT_SIG                       = ".sig"
)

var (
	ErrInvalidPartition = errors.New("invalid file system partition")
	ErrExpiredCRL       = errors.New("oudated certificate revocation list")
)

type CertificateRequest struct {
	Valid   int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
	Subject Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	SANS    *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
}

type TrustStore interface {
	Install(cn string) error
	Uninstall(cn string) error
}

type CertificateStore interface {
	Blob(key string) ([]byte, error)
	CAPubPEM() ([]byte, error)
	CAPubKey() (crypto.PublicKey, error)
	CAPrivKey(password []byte) (crypto.PrivateKey, error)
	CACertificate(cn string) (*x509.Certificate, error)
	Certificates(partition Partition) ([][]byte, error)
	EncodePEM(derCert []byte) ([]byte, error)
	PubKey(cn, name string, partition Partition) (crypto.PublicKey, error)
	PubKeyPEM(cn, name string, partition Partition) ([]byte, error)
	PrivKey(cn, keyName string, password []byte, partition Partition) (crypto.PrivateKey, error)
	Get(cn, name string, partition Partition, extension FSExtension) ([]byte, error)
	GetKeyed(cn, key string, partition Partition, extension FSExtension) ([]byte, error)
	Append(cn string, data []byte, partition Partition, extension FSExtension) error
	Save(cn string, data []byte, partition Partition, extension FSExtension) error
	SaveKeyed(cn, key string, data []byte, partition Partition, extension FSExtension) error
	SaveBlob(key string, data []byte) error
	Revoke(cn string, cert *x509.Certificate, password []byte) error
	RootCertForCA(cn string) (*x509.Certificate, error)
	IsRevoked(cn string, serialNumber *big.Int) (bool, error)
	IsRevokedAtDistributionPoints(cn string, serialNumber *big.Int) (bool, error)
	TrustedRoot(cn string) ([]byte, error)
	TrustedIntermediateCertPool() (*x509.CertPool, error)
	TrustedRootCertPool(includeSystemRoot bool) (*x509.CertPool, error)
	TrustedRootCerts() ([]*x509.Certificate, error)
	TrustedIntermediate(cn string) ([]byte, error)
	TrustedCertificateFor(cert *x509.Certificate) (*x509.Certificate, error)
	TrustsCA(cn string, partition Partition) (bool, error)
	HasCRL(cn string) (bool, error)
}
