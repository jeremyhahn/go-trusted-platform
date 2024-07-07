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
	FSEXT_DIGEST                    = ".digest"
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

func SupportedHashes() map[string]crypto.Hash {
	hashes := make(map[string]crypto.Hash)
	hashes["MD4"] = crypto.MD4
	hashes["MD5"] = crypto.MD5
	hashes["SHA1"] = crypto.SHA1
	hashes["SHA224"] = crypto.SHA224
	hashes["SHA256"] = crypto.SHA256
	hashes["SHA384"] = crypto.SHA384
	hashes["SHA512"] = crypto.SHA512
	hashes["MD5SHA1"] = crypto.MD5SHA1
	hashes["RIPEMD160"] = crypto.RIPEMD160
	hashes["SHA3_224"] = crypto.SHA3_224
	hashes["SHA3_256"] = crypto.SHA3_256
	hashes["SHA3_384"] = crypto.SHA3_384
	hashes["SHA3_512"] = crypto.SHA3_512
	hashes["SHA512_224"] = crypto.SHA512_224
	hashes["SHA512_256"] = crypto.SHA512_256
	hashes["BLAKE2s_256"] = crypto.BLAKE2s_256
	hashes["BLAKE2b_256"] = crypto.BLAKE2b_256
	hashes["BLAKE2b_384"] = crypto.BLAKE2b_384
	hashes["BLAKE2b_512"] = crypto.BLAKE2b_512
	return hashes
}

func SupportedSignatureAlgorithms() map[string]x509.SignatureAlgorithm {
	algos := make(map[string]x509.SignatureAlgorithm)
	algos["SHA256WithRSA"] = x509.SHA256WithRSA
	algos["SHA384WithRSA"] = x509.SHA384WithRSA
	algos["SHA512WithRSA"] = x509.SHA512WithRSA
	algos["ECDSAWithSHA256"] = x509.ECDSAWithSHA256
	algos["ECDSAWithSHA384"] = x509.ECDSAWithSHA384
	algos["ECDSAWithSHA512"] = x509.ECDSAWithSHA512
	algos["SHA256WithRSAPSS"] = x509.SHA256WithRSAPSS
	algos["SHA384WithRSAPSS"] = x509.SHA384WithRSAPSS
	algos["SHA512WithRSAPSS"] = x509.SHA512WithRSAPSS
	algos["PureEd25519"] = x509.PureEd25519
	return algos
}
