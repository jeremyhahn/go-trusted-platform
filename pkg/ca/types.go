package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	ErrInvalidPartition   = errors.New("certificate-authority: invalid file system partition")
	ErrInvalidKeyType     = errors.New("certificate-authority: invalid key type")
	ErrInvalidAlgorithm   = errors.New("certificate-authority: invalid algorithm")
	ErrInvalidEncodingPEM = errors.New("certificate-authority: invalid PEM encoding")
	ErrInvalidPassword    = errors.New("certificate-authority: invalid password")
	ErrExpiredCRL         = errors.New("certificate-authority: certificate revocation list expired")
	ErrCertNotFound       = errors.New("certificate-authority: certificate not found")
	ErrCertInvalid        = errors.New("certificate-authority: certificate invalid")
	ErrCertRevoked        = errors.New("certificate-authority: certificate revoked")
	ErrInvalidIssuingURL  = errors.New("certificate-authority: invalid issuing URL")
)

type CertificateRequest struct {
	SANS          *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject       Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid         int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
	KeyAttributes *keystore.KeyAttributes  `yaml:"-" json:"-" mapstructure:"-"`
}

type OSTrustStore interface {
	Install(cn string) error
	Uninstall(cn string) error
}

type CertificateStorer interface {
	Append(keystore.KeyAttributes, []byte, store.Partition, store.FSExtension) error
	CACertificate(cn string) (*x509.Certificate, error)
	Certificates(caAttrs keystore.KeyAttributes, partition store.Partition) ([][]byte, error)
	Get(attrs keystore.KeyAttributes, extension store.FSExtension, partition *store.Partition) ([]byte, error)
	HasCRL(attrs keystore.KeyAttributes) bool
	IsRevoked(attrs keystore.KeyAttributes, serialNumber *big.Int) (bool, error)
	IsRevokedAtDistributionPoints(caKeyAttrs keystore.KeyAttributes, serialNumber *big.Int) (bool, error)
	PubKey(attrs keystore.KeyAttributes) (crypto.PublicKey, error)
	PubKeyPEM(attrs keystore.KeyAttributes) ([]byte, error)
	Revoke(attrs keystore.KeyAttributes, cert *x509.Certificate, issuerCert *x509.Certificate, signer crypto.Signer) error
	RootCertForCA(attrs keystore.KeyAttributes) (*x509.Certificate, error)
	Save(attrs keystore.KeyAttributes, data []byte, extension store.FSExtension, partition *store.Partition) error
	TrustedIntermediate(cn string) ([]byte, error)
	TrustedIntermediateCertPool(caAttrs keystore.KeyAttributes) (*x509.CertPool, error)
	TrustedCertificateFor(leaf *x509.Certificate) (*x509.Certificate, error)
	TrustedRoot(attrs keystore.KeyAttributes, extension store.FSExtension) ([]byte, error)
	TrustedRootCertPool(caAttrs keystore.KeyAttributes, includeSystemRoot bool) (*x509.CertPool, error)
	TrustedRootCerts(attrs keystore.KeyAttributes) ([]*x509.Certificate, error)
	TrustsCA(attrs keystore.KeyAttributes, partition store.Partition) error
}
