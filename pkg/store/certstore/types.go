package certstore

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/op/go-logging"
)

type FSExtension string
type Partition string

var (
	ErrFileAlreadyExists           = errors.New("store/x509: file already exists")
	ErrMissingDistributionPointURL = errors.New("store/x509: missing distribution point URL")

	Partitions = []Partition{
		PARTITION_ROOT,
		PARTITION_TRUSTED_ROOT,
		PARTITION_TRUSTED_INTERMEDIATE,
		PARTITION_ISSUED,
		PARTITION_CRL,
	}

	PARTITION_ROOT                 Partition = ""
	PARTITION_TRUSTED_ROOT         Partition = "trusted-root"
	PARTITION_TRUSTED_INTERMEDIATE Partition = "trusted-intermediate"
	PARTITION_ISSUED               Partition = "issued"
	PARTITION_CRL                  Partition = "crl"

	FSEXT_CA_BUNDLE_PEM FSExtension = ".bundle.crt"
	FSEXT_CSR           FSExtension = ".csr"
	FSEXT_PEM           FSExtension = ".crt"
	FSEXT_DER           FSExtension = ".cer"
	FSEXT_CRL           FSExtension = ".crl"
)

type CertificateBackend interface {
	ImportCertificate(id []byte, certificate *x509.Certificate) error
	Get(id []byte) (*x509.Certificate, error)
	DeleteCertificate(id []byte) error
}

type CertificateStorer interface {
	CRLs(certificate *x509.Certificate) ([]*x509.RevocationList, error)
	Get(keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error)
	ImportCertificate(certificate *x509.Certificate) error
	ImportCRL(cn string, crlDER []byte) error
	IsRevoked(certificate *x509.Certificate, issuerCert *x509.Certificate) (bool, error)
	IsRevokedAtDistributionPoints(certificate *x509.Certificate) (bool, error)
	Revoke(certificate *x509.Certificate, issuerCert *x509.Certificate, signer crypto.Signer) error
	Save(certificate *x509.Certificate, partition Partition) error
}

var (
	ErrTrustExists                  = errors.New("store/x509: certificate already trusted")
	ErrInvalidPartition             = errors.New("store/x509: invalid file system partition")
	ErrInvalidType                  = errors.New("store/x509: invalid type")
	ErrInvalidAlgorithm             = errors.New("store/x509: invalid algorithm")
	ErrInvalidEncodingPEM           = errors.New("store/x509: invalid PEM encoding")
	ErrInvalidPassword              = errors.New("store/x509: invalid password")
	ErrExpiredCRL                   = errors.New("store/x509: certificate revocation list expired")
	ErrCRLNotFound                  = errors.New("store/x509: certificate revocation list not found")
	ErrCertNotFound                 = errors.New("store/x509: certificate not found")
	ErrCertInvalid                  = errors.New("store/x509: certificate invalid")
	ErrCertRevoked                  = errors.New("store/x509: certificate revoked")
	ErrInvalidIssuingURL            = errors.New("store/x509: invalid issuing URL")
	ErrInvalidAttributes            = errors.New("store/x509: invalid x509 attributes")
	ErrInvalidSerialNumber          = errors.New("store/x509: invalid serial number")
	ErrInvalidCertificateAttributes = errors.New("store/x509: invalid certificate attributes")
)

func ParseKeyStoreType(certificate *x509.Certificate) (keystore.StoreType, error) {
	for _, ext := range certificate.Extensions {

		if ext.Id.Equal(common.OIDTPKeyStore) {
			return keystore.ParseStoreType(fmt.Sprintf("%s", ext.Value))
		}
	}
	return "", keystore.ErrInvalidKeyStore
}

func ParseKeyType(certificate *x509.Certificate) (keystore.KeyType, error) {
	if certificate.IsCA {
		return keystore.KEY_TYPE_CA, nil
	}
	for _, ext := range certificate.Extensions {

		if ext.Id.Equal(common.OIDTCGManufacturer) ||
			ext.Id.Equal(common.OIDTCGModel) ||
			ext.Id.Equal(common.OIDTCGVersion) {

			return keystore.KEY_TYPE_ENDORSEMENT, nil
		}
	}
	// return 0, keystore.ErrInvalidKeyType
	return keystore.KEY_TYPE_TLS, nil
}

func ParseCertificateID(certificate *x509.Certificate, partition *Partition) ([]byte, error) {

	ext := FSEXT_DER
	if partition != nil && *partition == PARTITION_CRL {
		ext = FSEXT_CRL
	}

	ksType, err := ParseKeyStoreType(certificate)
	if err != nil {
		ksType = keystore.STORE_UNKNOWN
	}

	// Naming convention: common_name.key_store.key_algorithm.cer
	id := fmt.Sprintf("%s.%s.%s%s",
		certificate.Subject.CommonName,
		ksType,
		strings.ToLower(certificate.PublicKeyAlgorithm.String()),
		ext)

	return []byte(id), nil
}

func KeyAttributesFromCertificate(certificate *x509.Certificate) (*keystore.KeyAttributes, error) {
	hash, err := keystore.ParseHashFromSignatureAlgorithm(&certificate.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	keyType, err := ParseKeyType(certificate)
	if err != nil {
		return nil, err
	}
	storeType, err := ParseKeyStoreType(certificate)
	if err != nil {
		storeType = keystore.STORE_UNKNOWN
	}
	return &keystore.KeyAttributes{
		CN:                 certificate.Subject.CommonName,
		KeyAlgorithm:       certificate.PublicKeyAlgorithm,
		Hash:               hash,
		KeyType:            keyType,
		SignatureAlgorithm: certificate.SignatureAlgorithm,
		StoreType:          storeType,
	}, nil
}

func DebugCertificate(logger *logging.Logger, cert *x509.Certificate) {
	logger.Debug("X509 Certificate")
	logger.Debugf("  Common Name: %s", cert.Subject.CommonName)
	logger.Debugf("  Serial Number: %s", cert.SerialNumber.String())
	logger.Debugf("  Key Algorithm: %s", cert.PublicKeyAlgorithm.String())
	logger.Debugf("  Signature Algorithm: %s", cert.SignatureAlgorithm.String())

	logger.Debugf("  Issuer Common Name: %s", cert.Issuer.CommonName)
	logger.Debugf("  Issuer Serial Number: %s", cert.Issuer.SerialNumber)

	for i, dns := range cert.DNSNames {
		logger.Debugf("  dns.%d: %s", i, dns)
	}

	for i, ip := range cert.IPAddresses {
		logger.Debugf("  ip.%d: %s", i, ip)
	}

	for i, email := range cert.EmailAddresses {
		logger.Debugf("  email.%d: %s", i, email)
	}

	logger.Debugf("  Signature: %s", cert.Signature)
	logger.Debugf("  Public Key: %+v", cert.PublicKey)

	pem, err := EncodePEM(cert.Raw)
	if err != nil {
		logger.Error(err)
	}
	logger.Debugf("PEM: \n%s", string(pem))
}

func PrintCertificate(certificate *x509.Certificate) {
	if certificate == nil {
		return
	}

	storeType, _ := ParseKeyStoreType(certificate)

	fmt.Println("X509 Certificate")
	fmt.Printf("  Common Name: %s\n", certificate.Subject.CommonName)
	fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber.String())
	fmt.Printf("  Key Store: %s\n", storeType)
	fmt.Printf("  Key Algorithm: %s\n", certificate.PublicKeyAlgorithm.String())
	fmt.Printf("  Signature Algorithm: %s\n",
		certificate.SignatureAlgorithm.String())

	fmt.Printf("  Issuer Common Name: %s\n", certificate.Issuer.CommonName)
	fmt.Printf("  Issuing Certificate URL: %s\n",
		strings.Join(certificate.IssuingCertificateURL, ", "))

	for i, dns := range certificate.DNSNames {
		fmt.Printf("  dns.%d: %s\n", i, dns)
	}

	for i, ip := range certificate.IPAddresses {
		fmt.Printf("  ip.%d: %s\n", i, ip)
	}

	for i, email := range certificate.EmailAddresses {
		fmt.Printf("  email.%d: %s\n", i, email)
	}

	fmt.Printf("  Signature: %s\n", hex.EncodeToString(certificate.Signature))
	fmt.Printf("  Public Key: %+v\n", certificate.PublicKey)
}
