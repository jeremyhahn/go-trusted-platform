package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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
	IsRevoked(certificate *x509.Certificate, issuerCert *x509.Certificate) error
	IsRevokedAtDistributionPoints(certificate *x509.Certificate) error
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

func DebugCertificate(logger *logging.Logger, certificate *x509.Certificate) {
	logger.Debug("X509 Certificate")
	logger.Debugf("  Common Name: %s", certificate.Subject.CommonName)
	logger.Debugf("  Serial Number: %s", certificate.SerialNumber.String())
	logger.Debugf("  Key Algorithm: %s", certificate.PublicKeyAlgorithm.String())
	logger.Debugf("  Signature Algorithm: %s", certificate.SignatureAlgorithm.String())
	logger.Debugf("  Subject Key Identifier: %x", certificate.SubjectKeyId)
	logger.Debugf("  SHA-1 Fingerprint: %x", sha1.Sum(certificate.Raw))

	logger.Debugf("  Issuer Common Name: %s", certificate.Issuer.CommonName)
	logger.Debugf("  Issuer Serial Number: %s", certificate.Issuer.SerialNumber)

	for i, dns := range certificate.DNSNames {
		logger.Debugf("  dns.%d: %s", i, dns)
	}

	for i, ip := range certificate.IPAddresses {
		logger.Debugf("  ip.%d: %s", i, ip)
	}

	for i, email := range certificate.EmailAddresses {
		logger.Debugf("  email.%d: %s", i, email)
	}

	logger.Debugf("  Signature: %s", hex.EncodeToString(certificate.Signature))

	fmt.Println("  Public Key:")
	switch certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		logger.Debugf("    Exponent: %d\n", certificate.PublicKey.(*rsa.PublicKey).E)
		logger.Debugf("    Modulus: %d\n", certificate.PublicKey.(*rsa.PublicKey).N)
	case *ecdsa.PublicKey:
		params := certificate.PublicKey.(*ecdsa.PublicKey).Curve.Params()
		logger.Debugf("    Curve: %s\n", params.Name)
		logger.Debugf("    X: %d\n", certificate.PublicKey.(*ecdsa.PublicKey).X)
		logger.Debugf("    Y: %d\n", certificate.PublicKey.(*ecdsa.PublicKey).Y)
	}

	pem, err := EncodePEM(certificate.Raw)
	if err != nil {
		logger.Error(err)
	}
	logger.Debugf("PEM: \n%s", string(pem))
}

func ToString(certificate *x509.Certificate) string {

	if certificate == nil {
		return "nil"
	}

	var sb strings.Builder

	storeType, _ := ParseKeyStoreType(certificate)

	sb.WriteString("X509 Certificate\n")
	sb.WriteString(fmt.Sprintf("  Common Name: %s\n", certificate.Subject.CommonName))
	sb.WriteString(fmt.Sprintf("  Serial Number: %x\n", certificate.SerialNumber.Bytes()))
	sb.WriteString(fmt.Sprintf("  Key Store: %s\n", storeType))
	sb.WriteString(fmt.Sprintf("  Key Algorithm: %s\n", certificate.PublicKeyAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n",
		certificate.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("  SHA-1 Fingerprint: %x\n", sha1.Sum(certificate.Raw)))
	sb.WriteString(fmt.Sprintf("  Subject Key Identifier: %x\n", certificate.SubjectKeyId))

	sb.WriteString("  Subject Name:\n")
	sb.WriteString(fmt.Sprintf("     Country: %s\n", certificate.Subject.Country[0]))
	sb.WriteString(fmt.Sprintf("     State: %s\n", certificate.Subject.Province[0]))
	sb.WriteString(fmt.Sprintf("     Locality: %s\n", certificate.Subject.Locality[0]))
	sb.WriteString(fmt.Sprintf("     Street: %s\n", certificate.Subject.StreetAddress[0]))
	sb.WriteString(fmt.Sprintf("     Organization: %s\n", certificate.Subject.Organization[0]))
	sb.WriteString(fmt.Sprintf("     Organizational Unit: %s\n", certificate.Subject.OrganizationalUnit[0]))
	sb.WriteString(fmt.Sprintf("     Common Name: %s\n", certificate.Subject.CommonName))

	sb.WriteString("  Issuer Name:\n")
	sb.WriteString(fmt.Sprintf("     Country: %s\n", certificate.Issuer.Country[0]))
	sb.WriteString(fmt.Sprintf("     State: %s\n", certificate.Issuer.Province[0]))
	sb.WriteString(fmt.Sprintf("     Locality: %s\n", certificate.Issuer.Locality[0]))
	sb.WriteString(fmt.Sprintf("     Street: %s\n", certificate.Issuer.StreetAddress[0]))
	sb.WriteString(fmt.Sprintf("     Organization: %s\n", certificate.Issuer.Organization[0]))
	sb.WriteString(fmt.Sprintf("     Organizational Unit: %s\n", certificate.Issuer.OrganizationalUnit[0]))
	sb.WriteString(fmt.Sprintf("     Common Name: %s\n", certificate.Issuer.CommonName))

	sb.WriteString(fmt.Sprintf("  Issuing Certificate URL: %s\n",
		strings.Join(certificate.IssuingCertificateURL, ", ")))

	for i, dns := range certificate.DNSNames {
		sb.WriteString(fmt.Sprintf("  dns.%d: %s\n", i, dns))
	}

	for i, ip := range certificate.IPAddresses {
		sb.WriteString(fmt.Sprintf("  ip.%d: %s\n", i, ip))
	}

	for i, email := range certificate.EmailAddresses {
		sb.WriteString(fmt.Sprintf("  email.%d: %s\n", i, email))
	}

	sb.WriteString(fmt.Sprintf("  Signature: %s\n", hex.EncodeToString(certificate.Signature)))

	sb.WriteString("  Public Key:\n")

	der, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		sb.WriteString(err.Error())
	}
	sb.WriteString(fmt.Sprintf("    SHA-1 Fingerprint: %x\n", sha1.Sum(der)))

	sb.WriteString(keystore.PublicKeyToString(certificate.PublicKey))

	return sb.String()

}
