package certstore

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
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
	GetXSigned(keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error)
	ImportCertificate(certificate *x509.Certificate) error
	ImportXSignedCertificate(certificate *x509.Certificate) error
	ImportCRL(cn string, crlDER []byte) error
	IsRevoked(certificate *x509.Certificate, issuerCert *x509.Certificate) error
	IsRevokedAtDistributionPoints(certificate *x509.Certificate) error
	Issued(cn string) bool
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
	ErrInvalidAttributes            = errors.New("store/x509: invalid x509 attributes")
	ErrInvalidIssuingURL            = errors.New("store/x509: invalid issuing URL")
	ErrInvalidPlatformModel         = errors.New("store/x509: invalid platform model")
	ErrInvalidPlatformSerial        = errors.New("store/x509: invalid platform serial")
	ErrInvalidSerialNumber          = errors.New("store/x509: invalid serial number")
	ErrInvalidCertificateAttributes = errors.New("store/x509: invalid certificate attributes")

	ErrInvalidTPMManufacturer    = errors.New("store/x509: invalid TPM manufacturer OID")
	ErrInvalidTPMModel           = errors.New("store/x509: invalid TPM model OID")
	ErrInvalidTPMVersion         = errors.New("store/x509: invalid TPM version OID")
	ErrInvalidTPMFirmwareVersion = errors.New("store/x509: invalid TPM firmware version OID")
	ErrInvalidFIPS1402           = errors.New("store/x509: invalid FIPS 140-2 OID")
)

func ParseCertificateRequestPermanentIdentifier(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGPermanentIdentifier) {
			return string(ext.Value), nil
		}
	}
	return "", keystore.ErrInvalidPermanentIdentifier
}

func ParseCertificateRequestPlatformModel(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGPlatformModel) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidPlatformModel
}

func ParseCertificateRequestPlatformSerial(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGPlatformSerial) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidPlatformSerial
}

func ParseCertificateRequestTPMManufacturer(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGTPMManufacturer) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidTPMManufacturer
}

func ParseCertificateRequestTPMModel(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGTPMModel) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidTPMModel
}

func ParseCertificateRequestTPMVersion(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGTPMVersion) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidTPMVersion
}

func ParseCertificateRequestTPMFirmwareVersion(csr *x509.CertificateRequest) (string, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTCGTPMFirmwareVersion) {
			return string(ext.Value), nil
		}
	}
	return "", ErrInvalidTPMFirmwareVersion
}

func ParseCertificateRequestTPMFIPS1402(csr *x509.CertificateRequest) (bool, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTPFIPS140) {
			value, err := strconv.ParseBool(string(ext.Value))
			if err != nil {
				return false, err
			}
			return value, nil
		}
	}
	return false, ErrInvalidFIPS1402
}

func ParseCertificateRequestKeyStoreType(csr *x509.CertificateRequest) (keystore.StoreType, error) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(common.OIDTPKeyStore) {
			return keystore.ParseStoreType(fmt.Sprintf("%s", ext.Value))
		}
	}
	return "", keystore.ErrInvalidKeyStore
}

func ParseKeyStoreType(certificate *x509.Certificate) (keystore.StoreType, error) {
	for _, ext := range certificate.Extensions {
		if ext.Id.Equal(common.OIDTPKeyStore) {
			return keystore.ParseStoreType(fmt.Sprintf("%s", ext.Value))
		}
	}
	// return "", keystore.ErrInvalidKeyStore
	return keystore.STORE_UNKNOWN, nil
}

func ParseKeyType(certificate *x509.Certificate) (keystore.KeyType, error) {
	if certificate.IsCA {
		return keystore.KEY_TYPE_CA, nil
	}
	for _, ext := range certificate.Extensions {
		if ext.Id.Equal(common.OIDTCGTPMManufacturer) ||
			ext.Id.Equal(common.OIDTCGTPMModel) ||
			ext.Id.Equal(common.OIDTCGTPMVersion) {

			return keystore.KEY_TYPE_ENDORSEMENT, nil
		}
	}
	// return 0, keystore.ErrInvalidKeyType
	return keystore.KEY_TYPE_TLS, nil
}

func ParseIssuerCN(certificate *x509.Certificate) (string, error) {
	if len(certificate.IssuingCertificateURL) == 0 {
		return "", ErrInvalidIssuingURL
	}

	issuerURL := certificate.IssuingCertificateURL[0]
	urlParts := strings.Split(issuerURL, "/")
	if len(urlParts) < 3 {
		return "", ErrInvalidIssuingURL
	}

	fqdn := urlParts[2]
	return fqdn, nil
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

	// Naming convention: leaf_cn.key_store.key_algorithm.cer
	id := fmt.Sprintf("%s.%s.%s%s",
		certificate.Subject.CommonName,
		ksType,
		strings.ToLower(certificate.PublicKeyAlgorithm.String()),
		ext)

	return []byte(id), nil
}

func ParseXSignedCertificateID(certificate *x509.Certificate, partition *Partition) ([]byte, error) {

	ext := FSEXT_DER
	if partition != nil && *partition == PARTITION_CRL {
		ext = FSEXT_CRL
	}

	ksType, err := ParseKeyStoreType(certificate)
	if err != nil {
		ksType = keystore.STORE_UNKNOWN
	}

	issuerCN, err := ParseIssuerCN(certificate)
	if err != nil {
		return nil, err
	}

	// Naming convention: issuer_cn.leaf_cn.key_store.key_algorithm.cer
	id := fmt.Sprintf("%s/%s.%s.%s%s",
		issuerCN,
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

func ToString(certificate *x509.Certificate) string {

	if certificate == nil {
		return "nil"
	}

	var sb strings.Builder

	sb.WriteString("X509 Certificate\n")
	sb.WriteString(fmt.Sprintf("  Common Name: %s\n", certificate.Subject.CommonName))
	sb.WriteString(fmt.Sprintf("  Serial Number: %x\n", certificate.SerialNumber.Bytes()))
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

	storeType, err := ParseKeyStoreType(certificate)
	if err == nil {
		sb.WriteString("  Key Attributes:\n")
		sb.WriteString(fmt.Sprintf("    Store: %s\n", storeType))
		keyType, err := ParseKeyType(certificate)
		if err == nil {
			sb.WriteString(fmt.Sprintf("    Type: %s\n", keyType))
		}
	}

	return sb.String()

}
