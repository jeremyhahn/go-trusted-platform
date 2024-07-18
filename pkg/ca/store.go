package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
)

var (
	ErrFileAlreadyExists = errors.New("certificate-store: file already exists")
	ErrFileNotFound      = errors.New("certificcate-store: file not found")
)

type FileSystemCertStore struct {
	logger        *logging.Logger
	backend       store.Backend
	caDir         string
	caCN          string
	retainRevoked bool
	CertificateStorer
}

// Creates a new local file system backed x509 certificate store
func NewFileSystemCertStore(
	logger *logging.Logger,
	backend store.Backend,
	caDir, caCN string,
	retainRevoked bool) (CertificateStorer, error) {

	return FileSystemCertStore{
		logger:        logger,
		backend:       backend,
		caDir:         caDir,
		caCN:          caCN,
		retainRevoked: retainRevoked}, nil
}

func (cs FileSystemCertStore) Save(
	attrs keystore.KeyAttributes,
	data []byte,
	extension store.FSExtension,
	partition *store.Partition) error {

	return cs.backend.Save(attrs, data, extension, partition)
}

func (certstore FileSystemCertStore) Get(
	attrs keystore.KeyAttributes,
	extension store.FSExtension,
	partition *store.Partition) ([]byte, error) {

	return certstore.backend.Get(attrs, extension, partition)
}

// Returns the Root CA certificate for the requested CA certificate by
// recursively loading the certificate chain until the root is found.
func (certstore FileSystemCertStore) RootCertForCA(caAttrs keystore.KeyAttributes) (*x509.Certificate, error) {

	// Assume this is an Intermediate CA calling this function
	// and check the trusted-root partition first
	partition := store.PARTITION_TRUSTED_ROOT
	der, err := certstore.Get(caAttrs, store.FSEXT_DER, &partition)
	if err != nil {
		if err == store.ErrFileNotFound {
			// Try to load the cert from the root CA directory
			der, err = certstore.Get(caAttrs, store.FSEXT_DER, nil)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) || !cert.IsCA {
		caAttrs.Domain = cert.Issuer.CommonName
		caAttrs.CN = cert.Issuer.CommonName
		return certstore.RootCertForCA(caAttrs)
	}
	return cert, nil
}

// Returns a Trusted Root CertPool that contains the Certificate Authority root certificate with
// the options to include the local operating system trusted root certificates.
func (certstore FileSystemCertStore) TrustedRootCertPool(
	caAttrs keystore.KeyAttributes, includeSystemRoot bool) (*x509.CertPool, error) {

	roots := x509.NewCertPool()
	if includeSystemRoot {
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
	}

	// Add all imported trusted root CAs
	trustedRootCerts, err := certstore.TrustedRootCerts(caAttrs)
	if err != nil {
		return nil, err
	}
	for _, cert := range trustedRootCerts {
		pemBytes, err := EncodePEM(cert.Raw)
		if err != nil {
			return nil, ErrCertInvalid
		}
		ok := roots.AppendCertsFromPEM(pemBytes)
		if !ok {
			return nil, ErrCertInvalid
		}
	}

	return roots, nil
}

// Returns a Trusted Intermediate CertPool that contains the Certificate Authority intermediate
// certificate.
func (certstore FileSystemCertStore) TrustedIntermediateCertPool(
	caAttrs keystore.KeyAttributes) (*x509.CertPool, error) {

	intermediates := x509.NewCertPool()

	// Add the Intermediate Certificate Authority certificate first
	partition := store.PARTITION_CA
	intermediatePEM, err := certstore.Get(caAttrs, store.FSEXT_PEM, &partition)
	if err != nil {
		return nil, err
	}
	if ok := intermediates.AppendCertsFromPEM(intermediatePEM); !ok {
		certstore.logger.Error(err)
		return nil, err
	}

	// Add all imported trusted intermediate CAs
	trustedIntermediateCerts, err := certstore.Certificates(caAttrs, store.PARTITION_TRUSTED_INTERMEDIATE)
	if err != nil {
		return nil, err
	}

	for _, cert := range trustedIntermediateCerts {
		pem, err := EncodePEM(cert)
		if err != nil {
			return nil, err
		}
		ok := intermediates.AppendCertsFromPEM(pem)
		if !ok {
			return nil, ErrCertInvalid
		}
	}

	return intermediates, nil
}

// Returns the requested Trusted Root CA certificate
func (certstore FileSystemCertStore) TrustedRoot(
	attrs keystore.KeyAttributes,
	extension store.FSExtension) ([]byte, error) {

	partition := store.PARTITION_TRUSTED_ROOT
	return certstore.Get(attrs, extension, &partition)
}

// Returns a slice containing the Root Certificate Authority certificate and all
// trusted root certiticates that have been imported into the certificate store.
func (certstore FileSystemCertStore) TrustedRootCerts(attrs keystore.KeyAttributes) ([]*x509.Certificate, error) {

	// Get the root CA certificate
	rootCert, err := certstore.RootCertForCA(attrs)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}

	// Get all imported trusted root certificates
	trustedRootCerts, err := certstore.Certificates(attrs, store.PARTITION_TRUSTED_ROOT)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}

	// Create the slice and add the CA Root certificate first
	certs := make([]*x509.Certificate, len(trustedRootCerts)+1)
	certs[0] = rootCert

	// Add all of the imported trusted root certificates
	for i, bytes := range trustedRootCerts {
		cert, err := x509.ParseCertificate(bytes)
		if err != nil {
			return nil, err
		}
		certs[i+1] = cert
	}

	return certs, nil
}

// Returns true if the requested CA certificate exists in the certificate store
// and is trusted by the Certificate Authority.
func (certstore FileSystemCertStore) TrustsCA(attrs keystore.KeyAttributes, partition store.Partition) error {
	_, err := certstore.backend.Get(attrs, store.FSEXT_DER, &partition)
	if err == store.ErrFileNotFound {
		return nil
	}
	return ErrTrustExists
}

// // Returns true if the requested Certificate Revocation List  exists in the certificate store
func (certstore FileSystemCertStore) HasCRL(attrs keystore.KeyAttributes) bool {
	partition := store.PARTITION_CRL
	_, err := certstore.backend.Get(attrs, store.FSEXT_CRL, &partition)
	return err == nil
}

// Returns all PEM form certificates from the specified Certificate Authority
// partition. DER certificates (.cer) are encoded to PEM before being returned.
func (certstore FileSystemCertStore) Certificates(caAttrs keystore.KeyAttributes, partition store.Partition) ([][]byte, error) {
	partitionKey, err := certstore.backend.PartitionKey(caAttrs, &partition)
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(partitionKey)
	if err != nil {
		return nil, err
	}
	certs := make([][]byte, 0)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		pieces := strings.Split(file.Name(), ".")
		ext := store.FSExtension("." + pieces[len(pieces)-1])
		if ext != store.FSEXT_DER {
			continue
		}
		filePath := fmt.Sprintf("%s/%s", partitionKey, file.Name())
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		certs = append(certs, bytes)
	}
	return certs, nil
}

// Returns the RSA Public Key from the underlying key store
// using the provided key attributes
func (certstore FileSystemCertStore) PubKey(attrs keystore.KeyAttributes) (crypto.PublicKey, error) {
	bytes, err := certstore.Get(attrs, store.FSEXT_PUBLIC_PKCS1, nil)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKIXPublicKey(bytes)
}

// Returns and issued RSA Public Key in PEM form, from the issued partition
// for the specified common name.
func (certstore FileSystemCertStore) PubKeyPEM(attrs keystore.KeyAttributes) ([]byte, error) {
	partition := store.PARTITION_TLS
	return certstore.Get(attrs, store.FSEXT_PUBLIC_PEM, &partition)
}

// Appends certificate bytes to an existing certificate file
func (certstore FileSystemCertStore) Append(
	attrs keystore.KeyAttributes,
	data []byte,
	partition store.Partition,
	extension store.FSExtension) error {

	return certstore.backend.Append(attrs, data, extension, &partition)
}

// Returns true if the certificate is found in the local Certificate Authority
// revocation list and if its associated certificates were moved to the revoked partition.
func (certstore FileSystemCertStore) IsRevoked(attrs keystore.KeyAttributes, serialNumber *big.Int) (bool, error) {
	localCRL := fmt.Sprintf("%s/%s%s", certstore.caDir, certstore.caCN, store.FSEXT_CRL)
	revocationList, err := certstore.loadCRL(localCRL)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		certstore.logger.Error(err)
		return false, err
	}
	if revocationList != nil {
		for _, entry := range revocationList.RevokedCertificateEntries {
			if entry.SerialNumber.String() == serialNumber.String() {
				return true, nil
			}
		}
	}
	return false, nil
}

// Returns true if the certificate is found in any of the imported Distrubution
// Point Certificate Revocation Lists.
func (certstore FileSystemCertStore) IsRevokedAtDistributionPoints(
	caKeyAttrs keystore.KeyAttributes,
	serialNumber *big.Int) (bool, error) {

	// Load all distribution point CRLs
	revocationLists, err := certstore.loadCRLs(caKeyAttrs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		certstore.logger.Error(err)
		return false, err
	}
	// Check the CRL's to see if the certificate has been revoked
	for _, revocationList := range revocationLists {
		if revocationList != nil {
			for _, entry := range revocationList.RevokedCertificateEntries {
				if entry.SerialNumber.String() == serialNumber.String() {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Adds the specified certificate to the Certicicate Authority revocation list
// and moves all of the related certificates to the revoked certificates directory.
func (certstore FileSystemCertStore) Revoke(
	attrs keystore.KeyAttributes,
	cert *x509.Certificate,
	issuerCert *x509.Certificate,
	signer crypto.Signer) error {

	// A list of certificates revoked by the local Certificate Authority
	revokedCertificates := make([]x509.RevocationListEntry, 0)

	// Load the local Certiticate Authority's Certiticate Revocation List
	localCRL := fmt.Sprintf("%s/%s%s", certstore.caDir, certstore.caCN, store.FSEXT_CRL)
	revocationList, err := certstore.loadCRL(localCRL)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		certstore.logger.Error(err)
		return err
	}

	// Check to see if the certificate has an entry in the local Certificate Authority CRL
	if revocationList != nil {
		for _, serialNumber := range revocationList.RevokedCertificateEntries {
			if serialNumber.SerialNumber.String() == cert.SerialNumber.String() {
				return ErrCertRevoked
			}
		}
		revokedCertificates = revocationList.RevokedCertificateEntries
	}

	// Create a new revocation entry
	revokedCertificates = append(revokedCertificates,
		x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now()})

	// Create a new revocation list serial number
	serialNumber, err := util.X509SerialNumber()
	if err != nil {
		certstore.logger.Error(err)
		return err
	}

	// Create a new revocation list template
	template := x509.RevocationList{
		SignatureAlgorithm:        issuerCert.SignatureAlgorithm,
		RevokedCertificateEntries: revokedCertificates,
		Number:                    serialNumber,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader,
		&template, issuerCert, signer)
	if err != nil {
		certstore.logger.Error(err)
		return err
	}

	// Save the CRL to the ca partition
	crl := fmt.Sprintf("%s/%s%s", certstore.caDir, certstore.caCN, store.FSEXT_CRL)
	if err = os.WriteFile(crl, crlDER, 0644); err != nil {
		certstore.logger.Error(err)
		return err
	}

	// Get a reference to the "issued" certificates partition
	certDir, err := certstore.backend.PartitionKey(attrs, nil)
	if err != nil {
		certstore.logger.Error(err)
		return err
	}

	// Delete or move certiticates in "issued" to "revoked"
	commonExtensions := []store.FSExtension{
		store.FSEXT_PUBLIC_PEM,
		store.FSEXT_PUBLIC_PKCS1,
		store.FSEXT_PRIVATE_PKCS8,
		store.FSEXT_DER,
		store.FSEXT_PEM,
		store.FSEXT_CSR}
	if certstore.retainRevoked {
		revokedDir := fmt.Sprintf("%s/%s/%s", certstore.caDir, store.PARTITION_REVOKED, attrs.CN)
		for _, ext := range commonExtensions {
			// Include the key algorithm in the file name
			keyExt := certstore.backend.KeyFileExtension(attrs.KeyAlgorithm, ext)
			src := fmt.Sprintf("%s/%s%s", certDir, attrs.CN, keyExt)
			dst := fmt.Sprintf("%s/%s%s", revokedDir, attrs.CN, keyExt)
			if err := os.MkdirAll(revokedDir, fs.ModePerm); err != nil {
				return err
			}
			err = os.Rename(src, dst)
			if err != nil {
				if os.IsNotExist(err) {
					if ext == store.FSEXT_CSR || ext == store.FSEXT_PRIVATE_PKCS8 {
						// ignore errors for missing CSRs. some certs
						// may be generated without them. Ignore errors
						// for private keys because it may be a cert that
						// was generated from CSR or an opaque private key
						continue
					}
				}
				certstore.logger.Error(err)
				return err
			}
		}
	}

	// Delete the certificate data directory
	if err := os.RemoveAll(certDir); err != nil {
		certstore.logger.Error(err)
		return err
	}

	return nil
}

// Loads all Distribution Certificate Revocation List's from 3rd party
// Certificate Authorities
func (certstore FileSystemCertStore) loadCRLs(attrs keystore.KeyAttributes) ([]*x509.RevocationList, error) {
	crlFiles := make([]string, 0)
	partition := store.PARTITION_CRL
	partitionKey, err := certstore.backend.PartitionKey(attrs, &partition)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}
	files, err := os.ReadDir(partitionKey)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		crlFiles = append(crlFiles, file.Name())
	}
	revocationLists := make([]*x509.RevocationList, len(files))
	for i, crlFile := range crlFiles {
		revocationList, err := certstore.loadCRL(crlFile)
		if err != nil {
			return nil, err
		}
		revocationLists[i] = revocationList
	}
	return revocationLists, nil
}

// Load the local Certificate Authority Certificate Revocation List (CRL)
func (certstore FileSystemCertStore) loadCRL(file string) (*x509.RevocationList, error) {
	crlDer, err := os.ReadFile(file)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}
	revocationList, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		certstore.logger.Error(err)
		return nil, err
	}
	// Verify the CRL signature was signed by the CA and hasn't been tampered with
	// if err := revocationList.CheckSignatureFrom(store.certificate); err != nil {
	// 	certstore.logger.Error(err)
	// 	return nil, err
	// }
	// Verify the CRL has not expired
	if revocationList.NextUpdate.Before(time.Now()) {
		return nil, ErrExpiredCRL
	}
	// The CA should do the verifications
	return revocationList, nil
}
