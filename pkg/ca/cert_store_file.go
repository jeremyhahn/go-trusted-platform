package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/op/go-logging"
	"github.com/youmark/pkcs8"
)

var (
	ErrFileAlreadyExists = errors.New("certificate-store: file already exists")
	ErrFileNotFound      = errors.New("certificcate-store: file not found")
)

type FileSystemCertStore struct {
	logger                 *logging.Logger
	caDir                  string
	trustedRootDir         string
	trustedIntermediateDir string
	pubKeyDir              string
	issuedDir              string
	revokedDir             string
	crlDir                 string
	signedBlobDir          string
	cryptKeyDir            string
	signatureKeyDir        string
	certificate            *x509.Certificate
	caName                 string
	retainRevoked          bool
	CertificateStore
}

func NewFileSystemCertStore(
	logger *logging.Logger,
	caDir string,
	certificate *x509.Certificate,
	retainRevoked bool) (CertificateStore, error) {

	partitions := []Partition{
		PARTITION_CA,
		PARTITION_TRUSTED_ROOT,
		PARTITION_TRUSTED_INTERMEDIATE,
		PARTITION_PUBLIC_KEYS,
		PARTITION_ISSUED,
		PARTITION_REVOKED,
		PARTITION_CRL,
		PARTITION_SIGNED_BLOB,
		PARTITION_ENCRYPTION_KEYS,
		PARTITION_SIGNING_KEYS}

	for _, partition := range partitions {
		dir := fmt.Sprintf("%s/%s", caDir, partition)
		if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
			logger.Error(err)
			return nil, err
		}
	}

	return &FileSystemCertStore{
		logger:                 logger,
		caDir:                  caDir,
		trustedRootDir:         fmt.Sprintf("%s/%s", caDir, PARTITION_TRUSTED_ROOT),
		trustedIntermediateDir: fmt.Sprintf("%s/%s", caDir, PARTITION_TRUSTED_INTERMEDIATE),
		pubKeyDir:              fmt.Sprintf("%s/%s", caDir, PARTITION_PUBLIC_KEYS),
		issuedDir:              fmt.Sprintf("%s/%s", caDir, PARTITION_ISSUED),
		revokedDir:             fmt.Sprintf("%s/%s", caDir, PARTITION_REVOKED),
		crlDir:                 fmt.Sprintf("%s/%s", caDir, PARTITION_CRL),
		signedBlobDir:          fmt.Sprintf("%s/%s", caDir, PARTITION_SIGNED_BLOB),
		cryptKeyDir:            fmt.Sprintf("%s/%s", caDir, PARTITION_ENCRYPTION_KEYS),
		signatureKeyDir:        fmt.Sprintf("%s/%s", caDir, PARTITION_SIGNING_KEYS),
		certificate:            certificate,
		caName:                 certificate.Subject.CommonName,
		retainRevoked:          retainRevoked}, nil
}

// Returns the Root CA certificate for the requested CA certificate by
// recursively loading the current certificate chain until the root
// certificate is found.
func (store *FileSystemCertStore) RootCertForCA(cn string) (*x509.Certificate, error) {
	// Assume this is an Intermediate CA calling this function
	// and check the trusted-root partition first
	der, err := store.Get(cn, cn, PARTITION_TRUSTED_ROOT, FSEXT_DER)
	if err != nil {
		if err == ErrCertNotFound {
			// Try to load the cert from the root CA directory
			// (this is the root CA)
			der, err = store.Get(cn, cn, PARTITION_CA, FSEXT_DER)
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
		return store.RootCertForCA(cert.Issuer.CommonName)
	}
	return cert, nil
}

// Returns a slice containing the Root Certificate Authority certificate and all
// trusted root certiticates that have been imported into the certificate store.
func (store *FileSystemCertStore) TrustedRootCerts() ([]*x509.Certificate, error) {

	// Get the root CA certificate
	rootCert, err := store.RootCertForCA(store.caName)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}

	// Get all imported trusted root certificates
	trustedRootCerts, err := store.Certificates(PARTITION_TRUSTED_ROOT)
	if err != nil {
		store.logger.Error(err)
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

// Returns a Trusted Root CertPool that contains the Certificate Authority root certificate with
// the options to include the local operating system trusted root certificates.
func (store *FileSystemCertStore) TrustedRootCertPool(includeSystemRoot bool) (*x509.CertPool, error) {

	roots := x509.NewCertPool()
	if includeSystemRoot {
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
	}

	// Get the root CA certificate
	rootCert, err := store.RootCertForCA(store.caName)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}

	// Encode the root CA certificate in PEM form
	rootPEM, err := store.EncodePEM(rootCert.Raw)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}

	// Add the root CA to the certpool
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return nil, ErrCertInvalid
	}

	// Add all imported trusted root CAs
	trustedRootCerts, err := store.Certificates(PARTITION_TRUSTED_ROOT)
	if err != nil {
		return nil, err
	}
	for _, cert := range trustedRootCerts {
		ok := roots.AppendCertsFromPEM(cert)
		if !ok {
			return nil, ErrCertInvalid
		}
	}

	return roots, nil
}

// Returns a Trusted Intermediate CertPool that contains the Certificate Authority intermediate
// certificate.
func (store *FileSystemCertStore) TrustedIntermediateCertPool() (*x509.CertPool, error) {

	intermediates := x509.NewCertPool()

	// Add the Intermediate Certificate Authority certificate first
	intermediatePEM, err := store.Get(
		store.caName,
		store.caName,
		PARTITION_CA,
		FSEXT_PEM)
	if err != nil {
		return nil, err
	}
	if ok := intermediates.AppendCertsFromPEM(intermediatePEM); !ok {
		store.logger.Error(err)
		return nil, err
	}

	// Add all imported trusted intermediate CAs
	trustedIntermediateCerts, err := store.Certificates(PARTITION_TRUSTED_INTERMEDIATE)
	if err != nil {
		return nil, err
	}
	for _, cert := range trustedIntermediateCerts {
		ok := intermediates.AppendCertsFromPEM(cert)
		if !ok {
			return nil, ErrCertInvalid
		}
	}

	return intermediates, nil
}

// Returns the requested Trusted Root CA certificate
func (store *FileSystemCertStore) TrustedRoot(cn string) ([]byte, error) {
	return store.Get(cn, cn, PARTITION_TRUSTED_ROOT, FSEXT_PEM)
}

// Returns the requested Trusted Intermediate CA certificate
func (store *FileSystemCertStore) TrustedIntermediate(cn string) ([]byte, error) {
	return store.Get(cn, cn, PARTITION_TRUSTED_INTERMEDIATE, FSEXT_PEM)
}

// Returns a parent certificate from the trusted root or intermediate certificate store
func (store *FileSystemCertStore) TrustedCertificateFor(cert *x509.Certificate) (*x509.Certificate, error) {

	parent, err := store.TrustedIntermediate(cert.Issuer.CommonName)
	if err == nil {
		return x509.ParseCertificate(parent)
	}
	if err == ErrCertNotFound {
		parent, err = store.TrustedRoot(cert.Issuer.CommonName)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(parent)
	}

	return nil, ErrCertNotFound
}

// Returns true if the requested CA certificate exists in the certificate store
// and is trusted by the Certificate Authority.
func (store *FileSystemCertStore) TrustsCA(cn string, partition Partition) (bool, error) {
	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return false, err
	}
	filename := fmt.Sprintf("%s/%s%s", part, cn, FSEXT_PEM)
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, nil
}

// Returns true if the requested Certificate Revocation List  exists in the certificate store
func (store *FileSystemCertStore) HasCRL(cn string) (bool, error) {
	part, err := store.partition(PARTITION_CRL)
	if err != nil {
		store.logger.Error(err)
		return false, err
	}
	filename := fmt.Sprintf("%s/%s%s", part, cn, FSEXT_CRL)
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, nil
}

// Returns the requested Certificate Authority's x509 identity certificate
func (store *FileSystemCertStore) CACertificate(cn string) (*x509.Certificate, error) {
	der, err := store.Get(cn, cn, PARTITION_CA, FSEXT_DER)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Returns the Certificate Authority's RSA Private Key. This key should never
// be cached, saved, or exported outside of the Certificate Authority, only
// loaded on the stack and set to nil to clear it from memory as soon as possible.
func (store *FileSystemCertStore) CAPrivKey(password []byte) (crypto.PrivateKey, error) {
	file := fmt.Sprintf("%s/%s%s", store.caDir, store.caName, FSEXT_PRIVATE_PKCS8)
	bytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(bytes, password)
	if err != nil {
		// The PKCS8 package doesn't always return "invalid password",
		// sometimes this ASN.1 error is given when it fails to parse the
		// private key because it's encrypted and the password is incorrect.
		// It's impossible for the private key to have been generated with
		// an invalid structure (if generated by this platform) so this
		// means the password provided was incorrect.
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, ErrInvalidPassword
		}
		return nil, err
	}
	return key.(crypto.PrivateKey), nil
}

// Returns the Certificate Authority's RSA Public Key
func (store *FileSystemCertStore) CAPubKey() (crypto.PublicKey, error) {
	bytes, err := store.Get(store.caName, store.caName, PARTITION_CA, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(bytes)
	return pubKey.(crypto.PublicKey), err
}

// Returns the Certificate Authority's RSA Public Key in PEM form
func (store *FileSystemCertStore) CAPubPEM() ([]byte, error) {
	return store.Get(store.caName, store.caName, PARTITION_CA, FSEXT_PUBLIC_PEM)
}

// Returns all PEM form certificates from the specified Certificate Authority partition
func (store *FileSystemCertStore) Certificates(partition Partition) ([][]byte, error) {
	part := fmt.Sprintf("%s/%s", store.caDir, partition)
	files, err := os.ReadDir(part)
	if err != nil {
		return nil, err
	}
	certs := make([][]byte, 0)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		pieces := strings.Split(file.Name(), ".")
		ext := "." + pieces[len(pieces)-1]
		if ext != FSEXT_PEM {
			continue
		}
		filePath := fmt.Sprintf("%s/%s", part, file.Name())
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		certs = append(certs, bytes)
	}
	return certs, nil
}

// Returns a private key from the requested partition
func (store *FileSystemCertStore) PrivKey(cn, name string, password []byte, partition Partition) (crypto.PrivateKey, error) {
	file := fmt.Sprintf("%s/%s/%s/%s%s",
		store.caDir, partition, cn, name, FSEXT_PRIVATE_PKCS8)
	bytes, err := os.ReadFile(file)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}
	store.logger.Debugf("certificate-store: parsing private key: cn: %s, name: %s, partition: %s",
		cn, name, partition)
	key, err := pkcs8.ParsePKCS8PrivateKey(bytes, password)
	if err != nil {
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, ErrInvalidPassword
		}
		return nil, err
	}
	return key.(crypto.PrivateKey), nil
}

// Returns the RSA Public Key from the issued partition for the specified common name
func (store *FileSystemCertStore) PubKey(cn, name string, partition Partition) (crypto.PublicKey, error) {
	bytes, err := store.Get(cn, name, partition, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(bytes)
	return pubKey.(crypto.PublicKey), err
}

// Returns and issued RSA Public Key in PEM form, from the issued partition
// for the specified common name.
func (store *FileSystemCertStore) PubKeyPEM(cn, name string, partition Partition) ([]byte, error) {
	return store.Get(cn, name, partition, FSEXT_PUBLIC_PEM)
}

// Appends certificate bytes to an existing certificate file
func (store *FileSystemCertStore) Append(
	cn string,
	data []byte,
	partition Partition,
	extension FSExtension) error {

	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return err
	}
	var certDir string
	if partition == PARTITION_CA ||
		partition == PARTITION_TRUSTED_ROOT ||
		partition == PARTITION_TRUSTED_INTERMEDIATE ||
		partition == PARTITION_PUBLIC_KEYS ||
		partition == PARTITION_CRL {
		certDir = fmt.Sprintf("%s", part)
	} else {
		certDir = fmt.Sprintf("%s/%s", part, cn)
	}
	if err := os.MkdirAll(certDir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return err
	}
	certFile := fmt.Sprintf("%s/%s%s", certDir, cn, extension)

	f, err := os.OpenFile(certFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		store.logger.Error(err)
		return err
	}
	defer f.Close()

	if _, err = f.Write(data); err != nil {
		store.logger.Error(err)
		return err
	}

	store.logger.Debugf("certificate-store: appending certificate %s", certFile)
	return nil
}

// Saves an issued certificate to the file system
func (store *FileSystemCertStore) Save(
	cn string,
	data []byte,
	partition Partition,
	extension FSExtension) error {

	var certDir string
	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return err
	}
	if partition == PARTITION_CA ||
		partition == PARTITION_TRUSTED_ROOT ||
		partition == PARTITION_TRUSTED_INTERMEDIATE ||
		partition == PARTITION_PUBLIC_KEYS ||
		partition == PARTITION_CRL {
		certDir = fmt.Sprintf("%s", part)
	} else {
		certDir = fmt.Sprintf("%s/%s", part, cn)
	}
	if err := os.MkdirAll(certDir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return err
	}
	certFile := fmt.Sprintf("%s/%s%s", certDir, cn, extension)

	if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(certFile, data, 0644); err != nil {
			store.logger.Error(err)
			return err
		}
		store.logger.Debugf("certificate-store: saving certificate %s", certFile)
		return nil
	}

	return fmt.Errorf("%s: %s", ErrFileAlreadyExists, certFile)
}

// Saves a "keyed object" to the file system using the cn
// as a subfolder name, with the data blob stored inside.
// Keyed Object: An object to store to a specifid path
func (store *FileSystemCertStore) SaveKeyed(
	cn, key string,
	data []byte,
	partition Partition,
	extension FSExtension) error {

	var dir string
	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return err
	}

	dir = fmt.Sprintf("%s/%s/", part, cn)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return err
	}

	file := fmt.Sprintf("%s/%s%s", dir, key, extension)
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(file, data, 0644); err != nil {
			store.logger.Error(err)
			return err
		}
		store.logger.Debugf("certificate-store: saving certificate %s", file)
		return nil
	}

	return fmt.Errorf("%s: %s", ErrFileAlreadyExists, file)
}

// Saves a signed blob to the "signed" partition. If the blob key contains
// forward slashes, a directory hierarchy will be created to match the
// key. For example, the blob key /my/secret/blob.dat would get saved to
// cert-store/signed/my/secret/blob.dat
func (store *FileSystemCertStore) SaveBlob(key string, data []byte) error {
	trimmed := strings.TrimLeft(key, "/")
	dir := fmt.Sprintf("%s/%s", store.signedBlobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return err
	}
	blobFile := fmt.Sprintf("%s/%s%s", store.signedBlobDir, trimmed, FSEXT_BLOB)
	if err := os.WriteFile(blobFile, data, 0644); err != nil {
		store.logger.Error(err)
		return err
	}
	return nil
}

// Retrieves a signed blob from the "signed" partition. ErrBlobNotFound is
// returned if the signed data could not be found.
func (store *FileSystemCertStore) Blob(key string) ([]byte, error) {
	trimmed := strings.TrimLeft(key, "/")
	dir := fmt.Sprintf("%s/%s/", store.signedBlobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return nil, err
	}
	blobFile := fmt.Sprintf("%s/%s%s", store.signedBlobDir, trimmed, FSEXT_BLOB)
	bytes, err := os.ReadFile(blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.Errorf("certificate-store: error retrieving blob: %s, key: %s",
				blobFile, key)
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Retrieves key / certificate from the requested certificate
// store partition
func (store *FileSystemCertStore) Get(
	cn, name string,
	partition Partition,
	extension FSExtension) ([]byte, error) {

	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return nil, err

	}
	var certDir string
	if partition == PARTITION_CA ||
		partition == PARTITION_TRUSTED_ROOT ||
		partition == PARTITION_TRUSTED_INTERMEDIATE ||
		partition == PARTITION_PUBLIC_KEYS ||
		partition == PARTITION_CRL {
		certDir = fmt.Sprintf("%s", part)
	} else {
		certDir = fmt.Sprintf("%s/%s", part, cn)
	}
	certFile := fmt.Sprintf("%s/%s%s", certDir, name, extension)
	bytes, err := os.ReadFile(certFile)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.Warningf(
				"certificate-store: error retrieving certificate: %s, cn: %s, parition: %s",
				certFile, cn, partition)
			return nil, ErrCertNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Gets a "keyed object" from the store
func (store *FileSystemCertStore) GetKeyed(
	cn, key string,
	partition Partition,
	extension FSExtension) ([]byte, error) {

	var dir string
	part, err := store.partition(partition)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}

	dir = fmt.Sprintf("%s/%s/", part, cn)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return nil, err
	}

	file := fmt.Sprintf("%s/%s%s", dir, key, extension)
	bytes, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.Errorf(
				"certificate-store: error retrieving keyed object: %s", file)
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Returns true if the certificate is found in the local Certificate Authority
// revocation list and if its associated certificates were moved to the revoked partition.
func (store *FileSystemCertStore) IsRevoked(cn string, serialNumber *big.Int) (bool, error) {
	localCRL := fmt.Sprintf("%s/%s%s", store.caDir, store.caName, FSEXT_CRL)
	revocationList, err := store.loadCRL(localCRL)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		store.logger.Error(err)
		return false, err
	}
	if revocationList != nil {
		for _, entry := range revocationList.RevokedCertificateEntries {
			if entry.SerialNumber.String() == serialNumber.String() {
				return true, nil
			}
		}
	}
	revokedCert := fmt.Sprintf("%s/%s%s", store.revokedDir, cn, FSEXT_PEM)
	if _, err := os.Stat(revokedCert); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, nil
}

// Returns true if the certificate is found in any of the imported Distrubution
// Point Certificate Revocation Lists.
func (store *FileSystemCertStore) IsRevokedAtDistributionPoints(
	cn string,
	serialNumber *big.Int) (bool, error) {

	// Load all distribution point CRLs
	revocationLists, err := store.loadCRLs()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		store.logger.Error(err)
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
func (store *FileSystemCertStore) Revoke(cn string, cert *x509.Certificate, password []byte) error {

	// A list of certificates revoked by the local Certificate Authority
	revokedCertificates := make([]x509.RevocationListEntry, 0)

	// Load the local Certiticate Authority's Certiticate Revocation List
	localCRL := fmt.Sprintf("%s/%s%s", store.caDir, store.caName, FSEXT_CRL)
	revocationList, err := store.loadCRL(localCRL)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		store.logger.Error(err)
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
	serialNumber, err := newSerialNumber()
	if err != nil {
		store.logger.Error(err)
		return err
	}

	// Create a new revocation list template
	template := x509.RevocationList{
		SignatureAlgorithm:        store.certificate.SignatureAlgorithm,
		RevokedCertificateEntries: revokedCertificates,
		Number:                    serialNumber,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}

	// Load the local CA's private key to sign the new CRL
	privateKey, err := store.CAPrivKey(password)
	if err != nil {
		store.logger.Error(err)
		return err
	}

	var crlDER []byte
	// Create the new CRL
	if store.certificate.SignatureAlgorithm == x509.SHA256WithRSA {
		crlDER, err = x509.CreateRevocationList(rand.Reader,
			&template, store.certificate, privateKey.(*rsa.PrivateKey))
		if err != nil {
			store.logger.Error(err)
			return err
		}
	} else if store.certificate.SignatureAlgorithm == x509.ECDSAWithSHA256 {
		crlDER, err = x509.CreateRevocationList(rand.Reader,
			&template, store.certificate, privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			store.logger.Error(err)
			return err
		}
	}
	privateKey = nil

	// Save the CRL to the ca partition
	crl := fmt.Sprintf("%s/%s%s", store.caDir, store.caName, FSEXT_CRL)
	if err = os.WriteFile(crl, crlDER, 0644); err != nil {
		store.logger.Error(err)
		return err
	}

	// Get a reference to the "issued" certificates partition
	issuedPartition, err := store.partition(PARTITION_ISSUED)
	if err != nil {
		store.logger.Error(err)
		return err
	}
	certDir := fmt.Sprintf("%s/%s", issuedPartition, cn)

	// Delete or move certiticates in "issued" to "revoked"
	commonExtensions := []FSExtension{
		FSEXT_PRIVATE_PEM,
		FSEXT_PRIVATE_PKCS8,
		FSEXT_PUBLIC_PEM,
		FSEXT_PUBLIC_PKCS1,
		FSEXT_CSR,
		FSEXT_DER,
		FSEXT_PEM}
	if store.retainRevoked {
		// Create the certificate revocation directory if it doesnt exist
		revokedDir := fmt.Sprintf("%s/%s", store.revokedDir, cn)
		if err := os.MkdirAll(revokedDir, fs.ModePerm); err != nil {
			store.logger.Error(err)
			return err
		}
		for _, ext := range commonExtensions {
			src := fmt.Sprintf("%s/%s%s", certDir, cn, ext)
			dst := fmt.Sprintf("%s/%s%s", revokedDir, cn, ext)
			err = os.Rename(src, dst)
			if err != nil {
				if os.IsNotExist(err) {
					if ext == FSEXT_CSR || ext == FSEXT_PRIVATE_PKCS8 || ext == FSEXT_PRIVATE_PEM {
						// ignore errors for CSR and Private Key files
						// that dont exist since they are not present
						// for certificates generated from a CSR process.
						// IssueCertificate does not use CSRs.
						continue
					}
				}
				store.logger.Error(err)
				return err
			}
		}
	}

	// Delete the certificate directory
	if err := os.RemoveAll(certDir); err != nil {
		store.logger.Error(err)
		return err
	}

	return nil
}

// Encodes a raw DER byte array as a PEM byte array
func (store *FileSystemCertStore) EncodePEM(derCert []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return nil, err
	}
	return caPEM.Bytes(), nil
}

// Returns the file system path for the specified partition
func (store *FileSystemCertStore) partition(partition Partition) (string, error) {
	switch partition {
	case PARTITION_CA:
		return store.caDir, nil
	case PARTITION_TRUSTED_ROOT:
		return store.trustedRootDir, nil
	case PARTITION_TRUSTED_INTERMEDIATE:
		return store.trustedIntermediateDir, nil
	case PARTITION_PUBLIC_KEYS:
		return store.pubKeyDir, nil
	case PARTITION_ISSUED:
		return store.issuedDir, nil
	case PARTITION_REVOKED:
		return store.revokedDir, nil
	case PARTITION_CRL:
		return store.crlDir, nil
	case PARTITION_SIGNED_BLOB:
		return store.signedBlobDir, nil
	case PARTITION_ENCRYPTION_KEYS:
		return store.cryptKeyDir, nil
	case PARTITION_SIGNING_KEYS:
		return store.signatureKeyDir, nil
	}
	return "", ErrInvalidPartition
}

// Loads all Distribution Certificate Revocation List's from 3rd party
// Certificate Authorities
func (store *FileSystemCertStore) loadCRLs() ([]*x509.RevocationList, error) {
	crlFiles := make([]string, 0)
	partition, err := store.partition(PARTITION_CRL)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}
	files, err := os.ReadDir(partition)
	if err != nil {
		store.logger.Error(err)
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
		revocationList, err := store.loadCRL(crlFile)
		if err != nil {
			return nil, err
		}
		revocationLists[i] = revocationList
	}
	return revocationLists, nil
}

// Load the local Certificate Authority Certificate Revocation List (CRL)
func (store *FileSystemCertStore) loadCRL(file string) (*x509.RevocationList, error) {
	crlDer, err := os.ReadFile(file)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}
	revocationList, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		store.logger.Error(err)
		return nil, err
	}
	// Verify the CRL signature was signed by the CA and hasn't been tampered with
	// if err := revocationList.CheckSignatureFrom(store.certificate); err != nil {
	// 	store.logger.Error(err)
	// 	return nil, err
	// }
	// Verify the CRL has not expired
	if revocationList.NextUpdate.Before(time.Now()) {
		return nil, ErrExpiredCRL
	}
	return revocationList, nil
}

// Saves the local Certificate Authority Certificate Revocation List (CRL)
func (store *FileSystemCertStore) saveCRL(der []byte) error {
	crl := fmt.Sprintf("%s/%s%s", store.caDir, store.caName, FSEXT_CRL)
	if err := os.WriteFile(crl, der, 0644); err != nil {
		store.logger.Error(err)
		return err
	}
	return nil
}
