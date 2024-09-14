package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
)

type CertStore struct {
	logger    *logging.Logger
	blobStore blob.BlobStorer
	CertificateStorer
}

// Creates a new local file system backed x509 certificate store
func NewCertificateStore(
	logger *logging.Logger,
	blobStore blob.BlobStorer) (CertificateStorer, error) {

	return &CertStore{
		blobStore: blobStore,
		logger:    logger}, nil
}

// Imports a certificate to the certificate store
func (cs *CertStore) ImportCertificate(certificate *x509.Certificate) error {
	id, err := ParseCertificateID(certificate, nil)
	if err != nil {
		return err
	}
	return cs.blobStore.Save(id, certificate.Raw)
}

// Retrieves an x509 certificate from the certificate store.
func (cs *CertStore) Get(keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error) {
	id := fmt.Sprintf("%s.%s.%s%s",
		keyAttrs.CN,
		keyAttrs.StoreType,
		strings.ToLower(keyAttrs.KeyAlgorithm.String()),
		FSEXT_DER)
	der, err := cs.blobStore.Get([]byte(id))
	if err != nil {
		if err == blob.ErrBlobNotFound {
			return nil, ErrCertNotFound
		}
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Imports a certificate to the certificate store
func (cs *CertStore) Save(certificate *x509.Certificate, partition Partition) error {
	id, err := ParseCertificateID(certificate, &partition)
	if err != nil {
		return err
	}
	id = []byte(fmt.Sprintf("%s/%s", partition, id))
	return cs.blobStore.Save(id, certificate.Raw)
}

// Returns true if the requested Certificate Revocation List  exists in the certificate store
func (cs *CertStore) HasCRL(keyAttrs *keystore.KeyAttributes) bool {
	crlFileName := cs.crl(keyAttrs)
	// // crlFile := fmt.Sprintf("%s/%s", PARTITION_CRL, crlFileName)
	// return util.FileExists(crlFileName)

	// id := []byte(fmt.Sprintf("%s/%s", PARTITION_CRL, crlFileName))
	if _, err := cs.blobStore.Get([]byte(crlFileName)); err != nil {
		return false
	}
	return true
}

// Imports a new Certificate Revocation List
func (cs *CertStore) ImportCRL(cn string, crlDER []byte) error {
	path := fmt.Sprintf("%s/%s%s", PARTITION_CRL, cn, FSEXT_CRL)
	if err := os.WriteFile(path, crlDER, os.ModePerm); err != nil {
		return err
	}
	return nil
}

// Returns true if the certificate is found in the local Certificate Authority
// revocation list and if its associated certificates were moved to the revoked partition.
func (cs *CertStore) IsRevoked(
	certificate *x509.Certificate, issuerCert *x509.Certificate) error {
	revocationList, err := cs.loadCRL(issuerCert)
	if err != nil {
		if err == blob.ErrBlobNotFound {
			return nil
		}
		cs.logger.Error(err)
		return err
	}
	if revocationList != nil {
		for _, entry := range revocationList.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return ErrCertRevoked
			}
		}
	}
	return nil
}

// Returns true if the certificate is found in any of the imported Distrubution
// Point Certificate Revocation Lists.
func (cs *CertStore) IsRevokedAtDistributionPoints(
	certificate *x509.Certificate) error {

	keyAttrs, err := KeyAttributesFromCertificate(certificate)
	if err != nil {
		return nil
	}
	caKeyAttrs := *keyAttrs
	caKeyAttrs.CN = certificate.Issuer.CommonName

	// Load distribution point CRL for this certificate
	revocationLists, err := cs.CRLs(certificate)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err == ErrMissingDistributionPointURL {
			return nil
		}
		cs.logger.Error(err)
		return err
	}
	// Check the CRL's to see if the certificate has been revoked
	for _, revocationList := range revocationLists {
		if revocationList != nil {
			for _, entry := range revocationList.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
					return ErrCertRevoked
				}
			}
		}
	}
	return nil
}

// Adds the specified certificate to the Certicicate Authority revocation list
// and moves all of the related certificates to the revoked certificates directory.
func (cs *CertStore) Revoke(
	certificate *x509.Certificate,
	issuerCert *x509.Certificate,
	signer crypto.Signer) error {

	certID, err := ParseCertificateID(certificate, nil)
	if err != nil {
		return err
	}

	// A list of certificates revoked by the local Certificate Authority
	revokedCertificates := make([]x509.RevocationListEntry, 0)

	// Load the local Certiticate Authority's Certiticate Revocation List
	revocationList, err := cs.loadCRL(issuerCert)
	if err != nil {
		if err != blob.ErrBlobNotFound {
			cs.logger.Error(err)
			return err
		}
	}

	// Check to see if the certificate has an entry in the local Certificate Authority CRL
	if revocationList != nil {
		for _, serialNumber := range revocationList.RevokedCertificateEntries {
			if serialNumber.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return ErrCertRevoked
			}
		}
		revokedCertificates = revocationList.RevokedCertificateEntries
	}

	// Create a new revocation entry
	revokedCertificates = append(revokedCertificates,
		x509.RevocationListEntry{
			SerialNumber:   certificate.SerialNumber,
			RevocationTime: time.Now()})

	// Create a new revocation list serial number
	serialNumber, err := util.X509SerialNumber()
	if err != nil {
		cs.logger.Error(err)
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
		cs.logger.Error(err)
		return err
	}

	// Save the CRL to the ca partition
	keyAttrs, err := KeyAttributesFromCertificate(issuerCert)
	if err != nil {
		return err
	}
	crlFile := cs.caCRL(keyAttrs)

	if err := cs.blobStore.Save([]byte(crlFile), crlDER); err != nil {
		cs.logger.Error("%s: %s", err, crlFile)
		return err
	}

	return cs.blobStore.Delete(certID)
}

// Loads and parse all Distribution Certificate Revocation Lists in the provided
// certificate using the 3rd party CRL partition
func (cs *CertStore) CRLs(certificate *x509.Certificate) ([]*x509.RevocationList, error) {

	if len(certificate.CRLDistributionPoints) == 0 {
		return nil, ErrMissingDistributionPointURL
	}

	revocationLists := make([]*x509.RevocationList, len(certificate.CRLDistributionPoints))

	for i, _ := range certificate.CRLDistributionPoints {

		keyAttrs, err := KeyAttributesFromCertificate(certificate)
		if err != nil {
			return nil, err
		}
		crlFile := cs.crl(keyAttrs)

		crlDER, err := cs.blobStore.Get([]byte(crlFile))
		if err != nil {
			if err == blob.ErrBlobNotFound {
				return nil, ErrCRLNotFound
			}
			return nil, err
		}

		revocationList, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			cs.logger.Error(err)
			return nil, err
		}

		// Verify the CRL signature was signed by the CA and hasn't been tampered with
		if err := revocationList.CheckSignatureFrom(certificate); err != nil {
			cs.logger.Error(err)
			return nil, err
		}

		// Verify the CRL has not expired
		if revocationList.NextUpdate.Before(time.Now()) {
			return nil, ErrExpiredCRL
		}

		revocationLists[i] = revocationList
	}

	return revocationLists, nil
}

// Load the local Certificate Authority Certificate Revocation List (CRL)
func (cs *CertStore) loadCRL(certificate *x509.Certificate) (*x509.RevocationList, error) {

	keyAttrs, err := KeyAttributesFromCertificate(certificate)
	if err != nil {
		return nil, err
	}
	caCRL := cs.caCRL(keyAttrs)

	crlDER, err := cs.blobStore.Get([]byte(caCRL))
	if err != nil {
		cs.logger.Warningf("%s: %s", err, caCRL)
		return nil, err
	}

	revocationList, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		cs.logger.Error(err)
		return nil, err
	}

	// Verify the CRL signature was signed by the CA and hasn't been tampered with
	if err := revocationList.CheckSignatureFrom(certificate); err != nil {
		cs.logger.Error(err)
		return nil, err
	}

	// Verify the CRL has not expired
	if revocationList.NextUpdate.Before(time.Now()) {
		return nil, ErrExpiredCRL
	}
	// The CA should do the verifications
	return revocationList, nil
}

// Creates a Certificate Revocation List file name that contains the
// key algorithm in it's file extension
func (cs *CertStore) caCRL(keyAttrs *keystore.KeyAttributes) string {
	return fmt.Sprintf("%s.%s.%s%s",
		keyAttrs.CN,
		keyAttrs.StoreType,
		strings.ToLower(keyAttrs.KeyAlgorithm.String()),
		FSEXT_CRL)
}

func (cs *CertStore) crl(keyAttrs *keystore.KeyAttributes) string {
	return fmt.Sprintf("%s/%s.%s.%s%s",
		PARTITION_CRL,
		keyAttrs.CN,
		keyAttrs.StoreType,
		strings.ToLower(keyAttrs.KeyAlgorithm.String()),
		FSEXT_CRL)
}
