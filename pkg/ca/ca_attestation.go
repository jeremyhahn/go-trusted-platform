package ca

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	ATTEST_BLOB_ROOT     = "tpm"
	ATTEST_AK_NAME       = "ak"
	ATTEST_BLOB_QUOTE    = "quote"
	ATTEST_BLOB_EVENTLOG = "eventlog"
	ATTEST_BLOB_PCRS     = "pcrs"
)

// Imports a new TPM PEM encoded Endorsement Key into the certificate store
func (ca *CA) ImportEndorsementKeyCertificate(attrs keystore.KeyAttributes, ekCertPEM []byte) error {

	ca.params.Logger.Info("Importing Endorsement Key Certificate")

	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	certName := fmt.Sprintf("ek-cert%s", store.FSEXT_PEM)
	attrs.CN = certName

	blobKey := ca.TPMBlobKey(attrs)

	sigOpts, err := keystore.NewSignerOpts(ca.CAKeyAttributes(nil), ekCertPEM)
	sigOpts.BlobCN = &blobKey
	sigOpts.BlobData = ekCertPEM
	if _, err = ca.Sign(ca.params.Random, sigOpts.Digest(), sigOpts); err != nil {
		return err
	}
	return nil
}

// Returns the local TPM Endorsement Key x509 Certificate in PEM form
func (ca *CA) EndorsementKeyCertificate() ([]byte, error) {

	ca.params.Logger.Info("Retrieving Endorsement Key Certificate")

	attrs := ca.CAKeyAttributes(nil)
	attrs.CN = fmt.Sprintf("ak-cert%s", store.FSEXT_PEM)

	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	ekBlobCN := ca.TPMBlobKey(attrs)
	certPEM, err := ca.SignedBlob(ekBlobCN)
	if err == nil {
		// No need to perform integrity check on local file being
		// loaded from a trusted file system. If an attacker can compromise
		// the cert, they also have access to forge a signature to match
		// the malicious cert and pass verification.
		// signerOpts, err := NewSignerOpts(ca.Hash(), certPEM)
		// if err != nil {
		// 	return nil, err
		// }
		// verifyOpts := &VerifyOpts{
		// 	BlobCN:            &ekBlobCN,
		// 	UseStoredSignature: true,
		// }
		// if err := ca.VerifySignature(signerOpts.Digest(), nil, verifyOpts); err != nil {
		// 	return nil, err
		// }
		ca.params.Logger.Info("certificate-authority: loading TPM Endorsement Key")
		// Decode and return the signed and verified x509 EK cert from the CA
		_, err = DecodePEM(certPEM)
		if err != nil {
			return nil, err
		}
		return certPEM, nil
	}
	return nil, err
}

// Imports a TPM Attestation Key x509 certificate to the TPM blob storage
// partition. The certificate is encoded to PEM, signed by the CA public key,
// and saved to blob storage.
func (ca *CA) ImportAttestationKeyCertificate(attrs keystore.KeyAttributes, akDER []byte) error {

	ca.params.Logger.Info("Importing Attestation Key Certificate")
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	akCertBlobName := "ak-cert%s"
	attrs.CN = fmt.Sprintf(akCertBlobName, store.FSEXT_DER)
	blobKeyDER := ca.TPMBlobKey(attrs)

	// Default the domain to the common name if not provided
	if attrs.Domain == "" {
		return keystore.ErrDomainAttributeRequired
	}

	// Create signing options - store the cert, digest and checksum
	sigOpts, err := keystore.NewSignerOpts(ca.CAKeyAttributes(nil), akDER)
	sigOpts.BlobCN = &blobKeyDER
	sigOpts.BlobData = akDER

	// Sign the DER digest
	if _, err = ca.Sign(ca.params.Random, sigOpts.Digest(), sigOpts); err != nil {
		return err
	}

	// Encode the AK DER cert to PEM
	akPEM, err := EncodePEM(akDER)
	if err != nil {
		return err
	}

	// Save the PEM cert
	attrs.CN = fmt.Sprintf("%s%s", akCertBlobName, store.FSEXT_PEM)
	blobKeyPEM := ca.TPMBlobKey(attrs)
	if err := ca.ImportBlob(blobKeyPEM, akPEM); err != nil {
		return err
	}

	return nil
}

// Signs the requested quote using the CA public key and saves the
// signature, digest and quote to the signed blob store.
func (ca *CA) ImportAttestationQuote(attestatomAttrs keystore.KeyAttributes, data []byte) error {
	return ca.ImportAttestation(attestatomAttrs, ATTEST_BLOB_QUOTE, data)
}

// Signs the requested event log using the CA public key and saves the
// signature, digest and event log to the signed blob store.
func (ca *CA) ImportAttestationEventLog(attestatomAttrs keystore.KeyAttributes, data []byte) error {
	return ca.ImportAttestation(attestatomAttrs, ATTEST_BLOB_EVENTLOG, data)
}

// Signs the requested PCR list using the CA public key and saves the
// signature, digest and PCR list to the signed blob store.
func (ca *CA) ImportAttestationPCRs(attestatomAttrs keystore.KeyAttributes, pcrs []byte) error {
	return ca.ImportAttestation(attestatomAttrs, ATTEST_BLOB_PCRS, pcrs)
}

// Signs the requested blob type using the CA public key and saves the
// signature, digest and blob to the signed blob store.
func (ca *CA) ImportAttestation(attestatomAttrs keystore.KeyAttributes, blobType string, data []byte) error {

	// Create signing options using default CA key attributes
	opts, err := keystore.NewSignerOpts(attestatomAttrs, data)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Create attestation blob key based on the blob type
	var blobKey string
	switch blobType {

	case ATTEST_BLOB_QUOTE:
		blobKey = ca.quoteBlobCN(attestatomAttrs.CN)

	case ATTEST_BLOB_EVENTLOG:
		blobKey = ca.eventLogBlobCN(attestatomAttrs.CN)

	case ATTEST_BLOB_PCRS:
		blobKey = ca.pcrsBlobCN(attestatomAttrs.CN)

	default:
		return ErrInvalidAttestationBlobType
	}

	// Set storage properties
	opts.BlobCN = &blobKey
	opts.BlobData = data

	// Sign and store the requested data
	_, err = ca.Sign(ca.params.Random, nil, opts)
	if err != nil {
		return err
	}

	return nil
}

func (ca *CA) VerifyAttestationQuote(signerAttrs keystore.KeyAttributes, quote []byte) error {
	signing, err := keystore.NewSignerOpts(ca.CAKeyAttributes(nil), quote)
	if err != nil {
		return err
	}
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: signerAttrs,
		BlobCN:        ca.quoteBlobCN(signerAttrs.CN),
	}
	err = ca.VerifySignature(signing.Digest(), nil, verifyOpts)
	if err != nil {
		return err
	}
	return nil
}

func (ca *CA) VerifyAttestationEventLog(signerAttrs keystore.KeyAttributes, eventLog []byte) error {

	// Use the CA's public key to verify
	opts, err := keystore.NewSignerOpts(signerAttrs, eventLog)
	if err != nil {
		return err
	}

	digest := opts.Digest()

	// Use the signature in blob storage for verification
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: signerAttrs,
		BlobCN:        ca.eventLogBlobCN(signerAttrs.CN),
	}

	signature, err := ca.Sign(ca.params.Random, digest, opts)
	if err != nil {
		return err
	}

	// Verify the event log using the new digest and stored signature
	err = ca.VerifySignature(digest, signature, verifyOpts)
	if err != nil {
		return err
	}

	return nil
}

func (ca *CA) VerifyAttestationPCRs(signerAttrs keystore.KeyAttributes, pcrs []byte) error {

	// Create signing opts to get a digest using the CA's configured
	// hash function
	opts, err := keystore.NewSignerOpts(ca.CAKeyAttributes(nil), pcrs)
	if err != nil {
		return err
	}

	digest := opts.Digest()

	// Use the stored signature for verification
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: signerAttrs,
		BlobCN:        ca.pcrsBlobCN(signerAttrs.CN),
	}

	signature, err := ca.Sign(ca.params.Random, digest, opts)
	if err != nil {
		return err
	}

	// Verify the PCRs using the new digest and stored signature
	err = ca.VerifySignature(digest, signature, verifyOpts)
	if err != nil {
		return err
	}

	return nil
}

// Returns the relative path to the blob store for TPM
// and attestation related blobs, given the owner's key
// attributes.
func (ca *CA) TPMBlobKey(attrs keystore.KeyAttributes) string {
	//return fmt.Sprintf("tpm/%s/%s", attrs.CN, attrs.KeyName)
	return fmt.Sprintf("tpm/%s/%s", attrs.CN, attrs.CN)
}

// Returns the file path for a TPM attestation blob given the device
// common name and blob name
func (ca *CA) akBlobKey(cn, blobType string) string {
	path := fmt.Sprintf("%s/%s/%s",
		ATTEST_BLOB_ROOT, cn, blobType)
	return path
}

func (ca *CA) quoteBlobCN(cn string) string {
	return ca.akBlobKey(cn, ATTEST_BLOB_QUOTE)
}

func (ca *CA) eventLogBlobCN(cn string) string {
	return ca.akBlobKey(cn, ATTEST_BLOB_EVENTLOG)
}

func (ca *CA) pcrsBlobCN(cn string) string {
	return ca.akBlobKey(cn, ATTEST_BLOB_PCRS)
}
