package ca

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

var (
	ATTEST_BLOB_ROOT     = "tpm"
	ATTEST_AK_NAME       = "ak"
	ATTEST_BLOB_QUOTE    = "quote"
	ATTEST_BLOB_EVENTLOG = "eventlog"
	ATTEST_BLOB_PCRS     = "pcrs"
)

// Imports a new TPM PEM encoded Endorsement Key into the certificate store
func (ca *CA) ImportEndorsementKeyCertificate(ekCertPEM, caPassword []byte) error {
	if ca.params.DebugSecrets {
		ca.params.Logger.Debugf("ca/ImportEndorsementKeyCertificate: caPassword: %s", caPassword)
	}
	certName := fmt.Sprintf("ek-cert%s", FSEXT_PEM)
	blobKey := ca.TPMBlobKey(ca.commonName, certName)
	sigOpts, err := NewSigningOpts(ca.Hash(), ekCertPEM)
	sigOpts.Password = caPassword
	sigOpts.BlobKey = &blobKey
	sigOpts.BlobData = ekCertPEM
	sigOpts.StoreSignature = true
	if _, err = ca.Sign(ca.params.Random, sigOpts.Digest(), sigOpts); err != nil {
		return err
	}
	return nil
}

// Returns the local TPM Endorsement Key x509 Certificate in PEM form
func (ca *CA) EndorsementKeyCertificate() ([]byte, error) {
	certName := fmt.Sprintf("ak-cert%s", FSEXT_PEM)
	ekBlobKey := ca.TPMBlobKey(ca.commonName, certName)
	certPEM, err := ca.SignedBlob(ekBlobKey)
	if err == nil {
		// No need to perform integrity check on local file being
		// loaded from a trusted file system. If an attacker can compromise
		// the cert, they also have access to forge a signature to match
		// the malicious cert and pass verification.
		// signerOpts, err := NewSigningOpts(ca.Hash(), certPEM)
		// if err != nil {
		// 	return nil, err
		// }
		// verifyOpts := &VerifyOpts{
		// 	BlobKey:            &ekBlobKey,
		// 	UseStoredSignature: true,
		// }
		// if err := ca.VerifySignature(signerOpts.Digest(), nil, verifyOpts); err != nil {
		// 	return nil, err
		// }
		ca.params.Logger.Info("certificate-authority: loading TPM Endorsement Key")
		// Decode and return the signed and verified x509 EK cert from the CA
		_, err = ca.DecodePEM(certPEM)
		if err != nil {
			return nil, err
		}
		return certPEM, nil
	}
	return nil, err
}

// Imports a TPM Attestation Key x509 certificate to the TPM blob storage
// partition. The certificate is encoded to PEM, signed by the CA public key.
func (ca *CA) ImportAttestationKeyCertificate(domain, service string, akDER []byte) error {

	akCertBlobName := "ak-cert"
	// Build cert path
	akCertPathDER := fmt.Sprintf(
		"%s/%s/%s",
		service, akCertBlobName, FSEXT_DER)
	blobKeyDER := ca.TPMBlobKey(domain, akCertPathDER)

	// Create signing options - store the cert, digest and checksum
	sigOpts, err := NewSigningOpts(ca.Hash(), akDER)
	sigOpts.BlobKey = &blobKeyDER
	sigOpts.BlobData = akDER
	sigOpts.StoreSignature = true

	// Sign the DER digest
	if _, err = ca.Sign(ca.params.Random, sigOpts.Digest(), sigOpts); err != nil {
		return err
	}

	// Encode the AK DER cert to PEM
	akPEM, err := ca.EncodePEM(akDER)
	if err != nil {
		return err
	}

	// Save the PEM cert
	akCertPathPEM := fmt.Sprintf("%s/%s%s", service, akCertBlobName, FSEXT_PEM)
	blobKeyPEM := ca.TPMBlobKey(domain, akCertPathPEM)
	if err := ca.ImportBlob(blobKeyPEM, akPEM); err != nil {
		return err
	}

	return nil
}

func (ca *CA) VerifyAttestationQuote(cn string, quote []byte) error {
	sigingOpts, err := NewSigningOpts(ca.Hash(), quote)
	if err != nil {
		return err
	}
	verifyOpts := &VerifyOpts{
		BlobKey:            ca.quoteBlobKey(cn),
		UseStoredSignature: true,
	}
	err = ca.VerifySignature(sigingOpts.Digest(), nil, verifyOpts)
	if err != nil {
		return err
	}

	// if !bytes.Equal(quote.EventLog, signedEventLog) {
	// 	return ErrUnexpectedEventLogState
	// }

	return nil
}

func (ca *CA) VerifyAttestationEventLog(cn string, eventLog []byte) error {

	// Use the CA's public key to verify
	sigingOpts, err := NewSigningOpts(ca.Hash(), eventLog)
	if err != nil {
		return err
	}

	// Use the signature in blob storage for verification
	verifyOpts := &VerifyOpts{
		BlobKey:            ca.eventLogBlobKey(cn),
		UseStoredSignature: true,
	}

	// Verify the event log using the new digest and stored signature
	err = ca.VerifySignature(sigingOpts.Digest(), nil, verifyOpts)
	if err != nil {
		return err
	}

	return nil
}

func (ca *CA) VerifyAttestationPCRs(cn string, pcrs map[string][][]byte) error {

	// Gob the quoted PCRs
	pcrBuf := new(bytes.Buffer)
	encoder := gob.NewEncoder(pcrBuf)
	if err := encoder.Encode(pcrs); err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Create signing opts to get a digest using the CA's configured
	// hash function
	sigingOpts, err := NewSigningOpts(ca.Hash(), pcrBuf.Bytes())
	if err != nil {
		return err
	}

	// Use the stored signature for verification
	verifyOpts := &VerifyOpts{
		BlobKey:            ca.pcrsBlobKey(cn),
		UseStoredSignature: true,
	}

	// Verify the PCRs using the new digest and stored signature
	err = ca.VerifySignature(sigingOpts.Digest(), nil, verifyOpts)
	if err != nil {
		return err
	}

	// Make sure the current PCR state matches the signed /
	// expected PCR state.
	// if !bytes.Equal(pcrBuf.Bytes(), signedPCRs) {
	// 	return ErrUnexpectedEventLogState
	// }

	return nil
}

// Returns the requested attestation blob from the signed blob storage
func (ca *CA) AttestationSignature(cn, blobType string) ([]byte, error) {

	var blobKey *string
	switch blobType {

	case ATTEST_BLOB_QUOTE:
		blobKey = ca.quoteBlobKey(cn)

	case ATTEST_BLOB_EVENTLOG:
		blobKey = ca.eventLogBlobKey(cn)

	case ATTEST_BLOB_PCRS:
		blobKey = ca.pcrsBlobKey(cn)

	default:
		blobKey = &blobType
		//return ErrInvalidAttestationBlobType
	}

	return ca.Signature(*blobKey)
}

// Returns the requested attestation quote from the signed blob store
func (ca *CA) AttestationQuote(cn string) ([]byte, error) {
	return ca.SignedBlob(*ca.quoteBlobKey(cn))
}

// Returns the requested attestation event log from the signed blob store
func (ca *CA) AttestationEventLog(cn string) ([]byte, error) {
	return ca.SignedBlob(*ca.eventLogBlobKey(cn))
}

// Returns the requested attestation pcr state from the signed blob store
func (ca *CA) AttestationPCRs(cn string) (map[string][][]byte, error) {

	// Get the signed PCR state
	signedPCRs, err := ca.SignedBlob(*ca.pcrsBlobKey(cn))
	if err != nil {
		return nil, err
	}

	// De-gob the list
	var pcrs map[string][][]byte
	buf := bytes.NewBuffer(signedPCRs)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&pcrs); err != nil {
		return nil, err
	}

	return pcrs, nil
}

// Signs the requested quote using the CA public key and saves the
// signature, digest and quote to the signed blob store.
func (ca *CA) ImportAttestationQuote(cn string, data, caPassword []byte) error {
	return ca.ImportAttestation(cn, ATTEST_BLOB_QUOTE, data, caPassword)
}

// Signs the requested event log using the CA public key and saves the
// signature, digest and event log to the signed blob store.
func (ca *CA) ImportAttestationEventLog(cn string, data, caPassword []byte) error {
	return ca.ImportAttestation(cn, ATTEST_BLOB_EVENTLOG, data, caPassword)
}

// Signs the requested PCR list using the CA public key and saves the
// signature, digest and PCR list to the signed blob store.
func (ca *CA) ImportAttestationPCRs(cn string, pcrs map[string][][]byte, caPassword []byte) error {
	// Gob the PCR list
	pcrsBuf := new(bytes.Buffer)
	encoder := gob.NewEncoder(pcrsBuf)
	if err := encoder.Encode(pcrs); err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	return ca.ImportAttestation(cn, ATTEST_BLOB_PCRS, pcrsBuf.Bytes(), caPassword)
}

// Signs the requested blob type using the CA public key and saves the
// signature, digest and blob to the signed blob store.
func (ca *CA) ImportAttestation(cn, blobType string, data, caPassword []byte) error {

	// Create signing options
	opts, err := NewSigningOpts(ca.Hash(), data)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Create attestation blob key based on the blob type
	var blobKey *string
	switch blobType {

	case ATTEST_BLOB_QUOTE:
		blobKey = ca.quoteBlobKey(cn)

	case ATTEST_BLOB_EVENTLOG:
		blobKey = ca.eventLogBlobKey(cn)

	case ATTEST_BLOB_PCRS:
		blobKey = ca.pcrsBlobKey(cn)

	default:
		blobKey = &blobType
		//return ErrInvalidAttestationBlobType
	}

	// Set storage properties
	// opts.KeyCN = &cn
	// opts.KeyName = ca.akKeyName()
	opts.Password = caPassword
	opts.BlobKey = blobKey
	opts.BlobData = data
	opts.StoreSignature = true

	// Sign and store the requested data
	_, err = ca.Sign(ca.params.Random, opts.Digest(), opts)
	if err != nil {
		return err
	}

	return nil
}

// Returns the file path for a TPM attestation blob given the device
// common name and blob name
func (ca *CA) akBlobKey(cn, blobType string) *string {
	path := fmt.Sprintf("%s/%s/%s",
		ATTEST_BLOB_ROOT, cn, blobType)
	return &path
}

func (ca *CA) akKeyCN(cn string) *string {
	return &cn
}

func (ca *CA) akKeyName() *string {
	akKeyName := ATTEST_AK_NAME
	return &akKeyName
}

func (ca *CA) quoteBlobKey(cn string) *string {
	return ca.akBlobKey(cn, ATTEST_BLOB_QUOTE)
}

func (ca *CA) eventLogBlobKey(cn string) *string {
	return ca.akBlobKey(cn, ATTEST_BLOB_EVENTLOG)
}

func (ca *CA) pcrsBlobKey(cn string) *string {
	return ca.akBlobKey(cn, ATTEST_BLOB_PCRS)
}

// Returns the relative path to the blob store for TPM objects
// given a domain and common name for the object.
func (ca *CA) TPMBlobKey(domain, cn string) string {
	return fmt.Sprintf("tpm/%s/%s", domain, cn)
}
