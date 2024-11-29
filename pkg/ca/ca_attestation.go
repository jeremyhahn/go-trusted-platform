package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

// Imports a new TPM PEM encoded Endorsement Key into the certificate store
func (ca *CA) ImportEndorsementKeyCertificate(
	ekAttrs *keystore.KeyAttributes, ekCertBytes []byte) error {

	ca.params.Logger.Info("Importing Endorsement Key Certificate")

	keystore.DebugKeyAttributes(ca.params.Logger, ekAttrs)

	certName := fmt.Sprintf("%s%s", ca.ekCertName(), certstore.FSEXT_DER)
	ekAttrs.CN = certName

	blobKey := ca.tpmBlobKey(ekAttrs)

	caKeyAttrs, err := ca.CAKeyAttributes(ekAttrs.StoreType, ekAttrs.KeyAlgorithm)
	if err != nil {
		return err
	}

	sigOpts := keystore.NewSignerOpts(caKeyAttrs, ekCertBytes)
	digest, err := sigOpts.Digest()
	if err != nil {
		return err
	}
	sigOpts.BlobCN = blobKey
	sigOpts.BlobData = ekCertBytes
	if _, err = ca.Sign(ca.params.Random, digest, sigOpts); err != nil {
		return err
	}
	return nil
}

// Returns the local TPM Endorsement Key x509 Certificate in PEM form
func (ca *CA) EndorsementKeyCertificate() ([]byte, error) {

	ca.params.Logger.Info("Retrieving Endorsement Key Certificate")

	ekAttrs, err := ca.params.TPM.EKAttributes()
	if err != nil {
		return nil, err
	}

	attrs, err := ca.CAKeyAttributes(ekAttrs.StoreType, ekAttrs.KeyAlgorithm)
	if err != nil {
		return nil, err
	}
	attrs.CN = fmt.Sprintf("%s%s", ca.ekCertName(), certstore.FSEXT_DER)

	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	ekBlobCN := ca.tpmBlobKey(attrs)
	certPEM, err := ca.SignedBlob(ekBlobCN)
	if err == nil {
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
// partition in DER form.
func (ca *CA) ImportAttestationKeyCertificate(
	attrs *keystore.KeyAttributes, akDER []byte) error {

	ca.params.Logger.Info("Importing Attestation Key Certificate")
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	attrs.CN = fmt.Sprintf("%s%s", ca.akCertName(), certstore.FSEXT_DER)
	blobKeyDER := ca.tpmBlobKey(attrs)

	caKeyAttrs, err := ca.CAKeyAttributes(attrs.StoreType, attrs.KeyAlgorithm)
	if err != nil {
		return err
	}

	// Create signing options - store the cert, digest and checksum
	sigOpts := keystore.NewSignerOpts(caKeyAttrs, akDER)
	digest, err := sigOpts.Digest()
	if err != nil {
		return err
	}
	sigOpts.BlobCN = blobKeyDER
	sigOpts.BlobData = akDER

	// Sign the DER digest
	if _, err = ca.Sign(ca.params.Random, digest, sigOpts); err != nil {
		return err
	}

	// // Encode the AK DER cert to PEM
	// akPEM, err := EncodePEM(akDER)
	// if err != nil {
	// 	return err
	// }

	// // Save the PEM cert
	// attrs.CN = fmt.Sprintf("%s%s", akCertBlobName, certstore.FSEXT_PEM)
	// blobKeyPEM := ca.tpmBlobKey(attrs)
	// if err := ca.ImportBlob(blobKeyPEM, akPEM); err != nil {
	// 	return err
	// }

	return nil
}

// Signs the requested quote using the CA public key and saves the
// signature, digest and quote to the signed blob keystore.
func (ca *CA) ImportAttestationQuote(
	signerAttrs *keystore.KeyAttributes,
	data []byte,
	backend keystore.KeyBackend) error {

	ca.params.Logger.Infof("Importing attestation quote: %s", signerAttrs.CN)

	return ca.ImportAttestation(signerAttrs, ATTEST_BLOB_QUOTE, data, backend)
}

// Signs the requested event log using the CA public key and saves the
// signature, digest and event log to the signed blob keystore.
func (ca *CA) ImportAttestationEventLog(
	signerAttrs *keystore.KeyAttributes,
	data []byte,
	backend keystore.KeyBackend) error {

	ca.params.Logger.Infof("Importing attestation event log: %s", signerAttrs.CN)

	return ca.ImportAttestation(signerAttrs, ATTEST_BLOB_EVENTLOG, data, backend)
}

// Signs the requested PCR list using the CA public key and saves the
// signature, digest and PCR list to the signed blob keystore.
func (ca *CA) ImportAttestationPCRs(
	signerAttrs *keystore.KeyAttributes,
	pcrs []byte,
	backend keystore.KeyBackend) error {

	ca.params.Logger.Infof("Importing attestation: %s", signerAttrs.CN)

	return ca.ImportAttestation(signerAttrs, ATTEST_BLOB_PCRS, pcrs, backend)
}

// Signs the requested blob type using the CA public key and saves the
// signature, digest and blob to the signed blob keystore.
func (ca *CA) ImportAttestation(
	akAttrs *keystore.KeyAttributes,
	blobType string,
	data []byte,
	backend keystore.KeyBackend) error {

	// Create attestation blob key based on the blob type
	var blobKey []byte
	switch blobType {

	case ATTEST_BLOB_QUOTE:
		blobKey = ca.quoteBlobCN(akAttrs.CN)

	case ATTEST_BLOB_EVENTLOG:
		blobKey = ca.eventLogBlobCN(akAttrs.CN)

	case ATTEST_BLOB_PCRS:
		blobKey = ca.pcrsBlobCN(akAttrs.CN)

	default:
		return ErrInvalidAttestationBlobType
	}

	caKeyAttrs, err := ca.CAKeyAttributes(akAttrs.StoreType, akAttrs.KeyAlgorithm)
	if err != nil {
		return keystore.ErrInvalidKeyAlgorithm
	}

	// Create signing options using default CA key attributes
	opts := keystore.NewSignerOpts(caKeyAttrs, data)
	digest, err := opts.Digest()
	if err != nil {
		return err
	}

	if backend != nil {
		opts.Backend = backend
	}

	// Set storage properties
	opts.BlobCN = blobKey
	opts.BlobData = data

	// Set RSS PSS opts if this key is configured with the RSS PSS
	// signing algorithm
	if keystore.IsRSAPSS(akAttrs.SignatureAlgorithm) {
		opts.PSSOptions = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       akAttrs.Hash,
		}
	}

	// Sign and store the requested data
	if _, err := ca.Sign(ca.params.Random, digest, opts); err != nil {
		return err
	}

	return nil
}

func (ca *CA) ImportLocalAttestation(
	keyAttrs *keystore.KeyAttributes,
	quote tpm2.Quote,
	backend keystore.KeyBackend) error {

	ca.params.Logger.Info("Importing local attestation blobs")

	// Sign and store the quote
	err := ca.ImportAttestationQuote(keyAttrs, quote.Quoted, backend)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Sign and store the quote
	err = ca.ImportAttestationEventLog(keyAttrs, quote.EventLog, backend)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Sign and store the PCR state
	err = ca.ImportAttestationPCRs(keyAttrs, quote.PCRs, backend)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	return nil

}

// Verifies a TPM 2.0 quote using a previously captured event log and
// PCR state that's been signed and stored in the CA signed blob store.
//
// Rather than parsing and replaying the event log, a more simplistic
// approach is taken, which verifies the current event log and secure
// boot state blobs with the state stored in the CA signed blob store
// captured during device enrollment or local attestation. This may
// change in the future. The rationale for this is partly due to the
// event log not being a reliable source for integrity checking to begin
// with:
// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
func (ca *CA) VerifyQuote(akAttrs *keystore.KeyAttributes, quote tpm2.Quote, nonce []byte) error {

	ca.params.Logger.Infof("Verifying Quote: %s", akAttrs.CN)

	// Make sure the returned nonce matches the nonce
	// that was sent in the quote request.
	if !bytes.Equal(quote.Nonce, nonce) {
		return tpm2.ErrInvalidNonce
	}

	digest, err := keystore.Digest(akAttrs.Hash, quote.Quoted)
	if err != nil {
		return err
	}

	var pubKey crypto.PublicKey

	// If this is a TPM restricted signing key, get the public key
	// from it's TPM attributes
	if akAttrs.TPMAttributes != nil {

		if akAttrs.TPMAttributes.Public.ObjectAttributes.Restricted &&
			akAttrs.TPMAttributes.Public.ObjectAttributes.SignEncrypt {

			pubKey, err = ca.params.TPM.ParsePublicKey(akAttrs.TPMAttributes.BPublic.Bytes())
			if err != nil {
				return err
			}
		} else if akAttrs.TPMAttributes.PublicKeyBytes != nil {
			// This supports the TSS attestor / verifier flow. The "AK Profile" mentioned in
			// that spec only provides the public key and nothing else
			// pubKey, err = ca.params.TPM.ParsePublicKey(akAttrs.TPMAttributes.BPublic.Bytes())
			// if err != nil {
			// 	return err
			// }
			pubKey, err = x509.ParsePKIXPublicKey(akAttrs.TPMAttributes.PublicKeyBytes)
			if err != nil {
				return err
			}
		}
	} else {
		// Get the public key from the x509 certificate (store)
		cert, err := ca.Certificate(akAttrs)
		if err != nil {
			return err
		}
		pubKey = cert.PublicKey
	}

	if akAttrs.KeyAlgorithm == x509.RSA {

		rsaPub := pubKey.(*rsa.PublicKey)
		if keystore.IsRSAPSS(akAttrs.SignatureAlgorithm) {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       akAttrs.Hash,
			}
			err = rsa.VerifyPSS(
				rsaPub, akAttrs.Hash, digest, quote.Signature, pssOpts)
		} else {
			err = rsa.VerifyPKCS1v15(
				rsaPub, akAttrs.Hash, digest, quote.Signature)
		}
		if err != nil {
			return ErrInvalidSignature
		}
	} else if akAttrs.KeyAlgorithm == x509.ECDSA {

		ecdsaPub := pubKey.(*ecdsa.PublicKey)
		ok := ecdsa.VerifyASN1(ecdsaPub, digest, quote.Signature)
		if !ok {
			return ErrInvalidSignature
		}
	} else if akAttrs.KeyAlgorithm == x509.Ed25519 {

		ed25519Pub := pubKey.(ed25519.PublicKey)
		if !ed25519.Verify(ed25519Pub, digest, quote.Signature) {
			return ErrInvalidSignature
		}
	}

	// // Verify the event log
	// err = ca.VerifyAttestationEventLog(akAttrs, quote.EventLog)
	// if err != nil {
	// 	return err
	// }

	// // Verify PCR state
	// err = ca.VerifyAttestationPCRs(akAttrs, quote.PCRs)
	// if err != nil {
	// 	ca.params.Logger.Error("PCR state verification failed")
	// 	decoded, err := tpm2.DecodePCRs(quote.PCRs)
	// 	if err != nil {
	// 		return fmt.Errorf("certificate-authority: failed to decode PCR banks")
	// 	}
	// 	for _, bank := range decoded {
	// 		for _, pcr := range bank.PCRs {
	// 			ca.params.Logger.Debugf("%s pcr %d: 0x%s",
	// 				bank.Algorithm, pcr.ID, pcr.Value)
	// 		}
	// 	}
	// 	return err
	// }

	return nil
}

func (ca *CA) VerifyAttestationQuote(akAttrs *keystore.KeyAttributes, quote []byte) error {
	caKeyAttrs, err := ca.CAKeyAttributes(akAttrs.StoreType, akAttrs.KeyAlgorithm)
	if err != nil {
		return err
	}
	sigOpts := keystore.NewSignerOpts(caKeyAttrs, quote)
	digest, err := sigOpts.Digest()
	if err != nil {
		return err
	}
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: akAttrs,
		BlobCN:        ca.quoteBlobCN(akAttrs.CN),
	}
	err = ca.VerifySignature(digest, nil, verifyOpts)
	if err != nil {
		return err
	}
	return nil
}

func (ca *CA) VerifyAttestationEventLog(akAttrs *keystore.KeyAttributes, eventLog []byte) error {

	// Use the CA's public key to verify
	opts := keystore.NewSignerOpts(akAttrs, eventLog)
	digest, err := opts.Digest()
	if err != nil {
		return err
	}

	// Use the signature in blob storage for verification
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: akAttrs,
		BlobCN:        ca.eventLogBlobCN(akAttrs.CN),
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

func (ca *CA) VerifyAttestationPCRs(akAttrs *keystore.KeyAttributes, pcrs []byte) error {

	caKeyAttrs, err := ca.CAKeyAttributes(akAttrs.StoreType, akAttrs.KeyAlgorithm)
	if err != nil {
		return err
	}

	// Create signing opts to get a digest using the CA's configured
	// hash function
	opts := keystore.NewSignerOpts(caKeyAttrs, pcrs)
	digest, err := opts.Digest()
	if err != nil {
		return err
	}

	// Use the stored signature for verification
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: akAttrs,
		BlobCN:        ca.pcrsBlobCN(akAttrs.CN),
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
func (ca *CA) tpmBlobKey(attrs *keystore.KeyAttributes) []byte {
	return []byte(fmt.Sprintf("%s/%s/%s", ATTEST_BLOB_ROOT, attrs.CN, attrs.CN))
}

// Returns the file path for a TPM attestation blob given the device
// common name and blob names
func (ca *CA) akBlobKey(cn string, blobType string) []byte {

	// Default the path to the provided CN
	path := fmt.Sprintf("%s/%s/%s",
		ATTEST_BLOB_ROOT, cn, blobType)

	// Provided cn takes precedence
	if cn != "" {
		return []byte(path)
	}

	// Use the device model-serial number naming convention if configured
	config := ca.params.TPM.Config()
	if config.IDevID != nil {
		if config.IDevID.Model != "" && config.IDevID.Serial != "" {
			path = fmt.Sprintf("%s/%s/%s/%s",
				ATTEST_BLOB_ROOT,
				strings.ReplaceAll(config.IDevID.Model, " ", "-"),
				strings.ReplaceAll(config.IDevID.Serial, " ", "-"),
				blobType)
			return []byte(path)
		}
	}

	// Use a default name
	return []byte("default-attestation-key")
}

func (ca *CA) quoteBlobCN(cn string) []byte {
	return ca.akBlobKey(cn, ATTEST_BLOB_QUOTE)
}

func (ca *CA) eventLogBlobCN(cn string) []byte {
	return ca.akBlobKey(cn, ATTEST_BLOB_EVENTLOG)
}

func (ca *CA) pcrsBlobCN(cn string) []byte {
	return ca.akBlobKey(cn, ATTEST_BLOB_PCRS)
}

func (ca *CA) ekCertName() string {
	config := ca.params.TPM.Config()
	if config.IDevID != nil {
		if config.IDevID.Model == "" || config.IDevID.Serial == "" {
			return "ek"
		}
		return fmt.Sprintf("ek-%s-%s",
			config.IDevID.Model,
			config.IDevID.Serial)
	}
	return "ek"
}

func (ca *CA) akCertName() string {
	config := ca.params.TPM.Config()
	if config.IDevID != nil {
		if config.IDevID.Model == "" || config.IDevID.Serial == "" {
			return "ak"
		}
		return fmt.Sprintf("ak-%s-%s",
			config.IDevID.Model,
			config.IDevID.Serial)
	}
	return "ak"
}
