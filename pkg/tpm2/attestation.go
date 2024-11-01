package tpm2

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Returns an Attestation Key Profile (EK, AK, AK Name, TCG_CSR_IDEVID)
func (tpm *TPM2) AKProfile() (AKProfile, error) {

	if tpm.ekAttrs == nil {
		return AKProfile{}, ErrNotInitialized
	}

	if tpm.iakAttrs == nil {
		return AKProfile{}, ErrNotInitialized
	}
	return AKProfile{
		EKPub:              tpm.ekAttrs.TPMAttributes.PublicKeyBytes,
		AKPub:              tpm.iakAttrs.TPMAttributes.PublicKeyBytes,
		AKName:             tpm.iakAttrs.TPMAttributes.Name,
		SignatureAlgorithm: tpm.iakAttrs.SignatureAlgorithm,
	}, nil
}

// Performs TPM2_MakeCredential, returning the new credential
// challenge for an Attestor. If the secret parameter is
// not provided, a random AES-256 secret will be generated.
func (tpm *TPM2) MakeCredential(
	akName tpm2.TPM2BName,
	secret []byte) ([]byte, []byte, []byte, error) {

	tpm.logger.Info("Creating new Activation Credential")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, nil, err
	}

	if secret == nil {
		secret = aesgcm.NewAESGCM(tpm).GenerateKey()
	}
	digest := tpm2.TPM2BDigest{Buffer: secret}

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredential secret: %s", secret)
	}

	// Create the new credential challenge
	mc, err := tpm2.MakeCredential{
		Handle:      ekAttrs.TPMAttributes.Handle,
		Credential:  digest,
		ObjectNamae: akName,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, nil, err
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredential: secret (raw): %s", digest.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret (hex): 0x%x", Encode(digest.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (raw): %s", mc.CredentialBlob.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (hex): 0x%x", Encode(mc.CredentialBlob.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: secret response (raw): %s", mc.Secret.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret response (hex): 0x%x", Encode(mc.Secret.Buffer))
	}

	return mc.CredentialBlob.Buffer, mc.Secret.Buffer, digest.Buffer, nil
}

// Activates a credential challenge previously initiated by MakeCredential
func (tpm *TPM2) ActivateCredential(
	credentialBlob, encryptedSecret []byte) ([]byte, error) {

	tpm.logger.Info("Activating Credential")

	ekAttrs := tpm.iakAttrs.Parent

	var hierarchyAuth []byte
	var err error

	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth, err = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
	}

	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Activate the credential, proving the AK and EK are both loaded
	// into the same TPM, and the EK is able to decrypt the secret.
	tpm.logger.Debug("tpm2: activating credential")
	activateCredentialsResponse, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: tpm.iakAttrs.TPMAttributes.Handle,
			Name:   tpm.iakAttrs.TPMAttributes.Name,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Handle,
			Name:   ekAttrs.TPMAttributes.Name,
			Auth:   session,
		},
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: credentialBlob,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: encryptedSecret,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, ErrInvalidActivationCredential
	}

	// Release the decrypted secret. Print some helpful info
	// if secret debugging is enabled.
	digest := activateCredentialsResponse.CertInfo.Buffer
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: credential encrypted secret (raw): %s", encryptedSecret)
		tpm.logger.Debugf("tpm: credential encrypted secret (hex): 0x%x", Encode(encryptedSecret))

		tpm.logger.Debugf("tpm: TPM2BDigest (raw): %s", digest)
		tpm.logger.Debugf("tpm: TPM2BDigest (hex): 0x%x", Encode(digest))
	}

	// Return the decrypted secret
	return digest, nil
}

// Performs a TPM 2.0 quote over the PCRs defined in the
// TPM section of the platform configuration file, used
// for local attestation. The quote, event log, and PCR
// state is optionally signed and saved to the CA blob store.
func (tpm *TPM2) Quote(pcrs []uint, nonce []byte) (Quote, error) {

	if tpm.iakAttrs == nil {
		return Quote{}, ErrNotInitialized
	}

	if tpm.iakAttrs.Parent == nil {
		return Quote{}, ErrInvalidAKAttributes
	}

	tpm.logger.Info("Performing TPM 2.0 Quote")

	var quote Quote
	var akAuth []byte
	var err error

	if tpm.iakAttrs.Password != nil {
		akAuth, err = tpm.iakAttrs.Password.Bytes()
		if err != nil {
			return Quote{}, err
		}
	}

	// Create PCR selection(s)
	pcrSelections := make([]tpm2.TPMSPCRSelection, len(pcrs))
	for i, pcr := range pcrs {
		pcrSelections[i] = tpm2.TPMSPCRSelection{
			Hash:      tpm.iakAttrs.TPMAttributes.HashAlg,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
		}
	}
	pcrSelect := tpm2.TPMLPCRSelection{
		PCRSelections: pcrSelections,
	}

	// Create the quote
	q, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: tpm.iakAttrs.TPMAttributes.Handle,
			Name:   tpm.iakAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(akAuth),
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		PCRSelect: pcrSelect,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}

	var signature []byte

	var rsaSig *tpm2.TPMSSignatureRSA
	if tpm.iakAttrs.KeyAlgorithm == x509.RSA {

		if keystore.IsRSAPSS(tpm.iakAttrs.SignatureAlgorithm) {
			rsaSig, err = q.Signature.Signature.RSAPSS()
			if err != nil {
				return quote, err
			}
		} else {
			rsaSig, err = q.Signature.Signature.RSASSA()
			if err != nil {
				tpm.logger.Error(err)
				return quote, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if tpm.iakAttrs.KeyAlgorithm == x509.ECDSA {
		sig, err := q.Signature.Signature.ECDSA()
		if err != nil {
			return quote, err
		}
		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}
		signature, err = asn1.Marshal(asn1Struct)
		if err != nil {
			return quote, err
		}
	}

	// Get the event log:
	// Rather than parsing the event log and secure boot state,
	// capture the raw binary log as a blob so it can be signed
	// and imported to the CA blob storage. Verify should do a byte
	// level comparison and digest verification for the system state
	// integrity check.
	// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
	eventLog, err := tpm.EventLog()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// Some embedded systems may not have a measurement log or there may be a permission
			// problem. Log the warning and carry on...
			tpm.logger.Warn(ErrMissingMeasurementLog.Error())
		} else {
			return Quote{}, err
		}
	}

	allBanks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}

	pcrBytes, err := EncodePCRs(allBanks)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}

	return Quote{
		EventLog:  eventLog,
		Nonce:     nonce,
		PCRs:      pcrBytes,
		Quoted:    q.Quoted.Bytes(),
		Signature: signature,
	}, nil
}

// Create a random nonce and issue a quote command to the TPM
func (tpm *TPM2) PlatformQuote(
	keyAttrs *keystore.KeyAttributes) (Quote, []byte, error) {

	tpm.logger.Info("Performing local TPM 2.0 Quote")
	nonce, err := tpm.Random()
	if err != nil {
		return Quote{}, nil, err
	}
	quote, err := tpm.Quote([]uint{uint(tpm.config.PlatformPCR)}, nonce)
	if err != nil {
		return Quote{}, nil, err
	}
	return quote, nonce, nil
}
