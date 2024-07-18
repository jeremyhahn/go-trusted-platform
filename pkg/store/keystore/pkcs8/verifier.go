package pkcs8

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type Verify struct {
	signerStore store.SignerStorer
	keystore.Verifier
}

// Verifies a signature
func NewVerifier(
	signerStore store.SignerStorer) keystore.Verifier {

	return Verify{
		signerStore: signerStore,
	}
}

// Verifies a RSA (PKCS1v15 or PSS) or ECDSA digest using the supplied public key,
// hash function, and signature. Optional verification opts may be passed during
// instantiation to perform custom verification using key attributes and
// file integrity checking using the sum from a previously captured signing
// operation. Optional *rsa.PSSOptions may also be provided via the verifier
// opts to perform the verification using the RSA-PSS padding scheme. If not,
// PKCS1v15 will be used as the default.
func (verifier Verify) Verify(
	pub crypto.PublicKey,
	hash crypto.Hash,
	hashed, signature []byte,
	opts *keystore.VerifyOpts) error {

	if opts != nil {
		var err error
		keyAttrs := opts.KeyAttributes

		if opts.KeyAttributes.KeyAlgorithm == x509.RSA {

			// RSA
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return keystore.ErrInvalidPublicKeyRSA
			}

			if opts.PSSOptions != nil {
				err = rsa.VerifyPSS(rsaPub, keyAttrs.Hash, hashed, signature, opts.PSSOptions)
			} else {
				err = rsa.VerifyPKCS1v15(rsaPub, keyAttrs.Hash, hashed, signature)
			}

		} else if opts.KeyAttributes.KeyAlgorithm == x509.ECDSA {

			// ECDSA
			ecdsaPub, isECDSA := pub.(*ecdsa.PublicKey)
			if isECDSA {
				if !ecdsa.VerifyASN1(ecdsaPub, hashed, signature) {
					err = keystore.ErrSingatureVerification
				}
			}

		} else if opts.KeyAttributes.KeyAlgorithm == x509.Ed25519 {

			// Ed25519
			ed25519Pub, isECDSA := pub.(ed25519.PublicKey)
			if isECDSA {
				if !ed25519.Verify(ed25519Pub, hashed, signature) {
					err = keystore.ErrSingatureVerification
				}
			}
		} else {
			err = keystore.ErrInvalidSignatureAlgorithm
		}
		if err != nil {
			return err
		}

		// Perform data integrity check if enabled
		if opts.IntegrityCheck {
			if opts.BlobCN == "" {
				return keystore.ErrInvalidBlobName
			}
			checksum, err := verifier.signerStore.Checksum(*opts)
			if err != nil {
				return err
			}
			newSum := hex.EncodeToString(hashed)
			if bytes.Compare(checksum, []byte(newSum)) != 0 {
				return keystore.ErrFileIntegrityCheckFailed
			}
		}

		return nil
	}

	rsaPub, isRSA := pub.(*rsa.PublicKey)
	if isRSA {
		// No signing opts, default to PKCS1v15
		return rsa.VerifyPKCS1v15(rsaPub, hash, hashed, signature)
	}

	// ECDSA
	ecdsaPub, isECDSA := pub.(*ecdsa.PublicKey)
	if isECDSA {
		if !ecdsa.VerifyASN1(ecdsaPub, hashed, signature) {
			return keystore.ErrSingatureVerification
		}
	}

	return keystore.ErrInvalidSignatureAlgorithm
}
