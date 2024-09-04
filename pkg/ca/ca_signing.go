package ca

import (
	"crypto"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Implements crypto.Signer
// Signs a digest using the Certificate Authority public key. SignerOpts
// may be provided to override the signing key as well as perist blob storage.
func (ca *CA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signerOpts, ok := opts.(*keystore.SignerOpts)
	if ok {
		signer, err := ca.keychain.Signer(signerOpts.KeyAttributes)
		if err != nil {
			return nil, err
		}
		return signer.Sign(rand, digest, signerOpts)
	}
	// No signing opts passed, sign using the default CA key
	signer, err := ca.keychain.Signer(ca.defaultKeyAttributes)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, signerOpts)
}

// Returns a stored signature from the signed blob store
func (ca *CA) Signature(key string) ([]byte, error) {
	sigKey := fmt.Sprintf("%s%s", key, keystore.FSEXT_SIG)
	return ca.blobStore.Get([]byte(sigKey))
}

// Returns true if the specified blob key has a stored signature
func (ca *CA) IsSigned(key string) (bool, error) {
	sigKey := fmt.Sprintf("%s%s", key, keystore.FSEXT_SIG)
	if _, err := ca.blobStore.Get([]byte(sigKey)); err != nil {
		return false, err
	}
	return true, nil
}

// Returns signed data from the signed blob store
func (ca *CA) SignedBlob(key []byte) ([]byte, error) {
	return ca.blobStore.Get(key)
}

// Returns a blob's signed digest from blob storage
func (ca *CA) SignedDigest(key string, hash crypto.Hash) (bool, error) {
	digestKey := fmt.Sprintf("%s%s", key, keystore.FSEXT_DIGEST)
	if _, err := ca.blobStore.Get([]byte(digestKey)); err != nil {
		return false, err
	}
	return true, nil
}

// Returns a blob checksum (hex)
func (ca *CA) Checksum(key []byte) (bool, error) {
	checksumKey := fmt.Sprintf("%s.%s", key, keystore.HashFileExtension(ca.Hash()))
	if _, err := ca.blobStore.Get([]byte(checksumKey)); err != nil {
		return false, err
	}
	return true, nil
}

// Verifies a RSA PKCS1v15, RSA-PSS, ECDSA or Ed25519 digest
func (ca *CA) VerifySignature(digest, signature []byte, opts *keystore.VerifyOpts) error {

	if opts != nil {
		if opts.KeyAttributes.Hash == 0 {
			return keystore.ErrInvalidHashFunction
		}
		// Verify using the dedicated signing key provided by verify opts
		attrs := opts.KeyAttributes
		signer, err := ca.keychain.Signer(attrs)
		if err != nil {
			return err
		}
		verifier := ca.keychain.Verifier(attrs, opts)
		return verifier.Verify(
			signer.Public(), attrs.Hash, digest, signature, opts)
	}

	// Verify using the CA's matching algorithm key
	caKeyAttrs, err := ca.CAKeyAttributes(
		&opts.KeyAttributes.StoreType, &opts.KeyAttributes.KeyAlgorithm)
	if err != nil {
		return err
	}
	verifier := ca.keychain.Verifier(caKeyAttrs, nil)
	return verifier.Verify(ca.Public(), ca.Hash(), digest, signature, nil)
}
