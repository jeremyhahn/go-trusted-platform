package ca

import (
	"crypto"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Creates a new signing key that defaults to the same algorithm, key
// size (for RSA) or elliptic curve (for ECC) as the Certificate Authority.
func (ca *CA) NewSigningKey(attrs keystore.KeyAttributes) (crypto.Signer, error) {
	ca.params.Logger.Debugf("ca/NewSigningKey: creating new %s key",
		attrs.KeyType.String())
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)
	return ca.keyStore.CreateKey(attrs)
}

// Returns a signing key from the key store or ErrKeyDoesntExist
func (ca *CA) SigningKey(attrs keystore.KeyAttributes) (crypto.Signer, error) {
	ca.params.Logger.Debugf("ca/SigningKey: retrieving %s signing key",
		attrs.KeyType.String())
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)
	return ca.keyStore.Signer(attrs)
}

// Implements crypto.Signer
// Signs a digest using the Certificate Authority public key. SignerOpts
// may be provided to override the signing key as well as perist blob storage.
func (ca *CA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signerOpts, ok := opts.(keystore.SignerOpts)
	if ok {
		signer, err := ca.keyStore.Signer(signerOpts.KeyAttributes)
		if err != nil {
			return nil, err
		}
		return signer.Sign(rand, digest, signerOpts)
	}
	// No signing opts passed, sign using the CA key
	signer, err := ca.keyStore.Signer(ca.CAKeyAttributes(nil))
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, signerOpts)
}

// Returns a stored signature from the signed blob store
func (ca *CA) Signature(key string) ([]byte, error) {
	sigKey := fmt.Sprintf("%s%s", key, store.FSEXT_SIG)
	return ca.blobStore.Blob(sigKey)
}

// Returns true if the specified blob key has a stored signature
func (ca *CA) IsSigned(key string) (bool, error) {
	sigKey := fmt.Sprintf("%s%s", key, store.FSEXT_SIG)
	if _, err := ca.blobStore.Blob(sigKey); err != nil {
		return false, err
	}
	return true, nil
}

// Returns signed data from the signed blob store
func (ca *CA) SignedBlob(key string) ([]byte, error) {
	return ca.blobStore.Blob(key)
}

// Returns a blob's signed digest from blob storage
func (ca *CA) SignedDigest(key string, hash crypto.Hash) (bool, error) {
	digestKey := fmt.Sprintf("%s%s", key, store.FSEXT_DIGEST)
	if _, err := ca.blobStore.Blob(digestKey); err != nil {
		return false, err
	}
	return true, nil
}

// Returns a blob checksum (hex)
func (ca *CA) Checksum(key string) (bool, error) {
	checksumKey := fmt.Sprintf("%s.%s", key, store.HashFileExtension(ca.Hash()))
	if _, err := ca.blobStore.Blob(checksumKey); err != nil {
		return false, err
	}
	return true, nil
}

// Verifies a RSA PKCS1v15, RSA-PSS, ECDSA or Ed25519 digest
// Options:
// 1. KeyCN: An optional signing key. Default is CA public key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
func (ca *CA) VerifySignature(digest, signature []byte, opts *keystore.VerifyOpts) error {

	if opts != nil {
		if opts.KeyAttributes.Hash == 0 {
			return keystore.ErrInvalidHashFunction
		}
		// Verify using the dedicated signing key provided by verify opts
		attrs := opts.KeyAttributes
		signer, err := ca.keyStore.Signer(attrs)
		if err != nil {
			return err
		}
		verifier := ca.keyStore.Verifier(attrs, opts)
		return verifier.Verify(signer.Public(), attrs.Hash, digest, signature, opts)
	}

	// Verify using the CA's public key
	verifier := ca.keyStore.Verifier(ca.CAKeyAttributes(nil), nil)
	return verifier.Verify(ca.Public(), ca.Hash(), digest, signature, nil)
}
