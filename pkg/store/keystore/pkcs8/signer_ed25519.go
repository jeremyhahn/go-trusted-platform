package pkcs8

import (
	"crypto"
	"crypto/ed25519"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type SignerEd25519 struct {
	keyStore      keystore.KeyStorer
	signerStore   store.SignerStorer
	blobStore     blobstore.BlobStorer
	keyAttributes keystore.KeyAttributes
	pub           crypto.PublicKey
	crypto.Signer
}

// Signer that uses the Elliptical Curve Cryptography Digital Signature
// Algorithm (Ed25519).
//
// Signs the requested data using the Certificate Authority Private Key, or,
// optionally, the private key provided via SignerOpts during the call to Sign.
func NewSignerEd25519(
	keyStore keystore.KeyStorer,
	signerStore store.SignerStorer,
	keyAttributes keystore.KeyAttributes,
	publicKey crypto.PublicKey) crypto.Signer {

	return SignerEd25519{
		keyStore:      keyStore,
		signerStore:   signerStore,
		keyAttributes: keyAttributes,
		pub:           publicKey,
	}
}

// Returns the public half of the signing key
func (signer SignerEd25519) Public() crypto.PublicKey {
	return signer.pub
}

// Signs the requested digest using the PKCS #8 private key
func (signer SignerEd25519) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	// Try to parse as platform blob signer opts
	signerOpts, ok := opts.(keystore.SignerOpts)
	if ok {

		// Load the blob signing key
		blobSigner, err := signer.keyStore.Key(signerOpts.KeyAttributes)
		if err != nil {
			return nil, err
		}

		ed25519Priv, ok := blobSigner.(ed25519.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyEd25519
		}

		// Private key must match PrivateKeySize
		// https://pkg.go.dev/crypto/ed25519
		if len(ed25519Priv) != ed25519.PrivateKeySize {
			return nil, keystore.ErrInvalidPrivateKeyEd25519
		}

		// Sign the message
		signature = ed25519.Sign(ed25519Priv, digest)

		if signerOpts.BlobCN != nil {
			// Save the signature and digest to blob storage
			if err := signer.signerStore.SaveSignature(signerOpts, signature, digest); err != nil {
				return nil, err
			}
		}

		return signature, nil
	}

	// No key store / blob opts, sign using the key attributes
	// provided to the signer.
	ed25519Key, err := signer.keyStore.Key(signer.keyAttributes)
	if err != nil {
		return nil, err
	}

	ed25519Priv, ok := ed25519Key.(ed25519.PrivateKey)
	if !ok {
		return nil, keystore.ErrInvalidPrivateKeyEd25519
	}

	// Private key must match PrivateKeySize
	if len(ed25519Priv) != ed25519.PrivateKeySize {
		return nil, keystore.ErrInvalidPrivateKeyEd25519
	}

	// Sign the message
	return ed25519.Sign(ed25519Priv, digest), nil
}
