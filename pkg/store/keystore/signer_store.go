package keystore

import (
	"encoding/hex"
	"fmt"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

type SignerStorer interface {
	Checksum(verifyOpts *VerifyOpts) ([]byte, error)
	SaveSignature(opts any, signature, digest []byte) error
}

type SignerStore struct {
	blobStore blobstore.BlobStorer
	SignerStorer
}

// Provides blob storage for signed data
func NewSignerStore(
	blobStore blobstore.BlobStorer) SignerStorer {

	return SignerStore{
		blobStore: blobStore,
	}
}

// Returns a stored checksum from the signed blob store
func (ks SignerStore) Checksum(verifyOpts *VerifyOpts) ([]byte, error) {
	ext := HashFileExtension(verifyOpts.KeyAttributes.Hash)
	key := fmt.Sprintf("%s%s", verifyOpts.BlobCN, ext)
	return ks.blobStore.Get([]byte(key))
}

// Signs and saves blobs passed to a signer as SignerOpts
func (ks SignerStore) SaveSignature(
	opts any,
	signature, digest []byte) error {

	if opts, ok := opts.(*SignerOpts); ok {

		// Save the signature
		sigKey := fmt.Sprintf("%s%s", opts.BlobCN, FSEXT_SIG)
		if err := ks.blobStore.Save([]byte(sigKey), signature); err != nil {
			return err
		}

		// Save the digest
		digestKey := fmt.Sprintf("%s%s", opts.BlobCN, FSEXT_DIGEST)
		if err := ks.blobStore.Save([]byte(digestKey), digest); err != nil {
			return err
		}

		// Save a checksum
		checksum := hex.EncodeToString(digest)
		ext := FSExtension(HashFileExtension(opts.HashFunc()))
		checksumKey := fmt.Sprintf("%s%s", opts.BlobCN, ext)
		if err := ks.blobStore.Save([]byte(checksumKey), []byte(checksum)); err != nil {
			return err
		}

		// Save the data if set
		if opts.BlobData != nil {
			if err := ks.blobStore.Save([]byte(opts.BlobCN), opts.BlobData); err != nil {
				return err
			}
		}
	} else {
		return ErrInvalidSignerOpts
	}

	return nil
}
