package certstore

import (
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

type BlobStoreBackend struct {
	blobStore blob.BlobStorer
	CertificateBackend
}

func NewBlobStoreBackend(blobStore blob.BlobStorer) CertificateBackend {
	return &BlobStoreBackend{
		blobStore: blobStore,
	}
}

func (bse *BlobStoreBackend) ImportCertificate(
	id []byte, certificate *x509.Certificate) error {

	return bse.blobStore.Save(id, certificate.Raw)
}

func (bse *BlobStoreBackend) Get(id []byte) (*x509.Certificate, error) {
	der, err := bse.blobStore.Get(id)
	if err != nil {
		if err == blob.ErrBlobNotFound {
			return nil, ErrCertNotFound
		}
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (bse *BlobStoreBackend) DeleteCertificate(id []byte) error {
	return bse.blobStore.Delete(id)
}
