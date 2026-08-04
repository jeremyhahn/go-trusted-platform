// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCertStore is a mock implementation of CertificateStorer
type MockCertStore struct {
	mock.Mock
}

func (m *MockCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	args := m.Called(cn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockCertStore) StoreCertificate(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

func (m *MockCertStore) DeleteCertificate(cn string) error {
	args := m.Called(cn)
	return args.Error(0)
}

func (m *MockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	args := m.Called(chain)
	return args.Error(0)
}

func (m *MockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	args := m.Called(cn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockCertStore) StoreCRL(crl *x509.RevocationList) error {
	args := m.Called(crl)
	return args.Error(0)
}

func (m *MockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	args := m.Called(issuer)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.RevocationList), args.Error(1)
}

func (m *MockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	args := m.Called(cert, roots)
	return args.Error(0)
}

func (m *MockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	args := m.Called(cert)
	return args.Bool(0), args.Error(1)
}

func (m *MockCertStore) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockCertificateStorageAdapter is a mock implementation
type MockCertificateStorageAdapter struct {
	mock.Mock
}

func (m *MockCertificateStorageAdapter) SaveCert(ctx context.Context, id string, cert *x509.Certificate) error {
	args := m.Called(ctx, id, cert)
	return args.Error(0)
}

func (m *MockCertificateStorageAdapter) GetCert(ctx context.Context, id string) (*x509.Certificate, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockCertificateStorageAdapter) DeleteCert(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockCertificateStorageAdapter) SaveCertChain(ctx context.Context, id string, chain []*x509.Certificate) error {
	args := m.Called(ctx, id, chain)
	return args.Error(0)
}

func (m *MockCertificateStorageAdapter) GetCertChain(ctx context.Context, id string) ([]*x509.Certificate, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockCertificateStorageAdapter) ListCerts(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCertificateStorageAdapter) CertExists(ctx context.Context, id string) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

func (m *MockCertificateStorageAdapter) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockObjectStorer is a mock implementation
type MockObjectStorer struct {
	mock.Mock
}

func (m *MockObjectStorer) Count(partition *string) (int, error) {
	args := m.Called(partition)
	return args.Int(0), args.Error(1)
}

func (m *MockObjectStorer) Delete(key []byte) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockObjectStorer) Exists(key []byte) bool {
	args := m.Called(key)
	return args.Bool(0)
}

func (m *MockObjectStorer) Get(key []byte) ([]byte, error) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockObjectStorer) Home() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockObjectStorer) Partition() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockObjectStorer) Save(key, data []byte) error {
	args := m.Called(key, data)
	return args.Error(0)
}

func (m *MockObjectStorer) ObjectStorageClient() objectstorage.Client {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(objectstorage.Client)
}

func (m *MockObjectStorer) List(prefix string) ([]string, error) {
	args := m.Called(prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, cn string) *x509.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// Helper function to create a test CSR
func createTestCSR(t *testing.T, cn string) []byte {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	return csrDER
}

func TestTPM2CertStoreAdapter_Get(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Get existing certificate", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		expectedCert := createTestCertificate(t, "test.example.com")

		mockCS.On("GetCertificate", "test.example.com").Return(expectedCert, nil)

		cert, err := adapter.Get(attrs)
		require.NoError(t, err)
		assert.Equal(t, expectedCert, cert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Get with nil attributes", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		cert, err := adapter.Get(nil)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
		assert.Nil(t, cert)
	})

	t.Run("Get with empty CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: ""}

		cert, err := adapter.Get(attrs)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
		assert.Nil(t, cert)
	})

	t.Run("Get non-existent certificate", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "missing.example.com"}

		mockCS.On("GetCertificate", "missing.example.com").Return(nil, xkmssdk.ErrCertNotFound)

		cert, err := adapter.Get(attrs)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
		assert.Nil(t, cert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Get with object not found error", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		mockCS.On("GetCertificate", "test.example.com").Return(nil, object.ErrObjectNotFound)

		cert, err := adapter.Get(attrs)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
		assert.Nil(t, cert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Get with other error", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		expectedErr := errors.New("database error")

		mockCS.On("GetCertificate", "test.example.com").Return(nil, expectedErr)

		cert, err := adapter.Get(attrs)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, cert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Get with local ErrCertNotFound", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		mockCS.On("GetCertificate", "test.example.com").Return(nil, ErrCertNotFound)

		cert, err := adapter.Get(attrs)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
		assert.Nil(t, cert)
		mockCS.AssertExpectations(t)
	})
}

func TestTPM2CertStoreAdapter_Save(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Save certificate with storage adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)
		mockStorage := new(MockCertificateStorageAdapter)
		adapter := NewTPM2CertStoreAdapterWithStorage(logger, mockCS, mockStorage)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		cert := createTestCertificate(t, "test.example.com")

		mockStorage.On("SaveCert", mock.Anything, "test.example.com", cert).Return(nil)

		err := adapter.Save(attrs, cert)
		require.NoError(t, err)
		mockStorage.AssertExpectations(t)
	})

	t.Run("Save certificate without storage adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		cert := createTestCertificate(t, "test.example.com")

		mockCS.On("StoreCertificate", cert).Return(nil)

		err := adapter.Save(attrs, cert)
		require.NoError(t, err)
		mockCS.AssertExpectations(t)
	})

	t.Run("Save with nil attributes", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		cert := createTestCertificate(t, "test.example.com")

		err := adapter.Save(nil, cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid parameters")
	})

	t.Run("Save with empty CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: ""}
		cert := createTestCertificate(t, "test.example.com")

		err := adapter.Save(attrs, cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid parameters")
	})

	t.Run("Save with nil certificate", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		err := adapter.Save(attrs, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid parameters")
	})
}

func TestTPM2CertStoreAdapter_Delete(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Delete existing certificate", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		mockCS.On("DeleteCertificate", "test.example.com").Return(nil)

		err := adapter.Delete(attrs)
		require.NoError(t, err)
		mockCS.AssertExpectations(t)
	})

	t.Run("Delete with nil attributes", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		err := adapter.Delete(nil)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
	})

	t.Run("Delete with empty CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: ""}

		err := adapter.Delete(attrs)
		assert.ErrorIs(t, err, xkmssdk.ErrTPMStoreCertNotFound)
	})
}

func TestTPM2CertStoreAdapter_ImportCertificate(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	cert := createTestCertificate(t, "test.example.com")
	certPEM, err := EncodePEM(cert.Raw)
	require.NoError(t, err)

	t.Run("Import certificate with storage adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)
		mockStorage := new(MockCertificateStorageAdapter)
		adapter := NewTPM2CertStoreAdapterWithStorage(logger, mockCS, mockStorage)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		mockStorage.On("SaveCert", mock.Anything, "test.example.com", mock.AnythingOfType("*x509.Certificate")).Return(nil)

		importedCert, err := adapter.ImportCertificate(attrs, certPEM)
		require.NoError(t, err)
		assert.NotNil(t, importedCert)
		assert.Equal(t, "test.example.com", importedCert.Subject.CommonName)
		mockStorage.AssertExpectations(t)
	})

	t.Run("Import certificate without storage adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}

		mockCS.On("StoreCertificate", mock.AnythingOfType("*x509.Certificate")).Return(nil)

		importedCert, err := adapter.ImportCertificate(attrs, certPEM)
		require.NoError(t, err)
		assert.NotNil(t, importedCert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Import with nil attributes", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		importedCert, err := adapter.ImportCertificate(nil, certPEM)
		assert.Error(t, err)
		assert.Nil(t, importedCert)
		assert.Contains(t, err.Error(), "invalid key attributes")
	})

	t.Run("Import with empty CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: ""}

		importedCert, err := adapter.ImportCertificate(attrs, certPEM)
		assert.Error(t, err)
		assert.Nil(t, importedCert)
		assert.Contains(t, err.Error(), "invalid key attributes")
	})

	t.Run("Import with invalid PEM", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		invalidPEM := []byte("not a PEM")

		importedCert, err := adapter.ImportCertificate(attrs, invalidPEM)
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, importedCert)
	})

	t.Run("Import with wrong PEM type", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		wrongTypePEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`)

		importedCert, err := adapter.ImportCertificate(attrs, wrongTypePEM)
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, importedCert)
	})

	t.Run("Import with storage adapter error", func(t *testing.T) {
		mockCS := new(MockCertStore)
		mockStorage := new(MockCertificateStorageAdapter)
		adapter := NewTPM2CertStoreAdapterWithStorage(logger, mockCS, mockStorage)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		expectedErr := errors.New("storage error")

		mockStorage.On("SaveCert", mock.Anything, "test.example.com", mock.AnythingOfType("*x509.Certificate")).Return(expectedErr)

		importedCert, err := adapter.ImportCertificate(attrs, certPEM)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, importedCert)
		mockStorage.AssertExpectations(t)
	})

	t.Run("Import without storage adapter error", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		expectedErr := errors.New("store error")

		mockCS.On("StoreCertificate", mock.AnythingOfType("*x509.Certificate")).Return(expectedErr)

		importedCert, err := adapter.ImportCertificate(attrs, certPEM)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, importedCert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Import with malformed certificate in PEM", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
		// Valid PEM structure but invalid certificate data
		malformedPEM := []byte(`-----BEGIN CERTIFICATE-----
bm90IGEgdmFsaWQgY2VydGlmaWNhdGU=
-----END CERTIFICATE-----`)

		importedCert, err := adapter.ImportCertificate(attrs, malformedPEM)
		assert.Error(t, err)
		assert.Nil(t, importedCert)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})
}

func TestObjectStorageAdapter_SaveCert(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Save certificate", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert := createTestCertificate(t, "test.example.com")

		mockObjStore.On("Save", []byte("test-cert.pem"), mock.AnythingOfType("[]uint8")).Return(nil)

		err := adapter.SaveCert(ctx, "test-cert", cert)
		require.NoError(t, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Save certificate with error", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert := createTestCertificate(t, "test.example.com")
		expectedErr := errors.New("storage error")

		mockObjStore.On("Save", []byte("test-cert.pem"), mock.AnythingOfType("[]uint8")).Return(expectedErr)

		err := adapter.SaveCert(ctx, "test-cert", cert)
		assert.Equal(t, expectedErr, err)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_GetCert(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	cert := createTestCertificate(t, "test.example.com")
	certPEM, err := EncodePEM(cert.Raw)
	require.NoError(t, err)

	t.Run("Get existing certificate", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Get", []byte("test-cert.pem")).Return(certPEM, nil)

		retrievedCert, err := adapter.GetCert(ctx, "test-cert")
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get non-existent certificate", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Get", []byte("missing.pem")).Return(nil, object.ErrObjectNotFound)

		retrievedCert, err := adapter.GetCert(ctx, "missing")
		assert.ErrorIs(t, err, ErrCertNotFound)
		assert.Nil(t, retrievedCert)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get with invalid PEM", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Get", []byte("test-cert.pem")).Return([]byte("invalid PEM"), nil)

		retrievedCert, err := adapter.GetCert(ctx, "test-cert")
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, retrievedCert)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get with wrong PEM type", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		// Valid PEM but wrong type
		wrongTypePEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`)

		mockObjStore.On("Get", []byte("test-cert.pem")).Return(wrongTypePEM, nil)

		retrievedCert, err := adapter.GetCert(ctx, "test-cert")
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, retrievedCert)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_DeleteCert(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Delete certificate", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Delete", []byte("test-cert.pem")).Return(nil)

		err := adapter.DeleteCert(ctx, "test-cert")
		require.NoError(t, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Delete certificate with error", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		expectedErr := errors.New("delete error")
		mockObjStore.On("Delete", []byte("test-cert.pem")).Return(expectedErr)

		err := adapter.DeleteCert(ctx, "test-cert")
		assert.Equal(t, expectedErr, err)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_CertChain(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	cert1 := createTestCertificate(t, "cert1.example.com")
	cert2 := createTestCertificate(t, "cert2.example.com")
	chain := []*x509.Certificate{cert1, cert2}

	t.Run("Save and get certificate chain", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		// Save chain
		mockObjStore.On("Save", []byte("test-chain.chain.pem"), mock.AnythingOfType("[]uint8")).Return(nil).Once()

		err := adapter.SaveCertChain(ctx, "test-chain", chain)
		require.NoError(t, err)

		// Get chain
		mockObjStore.On("Get", []byte("test-chain.chain.pem")).Return(func(key []byte) []byte {
			// Create PEM chain
			var pemData []byte
			for _, cert := range chain {
				pemBytes, _ := EncodePEM(cert.Raw)
				pemData = append(pemData, pemBytes...)
			}
			return pemData
		}(nil), nil).Once()

		retrievedChain, err := adapter.GetCertChain(ctx, "test-chain")
		require.NoError(t, err)
		assert.Len(t, retrievedChain, 2)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get non-existent chain", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Get", []byte("missing.chain.pem")).Return(nil, object.ErrObjectNotFound)

		retrievedChain, err := adapter.GetCertChain(ctx, "missing")
		assert.ErrorIs(t, err, ErrChainNotFound)
		assert.Nil(t, retrievedChain)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Save certificate chain with error", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		expectedErr := errors.New("storage error")
		mockObjStore.On("Save", []byte("test-chain.chain.pem"), mock.AnythingOfType("[]uint8")).Return(expectedErr)

		err := adapter.SaveCertChain(ctx, "test-chain", chain)
		assert.Equal(t, expectedErr, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get chain with malformed certificate in PEM", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		// Valid PEM structure but invalid certificate data
		malformedChainPEM := []byte(`-----BEGIN CERTIFICATE-----
bm90IGEgdmFsaWQgY2VydGlmaWNhdGU=
-----END CERTIFICATE-----`)

		mockObjStore.On("Get", []byte("test-chain.chain.pem")).Return(malformedChainPEM, nil)

		retrievedChain, err := adapter.GetCertChain(ctx, "test-chain")
		assert.Error(t, err)
		assert.Nil(t, retrievedChain)
		assert.Contains(t, err.Error(), "failed to parse certificate")
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get chain with empty PEM data returns not found", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		// Data that doesn't decode to any PEM blocks
		mockObjStore.On("Get", []byte("test-chain.chain.pem")).Return([]byte("not a pem"), nil)

		retrievedChain, err := adapter.GetCertChain(ctx, "test-chain")
		assert.ErrorIs(t, err, ErrChainNotFound)
		assert.Nil(t, retrievedChain)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get chain skips non-certificate PEM blocks", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		// Mix of certificate and non-certificate PEM blocks
		certPEM, err := EncodePEM(cert1.Raw)
		require.NoError(t, err)

		privateKeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----
`)
		mixedPEM := append(privateKeyPEM, certPEM...)

		mockObjStore.On("Get", []byte("test-chain.chain.pem")).Return(mixedPEM, nil)

		retrievedChain, err := adapter.GetCertChain(ctx, "test-chain")
		require.NoError(t, err)
		// Should only get the certificate, not the private key
		assert.Len(t, retrievedChain, 1)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_CertExists(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Certificate exists", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Exists", []byte("test-cert.pem")).Return(true)

		exists, err := adapter.CertExists(ctx, "test-cert")
		require.NoError(t, err)
		assert.True(t, exists)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Certificate does not exist", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		mockObjStore.On("Exists", []byte("missing.pem")).Return(false)

		exists, err := adapter.CertExists(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, exists)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_ListCerts(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("ListCerts returns empty list", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		mockObjStore.On("List", "").Return([]string{}, nil)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		certs, err := adapter.ListCerts(ctx)
		require.NoError(t, err)
		assert.Empty(t, certs)
		mockObjStore.AssertExpectations(t)
	})
}

func TestObjectStorageAdapter_Close(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	mockObjStore := new(MockObjectStorer)
	adapter := &ObjectStorageAdapter{
		objStore: mockObjStore,
		logger:   logger,
	}

	err := adapter.Close()
	require.NoError(t, err)
}

func TestNewCertificateStore(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Create certificate store with object storage", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)

		cs, err := NewCertificateStore(logger, mockObjStore)
		require.NoError(t, err)
		assert.NotNil(t, cs)
	})
}

func TestNewCertificateStoreWithStorage(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Create certificate store with storage adapter", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)

		cs, storage, err := NewCertificateStoreWithStorage(logger, mockObjStore)
		require.NoError(t, err)
		assert.NotNil(t, cs)
		assert.NotNil(t, storage)

		// Verify storage adapter is an ObjectStorageAdapter
		_, ok := storage.(*ObjectStorageAdapter)
		assert.True(t, ok)
	})
}

func TestNewTPM2CertStoreAdapter(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Create TPM2 cert store adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)

		adapter := NewTPM2CertStoreAdapter(logger, mockCS)
		assert.NotNil(t, adapter)

		// Verify it implements xkmssdk.TPMCertificateStorer (compile-time check via return type)
		_ = adapter
	})
}

func TestNewTPM2CertStoreAdapterWithStorage(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Create TPM2 cert store adapter with storage", func(t *testing.T) {
		mockCS := new(MockCertStore)
		mockStorage := new(MockCertificateStorageAdapter)

		adapter := NewTPM2CertStoreAdapterWithStorage(logger, mockCS, mockStorage)
		assert.NotNil(t, adapter)

		// Verify it implements xkmssdk.TPMCertificateStorer (compile-time check via return type)
		_ = adapter
	})
}

func TestNewCertStoreAdapter(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Create cert store adapter", func(t *testing.T) {
		mockCS := new(MockCertStore)

		adapter := NewCertStoreAdapter(logger, mockCS)
		assert.NotNil(t, adapter)

		// Verify it implements xkmssdk.TPMCertificateStorer (compile-time check via return type)
		_ = adapter
	})
}

func TestToString(t *testing.T) {
	t.Run("ToString returns string representation", func(t *testing.T) {
		cert := createTestCertificate(t, "test.example.com")

		result := ToString(cert)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test.example.com")
	})

	t.Run("ToString with nil certificate", func(t *testing.T) {
		// The underlying xkmssdk.ToString returns "<nil certificate>" for nil
		result := ToString(nil)
		assert.Equal(t, "<nil certificate>", result)
	})
}

func TestEncodePEM(t *testing.T) {
	cert := createTestCertificate(t, "test.example.com")

	t.Run("Encode valid certificate", func(t *testing.T) {
		pemData, err := EncodePEM(cert.Raw)
		require.NoError(t, err)
		assert.Contains(t, string(pemData), "BEGIN CERTIFICATE")
		assert.Contains(t, string(pemData), "END CERTIFICATE")
	})

	t.Run("Encode empty certificate", func(t *testing.T) {
		pemData, err := EncodePEM([]byte{})
		require.NoError(t, err)
		assert.Contains(t, string(pemData), "BEGIN CERTIFICATE")
		assert.Contains(t, string(pemData), "END CERTIFICATE")
	})
}

func TestDecodePEM(t *testing.T) {
	cert := createTestCertificate(t, "test.example.com")
	pemData, err := EncodePEM(cert.Raw)
	require.NoError(t, err)

	t.Run("Decode valid PEM", func(t *testing.T) {
		decodedCert, err := DecodePEM(pemData)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, decodedCert.Subject.CommonName)
	})

	t.Run("Decode invalid PEM", func(t *testing.T) {
		invalidPEM := []byte("not a PEM")
		decodedCert, err := DecodePEM(invalidPEM)
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, decodedCert)
	})

	t.Run("Decode malformed certificate", func(t *testing.T) {
		malformedPEM := []byte(`-----BEGIN CERTIFICATE-----
bm90IGEgdmFsaWQgY2VydGlmaWNhdGU=
-----END CERTIFICATE-----`)

		decodedCert, err := DecodePEM(malformedPEM)
		assert.Error(t, err)
		assert.Nil(t, decodedCert)
	})
}

func TestEncodeCSR(t *testing.T) {
	t.Run("Encode valid CSR", func(t *testing.T) {
		csrDER := createTestCSR(t, "test.example.com")

		pemData, err := EncodeCSR(csrDER)
		require.NoError(t, err)
		assert.Contains(t, string(pemData), "BEGIN CERTIFICATE REQUEST")
		assert.Contains(t, string(pemData), "END CERTIFICATE REQUEST")
	})

	t.Run("Encode empty CSR", func(t *testing.T) {
		pemData, err := EncodeCSR([]byte{})
		require.NoError(t, err)
		assert.Contains(t, string(pemData), "BEGIN CERTIFICATE REQUEST")
		assert.Contains(t, string(pemData), "END CERTIFICATE REQUEST")
	})
}

func TestDecodeCSR(t *testing.T) {
	csrDER := createTestCSR(t, "test.example.com")
	pemData, err := EncodeCSR(csrDER)
	require.NoError(t, err)

	t.Run("Decode valid CSR PEM", func(t *testing.T) {
		csr, err := DecodeCSR(pemData)
		require.NoError(t, err)
		assert.NotNil(t, csr)
		assert.Equal(t, "test.example.com", csr.Subject.CommonName)
	})

	t.Run("Decode invalid PEM", func(t *testing.T) {
		invalidPEM := []byte("not a PEM")
		csr, err := DecodeCSR(invalidPEM)
		assert.ErrorIs(t, err, ErrInvalidPEM)
		assert.Nil(t, csr)
	})

	t.Run("Decode malformed CSR", func(t *testing.T) {
		malformedPEM := []byte(`-----BEGIN CERTIFICATE REQUEST-----
bm90IGEgdmFsaWQgY3Ny
-----END CERTIFICATE REQUEST-----`)

		csr, err := DecodeCSR(malformedPEM)
		assert.Error(t, err)
		assert.Nil(t, csr)
	})
}

func TestErrors(t *testing.T) {
	t.Run("Error messages are descriptive", func(t *testing.T) {
		assert.Contains(t, ErrCertNotFound.Error(), "certstore")
		assert.Contains(t, ErrChainNotFound.Error(), "certstore")
		assert.Contains(t, ErrInvalidPEM.Error(), "certstore")
	})
}

// TestEncodePEMRoundTrip tests that encoding and decoding produces the same certificate
func TestEncodePEMRoundTrip(t *testing.T) {
	cert := createTestCertificate(t, "roundtrip.example.com")

	pemData, err := EncodePEM(cert.Raw)
	require.NoError(t, err)

	decodedCert, err := DecodePEM(pemData)
	require.NoError(t, err)

	assert.Equal(t, cert.Subject.CommonName, decodedCert.Subject.CommonName)
	assert.Equal(t, cert.SerialNumber, decodedCert.SerialNumber)
	assert.Equal(t, cert.Raw, decodedCert.Raw)
}

// TestEncodeCSRRoundTrip tests that encoding and decoding CSR produces the same result
func TestEncodeCSRRoundTrip(t *testing.T) {
	csrDER := createTestCSR(t, "roundtrip.example.com")

	pemData, err := EncodeCSR(csrDER)
	require.NoError(t, err)

	decodedCSR, err := DecodeCSR(pemData)
	require.NoError(t, err)

	assert.Equal(t, "roundtrip.example.com", decodedCSR.Subject.CommonName)
}

// TestDecodePEM_DifferentPEMTypes tests decoding different PEM block types
func TestDecodePEM_DifferentPEMTypes(t *testing.T) {
	t.Run("Decode CSR as certificate fails", func(t *testing.T) {
		csrDER := createTestCSR(t, "test.example.com")
		csrPEM, err := EncodeCSR(csrDER)
		require.NoError(t, err)

		// Try to decode CSR PEM as certificate - should fail parsing
		_, err = DecodePEM(csrPEM)
		assert.Error(t, err)
	})

	t.Run("Decode certificate as CSR fails", func(t *testing.T) {
		cert := createTestCertificate(t, "test.example.com")
		certPEM, err := EncodePEM(cert.Raw)
		require.NoError(t, err)

		// Try to decode certificate PEM as CSR - should fail parsing
		_, err = DecodeCSR(certPEM)
		assert.Error(t, err)
	})
}

// TestObjectStorageAdapter_MultipleCertificates tests storing multiple certificates
func TestObjectStorageAdapter_MultipleCertificates(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Store and retrieve multiple certificates", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert1 := createTestCertificate(t, "cert1.example.com")
		cert2 := createTestCertificate(t, "cert2.example.com")

		cert1PEM, err := EncodePEM(cert1.Raw)
		require.NoError(t, err)
		cert2PEM, err := EncodePEM(cert2.Raw)
		require.NoError(t, err)

		// Save certificates
		mockObjStore.On("Save", []byte("cert1.pem"), mock.AnythingOfType("[]uint8")).Return(nil)
		mockObjStore.On("Save", []byte("cert2.pem"), mock.AnythingOfType("[]uint8")).Return(nil)

		err = adapter.SaveCert(ctx, "cert1", cert1)
		require.NoError(t, err)
		err = adapter.SaveCert(ctx, "cert2", cert2)
		require.NoError(t, err)

		// Retrieve certificates
		mockObjStore.On("Get", []byte("cert1.pem")).Return(cert1PEM, nil)
		mockObjStore.On("Get", []byte("cert2.pem")).Return(cert2PEM, nil)

		retrievedCert1, err := adapter.GetCert(ctx, "cert1")
		require.NoError(t, err)
		assert.Equal(t, "cert1.example.com", retrievedCert1.Subject.CommonName)

		retrievedCert2, err := adapter.GetCert(ctx, "cert2")
		require.NoError(t, err)
		assert.Equal(t, "cert2.example.com", retrievedCert2.Subject.CommonName)

		mockObjStore.AssertExpectations(t)
	})
}

// TestTPM2CertStoreAdapter_EdgeCases tests edge cases for the TPM2 adapter
func TestTPM2CertStoreAdapter_EdgeCases(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)

	t.Run("Get with whitespace-only CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		adapter := NewTPM2CertStoreAdapter(logger, mockCS)

		attrs := &xkmssdk.KeyAttributes{CN: "   "}
		expectedCert := createTestCertificate(t, "   ")

		mockCS.On("GetCertificate", "   ").Return(expectedCert, nil)

		cert, err := adapter.Get(attrs)
		require.NoError(t, err)
		assert.NotNil(t, cert)
		mockCS.AssertExpectations(t)
	})

	t.Run("Save with special characters in CN", func(t *testing.T) {
		mockCS := new(MockCertStore)
		mockStorage := new(MockCertificateStorageAdapter)
		adapter := NewTPM2CertStoreAdapterWithStorage(logger, mockCS, mockStorage)

		attrs := &xkmssdk.KeyAttributes{CN: "test/cert:with:special.chars"}
		cert := createTestCertificate(t, "test.example.com")

		mockStorage.On("SaveCert", mock.Anything, "test/cert:with:special.chars", cert).Return(nil)

		err := adapter.Save(attrs, cert)
		require.NoError(t, err)
		mockStorage.AssertExpectations(t)
	})
}

// TestDecodePEMEdgeCases tests edge cases for PEM decoding
func TestDecodePEMEdgeCases(t *testing.T) {
	t.Run("Decode PEM with trailing newlines", func(t *testing.T) {
		cert := createTestCertificate(t, "test.example.com")
		pemData, err := EncodePEM(cert.Raw)
		require.NoError(t, err)

		// Add trailing newlines (pem.Decode handles these)
		pemWithNewlines := append(pemData, []byte("\n\n\n")...)

		decodedCert, err := DecodePEM(pemWithNewlines)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, decodedCert.Subject.CommonName)
	})

	t.Run("Decode PEM with multiple blocks returns first", func(t *testing.T) {
		cert1 := createTestCertificate(t, "cert1.example.com")
		cert2 := createTestCertificate(t, "cert2.example.com")

		pem1, err := EncodePEM(cert1.Raw)
		require.NoError(t, err)
		pem2, err := EncodePEM(cert2.Raw)
		require.NoError(t, err)

		// Concatenate two PEM blocks
		multiPEM := append(pem1, pem2...)

		// DecodePEM should return the first certificate
		decodedCert, err := DecodePEM(multiPEM)
		require.NoError(t, err)
		assert.Equal(t, "cert1.example.com", decodedCert.Subject.CommonName)
	})
}

// TestDecodeCSREdgeCases tests edge cases for CSR decoding
func TestDecodeCSREdgeCases(t *testing.T) {
	t.Run("Decode CSR with trailing newlines", func(t *testing.T) {
		csrDER := createTestCSR(t, "test.example.com")
		pemData, err := EncodeCSR(csrDER)
		require.NoError(t, err)

		// Add trailing newlines (pem.Decode handles these)
		pemWithNewlines := append(pemData, []byte("\n\n\n")...)

		decodedCSR, err := DecodeCSR(pemWithNewlines)
		require.NoError(t, err)
		assert.Equal(t, "test.example.com", decodedCSR.Subject.CommonName)
	})
}

// TestObjectStorageAdapter_WithNestedPaths tests certificates with nested path IDs
func TestObjectStorageAdapter_WithNestedPaths(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Save certificate with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert := createTestCertificate(t, "test.example.com")
		nestedID := "org/dept/team/cert"

		mockObjStore.On("Save", []byte("org/dept/team/cert.pem"), mock.AnythingOfType("[]uint8")).Return(nil)

		err := adapter.SaveCert(ctx, nestedID, cert)
		require.NoError(t, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get certificate with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert := createTestCertificate(t, "test.example.com")
		certPEM, err := EncodePEM(cert.Raw)
		require.NoError(t, err)

		nestedID := "org/dept/team/cert"

		mockObjStore.On("Get", []byte("org/dept/team/cert.pem")).Return(certPEM, nil)

		retrievedCert, err := adapter.GetCert(ctx, nestedID)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Delete certificate with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		nestedID := "org/dept/team/cert"

		mockObjStore.On("Delete", []byte("org/dept/team/cert.pem")).Return(nil)

		err := adapter.DeleteCert(ctx, nestedID)
		require.NoError(t, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Check exists for certificate with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		nestedID := "org/dept/team/cert"

		mockObjStore.On("Exists", []byte("org/dept/team/cert.pem")).Return(true)

		exists, err := adapter.CertExists(ctx, nestedID)
		require.NoError(t, err)
		assert.True(t, exists)
		mockObjStore.AssertExpectations(t)
	})
}

// TestObjectStorageAdapter_CertChainWithNestedPaths tests chain operations with nested paths
func TestObjectStorageAdapter_CertChainWithNestedPaths(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Save cert chain with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert1 := createTestCertificate(t, "cert1.example.com")
		cert2 := createTestCertificate(t, "cert2.example.com")
		chain := []*x509.Certificate{cert1, cert2}
		nestedID := "org/dept/chain"

		mockObjStore.On("Save", []byte("org/dept/chain.chain.pem"), mock.AnythingOfType("[]uint8")).Return(nil)

		err := adapter.SaveCertChain(ctx, nestedID, chain)
		require.NoError(t, err)
		mockObjStore.AssertExpectations(t)
	})

	t.Run("Get cert chain with nested path ID", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert1 := createTestCertificate(t, "cert1.example.com")
		cert2 := createTestCertificate(t, "cert2.example.com")
		chain := []*x509.Certificate{cert1, cert2}

		var pemData []byte
		for _, cert := range chain {
			pemBytes, _ := EncodePEM(cert.Raw)
			pemData = append(pemData, pemBytes...)
		}

		nestedID := "org/dept/chain"

		mockObjStore.On("Get", []byte("org/dept/chain.chain.pem")).Return(pemData, nil)

		retrievedChain, err := adapter.GetCertChain(ctx, nestedID)
		require.NoError(t, err)
		assert.Len(t, retrievedChain, 2)
		mockObjStore.AssertExpectations(t)
	})
}

// TestObjectStorageAdapterVerifyPEMFormat tests that saved data is valid PEM format
func TestObjectStorageAdapterVerifyPEMFormat(t *testing.T) {
	logger := logging.NewLogger(0, io.Discard)
	ctx := context.Background()

	t.Run("Verify saved certificate is valid PEM", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert := createTestCertificate(t, "test.example.com")
		var savedData []byte

		mockObjStore.On("Save", []byte("test.pem"), mock.AnythingOfType("[]uint8")).Run(func(args mock.Arguments) {
			savedData = args.Get(1).([]byte)
		}).Return(nil)

		err := adapter.SaveCert(ctx, "test", cert)
		require.NoError(t, err)

		// Verify saved data is valid PEM
		block, _ := pem.Decode(savedData)
		require.NotNil(t, block, "saved data should be valid PEM")
		assert.Equal(t, "CERTIFICATE", block.Type)

		// Verify it can be parsed back
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, parsedCert.Subject.CommonName)

		mockObjStore.AssertExpectations(t)
	})

	t.Run("Verify saved chain is valid PEM", func(t *testing.T) {
		mockObjStore := new(MockObjectStorer)
		adapter := &ObjectStorageAdapter{
			objStore: mockObjStore,
			logger:   logger,
		}

		cert1 := createTestCertificate(t, "cert1.example.com")
		cert2 := createTestCertificate(t, "cert2.example.com")
		chain := []*x509.Certificate{cert1, cert2}
		var savedData []byte

		mockObjStore.On("Save", []byte("chain.chain.pem"), mock.AnythingOfType("[]uint8")).Run(func(args mock.Arguments) {
			savedData = args.Get(1).([]byte)
		}).Return(nil)

		err := adapter.SaveCertChain(ctx, "chain", chain)
		require.NoError(t, err)

		// Verify saved data contains two valid PEM blocks
		data := savedData
		certCount := 0
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			assert.Equal(t, "CERTIFICATE", block.Type)
			certCount++
			data = rest
		}
		assert.Equal(t, 2, certCount)

		mockObjStore.AssertExpectations(t)
	})
}
