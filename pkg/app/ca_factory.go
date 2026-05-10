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

package app

import (
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	objmemory "github.com/jeremyhahn/go-objstore/pkg/memory"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
	localcertstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
)

// CAStoreFactory implements ca.CertStoreFactory, ca.ObjectStoreFactory, and ca.KeyStoreFactory
// to create per-CA certstores, objectstores, and keystores.
//
// Key management uses QuicBaaS SDK for all operations. go-xkms is NOT used
// for key storage - only QuicBaaS provides the KMS backend. This design ensures:
//   - Centralized key management through QuicBaaS
//   - Consistent audit logging
//   - Proper tenant isolation
//   - No dependency on local filesystem for keys
type CAStoreFactory struct {
	app           *App
	platformDir   string
	storage       objectstorage.Client
	certPartition string
}

// NewCAStoreFactory creates a new factory for creating per-CA stores.
// The platformDir is the base directory (e.g., "trusted-data") and each CA
// will have its own subdirectory at platformDir/ca/<ca-cn>/
// Note: soPIN and userPIN are accepted for API consistency but not used.
func NewCAStoreFactory(app *App, platformDir string, storage objectstorage.Client, soPIN, userPIN xkmssdk.Password) *CAStoreFactory {
	// Note: soPIN and userPIN are not used - QuicBaaS handles authentication
	_ = soPIN
	_ = userPIN
	return &CAStoreFactory{
		app:           app,
		platformDir:   platformDir,
		storage:       storage,
		certPartition: "x509",
	}
}

// CreateCertStore implements ca.CertStoreFactory.
// Creates a certificate store for the given CA identity at platformDir/ca/<cn>/x509/
func (f *CAStoreFactory) CreateCertStore(cn string) (interface{}, error) {
	// Build the CA root directory path: platformDir/ca/<cn>/
	caRoot := fmt.Sprintf("%s/ca/%s", f.platformDir, cn)

	f.app.Logger.Debug("Creating certstore for CA",
		"cn", cn,
		"path", caRoot)

	// Create certificate store backend using QuicBaaS ObjectStorage
	certBackend, err := object.NewObjectStore(
		f.app.Logger, f.storage, caRoot, &f.certPartition)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert backend for CA %s: %w", cn, err)
	}

	// Create the certificate store
	certStore, err := localcertstore.NewCertificateStore(f.app.Logger, certBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert store for CA %s: %w", cn, err)
	}

	return certStore, nil
}

// CreateObjectStore implements ca.ObjectStoreFactory.
// Creates an object store for the given CA identity at platformDir/ca/<cn>/
// Returns a common.Storage adapter wrapping the QuicBaaS ObjectStorage client,
// which satisfies go-trusted-ca's CertificateAuthority.ObjectStore() interface.
func (f *CAStoreFactory) CreateObjectStore(cn string) (interface{}, error) {
	// Build the CA root directory path: platformDir/ca/<cn>/
	caRoot := fmt.Sprintf("%s/ca/%s", f.platformDir, cn)

	f.app.Logger.Debug("Creating objectstore for CA",
		"cn", cn,
		"path", caRoot)

	// Create reverse adapter: ObjectStorage -> common.Storage
	// go-trusted-ca's CA interface requires ObjectStore() common.Storage
	caObjStorage := object.NewObjStoreAdapter(f.storage)
	if err := caObjStorage.Configure(map[string]string{"path": caRoot}); err != nil {
		return nil, fmt.Errorf("failed to configure CA object storage for CA %s: %w", cn, err)
	}

	return caObjStorage, nil
}

// CreateKeyStore implements ca.KeyStoreFactory.
// Creates a QuicBaaS-backed keystore for the given CA identity.
//
// All key management operations go through QuicBaaS SDK - no go-xkms
// backends are used for key storage. This ensures centralized, distributed
// key management with proper audit logging and tenant isolation.
func (f *CAStoreFactory) CreateKeyStore(cn string) (interface{}, error) {
	f.app.Logger.Debug("Creating QuicBaaS keystore for CA",
		"cn", cn)

	// Get QuicBaaS clients from the app
	dbSvc := f.app.QuicBaaSService()
	if dbSvc == nil {
		return nil, fmt.Errorf("QuicBaaS service not initialized")
	}

	// Get SDK client for KMS and Crypto operations
	sdkClient := f.app.QuicBaaSSDKClient()
	if sdkClient == nil {
		return nil, fmt.Errorf("QuicBaaS SDK client not initialized")
	}

	// Create certificate store for this CA (certs are stored separately from keys)
	caRoot := fmt.Sprintf("%s/ca/%s", f.platformDir, cn)
	certBackend, err := object.NewObjectStore(
		f.app.Logger, f.storage, caRoot, &f.certPartition)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert backend for CA %s: %w", cn, err)
	}

	certStore, err := localcertstore.NewCertificateStore(f.app.Logger, certBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert store for CA %s: %w", cn, err)
	}

	// Create QuicBaaS-backed keystore
	ks, err := caquicbaas.NewQuicBaaSKeyStore(&caquicbaas.QuicBaaSKeyStoreConfig{
		KMS:       sdkClient.KMS(),
		Crypto:    sdkClient.Crypto(),
		CertStore: certStore,
		Prefix:    fmt.Sprintf("ca.%s.", cn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create QuicBaaS keystore for CA %s: %w", cn, err)
	}

	f.app.Logger.Debug("Created QuicBaaS keystore for CA",
		"cn", cn,
		"prefix", fmt.Sprintf("ca.%s.", cn))

	return ks, nil
}

// Ensure CAStoreFactory implements the expected interfaces
var _ interface {
	CreateCertStore(cn string) (interface{}, error)
} = (*CAStoreFactory)(nil)

var _ interface {
	CreateObjectStore(cn string) (interface{}, error)
} = (*CAStoreFactory)(nil)

var _ interface {
	CreateKeyStore(cn string) (interface{}, error)
} = (*CAStoreFactory)(nil)

// CertStoreFactoryAdapter wraps a xkmssdk.CertStore to return it from the factory.
// This is used for backward compatibility with code that expects a specific certstore.
type CertStoreFactoryAdapter struct {
	certStore xkmssdk.CertStore
}

func (a *CertStoreFactoryAdapter) CreateCertStore(cn string) (interface{}, error) {
	return a.certStore, nil
}

// BootstrapCAStoreFactory implements ca.CertStoreFactory, ca.ObjectStoreFactory,
// and ca.KeyStoreFactory using only local filesystem storage via go-xkms and
// go-objstore. This factory is used during platform CA bootstrap, BEFORE
// QuicBaaS is running, and does not depend on any network services.
//
// After QuicBaaS starts, the regular CAStoreFactory (QuicBaaS-backed) is used
// for all subsequent CA operations.
type BootstrapCAStoreFactory struct {
	logger      *slog.Logger
	platformDir string
	environment Environment
}

// NewBootstrapCAStoreFactory creates a new bootstrap factory for creating per-CA
// stores backed by local filesystem storage. The platformDir is the base directory
// (e.g., "trusted-data") and each CA will have its own subdirectory at
// platformDir/ca/<ca-cn>/.
func NewBootstrapCAStoreFactory(logger *slog.Logger, platformDir string, environment Environment) *BootstrapCAStoreFactory {
	return &BootstrapCAStoreFactory{
		logger:      logger,
		platformDir: platformDir,
		environment: environment,
	}
}

// CreateKeyStore implements ca.KeyStoreFactory.
// Creates a file-backed xkms ServiceBackend for the given CA identity.
// Keys are stored in PKCS#8 format under platformDir/ca/<cn>/keys/.
// This follows the same pattern as go-quicbaas lifecycle.go initializeCA().
func (f *BootstrapCAStoreFactory) CreateKeyStore(cn string) (interface{}, error) {
	keysDir := fmt.Sprintf("%s/ca/%s/keys", f.platformDir, cn)
	certsDir := fmt.Sprintf("%s/ca/%s/certs", f.platformDir, cn)

	f.logger.Debug("Creating bootstrap keystore for CA",
		slog.String("cn", cn),
		slog.String("keysDir", keysDir),
		slog.String("certsDir", certsDir))

	var keyStorage, certStorage xkmssdk.StorageBackend

	if f.environment == EnvTest {
		keyStorage = xkmssdk.NewStorageMemory()
		certStorage = xkmssdk.NewStorageMemory()
	} else {
		var err error
		keyStorage, err = xkmssdk.NewFileStorageBackend(keysDir)
		if err != nil {
			return nil, ErrBootstrapStoreInit{
				Store: "key-storage",
				CN:    cn,
				Cause: err,
			}
		}
		certStorage, err = xkmssdk.NewFileStorageBackend(certsDir)
		if err != nil {
			return nil, ErrBootstrapStoreInit{
				Store: "cert-storage",
				CN:    cn,
				Cause: err,
			}
		}
	}

	// Create PKCS#8 backend for key operations
	pkcs8Backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	if err != nil {
		return nil, ErrBootstrapStoreInit{
			Store: "pkcs8-backend",
			CN:    cn,
			Cause: err,
		}
	}

	// Create unified xkms service backend
	serviceBackend, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     pkcs8Backend,
		CertStorage: certStorage,
	})
	if err != nil {
		return nil, ErrBootstrapStoreInit{
			Store: "service-backend",
			CN:    cn,
			Cause: err,
		}
	}

	f.logger.Debug("Created bootstrap keystore for CA",
		slog.String("cn", cn))

	return serviceBackend, nil
}

// CreateCertStore implements ca.CertStoreFactory.
// Creates a file-backed xkms CertStore for the given CA identity.
// Certificates are stored under platformDir/ca/<cn>/certs/.
func (f *BootstrapCAStoreFactory) CreateCertStore(cn string) (interface{}, error) {
	certsDir := fmt.Sprintf("%s/ca/%s/certs", f.platformDir, cn)

	f.logger.Debug("Creating bootstrap certstore for CA",
		slog.String("cn", cn),
		slog.String("certsDir", certsDir))

	var certStorage xkmssdk.StorageBackend

	if f.environment == EnvTest {
		certStorage = xkmssdk.NewStorageMemory()
	} else {
		var err error
		certStorage, err = xkmssdk.NewFileStorageBackend(certsDir)
		if err != nil {
			return nil, ErrBootstrapStoreInit{
				Store: "cert-storage",
				CN:    cn,
				Cause: err,
			}
		}
	}

	// Create certificate adapter and cert store
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorage)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	if err != nil {
		return nil, ErrBootstrapStoreInit{
			Store: "cert-store",
			CN:    cn,
			Cause: err,
		}
	}

	f.logger.Debug("Created bootstrap certstore for CA",
		slog.String("cn", cn))

	return certStore, nil
}

// CreateObjectStore implements ca.ObjectStoreFactory.
// Creates a local filesystem-backed common.Storage for the given CA identity.
// Objects are stored under platformDir/ca/<cn>/.
func (f *BootstrapCAStoreFactory) CreateObjectStore(cn string) (interface{}, error) {
	caRoot := fmt.Sprintf("%s/ca/%s", f.platformDir, cn)

	f.logger.Debug("Creating bootstrap objectstore for CA",
		slog.String("cn", cn),
		slog.String("path", caRoot))

	var objStorage interface{ Configure(map[string]string) error }

	if f.environment == EnvTest {
		objStorage = objmemory.New()
	} else {
		objStorage = local.New()
	}

	if err := objStorage.Configure(map[string]string{"path": caRoot}); err != nil {
		return nil, ErrBootstrapStoreInit{
			Store: "object-store",
			CN:    cn,
			Cause: err,
		}
	}

	f.logger.Debug("Created bootstrap objectstore for CA",
		slog.String("cn", cn))

	return objStorage, nil
}

// Ensure BootstrapCAStoreFactory implements the expected interfaces
var _ interface {
	CreateCertStore(cn string) (interface{}, error)
} = (*BootstrapCAStoreFactory)(nil)

var _ interface {
	CreateObjectStore(cn string) (interface{}, error)
} = (*BootstrapCAStoreFactory)(nil)

var _ interface {
	CreateKeyStore(cn string) (interface{}, error)
} = (*BootstrapCAStoreFactory)(nil)
