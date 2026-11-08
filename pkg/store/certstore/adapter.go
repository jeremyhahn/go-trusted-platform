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

// Package certstore provides adapter types and functions for bridging between
// go-trusted-platform's certificate store usage and go-xkms's CertStore implementation.
package certstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
)

var (
	ErrCertNotFound  = errors.New("certstore: certificate not found")
	ErrChainNotFound = errors.New("certstore: certificate chain not found")
	ErrInvalidPEM    = errors.New("certstore: invalid PEM data")
)

// CertificateStorer is an alias for go-xkms's CertStore interface
// for backward compatibility.
type CertificateStorer = xkmssdk.CertStore

// CertificateStorageAdapter is an alias for direct storage operations
type CertificateStorageAdapter = xkmssdk.CertificateStorageAdapter

// TPM2CertStoreAdapter implements xkmssdk.TPMCertificateStorer by wrapping a CertStore.
// This adapter translates between KeyAttributes-based storage and CN-based storage.
type TPM2CertStoreAdapter struct {
	logger    *logging.Logger
	certStore xkmssdk.CertStore
	storage   CertificateStorageAdapter // Direct storage access for custom ID operations
}

// Get retrieves a certificate using KeyAttributes
func (a *TPM2CertStoreAdapter) Get(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, xkmssdk.ErrTPMStoreCertNotFound
	}
	cert, err := a.certStore.GetCertificate(attrs.CN)
	if err != nil {
		// Convert local not-found errors to xkmssdk.ErrTPMStoreCertNotFound
		// so the TPM module can properly detect and handle this case
		if errors.Is(err, ErrCertNotFound) || errors.Is(err, xkmssdk.ErrCertNotFound) {
			return nil, xkmssdk.ErrTPMStoreCertNotFound
		}
		// Also check for object not found errors
		if errors.Is(err, object.ErrObjectNotFound) {
			return nil, xkmssdk.ErrTPMStoreCertNotFound
		}
		return nil, err
	}
	return cert, nil
}

// Save stores a certificate using KeyAttributes.
// Uses attrs.CN as the storage key to ensure consistent lookup.
func (a *TPM2CertStoreAdapter) Save(attrs *xkmssdk.KeyAttributes, cert *x509.Certificate) error {
	if attrs == nil || attrs.CN == "" || cert == nil {
		return errors.New("certstore: invalid parameters")
	}
	// Use direct storage access with attrs.CN as the key for consistent lookup
	if a.storage != nil {
		return a.storage.SaveCert(context.Background(), attrs.CN, cert)
	}
	// Fall back to certStore.StoreCertificate which uses cert.Subject.CommonName
	return a.certStore.StoreCertificate(cert)
}

// Delete removes a certificate using KeyAttributes
func (a *TPM2CertStoreAdapter) Delete(attrs *xkmssdk.KeyAttributes) error {
	if attrs == nil || attrs.CN == "" {
		return xkmssdk.ErrTPMStoreCertNotFound
	}
	return a.certStore.DeleteCertificate(attrs.CN)
}

// ImportCertificate imports a PEM-encoded certificate.
// Uses attrs.CN as the storage key to ensure consistent lookup.
func (a *TPM2CertStoreAdapter) ImportCertificate(attrs *xkmssdk.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, errors.New("certstore: invalid key attributes")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEM
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &WrappedError{Msg: "certstore: failed to parse certificate", Err: err}
	}

	// Use direct storage access with attrs.CN as the key for consistent lookup
	if a.storage != nil {
		if err := a.storage.SaveCert(context.Background(), attrs.CN, cert); err != nil {
			return nil, err
		}
		return cert, nil
	}

	// Fall back to certStore.StoreCertificate which uses cert.Subject.CommonName
	if err := a.certStore.StoreCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// ObjectStorageAdapter implements xkmssdk.CertificateStorageAdapter using
// go-trusted-platform's object storage.
type ObjectStorageAdapter struct {
	objStore object.ObjectStorer
	logger   *logging.Logger
}

// SaveCert saves a certificate to object storage.
// Uses .pem extension: certs/{id}.pem
//
// The id frequently comes from a cert's CommonName (e.g. ACME
// enrollment passes ctx.Certificate.Subject.CommonName here). TCG
// CSR-IDevID certs commonly carry CNs like "SuperMicro X10-node-01-edge-01"
// containing whitespace, which the underlying object-storage path
// validator rejects (PATH_INVALID, no control chars / no spaces).
// We sanitize the id to a filesystem-safe form on write and apply
// the same transformation on every read so the round-trip is
// transparent to callers.
func (a *ObjectStorageAdapter) SaveCert(ctx context.Context, id string, cert *x509.Certificate) error {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	data := pem.EncodeToMemory(pemBlock)
	return a.objStore.Save([]byte(sanitizeCertID(id)+".pem"), data)
}

// GetCert retrieves a certificate from object storage.
// Looks for certificate at: certs/{id}.pem
func (a *ObjectStorageAdapter) GetCert(ctx context.Context, id string) (*x509.Certificate, error) {
	data, err := a.objStore.Get([]byte(sanitizeCertID(id) + ".pem"))
	if err != nil {
		return nil, ErrCertNotFound
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEM
	}

	return x509.ParseCertificate(block.Bytes)
}

// DeleteCert removes a certificate from object storage.
func (a *ObjectStorageAdapter) DeleteCert(ctx context.Context, id string) error {
	return a.objStore.Delete([]byte(sanitizeCertID(id) + ".pem"))
}

// SaveCertChain saves a certificate chain to object storage.
func (a *ObjectStorageAdapter) SaveCertChain(ctx context.Context, id string, chain []*x509.Certificate) error {
	var pemData []byte
	for _, cert := range chain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(pemBlock)...)
	}
	return a.objStore.Save([]byte(sanitizeCertID(id)+".chain.pem"), pemData)
}

// GetCertChain retrieves a certificate chain from object storage.
func (a *ObjectStorageAdapter) GetCertChain(ctx context.Context, id string) ([]*x509.Certificate, error) {
	data, err := a.objStore.Get([]byte(sanitizeCertID(id) + ".chain.pem"))
	if err != nil {
		return nil, ErrChainNotFound
	}

	var chain []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, &WrappedError{Msg: "certstore: failed to parse certificate", Err: err}
			}
			chain = append(chain, cert)
		}
		data = rest
	}

	if len(chain) == 0 {
		return nil, ErrChainNotFound
	}
	return chain, nil
}

// certPEMSuffix is the file extension used for certificate PEM files.
const certPEMSuffix = ".pem"

// certChainPEMSuffix is the file extension used for certificate chain PEM files.
const certChainPEMSuffix = ".chain.pem"

// ListCerts lists all certificate IDs in the object storage.
// It uses the ObjectStorer's List method to enumerate certificate files,
// then strips the path prefix and .pem suffix to return bare certificate IDs (CNs).
// Certificate chain files (.chain.pem) are excluded from the results.
func (a *ObjectStorageAdapter) ListCerts(ctx context.Context) ([]string, error) {
	keys, err := a.objStore.List("")
	if err != nil {
		return []string{}, nil
	}

	var ids []string
	for _, key := range keys {
		// Skip certificate chain files
		if strings.HasSuffix(key, certChainPEMSuffix) {
			continue
		}
		// Only include .pem certificate files
		if !strings.HasSuffix(key, certPEMSuffix) {
			continue
		}
		// Strip the prefix path and .pem suffix to get the certificate ID (CN)
		base := filepath.Base(key)
		id := strings.TrimSuffix(base, certPEMSuffix)
		if id != "" {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// CertExists checks if a certificate exists in object storage.
func (a *ObjectStorageAdapter) CertExists(ctx context.Context, id string) (bool, error) {
	exists := a.objStore.Exists([]byte(sanitizeCertID(id) + ".pem"))
	return exists, nil
}

// sanitizeCertID rewrites a cert identifier (typically the cert's CN)
// into a form that's safe to use as a path component in the underlying
// object store. The store rejects paths containing whitespace, control
// characters, or consecutive slashes, but real-world certs frequently
// arrive with CNs like "SuperMicro X10-node-01-edge-01" — TCG IDevID
// certs in particular often carry vendor/model/serial separated by
// spaces.
//
// Mapping rules:
//   - ASCII alphanumerics, hyphens, dots, underscores, and forward
//     slashes pass through. Slashes are preserved because callers
//     legitimately use nested paths like "org/dept/team/cert".
//   - Everything else (whitespace, control chars, other punctuation,
//     non-ASCII) is replaced with a single hyphen, with runs
//     collapsed so "Super  Micro" doesn't become "Super--Micro".
//   - Leading/trailing hyphens and dots are trimmed.
//
// The transformation is deterministic and applied symmetrically on
// both writes and reads, so callers see the original id unchanged.
func sanitizeCertID(id string) string {
	if id == "" {
		return ""
	}
	var b strings.Builder
	prevHyphen := false
	for _, r := range id {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == '/':
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-.")
}

// Close closes the adapter (no-op for object storage).
func (a *ObjectStorageAdapter) Close() error {
	return nil
}

// NewCertificateStore creates a new certificate store using the provided
// object storage backend. This is a wrapper around go-xkms's xkmssdk.NewCertStore.
func NewCertificateStore(logger *logging.Logger, objStore object.ObjectStorer) (CertificateStorer, error) {
	config := &xkmssdk.CertStoreConfig{
		CertStorage: &ObjectStorageAdapter{
			objStore: objStore,
			logger:   logger,
		},
	}
	return xkmssdk.NewCertStore(config)
}

// NewCertificateStoreWithStorage creates a new certificate store and returns both
// the store and the underlying storage adapter for direct access operations.
func NewCertificateStoreWithStorage(logger *logging.Logger, objStore object.ObjectStorer) (CertificateStorer, CertificateStorageAdapter, error) {
	storage := &ObjectStorageAdapter{
		objStore: objStore,
		logger:   logger,
	}
	config := &xkmssdk.CertStoreConfig{
		CertStorage: storage,
	}
	cs, err := xkmssdk.NewCertStore(config)
	if err != nil {
		return nil, nil, err
	}
	return cs, storage, nil
}

// NewTPM2CertStoreAdapter creates a certificate store adapter for TPM2-backed
// storage. This wraps a CertStore to provide the xkmssdk.TPMCertificateStorer interface
// expected by tpm2.Params.
func NewTPM2CertStoreAdapter(logger *logging.Logger, cs CertificateStorer) xkmssdk.TPMCertificateStorer {
	return &TPM2CertStoreAdapter{
		logger:    logger,
		certStore: cs,
	}
}

// NewTPM2CertStoreAdapterWithStorage creates a certificate store adapter with
// direct storage access for operations that need custom storage keys.
func NewTPM2CertStoreAdapterWithStorage(logger *logging.Logger, cs CertificateStorer, storage CertificateStorageAdapter) xkmssdk.TPMCertificateStorer {
	return &TPM2CertStoreAdapter{
		logger:    logger,
		certStore: cs,
		storage:   storage,
	}
}

// NewCertStoreAdapter creates a certificate store adapter that provides
// go-trusted-ca's CertificateStorer interface for use with CA operations.
// This is a convenience function that wraps the TPM2CertStoreAdapter.
func NewCertStoreAdapter(logger *logging.Logger, cs CertificateStorer) xkmssdk.TPMCertificateStorer {
	return NewTPM2CertStoreAdapter(logger, cs)
}

// ToString returns a human-readable string representation of a certificate.
// This is a convenience wrapper around go-xkms's xkmssdk.CertToString function.
func ToString(cert *x509.Certificate) string {
	return xkmssdk.CertToString(cert)
}

// EncodePEM encodes a raw DER byte array as a PEM byte array.
func EncodePEM(derCert []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return nil, err
	}
	return caPEM.Bytes(), nil
}

// DecodePEM decodes PEM bytes to *x509.Certificate.
func DecodePEM(pemData []byte) (*x509.Certificate, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemData); block == nil {
		return nil, ErrInvalidPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

// EncodeCSR encodes a Certificate Signing Request to PEM form.
func EncodeCSR(csr []byte) ([]byte, error) {
	csrPEM := new(bytes.Buffer)
	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	if err := pem.Encode(csrPEM, csrBlock); err != nil {
		return nil, err
	}
	return csrPEM.Bytes(), nil
}

// DecodeCSR decodes CSR bytes to x509.CertificateRequest.
func DecodeCSR(pemData []byte) (*x509.CertificateRequest, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemData); block == nil {
		return nil, ErrInvalidPEM
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
