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

// Package caquicbaas provides adapters for integrating QuicBaaS with go-trusted-ca.
// This file provides a KeyStore adapter that implements xkmssdk.ServiceBackend
// using QuicBaaS SDK for all key management operations.
package caquicbaas

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	quicbaascrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// QuicBaaSKeyStore implements xkmssdk.ServiceBackend using QuicBaaS SDK for all
// key management operations. This adapter allows go-trusted-ca to use
// QuicBaaS as its underlying key storage without depending on go-xkms
// backends for non-hardware operations.
//
// Thread-safety: All operations delegate to the thread-safe QuicBaaS SDK client.
type QuicBaaSKeyStore struct {
	kms       quicbaassdk.KMSClient
	crypto    quicbaassdk.CryptoClient
	certStore xkmssdk.CertStore
	prefix    string // Key ID prefix for namespacing (e.g., "ca.root.")
}

// QuicBaaSKeyStoreConfig configures the QuicBaaS key store adapter.
type QuicBaaSKeyStoreConfig struct {
	// KMS is the QuicBaaS SDK KMS client for key operations.
	KMS quicbaassdk.KMSClient

	// Crypto is the QuicBaaS SDK Crypto client for signing/encryption.
	Crypto quicbaassdk.CryptoClient

	// CertStore is used for certificate storage (external to QuicBaaS KMS).
	CertStore xkmssdk.CertStore

	// Prefix is prepended to all key IDs for namespacing.
	// Example: "ca.root." results in keys like "ca.root.mykey"
	Prefix string
}

// NewQuicBaaSKeyStore creates a new QuicBaaS-backed KeyStore.
func NewQuicBaaSKeyStore(cfg *QuicBaaSKeyStoreConfig) (*QuicBaaSKeyStore, error) {
	if cfg == nil {
		return nil, ErrInvalidInput{Field: "config", Reason: "config is required"}
	}
	if cfg.KMS == nil {
		return nil, ErrInvalidInput{Field: "kms", Reason: "KMS client is required"}
	}
	if cfg.Crypto == nil {
		return nil, ErrInvalidInput{Field: "crypto", Reason: "Crypto client is required"}
	}

	return &QuicBaaSKeyStore{
		kms:       cfg.KMS,
		crypto:    cfg.Crypto,
		certStore: cfg.CertStore,
		prefix:    cfg.Prefix,
	}, nil
}

// keyIDFromAttrs generates a namespaced key ID from the key attributes.
//
// Format: prefix + CN + "." + algorithm (e.g., "ca.root-ca.example.com.leaf.example.com.ecdsa")
//
// The prefix already scopes the key to a specific CA (e.g., "ca.ca01.localhost.").
// Within that namespace each key must be uniquely identified by both the certificate's
// CN and the algorithm, because a single CA issues many leaf certificates and stores
// one key per certificate. Using only the algorithm as the suffix (the previous
// design) caused all ECDSA leaf keys — including the CA's own signing key — to
// collide on the same name, which caused revocation of any ECDSA leaf to delete the
// CA's signing key and rendered subsequent issuances impossible within the same
// daemon session.
//
// When attrs.CN is empty and the algorithm is unknown, the key falls back to "key"
// to remain safe for symmetric or exotic key types.
func (ks *QuicBaaSKeyStore) keyIDFromAttrs(attrs *xkmssdk.KeyAttributes) string {
	var algSuffix string
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		algSuffix = "rsa"
	case x509.ECDSA:
		algSuffix = "ecdsa"
	case x509.Ed25519:
		algSuffix = "ed25519"
	default:
		// Unknown or symmetric key: use CN alone when available.
		if attrs.CN != "" {
			return ks.prefix + attrs.CN
		}
		return ks.prefix + "key"
	}

	if attrs.CN != "" {
		return ks.prefix + attrs.CN + "." + algSuffix
	}
	return ks.prefix + algSuffix
}

// sdkAlgorithmToX509 maps QuicBaaS SDK algorithm to x509 key algorithm.
// QuicBaaS KMS supports: RSA2048, RSA4096, ECDSAP256, ECDSAP384, ED25519.
func (ks *QuicBaaSKeyStore) sdkAlgorithmToX509(alg kms.KeyAlgorithm) x509.PublicKeyAlgorithm {
	switch alg {
	case kms.AlgorithmRSA2048, kms.AlgorithmRSA4096:
		return x509.RSA
	case kms.AlgorithmECDSAP256, kms.AlgorithmECDSAP384:
		return x509.ECDSA
	case kms.AlgorithmED25519:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// getPublicKey retrieves the public key from QuicBaaS KMS and parses it.
func (ks *QuicBaaSKeyStore) getPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	resp, err := ks.kms.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if resp == nil || len(resp.PublicKey) == 0 {
		return nil, ErrOperationFailed{Operation: "getPublicKey", Cause: ErrKeyNotFound{KeyID: keyID}}
	}

	// Parse the DER-encoded public key
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "getPublicKey", Cause: err}
	}

	return publicKey, nil
}

// GenerateRSA generates a new RSA key pair using QuicBaaS KMS.
func (ks *QuicBaaSKeyStore) GenerateRSA(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)
	algorithm := kms.AlgorithmRSA2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize >= 4096 {
		algorithm = kms.AlgorithmRSA4096
	}

	req := &kms.GenerateKeyRequest{
		Name:      keyID,
		Algorithm: algorithm,
		Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
	}

	_, err := ks.kms.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateRSA", Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateRSA", Cause: err}
	}

	// Return a signer wrapper that uses QuicBaaS for signing
	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GenerateECDSA generates a new ECDSA key pair using QuicBaaS KMS.
func (ks *QuicBaaSKeyStore) GenerateECDSA(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)
	algorithm := kms.AlgorithmECDSAP256
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve.Params().BitSize >= 384 {
		algorithm = kms.AlgorithmECDSAP384
	}

	req := &kms.GenerateKeyRequest{
		Name:      keyID,
		Algorithm: algorithm,
		Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
	}

	_, err := ks.kms.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateECDSA", Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateECDSA", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GenerateEd25519 generates a new Ed25519 key pair using QuicBaaS KMS.
func (ks *QuicBaaSKeyStore) GenerateEd25519(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	req := &kms.GenerateKeyRequest{
		Name:      keyID,
		Algorithm: kms.AlgorithmED25519,
		Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
	}

	_, err := ks.kms.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateEd25519", Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateEd25519", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GetKey retrieves an existing key.
func (ks *QuicBaaSKeyStore) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	_, err := ks.kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: keyID, Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GetKey", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GetKeyByID retrieves a key using the unified Key ID format.
// The keyID is used directly (with prefix applied if configured).
func (ks *QuicBaaSKeyStore) GetKeyByID(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	if keyID == "" {
		return nil, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}

	// Apply prefix if the keyID doesn't already have it
	fullKeyID := keyID
	if ks.prefix != "" && !strings.HasPrefix(keyID, ks.prefix) {
		fullKeyID = ks.prefix + keyID
	}

	_, err := ks.kms.GetKey(ctx, fullKeyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: fullKeyID, Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, fullKeyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GetKeyByID", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     fullKeyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
func (ks *QuicBaaSKeyStore) GetSignerByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	if keyID == "" {
		return nil, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}

	// Apply prefix if the keyID doesn't already have it
	fullKeyID := keyID
	if ks.prefix != "" && !strings.HasPrefix(keyID, ks.prefix) {
		fullKeyID = ks.prefix + keyID
	}

	_, err := ks.kms.GetKey(ctx, fullKeyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: fullKeyID, Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, fullKeyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GetSignerByID", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     fullKeyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
func (ks *QuicBaaSKeyStore) GetDecrypterByID(ctx context.Context, keyID string) (crypto.Decrypter, error) {
	if keyID == "" {
		return nil, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}

	// Apply prefix if the keyID doesn't already have it
	fullKeyID := keyID
	if ks.prefix != "" && !strings.HasPrefix(keyID, ks.prefix) {
		fullKeyID = ks.prefix + keyID
	}

	_, err := ks.kms.GetKey(ctx, fullKeyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: fullKeyID, Cause: err}
	}

	return &quicbaasDecrypter{
		keyID:  fullKeyID,
		crypto: ks.crypto,
	}, nil
}

// DeleteKey deletes a key.
func (ks *QuicBaaSKeyStore) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	if attrs == nil {
		return ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	return ks.kms.DeleteKey(ctx, keyID)
}

// ListKeys returns all key attributes for keys managed by this XKMS backend.
func (ks *QuicBaaSKeyStore) ListKeys(ctx context.Context) ([]*xkmssdk.KeyAttributes, error) {
	resp, err := ks.kms.ListKeys(ctx)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "ListKeys", Cause: err}
	}

	attrs := make([]*xkmssdk.KeyAttributes, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		// Strip the prefix from the key ID to get the CN
		cn := k.KeyID
		if ks.prefix != "" && strings.HasPrefix(k.KeyID, ks.prefix) {
			cn = strings.TrimPrefix(k.KeyID, ks.prefix)
		}

		attr := &xkmssdk.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: ks.sdkAlgorithmToX509(k.Algorithm),
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

// RotateKey rotates a key to a new version.
func (ks *QuicBaaSKeyStore) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	_, err := ks.kms.RotateKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "RotateKey", Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "RotateKey", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// Signer returns a crypto.Signer for the key.
func (ks *QuicBaaSKeyStore) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	// Verify key exists
	_, err := ks.kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: keyID, Cause: err}
	}

	// Retrieve the public key for the signer
	publicKey, err := ks.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "Signer", Cause: err}
	}

	return &quicbaasSigner{
		keyID:     keyID,
		kms:       ks.kms,
		crypto:    ks.crypto,
		publicKey: publicKey,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key.
func (ks *QuicBaaSKeyStore) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	keyID := ks.keyIDFromAttrs(attrs)

	// Verify key exists
	_, err := ks.kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: keyID, Cause: err}
	}

	return &quicbaasDecrypter{
		keyID:  keyID,
		crypto: ks.crypto,
	}, nil
}

// Certificate operations delegate to the cert store.
// Note: xkmssdk.CertStore uses CN derived from certificate for storage.
// The keyID parameter is provided for API compatibility but certificates
// are indexed by their Subject.CommonName.

// SaveCert saves a certificate.
func (ks *QuicBaaSKeyStore) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	if ks.certStore == nil {
		return ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}
	return ks.certStore.StoreCertificate(cert)
}

// GetCert retrieves a certificate.
func (ks *QuicBaaSKeyStore) GetCert(ctx context.Context, keyID string) (*x509.Certificate, error) {
	if ks.certStore == nil {
		return nil, ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}
	return ks.certStore.GetCertificate(keyID)
}

// DeleteCert deletes a certificate.
func (ks *QuicBaaSKeyStore) DeleteCert(ctx context.Context, keyID string) error {
	if ks.certStore == nil {
		return ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}
	return ks.certStore.DeleteCertificate(keyID)
}

// SaveCertChain saves a certificate chain.
func (ks *QuicBaaSKeyStore) SaveCertChain(ctx context.Context, keyID string, certs []*x509.Certificate) error {
	if ks.certStore == nil {
		return ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}
	return ks.certStore.StoreCertificateChain(certs)
}

// GetCertChain retrieves a certificate chain.
func (ks *QuicBaaSKeyStore) GetCertChain(ctx context.Context, keyID string) ([]*x509.Certificate, error) {
	if ks.certStore == nil {
		return nil, ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}
	return ks.certStore.GetCertificateChain(keyID)
}

// ListCerts returns all certificate IDs currently stored.
func (ks *QuicBaaSKeyStore) ListCerts(ctx context.Context) ([]string, error) {
	if ks.certStore == nil {
		return nil, ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}

	certs, err := ks.certStore.ListCertificates()
	if err != nil {
		return nil, ErrOperationFailed{Operation: "ListCerts", Cause: err}
	}

	ids := make([]string, 0, len(certs))
	for _, cert := range certs {
		ids = append(ids, cert.Subject.CommonName)
	}
	return ids, nil
}

// CertExists checks if a certificate exists for the given key ID.
func (ks *QuicBaaSKeyStore) CertExists(ctx context.Context, keyID string) (bool, error) {
	if ks.certStore == nil {
		return false, ErrInvalidInput{Field: "certStore", Reason: "cert store not configured"}
	}

	cert, err := ks.certStore.GetCertificate(keyID)
	if err != nil {
		// If the error indicates not found, return false without error
		return false, nil
	}
	return cert != nil, nil
}

// GetTLSCertificate returns a TLS certificate for the key.
// The keyID parameter is used to locate the certificate.
// The attrs parameter is used to locate the signing key.
//
// The chain lookup is best-effort — when the cert chain object is
// missing from the cert store we fall back to serving just the leaf
// certificate, matching go-xkms's compositeBackend behaviour. This
// matters because the webservice's initial cert issuance only stores
// the leaf under the target CN: the chain object is only written when
// an explicit cross-sign or chain-import runs, which may not have
// happened at first startup. Without this fallback the webserver's
// startHTTPS path calls logger.FatalError and silently exits 255 (we
// debugged this on node-02 first boot: cert PEM was in QuicBaaS
// objectstorage, `<cn>.chain.pem` was not, server died before opening
// any listening ports). Serving only the leaf is correct in
// single-hop CA topologies; clients that need the issuer chain pull
// it via AIA.
func (ks *QuicBaaSKeyStore) GetTLSCertificate(ctx context.Context, keyID string, attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	if keyID == "" {
		return tls.Certificate{}, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}
	if attrs == nil {
		return tls.Certificate{}, ErrInvalidInput{Field: "attrs", Reason: "key attributes are required"}
	}

	signer, err := ks.Signer(ctx, attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	chain, chainErr := ks.GetCertChain(ctx, keyID)
	if chainErr != nil || len(chain) == 0 {
		// Chain not available — fall back to the leaf cert under the
		// same CN. GetCert handles the bare cert lookup.
		leaf, leafErr := ks.GetCert(ctx, keyID)
		if leafErr != nil {
			return tls.Certificate{}, ErrKeyNotFound{KeyID: keyID, Cause: leafErr}
		}
		chain = []*x509.Certificate{leaf}
	}

	tlsCert := tls.Certificate{
		PrivateKey: signer,
	}
	for _, cert := range chain {
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}
	tlsCert.Leaf = chain[0]

	return tlsCert, nil
}

// KeyID returns the key ID for the given attributes.
func (ks *QuicBaaSKeyStore) KeyID(attrs *xkmssdk.KeyAttributes) string {
	return ks.keyIDFromAttrs(attrs)
}

// ParseKeyID parses a key ID into key attributes.
func (ks *QuicBaaSKeyStore) ParseKeyID(keyID string) (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		CN: keyID,
	}, nil
}

// Seal and Unseal operations - uses new interface signatures.

// Seal seals data using the backend's native sealing mechanism.
// QuicBaaS KMS does not support TPM-style sealing - returns error.
func (ks *QuicBaaSKeyStore) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	return nil, ErrUnsupportedOperation{
		Operation: "Seal",
		Reason:    "QuicBaaS KMS does not support sealing operations - use go-xkms TPM2 backend",
	}
}

// Unseal decrypts/recovers data that was previously sealed.
// QuicBaaS KMS does not support TPM-style unsealing - returns error.
func (ks *QuicBaaSKeyStore) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	return nil, ErrUnsupportedOperation{
		Operation: "Unseal",
		Reason:    "QuicBaaS KMS does not support unsealing operations - use go-xkms TPM2 backend",
	}
}

// CanSeal returns true if the backend supports sealing operations.
// QuicBaaS KMS does not support TPM-style sealing.
func (ks *QuicBaaSKeyStore) CanSeal() bool {
	return false
}

// KeyProvider returns the underlying key provider - not applicable for QuicBaaS.
// QuicBaaS uses external KMS, not a local backend.
func (ks *QuicBaaSKeyStore) KeyProvider() xkmssdk.KeyProvider {
	return nil
}

// Type reports what kind of backend holds this keystore's keys. The keys live
// in the control plane's quicbaas KMS, reached over the SDK, whose backend
// (software, TPM, PKCS#11, cloud KMS) is the server's configuration and is
// not visible to this adapter, so the answer is StoreUnknown rather than a
// guess. The CA does not read it: an issuing identity's keystore type comes
// from that identity's configured KeystoreType.
func (ks *QuicBaaSKeyStore) Type() xkmssdk.StoreType {
	return xkmssdk.StoreUnknown
}

// CertStorage returns the certificate storage adapter.
// Returns nil as we use xkmssdk.CertStore directly.
func (ks *QuicBaaSKeyStore) CertStorage() xkmssdk.CertificateStorageAdapter {
	return nil
}

// Close releases all resources held by the XKMS backend.
// QuicBaaS clients are managed externally, so this is a no-op.
func (ks *QuicBaaSKeyStore) Close() error {
	return nil
}

// quicbaasSigner implements crypto.Signer using QuicBaaS.
type quicbaasSigner struct {
	keyID     string
	kms       quicbaassdk.KMSClient
	crypto    quicbaassdk.CryptoClient
	publicKey crypto.PublicKey // Cached from certificate if available
}

// Public returns the public key.
// Note: QuicBaaS KMS doesn't expose public keys directly. The public key
// must be retrieved from the associated certificate.
func (s *quicbaasSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest.
func (s *quicbaasSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// crypto.Signer.Sign is a fixed stdlib interface boundary with no ctx
	// parameter, so the request context cannot be threaded here.
	ctx := context.Background()

	// Map crypto.SignerOpts to QuicBaaS hash algorithm
	hashAlg := quicbaascrypto.HashSHA256
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA384:
			hashAlg = quicbaascrypto.HashSHA384
		case crypto.SHA512:
			hashAlg = quicbaascrypto.HashSHA512
		default:
			hashAlg = quicbaascrypto.HashSHA256
		}
	}

	req := &quicbaascrypto.SignRequest{
		KeyID:     s.keyID,
		Data:      digest,
		HashAlg:   hashAlg,
		PreHashed: true, // digest is already hashed by the crypto.Signer caller
	}

	resp, err := s.crypto.Sign(ctx, req)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "Sign", Cause: err}
	}
	return resp.Signature, nil
}

// quicbaasDecrypter implements crypto.Decrypter using QuicBaaS.
type quicbaasDecrypter struct {
	keyID     string
	kms       quicbaassdk.KMSClient
	crypto    quicbaassdk.CryptoClient
	publicKey crypto.PublicKey // Cached from certificate if available
}

// Public returns the public key.
func (d *quicbaasDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the ciphertext.
func (d *quicbaasDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	// crypto.Decrypter.Decrypt is a fixed stdlib interface boundary with no
	// ctx parameter, so the request context cannot be threaded here.
	ctx := context.Background()

	req := &quicbaascrypto.DecryptRequest{
		KeyID:      d.keyID,
		Ciphertext: ciphertext,
	}

	resp, err := d.crypto.Decrypt(ctx, req)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "Decrypt", Cause: err}
	}
	return resp.Plaintext, nil
}

// Compile-time interface check
var _ xkmssdk.ServiceBackend = (*QuicBaaSKeyStore)(nil)
