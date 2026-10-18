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
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeSecretStore is an in-memory secretStore used to exercise the Secure Boot
// provisioner without a live QuicBaaS SecretsService. It records every write so
// the tests can assert idempotence.
type fakeSecretStore struct {
	mu     sync.Mutex
	data   map[string][]byte
	meta   map[string]map[string]string
	writes map[string]int
	getErr error
	putErr error
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{
		data:   make(map[string][]byte),
		meta:   make(map[string]map[string]string),
		writes: make(map[string]int),
	}
}

func (f *fakeSecretStore) GetSecret(_ context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	data, ok := f.data[req.SecretID]
	if !ok {
		return nil, errors.New("secrets: secret not found")
	}
	return &baasservice.GetSecretResponse{SecretID: req.SecretID, Data: data}, nil
}

func (f *fakeSecretStore) StoreSecret(_ context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.data[req.Name] = req.Data
	f.meta[req.Name] = req.Metadata
	f.writes[req.Name]++
	return &baasservice.StoreSecretResponse{SecretID: req.Name}, nil
}

func (f *fakeSecretStore) get(name string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.data[name]
	return data, ok
}

func (f *fakeSecretStore) writeCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes[name]
}

// secureBootTestApp returns an App with a fully populated kms:// Secure Boot
// config matching the shipped device templates.
func secureBootTestApp() *App {
	return &App{
		Logger: logging.DefaultLogger(),
		SecureBootConfig: &installer.SecureBootConfig{
			Enabled: true,
			PK: installer.SecureBootKeyRef{
				KeyConfig: common.KeyConfig{CN: "Trusted Platform Secure Boot PK", StoreType: "tpm2"},
				KeyURI:    "kms://platform/secureboot/pk",
				CertURI:   "kms://platform/secureboot/pk-cert",
			},
			KEK: installer.SecureBootKeyRef{
				KeyConfig: common.KeyConfig{CN: "Trusted Platform Secure Boot KEK", StoreType: "tpm2"},
				KeyURI:    "kms://platform/secureboot/kek",
				CertURI:   "kms://platform/secureboot/kek-cert",
			},
			DB: installer.SecureBootKeyRef{
				KeyConfig: common.KeyConfig{CN: "Trusted Platform Secure Boot DB", StoreType: "software"},
				KeyURI:    "kms://platform/secureboot/db",
				CertURI:   "kms://platform/secureboot/db-cert",
			},
		},
	}
}

// secureBootAllPaths lists the six secret paths the provisioner must create.
var secureBootAllPaths = []string{
	"platform/secureboot/pk", "platform/secureboot/pk-cert",
	"platform/secureboot/kek", "platform/secureboot/kek-cert",
	"platform/secureboot/db", "platform/secureboot/db-cert",
}

// TestProvisionSecureBootKeys_NoOp verifies the provisioner does nothing when
// Secure Boot is absent, disabled, or references no KMS-managed material.
func TestProvisionSecureBootKeys_NoOp(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_config", func(t *testing.T) {
		app := &App{Logger: logging.DefaultLogger()}
		require.NoError(t, app.ProvisionSecureBootKeys(ctx))
	})

	t.Run("disabled", func(t *testing.T) {
		app := secureBootTestApp()
		app.SecureBootConfig.Enabled = false

		// A disabled config must not even reach the secret store: the store
		// resolver would otherwise fail closed on a node without QuicBaaS.
		require.NoError(t, app.ProvisionSecureBootKeys(ctx))
	})

	t.Run("no_kms_uris", func(t *testing.T) {
		app := secureBootTestApp()
		for _, ref := range []*installer.SecureBootKeyRef{
			&app.SecureBootConfig.PK, &app.SecureBootConfig.KEK, &app.SecureBootConfig.DB,
		} {
			ref.KeyURI = "file:///etc/trusted-platform/secure-boot/db.key"
			ref.CertURI = "file:///etc/trusted-platform/secure-boot/db.crt"
		}
		require.NoError(t, app.ProvisionSecureBootKeys(ctx))
	})

	t.Run("kms_uris_without_secrets_service", func(t *testing.T) {
		app := secureBootTestApp()
		err := app.ProvisionSecureBootKeys(ctx)
		require.Error(t, err)

		var unavailable *ErrSecureBootSecretsUnavailable
		assert.True(t, errors.As(err, &unavailable), "expected ErrSecureBootSecretsUnavailable, got %v", err)
	})
}

// TestProvisionSecureBootKeys_GeneratesAll verifies all six entries are created
// with usable PEM key material and matching self-signed certificates.
func TestProvisionSecureBootKeys_GeneratesAll(t *testing.T) {
	ctx := context.Background()
	app := secureBootTestApp()
	store := newFakeSecretStore()

	require.NoError(t, app.provisionSecureBootKeys(ctx, store))

	for _, path := range secureBootAllPaths {
		data, ok := store.get(path)
		require.True(t, ok, "missing secret at %s", path)
		require.NotEmpty(t, data, "empty secret at %s", path)
	}

	cases := []struct {
		keyPath  string
		certPath string
		cn       string
		codeSign bool
	}{
		{"platform/secureboot/pk", "platform/secureboot/pk-cert", "Trusted Platform Secure Boot PK", false},
		{"platform/secureboot/kek", "platform/secureboot/kek-cert", "Trusted Platform Secure Boot KEK", false},
		{"platform/secureboot/db", "platform/secureboot/db-cert", "Trusted Platform Secure Boot DB", true},
	}
	for _, tc := range cases {
		t.Run(tc.cn, func(t *testing.T) {
			keyPEM, _ := store.get(tc.keyPath)
			block, _ := pem.Decode(keyPEM)
			require.NotNil(t, block, "private key is not PEM")
			assert.Equal(t, "PRIVATE KEY", block.Type)

			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			rsaKey, ok := key.(*rsa.PrivateKey)
			require.True(t, ok, "expected RSA key by default, got %T", key)
			assert.Equal(t, secureBootDefaultRSABits, rsaKey.N.BitLen())

			certPEM, _ := store.get(tc.certPath)
			certBlock, _ := pem.Decode(certPEM)
			require.NotNil(t, certBlock, "certificate is not PEM")
			assert.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)
			assert.Equal(t, tc.cn, cert.Subject.CommonName)
			assert.Equal(t, tc.cn, cert.Issuer.CommonName, "certificate must be self-signed")
			assert.True(t, cert.IsCA)
			assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
			assert.NotZero(t, cert.KeyUsage&x509.KeyUsageDigitalSignature)
			assert.Equal(t, secureBootDefaultValidYears, cert.NotAfter.Year()-cert.NotBefore.Year())

			// The stored certificate must actually verify against the stored key.
			require.NoError(t, cert.CheckSignatureFrom(cert))
			assert.True(t, rsaKey.PublicKey.Equal(cert.PublicKey))

			if tc.codeSign {
				assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
			} else {
				assert.Empty(t, cert.ExtKeyUsage)
			}
		})
	}
}

// TestProvisionSecureBootKeys_Idempotent verifies a second boot leaves existing
// Secure Boot material byte-for-byte untouched.
func TestProvisionSecureBootKeys_Idempotent(t *testing.T) {
	ctx := context.Background()
	app := secureBootTestApp()
	store := newFakeSecretStore()

	require.NoError(t, app.provisionSecureBootKeys(ctx, store))

	first := make(map[string][]byte, len(secureBootAllPaths))
	for _, path := range secureBootAllPaths {
		data, ok := store.get(path)
		require.True(t, ok)
		first[path] = append([]byte(nil), data...)
		require.Equal(t, 1, store.writeCount(path))
	}

	require.NoError(t, app.provisionSecureBootKeys(ctx, store))

	for _, path := range secureBootAllPaths {
		data, ok := store.get(path)
		require.True(t, ok)
		assert.Equal(t, first[path], data, "material at %s was rewritten", path)
		assert.Equal(t, 1, store.writeCount(path), "second run wrote %s again", path)
	}
}

// TestProvisionSecureBootKeys_Errors verifies the failure paths: a malformed
// config, an indeterminate KMS probe, and a store that rejects writes.
func TestProvisionSecureBootKeys_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("kms_key_uri_with_non_kms_cert_uri", func(t *testing.T) {
		app := secureBootTestApp()
		app.SecureBootConfig.PK.CertURI = "file:///etc/trusted-platform/secure-boot/pk.crt"

		err := app.provisionSecureBootKeys(ctx, newFakeSecretStore())
		require.Error(t, err)

		var provisionErr *ErrSecureBootProvision
		require.True(t, errors.As(err, &provisionErr))
		assert.Equal(t, secureBootRolePK, provisionErr.Role)
	})

	t.Run("indeterminate_kms_probe_fails_closed", func(t *testing.T) {
		app := secureBootTestApp()
		store := newFakeSecretStore()
		store.getErr = errors.New("kms unavailable: connection refused")

		err := app.provisionSecureBootKeys(ctx, store)
		require.Error(t, err)

		var existenceErr *ErrSecureBootExistenceCheck
		require.True(t, errors.As(err, &existenceErr), "expected fail-closed existence error, got %v", err)
		assert.Equal(t, "platform/secureboot/pk", existenceErr.Path)
		assert.Empty(t, store.data, "no material may be written when the probe is indeterminate")
	})

	t.Run("store_write_failure", func(t *testing.T) {
		app := secureBootTestApp()
		store := newFakeSecretStore()
		store.putErr = errors.New("kms write rejected")

		err := app.provisionSecureBootKeys(ctx, store)
		require.Error(t, err)

		var provisionErr *ErrSecureBootProvision
		require.True(t, errors.As(err, &provisionErr))
		assert.ErrorIs(t, err, store.putErr)
	})

	t.Run("unsupported_algorithm", func(t *testing.T) {
		app := secureBootTestApp()
		app.SecureBootConfig.DB.KeyAlgorithm = "Ed448"

		err := app.provisionSecureBootKeys(ctx, newFakeSecretStore())
		require.Error(t, err)

		var provisionErr *ErrSecureBootProvision
		require.True(t, errors.As(err, &provisionErr))
		assert.Equal(t, secureBootRoleDB, provisionErr.Role)
	})

	t.Run("rsa_key_too_small", func(t *testing.T) {
		app := secureBootTestApp()
		app.SecureBootConfig.DB.RSAConfig = &common.RSAConfig{KeySize: 1024}

		err := app.provisionSecureBootKeys(ctx, newFakeSecretStore())
		require.Error(t, err)

		var provisionErr *ErrSecureBootProvision
		require.True(t, errors.As(err, &provisionErr))
		assert.Equal(t, "generate key", provisionErr.Stage)
	})

	t.Run("unsupported_ecc_curve", func(t *testing.T) {
		app := secureBootTestApp()
		app.SecureBootConfig.DB.KeyAlgorithm = "ECDSA"
		app.SecureBootConfig.DB.ECCConfig = &common.ECCConfig{Curve: "brainpoolP256r1"}

		err := app.provisionSecureBootKeys(ctx, newFakeSecretStore())
		require.Error(t, err)

		var provisionErr *ErrSecureBootProvision
		require.True(t, errors.As(err, &provisionErr))
	})
}

// TestProvisionSecureBootKeys_ECDSA verifies the ECDSA path honors the
// configured curve.
func TestProvisionSecureBootKeys_ECDSA(t *testing.T) {
	ctx := context.Background()
	app := secureBootTestApp()
	app.SecureBootConfig.DB.KeyAlgorithm = "ecdsa"
	app.SecureBootConfig.DB.ECCConfig = &common.ECCConfig{Curve: "P-384"}
	store := newFakeSecretStore()

	require.NoError(t, app.provisionSecureBootKeys(ctx, store))

	keyPEM, ok := store.get("platform/secureboot/db")
	require.True(t, ok)
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA key, got %T", key)
	assert.Equal(t, "P-384", ecKey.Curve.Params().Name)
	assert.Equal(t, "ECDSA-P384", store.meta["platform/secureboot/db"]["algorithm"])
}

// TestProvisionSecureBootKeys_DefaultCN verifies a config that omits cn still
// produces a certificate with a meaningful Subject.
func TestProvisionSecureBootKeys_DefaultCN(t *testing.T) {
	ctx := context.Background()
	app := secureBootTestApp()
	app.SecureBootConfig.PK.CN = ""
	store := newFakeSecretStore()

	require.NoError(t, app.provisionSecureBootKeys(ctx, store))

	certPEM, ok := store.get("platform/secureboot/pk-cert")
	require.True(t, ok)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, secureBootDefaultCN[secureBootRolePK], cert.Subject.CommonName)
}

// TestSecureBootKMSPath verifies kms:// URI to secret-ID derivation, including
// the query-string and scheme cases the LocalKMS resolver applies.
func TestSecureBootKMSPath(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
		ok   bool
	}{
		{"plain", "kms://platform/secureboot/pk", "platform/secureboot/pk", true},
		{"query_stripped", "kms://platform/secureboot/db?ensure=true&len=32", "platform/secureboot/db", true},
		{"fragment_stripped", "kms://platform/secureboot/db#v2", "platform/secureboot/db", true},
		{"uppercase_scheme", "KMS://platform/secureboot/kek", "platform/secureboot/kek", true},
		{"trailing_slash", "kms://platform/secureboot/kek/", "platform/secureboot/kek", true},
		{"file_scheme", "file:///etc/secure-boot/db.key", "", false},
		{"empty", "", "", false},
		{"scheme_only", "kms://", "", false},
		{"query_only_path", "kms://?ensure=true", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := secureBootKMSPath(tc.uri)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIsSecureBootSecretNotFound verifies the not-found classifier that gates
// regeneration: only a positive not-found may lead to overwriting.
func TestIsSecureBootSecretNotFound(t *testing.T) {
	assert.False(t, isSecureBootSecretNotFound(nil))
	assert.True(t, isSecureBootSecretNotFound(errors.New("secrets: secret not found")))
	assert.True(t, isSecureBootSecretNotFound(errors.New("NOT FOUND")))
	assert.False(t, isSecureBootSecretNotFound(errors.New("connection refused")))
	assert.False(t, isSecureBootSecretNotFound(errors.New("permission denied")))
}
