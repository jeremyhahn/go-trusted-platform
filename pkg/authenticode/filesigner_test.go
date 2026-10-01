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

package authenticode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileSigner_SignsAndVerifies(t *testing.T) {
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())

	signer, err := NewFileSigner(context.Background(), keyPath, certPath, nil)
	require.NoError(t, err)

	var signed bytes.Buffer
	require.NoError(t, signer.Sign(bytes.NewReader(authenticodetest.MinimalPE(authenticodetest.MachineARM64)), &signed))
	assert.Greater(t, signed.Len(), len(authenticodetest.MinimalPE(authenticodetest.MachineARM64)), "a signature was embedded")
	assert.NoError(t, signer.Verify(bytes.NewReader(signed.Bytes())))
}

func TestNewFileSigner_PKCS1Key(t *testing.T) {
	dir := t.TempDir()
	pkcs8Path, certPath := authenticodetest.WriteKeyPair(t, dir)
	loaded, err := LoadPrivateKeyPEM(pkcs8Path)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "rsa.key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(loaded.(*rsa.PrivateKey))}), 0o600))

	_, err = NewFileSigner(context.Background(), keyPath, certPath, nil)

	assert.NoError(t, err, "PKCS#1 keys are accepted alongside PKCS#8")
}

func TestLoadPrivateKeyPEM_Errors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadPrivateKeyPEM(filepath.Join(dir, "absent.key"))
		var kerr *KeyFileError
		require.ErrorAs(t, err, &kerr)
		assert.Equal(t, KeyFileRead, kerr.Stage)
	})

	t.Run("not PEM", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.key")
		require.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))
		_, err := LoadPrivateKeyPEM(path)
		var kerr *KeyFileError
		require.ErrorAs(t, err, &kerr)
		assert.Equal(t, KeyFileDecode, kerr.Stage)
	})

	t.Run("PEM that is not a key", func(t *testing.T) {
		path := filepath.Join(dir, "cert-as-key.key")
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600))
		_, err := LoadPrivateKeyPEM(path)
		var kerr *KeyFileError
		require.ErrorAs(t, err, &kerr)
		assert.Equal(t, KeyFileParse, kerr.Stage)
	})
}

func TestLoadCertificate(t *testing.T) {
	dir := t.TempDir()
	_, certPath := authenticodetest.WriteKeyPair(t, dir)
	pemCert, err := LoadCertificate(certPath)
	require.NoError(t, err)

	t.Run("raw DER is accepted", func(t *testing.T) {
		der := filepath.Join(dir, "db.der")
		require.NoError(t, os.WriteFile(der, pemCert.Raw, 0o644))
		cert, err := LoadCertificate(der)
		require.NoError(t, err)
		assert.True(t, cert.Equal(pemCert))
	})

	t.Run("failures", func(t *testing.T) {
		_, err := LoadCertificate(filepath.Join(dir, "absent.crt"))
		var cerr *CertFileError
		require.ErrorAs(t, err, &cerr)
		assert.Equal(t, KeyFileRead, cerr.Stage)

		path := filepath.Join(dir, "garbage.crt")
		require.NoError(t, os.WriteFile(path, []byte("nope"), 0o644))
		_, err = LoadCertificate(path)
		require.ErrorAs(t, err, &cerr)
		assert.Equal(t, KeyFileParse, cerr.Stage, "neither PEM nor DER")

		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{9, 9}}), 0o644))
		_, err = LoadCertificate(path)
		require.ErrorAs(t, err, &cerr)
		assert.Equal(t, KeyFileParse, cerr.Stage)

		keyPath, _ := authenticodetest.WriteKeyPair(t, t.TempDir())
		_, err = NewFileSigner(context.Background(), keyPath, path, nil)
		assert.ErrorAs(t, err, &cerr, "NewFileSigner surfaces the certificate error")
	})
}

// TestLoadSigningPair_ECDSAAndFailures covers the build gate's inputs (the ISO
// build stages exactly what the installer's file:// path then loads): an
// ECDSA pair loads; a garbage key, a garbage certificate and a missing key are
// each refused.
func TestLoadSigningPair_ECDSAAndFailures(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "db"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath, certPath := filepath.Join(dir, "db.key"), filepath.Join(dir, "db.crt")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644))
	garbage := filepath.Join(dir, "garbage")
	require.NoError(t, os.WriteFile(garbage, []byte("not pem"), 0o600))

	_, _, err = LoadSigningPair(keyPath, certPath)
	require.NoError(t, err, "a matched ECDSA pair loads")
	for name, pair := range map[string][2]string{
		"garbage key":         {garbage, certPath},
		"garbage certificate": {keyPath, garbage},
		"missing key":         {filepath.Join(dir, "missing"), certPath},
	} {
		_, _, err := LoadSigningPair(pair[0], pair[1])
		assert.Error(t, err, name)
	}
}

func TestLoadSigningPair_RefusesAMismatchedPair(t *testing.T) {
	keyA, _ := authenticodetest.WriteKeyPair(t, t.TempDir())
	_, certB := authenticodetest.WriteKeyPair(t, t.TempDir())

	_, _, err := LoadSigningPair(keyA, certB)
	var mismatch *KeyCertMismatchError
	require.ErrorAs(t, err, &mismatch)

	_, err = NewFileSigner(context.Background(), keyA, certB, nil)
	require.ErrorAs(t, err, &mismatch)
}

// opaqueSigner exposes nothing but crypto.Signer, as a KMS-backed key does.
type opaqueSigner struct{ inner crypto.Signer }

func (o opaqueSigner) Public() crypto.PublicKey { return o.inner.Public() }
func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.inner.Sign(r, digest, opts)
}

func TestNewCryptoSigner(t *testing.T) {
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	key, cert, err := LoadSigningPair(keyPath, certPath)
	require.NoError(t, err)

	t.Run("signs through any crypto.Signer", func(t *testing.T) {
		signer, err := NewCryptoSigner(context.Background(), opaqueSigner{key}, cert, nil)
		require.NoError(t, err)
		pe := authenticodetest.MinimalPE(authenticodetest.MachineARM64)
		var signed bytes.Buffer
		require.NoError(t, signer.Sign(bytes.NewReader(pe), &signed))
		assert.NoError(t, signer.Verify(bytes.NewReader(signed.Bytes())))
	})

	t.Run("refusals", func(t *testing.T) {
		_, err := NewCryptoSigner(context.Background(), nil, cert, nil)
		require.Error(t, err)
		_, err = NewCryptoSigner(context.Background(), key, nil, nil)
		require.Error(t, err)

		_, otherCert := authenticodetest.WriteKeyPair(t, t.TempDir())
		other, err := LoadCertificate(otherCert)
		require.NoError(t, err)
		_, err = NewCryptoSigner(context.Background(), key, other, nil)
		var mismatch *KeyCertMismatchError
		require.ErrorAs(t, err, &mismatch)
	})
}

// TestNewVerifier: verification needs no key — a verifier checks a signed PE,
// names its signer, rejects an unsigned one, and refuses to sign.
func TestNewVerifier(t *testing.T) {
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	signer, err := NewFileSigner(context.Background(), keyPath, certPath, nil)
	require.NoError(t, err)
	pe := authenticodetest.MinimalPE(authenticodetest.MachineARM64)
	var signed bytes.Buffer
	require.NoError(t, signer.Sign(bytes.NewReader(pe), &signed))
	cert, err := LoadCertificate(certPath)
	require.NoError(t, err)

	verifier := NewVerifier(context.Background(), nil)
	require.NoError(t, verifier.Verify(bytes.NewReader(signed.Bytes())))
	embedded, err := verifier.ExtractCertificate(bytes.NewReader(signed.Bytes()))
	require.NoError(t, err)
	assert.True(t, embedded.Equal(cert), "the embedded signer is the signing certificate")

	assert.Error(t, verifier.Verify(bytes.NewReader(pe)), "an unsigned PE does not verify")
	assert.ErrorIs(t, verifier.Sign(bytes.NewReader(pe), &bytes.Buffer{}), ErrNoSigningKey)
	assert.Nil(t, verifier.(*Signer).Public())
}
