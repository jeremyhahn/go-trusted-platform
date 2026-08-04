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

package secureboot

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateModuleSigningKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module-signing-key.pem")

	msk, err := GenerateModuleSigningKey(context.Background(), &ModuleSigningKeyConfig{
		Path:         path,
		KeyBits:      2048,
		Organization: "Automate The Things",
		Country:      "US",
	})
	if err != nil {
		t.Fatalf("GenerateModuleSigningKey: %v", err)
	}
	if msk.Path != path {
		t.Errorf("Path = %q, want %q", msk.Path, path)
	}

	// File exists with owner-only permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("bundle permissions = %o, want 0600", perm)
	}

	// Bundle layout: PRIVATE KEY block first, CERTIFICATE block second —
	// the exact layout the kernel build expects for CONFIG_MODULE_SIG_KEY.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	keyBlock, rest := pem.Decode(data)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("first PEM block = %v, want PRIVATE KEY", keyBlock)
	}
	certBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("second PEM block = %v, want CERTIFICATE", certBlock)
	}

	// Certificate carries the kernel-required extensions.
	cert := msk.Certificate
	if cert.IsCA {
		t.Error("certificate must not be a CA")
	}
	if !cert.BasicConstraintsValid {
		t.Error("certificate must carry basicConstraints")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want digitalSignature only", cert.KeyUsage)
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Error("SubjectKeyId must be set")
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Error("AuthorityKeyId must be set")
	}
	if cert.Subject.CommonName != DefaultModuleKeyCN {
		t.Errorf("CN = %q, want default %q", cert.Subject.CommonName, DefaultModuleKeyCN)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("certificate is not self-signed: %v", err)
	}

	rsaKey, ok := msk.Signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Signer type = %T, want *rsa.PrivateKey", msk.Signer)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("key size = %d, want 2048", rsaKey.N.BitLen())
	}
}

func TestGenerateModuleSigningKeyRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module-signing-key.pem")

	cfg := &ModuleSigningKeyConfig{Path: path, KeyBits: 2048}
	if _, err := GenerateModuleSigningKey(context.Background(), cfg); err != nil {
		t.Fatalf("first generation: %v", err)
	}

	_, err := GenerateModuleSigningKey(context.Background(), cfg)
	var exists ErrModuleKeyExists
	if !errors.As(err, &exists) {
		t.Fatalf("second generation error = %v, want ErrModuleKeyExists", err)
	}
	if exists.Path != path {
		t.Errorf("ErrModuleKeyExists.Path = %q, want %q", exists.Path, path)
	}

	// Force overwrites.
	cfg.Force = true
	if _, err := GenerateModuleSigningKey(context.Background(), cfg); err != nil {
		t.Fatalf("forced regeneration: %v", err)
	}
}

func TestGenerateModuleSigningKeyInvalidConfig(t *testing.T) {
	ctx := context.Background()

	if _, err := GenerateModuleSigningKey(ctx, nil); !errors.Is(err, ErrConfigNil) {
		t.Errorf("nil config error = %v, want ErrConfigNil", err)
	}

	if _, err := GenerateModuleSigningKey(ctx, &ModuleSigningKeyConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty path error = %v, want ErrInvalidConfig", err)
	}

	weak := &ModuleSigningKeyConfig{Path: filepath.Join(t.TempDir(), "k.pem"), KeyBits: 1024}
	if _, err := GenerateModuleSigningKey(ctx, weak); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("weak key error = %v, want ErrInvalidConfig", err)
	}
}

func TestGenerateModuleSigningKeyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := GenerateModuleSigningKey(ctx, &ModuleSigningKeyConfig{
		Path:    filepath.Join(t.TempDir(), "k.pem"),
		KeyBits: 2048,
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestLoadModuleSigningKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module-signing-key.pem")

	generated, err := GenerateModuleSigningKey(context.Background(), &ModuleSigningKeyConfig{Path: path, KeyBits: 2048})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	loaded, err := LoadModuleSigningKey(path)
	if err != nil {
		t.Fatalf("LoadModuleSigningKey: %v", err)
	}
	if !loaded.Certificate.Equal(generated.Certificate) {
		t.Error("loaded certificate does not match generated certificate")
	}
	loadedKey, ok := loaded.Signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("loaded signer type = %T, want *rsa.PrivateKey", loaded.Signer)
	}
	genKey := generated.Signer.(*rsa.PrivateKey)
	if loadedKey.N.Cmp(genKey.N) != 0 {
		t.Error("loaded key does not match generated key")
	}
}

func TestLoadModuleSigningKeyErrors(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	_, err := LoadModuleSigningKey(filepath.Join(dir, "missing.pem"))
	var notFound ErrModuleKeyNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("missing file error = %v, want ErrModuleKeyNotFound", err)
	}

	// File without a private key.
	certOnly := filepath.Join(dir, "cert-only.pem")
	generated, err := GenerateModuleSigningKey(context.Background(), &ModuleSigningKeyConfig{
		Path:    filepath.Join(dir, "full.pem"),
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generated.Certificate.Raw})
	if err := os.WriteFile(certOnly, certPEM, 0600); err != nil {
		t.Fatalf("write cert-only: %v", err)
	}
	_, err = LoadModuleSigningKey(certOnly)
	var malformed ErrModuleKeyMalformed
	if !errors.As(err, &malformed) {
		t.Errorf("cert-only error = %v, want ErrModuleKeyMalformed", err)
	}

	// Garbage content.
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not pem at all"), 0600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := LoadModuleSigningKey(garbage); !errors.As(err, &malformed) {
		t.Errorf("garbage error = %v, want ErrModuleKeyMalformed", err)
	}
}
