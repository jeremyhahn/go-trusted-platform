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

package common

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// mustPassword builds a password for a test, failing the test if the enclave
// backing it cannot be allocated.
func mustPassword(t *testing.T, secret string) xkmssdk.Password {
	t.Helper()
	password, err := xkmssdk.NewPasswordFromString(secret)
	if err != nil {
		t.Fatalf("NewPasswordFromString(%q): %v", secret, err)
	}
	return password
}

func TestKeyConfigToKeyAttributes_RSA(t *testing.T) {
	kc := &KeyConfig{
		CN:                 "test-key",
		Debug:              true,
		Hash:               "SHA256",
		KeyAlgorithm:       "RSA",
		Password:           "test-password",
		PlatformPolicy:     true,
		SignatureAlgorithm: "SHA256-RSA-PSS",
		StoreType:          "tpm2",
		RSAConfig: &RSAConfig{
			KeySize: 2048,
		},
		Exportable: false,
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.CN != "test-key" {
		t.Errorf("Expected CN=test-key, got %s", attrs.CN)
	}

	if attrs.Hash != crypto.SHA256 {
		t.Errorf("Expected Hash=SHA256, got %s", attrs.Hash)
	}

	if attrs.KeyAlgorithm != x509.RSA {
		t.Errorf("Expected KeyAlgorithm=RSA, got %s", attrs.KeyAlgorithm)
	}

	if attrs.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		t.Errorf("Expected SignatureAlgorithm=SHA256WithRSAPSS, got %s", attrs.SignatureAlgorithm)
	}

	if attrs.StoreType != xkmssdk.StoreTPM2 {
		t.Errorf("Expected StoreType=tpm2, got %s", attrs.StoreType)
	}

	if attrs.RSAAttributes == nil {
		t.Fatal("Expected RSAAttributes to be set")
	}

	if attrs.RSAAttributes.KeySize != 2048 {
		t.Errorf("Expected RSA KeySize=2048, got %d", attrs.RSAAttributes.KeySize)
	}

	if attrs.Password == nil {
		t.Fatal("Expected Password to be set")
	}

	pw, err := attrs.Password.String()
	if err != nil {
		t.Fatalf("Failed to get password string: %v", err)
	}
	if pw != "test-password" {
		t.Errorf("Expected password=test-password, got %s", pw)
	}
}

func TestKeyConfigToKeyAttributes_ECDSA(t *testing.T) {
	kc := &KeyConfig{
		CN:                 "test-ecc-key",
		Hash:               "SHA256",
		KeyAlgorithm:       "ECDSA",
		SignatureAlgorithm: "ECDSA-SHA256",
		StoreType:          "software",
		ECCConfig: &ECCConfig{
			Curve: "P-256",
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.KeyAlgorithm != x509.ECDSA {
		t.Errorf("Expected KeyAlgorithm=ECDSA, got %s", attrs.KeyAlgorithm)
	}

	if attrs.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("Expected SignatureAlgorithm=ECDSAWithSHA256, got %s", attrs.SignatureAlgorithm)
	}

	if attrs.ECCAttributes == nil {
		t.Fatal("Expected ECCAttributes to be set")
	}

	if attrs.ECCAttributes.Curve != elliptic.P256() {
		t.Errorf("Expected curve=P-256, got %s", attrs.ECCAttributes.Curve.Params().Name)
	}
}

func TestNewKeyConfigFromAttributes(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:                 "test-key",
		Debug:              true,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.RSA,
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          xkmssdk.StoreTPM2,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
		Password:   mustPassword(t, "test-password"),
		Exportable: false,
	}

	kc := NewKeyConfigFromAttributes(attrs)

	if kc.CN != "test-key" {
		t.Errorf("Expected CN=test-key, got %s", kc.CN)
	}

	if kc.Hash != "SHA-256" {
		t.Errorf("Expected Hash=SHA-256, got %s", kc.Hash)
	}

	if kc.KeyAlgorithm != "RSA" {
		t.Errorf("Expected KeyAlgorithm=RSA, got %s", kc.KeyAlgorithm)
	}

	if kc.SignatureAlgorithm != "SHA256-RSAPSS" {
		t.Errorf("Expected SignatureAlgorithm=SHA256-RSAPSS, got %s", kc.SignatureAlgorithm)
	}

	if kc.StoreType != "tpm2" {
		t.Errorf("Expected StoreType=tpm2, got %s", kc.StoreType)
	}

	if kc.RSAConfig == nil {
		t.Fatal("Expected RSAConfig to be set")
	}

	if kc.RSAConfig.KeySize != 2048 {
		t.Errorf("Expected RSA KeySize=2048, got %d", kc.RSAConfig.KeySize)
	}

	if kc.Password != "test-password" {
		t.Errorf("Expected password=test-password, got %s", kc.Password)
	}
}

func TestKeyConfigToKeyAttributes_InvalidHash(t *testing.T) {
	kc := &KeyConfig{
		Hash: "INVALID-HASH",
	}

	_, err := kc.ToKeyAttributes()
	if err == nil {
		t.Fatal("Expected error for invalid hash, got nil")
	}
}

func TestKeyConfigToKeyAttributes_InvalidKeyAlgorithm(t *testing.T) {
	kc := &KeyConfig{
		KeyAlgorithm: "INVALID-ALGORITHM",
	}

	_, err := kc.ToKeyAttributes()
	if err == nil {
		t.Fatal("Expected error for invalid key algorithm, got nil")
	}
}

func TestKeyConfigToKeyAttributes_InvalidStoreType(t *testing.T) {
	kc := &KeyConfig{
		StoreType: "INVALID-STORE",
	}

	_, err := kc.ToKeyAttributes()
	if err == nil {
		t.Fatal("Expected error for invalid store type, got nil")
	}
}

func TestKeyConfigToKeyAttributes_InvalidCurve(t *testing.T) {
	kc := &KeyConfig{
		ECCConfig: &ECCConfig{
			Curve: "INVALID-CURVE",
		},
	}

	_, err := kc.ToKeyAttributes()
	if err == nil {
		t.Fatal("Expected error for invalid curve, got nil")
	}
}

func TestKeyConfigToKeyAttributes_AES(t *testing.T) {
	kc := &KeyConfig{
		CN:        "test-aes-key",
		StoreType: "software",
		AESConfig: &AESConfig{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.SymmetricAlgorithm == "" {
		t.Fatal("Expected SymmetricAlgorithm to be set")
	}

	if attrs.SymmetricAlgorithm != xkmssdk.SymmetricAES256GCM {
		t.Errorf("Expected SymmetricAlgorithm=aes256-gcm, got %s", attrs.SymmetricAlgorithm)
	}

	if attrs.SymmetricAlgorithm.KeySize() != 256 {
		t.Errorf("Expected AES KeySize=256, got %d", attrs.SymmetricAlgorithm.KeySize())
	}

	if attrs.SymmetricAlgorithm.NonceSize() != 12 {
		t.Errorf("Expected AES NonceSize=12, got %d", attrs.SymmetricAlgorithm.NonceSize())
	}
}

func TestDefaultPassword(t *testing.T) {
	if DEFAULT_PASSWORD != xkmssdk.DEFAULT_PASSWORD {
		t.Errorf("Expected DEFAULT_PASSWORD to match xkmssdk.DEFAULT_PASSWORD")
	}
}

func TestKeyConfigToKeyAttributes_PasswordCache(t *testing.T) {
	kc := &KeyConfig{
		CN:             "test-key",
		PlatformPolicy: true,
		StoreType:      "tpm2",
		PasswordCache: &PasswordCacheConfig{
			Enabled: true,
			TTL:     600, // 10 minutes
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.PasswordCache == nil {
		t.Fatal("Expected PasswordCache to be set")
	}

	if !attrs.PasswordCache.Enabled {
		t.Error("Expected PasswordCache.Enabled=true")
	}

	if attrs.PasswordCache.TTL != 600 {
		t.Errorf("Expected PasswordCache.TTL=600, got %d", attrs.PasswordCache.TTL)
	}
}

func TestKeyConfigToKeyAttributes_PasswordCacheDisabled(t *testing.T) {
	kc := &KeyConfig{
		CN:             "test-key",
		PlatformPolicy: true,
		StoreType:      "tpm2",
		PasswordCache: &PasswordCacheConfig{
			Enabled: false,
			TTL:     300,
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.PasswordCache == nil {
		t.Fatal("Expected PasswordCache to be set")
	}

	if attrs.PasswordCache.Enabled {
		t.Error("Expected PasswordCache.Enabled=false")
	}
}

func TestKeyConfigToKeyAttributes_PasswordCacheNil(t *testing.T) {
	kc := &KeyConfig{
		CN:            "test-key",
		StoreType:     "tpm2",
		PasswordCache: nil,
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.PasswordCache != nil {
		t.Error("Expected PasswordCache to be nil")
	}
}

func TestNewKeyConfigFromAttributes_PasswordCache(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: true,
		StoreType:      xkmssdk.StoreTPM2,
		PasswordCache: &xkmssdk.PasswordCacheConfig{
			Enabled: true,
			TTL:     900,
		},
	}

	kc := NewKeyConfigFromAttributes(attrs)

	if kc.PasswordCache == nil {
		t.Fatal("Expected PasswordCache to be set")
	}

	if !kc.PasswordCache.Enabled {
		t.Error("Expected PasswordCache.Enabled=true")
	}

	if kc.PasswordCache.TTL != 900 {
		t.Errorf("Expected PasswordCache.TTL=900, got %d", kc.PasswordCache.TTL)
	}
}

func TestNewKeyConfigFromAttributes_PasswordCacheNil(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:            "test-key",
		StoreType:     xkmssdk.StoreTPM2,
		PasswordCache: nil,
	}

	kc := NewKeyConfigFromAttributes(attrs)

	if kc.PasswordCache != nil {
		t.Error("Expected PasswordCache to be nil")
	}
}

func TestKeyConfigToKeyAttributes_InvalidSignatureAlgorithm(t *testing.T) {
	kc := &KeyConfig{
		CN:                 "test-key",
		SignatureAlgorithm: "INVALID-SIG-ALGORITHM",
	}

	_, err := kc.ToKeyAttributes()
	if err == nil {
		t.Fatal("Expected error for invalid signature algorithm, got nil")
	}
}

func TestKeyConfigToKeyAttributes_AES128(t *testing.T) {
	kc := &KeyConfig{
		CN:        "test-aes128-key",
		StoreType: "software",
		AESConfig: &AESConfig{
			KeySize:   128,
			NonceSize: 12,
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.SymmetricAlgorithm == "" {
		t.Fatal("Expected SymmetricAlgorithm to be set")
	}

	if attrs.SymmetricAlgorithm != xkmssdk.SymmetricAES128GCM {
		t.Errorf("Expected SymmetricAlgorithm=aes128-gcm, got %s", attrs.SymmetricAlgorithm)
	}

	if attrs.SymmetricAlgorithm.KeySize() != 128 {
		t.Errorf("Expected AES KeySize=128, got %d", attrs.SymmetricAlgorithm.KeySize())
	}
}

func TestKeyConfigToKeyAttributes_AES192(t *testing.T) {
	kc := &KeyConfig{
		CN:        "test-aes192-key",
		StoreType: "software",
		AESConfig: &AESConfig{
			KeySize:   192,
			NonceSize: 12,
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.SymmetricAlgorithm == "" {
		t.Fatal("Expected SymmetricAlgorithm to be set")
	}

	if attrs.SymmetricAlgorithm != xkmssdk.SymmetricAES192GCM {
		t.Errorf("Expected SymmetricAlgorithm=aes192-gcm, got %s", attrs.SymmetricAlgorithm)
	}

	if attrs.SymmetricAlgorithm.KeySize() != 192 {
		t.Errorf("Expected AES KeySize=192, got %d", attrs.SymmetricAlgorithm.KeySize())
	}
}

func TestKeyConfigToKeyAttributes_AESDefaultSize(t *testing.T) {
	kc := &KeyConfig{
		CN:        "test-aes-default-key",
		StoreType: "software",
		AESConfig: &AESConfig{
			KeySize:   64, // Invalid size, should default to AES-256
			NonceSize: 12,
		},
	}

	attrs, err := kc.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes failed: %v", err)
	}

	if attrs.SymmetricAlgorithm == "" {
		t.Fatal("Expected SymmetricAlgorithm to be set")
	}

	// Invalid key sizes should default to AES-256-GCM
	if attrs.SymmetricAlgorithm != xkmssdk.SymmetricAES256GCM {
		t.Errorf("Expected SymmetricAlgorithm=aes256-gcm for invalid size, got %s", attrs.SymmetricAlgorithm)
	}
}

func TestNewKeyConfigFromAttributes_ECCAttributes(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:                 "test-ecc-key",
		Debug:              false,
		Hash:               crypto.SHA384,
		KeyAlgorithm:       x509.ECDSA,
		PlatformPolicy:     false,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		StoreType:          xkmssdk.StoreSoftware,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P384(),
		},
		Exportable: true,
	}

	kc := NewKeyConfigFromAttributes(attrs)

	if kc.CN != "test-ecc-key" {
		t.Errorf("Expected CN=test-ecc-key, got %s", kc.CN)
	}

	if kc.KeyAlgorithm != "ECDSA" {
		t.Errorf("Expected KeyAlgorithm=ECDSA, got %s", kc.KeyAlgorithm)
	}

	if kc.ECCConfig == nil {
		t.Fatal("Expected ECCConfig to be set")
	}

	if kc.ECCConfig.Curve != "P-384" {
		t.Errorf("Expected curve=P-384, got %s", kc.ECCConfig.Curve)
	}

	if !kc.Exportable {
		t.Error("Expected Exportable=true")
	}
}

func TestNewKeyConfigFromAttributes_SymmetricAlgorithm(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:                 "test-symmetric-key",
		StoreType:          xkmssdk.StoreSoftware,
		SymmetricAlgorithm: xkmssdk.SymmetricAES256GCM,
	}

	kc := NewKeyConfigFromAttributes(attrs)

	if kc.CN != "test-symmetric-key" {
		t.Errorf("Expected CN=test-symmetric-key, got %s", kc.CN)
	}

	if kc.AESConfig == nil {
		t.Fatal("Expected AESConfig to be set")
	}

	if kc.AESConfig.KeySize != 256 {
		t.Errorf("Expected AES KeySize=256, got %d", kc.AESConfig.KeySize)
	}

	if kc.AESConfig.NonceSize != 12 {
		t.Errorf("Expected AES NonceSize=12, got %d", kc.AESConfig.NonceSize)
	}
}

func TestNewKeyConfigFromAttributes_UnknownSignatureAlgorithm(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		CN:                 "test-key",
		StoreType:          xkmssdk.StoreSoftware,
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
	}

	kc := NewKeyConfigFromAttributes(attrs)

	// SignatureAlgorithm should not be set for UnknownSignatureAlgorithm
	if kc.SignatureAlgorithm != "" {
		t.Errorf("Expected SignatureAlgorithm to be empty for unknown, got %s", kc.SignatureAlgorithm)
	}
}
