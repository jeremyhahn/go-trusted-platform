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

package vtpm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// TestSetupSecureBoot_LeavesDaemonKMSUsable is the regression test for #949.
// platformd registers its KMS backends, the ones its CA signs EK
// certificates with, in the process-wide go-xkms service. A Secure Boot
// bundle build used to reset and close that registry, so every later
// CreateBundle failed with "keystore: not initialized". Two Secure Boot
// builds in a row, both failing at enrollment after the keys are generated,
// must leave the daemon's signing key usable.
func TestSetupSecureBoot_LeavesDaemonKMSUsable(t *testing.T) {
	ctx := context.Background()
	resetProcessKMS(t)
	t.Cleanup(func() { resetProcessKMS(t) })

	daemonKey := initDaemonKMS(t, ctx)

	svc, err := NewService(createTestConfig(t), nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// Enrollment fails after key generation: no OVMF VARS template.
	svc.config.OVMFVars = filepath.Join(t.TempDir(), "missing-OVMF_VARS.fd")

	for i := 0; i < 2; i++ {
		bundleDir := t.TempDir()
		_, _, err := svc.setupSecureBoot(ctx,
			filepath.Join(bundleDir, "secureboot"),
			filepath.Join(bundleDir, "nvram", "OVMF_VARS.fd"),
			fmt.Sprintf("bundle-%d", i))

		var enrollErr ErrSecureBootEnrollmentFailed
		if !errors.As(err, &enrollErr) {
			t.Fatalf("build %d: want ErrSecureBootEnrollmentFailed, got %v", i, err)
		}
		assertDaemonKeySigns(t, ctx, daemonKey)
	}
}

// TestSetupSecureBoot_KeyGenFailureLeavesDaemonKMSUsable covers the build
// that fails before any key exists: the keys directory cannot be created.
func TestSetupSecureBoot_KeyGenFailureLeavesDaemonKMSUsable(t *testing.T) {
	ctx := context.Background()
	resetProcessKMS(t)
	t.Cleanup(func() { resetProcessKMS(t) })

	daemonKey := initDaemonKMS(t, ctx)

	svc, err := NewService(createTestConfig(t), nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	_, _, err = svc.setupSecureBoot(ctx, filepath.Join(blocker, "secureboot"),
		filepath.Join(t.TempDir(), "OVMF_VARS.fd"), "bundle-keygen")

	var genErr ErrSecureBootKeyGenFailed
	if !errors.As(err, &genErr) {
		t.Fatalf("want ErrSecureBootKeyGenFailed, got %v", err)
	}
	assertDaemonKeySigns(t, ctx, daemonKey)
}

// initDaemonKMS registers a software backend in the process-wide go-xkms
// service, as platformd does at start-up, and generates the CA signing key.
func initDaemonKMS(t *testing.T, ctx context.Context) *xkmssdk.KeyAttributes {
	t.Helper()
	dir := t.TempDir()
	keyStorage, err := xkmssdk.NewFileStorageBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("key storage: %v", err)
	}
	certStorage, err := xkmssdk.NewFileStorageBackend(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatalf("cert storage: %v", err)
	}
	software, err := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{KeyStorage: keyStorage})
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	backend, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{Backend: software, CertStorage: certStorage})
	if err != nil {
		t.Fatalf("service backend: %v", err)
	}
	if err := xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends:       map[string]xkmssdk.ServiceBackend{string(xkmssdk.StoreSoftware): backend},
		DefaultBackend: string(xkmssdk.StoreSoftware),
	}); err != nil {
		t.Fatalf("ServiceInitialize: %v", err)
	}

	attrs := &xkmssdk.KeyAttributes{
		CN:            "platform-ca",
		KeyAlgorithm:  x509.RSA,
		KeyType:       xkmssdk.KeyTypeSigning,
		StoreType:     xkmssdk.StoreSoftware,
		RSAAttributes: &xkmssdk.RSAAttributes{KeySize: 2048},
	}
	if _, err := xkmssdk.ServiceGenerateKey(ctx, attrs); err != nil {
		t.Fatalf("generate daemon key: %v", err)
	}
	return attrs
}

// assertDaemonKeySigns signs a digest with the daemon's key through the
// process-wide service, the path the CA takes to sign an EK certificate.
func assertDaemonKeySigns(t *testing.T, ctx context.Context, attrs *xkmssdk.KeyAttributes) {
	t.Helper()
	if !xkmssdk.ServiceIsInitialized() {
		t.Fatal("process-wide KMS service was reset")
	}
	key, err := xkmssdk.ServiceKey(ctx, attrs)
	if err != nil {
		t.Fatalf("daemon key: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("daemon key %T is not a crypto.Signer", key)
	}
	digest := sha256.Sum256([]byte("ek certificate tbs"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("daemon key sign: %v", err)
	}
}

// resetProcessKMS clears the process-wide go-xkms service registry.
func resetProcessKMS(t *testing.T) {
	t.Helper()
	if xkmssdk.ServiceIsInitialized() {
		if err := xkmssdk.ServiceClose(); err != nil {
			t.Fatalf("ServiceClose: %v", err)
		}
		xkmssdk.ServiceReset()
	}
}
