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

package jwt

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
)

// testDataDir is the root for the key material these tests generate. It is
// created under the OS temp directory, NOT in the source tree (#273).
//
// These tests generate real RSA private keys through a file-backed keystore,
// so they need a real directory. Putting it at "./testdata" violated the
// repo's unit-test rule ("NEVER modify the host system", "ALWAYS run in
// memory") and, because testdata/ is not gitignored, left untracked key
// material in the working tree whenever the run did not reach teardown --
// measured at 288 KB when the run was killed at 15s and 956 KB at 25s. Since
// `go test ./...` followed by `git add -A` is an entirely ordinary sequence,
// that is key material one keystroke from being staged.
//
// Cleanup is still best-effort, and deliberately so: teardown removes this on
// a normal exit, and what an interrupted run leaves behind now lands in the
// OS temp directory, where it is the OS's problem rather than the repo's.
var testDataDir string

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	if testDataDir != "" {
		os.RemoveAll(testDataDir)
	}
}

func setup() {
	dir, err := os.MkdirTemp("", "gtp-jwt-testdata-")
	if err != nil {
		slog.Error("failed to create test data directory", "error", err)
		os.Exit(1)
	}
	testDataDir = dir
}

func testKeyConfig() *xkmssdk.KeyConfig {
	return &xkmssdk.KeyConfig{
		CN:                 "test",
		Hash:               "SHA256", // Use format that ParseHash expects (without hyphen)
		KeyAlgorithm:       xkmssdk.KeyAlgorithmString(x509.RSA.String()),
		SignatureAlgorithm: xkmssdk.SignatureAlgorithmName(x509.SHA256WithRSA.String()),
		StoreType:          xkmssdk.StoreSoftware,
	}
}

func testServiceParams() ServiceParams {
	params, _ := testServiceParamsWithXKMS()
	return params
}

func testServiceParamsWithXKMS() (ServiceParams, *platform.XKMS) {
	keyAttrs, err := xkmssdk.KeyAttributesFromConfig(testKeyConfig())
	if err != nil {
		panic(err)
	}
	ks := createXKMS()
	return ServiceParams{
		Audience:   "localhost",
		Issuer:     "localhost",
		Expiration: 3600,
		KeyAttrs:   keyAttrs,
		XKMS:       ks,
	}, ks
}

func createXKMS() *platform.XKMS {
	logger := slog.Default()

	// Create a temp directory for testing
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		slog.Error("failed to generate random bytes", "error", err)
		os.Exit(1)
	}
	hexVal := hex.EncodeToString(buf)
	testDir := filepath.Join(testDataDir, hexVal)

	if err := os.MkdirAll(testDir, fs.ModePerm); err != nil {
		slog.Error("failed to create test directory", "error", err)
		os.Exit(1)
	}

	// Create file storage backend for go-xkms
	storageBackend, err := xkmssdk.NewFileStorageBackend(testDir)
	if err != nil {
		slog.Error("failed to create file storage backend", "error", err)
		os.Exit(1)
	}

	// Create a key store backend
	keyBackend := xkmssdk.NewFileBackend(logger, storageBackend)

	// Create XKMS config using software backend for JWT tests
	// TPM testing requires integration tests with actual TPM/simulator
	xkmsConfig := &platform.XKMSConfig{
		CN: "test",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{
			KeyStorage: storageBackend,
		},
	}

	// Create a new XKMS with only PKCS #8 backend
	// Pass nil for TPM and platformKS since we're only testing PKCS8
	ks, err := platform.NewXKMS(
		logger,
		xkmsConfig,
		keyBackend,
		storageBackend,
		storageBackend, // certStorage
		nil,            // No TPM for unit tests
		nil)            // No platform key store for unit tests
	if err != nil {
		slog.Error("failed to create xkms", "error", err)
		os.Exit(1)
	}

	return ks
}
