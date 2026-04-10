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
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

const (
	TESTDATA_DIR = "./testdata"
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	os.RemoveAll(TESTDATA_DIR)
}

func setup() {
	os.RemoveAll(TESTDATA_DIR)
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
	testDir := fmt.Sprintf("%s/%s", TESTDATA_DIR, hexVal)

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
