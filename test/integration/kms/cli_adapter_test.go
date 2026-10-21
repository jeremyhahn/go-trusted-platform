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

//go:build integration

package kms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// failingPlatformCTL returns an adapter whose platformctl exits 1 without
// output, so every call fails with the command line the adapter built.
func failingPlatformCTL(t *testing.T) *CLIAdapter {
	t.Helper()
	path := filepath.Join(t.TempDir(), "platformctl")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	return NewCLIAdapterWithConfig(path, "", 10*time.Second)
}

// commandLine returns the command line of a failed CLI call.
func commandLine(t *testing.T, err error) string {
	t.Helper()
	var failed ErrCLICommandFailed
	require.True(t, errors.As(err, &failed), "want ErrCLICommandFailed, got %v", err)
	return failed.Command
}

func TestCLIAdapter_SendsTheDocumentedAESSpelling(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.KeyGenerate(ctx, KeyGenerateOptions{KeyID: "k", Algorithm: "AES-256-GCM"})
	assert.Contains(t, commandLine(t, err), "kms key generate k --algorithm aes-256")

	_, err = adapter.DEKCreate(ctx, DEKCreateOptions{Path: "p", Algorithm: "AES-256-GCM"})
	assert.Contains(t, commandLine(t, err), "kms dek create p --algorithm aes-256")
}

func TestCLIKeyAlgorithm_EverySpellingParsesInTheCLI(t *testing.T) {
	for suiteName := range cliKeyAlgorithms {
		_, err := kmssvc.ParseKeyAlgorithm(suiteName)
		require.Error(t, err, "%s parses as is; the mapping is not needed", suiteName)

		_, err = kmssvc.ParseKeyAlgorithm(cliKeyAlgorithm(suiteName))
		assert.NoError(t, err, "%s -> %s", suiteName, cliKeyAlgorithm(suiteName))
	}
}

func TestCLIKeyAlgorithm_PassesOtherNamesThrough(t *testing.T) {
	assert.Equal(t, "ECDSA-P256", cliKeyAlgorithm("ECDSA-P256"))
	assert.Equal(t, "not-an-algorithm", cliKeyAlgorithm("not-an-algorithm"),
		"an unknown name reaches the CLI unchanged, so the CLI's own error reports it")
}
