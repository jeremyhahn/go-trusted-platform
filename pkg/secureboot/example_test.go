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

package secureboot_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// Example_basicUsage demonstrates basic key generation with XKMSManager
func Example_basicUsage() {
	// Create temporary directory for this example
	tmpDir, _ := os.MkdirTemp("", "secureboot-example-*")
	defer os.RemoveAll(tmpDir)

	// Configure key generation with XKMSManager
	config := &secureboot.XKMSConfig{
		KeysDir:      tmpDir,
		Backend:      secureboot.BackendSoftware,
		CommonName:   "Example Secure Boot",
		Country:      "US",
		Organization: "Example Organization",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true,
	}

	// Create a logger that doesn't output to stdout/stderr for examples
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	// Create XKMS manager
	km, err := secureboot.NewXKMSManager(config, logger)
	if err != nil {
		fmt.Printf("Failed to create XKMS manager: %v\n", err)
		return
	}

	// Generate all keys
	ctx := context.Background()
	if err := km.GenerateAll(ctx); err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		return
	}

	// Get key paths
	paths := km.GetKeyPaths()

	// Verify certificates exist
	if _, err := os.Stat(paths.PKCert); err == nil {
		fmt.Println("Platform Key generated successfully")
	}
	if _, err := os.Stat(paths.KEKCert); err == nil {
		fmt.Println("Key Exchange Key generated successfully")
	}
	if _, err := os.Stat(paths.DBCert); err == nil {
		fmt.Println("Database Key generated successfully")
	}

	// Output:
	// Platform Key generated successfully
	// Key Exchange Key generated successfully
	// Database Key generated successfully
}

// Example_individualKeys demonstrates generating keys individually
func Example_individualKeys() {
	// Create temporary directory
	tmpDir, _ := os.MkdirTemp("", "secureboot-example-*")
	defer os.RemoveAll(tmpDir)

	config := &secureboot.XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    secureboot.BackendSoftware,
		CommonName: "Individual Keys Example",
		KeySize:    2048,
		ValidYears: 10,
		ExportKeys: true,
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)

	km, err := secureboot.NewXKMSManager(config, logger)
	if err != nil {
		fmt.Printf("Failed to create XKMS manager: %v\n", err)
		return
	}
	ctx := context.Background()

	// Generate Platform Key only
	if err := km.GeneratePlatformKey(ctx); err != nil {
		fmt.Printf("Failed to generate Platform Key: %v\n", err)
		return
	}

	paths := km.GetKeyPaths()
	if _, err := os.Stat(paths.PKCert); err == nil {
		fmt.Println("Platform Key exists")
	}
	if _, err := os.Stat(paths.KEKCert); os.IsNotExist(err) {
		fmt.Println("KEK does not exist yet")
	}

	// Output:
	// Platform Key exists
	// KEK does not exist yet
}

// Example_checkExistingKeys demonstrates checking for existing keys
func Example_checkExistingKeys() {
	// Create temporary directory
	tmpDir, _ := os.MkdirTemp("", "secureboot-example-*")
	defer os.RemoveAll(tmpDir)

	config := &secureboot.XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    secureboot.BackendSoftware,
		ExportKeys: true,
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)

	km, err := secureboot.NewXKMSManager(config, logger)
	if err != nil {
		fmt.Printf("Failed to create XKMS manager: %v\n", err)
		return
	}

	// Check before generation
	if !km.KeysExist() {
		fmt.Println("Keys do not exist")
	}

	// Generate keys
	ctx := context.Background()
	if err := km.GenerateAll(ctx); err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		return
	}

	// Check after generation
	if km.KeysExist() {
		fmt.Println("Keys exist after generation")
	}

	// Output:
	// Keys do not exist
	// Keys exist after generation
}

// Example_keyPaths demonstrates retrieving key file paths
func Example_keyPaths() {
	tmpDir, _ := os.MkdirTemp("", "secureboot-example-*")
	defer os.RemoveAll(tmpDir)

	config := &secureboot.XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    secureboot.BackendSoftware,
		ExportKeys: true,
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)

	km, err := secureboot.NewXKMSManager(config, logger)
	if err != nil {
		fmt.Printf("Failed to create XKMS manager: %v\n", err)
		return
	}

	paths := km.GetKeyPaths()

	// Show expected file names
	fmt.Println("PK cert file:", filepath.Base(paths.PKCert))
	fmt.Println("KEK cert file:", filepath.Base(paths.KEKCert))
	fmt.Println("DB cert file:", filepath.Base(paths.DBCert))

	// Output:
	// PK cert file: PK.crt
	// KEK cert file: KEK.crt
	// DB cert file: DB.crt
}

// Example_idempotentGeneration demonstrates that GenerateAll is idempotent
func Example_idempotentGeneration() {
	tmpDir, _ := os.MkdirTemp("", "secureboot-example-*")
	defer os.RemoveAll(tmpDir)

	config := &secureboot.XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    secureboot.BackendSoftware,
		ExportKeys: true,
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)

	km, err := secureboot.NewXKMSManager(config, logger)
	if err != nil {
		fmt.Printf("Failed to create XKMS manager: %v\n", err)
		return
	}
	ctx := context.Background()

	// First generation
	if err := km.GenerateAll(ctx); err != nil {
		fmt.Printf("First generation failed: %v\n", err)
		return
	}
	fmt.Println("First generation completed")

	// Second generation (should skip)
	if err := km.GenerateAll(ctx); err != nil {
		fmt.Printf("Second generation failed: %v\n", err)
		return
	}
	fmt.Println("Second generation completed (skipped)")

	// Output:
	// First generation completed
	// Second generation completed (skipped)
}
