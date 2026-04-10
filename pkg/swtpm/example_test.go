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

package swtpm_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

func Example() {
	// Create configuration
	config := &swtpm.Config{
		StateDir:   "/tmp/example-tpm",
		SocketPath: "/tmp/example-tpm/swtpm.sock",
		PCRBanks:   []string{"sha256"},
		LogLevel:   20,
		Debug:      false,
	}

	// Create logger
	logger := logging.DefaultLogger()

	// Create SWTPM instance
	tpm, err := swtpm.NewSWTPM(config, logger)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize TPM state
	ctx := context.Background()
	if err := tpm.Initialize(ctx); err != nil {
		log.Fatal(err)
	}

	// Start the daemon
	if err := tpm.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := tpm.Stop(); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	// Wait for socket to be ready
	if err := tpm.WaitForSocket(5 * time.Second); err != nil {
		log.Fatal(err)
	}

	// Check status
	if tpm.IsRunning() {
		fmt.Printf("TPM is running with PID: %d\n", tpm.PID())
		fmt.Printf("Socket path: %s\n", tpm.SocketPath())
	}
}

func ExampleNewSWTPM() {
	config := &swtpm.Config{
		StateDir: "/tmp/my-tpm",
		PCRBanks: []string{"sha256"},
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	tpm, err := swtpm.NewSWTPM(config, logger)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created SWTPM instance for state directory: %s\n", tpm.StateDir())
}

func ExampleSWTPM_Initialize() {
	config := &swtpm.Config{
		StateDir: "/tmp/my-tpm",
		PCRBanks: []string{"sha256", "sha384"},
	}

	logger := logging.DefaultLogger()
	tpm, _ := swtpm.NewSWTPM(config, logger)

	ctx := context.Background()
	if err := tpm.Initialize(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("TPM state initialized successfully")
}

func ExampleSWTPM_Start() {
	config := &swtpm.Config{
		StateDir: "/tmp/my-tpm",
	}

	logger := logging.DefaultLogger()
	tpm, _ := swtpm.NewSWTPM(config, logger)

	ctx := context.Background()
	if err := tpm.Initialize(ctx); err != nil {
		log.Fatal(err)
	}

	if err := tpm.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := tpm.Stop(); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	fmt.Printf("TPM daemon started with PID: %d\n", tpm.PID())
}

func ExampleStopExisting() {
	// Stop any existing swtpm processes for a state directory
	if err := swtpm.StopExisting("/tmp/my-tpm"); err != nil {
		log.Printf("Warning: failed to stop existing processes: %v", err)
	}

	fmt.Println("Stopped existing swtpm processes")
}
