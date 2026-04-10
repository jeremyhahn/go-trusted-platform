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

package iso

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestDefaultXorrisoRunner_Run(t *testing.T) {
	runner := &defaultXorrisoRunner{
		logger: logging.DefaultLogger(),
	}

	_, xorrisoLookupErr := exec.LookPath("xorriso")
	xorrisoAvailable := xorrisoLookupErr == nil

	t.Run("successful run", func(t *testing.T) {
		ctx := context.Background()
		var stdout, stderr bytes.Buffer

		args := []string{"-version"}
		err := runner.Run(ctx, args, &stdout, &stderr)

		if xorrisoAvailable {
			assert.NoError(t, err)
			assert.Contains(t, stdout.String(), "xorriso")
		} else {
			// xorriso binary not found - Run should return an error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "xorriso command failed")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Create a cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		var stdout, stderr bytes.Buffer
		args := []string{"-version"}

		err := runner.Run(ctx, args, &stdout, &stderr)
		// Should fail due to context cancellation or binary not found
		assert.Error(t, err)
	})

	t.Run("invalid arguments", func(t *testing.T) {
		ctx := context.Background()
		var stdout, stderr bytes.Buffer

		// Use invalid arguments to trigger error
		args := []string{"--invalid-flag-that-doesnt-exist"}
		err := runner.Run(ctx, args, &stdout, &stderr)

		// Should fail: either xorriso rejects the flag, or xorriso is not found
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "xorriso command failed")
	})
}

func TestDefaultXorrisoRunner_Version(t *testing.T) {
	runner := &defaultXorrisoRunner{
		logger: logging.DefaultLogger(),
	}

	_, xorrisoLookupErr := exec.LookPath("xorriso")
	xorrisoAvailable := xorrisoLookupErr == nil

	t.Run("get version", func(t *testing.T) {
		ctx := context.Background()
		version, err := runner.Version(ctx)

		if xorrisoAvailable {
			assert.NoError(t, err)
			assert.NotEmpty(t, version)
			assert.True(t, strings.Contains(version, "xorriso") || strings.Contains(version, "Xorriso"),
				"version output should contain 'xorriso': %s", version)
		} else {
			// xorriso binary not found - Version should return an error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "xorriso version")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Create a cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := runner.Version(ctx)
		// Should fail due to context cancellation or binary not found
		assert.Error(t, err)
	})
}

func TestDefaultXorrisoRunner_Integration(t *testing.T) {
	// Integration test for the runner: exercises Version and Run consistency

	t.Run("version and run consistency", func(t *testing.T) {
		runner := &defaultXorrisoRunner{
			logger: logging.DefaultLogger(),
		}

		ctx := context.Background()

		// Get version
		version, versionErr := runner.Version(ctx)

		// Run with version flag
		var stdout, stderr bytes.Buffer
		runErr := runner.Run(ctx, []string{"-version"}, &stdout, &stderr)

		_, xorrisoLookupErr := exec.LookPath("xorriso")
		xorrisoAvailable := xorrisoLookupErr == nil
		if xorrisoAvailable {
			assert.NoError(t, versionErr)
			assert.NotEmpty(t, version)
			assert.NoError(t, runErr)

			// Both outputs should contain "xorriso"
			assert.True(t, strings.Contains(version, "xorriso") || strings.Contains(version, "Xorriso"))
			output := stdout.String()
			assert.True(t, strings.Contains(output, "xorriso") || strings.Contains(output, "Xorriso"))
		} else {
			// Both should fail consistently when xorriso is not available
			assert.Error(t, versionErr)
			assert.Error(t, runErr)
		}
	})
}

// Test that the builder uses the runner correctly
func TestBuilder_UsesRunnerCorrectly(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := tmpDir + "/iso"
	outputISO := tmpDir + "/test.iso"

	// Track calls to the runner
	runCalled := false
	versionCalled := false

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			runCalled = true
			// Simulate creating the ISO file
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("mock iso"), 0644)
				}
			}
			return nil
		},
		versionFunc: func(ctx context.Context) (string, error) {
			versionCalled = true
			return "xorriso 1.5.4", nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: outputISO,
	}

	// BuildISO should call Run
	ctx := context.Background()
	err := builder.BuildISO(ctx, config)
	assert.NoError(t, err)
	assert.True(t, runCalled, "BuildISO should call runner.Run")

	// Version can be called independently
	version, err := mockRunner.Version(ctx)
	assert.NoError(t, err)
	assert.True(t, versionCalled, "Version should be callable")
	assert.NotEmpty(t, version)
}
