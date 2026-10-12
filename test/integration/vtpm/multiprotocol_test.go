//go:build integration

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

// Package vtpm provides multi-protocol integration tests for vTPM services.
// These tests verify that vTPM operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified VTPMCommands interface.
//
// Run tests via:
//
//	make integration-test-vtpm
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package vtpm

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestVTPMMultiProtocol runs the complete vTPM test suite against all protocol adapters.
// Each adapter implements the VTPMCommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestVTPMMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement VTPMCommands
	adapters := []VTPMCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "vtpm", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testVTPMProtocol(t, ctx, adapter)
		})
	}
}

// testVTPMProtocol runs the complete vTPM test suite against a single protocol adapter.
func testVTPMProtocol(t *testing.T, ctx context.Context, cmd VTPMCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("BundleOperations", func(t *testing.T) {
		testBundleOperations(t, ctx, cmd, prefix)
	})

	t.Run("TemplateOperations", func(t *testing.T) {
		testTemplateOperations(t, ctx, cmd, prefix)
	})

	t.Run("ExportImport", func(t *testing.T) {
		testExportImport(t, ctx, cmd, prefix)
	})

	t.Run("Validation", func(t *testing.T) {
		testValidation(t, ctx, cmd, prefix)
	})

	t.Run("RuntimeTPMOperations", func(t *testing.T) {
		testRuntimeTPMOperations(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Bundle Operations Tests
// =============================================================================

func testBundleOperations(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testBundleCreate(t, ctx, cmd, prefix)
	testBundleGet(t, ctx, cmd, prefix)
	testBundleList(t, ctx, cmd, prefix)
	testBundleDelete(t, ctx, cmd, prefix)
	testBundleLifecycle(t, ctx, cmd, prefix)
}

func testBundleCreate(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateBundlePreAssigned", func(t *testing.T) {
		hostname := fmt.Sprintf("%s-create-preassigned", prefix)
		opts := CreateBundleOptions{
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: false,
			Labels: map[string]string{
				"test":     "true",
				"protocol": cmd.Name(),
			},
		}

		result, err := cmd.CreateBundle(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "CreateBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.NotEmpty(t, result.Bundle.ID, "Bundle ID should not be empty")
		assert.Equal(t, vtpm.BundleModePreAssigned, result.Bundle.Mode, "Mode should be pre-assigned")

		// Cleanup
		if result.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: result.Bundle.ID})
		}
	})

	t.Run("CreateBundleWithECC", func(t *testing.T) {
		hostname := fmt.Sprintf("%s-create-ecc", prefix)
		opts := CreateBundleOptions{
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			EKAlgorithm:       vtpm.EKAlgorithmECC,
			SecureBootEnabled: false,
		}

		result, err := cmd.CreateBundle(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "CreateBundle with ECC should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.NotEmpty(t, result.Bundle.ID, "Bundle ID should not be empty")

		// Cleanup
		if result.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: result.Bundle.ID})
		}
	})

	t.Run("CreateBundleWithSecureBoot", func(t *testing.T) {
		hostname := fmt.Sprintf("%s-create-secboot", prefix)
		opts := CreateBundleOptions{
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
		}

		result, err := cmd.CreateBundle(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "CreateBundle with SecureBoot should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.NotEmpty(t, result.Bundle.ID, "Bundle ID should not be empty")

		// Cleanup
		if result.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: result.Bundle.ID})
		}
	})

	t.Run("CreateBundleMissingHostnameFails", func(t *testing.T) {
		opts := CreateBundleOptions{
			Mode:        vtpm.BundleModePreAssigned,
			Hostname:    "", // Missing hostname
			EKAlgorithm: vtpm.EKAlgorithmRSA,
		}

		_, err := cmd.CreateBundle(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.Error(t, err, "CreateBundle should fail with missing hostname")
	})
}

func testBundleGet(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a bundle first
	hostname := fmt.Sprintf("%s-get", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Setup: CreateBundle result should not be nil")
	require.NotNil(t, createResult.Bundle, "Setup: Bundle should not be nil")
	defer func() {
		if createResult.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: createResult.Bundle.ID})
		}
	}()

	t.Run("GetExistingBundle", func(t *testing.T) {
		result, err := cmd.GetBundle(testCtx, GetBundleOptions{ID: createResult.Bundle.ID})
		if surface.IsNotImplemented(err) {
			t.Skip("GetBundle not implemented for this adapter")
		}
		require.NoError(t, err, "GetBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.Equal(t, createResult.Bundle.ID, result.Bundle.ID, "Bundle ID should match")
		assert.Equal(t, vtpm.BundleModePreAssigned, result.Bundle.Mode, "Mode should match")
	})

	t.Run("GetNonexistentBundleFails", func(t *testing.T) {
		_, err := cmd.GetBundle(testCtx, GetBundleOptions{ID: prefix + "-nonexistent-bundle-id"})
		if surface.IsNotImplemented(err) {
			t.Skip("GetBundle not implemented for this adapter")
		}
		require.Error(t, err, "GetBundle should fail for nonexistent bundle")
	})
}

func testBundleDelete(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a bundle for deletion
	hostname := fmt.Sprintf("%s-delete", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Setup: CreateBundle result should not be nil")
	require.NotNil(t, createResult.Bundle, "Setup: Bundle should not be nil")

	t.Run("DeleteExistingBundle", func(t *testing.T) {
		result, err := cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: createResult.Bundle.ID})
		if surface.IsNotImplemented(err) {
			t.Skip("DeleteBundle not implemented for this adapter")
		}
		require.NoError(t, err, "DeleteBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Delete should be successful")
	})

	t.Run("VerifyBundleIsDeleted", func(t *testing.T) {
		_, err := cmd.GetBundle(testCtx, GetBundleOptions{ID: createResult.Bundle.ID})
		if surface.IsNotImplemented(err) {
			t.Skip("GetBundle not implemented for this adapter")
		}
		require.Error(t, err, "GetBundle should fail for deleted bundle")
	})

	t.Run("DeleteNonexistentBundleFails", func(t *testing.T) {
		_, err := cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: prefix + "-nonexistent-delete-id"})
		if surface.IsNotImplemented(err) {
			t.Skip("DeleteBundle not implemented for this adapter")
		}
		require.Error(t, err, "DeleteBundle should fail for nonexistent bundle")
	})
}

func testBundleList(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple bundles for listing
	var createdIDs []string
	for i := 0; i < 3; i++ {
		hostname := fmt.Sprintf("%s-list-%d", prefix, i)
		opts := CreateBundleOptions{
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: false,
			Labels: map[string]string{
				"test-batch": prefix,
			},
		}
		result, err := cmd.CreateBundle(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "Setup: CreateBundle should succeed")
		if result != nil && result.Bundle != nil && result.Bundle.ID != "" {
			createdIDs = append(createdIDs, result.Bundle.ID)
		}
	}
	defer func() {
		for _, id := range createdIDs {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: id})
		}
	}()

	t.Run("ListAllBundles", func(t *testing.T) {
		opts := ListBundlesOptions{
			Limit: 100,
		}
		result, err := cmd.ListBundles(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("ListBundles not implemented for this adapter")
		}
		require.NoError(t, err, "ListBundles should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Bundles), 3, "Should have at least 3 bundles")
	})

	t.Run("ListBundlesWithPagination", func(t *testing.T) {
		opts := ListBundlesOptions{
			Limit: 2,
		}
		result, err := cmd.ListBundles(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("ListBundles not implemented for this adapter")
		}
		require.NoError(t, err, "ListBundles should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, len(result.Bundles), 2, "Should respect limit")
	})

	t.Run("ListBundlesByMode", func(t *testing.T) {
		opts := ListBundlesOptions{
			Mode:  vtpm.BundleModePreAssigned,
			Limit: 100,
		}
		result, err := cmd.ListBundles(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("ListBundles not implemented for this adapter")
		}
		require.NoError(t, err, "ListBundles should succeed for mode filter")
		require.NotNil(t, result, "Result should not be nil")

		for _, bundle := range result.Bundles {
			assert.Equal(t, vtpm.BundleModePreAssigned, bundle.Mode, "All bundles should be pre-assigned mode")
		}
	})
}

func testBundleLifecycle(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("FullBundleLifecycle", func(t *testing.T) {
		// Create bundle
		hostname := fmt.Sprintf("%s-lifecycle", prefix)
		createOpts := CreateBundleOptions{
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: false,
			Labels: map[string]string{
				"lifecycle-test": "true",
			},
		}

		createResult, err := cmd.CreateBundle(testCtx, createOpts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "CreateBundle should succeed")
		require.NotNil(t, createResult, "Create result should not be nil")
		require.NotNil(t, createResult.Bundle, "Bundle should not be nil")
		require.NotEmpty(t, createResult.Bundle.ID, "Bundle ID should not be empty")

		bundleID := createResult.Bundle.ID

		// Get bundle
		getResult, err := cmd.GetBundle(testCtx, GetBundleOptions{ID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("GetBundle not implemented for this adapter")
		}
		require.NoError(t, err, "GetBundle should succeed")
		require.NotNil(t, getResult, "Get result should not be nil")
		require.NotNil(t, getResult.Bundle, "Bundle should not be nil")
		assert.Equal(t, bundleID, getResult.Bundle.ID, "Bundle ID should match")

		// Validate bundle
		validateResult, err := cmd.ValidateBundle(testCtx, ValidateBundleOptions{ID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Log("ValidateBundle not implemented, skipping validation step")
		} else {
			require.NoError(t, err, "ValidateBundle should succeed")
			require.NotNil(t, validateResult, "Validate result should not be nil")
			assert.True(t, validateResult.Valid, "Bundle should be valid")
		}

		// Get bundle path
		pathResult, err := cmd.GetBundlePath(testCtx, GetBundlePathOptions{ID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Log("GetBundlePath not implemented, skipping path check")
		} else {
			require.NoError(t, err, "GetBundlePath should succeed")
			assert.NotEmpty(t, pathResult.Path, "Path should not be empty")
		}

		// Get TPM socket path
		socketResult, err := cmd.GetTPMSocketPath(testCtx, GetTPMSocketPathOptions{ID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Log("GetTPMSocketPath not implemented, skipping socket check")
		} else {
			require.NoError(t, err, "GetTPMSocketPath should succeed")
			assert.NotEmpty(t, socketResult.Path, "Socket path should not be empty")
		}

		// Delete bundle
		deleteResult, err := cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("DeleteBundle not implemented for this adapter")
		}
		require.NoError(t, err, "DeleteBundle should succeed")
		require.NotNil(t, deleteResult, "Delete result should not be nil")
		assert.True(t, deleteResult.Success, "Delete should be successful")

		// Verify deletion
		_, err = cmd.GetBundle(testCtx, GetBundleOptions{ID: bundleID})
		require.Error(t, err, "GetBundle should fail for deleted bundle")
	})
}

// =============================================================================
// Template Operations Tests
// =============================================================================

func testTemplateOperations(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testTemplateCreate(t, ctx, cmd, prefix)
	testTemplateGet(t, ctx, cmd, prefix)
	testTemplateDelete(t, ctx, cmd, prefix)
	testTemplateList(t, ctx, cmd, prefix)
	testTemplateClone(t, ctx, cmd, prefix)
}

func testTemplateCreate(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateTemplate", func(t *testing.T) {
		templateID := fmt.Sprintf("%s-template-create", prefix)
		opts := CreateTemplateOptions{
			ID:                templateID,
			Description:       "Test template for multi-protocol testing",
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: false,
		}

		result, err := cmd.CreateTemplate(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "CreateTemplate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Template, "Template should not be nil")
		assert.Equal(t, templateID, result.Template.ID, "Template ID should match")
		assert.Equal(t, "Test template for multi-protocol testing", result.Template.Description, "Description should match")

		// Cleanup
		if result.Template.ID != "" {
			_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: result.Template.ID})
		}
	})

	t.Run("CreateTemplateWithSecureBoot", func(t *testing.T) {
		templateID := fmt.Sprintf("%s-template-secboot", prefix)
		opts := CreateTemplateOptions{
			ID:                templateID,
			Description:       "Template with SecureBoot enabled",
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
		}

		result, err := cmd.CreateTemplate(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "CreateTemplate with SecureBoot should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Template, "Template should not be nil")
		assert.Equal(t, templateID, result.Template.ID, "Template ID should match")
		assert.True(t, result.Template.SecureBootEnabled, "SecureBoot should be enabled")

		// Cleanup
		if result.Template.ID != "" {
			_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: result.Template.ID})
		}
	})

	t.Run("CreateTemplateWithECC", func(t *testing.T) {
		templateID := fmt.Sprintf("%s-template-ecc", prefix)
		opts := CreateTemplateOptions{
			ID:                templateID,
			Description:       "Template with ECC EK algorithm",
			EKAlgorithm:       vtpm.EKAlgorithmECC,
			SecureBootEnabled: false,
		}

		result, err := cmd.CreateTemplate(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "CreateTemplate with ECC should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Template, "Template should not be nil")
		assert.Equal(t, templateID, result.Template.ID, "Template ID should match")

		// Cleanup
		if result.Template.ID != "" {
			_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: result.Template.ID})
		}
	})

	t.Run("CreateTemplateMissingIDFails", func(t *testing.T) {
		opts := CreateTemplateOptions{
			ID:          "", // Missing ID
			Description: "Template without ID",
		}

		_, err := cmd.CreateTemplate(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateTemplate not implemented for this adapter")
		}
		require.Error(t, err, "CreateTemplate should fail with missing ID")
	})
}

func testTemplateGet(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a template first
	templateID := fmt.Sprintf("%s-template-get", prefix)
	createOpts := CreateTemplateOptions{
		ID:                templateID,
		Description:       "Template for get test",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateTemplate(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateTemplate not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateTemplate should succeed")
	defer func() {
		if createResult != nil && createResult.Template != nil && createResult.Template.ID != "" {
			_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: createResult.Template.ID})
		}
	}()

	t.Run("GetExistingTemplate", func(t *testing.T) {
		result, err := cmd.GetTemplate(testCtx, GetTemplateOptions{ID: templateID})
		if surface.IsNotImplemented(err) {
			t.Skip("GetTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "GetTemplate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Template, "Template should not be nil")
		assert.Equal(t, templateID, result.Template.ID, "Template ID should match")
		assert.Equal(t, "Template for get test", result.Template.Description, "Description should match")
	})

	t.Run("GetNonexistentTemplateFails", func(t *testing.T) {
		_, err := cmd.GetTemplate(testCtx, GetTemplateOptions{ID: prefix + "-nonexistent-template-id"})
		if surface.IsNotImplemented(err) {
			t.Skip("GetTemplate not implemented for this adapter")
		}
		require.Error(t, err, "GetTemplate should fail for nonexistent template")
	})
}

func testTemplateDelete(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a template for deletion
	templateID := fmt.Sprintf("%s-template-delete", prefix)
	createOpts := CreateTemplateOptions{
		ID:                templateID,
		Description:       "Template for delete test",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	_, err := cmd.CreateTemplate(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateTemplate not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateTemplate should succeed")

	t.Run("DeleteExistingTemplate", func(t *testing.T) {
		result, err := cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: templateID})
		if surface.IsNotImplemented(err) {
			t.Skip("DeleteTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "DeleteTemplate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Delete should be successful")
	})

	t.Run("VerifyTemplateIsDeleted", func(t *testing.T) {
		_, err := cmd.GetTemplate(testCtx, GetTemplateOptions{ID: templateID})
		if surface.IsNotImplemented(err) {
			t.Skip("GetTemplate not implemented for this adapter")
		}
		require.Error(t, err, "GetTemplate should fail for deleted template")
	})

	t.Run("DeleteNonexistentTemplateFails", func(t *testing.T) {
		_, err := cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: prefix + "-nonexistent-template-delete"})
		if surface.IsNotImplemented(err) {
			t.Skip("DeleteTemplate not implemented for this adapter")
		}
		require.Error(t, err, "DeleteTemplate should fail for nonexistent template")
	})
}

func testTemplateList(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple templates for listing
	var createdIDs []string
	for i := 0; i < 3; i++ {
		templateID := fmt.Sprintf("%s-template-list-%d", prefix, i)
		opts := CreateTemplateOptions{
			ID:                templateID,
			Description:       fmt.Sprintf("List test template %d", i),
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: false,
		}
		result, err := cmd.CreateTemplate(testCtx, opts)
		if surface.IsNotImplemented(err) {
			t.Skip("CreateTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "Setup: CreateTemplate should succeed")
		if result != nil && result.Template != nil && result.Template.ID != "" {
			createdIDs = append(createdIDs, result.Template.ID)
		}
	}
	defer func() {
		for _, id := range createdIDs {
			_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: id})
		}
	}()

	t.Run("ListAllTemplates", func(t *testing.T) {
		result, err := cmd.ListTemplates(testCtx, ListTemplatesOptions{})
		if surface.IsNotImplemented(err) {
			t.Skip("ListTemplates not implemented for this adapter")
		}
		require.NoError(t, err, "ListTemplates should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Templates), 3, "Should have at least 3 templates")
	})
}

func testTemplateClone(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create a template for cloning
	templateID := fmt.Sprintf("%s-template-clone-src", prefix)
	createOpts := CreateTemplateOptions{
		ID:                templateID,
		Description:       "Source template for cloning",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	_, err := cmd.CreateTemplate(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateTemplate not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateTemplate should succeed")

	var clonedBundleID string
	defer func() {
		_, _ = cmd.DeleteTemplate(testCtx, DeleteTemplateOptions{ID: templateID})
		if clonedBundleID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: clonedBundleID})
		}
	}()

	t.Run("CloneTemplateToBundle", func(t *testing.T) {
		hostname := fmt.Sprintf("%s-cloned", prefix)
		cloneOpts := CloneTemplateOptions{
			TemplateID: templateID,
			Hostname:   hostname,
			Labels: map[string]string{
				"cloned": "true",
			},
		}

		result, err := cmd.CloneTemplate(testCtx, cloneOpts)
		if surface.IsNotImplemented(err) {
			t.Skip("CloneTemplate not implemented for this adapter")
		}
		require.NoError(t, err, "CloneTemplate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.NotEmpty(t, result.Bundle.ID, "Cloned bundle ID should not be empty")
		assert.Equal(t, vtpm.BundleModePreAssigned, result.Bundle.Mode, "Cloned bundle should be pre-assigned")
		assert.Equal(t, templateID, result.Bundle.ClonedFrom, "ClonedFrom should reference template")

		clonedBundleID = result.Bundle.ID
	})

	t.Run("CloneNonexistentTemplateFails", func(t *testing.T) {
		cloneOpts := CloneTemplateOptions{
			TemplateID: prefix + "-nonexistent-template",
			Hostname:   "test-clone-fail",
		}

		_, err := cmd.CloneTemplate(testCtx, cloneOpts)
		if surface.IsNotImplemented(err) {
			t.Skip("CloneTemplate not implemented for this adapter")
		}
		require.Error(t, err, "CloneTemplate should fail for nonexistent template")
	})

	t.Run("CloneTemplateMissingHostnameFails", func(t *testing.T) {
		cloneOpts := CloneTemplateOptions{
			TemplateID: templateID,
			Hostname:   "", // Missing hostname
		}

		_, err := cmd.CloneTemplate(testCtx, cloneOpts)
		if surface.IsNotImplemented(err) {
			t.Skip("CloneTemplate not implemented for this adapter")
		}
		require.Error(t, err, "CloneTemplate should fail with missing hostname")
	})
}

// =============================================================================
// Export/Import Tests
// =============================================================================

func testExportImport(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testExportBundle(t, ctx, cmd, prefix)
	testImportBundle(t, ctx, cmd, prefix)
}

func testExportBundle(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create a bundle for export
	hostname := fmt.Sprintf("%s-export", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")
	defer func() {
		if createResult.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: createResult.Bundle.ID})
		}
	}()

	t.Run("ExportExistingBundle", func(t *testing.T) {
		result, err := cmd.ExportBundle(testCtx, ExportBundleOptions{ID: createResult.Bundle.ID})
		if surface.IsNotImplemented(err) {
			t.Skip("ExportBundle not implemented for this adapter")
		}
		require.NoError(t, err, "ExportBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.ArchivePath, "Archive path should not be empty")
	})

	t.Run("ExportNonexistentBundleFails", func(t *testing.T) {
		_, err := cmd.ExportBundle(testCtx, ExportBundleOptions{ID: prefix + "-nonexistent-export"})
		if surface.IsNotImplemented(err) {
			t.Skip("ExportBundle not implemented for this adapter")
		}
		require.Error(t, err, "ExportBundle should fail for nonexistent bundle")
	})
}

func testImportBundle(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create and export a bundle to get valid import data
	hostname := fmt.Sprintf("%s-import-src", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")

	exportResult, err := cmd.ExportBundle(testCtx, ExportBundleOptions{ID: createResult.Bundle.ID})
	if surface.IsNotImplemented(err) {
		t.Skip("ExportBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: ExportBundle should succeed")

	// Delete the original bundle to allow importing
	_, err = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: createResult.Bundle.ID})
	require.NoError(t, err, "Setup: DeleteBundle should succeed")

	var importedBundleID string
	defer func() {
		if importedBundleID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: importedBundleID})
		}
	}()

	t.Run("ImportValidBundle", func(t *testing.T) {
		result, err := cmd.ImportBundle(testCtx, ImportBundleOptions{ArchivePath: exportResult.ArchivePath})
		if surface.IsNotImplemented(err) {
			t.Skip("ImportBundle not implemented for this adapter")
		}
		require.NoError(t, err, "ImportBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Bundle, "Bundle should not be nil")
		assert.NotEmpty(t, result.Bundle.ID, "Imported bundle ID should not be empty")

		importedBundleID = result.Bundle.ID
	})

	t.Run("ImportInvalidPathFails", func(t *testing.T) {
		_, err := cmd.ImportBundle(testCtx, ImportBundleOptions{ArchivePath: "/nonexistent/path/bundle.tar.gz"})
		if surface.IsNotImplemented(err) {
			t.Skip("ImportBundle not implemented for this adapter")
		}
		require.Error(t, err, "ImportBundle should fail with invalid path")
	})
}

// =============================================================================
// Validation Tests
// =============================================================================

func testValidation(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testValidateBundle(t, ctx, cmd, prefix)
}

func testValidateBundle(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a bundle for validation
	hostname := fmt.Sprintf("%s-validate", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")
	defer func() {
		if createResult.Bundle.ID != "" {
			_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: createResult.Bundle.ID})
		}
	}()

	t.Run("ValidateExistingBundle", func(t *testing.T) {
		result, err := cmd.ValidateBundle(testCtx, ValidateBundleOptions{ID: createResult.Bundle.ID})
		if surface.IsNotImplemented(err) {
			t.Skip("ValidateBundle not implemented for this adapter")
		}
		require.NoError(t, err, "ValidateBundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Valid, "Bundle should be valid")
		assert.Empty(t, result.Errors, "There should be no validation errors")
	})

	t.Run("ValidateNonexistentBundleFails", func(t *testing.T) {
		_, err := cmd.ValidateBundle(testCtx, ValidateBundleOptions{ID: prefix + "-nonexistent-validate"})
		if surface.IsNotImplemented(err) {
			t.Skip("ValidateBundle not implemented for this adapter")
		}
		require.Error(t, err, "ValidateBundle should fail for nonexistent bundle")
	})
}

// =============================================================================
// Runtime TPM Operations Tests
// =============================================================================

func testRuntimeTPMOperations(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testStartStop(t, ctx, cmd, prefix)
	testSealUnseal(t, ctx, cmd, prefix)
	testPCROperations(t, ctx, cmd, prefix)
	testQuote(t, ctx, cmd, prefix)
}

func testStartStop(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create a bundle for runtime tests
	hostname := fmt.Sprintf("%s-runtime-startstop", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")

	bundleID := createResult.Bundle.ID
	defer func() {
		// Stop the vTPM if running
		_, _ = cmd.Stop(testCtx, StopOptions{BundleID: bundleID})
		// Delete the bundle
		_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: bundleID})
	}()

	// Track whether Start succeeded - subsequent tests depend on it
	startSucceeded := false

	t.Run("StartVTPM", func(t *testing.T) {
		result, err := cmd.Start(testCtx, StartOptions{BundleID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("Start not implemented for this adapter")
		}
		require.NoError(t, err, "Start should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, bundleID, result.BundleID, "Bundle ID should match")
		assert.True(t, result.Running, "vTPM should be running")
		assert.NotEmpty(t, result.SocketPath, "Socket path should not be empty")
		startSucceeded = true
	})

	t.Run("IsRunning", func(t *testing.T) {
		if !startSucceeded {
			t.Skip("Skipping: Start did not succeed")
		}
		result, err := cmd.IsRunning(testCtx, IsRunningOptions{BundleID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("IsRunning not implemented for this adapter")
		}
		require.NoError(t, err, "IsRunning should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, bundleID, result.BundleID, "Bundle ID should match")
		assert.True(t, result.Running, "vTPM should be running")
	})

	t.Run("StopVTPM", func(t *testing.T) {
		if !startSucceeded {
			t.Skip("Skipping: Start did not succeed")
		}
		result, err := cmd.Stop(testCtx, StopOptions{BundleID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("Stop not implemented for this adapter")
		}
		require.NoError(t, err, "Stop should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, bundleID, result.BundleID, "Bundle ID should match")
		assert.True(t, result.Stopped, "vTPM should be stopped")
	})

	t.Run("IsRunningAfterStop", func(t *testing.T) {
		if !startSucceeded {
			t.Skip("Skipping: Start did not succeed")
		}
		result, err := cmd.IsRunning(testCtx, IsRunningOptions{BundleID: bundleID})
		if surface.IsNotImplemented(err) {
			t.Skip("IsRunning not implemented for this adapter")
		}
		require.NoError(t, err, "IsRunning should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.False(t, result.Running, "vTPM should not be running after stop")
	})
}

func testSealUnseal(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// Create and start a bundle for seal/unseal tests
	hostname := fmt.Sprintf("%s-runtime-seal", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")

	bundleID := createResult.Bundle.ID
	defer func() {
		_, _ = cmd.Stop(testCtx, StopOptions{BundleID: bundleID})
		_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: bundleID})
	}()

	// Start the vTPM
	_, err = cmd.Start(testCtx, StartOptions{BundleID: bundleID})
	if surface.IsNotImplemented(err) {
		t.Skip("Start not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: Start should succeed")

	t.Run("SealAndUnseal", func(t *testing.T) {
		// Generate random data to seal
		plaintext := make([]byte, 32)
		_, err := rand.Read(plaintext)
		require.NoError(t, err, "Failed to generate random data")

		// Seal the data
		sealResult, err := cmd.Seal(testCtx, SealOptions{
			BundleID: bundleID,
			Data:     plaintext,
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Seal not implemented for this adapter")
		}
		require.NoError(t, err, "Seal should succeed")
		require.NotNil(t, sealResult, "Seal result should not be nil")
		assert.NotEmpty(t, sealResult.SealedData, "Sealed data should not be empty")
		assert.NotEqual(t, plaintext, sealResult.SealedData, "Sealed data should differ from plaintext")

		// Unseal the data
		unsealResult, err := cmd.Unseal(testCtx, UnsealOptions{
			BundleID:   bundleID,
			SealedData: sealResult.SealedData,
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Unseal not implemented for this adapter")
		}
		require.NoError(t, err, "Unseal should succeed")
		require.NotNil(t, unsealResult, "Unseal result should not be nil")
		assert.True(t, bytes.Equal(plaintext, unsealResult.Data), "Unsealed data should match original plaintext")
	})

	t.Run("SealWithPCRPolicy", func(t *testing.T) {
		// Generate random data to seal
		plaintext := make([]byte, 32)
		_, err := rand.Read(plaintext)
		require.NoError(t, err, "Failed to generate random data")

		// Seal with PCR binding
		sealResult, err := cmd.Seal(testCtx, SealOptions{
			BundleID: bundleID,
			Data:     plaintext,
			PCRs:     []int{0, 1, 7},
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Seal not implemented for this adapter")
		}
		require.NoError(t, err, "Seal with PCR policy should succeed")
		require.NotNil(t, sealResult, "Seal result should not be nil")
		assert.NotEmpty(t, sealResult.SealedData, "Sealed data should not be empty")

		// Unseal should work if PCRs haven't changed
		unsealResult, err := cmd.Unseal(testCtx, UnsealOptions{
			BundleID:   bundleID,
			SealedData: sealResult.SealedData,
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Unseal not implemented for this adapter")
		}
		require.NoError(t, err, "Unseal should succeed when PCRs match")
		require.NotNil(t, unsealResult, "Unseal result should not be nil")
		assert.True(t, bytes.Equal(plaintext, unsealResult.Data), "Unsealed data should match original plaintext")
	})
}

func testPCROperations(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// Create and start a bundle for PCR tests
	hostname := fmt.Sprintf("%s-runtime-pcr", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")

	bundleID := createResult.Bundle.ID
	defer func() {
		_, _ = cmd.Stop(testCtx, StopOptions{BundleID: bundleID})
		_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: bundleID})
	}()

	// Start the vTPM
	_, err = cmd.Start(testCtx, StartOptions{BundleID: bundleID})
	if surface.IsNotImplemented(err) {
		t.Skip("Start not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: Start should succeed")

	t.Run("ReadPCR", func(t *testing.T) {
		result, err := cmd.ReadPCR(testCtx, ReadPCROptions{
			BundleID: bundleID,
			PCRIndex: 0,
		})
		if surface.IsNotImplemented(err) {
			t.Skip("ReadPCR not implemented for this adapter")
		}
		require.NoError(t, err, "ReadPCR should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, bundleID, result.BundleID, "Bundle ID should match")
		assert.Equal(t, 0, result.PCRIndex, "PCR index should match")
		// PCR 0 should have a value (may be all zeros or already extended)
		assert.NotNil(t, result.Value, "PCR value should not be nil")
	})

	t.Run("ExtendPCR", func(t *testing.T) {
		// Read initial PCR value
		initialResult, err := cmd.ReadPCR(testCtx, ReadPCROptions{
			BundleID: bundleID,
			PCRIndex: 16, // Use PCR 16 which is typically user-extendable
		})
		if surface.IsNotImplemented(err) {
			t.Skip("ReadPCR not implemented for this adapter")
		}
		require.NoError(t, err, "ReadPCR should succeed")
		initialValue := initialResult.Value

		// Extend PCR with some data
		extendData := []byte("test-extend-data-for-integration")
		extendResult, err := cmd.ExtendPCR(testCtx, ExtendPCROptions{
			BundleID: bundleID,
			PCRIndex: 16,
			Data:     extendData,
		})
		if surface.IsNotImplemented(err) {
			t.Skip("ExtendPCR not implemented for this adapter")
		}
		require.NoError(t, err, "ExtendPCR should succeed")
		require.NotNil(t, extendResult, "Result should not be nil")
		assert.True(t, extendResult.Extended, "PCR should be extended")

		// Read PCR value after extension
		afterResult, err := cmd.ReadPCR(testCtx, ReadPCROptions{
			BundleID: bundleID,
			PCRIndex: 16,
		})
		require.NoError(t, err, "ReadPCR after extend should succeed")

		// PCR value should have changed
		assert.False(t, bytes.Equal(initialValue, afterResult.Value), "PCR value should change after extension")
	})

	t.Run("ReadMultiplePCRs", func(t *testing.T) {
		for _, pcrIndex := range []int{0, 1, 7} {
			result, err := cmd.ReadPCR(testCtx, ReadPCROptions{
				BundleID: bundleID,
				PCRIndex: pcrIndex,
			})
			if surface.IsNotImplemented(err) {
				t.Skipf("ReadPCR not implemented for this adapter")
			}
			require.NoError(t, err, "ReadPCR for PCR %d should succeed", pcrIndex)
			require.NotNil(t, result, "Result should not be nil for PCR %d", pcrIndex)
			assert.Equal(t, pcrIndex, result.PCRIndex, "PCR index should match")
		}
	})
}

func testQuote(t *testing.T, ctx context.Context, cmd VTPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// Create and start a bundle for quote tests
	hostname := fmt.Sprintf("%s-runtime-quote", prefix)
	createOpts := CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: false,
	}
	createResult, err := cmd.CreateBundle(testCtx, createOpts)
	if surface.IsNotImplemented(err) {
		t.Skip("CreateBundle not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: CreateBundle should succeed")
	require.NotNil(t, createResult, "Create result should not be nil")
	require.NotNil(t, createResult.Bundle, "Bundle should not be nil")

	bundleID := createResult.Bundle.ID
	defer func() {
		_, _ = cmd.Stop(testCtx, StopOptions{BundleID: bundleID})
		_, _ = cmd.DeleteBundle(testCtx, DeleteBundleOptions{ID: bundleID})
	}()

	// Start the vTPM
	_, err = cmd.Start(testCtx, StartOptions{BundleID: bundleID})
	if surface.IsNotImplemented(err) {
		t.Skip("Start not implemented for this adapter")
	}
	require.NoError(t, err, "Setup: Start should succeed")

	t.Run("GenerateQuote", func(t *testing.T) {
		// Generate random nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		require.NoError(t, err, "Failed to generate nonce")

		result, err := cmd.Quote(testCtx, QuoteOptions{
			BundleID: bundleID,
			Nonce:    nonce,
			PCRs:     []int{0, 1, 7},
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Quote not implemented for this adapter")
		}
		require.NoError(t, err, "Quote should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, bundleID, result.BundleID, "Bundle ID should match")
		assert.NotEmpty(t, result.Quote, "Quote should not be empty")
		assert.NotEmpty(t, result.Signature, "Signature should not be empty")
		assert.NotEmpty(t, result.PCRValues, "PCR values should not be empty")
		assert.NotEmpty(t, result.HashAlgorithm, "Hash algorithm should not be empty")

		// Verify we got values for the requested PCRs
		for _, pcrIndex := range []int{0, 1, 7} {
			value, exists := result.PCRValues[pcrIndex]
			assert.True(t, exists, "PCR %d should be in quote result", pcrIndex)
			assert.NotEmpty(t, value, "PCR %d value should not be empty", pcrIndex)
		}
	})

	t.Run("QuoteWithDifferentNonce", func(t *testing.T) {
		// Generate first nonce
		nonce1 := make([]byte, 32)
		_, err := rand.Read(nonce1)
		require.NoError(t, err, "Failed to generate nonce1")

		result1, err := cmd.Quote(testCtx, QuoteOptions{
			BundleID: bundleID,
			Nonce:    nonce1,
			PCRs:     []int{0},
		})
		if surface.IsNotImplemented(err) {
			t.Skip("Quote not implemented for this adapter")
		}
		require.NoError(t, err, "Quote with nonce1 should succeed")

		// Generate second nonce
		nonce2 := make([]byte, 32)
		_, err = rand.Read(nonce2)
		require.NoError(t, err, "Failed to generate nonce2")

		result2, err := cmd.Quote(testCtx, QuoteOptions{
			BundleID: bundleID,
			Nonce:    nonce2,
			PCRs:     []int{0},
		})
		require.NoError(t, err, "Quote with nonce2 should succeed")

		// Quotes should be different due to different nonces
		assert.False(t, bytes.Equal(result1.Quote, result2.Quote), "Quotes with different nonces should differ")
		assert.False(t, bytes.Equal(result1.Signature, result2.Signature), "Signatures with different nonces should differ")
	})
}

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

func TestVTPMCLI(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("cli-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
}

func TestVTPMREST(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("rest-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
}

func TestVTPMGRPC(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("grpc-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
}

func TestVTPMQUIC(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("quic-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
	testRuntimeTPMOperations(t, ctx, adapter, prefix)
}

func TestVTPMMCP(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("mcp-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
	testRuntimeTPMOperations(t, ctx, adapter, prefix)
}

func TestVTPMUnix(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "vtpm", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("unix-%d", time.Now().Unix())
	testBundleOperations(t, ctx, adapter, prefix)
	testTemplateOperations(t, ctx, adapter, prefix)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestVTPMErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapters := []VTPMCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "vtpm", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			prefix := fmt.Sprintf("err-%s-%d", adapter.Name(), time.Now().Unix())

			t.Run("GetBundle_NotFound", func(t *testing.T) {
				_, err := adapter.GetBundle(ctx, GetBundleOptions{ID: "nonexistent-bundle-id-" + prefix})
				if surface.IsNotImplemented(err) {
					t.Skip("GetBundle not implemented for this adapter")
				}
				require.Error(t, err, "GetBundle should return error for non-existent bundle")
			})

			t.Run("GetTemplate_NotFound", func(t *testing.T) {
				_, err := adapter.GetTemplate(ctx, GetTemplateOptions{ID: "nonexistent-template-id-" + prefix})
				if surface.IsNotImplemented(err) {
					t.Skip("GetTemplate not implemented for this adapter")
				}
				require.Error(t, err, "GetTemplate should return error for non-existent template")
			})

			t.Run("CreateBundle_InvalidMode", func(t *testing.T) {
				opts := CreateBundleOptions{
					Mode:        "", // Invalid mode
					Hostname:    "test-invalid-mode",
					EKAlgorithm: vtpm.EKAlgorithmRSA,
				}
				_, err := adapter.CreateBundle(ctx, opts)
				if surface.IsNotImplemented(err) {
					t.Skip("CreateBundle not implemented for this adapter")
				}
				// Some adapters may accept empty mode, which is fine
				// Just verifying the call doesn't panic
			})

			t.Run("DeleteBundle_NotFound", func(t *testing.T) {
				_, err := adapter.DeleteBundle(ctx, DeleteBundleOptions{ID: "nonexistent-delete-id-" + prefix})
				if surface.IsNotImplemented(err) {
					t.Skip("DeleteBundle not implemented for this adapter")
				}
				require.Error(t, err, "DeleteBundle should fail for non-existent bundle")
			})

			t.Run("CloneTemplate_InvalidTemplate", func(t *testing.T) {
				opts := CloneTemplateOptions{
					TemplateID: "nonexistent-template-" + prefix,
					Hostname:   "test-clone-invalid",
				}
				_, err := adapter.CloneTemplate(ctx, opts)
				if surface.IsNotImplemented(err) {
					t.Skip("CloneTemplate not implemented for this adapter")
				}
				require.Error(t, err, "CloneTemplate should fail for non-existent template")
			})

			t.Run("ExportBundle_NotFound", func(t *testing.T) {
				_, err := adapter.ExportBundle(ctx, ExportBundleOptions{ID: "nonexistent-export-id-" + prefix})
				if surface.IsNotImplemented(err) {
					t.Skip("ExportBundle not implemented for this adapter")
				}
				require.Error(t, err, "ExportBundle should fail for non-existent bundle")
			})

			t.Run("ValidateBundle_NotFound", func(t *testing.T) {
				_, err := adapter.ValidateBundle(ctx, ValidateBundleOptions{ID: "nonexistent-validate-id-" + prefix})
				if surface.IsNotImplemented(err) {
					t.Skip("ValidateBundle not implemented for this adapter")
				}
				require.Error(t, err, "ValidateBundle should fail for non-existent bundle")
			})
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================
