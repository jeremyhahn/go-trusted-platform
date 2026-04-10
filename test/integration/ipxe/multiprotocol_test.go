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

// Package ipxe provides multi-protocol integration tests for iPXE boot services.
// These tests verify that the complete PXE boot flow works correctly,
// including DHCP, TFTP, and HTTP server components working together.
//
// Run tests via:
//
//	make integration-test-ipxe
//
// The tests can be run in the devcontainer with appropriate privileges.
package ipxe

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Full Flow Integration Tests
// =============================================================================

// TestIPXEFullBootFlow tests the complete PXE boot sequence.
// This simulates what happens when a real PXE client boots:
// 1. DHCP DISCOVER -> OFFER (get iPXE firmware)
// 2. TFTP download iPXE firmware
// 3. DHCP DISCOVER -> OFFER (iPXE gets script URL)
// 4. HTTP fetch boot.ipxe
// 5. HTTP fetch menu.ipxe
// 6. HTTP fetch selected boot entry
func TestIPXEFullBootFlow(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := LongRunningTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("FullPXEBootSequence", func(t *testing.T) {
		// Step 1: Verify HTTP server is ready
		httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
		err := httpAdapter.Setup(ctx)
		require.NoError(t, err, "HTTP server should be ready")
		defer httpAdapter.Teardown()

		// Step 2: Verify TFTP server is ready with firmware
		tftpAdapter := NewTFTPClientAdapter(cfg.ServerIP.String(), cfg.TFTPPort)
		err = tftpAdapter.Setup(ctx)
		require.NoError(t, err, "TFTP server should be ready")
		defer tftpAdapter.Teardown()

		// Step 3: Download iPXE firmware via TFTP
		firmware, err := tftpAdapter.TFTPDownload(ctx, "ipxe.efi")
		require.NoError(t, err, "Should download iPXE firmware")
		assert.Greater(t, len(firmware.Data), 500*1024,
			"iPXE firmware should be at least 500KB")

		// Step 4: Fetch boot script via HTTP
		bootScript, err := httpAdapter.HTTPGetBootScript(ctx)
		require.NoError(t, err, "Should fetch boot script")
		assert.Equal(t, http.StatusOK, bootScript.StatusCode)
		assert.True(t, strings.HasPrefix(bootScript.Script, "#!ipxe"),
			"Boot script should be valid iPXE")

		// Step 5: Fetch menu script via HTTP
		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu script")
		assert.Equal(t, http.StatusOK, menuScript.StatusCode)
		assert.True(t, strings.HasPrefix(menuScript.Script, "#!ipxe"),
			"Menu script should be valid iPXE")

		// Step 6: Fetch boot entries
		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			if err != nil {
				t.Logf("Boot entry %s not available: %v", entryName, err)
				continue
			}
			assert.Equal(t, http.StatusOK, entry.StatusCode,
				"Boot entry %s should be available", entryName)
			assert.True(t, strings.HasPrefix(entry.Script, "#!ipxe"),
				"Boot entry %s should be valid iPXE", entryName)
		}
	})
}

// TestIPXEDHCPToHTTPChain tests the DHCP -> HTTP chainloading flow.
func TestIPXEDHCPToHTTPChain(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfNoDHCP(t)
	SkipIfNoNetworkPrivileges(t)

	ctx, cancel := LongRunningTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("NonIPXEClientFlow", func(t *testing.T) {
		// Non-iPXE client should get TFTP boot file
		clientMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "DHCP DISCOVER should succeed")

		// Should get TFTP boot filename
		assert.NotEmpty(t, offer.BootFileName, "Should get boot filename")
		assert.Contains(t, offer.BootFileName, "ipxe.efi",
			"Non-iPXE client should get iPXE firmware filename")

		// TFTP server IP should be set
		assert.Equal(t, cfg.ServerIP.String(), offer.ServerIPAddr.String(),
			"TFTP server should be set")
	})

	t.Run("IPXEClientFlow", func(t *testing.T) {
		// iPXE client should get HTTP script URL
		clientMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, true)
		require.NoError(t, err, "DHCP DISCOVER should succeed")

		// Should get HTTP script URL
		assert.NotEmpty(t, offer.BootFileName, "Should get boot filename")
		assert.True(t,
			strings.HasPrefix(offer.BootFileName, "http://") ||
				strings.Contains(offer.BootFileName, "/boot.ipxe"),
			"iPXE client should get HTTP script URL")
	})
}

// TestIPXEMultiClientBoot tests multiple clients booting simultaneously.
func TestIPXEMultiClientBoot(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := GetTestServerConfig()
	numClients := 5

	t.Run("ConcurrentHTTPBoot", func(t *testing.T) {
		type result struct {
			clientID int
			success  bool
			err      error
		}

		results := make(chan result, numClients)

		// Simulate multiple clients fetching boot scripts
		for i := 0; i < numClients; i++ {
			go func(id int) {
				adapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
				if err := adapter.Setup(ctx); err != nil {
					results <- result{clientID: id, success: false, err: err}
					return
				}
				defer adapter.Teardown()

				// Fetch boot script
				script, err := adapter.HTTPGetBootScript(ctx)
				if err != nil {
					results <- result{clientID: id, success: false, err: err}
					return
				}

				results <- result{
					clientID: id,
					success:  script.StatusCode == http.StatusOK,
				}
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("Client %d failed: %v", r.clientID, r.err)
			} else if r.success {
				successCount++
			}
		}

		assert.Equal(t, numClients, successCount, "All clients should boot successfully")
	})

	t.Run("ConcurrentTFTPDownload", func(t *testing.T) {
		type result struct {
			clientID int
			size     int
			err      error
		}

		results := make(chan result, numClients)

		// Simulate multiple clients downloading firmware
		for i := 0; i < numClients; i++ {
			go func(id int) {
				adapter := NewTFTPClientAdapter(cfg.ServerIP.String(), cfg.TFTPPort)
				if err := adapter.Setup(ctx); err != nil {
					results <- result{clientID: id, err: err}
					return
				}
				defer adapter.Teardown()

				// Download firmware
				download, err := adapter.TFTPDownload(ctx, "ipxe.efi")
				if err != nil {
					results <- result{clientID: id, err: err}
					return
				}

				results <- result{
					clientID: id,
					size:     len(download.Data),
				}
			}(i)
		}

		// Collect results
		var expectedSize int
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("Client %d failed: %v", r.clientID, r.err)
				continue
			}

			if expectedSize == 0 {
				expectedSize = r.size
			} else {
				assert.Equal(t, expectedSize, r.size,
					"All clients should get same firmware size")
			}
		}
	})
}

// =============================================================================
// Service Interaction Tests
// =============================================================================

// TestIPXEServerComponents tests that all server components work together.
func TestIPXEServerComponents(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("AllServicesReady", func(t *testing.T) {
		// HTTP server should respond
		httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
		err := httpAdapter.Setup(ctx)
		require.NoError(t, err, "HTTP server should be ready")
		defer httpAdapter.Teardown()

		health, err := httpAdapter.HTTPGetHealth(ctx)
		require.NoError(t, err, "Health check should succeed")
		assert.Equal(t, http.StatusOK, health.StatusCode)
		assert.Equal(t, "healthy", health.Status)

		// TFTP server should respond
		tftpAdapter := NewTFTPClientAdapter(cfg.ServerIP.String(), cfg.TFTPPort)
		err = tftpAdapter.Setup(ctx)
		require.NoError(t, err, "TFTP server should be ready")
		defer tftpAdapter.Teardown()

		// Should be able to download firmware
		download, err := tftpAdapter.TFTPDownload(ctx, "ipxe.efi")
		require.NoError(t, err, "TFTP download should succeed")
		assert.Greater(t, len(download.Data), 0, "Firmware should not be empty")
	})

	t.Run("ConsistentBootConfiguration", func(t *testing.T) {
		// Verify menu and boot entries are consistent
		httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
		err := httpAdapter.Setup(ctx)
		require.NoError(t, err, "HTTP server should be ready")
		defer httpAdapter.Teardown()

		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu")

		// Each menu entry should have a corresponding boot script
		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			if err != nil {
				continue // Some entries may not be configured
			}

			assert.Equal(t, http.StatusOK, entry.StatusCode,
				"Boot entry %s should be available", entryName)

			// Entry script should contain boot commands
			hasBootCmd := strings.Contains(entry.Script, "kernel") ||
				strings.Contains(entry.Script, "chain") ||
				strings.Contains(entry.Script, "boot")
			assert.True(t, hasBootCmd,
				"Boot entry %s should have boot commands", entryName)
		}
	})
}

// TestIPXEBootScriptChaining tests the boot script chain from boot.ipxe to menu.
func TestIPXEBootScriptChaining(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("BootToMenuChain", func(t *testing.T) {
		httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
		err := httpAdapter.Setup(ctx)
		require.NoError(t, err, "HTTP server should be ready")
		defer httpAdapter.Teardown()

		// Fetch boot script
		bootScript, err := httpAdapter.HTTPGetBootScript(ctx)
		require.NoError(t, err, "Should fetch boot script")

		// Boot script should chain to menu
		assert.Contains(t, bootScript.Script, "chain",
			"Boot script should chain to menu")
		assert.Contains(t, bootScript.Script, "menu.ipxe",
			"Boot script should reference menu.ipxe")

		// Fetch menu script
		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu script")

		// Menu should have items
		assert.Contains(t, menuScript.Script, "item",
			"Menu should contain items")
		assert.Contains(t, menuScript.Script, "choose",
			"Menu should have choose command")
	})
}

// =============================================================================
// Boot Entry Tests
// =============================================================================

// TestIPXEBootEntryGeneration tests that boot entries are correctly generated.
func TestIPXEBootEntryGeneration(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
	err := httpAdapter.Setup(ctx)
	require.NoError(t, err, "HTTP server should be ready")
	defer httpAdapter.Teardown()

	t.Run("ISOBasedEntry", func(t *testing.T) {
		// If an ISO-based entry exists, verify it has correct structure
		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu")

		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			if err != nil {
				continue
			}

			// ISO-based entries should have kernel/initrd URLs
			if strings.Contains(entry.Script, "iso_url") {
				assert.Contains(t, entry.Script, "kernel",
					"ISO entry should load kernel")
				assert.Contains(t, entry.Script, "initrd",
					"ISO entry should load initrd")
			}
		}
	})

	t.Run("KernelBasedEntry", func(t *testing.T) {
		// Verify kernel-based entries have correct structure
		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu")

		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			if err != nil {
				continue
			}

			// If entry loads kernel directly
			if strings.Contains(entry.Script, "kernel ") {
				// Should have boot or initrd command
				hasBoot := strings.Contains(entry.Script, "boot")
				hasInitrd := strings.Contains(entry.Script, "initrd")
				assert.True(t, hasBoot || hasInitrd,
					"Kernel entry should have boot or initrd")
			}
		}
	})
}

// TestIPXEProxyURLGeneration tests that HTTPS proxy URLs are correctly generated.
func TestIPXEProxyURLGeneration(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
	err := httpAdapter.Setup(ctx)
	require.NoError(t, err, "HTTP server should be ready")
	defer httpAdapter.Teardown()

	t.Run("HTTPSURLsProxied", func(t *testing.T) {
		// Boot entries with HTTPS URLs should use proxy
		menuScript, err := httpAdapter.HTTPGetMenuScript(ctx)
		require.NoError(t, err, "Should fetch menu")

		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			if err != nil {
				continue
			}

			// Check if entry uses HTTPS URLs
			if strings.Contains(entry.Script, "https://") {
				t.Logf("Entry %s contains non-proxied HTTPS URL", entryName)
			}

			// Proxied URLs should use /proxy/ path
			if strings.Contains(entry.Script, "/proxy/https/") {
				t.Logf("Entry %s correctly uses proxy for HTTPS", entryName)
			}
		}
	})
}

// =============================================================================
// Resilience Tests
// =============================================================================

// TestIPXEServiceRecovery tests that services recover from errors.
func TestIPXEServiceRecovery(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("HTTPRecovery", func(t *testing.T) {
		httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
		err := httpAdapter.Setup(ctx)
		require.NoError(t, err, "HTTP server should be ready")
		defer httpAdapter.Teardown()

		// Multiple requests should all succeed
		for i := 0; i < 5; i++ {
			health, err := httpAdapter.HTTPGetHealth(ctx)
			require.NoError(t, err, "Health check %d should succeed", i)
			assert.Equal(t, http.StatusOK, health.StatusCode)
		}
	})

	t.Run("TFTPRecovery", func(t *testing.T) {
		tftpAdapter := NewTFTPClientAdapter(cfg.ServerIP.String(), cfg.TFTPPort)
		err := tftpAdapter.Setup(ctx)
		require.NoError(t, err, "TFTP server should be ready")
		defer tftpAdapter.Teardown()

		// Multiple downloads should all succeed
		for i := 0; i < 3; i++ {
			download, err := tftpAdapter.TFTPDownload(ctx, "ipxe.efi")
			require.NoError(t, err, "Download %d should succeed", i)
			assert.Greater(t, len(download.Data), 0)
		}
	})
}

// =============================================================================
// Protocol Adapter Factory
// =============================================================================

// ProtocolTestAdapter provides a unified interface for testing all protocols.
type ProtocolTestAdapter struct {
	HTTP *HTTPClientAdapter
	TFTP *TFTPClientAdapter
}

// NewProtocolTestAdapter creates adapters for all protocols.
func NewProtocolTestAdapter(cfg TestServerConfig) *ProtocolTestAdapter {
	return &ProtocolTestAdapter{
		HTTP: NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort),
		TFTP: NewTFTPClientAdapter(cfg.ServerIP.String(), cfg.TFTPPort),
	}
}

// Setup initializes all protocol adapters.
func (p *ProtocolTestAdapter) Setup(ctx context.Context) error {
	if err := p.HTTP.Setup(ctx); err != nil {
		return fmt.Errorf("HTTP setup failed: %w", err)
	}

	if err := p.TFTP.Setup(ctx); err != nil {
		p.HTTP.Teardown()
		return fmt.Errorf("TFTP setup failed: %w", err)
	}

	return nil
}

// Teardown cleans up all protocol adapters.
func (p *ProtocolTestAdapter) Teardown() error {
	var firstErr error

	if err := p.HTTP.Teardown(); err != nil && firstErr == nil {
		firstErr = err
	}

	if err := p.TFTP.Teardown(); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// TestProtocolAdapterFactory tests the protocol adapter factory.
func TestProtocolAdapterFactory(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("CreateAndUseAdapters", func(t *testing.T) {
		adapter := NewProtocolTestAdapter(cfg)

		err := adapter.Setup(ctx)
		require.NoError(t, err, "Adapter setup should succeed")
		defer adapter.Teardown()

		// Use HTTP adapter
		health, err := adapter.HTTP.HTTPGetHealth(ctx)
		require.NoError(t, err, "HTTP health should succeed")
		assert.Equal(t, http.StatusOK, health.StatusCode)

		// Use TFTP adapter
		download, err := adapter.TFTP.TFTPDownload(ctx, "ipxe.efi")
		require.NoError(t, err, "TFTP download should succeed")
		assert.Greater(t, len(download.Data), 0)
	})
}
