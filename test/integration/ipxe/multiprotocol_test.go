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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
		assert.True(t, bytes.Equal(FirmwareFixture("ipxe.efi"), firmware.Data),
			"TFTP should serve the iPXE firmware byte for byte")

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

		// Step 6: Fetch every configured boot entry
		require.ElementsMatch(t, []string{"alpine-test", "test-kernel"}, menuScript.BootEntries,
			"Menu should list the suite's boot entries")
		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			require.NoError(t, err, "Should fetch boot entry %s", entryName)
			assert.Equal(t, http.StatusOK, entry.StatusCode,
				"Boot entry %s should be available", entryName)
			assert.True(t, strings.HasPrefix(entry.Script, "#!ipxe"),
				"Boot entry %s should be valid iPXE", entryName)
		}
	})
}

// TestIPXEDHCPToHTTPChain follows the boot chain a client takes from the
// DHCP answer: each step fetches what the step before handed out, from the
// server that answered, so a wrong filename, address or script line breaks
// the chain here as it would on a real client.
func TestIPXEDHCPToHTTPChain(t *testing.T) {
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

	ctx, cancel := LongRunningTestContext()
	defer cancel()

	t.Run("NonIPXEClientFlow", func(t *testing.T) {
		// A UEFI PXE ROM is offered the iPXE firmware over TFTP
		offer, err := sendDHCPDiscover(ctx, cfg, GenerateRandomMAC(), ArchEFIx64, true, false)
		require.NoError(t, err, "DHCP DISCOVER should succeed")
		require.Equal(t, "ipxe.efi", offer.BootFileName,
			"Non-iPXE client should get the iPXE firmware filename")
		require.Equal(t, cfg.ServerIP.String(), offer.ServerIPAddr.String(),
			"TFTP server should be the PXE server")

		// Fetch the offered file from the offered server. The suite's TFTP
		// server listens on a free port, not 69, so the port comes from cfg.
		tftpCfg := cfg
		tftpCfg.ServerIP = offer.ServerIPAddr
		firmware, err := downloadTFTPFile(ctx, tftpCfg, offer.BootFileName)
		require.NoError(t, err, "TFTP download of the offered boot file should succeed")
		assert.True(t, bytes.Equal(FirmwareFixture("ipxe.efi"), firmware),
			"The offered boot file should be the iPXE firmware byte for byte")
	})

	t.Run("IPXEClientFlow", func(t *testing.T) {
		// Step 1: iPXE itself is offered the HTTP boot script
		offer, err := sendDHCPDiscover(ctx, cfg, GenerateRandomMAC(), ArchEFIx64, true, true)
		require.NoError(t, err, "DHCP DISCOVER should succeed")
		bootURL := fmt.Sprintf("http://%s:%d/boot.ipxe", cfg.ServerIP, cfg.HTTPPort)
		require.Equal(t, bootURL, offer.BootFileName,
			"iPXE client should be chained to the platform's boot script")

		// Step 2: the boot script, fetched from the URL DHCP handed out
		resp, script, err := httpGet(ctx, offer.BootFileName)
		require.NoError(t, err, "Fetching the offered boot script should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Boot script should return 200")
		require.True(t, strings.HasPrefix(script, "#!ipxe"), "Boot script should be an iPXE script")
		require.Contains(t, script, "chain menu.ipxe?arch=${buildarch}",
			"Boot script should chain the menu for the client's architecture")

		// Step 3: the menu, resolved against the boot script's URL as iPXE
		// resolves a relative chain, with x86_64 for ${buildarch}
		base, err := url.Parse(offer.BootFileName)
		require.NoError(t, err, "Boot file name should be a URL")
		menuURL := base.ResolveReference(&url.URL{Path: "menu.ipxe", RawQuery: "arch=x86_64"})
		resp, menu, err := httpGet(ctx, menuURL.String())
		require.NoError(t, err, "Fetching the menu should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Menu should return 200")
		require.Contains(t, menu, "item test-kernel", "Menu should offer the kernel entry")
		entryURL := base.ResolveReference(&url.URL{Path: "/boot/test-kernel.ipxe"}).String()
		require.Contains(t, menu, "chain "+entryURL, "Menu should chain the kernel entry's script")

		// Step 4: the entry script the menu chains, which loads the kernel
		resp, entry, err := httpGet(ctx, entryURL)
		require.NoError(t, err, "Fetching the entry script should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Entry script should return 200")
		assert.True(t, strings.HasPrefix(entry, "#!ipxe"), "Entry script should be an iPXE script")
		assert.Contains(t, entry, "kernel http://example.com/vmlinuz console=ttyS0",
			"Entry script should load the configured kernel with its arguments")
		assert.Contains(t, entry, "initrd http://example.com/initrd.img",
			"Entry script should load the configured initrd")
	})
}

// TestIPXEMultiClientBoot tests multiple clients booting simultaneously.
func TestIPXEMultiClientBoot(t *testing.T) {
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
			data     []byte
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
					data:     download.Data,
				}
			}(i)
		}

		// Collect results
		want := FirmwareFixture("ipxe.efi")
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("Client %d failed: %v", r.clientID, r.err)
				continue
			}

			assert.True(t, bytes.Equal(want, r.data),
				"Client %d should get the served firmware", r.clientID)
		}
	})
}

// =============================================================================
// Service Interaction Tests
// =============================================================================

// TestIPXEServerComponents tests that all server components work together.
func TestIPXEServerComponents(t *testing.T) {
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
		assert.True(t, bytes.Equal(FirmwareFixture("ipxe.efi"), download.Data),
			"TFTP should serve the iPXE firmware byte for byte")
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
		require.ElementsMatch(t, []string{"alpine-test", "test-kernel"}, menuScript.BootEntries,
			"Menu should list the suite's boot entries")
		for _, entryName := range menuScript.BootEntries {
			entry, err := httpAdapter.HTTPGetBootEntry(ctx, entryName)
			require.NoError(t, err, "Should fetch boot entry %s", entryName)

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
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
	err := httpAdapter.Setup(ctx)
	require.NoError(t, err, "HTTP server should be ready")
	defer httpAdapter.Teardown()

	t.Run("ISOBasedEntry", func(t *testing.T) {
		// alpine-test is the suite's ISO-based entry
		entry, err := httpAdapter.HTTPGetBootEntry(ctx, "alpine-test")
		require.NoError(t, err, "Should fetch the ISO entry")
		require.Equal(t, http.StatusOK, entry.StatusCode)

		assert.Contains(t, entry.Script, "set iso_url ", "ISO entry should name the ISO")
		assert.Contains(t, entry.Script, "kernel ", "ISO entry should load kernel")
		assert.Contains(t, entry.Script, "initrd ", "ISO entry should load initrd")
	})

	t.Run("KernelBasedEntry", func(t *testing.T) {
		// test-kernel is the suite's kernel-based entry
		entry, err := httpAdapter.HTTPGetBootEntry(ctx, "test-kernel")
		require.NoError(t, err, "Should fetch the kernel entry")
		require.Equal(t, http.StatusOK, entry.StatusCode)

		assert.Contains(t, entry.Script, "kernel http://example.com/vmlinuz console=ttyS0")
		assert.Contains(t, entry.Script, "initrd http://example.com/initrd.img")
		assert.Contains(t, entry.Script, "\nboot", "Kernel entry should boot")
	})
}

// TestIPXEProxyURLGeneration tests that HTTPS proxy URLs are correctly generated.
func TestIPXEProxyURLGeneration(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	httpAdapter := NewHTTPClientAdapter(cfg.ServerIP.String(), cfg.HTTPPort)
	err := httpAdapter.Setup(ctx)
	require.NoError(t, err, "HTTP server should be ready")
	defer httpAdapter.Teardown()

	t.Run("HTTPSURLsProxied", func(t *testing.T) {
		// alpine-test's ISO is on an HTTPS mirror; iPXE cannot fetch HTTPS,
		// so every URL the script fetches must go through the proxy route
		entry, err := httpAdapter.HTTPGetBootEntry(ctx, "alpine-test")
		require.NoError(t, err, "Should fetch the alpine-test entry")

		proxyBase := fmt.Sprintf("http://%s:%d/proxy/https/dl-cdn.alpinelinux.org/",
			cfg.ServerIP, cfg.HTTPPort)
		assert.Contains(t, entry.Script, "set kernel_url "+proxyBase,
			"Kernel URL should go through the proxy")
		assert.Contains(t, entry.Script, "set initrd_url "+proxyBase,
			"Initrd URL should go through the proxy")
		assert.Contains(t, entry.Script, "alpine_repo="+proxyBase,
			"Repository URL in the kernel args should go through the proxy")
	})
}

// =============================================================================
// Resilience Tests
// =============================================================================

// TestIPXEServiceRecovery tests that services recover from errors.
func TestIPXEServiceRecovery(t *testing.T) {
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
			assert.True(t, bytes.Equal(FirmwareFixture("ipxe.efi"), download.Data),
				"TFTP should serve the iPXE firmware byte for byte")
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
		return err
	}

	if err := p.TFTP.Setup(ctx); err != nil {
		return errors.Join(err, p.HTTP.Teardown())
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
		assert.True(t, bytes.Equal(FirmwareFixture("ipxe.efi"), download.Data),
			"TFTP should serve the iPXE firmware byte for byte")
	})
}
