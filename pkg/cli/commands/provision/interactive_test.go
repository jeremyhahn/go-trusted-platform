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

package provision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Interactive Command Tests
// =============================================================================

func TestNewInteractiveCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newInteractiveCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "interactive", cmd.Use)
	assert.Equal(t, "Interactive QR provisioning", cmd.Short)

	// Verify all flags exist
	for _, flagName := range []string{"server-url", "ek-serial", "mac", "eab-kid", "eab-hmac", "output", "timeout"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}

	// Verify timeout default
	timeoutFlag := cmd.Flag("timeout")
	assert.Equal(t, "600", timeoutFlag.DefValue)
}

func TestNewInteractiveCommand_InvalidTimeout(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newInteractiveCommand(getFlags)
	cmd.SetArgs([]string{
		"--server-url", "https://platform:8443",
		"--ek-serial", "EK-123",
		"--mac", "00:11:22:33:44:55",
		"--eab-kid", "kid",
		"--eab-hmac", "hmac",
		"--output", "/tmp/test.yaml",
		"--timeout", "0",
	})

	err := cmd.Execute()
	require.Error(t, err)

	var timeoutErr ErrInvalidTimeout
	require.ErrorAs(t, err, &timeoutErr)
}

// =============================================================================
// GenerateQRText Tests
// =============================================================================

func TestGenerateQRText(t *testing.T) {
	url := "https://platform:8443/provision/session-abc123"
	text := generateQRText(url)

	assert.Contains(t, text, "DEVICE PROVISIONING")
	assert.Contains(t, text, url)
	assert.Contains(t, text, "Open this URL to provision the device")
}

func TestGenerateQRText_EmptyURL(t *testing.T) {
	text := generateQRText("")

	assert.Contains(t, text, "DEVICE PROVISIONING")
	// Should still have the structure even with empty URL
	assert.Contains(t, text, "Open this URL")
}

func TestGenerateQRText_LongURL(t *testing.T) {
	url := "https://very-long-hostname.example.com:8443/api/v1/provisioning/session/a-very-long-session-identifier-that-is-uuid-based"
	text := generateQRText(url)

	assert.Contains(t, text, url)
}

// =============================================================================
// PollForConfig Tests
// =============================================================================

func TestPollForConfig_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := pollResponse{Status: statusPending}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Use a very short context timeout so the poll loop exits quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "config.yaml")

	err := pollForConfig(ctx, server.Client(), server.URL, "session-timeout", outputPath, 1)
	require.Error(t, err)

	var timeoutErr ErrPollTimeout
	require.ErrorAs(t, err, &timeoutErr)
	assert.Equal(t, "session-timeout", timeoutErr.SessionID)
}

func TestPollForConfig_FulfilledAfterPolling(t *testing.T) {
	var pollCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		count := pollCount.Add(1)

		if count >= 2 {
			// Fulfilled on second poll
			resp := pollResponse{
				Status: statusOK,
				Config: "platform:\n  provisioned: true\n",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Still pending
		resp := pollResponse{Status: statusPending}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "config.yaml")

	// Override poll interval to 100ms for faster testing
	// We test via pollForConfig which uses the ticker internally.
	// Since pollIntervalSeconds is 5s, we use a shorter context and test
	// the cancellation path instead. For the fulfillment test, we call
	// pollSession directly and then writeConfigToFile.

	// Test the individual components instead of the full loop to avoid
	// waiting for the 5-second ticker interval in unit tests.
	pollResp, err := pollSession(ctx, server.Client(), server.URL, "session-fulfill")
	require.NoError(t, err)
	assert.Equal(t, statusPending, pollResp.Status)

	// Second poll should return OK
	pollResp2, err := pollSession(ctx, server.Client(), server.URL, "session-fulfill")
	require.NoError(t, err)
	assert.Equal(t, statusOK, pollResp2.Status)
	assert.Contains(t, pollResp2.Config, "provisioned: true")

	// Write the config
	err = writeConfigToFile(pollResp2.Config, outputPath)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrServerURLRequired(t *testing.T) {
	err := ErrServerURLRequired{}
	assert.Equal(t, "provision: --server-url is required", err.Error())
}

func TestErrEKSerialRequired(t *testing.T) {
	err := ErrEKSerialRequired{}
	assert.Equal(t, "provision: --ek-serial is required", err.Error())
}

func TestErrMACRequired(t *testing.T) {
	err := ErrMACRequired{}
	assert.Equal(t, "provision: --mac is required", err.Error())
}

func TestErrEABKIDRequired(t *testing.T) {
	err := ErrEABKIDRequired{}
	assert.Equal(t, "provision: --eab-kid is required", err.Error())
}

func TestErrEABHMACRequired(t *testing.T) {
	err := ErrEABHMACRequired{}
	assert.Equal(t, "provision: --eab-hmac is required", err.Error())
}

func TestErrOutputRequired(t *testing.T) {
	err := ErrOutputRequired{}
	assert.Equal(t, "provision: --output is required", err.Error())
}

func TestErrNonceFetchFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrNonceFetchFailed{URL: "https://example.com/nonce", Cause: cause}
	assert.Contains(t, err.Error(), "https://example.com/nonce")
	assert.ErrorIs(t, err, cause)
}

func TestErrConfigRequestFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrConfigRequestFailed{URL: "https://example.com/config", Cause: cause}
	assert.Contains(t, err.Error(), "https://example.com/config")
	assert.ErrorIs(t, err, cause)
}

func TestErrUnexpectedStatus(t *testing.T) {
	err := ErrUnexpectedStatus{StatusCode: 503, Body: "service unavailable"}
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "service unavailable")
}

func TestErrConfigWriteFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrConfigWriteFailed{Path: "/tmp/bad.yaml", Cause: cause}
	assert.Contains(t, err.Error(), "/tmp/bad.yaml")
	assert.ErrorIs(t, err, cause)
}

func TestErrPollFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrPollFailed{SessionID: "session-123", Cause: cause}
	assert.Contains(t, err.Error(), "session-123")
	assert.ErrorIs(t, err, cause)
}

func TestErrPollTimeout(t *testing.T) {
	err := ErrPollTimeout{SessionID: "session-abc", Timeout: 300}
	assert.Contains(t, err.Error(), "300")
	assert.Contains(t, err.Error(), "session-abc")
}

func TestErrResponseDecodeFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrResponseDecodeFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to decode")
	assert.ErrorIs(t, err, cause)
}

func TestErrInvalidTimeout(t *testing.T) {
	err := ErrInvalidTimeout{Value: -5}
	assert.Contains(t, err.Error(), "-5")
	assert.Contains(t, err.Error(), "must be > 0")
}
