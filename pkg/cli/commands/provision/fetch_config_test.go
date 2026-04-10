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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Fetch Config Command Tests
// =============================================================================

func TestNewFetchConfigCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newFetchConfigCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "fetch-config", cmd.Use)
	assert.Equal(t, "Fetch provisioning config from server", cmd.Short)

	// Verify all flags exist
	for _, flagName := range []string{"server-url", "ek-serial", "mac", "eab-kid", "eab-hmac", "output"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestNewFetchConfigCommand_FlagDefaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newFetchConfigCommand(getFlags)

	// All flags should have empty defaults
	for _, flagName := range []string{"server-url", "ek-serial", "mac", "eab-kid", "eab-hmac", "output"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue, "flag %s should default to empty", flagName)
	}
}

// =============================================================================
// BuildConfigRequest Tests
// =============================================================================

func TestBuildConfigRequest(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		mac:       "00:11:22:33:44:55",
		eabKID:    "my-key-id",
		eabHMAC:   "base64-hmac-value",
		output:    "/tmp/config.yaml",
	}

	req := buildConfigRequest(flags, "test-nonce-abc")

	assert.Equal(t, "EK-12345", req.EKSerial)
	assert.Equal(t, "00:11:22:33:44:55", req.MACAddress)
	assert.Equal(t, "my-key-id", req.EABKeyID)
	assert.Equal(t, "base64-hmac-value", req.EABHMAC)
	assert.Equal(t, "test-nonce-abc", req.Nonce)
}

func TestBuildConfigRequest_EmptyNonce(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-99999",
		mac:       "AA:BB:CC:DD:EE:FF",
		eabKID:    "kid",
		eabHMAC:   "hmac",
		output:    "/tmp/out.yaml",
	}

	req := buildConfigRequest(flags, "")

	assert.Equal(t, "EK-99999", req.EKSerial)
	assert.Equal(t, "", req.Nonce)
}

// =============================================================================
// ValidateProvisionFlags Tests
// =============================================================================

func TestValidateProvisionFlags(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		mac:       "00:11:22:33:44:55",
		eabKID:    "key-id",
		eabHMAC:   "hmac-val",
		output:    "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	assert.NoError(t, err)
}

func TestValidateProvisionFlags_MissingServerURL(t *testing.T) {
	flags := &provisionFlags{
		ekSerial: "EK-12345",
		mac:      "00:11:22:33:44:55",
		eabKID:   "key-id",
		eabHMAC:  "hmac-val",
		output:   "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestValidateProvisionFlags_MissingEKSerial(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		mac:       "00:11:22:33:44:55",
		eabKID:    "key-id",
		eabHMAC:   "hmac-val",
		output:    "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var ekErr ErrEKSerialRequired
	require.ErrorAs(t, err, &ekErr)
}

func TestValidateProvisionFlags_MissingMAC(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		eabKID:    "key-id",
		eabHMAC:   "hmac-val",
		output:    "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var macErr ErrMACRequired
	require.ErrorAs(t, err, &macErr)
}

func TestValidateProvisionFlags_MissingEABKID(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		mac:       "00:11:22:33:44:55",
		eabHMAC:   "hmac-val",
		output:    "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var kidErr ErrEABKIDRequired
	require.ErrorAs(t, err, &kidErr)
}

func TestValidateProvisionFlags_MissingEABHMAC(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		mac:       "00:11:22:33:44:55",
		eabKID:    "key-id",
		output:    "/tmp/config.yaml",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var hmacErr ErrEABHMACRequired
	require.ErrorAs(t, err, &hmacErr)
}

func TestValidateProvisionFlags_MissingOutput(t *testing.T) {
	flags := &provisionFlags{
		serverURL: "https://platform:8443",
		ekSerial:  "EK-12345",
		mac:       "00:11:22:33:44:55",
		eabKID:    "key-id",
		eabHMAC:   "hmac-val",
	}

	err := validateProvisionFlags(flags)
	require.Error(t, err)

	var outErr ErrOutputRequired
	require.ErrorAs(t, err, &outErr)
}

// =============================================================================
// WriteConfigToFile Tests
// =============================================================================

func TestWriteConfigToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "config.yaml")

	configYAML := "server:\n  host: platform.example.com\n  port: 8443\n"
	err := writeConfigToFile(configYAML, outputPath)
	require.NoError(t, err)

	// Verify file was written
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, configYAML, string(data))

	// Verify file permissions (0600 - owner read/write only)
	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteConfigToFile_CreatesParentDir(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nested", "deep", "config.yaml")

	err := writeConfigToFile("test: value\n", outputPath)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "test: value\n", string(data))
}

func TestWriteConfigToFile_InvalidPath(t *testing.T) {
	// /dev/null/impossible is not writable
	err := writeConfigToFile("test: value\n", "/dev/null/impossible/config.yaml")
	require.Error(t, err)

	var writeErr ErrConfigWriteFailed
	require.ErrorAs(t, err, &writeErr)
}

// =============================================================================
// FetchNonce Tests (with httptest)
// =============================================================================

func TestFetchNonce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/provisioning/config/nonce", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := nonceResponse{Nonce: "test-nonce-12345"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	nonce, err := fetchNonce(ctx, server.Client(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, "test-nonce-12345", nonce)
}

func TestFetchNonce_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchNonce(ctx, server.Client(), server.URL)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusInternalServerError, statusErr.StatusCode)
}

func TestFetchNonce_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-valid-json"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchNonce(ctx, server.Client(), server.URL)
	require.Error(t, err)

	var decodeErr ErrResponseDecodeFailed
	require.ErrorAs(t, err, &decodeErr)
}

func TestFetchNonce_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	_, err := fetchNonce(ctx, &http.Client{}, "http://127.0.0.1:1")
	require.Error(t, err)

	var fetchErr ErrNonceFetchFailed
	require.ErrorAs(t, err, &fetchErr)
}

// =============================================================================
// SendConfigRequest Tests (with httptest)
// =============================================================================

func TestSendConfigRequest_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/provisioning/config", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req configRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "EK-123", req.EKSerial)

		w.Header().Set("Content-Type", "application/json")
		resp := configResponse{
			Status: statusOK,
			Config: "platform:\n  host: example.com\n",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	cfgReq := configRequest{
		EKSerial:   "EK-123",
		MACAddress: "00:11:22:33:44:55",
		EABKeyID:   "kid",
		EABHMAC:    "hmac",
		Nonce:      "nonce-abc",
	}

	resp, err := sendConfigRequest(ctx, server.Client(), server.URL, cfgReq)
	require.NoError(t, err)
	assert.Equal(t, statusOK, resp.Status)
	assert.Contains(t, resp.Config, "example.com")
}

func TestSendConfigRequest_Pending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := configResponse{
			Status:       statusPending,
			SessionID:    "session-xyz",
			ProvisionURL: "https://platform:8443/provision/session-xyz",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	cfgReq := configRequest{EKSerial: "EK-456"}

	resp, err := sendConfigRequest(ctx, server.Client(), server.URL, cfgReq)
	require.NoError(t, err)
	assert.Equal(t, statusPending, resp.Status)
	assert.Equal(t, "session-xyz", resp.SessionID)
	assert.Contains(t, resp.ProvisionURL, "session-xyz")
}

func TestSendConfigRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	ctx := context.Background()
	cfgReq := configRequest{EKSerial: "EK-bad"}

	_, err := sendConfigRequest(ctx, server.Client(), server.URL, cfgReq)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusBadRequest, statusErr.StatusCode)
}

func TestSendConfigRequest_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	cfgReq := configRequest{EKSerial: "EK-123"}

	_, err := sendConfigRequest(ctx, &http.Client{}, "http://127.0.0.1:1", cfgReq)
	require.Error(t, err)

	var reqErr ErrConfigRequestFailed
	require.ErrorAs(t, err, &reqErr)
}

// =============================================================================
// PollSession Tests
// =============================================================================

func TestPollSession_Fulfilled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/provisioning/config/poll/session-abc", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := pollResponse{
			Status: statusOK,
			Config: "platform:\n  approved: true\n",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	resp, err := pollSession(ctx, server.Client(), server.URL, "session-abc")
	require.NoError(t, err)
	assert.Equal(t, statusOK, resp.Status)
	assert.Contains(t, resp.Config, "approved: true")
}

func TestPollSession_StillPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := pollResponse{Status: statusPending}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	resp, err := pollSession(ctx, server.Client(), server.URL, "session-pending")
	require.NoError(t, err)
	assert.Equal(t, statusPending, resp.Status)
	assert.Empty(t, resp.Config)
}

func TestPollSession_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := pollSession(ctx, server.Client(), server.URL, "session-err")
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusServiceUnavailable, statusErr.StatusCode)
}

func TestPollSession_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	_, err := pollSession(ctx, &http.Client{}, "http://127.0.0.1:1", "session-fail")
	require.Error(t, err)

	var pollErr ErrPollFailed
	require.ErrorAs(t, err, &pollErr)
	assert.Equal(t, "session-fail", pollErr.SessionID)
}
