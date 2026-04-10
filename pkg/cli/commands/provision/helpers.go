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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// validateProvisionFlags validates that all required provisioning flags are set.
func validateProvisionFlags(flags *provisionFlags) error {
	if flags.serverURL == "" {
		return ErrServerURLRequired{}
	}
	if flags.ekSerial == "" {
		return ErrEKSerialRequired{}
	}
	if flags.mac == "" {
		return ErrMACRequired{}
	}
	if flags.eabKID == "" {
		return ErrEABKIDRequired{}
	}
	if flags.eabHMAC == "" {
		return ErrEABHMACRequired{}
	}
	if flags.output == "" {
		return ErrOutputRequired{}
	}
	return nil
}

// buildConfigRequest creates a configRequest from the provision flags and nonce.
func buildConfigRequest(flags *provisionFlags, nonce string) configRequest {
	return configRequest{
		EKSerial:   flags.ekSerial,
		MACAddress: flags.mac,
		EABKeyID:   flags.eabKID,
		EABHMAC:    flags.eabHMAC,
		Nonce:      nonce,
	}
}

// fetchNonce retrieves a nonce from the provisioning server.
func fetchNonce(ctx context.Context, client *http.Client, serverURL string) (string, error) {
	nonceURL := strings.TrimRight(serverURL, "/") + "/api/v1/provisioning/config/nonce"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nonceURL, nil)
	if err != nil {
		return "", ErrNonceFetchFailed{URL: nonceURL, Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", ErrNonceFetchFailed{URL: nonceURL, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var nonceResp nonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return "", ErrResponseDecodeFailed{Cause: err}
	}

	return nonceResp.Nonce, nil
}

// sendConfigRequest sends the provisioning config request to the server and
// returns the parsed response.
func sendConfigRequest(ctx context.Context, client *http.Client, serverURL string, cfgReq configRequest) (*configResponse, error) {
	configURL := strings.TrimRight(serverURL, "/") + "/api/v1/provisioning/config"

	body, err := json.Marshal(cfgReq)
	if err != nil {
		return nil, ErrConfigRequestFailed{URL: configURL, Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, configURL, bytes.NewReader(body))
	if err != nil {
		return nil, ErrConfigRequestFailed{URL: configURL, Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrConfigRequestFailed{URL: configURL, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var cfgResp configResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfgResp); err != nil {
		return nil, ErrResponseDecodeFailed{Cause: err}
	}

	return &cfgResp, nil
}

// pollSession polls the server for a fulfilled provisioning session.
func pollSession(ctx context.Context, client *http.Client, serverURL, sessionID string) (*pollResponse, error) {
	pollURL := strings.TrimRight(serverURL, "/") + "/api/v1/provisioning/config/poll/" + sessionID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, ErrPollFailed{SessionID: sessionID, Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrPollFailed{SessionID: sessionID, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var pollResp pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, ErrResponseDecodeFailed{Cause: err}
	}

	return &pollResp, nil
}

// writeConfigToFile writes the config YAML content to the specified output path.
func writeConfigToFile(configYAML, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ErrConfigWriteFailed{Path: outputPath, Cause: err}
	}

	if err := os.WriteFile(outputPath, []byte(configYAML), 0600); err != nil {
		return ErrConfigWriteFailed{Path: outputPath, Cause: err}
	}

	return nil
}

// generateQRText generates a text representation of a provisioning URL suitable
// for display when a QR code library is not available. The URL itself is the
// primary output; operators can type it into a browser manually.
func generateQRText(provisionURL string) string {
	var b strings.Builder
	b.WriteString("========================================\n")
	b.WriteString("  DEVICE PROVISIONING\n")
	b.WriteString("========================================\n")
	b.WriteString("\n")
	b.WriteString("Open this URL to provision the device:\n")
	b.WriteString("\n")
	b.WriteString("  ")
	b.WriteString(provisionURL)
	b.WriteString("\n")
	b.WriteString("\n")
	b.WriteString("========================================\n")
	return b.String()
}
