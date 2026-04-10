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

package fido2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements FIDO2Commands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath string
}

// NewCLIAdapter creates a new CLI protocol adapter instance.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup initializes the CLI adapter by locating the platformctl binary.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	// Check if the binary exists and is executable
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	c.binaryPath = binaryPath
	return nil
}

// Teardown performs any cleanup needed by the CLI adapter.
func (c *CLIAdapter) Teardown() error {
	return nil
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("command failed: %s: %w", string(output), err)
	}
	return output, nil
}

// =============================================================================
// FIDO2 List Operations
// =============================================================================

// List retrieves FIDO2 tokens via CLI.
func (c *CLIAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := []string{"fido2", "list", "-o", "json"}

	if opts.Device != "" {
		args = append(args, "--device", opts.Device)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		// Check if it's a "no tokens found" case (not an error)
		if strings.Contains(string(output), "No FIDO2 tokens found") {
			return &ListResult{
				Device: opts.Device,
				Tokens: []FIDO2TokenInfo{},
			}, nil
		}
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 list", Err: err}
	}

	var resp struct {
		Device string `json:"device"`
		Tokens []struct {
			TokenID         string   `json:"token_id"`
			Type            string   `json:"type"`
			Keyslots        []string `json:"keyslots"`
			FIDO2Credential string   `json:"fido2_credential"`
			FIDO2Salt       string   `json:"fido2_salt"`
			FIDO2RP         string   `json:"fido2_rp"`
			FIDO2UPRequired bool     `json:"fido2_up_required"`
		} `json:"tokens"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Text output parsing fallback for non-JSON output
		return c.parseListTextOutput(output, opts.Device)
	}

	result := &ListResult{
		Device: resp.Device,
		Tokens: make([]FIDO2TokenInfo, 0, len(resp.Tokens)),
	}

	for _, t := range resp.Tokens {
		result.Tokens = append(result.Tokens, FIDO2TokenInfo{
			TokenID:         t.TokenID,
			Type:            t.Type,
			Keyslots:        t.Keyslots,
			FIDO2Credential: t.FIDO2Credential,
			FIDO2Salt:       t.FIDO2Salt,
			FIDO2RP:         t.FIDO2RP,
			FIDO2UPRequired: t.FIDO2UPRequired,
		})
	}

	return result, nil
}

// parseListTextOutput parses text output when JSON is not available.
func (c *CLIAdapter) parseListTextOutput(output []byte, device string) (*ListResult, error) {
	result := &ListResult{
		Device: device,
		Tokens: []FIDO2TokenInfo{},
	}

	lines := strings.Split(string(output), "\n")
	var currentToken *FIDO2TokenInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Token ID:") {
			if currentToken != nil {
				result.Tokens = append(result.Tokens, *currentToken)
			}
			currentToken = &FIDO2TokenInfo{
				TokenID: strings.TrimSpace(strings.TrimPrefix(line, "Token ID:")),
			}
		} else if currentToken != nil {
			if strings.HasPrefix(line, "Type:") {
				currentToken.Type = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			} else if strings.HasPrefix(line, "Relying Party:") {
				currentToken.FIDO2RP = strings.TrimSpace(strings.TrimPrefix(line, "Relying Party:"))
			} else if strings.HasPrefix(line, "User Presence Required:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "User Presence Required:"))
				currentToken.FIDO2UPRequired = val == "true"
			} else if strings.HasPrefix(line, "Credential ID:") {
				currentToken.FIDO2Credential = strings.TrimSpace(strings.TrimPrefix(line, "Credential ID:"))
			} else if strings.HasPrefix(line, "Salt:") {
				currentToken.FIDO2Salt = strings.TrimSpace(strings.TrimPrefix(line, "Salt:"))
			}
		}

		// Extract device from output if present
		if strings.HasPrefix(line, "FIDO2 Tokens on") {
			parts := strings.Split(line, "on")
			if len(parts) > 1 {
				result.Device = strings.TrimSpace(parts[1])
			}
		}
	}

	if currentToken != nil {
		result.Tokens = append(result.Tokens, *currentToken)
	}

	return result, nil
}

// =============================================================================
// FIDO2 Info Operations
// =============================================================================

// Info retrieves detailed FIDO2 and LUKS information via CLI.
func (c *CLIAdapter) Info(ctx context.Context, opts InfoOptions) (*InfoResult, error) {
	args := []string{"fido2", "info", "-o", "json"}

	if opts.Device != "" {
		args = append(args, "--device", opts.Device)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 info", Err: err}
	}

	var resp struct {
		Device         string `json:"device"`
		UUID           string `json:"uuid"`
		Label          string `json:"label"`
		Version        int    `json:"version"`
		Cipher         string `json:"cipher"`
		KeySize        int    `json:"key_size"`
		SectorSize     int    `json:"sector_size"`
		ActiveKeyslots []struct {
			SlotNumber int    `json:"slot_number"`
			Type       string `json:"type"`
			KeySize    int    `json:"key_size"`
			Priority   *int   `json:"priority"`
			KDFType    string `json:"kdf_type"`
			KDFHash    string `json:"kdf_hash"`
			Encryption string `json:"encryption"`
		} `json:"active_keyslots"`
		FIDO2Tokens []struct {
			TokenID         string   `json:"token_id"`
			Type            string   `json:"type"`
			Keyslots        []string `json:"keyslots"`
			FIDO2Credential string   `json:"fido2_credential"`
			FIDO2Salt       string   `json:"fido2_salt"`
			FIDO2RP         string   `json:"fido2_rp"`
			FIDO2UPRequired bool     `json:"fido2_up_required"`
		} `json:"fido2_tokens"`
		Segments []struct {
			SegmentID  string `json:"segment_id"`
			Type       string `json:"type"`
			Offset     string `json:"offset"`
			Size       string `json:"size"`
			Encryption string `json:"encryption"`
			SectorSize int    `json:"sector_size"`
		} `json:"segments"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Text output parsing fallback
		return c.parseInfoTextOutput(output, opts.Device)
	}

	result := &InfoResult{
		Device:     resp.Device,
		UUID:       resp.UUID,
		Label:      resp.Label,
		Version:    resp.Version,
		Cipher:     resp.Cipher,
		KeySize:    resp.KeySize,
		SectorSize: resp.SectorSize,
	}

	for _, ks := range resp.ActiveKeyslots {
		result.ActiveKeyslots = append(result.ActiveKeyslots, KeyslotInfo{
			SlotNumber: ks.SlotNumber,
			Type:       ks.Type,
			KeySize:    ks.KeySize,
			Priority:   ks.Priority,
			KDFType:    ks.KDFType,
			KDFHash:    ks.KDFHash,
			Encryption: ks.Encryption,
		})
	}

	for _, t := range resp.FIDO2Tokens {
		result.FIDO2Tokens = append(result.FIDO2Tokens, FIDO2TokenInfo{
			TokenID:         t.TokenID,
			Type:            t.Type,
			Keyslots:        t.Keyslots,
			FIDO2Credential: t.FIDO2Credential,
			FIDO2Salt:       t.FIDO2Salt,
			FIDO2RP:         t.FIDO2RP,
			FIDO2UPRequired: t.FIDO2UPRequired,
		})
	}

	for _, s := range resp.Segments {
		result.Segments = append(result.Segments, SegmentInfo{
			SegmentID:  s.SegmentID,
			Type:       s.Type,
			Offset:     s.Offset,
			Size:       s.Size,
			Encryption: s.Encryption,
			SectorSize: s.SectorSize,
		})
	}

	return result, nil
}

// parseInfoTextOutput parses text output when JSON is not available.
func (c *CLIAdapter) parseInfoTextOutput(output []byte, device string) (*InfoResult, error) {
	result := &InfoResult{
		Device: device,
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "UUID:") {
			result.UUID = strings.TrimSpace(strings.TrimPrefix(line, "UUID:"))
		} else if strings.HasPrefix(line, "Label:") {
			result.Label = strings.TrimSpace(strings.TrimPrefix(line, "Label:"))
		} else if strings.HasPrefix(line, "Version:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			val = strings.TrimPrefix(val, "LUKS")
			if v, err := strconv.Atoi(val); err == nil {
				result.Version = v
			}
		} else if strings.HasPrefix(line, "Cipher:") {
			result.Cipher = strings.TrimSpace(strings.TrimPrefix(line, "Cipher:"))
		} else if strings.HasPrefix(line, "Key Size:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Key Size:"))
			val = strings.TrimSuffix(val, " bits")
			if v, err := strconv.Atoi(val); err == nil {
				result.KeySize = v
			}
		} else if strings.HasPrefix(line, "Sector Size:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Sector Size:"))
			val = strings.TrimSuffix(val, " bytes")
			if v, err := strconv.Atoi(val); err == nil {
				result.SectorSize = v
			}
		}
	}

	return result, nil
}

// =============================================================================
// FIDO2 Enroll Operations
// =============================================================================

// Enroll enrolls a FIDO2 credential via CLI.
func (c *CLIAdapter) Enroll(ctx context.Context, opts EnrollOptions) (*EnrollResult, error) {
	args := []string{"fido2", "enroll", "-o", "json"}

	if opts.Device != "" {
		args = append(args, "--device", opts.Device)
	}
	if opts.Passphrase != "" {
		args = append(args, "--passphrase", opts.Passphrase)
	}
	if opts.Slot > 0 {
		args = append(args, "--slot", strconv.Itoa(opts.Slot))
	}
	if opts.RP != "" {
		args = append(args, "--rp", opts.RP)
	}
	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}
	if opts.FIPS {
		args = append(args, "--fips")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 enroll", Err: err}
	}

	var resp struct {
		Success      bool   `json:"success"`
		Message      string `json:"message"`
		Device       string `json:"device"`
		Slot         int    `json:"slot"`
		RelyingParty string `json:"relying_party"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Check for success in text output
		outputStr := string(output)
		if strings.Contains(outputStr, "Enrollment Complete") {
			return &EnrollResult{
				Success:      true,
				Message:      "Enrollment completed successfully",
				Device:       opts.Device,
				Slot:         opts.Slot,
				RelyingParty: opts.RP,
			}, nil
		}
		return nil, ErrInvalidResponse{Method: "fido2 enroll", Reason: err.Error()}
	}

	return &EnrollResult{
		Success:      resp.Success,
		Message:      resp.Message,
		Device:       resp.Device,
		Slot:         resp.Slot,
		RelyingParty: resp.RelyingParty,
	}, nil
}

// =============================================================================
// FIDO2 Remove Operations
// =============================================================================

// Remove removes a FIDO2 token via CLI.
func (c *CLIAdapter) Remove(ctx context.Context, opts RemoveOptions) (*RemoveResult, error) {
	args := []string{"fido2", "remove", "-o", "json"}

	if opts.Device != "" {
		args = append(args, "--device", opts.Device)
	}
	if opts.TokenID != "" {
		args = append(args, "--token", opts.TokenID)
	}
	if opts.Slot >= 0 {
		args = append(args, "--slot", strconv.Itoa(opts.Slot))
	}
	if opts.Force {
		args = append(args, "--force")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 remove", Err: err}
	}

	var resp struct {
		Success        bool   `json:"success"`
		Message        string `json:"message"`
		TokenIDRemoved string `json:"token_id_removed"`
		SlotRemoved    int    `json:"slot_removed"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Check for success in text output
		outputStr := string(output)
		if strings.Contains(outputStr, "Removal Complete") {
			return &RemoveResult{
				Success:        true,
				Message:        "Removal completed successfully",
				TokenIDRemoved: opts.TokenID,
				SlotRemoved:    opts.Slot,
			}, nil
		}
		if strings.Contains(outputStr, "Operation cancelled") {
			return &RemoveResult{
				Success: false,
				Message: "Operation cancelled by user",
			}, nil
		}
		return nil, ErrInvalidResponse{Method: "fido2 remove", Reason: err.Error()}
	}

	return &RemoveResult{
		Success:        resp.Success,
		Message:        resp.Message,
		TokenIDRemoved: resp.TokenIDRemoved,
		SlotRemoved:    resp.SlotRemoved,
	}, nil
}

// =============================================================================
// FIDO2 Test Operations
// =============================================================================

// Test tests FIDO2 unlock via CLI.
func (c *CLIAdapter) Test(ctx context.Context, opts TestOptions) (*TestResult, error) {
	args := []string{"fido2", "test", "-o", "json"}

	if opts.Device != "" {
		args = append(args, "--device", opts.Device)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 test", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		Message   string `json:"message"`
		TokenInfo struct {
			TokenID         string   `json:"token_id"`
			Type            string   `json:"type"`
			Keyslots        []string `json:"keyslots"`
			FIDO2Credential string   `json:"fido2_credential"`
			FIDO2Salt       string   `json:"fido2_salt"`
			FIDO2RP         string   `json:"fido2_rp"`
			FIDO2UPRequired bool     `json:"fido2_up_required"`
		} `json:"token_info"`
		RelyingParty string   `json:"relying_party"`
		Keyslots     []string `json:"keyslots"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Check for success in text output
		outputStr := string(output)
		if strings.Contains(outputStr, "Test Passed") {
			return &TestResult{
				Success: true,
				Message: "FIDO2 unlock test passed",
			}, nil
		}
		return nil, ErrInvalidResponse{Method: "fido2 test", Reason: err.Error()}
	}

	result := &TestResult{
		Success:      resp.Success,
		Message:      resp.Message,
		RelyingParty: resp.RelyingParty,
		Keyslots:     resp.Keyslots,
	}

	if resp.TokenInfo.TokenID != "" {
		result.TokenInfo = &FIDO2TokenInfo{
			TokenID:         resp.TokenInfo.TokenID,
			Type:            resp.TokenInfo.Type,
			Keyslots:        resp.TokenInfo.Keyslots,
			FIDO2Credential: resp.TokenInfo.FIDO2Credential,
			FIDO2Salt:       resp.TokenInfo.FIDO2Salt,
			FIDO2RP:         resp.TokenInfo.FIDO2RP,
			FIDO2UPRequired: resp.TokenInfo.FIDO2UPRequired,
		}
	}

	return result, nil
}

// Ensure CLIAdapter implements FIDO2Commands interface.
var _ FIDO2Commands = (*CLIAdapter)(nil)
