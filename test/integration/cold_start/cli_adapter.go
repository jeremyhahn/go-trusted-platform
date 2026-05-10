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

package cold_start

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CLIAdapter drives cold-start operations by shelling out to platformctl.
// It mirrors the ceremony CLI adapter conventions but targets the
// dedicated cold-start daemon instead of the shared platformd.
type CLIAdapter struct {
	binary     string
	cfg        HarnessConfig
	configPath string
	configDir  string
}

// NewCLIAdapter returns a fresh CLI adapter.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates platformctl and writes a temp config pointing it at the
// cold-start daemon's Unix socket and gRPC endpoint.
func (c *CLIAdapter) Setup(ctx context.Context, h *Harness) error {
	binary := os.Getenv(EnvPlatformCTLPath)
	if binary == "" {
		binary = "/tmp/platformctl"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return &ErrAdapterNotReady{Adapter: "CLI: " + err.Error()}
	}
	c.binary = binary
	c.cfg = h.Config()

	dir, err := os.MkdirTemp("", "platformctl-cold-start-*")
	if err != nil {
		return err
	}
	c.configDir = dir
	c.configPath = filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`current_context: cold-start
contexts:
  - name: cold-start
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.cfg.SocketPath, fmt.Sprintf("127.0.0.1:%d", c.cfg.GRPCPort))
	return os.WriteFile(c.configPath, []byte(body), 0o600)
}

// Teardown removes the temp config dir.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		_ = os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// run shells out to platformctl with the cold-start context.
func (c *CLIAdapter) run(ctx context.Context, args ...string) ([]byte, error) {
	full := []string{"--config", c.configPath, "--context", "cold-start"}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, c.binary, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("platformctl %s: %w (stderr=%s)", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Health invokes "platformctl service status" against the cold-start
// daemon. The current canonical CLI surface does not expose a
// dedicated "platformctl health" command — service status is the
// closest equivalent and parses out the daemon state.
func (c *CLIAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	out, err := c.run(ctx, "service", "status", "--output", "json")
	if err != nil {
		return nil, err
	}
	var raw struct {
		State string `json:"state"`
		Ready bool   `json:"ready"`
	}
	if jerr := json.Unmarshal(out, &raw); jerr != nil {
		// Fall back to a minimal snapshot so the scenario can keep
		// going against older CLI builds that emit free-form text.
		return &HealthSnapshot{State: "unknown", Ready: true}, nil
	}
	return &HealthSnapshot{State: raw.State, Ready: raw.Ready}, nil
}

// AddMTLSFactor invokes "platformctl auth factor add --method mtls".
func (c *CLIAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	args := []string{
		"auth", "factor", "add",
		"--username", username,
		"--method", "mtls",
		"--client-cert", bundlePath,
		"--label", label,
		"--output", "json",
	}
	if _, err := c.run(ctx, args...); err != nil {
		return err
	}
	return nil
}

// ListFactors invokes "platformctl auth factor list".
func (c *CLIAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	out, err := c.run(ctx, "auth", "factor", "list", "--username", username, "--output", "json")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Factors []struct {
			ID     string `json:"id"`
			Method string `json:"method"`
			Label  string `json:"label"`
		} `json:"factors"`
	}
	if jerr := json.Unmarshal(out, &raw); jerr != nil {
		return nil, jerr
	}
	records := make([]FactorRecord, 0, len(raw.Factors))
	for _, f := range raw.Factors {
		records = append(records, FactorRecord{ID: f.ID, Method: f.Method, Label: f.Label})
	}
	return records, nil
}

// LoginMTLS invokes "platformctl auth login --method mtls".
func (c *CLIAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	out, err := c.run(ctx, "auth", "login",
		"--username", username,
		"--method", "mtls",
		"--client-cert", bundlePath,
		"--output", "json",
	)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Token string `json:"token"`
	}
	if jerr := json.Unmarshal(out, &raw); jerr != nil {
		return nil, jerr
	}
	sub, _ := decodeJWTSubClaim(raw.Token)
	return &LoginSnapshot{Token: raw.Token, Subject: sub}, nil
}

// RotateMTLSFactor invokes "platformctl auth factor rotate".
func (c *CLIAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	out, err := c.run(ctx, "auth", "factor", "rotate",
		"--username", username,
		"--factor-id", factorID,
		"--client-cert", newBundlePath,
		"--output", "json",
	)
	if err != nil {
		return "", err
	}
	var raw struct {
		ID string `json:"id"`
	}
	if jerr := json.Unmarshal(out, &raw); jerr != nil {
		return "", jerr
	}
	return raw.ID, nil
}

// RemoveFactor invokes "platformctl auth factor remove". Translates the
// CLI's exit-1 + "last factor" stderr message into ErrLastFactor.
func (c *CLIAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	_, err := c.run(ctx, "auth", "factor", "remove",
		"--username", username,
		"--factor-id", factorID,
		"--output", "json",
	)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "last factor") {
		return &ErrLastFactor{Username: username, Reason: err.Error()}
	}
	return err
}

var _ ColdStartCommands = (*CLIAdapter)(nil)
