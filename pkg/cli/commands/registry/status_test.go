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

package registry

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

func TestNewStatusCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewStatusCommand returned nil")
	}

	if cmd.Use != "status" {
		t.Errorf("expected Use to be 'status', got %q", cmd.Use)
	}

	if cmd.Short != "Show registry status" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStatusCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	expectedAliases := []string{"health", "info"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}

	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias %q at index %d, got %q", alias, i, cmd.Aliases[i])
		}
	}
}

func TestNewStatusCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewStatusCommand_AcceptsNoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	// Status command should not require any arguments
	if cmd.Args != nil {
		err := cmd.Args(cmd, []string{})
		if err != nil {
			t.Errorf("status command should accept no args: %v", err)
		}
	}
}

func TestNewStatusCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "metrics", shorthand: ""},
		{name: "storage", shorthand: ""},
		{name: "attestation", shorthand: ""},
		{name: "encryption", shorthand: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("expected flag %q to exist", tt.name)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.name, flag.Shorthand)
			}
		})
	}
}

func TestNewStatusCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	flags := []string{"metrics", "storage", "attestation", "encryption"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.DefValue != "false" {
				t.Errorf("expected default value 'false' for %q, got %q", name, flag.DefValue)
			}
		})
	}
}

func TestNewStatusCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	flags := []string{"metrics", "storage", "attestation", "encryption"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have usage text", name)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  int64
		expected string
	}{
		{0, "N/A"},
		{1, "1s"},
		{60, "1m 0s"},
		{61, "1m 1s"},
		{3600, "1h 0m 0s"},
		{3661, "1h 1m 1s"},
		{86400, "1d 0h 0m 0s"},
		{90061, "1d 1h 1m 1s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatDuration(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, result, tt.expected)
			}
		})
	}
}

func TestIsDefaultView(t *testing.T) {
	tests := []struct {
		metrics     bool
		storage     bool
		attestation bool
		encryption  bool
		expected    bool
	}{
		{false, false, false, false, true},
		{true, false, false, false, false},
		{false, true, false, false, false},
		{false, false, true, false, false},
		{false, false, false, true, false},
		{true, true, true, true, false},
	}

	for _, tt := range tests {
		result := isDefaultView(tt.metrics, tt.storage, tt.attestation, tt.encryption)
		if result != tt.expected {
			t.Errorf("isDefaultView(%v, %v, %v, %v) = %v, want %v",
				tt.metrics, tt.storage, tt.attestation, tt.encryption, result, tt.expected)
		}
	}
}

func TestPrintStatusTable_NilStatus(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	err := printStatusTable(printer, nil, false, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintStatusTable_MinimalStatus(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com",
		Uptime:   3600,
	}

	err := printStatusTable(printer, status, false, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintStatusTable_WithStorage(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com",
		Uptime:   3600,
		Storage: &StorageStatus{
			Backend:    "filesystem",
			Healthy:    true,
			UsedBytes:  1073741824,
			TotalBytes: 10737418240,
			ImageCount: 100,
			LayerCount: 500,
			BlobCount:  1000,
		},
	}

	err := printStatusTable(printer, status, false, true, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintStatusTable_WithAttestation(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com",
		Uptime:   3600,
		Attestation: &AttestationStatus{
			Enabled:        true,
			Required:       true,
			PolicyEngine:   "OPA",
			PolicyEndpoint: "http://localhost:8181",
			PolicyHealthy:  true,
		},
	}

	err := printStatusTable(printer, status, false, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintStatusTable_WithEncryption(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com",
		Uptime:   3600,
		Encryption: &EncryptionStatus{
			Enabled:           true,
			KeyManagement:     "KMS",
			DefaultKeyID:      "default-key",
			EncryptedImages:   50,
			UnencryptedImages: 50,
		},
	}

	err := printStatusTable(printer, status, false, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintStatusTable_WithMetrics(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com",
		Uptime:   3600,
		Metrics: &RegistryMetrics{
			PushCount:      1000,
			PullCount:      5000,
			DeleteCount:    100,
			RequestsPerSec: 10.5,
			AvgResponseMs:  25.3,
			ActivePushes:   2,
			ActivePulls:    10,
		},
	}

	err := printStatusTable(printer, status, true, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewStatusCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewStatusCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	flags := []string{"metrics", "storage", "attestation", "encryption"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Value.Type() != "bool" {
				t.Errorf("expected %s flag to be bool, got %s", name, flag.Value.Type())
			}
		})
	}
}

func TestConvertStatusDomainResponse_StorageBackend(t *testing.T) {
	resp := &regsvc.RegistryStatusResult{
		Health:    regsvc.HealthStatusHealthy,
		Version:   "1.2.3",
		StartedAt: 100,
		Timestamp: 160,
		Storage:   &regsvc.StorageStats{ArtifactCount: 4},
		Components: []*regsvc.ComponentStatus{{
			Name:    "storage",
			Status:  regsvc.HealthStatusHealthy,
			Details: map[string]string{"backend": "quicbaas"},
		}},
	}

	result := convertStatusDomainResponse(resp)

	if !result.Status.Healthy || result.Status.Version != "1.2.3" || result.Status.Uptime != 60 {
		t.Fatalf("status = %+v, want healthy 1.2.3 with 60 s uptime", result.Status)
	}
	storage := result.Status.Storage
	if storage.Backend != "quicbaas" || !storage.Healthy || storage.ImageCount != 4 {
		t.Fatalf("storage = %+v, want healthy quicbaas with 4 images", storage)
	}

	// platformctl prints the flat status document with -o json: the backend
	// is in the storage object and repeated as storage_backend.
	out, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var printed struct {
		Status         string `json:"status"`
		StorageBackend string `json:"storage_backend"`
		Storage        struct {
			Backend string `json:"backend"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(out, &printed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if printed.Status != registryStateRunning {
		t.Fatalf("printed status = %q, want %q in %s", printed.Status, registryStateRunning, out)
	}
	if printed.Storage.Backend != "quicbaas" || printed.StorageBackend != "quicbaas" {
		t.Fatalf("printed backend = %q / %q, want quicbaas in %s", printed.Storage.Backend, printed.StorageBackend, out)
	}
}

func TestConvertStatusDomainResponse_UnhealthyStorageWithoutBackend(t *testing.T) {
	resp := &regsvc.RegistryStatusResult{
		Health: regsvc.HealthStatusUnhealthy,
		Components: []*regsvc.ComponentStatus{{
			Name:   "storage",
			Status: regsvc.HealthStatusUnhealthy,
		}},
	}

	result := convertStatusDomainResponse(resp)

	if result.Status.Healthy {
		t.Fatal("unhealthy registry reported healthy")
	}
	storage := result.Status.Storage
	if storage == nil || storage.Healthy || storage.Backend != "" {
		t.Fatalf("storage = %+v, want unhealthy with no backend", storage)
	}
}
