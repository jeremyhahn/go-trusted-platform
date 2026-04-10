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
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

func TestRegistryStatus_Fields(t *testing.T) {
	status := RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com:5000",
		Storage: &StorageStatus{
			Backend:    "s3",
			Healthy:    true,
			UsedBytes:  1073741824,
			TotalBytes: 10737418240,
			ImageCount: 100,
			LayerCount: 500,
			BlobCount:  1000,
		},
		Attestation: &AttestationStatus{
			Enabled:        true,
			Required:       true,
			PolicyEngine:   "OPA",
			PolicyEndpoint: "http://localhost:8181",
			PolicyHealthy:  true,
		},
		Encryption: &EncryptionStatus{
			Enabled:           true,
			KeyManagement:     "KMS",
			DefaultKeyID:      "default-key",
			EncryptedImages:   50,
			UnencryptedImages: 50,
		},
		Metrics: &RegistryMetrics{
			PushCount:      1000,
			PullCount:      5000,
			DeleteCount:    100,
			RequestsPerSec: 10.5,
			AvgResponseMs:  25.3,
			ActivePushes:   2,
			ActivePulls:    10,
		},
		Uptime: 86400,
	}

	if !status.Healthy {
		t.Error("expected Healthy to be true")
	}

	if status.Version != "1.0.0" {
		t.Errorf("unexpected Version: %q", status.Version)
	}

	if status.Endpoint != "https://registry.example.com:5000" {
		t.Errorf("unexpected Endpoint: %q", status.Endpoint)
	}

	if status.Storage == nil {
		t.Fatal("Storage should not be nil")
	}

	if status.Attestation == nil {
		t.Fatal("Attestation should not be nil")
	}

	if status.Encryption == nil {
		t.Fatal("Encryption should not be nil")
	}

	if status.Metrics == nil {
		t.Fatal("Metrics should not be nil")
	}

	if status.Uptime != 86400 {
		t.Errorf("unexpected Uptime: %d", status.Uptime)
	}
}

func TestStorageStatus_Fields(t *testing.T) {
	storage := StorageStatus{
		Backend:    "filesystem",
		Healthy:    true,
		UsedBytes:  1073741824,
		TotalBytes: 10737418240,
		ImageCount: 100,
		LayerCount: 500,
		BlobCount:  1000,
	}

	if storage.Backend != "filesystem" {
		t.Errorf("unexpected Backend: %q", storage.Backend)
	}

	if !storage.Healthy {
		t.Error("expected Healthy to be true")
	}

	if storage.UsedBytes != 1073741824 {
		t.Errorf("unexpected UsedBytes: %d", storage.UsedBytes)
	}

	if storage.TotalBytes != 10737418240 {
		t.Errorf("unexpected TotalBytes: %d", storage.TotalBytes)
	}

	if storage.ImageCount != 100 {
		t.Errorf("unexpected ImageCount: %d", storage.ImageCount)
	}

	if storage.LayerCount != 500 {
		t.Errorf("unexpected LayerCount: %d", storage.LayerCount)
	}

	if storage.BlobCount != 1000 {
		t.Errorf("unexpected BlobCount: %d", storage.BlobCount)
	}
}

func TestAttestationStatus_Fields(t *testing.T) {
	attestation := AttestationStatus{
		Enabled:        true,
		Required:       true,
		PolicyEngine:   "OPA",
		PolicyEndpoint: "http://localhost:8181",
		PolicyHealthy:  true,
	}

	if !attestation.Enabled {
		t.Error("expected Enabled to be true")
	}

	if !attestation.Required {
		t.Error("expected Required to be true")
	}

	if attestation.PolicyEngine != "OPA" {
		t.Errorf("unexpected PolicyEngine: %q", attestation.PolicyEngine)
	}

	if attestation.PolicyEndpoint != "http://localhost:8181" {
		t.Errorf("unexpected PolicyEndpoint: %q", attestation.PolicyEndpoint)
	}

	if !attestation.PolicyHealthy {
		t.Error("expected PolicyHealthy to be true")
	}
}

func TestEncryptionStatus_Fields(t *testing.T) {
	encryption := EncryptionStatus{
		Enabled:           true,
		KeyManagement:     "KMS",
		DefaultKeyID:      "default-key",
		EncryptedImages:   50,
		UnencryptedImages: 50,
	}

	if !encryption.Enabled {
		t.Error("expected Enabled to be true")
	}

	if encryption.KeyManagement != "KMS" {
		t.Errorf("unexpected KeyManagement: %q", encryption.KeyManagement)
	}

	if encryption.DefaultKeyID != "default-key" {
		t.Errorf("unexpected DefaultKeyID: %q", encryption.DefaultKeyID)
	}

	if encryption.EncryptedImages != 50 {
		t.Errorf("unexpected EncryptedImages: %d", encryption.EncryptedImages)
	}

	if encryption.UnencryptedImages != 50 {
		t.Errorf("unexpected UnencryptedImages: %d", encryption.UnencryptedImages)
	}
}

func TestRegistryMetrics_Fields(t *testing.T) {
	metrics := RegistryMetrics{
		PushCount:      1000,
		PullCount:      5000,
		DeleteCount:    100,
		RequestsPerSec: 10.5,
		AvgResponseMs:  25.3,
		ActivePushes:   2,
		ActivePulls:    10,
	}

	if metrics.PushCount != 1000 {
		t.Errorf("unexpected PushCount: %d", metrics.PushCount)
	}

	if metrics.PullCount != 5000 {
		t.Errorf("unexpected PullCount: %d", metrics.PullCount)
	}

	if metrics.DeleteCount != 100 {
		t.Errorf("unexpected DeleteCount: %d", metrics.DeleteCount)
	}

	if metrics.RequestsPerSec != 10.5 {
		t.Errorf("unexpected RequestsPerSec: %f", metrics.RequestsPerSec)
	}

	if metrics.AvgResponseMs != 25.3 {
		t.Errorf("unexpected AvgResponseMs: %f", metrics.AvgResponseMs)
	}

	if metrics.ActivePushes != 2 {
		t.Errorf("unexpected ActivePushes: %d", metrics.ActivePushes)
	}

	if metrics.ActivePulls != 10 {
		t.Errorf("unexpected ActivePulls: %d", metrics.ActivePulls)
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

func TestStatusResult_Fields(t *testing.T) {
	result := StatusResult{
		Status: &RegistryStatus{
			Healthy:  true,
			Version:  "1.0.0",
			Endpoint: "https://registry.example.com",
		},
	}

	if result.Status == nil {
		t.Fatal("Status should not be nil")
	}

	if !result.Status.Healthy {
		t.Error("expected Status.Healthy to be true")
	}

	if result.Status.Version != "1.0.0" {
		t.Errorf("unexpected Status.Version: %q", result.Status.Version)
	}
}

// Tests for convertStatusResponse function
func TestConvertStatusResponse_Healthy(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "2.0.0",
	}

	result := convertStatusResponse(resp)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if !result.Status.Healthy {
		t.Error("expected Healthy to be true")
	}

	if result.Status.Version != "2.0.0" {
		t.Errorf("expected Version '2.0.0', got %q", result.Status.Version)
	}
}

func TestConvertStatusResponse_Unhealthy(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
		Version: "1.0.0",
	}

	result := convertStatusResponse(resp)

	if result.Status.Healthy {
		t.Error("expected Healthy to be false")
	}
}

func TestConvertStatusResponse_WithUptime(t *testing.T) {
	startedAt := timestamppb.Now()
	startedAt.Seconds -= 3600 // 1 hour ago
	timestamp := timestamppb.Now()

	resp := &platformv1.RegistryStatusResponse{
		Health:    platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:   "1.0.0",
		StartedAt: startedAt,
		Timestamp: timestamp,
	}

	result := convertStatusResponse(resp)

	// Uptime should be approximately 3600 seconds
	if result.Status.Uptime < 3590 || result.Status.Uptime > 3610 {
		t.Errorf("expected Uptime around 3600, got %d", result.Status.Uptime)
	}
}

func TestConvertStatusResponse_WithStorage(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Storage: &platformv1.StorageStats{
			UsedBytes:       1000000,
			TotalBytes:      10000000,
			ArtifactCount:   50,
			LayerCount:      200,
			RepositoryCount: 10,
		},
	}

	result := convertStatusResponse(resp)

	if result.Status.Storage == nil {
		t.Fatal("expected Storage to be non-nil")
	}

	if result.Status.Storage.UsedBytes != 1000000 {
		t.Errorf("expected UsedBytes 1000000, got %d", result.Status.Storage.UsedBytes)
	}

	if result.Status.Storage.TotalBytes != 10000000 {
		t.Errorf("expected TotalBytes 10000000, got %d", result.Status.Storage.TotalBytes)
	}

	if result.Status.Storage.ImageCount != 50 {
		t.Errorf("expected ImageCount 50, got %d", result.Status.Storage.ImageCount)
	}

	if result.Status.Storage.LayerCount != 200 {
		t.Errorf("expected LayerCount 200, got %d", result.Status.Storage.LayerCount)
	}

	if result.Status.Storage.BlobCount != 10 {
		t.Errorf("expected BlobCount 10, got %d", result.Status.Storage.BlobCount)
	}
}

func TestConvertStatusResponse_WithAttestationComponent(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Components: []*platformv1.ComponentHealth{
			{
				Name:   "attestation",
				Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			},
		},
	}

	result := convertStatusResponse(resp)

	if result.Status.Attestation == nil {
		t.Fatal("expected Attestation to be non-nil")
	}

	if !result.Status.Attestation.Enabled {
		t.Error("expected Attestation.Enabled to be true")
	}

	if !result.Status.Attestation.PolicyHealthy {
		t.Error("expected Attestation.PolicyHealthy to be true")
	}
}

func TestConvertStatusResponse_WithEncryptionComponent(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Components: []*platformv1.ComponentHealth{
			{
				Name:   "encryption",
				Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			},
		},
	}

	result := convertStatusResponse(resp)

	if result.Status.Encryption == nil {
		t.Fatal("expected Encryption to be non-nil")
	}

	if !result.Status.Encryption.Enabled {
		t.Error("expected Encryption.Enabled to be true")
	}
}

func TestConvertStatusResponse_MultipleComponents(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Components: []*platformv1.ComponentHealth{
			{
				Name:   "attestation",
				Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			},
			{
				Name:   "encryption",
				Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			},
			{
				Name:   "unknown",
				Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			},
		},
	}

	result := convertStatusResponse(resp)

	if result.Status.Attestation == nil {
		t.Error("expected Attestation to be non-nil")
	}

	if result.Status.Encryption == nil {
		t.Error("expected Encryption to be non-nil")
	}
}

func TestConvertStatusResponse_AttestationUnhealthy(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Components: []*platformv1.ComponentHealth{
			{
				Name:   "attestation",
				Status: platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
			},
		},
	}

	result := convertStatusResponse(resp)

	if result.Status.Attestation == nil {
		t.Fatal("expected Attestation to be non-nil")
	}

	if result.Status.Attestation.PolicyHealthy {
		t.Error("expected Attestation.PolicyHealthy to be false")
	}
}

func TestConvertStatusResponse_NilStorage(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.0.0",
		Storage: nil,
	}

	result := convertStatusResponse(resp)

	if result.Status.Storage != nil {
		t.Error("expected Storage to be nil")
	}
}

func TestConvertStatusResponse_NilComponents(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:     platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:    "1.0.0",
		Components: nil,
	}

	result := convertStatusResponse(resp)

	if result.Status.Attestation != nil {
		t.Error("expected Attestation to be nil")
	}

	if result.Status.Encryption != nil {
		t.Error("expected Encryption to be nil")
	}
}

func TestConvertStatusResponse_NilTimestamps(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:    platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:   "1.0.0",
		StartedAt: nil,
		Timestamp: nil,
	}

	result := convertStatusResponse(resp)

	if result.Status.Uptime != 0 {
		t.Errorf("expected Uptime 0, got %d", result.Status.Uptime)
	}
}

func TestConvertStatusResponse_OnlyStartedAt(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:    platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:   "1.0.0",
		StartedAt: timestamppb.Now(),
		Timestamp: nil,
	}

	result := convertStatusResponse(resp)

	// Uptime should be 0 if timestamp is nil
	if result.Status.Uptime != 0 {
		t.Errorf("expected Uptime 0, got %d", result.Status.Uptime)
	}
}

func TestConvertStatusResponse_OnlyTimestamp(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:    platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version:   "1.0.0",
		StartedAt: nil,
		Timestamp: timestamppb.Now(),
	}

	result := convertStatusResponse(resp)

	// Uptime should be 0 if started_at is nil
	if result.Status.Uptime != 0 {
		t.Errorf("expected Uptime 0, got %d", result.Status.Uptime)
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

func TestStatusResult_ZeroValues(t *testing.T) {
	var result StatusResult

	if result.Status != nil {
		t.Error("expected nil Status")
	}
}

func TestRegistryStatus_ZeroValues(t *testing.T) {
	var status RegistryStatus

	if status.Healthy {
		t.Error("expected Healthy to be false")
	}

	if status.Version != "" {
		t.Errorf("expected empty Version, got %q", status.Version)
	}

	if status.Endpoint != "" {
		t.Errorf("expected empty Endpoint, got %q", status.Endpoint)
	}

	if status.Storage != nil {
		t.Error("expected nil Storage")
	}

	if status.Uptime != 0 {
		t.Errorf("expected Uptime 0, got %d", status.Uptime)
	}
}
