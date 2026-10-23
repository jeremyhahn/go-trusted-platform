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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// RegistryStatus represents the status of the registry
type RegistryStatus struct {
	Healthy     bool               `json:"healthy" yaml:"healthy"`
	Version     string             `json:"version" yaml:"version"`
	Endpoint    string             `json:"endpoint" yaml:"endpoint"`
	Storage     *StorageStatus     `json:"storage" yaml:"storage"`
	Attestation *AttestationStatus `json:"attestation" yaml:"attestation"`
	Encryption  *EncryptionStatus  `json:"encryption" yaml:"encryption"`
	Metrics     *RegistryMetrics   `json:"metrics,omitempty" yaml:"metrics,omitempty"`
	Uptime      int64              `json:"uptime_seconds" yaml:"uptime_seconds"`
}

// StorageStatus represents storage backend status
type StorageStatus struct {
	Backend    string `json:"backend" yaml:"backend"`
	Healthy    bool   `json:"healthy" yaml:"healthy"`
	UsedBytes  int64  `json:"used_bytes" yaml:"used_bytes"`
	TotalBytes int64  `json:"total_bytes,omitempty" yaml:"total_bytes,omitempty"`
	ImageCount int64  `json:"image_count" yaml:"image_count"`
	LayerCount int64  `json:"layer_count" yaml:"layer_count"`
	BlobCount  int64  `json:"blob_count" yaml:"blob_count"`
}

// AttestationStatus represents attestation configuration status
type AttestationStatus struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Required       bool   `json:"required" yaml:"required"`
	PolicyEngine   string `json:"policy_engine,omitempty" yaml:"policy_engine,omitempty"`
	PolicyEndpoint string `json:"policy_endpoint,omitempty" yaml:"policy_endpoint,omitempty"`
	PolicyHealthy  bool   `json:"policy_healthy" yaml:"policy_healthy"`
}

// EncryptionStatus represents encryption configuration status
type EncryptionStatus struct {
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	KeyManagement     string `json:"key_management,omitempty" yaml:"key_management,omitempty"`
	DefaultKeyID      string `json:"default_key_id,omitempty" yaml:"default_key_id,omitempty"`
	EncryptedImages   int64  `json:"encrypted_images" yaml:"encrypted_images"`
	UnencryptedImages int64  `json:"unencrypted_images" yaml:"unencrypted_images"`
}

// RegistryMetrics represents registry performance metrics
type RegistryMetrics struct {
	PushCount      int64   `json:"push_count" yaml:"push_count"`
	PullCount      int64   `json:"pull_count" yaml:"pull_count"`
	DeleteCount    int64   `json:"delete_count" yaml:"delete_count"`
	RequestsPerSec float64 `json:"requests_per_sec" yaml:"requests_per_sec"`
	AvgResponseMs  float64 `json:"avg_response_ms" yaml:"avg_response_ms"`
	ActivePushes   int32   `json:"active_pushes" yaml:"active_pushes"`
	ActivePulls    int32   `json:"active_pulls" yaml:"active_pulls"`
}

// StatusResult represents the result of a status query
type StatusResult struct {
	Status *RegistryStatus `json:"status" yaml:"status"`
}

// Registry states printed in the status document's status field.
const (
	registryStateRunning  = "running"
	registryStateDegraded = "degraded"
)

// The storage component and its backend detail as the registry service
// reports them (pkg/registry StatusComponentStorage, StatusDetailBackend).
const (
	statusComponentStorage = "storage"
	statusDetailBackend    = "backend"
)

// statusDocument is the flat document `registry status` prints with
// --output json or yaml (docs/registry/cli.md §7).
type statusDocument struct {
	Healthy        bool               `json:"healthy" yaml:"healthy"`
	Status         string             `json:"status" yaml:"status"`
	Version        string             `json:"version" yaml:"version"`
	Endpoint       string             `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	UptimeSeconds  int64              `json:"uptime_seconds" yaml:"uptime_seconds"`
	ImageCount     int64              `json:"image_count" yaml:"image_count"`
	TotalSize      int64              `json:"total_size" yaml:"total_size"`
	StorageBackend string             `json:"storage_backend,omitempty" yaml:"storage_backend,omitempty"`
	Storage        *StorageStatus     `json:"storage,omitempty" yaml:"storage,omitempty"`
	Attestation    *AttestationStatus `json:"attestation,omitempty" yaml:"attestation,omitempty"`
	Encryption     *EncryptionStatus  `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	Metrics        *RegistryMetrics   `json:"metrics,omitempty" yaml:"metrics,omitempty"`
}

// document flattens the result into the printed status document.
func (r *StatusResult) document() *statusDocument {
	if r.Status == nil {
		return &statusDocument{Status: registryStateDegraded}
	}
	doc := &statusDocument{
		Healthy:       r.Status.Healthy,
		Status:        registryStateDegraded,
		Version:       r.Status.Version,
		Endpoint:      r.Status.Endpoint,
		UptimeSeconds: r.Status.Uptime,
		Storage:       r.Status.Storage,
		Attestation:   r.Status.Attestation,
		Encryption:    r.Status.Encryption,
		Metrics:       r.Status.Metrics,
	}
	if r.Status.Healthy {
		doc.Status = registryStateRunning
	}
	if r.Status.Storage != nil {
		doc.ImageCount = r.Status.Storage.ImageCount
		doc.TotalSize = r.Status.Storage.UsedBytes
		doc.StorageBackend = r.Status.Storage.Backend
	}
	return doc
}

// MarshalJSON prints the flat status document.
func (r *StatusResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.document())
}

// MarshalYAML prints the flat status document.
func (r *StatusResult) MarshalYAML() (interface{}, error) {
	return r.document(), nil
}

// NewStatusCommand creates the status subcommand
func NewStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var showMetrics bool
	var showStorage bool
	var showAttestation bool
	var showEncryption bool

	cmd := &cobra.Command{
		Use:     "status",
		Aliases: []string{"health", "info"},
		Short:   "Show registry status",
		Long: `Display the status and health of the Trusted Registry.

Shows information about:
  - Overall registry health and version
  - Storage backend status and usage
  - Attestation configuration and policy status
  - Encryption configuration and statistics
  - Performance metrics (optional)

Examples:
  # Show basic status
  platformctl registry status

  # Show status with metrics
  platformctl registry status --metrics

  # Show all details
  platformctl registry status --metrics --storage --attestation --encryption

  # JSON output for scripting
  platformctl registry status --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStatus(flags, showMetrics, showStorage, showAttestation, showEncryption)
		},
	}

	cmd.Flags().BoolVar(&showMetrics, "metrics", false, "show performance metrics")
	cmd.Flags().BoolVar(&showStorage, "storage", false, "show detailed storage information")
	cmd.Flags().BoolVar(&showAttestation, "attestation", false, "show attestation configuration")
	cmd.Flags().BoolVar(&showEncryption, "encryption", false, "show encryption configuration")

	return cmd
}

// runStatus executes the status command
func runStatus(flags *cli.CommonFlags, showMetrics, showStorage, showAttestation, showEncryption bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	regClient := regsvc.NewClientFromGRPC(base.Client().Registry())

	ctx := base.Context()
	resp, err := regClient.StatusDomain(ctx)
	if err != nil {
		return ErrStatusFailed{Err: err}
	}

	// Convert response to our result type
	result := convertStatusDomainResponse(resp)

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printStatusTable(printer, result.Status, showMetrics, showStorage, showAttestation, showEncryption)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// convertStatusDomainResponse converts a domain status response to the CLI result type
func convertStatusDomainResponse(resp *regsvc.RegistryStatusResult) *StatusResult {
	result := &StatusResult{
		Status: &RegistryStatus{
			Healthy: resp.Health == regsvc.HealthStatusHealthy,
			Version: resp.Version,
		},
	}

	// Calculate uptime
	if resp.StartedAt > 0 && resp.Timestamp > 0 {
		result.Status.Uptime = resp.Timestamp - resp.StartedAt
	}

	// Convert storage stats
	if resp.Storage != nil {
		result.Status.Storage = &StorageStatus{
			Healthy:    true,
			UsedBytes:  resp.Storage.UsedBytes,
			TotalBytes: resp.Storage.TotalBytes,
			ImageCount: resp.Storage.ArtifactCount,
			LayerCount: resp.Storage.LayerCount,
			BlobCount:  resp.Storage.RepositoryCount,
		}
	}

	// Check component health
	for _, component := range resp.Components {
		switch component.Name {
		case statusComponentStorage:
			if result.Status.Storage == nil {
				result.Status.Storage = &StorageStatus{}
			}
			result.Status.Storage.Backend = component.Details[statusDetailBackend]
			result.Status.Storage.Healthy = component.Status == regsvc.HealthStatusHealthy
		case "attestation":
			if result.Status.Attestation == nil {
				result.Status.Attestation = &AttestationStatus{}
			}
			result.Status.Attestation.Enabled = true
			result.Status.Attestation.PolicyHealthy = component.Status == regsvc.HealthStatusHealthy
		case "encryption":
			if result.Status.Encryption == nil {
				result.Status.Encryption = &EncryptionStatus{}
			}
			result.Status.Encryption.Enabled = true
		}
	}

	return result
}

// printStatusTable prints the registry status in table format
func printStatusTable(printer *cli.Printer, status *RegistryStatus, showMetrics, showStorage, showAttestation, showEncryption bool) error {
	if status == nil {
		printer.PrintError("Registry status unavailable")
		return nil
	}

	// Overall status
	fmt.Println("Registry Status")
	fmt.Println("===============")
	printer.PrintKeyValue("Health", formatHealthStatus(status.Healthy))
	printer.PrintKeyValue("Version", status.Version)
	printer.PrintKeyValue("Endpoint", status.Endpoint)
	printer.PrintKeyValue("Uptime", formatDuration(status.Uptime))

	// Storage section
	if (showStorage || isDefaultView(showMetrics, showStorage, showAttestation, showEncryption)) && status.Storage != nil {
		fmt.Println()
		fmt.Println("Storage")
		fmt.Println("-------")
		printer.PrintKeyValue("Backend", status.Storage.Backend)
		printer.PrintKeyValue("Health", formatHealthStatus(status.Storage.Healthy))
		printer.PrintKeyValue("Used Space", formatBytes(status.Storage.UsedBytes))
		if status.Storage.TotalBytes > 0 {
			percentage := float64(status.Storage.UsedBytes) / float64(status.Storage.TotalBytes) * 100
			printer.PrintKeyValue("Total Space", formatBytes(status.Storage.TotalBytes))
			printer.PrintKeyValue("Usage", fmt.Sprintf("%.1f%%", percentage))
		}
		printer.PrintKeyValue("Images", fmt.Sprintf("%d", status.Storage.ImageCount))
		printer.PrintKeyValue("Layers", fmt.Sprintf("%d", status.Storage.LayerCount))
		printer.PrintKeyValue("Blobs", fmt.Sprintf("%d", status.Storage.BlobCount))
	}

	// Attestation section
	if (showAttestation || isDefaultView(showMetrics, showStorage, showAttestation, showEncryption)) && status.Attestation != nil {
		fmt.Println()
		fmt.Println("Attestation")
		fmt.Println("-----------")
		printer.PrintKeyValue("Enabled", formatBool(status.Attestation.Enabled))
		printer.PrintKeyValue("Required", formatBool(status.Attestation.Required))
		if status.Attestation.PolicyEngine != "" {
			printer.PrintKeyValue("Policy Engine", status.Attestation.PolicyEngine)
		}
		if status.Attestation.PolicyEndpoint != "" {
			printer.PrintKeyValue("Policy Endpoint", status.Attestation.PolicyEndpoint)
		}
		printer.PrintKeyValue("Policy Health", formatHealthStatus(status.Attestation.PolicyHealthy))
	}

	// Encryption section
	if (showEncryption || isDefaultView(showMetrics, showStorage, showAttestation, showEncryption)) && status.Encryption != nil {
		fmt.Println()
		fmt.Println("Encryption")
		fmt.Println("----------")
		printer.PrintKeyValue("Enabled", formatBool(status.Encryption.Enabled))
		if status.Encryption.KeyManagement != "" {
			printer.PrintKeyValue("Key Management", status.Encryption.KeyManagement)
		}
		if status.Encryption.DefaultKeyID != "" {
			printer.PrintKeyValue("Default Key ID", status.Encryption.DefaultKeyID)
		}
		printer.PrintKeyValue("Encrypted Images", fmt.Sprintf("%d", status.Encryption.EncryptedImages))
		printer.PrintKeyValue("Unencrypted Images", fmt.Sprintf("%d", status.Encryption.UnencryptedImages))
	}

	// Metrics section
	if showMetrics && status.Metrics != nil {
		fmt.Println()
		fmt.Println("Metrics")
		fmt.Println("-------")
		printer.PrintKeyValue("Total Pushes", fmt.Sprintf("%d", status.Metrics.PushCount))
		printer.PrintKeyValue("Total Pulls", fmt.Sprintf("%d", status.Metrics.PullCount))
		printer.PrintKeyValue("Total Deletes", fmt.Sprintf("%d", status.Metrics.DeleteCount))
		printer.PrintKeyValue("Requests/sec", fmt.Sprintf("%.2f", status.Metrics.RequestsPerSec))
		printer.PrintKeyValue("Avg Response", fmt.Sprintf("%.2f ms", status.Metrics.AvgResponseMs))
		printer.PrintKeyValue("Active Pushes", fmt.Sprintf("%d", status.Metrics.ActivePushes))
		printer.PrintKeyValue("Active Pulls", fmt.Sprintf("%d", status.Metrics.ActivePulls))
	}

	return nil
}

// isDefaultView returns true if no specific view flags are set
func isDefaultView(showMetrics, showStorage, showAttestation, showEncryption bool) bool {
	return !showMetrics && !showStorage && !showAttestation && !showEncryption
}

// formatDuration formats seconds into a human-readable duration string
func formatDuration(seconds int64) string {
	if seconds == 0 {
		return "N/A"
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}
