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
	"context"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// RegistryClient interface for dependency injection
type RegistryClient interface {
	Push(ctx context.Context, req *PushRequest) (*PushResult, error)
	Pull(ctx context.Context, req *PullRequest) (*PullResult, error)
	List(ctx context.Context, req *ListRequest) (*ListResult, error)
	Delete(ctx context.Context, req *DeleteRequest) (*DeleteResultCLI, error)
	Inspect(ctx context.Context, req *InspectRequest) (*InspectResult, error)
	Status(ctx context.Context, req *StatusRequest) (*StatusResult, error)
}

// PushRequest represents the parameters for a push operation
type PushRequest struct {
	Reference    string
	Encrypt      bool
	KeyID        string
	Sign         bool
	SigningKeyID string
	Overwrite    bool
}

// PullRequest represents the parameters for a pull operation
type PullRequest struct {
	Reference string
	Decrypt   bool
	Verify    bool
	Platform  string
}

// ListRequest represents the parameters for a list operation
type ListRequest struct {
	Repository    string
	Prefix        string
	Limit         int32
	Cursor        string
	ShowEncrypted bool
	SortBy        string
	SortDesc      bool
}

// DeleteRequest represents the parameters for a delete operation
type DeleteRequest struct {
	Reference    string
	Force        bool
	DryRun       bool
	KeepUntagged bool
}

// InspectRequest represents the parameters for an inspect operation
type InspectRequest struct {
	Reference      string
	ShowLayers     bool
	ShowSignature  bool
	ShowEncryption bool
	RawManifest    bool
}

// StatusRequest represents the parameters for a status operation
type StatusRequest struct {
	ShowMetrics     bool
	ShowStorage     bool
	ShowAttestation bool
	ShowEncryption  bool
}

// Printer interface for dependency injection
type Printer interface {
	Print(v interface{}) error
	PrintKeyValue(key, value string)
	PrintSuccess(message string)
	PrintInfo(message string)
	PrintWarning(message string)
	PrintError(message string)
}

// CommandExecutor holds dependencies for command execution
type CommandExecutor struct {
	Client       RegistryClient
	Printer      Printer
	Ctx          context.Context
	OutputFormat cli.OutputFormat
	Output       io.Writer
}

// executePush executes push operation with injected dependencies
func executePush(exec *CommandExecutor, req *PushRequest) error {
	// Validate image reference
	if err := validateImageRef(req.Reference); err != nil {
		return err
	}

	// Validate encryption parameters
	if req.Encrypt && req.KeyID == "" {
		return ErrEncryptionKeyRequired{}
	}

	resp, err := exec.Client.Push(exec.Ctx, req)
	if err != nil {
		return ErrPushFailed{Reference: req.Reference, Err: err}
	}

	return printPushResponse(exec.Printer, exec.OutputFormat, resp)
}

// printPushResponse formats and prints the push response
func printPushResponse(printer Printer, format cli.OutputFormat, resp *PushResult) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Image pushed successfully: %s", resp.Reference))
		printer.PrintKeyValue("Reference", resp.Reference)
		printer.PrintKeyValue("Digest", resp.Digest)
		printer.PrintKeyValue("Size", formatBytes(resp.Size))
		printer.PrintKeyValue("Encrypted", formatBool(resp.Encrypted))
		if resp.KeyID != "" {
			printer.PrintKeyValue("Key ID", resp.KeyID)
		}
		printer.PrintKeyValue("Signed", formatBool(resp.Signed))
		printer.PrintKeyValue("Pushed At", formatTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executePull executes pull operation with injected dependencies
func executePull(exec *CommandExecutor, req *PullRequest) error {
	// Validate image reference
	if err := validateImageRef(req.Reference); err != nil {
		return err
	}

	resp, err := exec.Client.Pull(exec.Ctx, req)
	if err != nil {
		return ErrPullFailed{Reference: req.Reference, Err: err}
	}

	return printPullResponse(exec.Printer, exec.OutputFormat, resp)
}

// printPullResponse formats and prints the pull response
func printPullResponse(printer Printer, format cli.OutputFormat, resp *PullResult) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Image pulled successfully: %s", resp.Reference))
		printer.PrintKeyValue("Reference", resp.Reference)
		printer.PrintKeyValue("Digest", resp.Digest)
		printer.PrintKeyValue("Size", formatBytes(resp.Size))
		printer.PrintKeyValue("Decrypted", formatBool(resp.Decrypted))
		printer.PrintKeyValue("Verified", formatBool(resp.Verified))
		if resp.Platform != "" {
			printer.PrintKeyValue("Platform", resp.Platform)
		}
		printer.PrintKeyValue("Pulled At", formatTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeList executes list operation with injected dependencies
func executeList(exec *CommandExecutor, req *ListRequest) error {
	resp, err := exec.Client.List(exec.Ctx, req)
	if err != nil {
		return ErrListFailed{Err: err}
	}

	return printListResponse(exec.Printer, exec.OutputFormat, resp)
}

// printListResponse formats and prints the list response
func printListResponse(printer Printer, format cli.OutputFormat, resp *ListResult) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Images) == 0 {
			printer.PrintInfo("No images found")
			return nil
		}

		table := cli.NewTableData("REFERENCE", "DIGEST", "SIZE", "ENCRYPTED", "SIGNED", "PUSHED AT")
		for _, img := range resp.Images {
			table.AddRow(
				img.Reference,
				truncateDigest(img.Digest),
				formatBytes(img.Size),
				formatBool(img.Encrypted),
				formatBool(img.Signed),
				formatTimestamp(img.PushedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", resp.TotalCount))
		if resp.HasMore {
			printer.PrintKeyValue("Next Cursor", resp.NextCursor)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeDelete executes delete operation with injected dependencies
func executeDelete(exec *CommandExecutor, req *DeleteRequest) error {
	// Validate image reference
	if err := validateImageRef(req.Reference); err != nil {
		return err
	}

	// Handle dry run mode
	if req.DryRun {
		result := &DeleteResultCLI{
			Reference: req.Reference,
			Digest:    "sha256:placeholder",
			Deleted:   false,
			Message:   "dry run - no changes made",
			Timestamp: 0,
		}
		return printDeleteResponseTestable(exec.Printer, exec.OutputFormat, result, true)
	}

	resp, err := exec.Client.Delete(exec.Ctx, req)
	if err != nil {
		return ErrDeleteFailed{Reference: req.Reference, Err: err}
	}

	return printDeleteResponseTestable(exec.Printer, exec.OutputFormat, resp, false)
}

// printDeleteResponseTestable outputs the delete result in the appropriate format
func printDeleteResponseTestable(printer Printer, format cli.OutputFormat, result *DeleteResultCLI, dryRun bool) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if dryRun {
			printer.PrintWarning(fmt.Sprintf("Would delete: %s", result.Reference))
		} else if result.Deleted {
			printer.PrintSuccess(fmt.Sprintf("Image deleted successfully: %s", result.Reference))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete image: %s", result.Reference))
			if result.Message != "" {
				printer.PrintInfo(result.Message)
			}
		}
		printer.PrintKeyValue("Reference", result.Reference)
		printer.PrintKeyValue("Digest", result.Digest)
		printer.PrintKeyValue("Deleted", formatBool(result.Deleted))
		if result.Message != "" {
			printer.PrintKeyValue("Message", result.Message)
		}
		if !dryRun && result.Deleted {
			printer.PrintKeyValue("Deleted At", formatTimestamp(result.Timestamp))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeInspect executes inspect operation with injected dependencies
func executeInspect(exec *CommandExecutor, req *InspectRequest) error {
	// Validate image reference
	if err := validateImageRef(req.Reference); err != nil {
		return err
	}

	resp, err := exec.Client.Inspect(exec.Ctx, req)
	if err != nil {
		return ErrInspectFailed{Reference: req.Reference, Err: err}
	}

	return printInspectResponse(exec.Printer, exec.OutputFormat, resp, req.ShowLayers, req.ShowSignature, req.ShowEncryption)
}

// printInspectResponse formats and prints the inspect response
func printInspectResponse(printer Printer, format cli.OutputFormat, resp *InspectResult, showLayers, showSignature, showEncryption bool) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printInspectTableTestable(printer, resp.Manifest, showLayers, showSignature, showEncryption)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// printInspectTableTestable prints the manifest in table format using Printer interface
func printInspectTableTestable(printer Printer, manifest *ImageManifest, showLayers, showSignature, showEncryption bool) error {
	if manifest == nil {
		printer.PrintInfo("No manifest found")
		return nil
	}

	// Basic information
	printer.PrintKeyValue("Reference", manifest.Reference)
	printer.PrintKeyValue("Digest", manifest.Digest)
	printer.PrintKeyValue("Media Type", manifest.MediaType)
	printer.PrintKeyValue("Schema Version", fmt.Sprintf("%d", manifest.SchemaVer))
	printer.PrintKeyValue("Created At", formatTimestamp(manifest.CreatedAt))
	printer.PrintKeyValue("Pushed At", formatTimestamp(manifest.PushedAt))
	if manifest.PushedBy != "" {
		printer.PrintKeyValue("Pushed By", manifest.PushedBy)
	}

	// Config section
	if manifest.Config != nil {
		printer.PrintKeyValue("Config Digest", manifest.Config.Digest)
		printer.PrintKeyValue("Config Size", formatBytes(manifest.Config.Size))
		printer.PrintKeyValue("Config Media Type", manifest.Config.MediaType)
	}

	// Layers section
	if showLayers && len(manifest.Layers) > 0 {
		table := cli.NewTableData("INDEX", "DIGEST", "SIZE", "MEDIA TYPE", "ENCRYPTED")
		for i, layer := range manifest.Layers {
			table.AddRow(
				fmt.Sprintf("%d", i),
				truncateDigest(layer.Digest),
				formatBytes(layer.Size),
				layer.MediaType,
				formatBool(layer.Encrypted),
			)
		}
		if err := printer.Print(*table); err != nil {
			return err
		}
	} else if len(manifest.Layers) > 0 {
		var totalSize int64
		for _, layer := range manifest.Layers {
			totalSize += layer.Size
		}
		printer.PrintKeyValue("Layer Count", fmt.Sprintf("%d", len(manifest.Layers)))
		printer.PrintKeyValue("Total Size", formatBytes(totalSize))
	}

	// Signature section
	if showSignature && manifest.Signature != nil {
		printer.PrintKeyValue("Signed", formatBool(manifest.Signature.Signed))
		if manifest.Signature.Signed {
			printer.PrintKeyValue("Valid", formatBool(manifest.Signature.Valid))
			if manifest.Signature.SignedBy != "" {
				printer.PrintKeyValue("Signed By", manifest.Signature.SignedBy)
			}
			if manifest.Signature.KeyID != "" {
				printer.PrintKeyValue("Key ID", manifest.Signature.KeyID)
			}
			if manifest.Signature.Algorithm != "" {
				printer.PrintKeyValue("Algorithm", manifest.Signature.Algorithm)
			}
			if manifest.Signature.ValidatedAt > 0 {
				printer.PrintKeyValue("Validated At", formatTimestamp(manifest.Signature.ValidatedAt))
			}
		}
	}

	// Encryption section
	if showEncryption && manifest.Encryption != nil {
		printer.PrintKeyValue("Encrypted", formatBool(manifest.Encryption.Encrypted))
		if manifest.Encryption.Encrypted {
			printer.PrintKeyValue("Encrypted Layers", fmt.Sprintf("%d", manifest.Encryption.LayerCount))
			if manifest.Encryption.Algorithm != "" {
				printer.PrintKeyValue("Algorithm", manifest.Encryption.Algorithm)
			}
			if len(manifest.Encryption.KeyIDs) > 0 {
				printer.PrintKeyValue("Key IDs", fmt.Sprintf("%v", manifest.Encryption.KeyIDs))
			}
		}
	}

	// Annotations section
	if len(manifest.Annotations) > 0 {
		for key, value := range manifest.Annotations {
			printer.PrintKeyValue(key, value)
		}
	}

	return nil
}

// executeStatus executes status operation with injected dependencies
func executeStatus(exec *CommandExecutor, req *StatusRequest) error {
	resp, err := exec.Client.Status(exec.Ctx, req)
	if err != nil {
		return ErrStatusFailed{Err: err}
	}

	return printStatusResponse(exec.Printer, exec.OutputFormat, resp, req.ShowMetrics, req.ShowStorage, req.ShowAttestation, req.ShowEncryption)
}

// printStatusResponse formats and prints the status response
func printStatusResponse(printer Printer, format cli.OutputFormat, resp *StatusResult, showMetrics, showStorage, showAttestation, showEncryption bool) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printStatusTableTestable(printer, resp.Status, showMetrics, showStorage, showAttestation, showEncryption)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// printStatusTableTestable prints the registry status in table format using Printer interface
func printStatusTableTestable(printer Printer, status *RegistryStatus, showMetrics, showStorage, showAttestation, showEncryption bool) error {
	if status == nil {
		printer.PrintError("Registry status unavailable")
		return nil
	}

	// Overall status
	printer.PrintKeyValue("Health", formatHealthStatus(status.Healthy))
	printer.PrintKeyValue("Version", status.Version)
	printer.PrintKeyValue("Endpoint", status.Endpoint)
	printer.PrintKeyValue("Uptime", formatDuration(status.Uptime))

	// Storage section
	if (showStorage || isDefaultView(showMetrics, showStorage, showAttestation, showEncryption)) && status.Storage != nil {
		printer.PrintKeyValue("Storage Backend", status.Storage.Backend)
		printer.PrintKeyValue("Storage Health", formatHealthStatus(status.Storage.Healthy))
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
		printer.PrintKeyValue("Attestation Enabled", formatBool(status.Attestation.Enabled))
		printer.PrintKeyValue("Attestation Required", formatBool(status.Attestation.Required))
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
		printer.PrintKeyValue("Encryption Enabled", formatBool(status.Encryption.Enabled))
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
