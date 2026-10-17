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

package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// defaultDEKAlgorithm is the algorithm `kms dek create` asks for when
// --algorithm is not given.
const defaultDEKAlgorithm = "AES-256-GCM"

// ErrDEKOperationFailed wraps an SDK error from a `kms dek` verb.
type ErrDEKOperationFailed struct {
	Operation string
	Path      string
	Err       error
}

func (e ErrDEKOperationFailed) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("dek %s failed: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("dek %s failed for %s: %v", e.Operation, e.Path, e.Err)
}

func (e ErrDEKOperationFailed) Unwrap() error {
	return e.Err
}

// ErrDEKEmptyResponse is returned when the SDK reports success but returns
// no DEK.
type ErrDEKEmptyResponse struct {
	Operation string
	Path      string
}

func (e ErrDEKEmptyResponse) Error() string {
	return fmt.Sprintf("dek %s returned no DEK for %s", e.Operation, e.Path)
}

// dekOutput is the JSON shape of one DEK. Timestamps are Unix seconds, 0 when
// unset.
type dekOutput struct {
	Path           string `json:"path" yaml:"path"`
	Algorithm      string `json:"algorithm" yaml:"algorithm"`
	Version        int    `json:"version" yaml:"version"`
	Status         string `json:"status" yaml:"status"`
	IsDefault      bool   `json:"is_default" yaml:"is_default"`
	CreatedAt      int64  `json:"created_at" yaml:"created_at"`
	RotatedAt      int64  `json:"rotated_at,omitempty" yaml:"rotated_at,omitempty"`
	Description    string `json:"description,omitempty" yaml:"description,omitempty"`
	BackendType    string `json:"backend_type,omitempty" yaml:"backend_type,omitempty"`
	UsageCount     uint64 `json:"usage_count" yaml:"usage_count"`
	BytesUsed      uint64 `json:"bytes_used" yaml:"bytes_used"`
	MaxUsageCount  uint64 `json:"max_usage_count" yaml:"max_usage_count"`
	MaxBytesUsed   uint64 `json:"max_bytes_used" yaml:"max_bytes_used"`
	WarningPercent int    `json:"warning_percent" yaml:"warning_percent"`
}

// dekEnvelope wraps a single DEK for `create` and `get`.
type dekEnvelope struct {
	DEK dekOutput `json:"dek" yaml:"dek"`
}

type dekListOutput struct {
	DEKs       []dekOutput `json:"deks" yaml:"deks"`
	TotalCount int         `json:"total_count" yaml:"total_count"`
	HasMore    bool        `json:"has_more" yaml:"has_more"`
}

type dekDeleteOutput struct {
	Path    string `json:"path" yaml:"path"`
	Deleted bool   `json:"deleted" yaml:"deleted"`
}

type dekRotateOutput struct {
	Path       string `json:"path" yaml:"path"`
	OldVersion int    `json:"old_version" yaml:"old_version"`
	NewVersion int    `json:"new_version" yaml:"new_version"`
}

// dekStatusOutput flattens the DEK and its re-encryption progress.
type dekStatusOutput struct {
	dekOutput              `yaml:",inline"`
	ReencryptionInProgress bool    `json:"reencryption_in_progress" yaml:"reencryption_in_progress"`
	ProcessedKeys          int     `json:"processed_keys,omitempty" yaml:"processed_keys,omitempty"`
	TotalKeys              int     `json:"total_keys,omitempty" yaml:"total_keys,omitempty"`
	FailedKeys             int     `json:"failed_keys,omitempty" yaml:"failed_keys,omitempty"`
	PercentComplete        float64 `json:"percent_complete,omitempty" yaml:"percent_complete,omitempty"`
	ReencryptionStartedAt  int64   `json:"reencryption_started_at,omitempty" yaml:"reencryption_started_at,omitempty"`
	ReencryptionError      string  `json:"reencryption_error,omitempty" yaml:"reencryption_error,omitempty"`
}

type dekSetDefaultOutput struct {
	Path            string `json:"path" yaml:"path"`
	PreviousDefault string `json:"previous_default,omitempty" yaml:"previous_default,omitempty"`
}

type dekSafetyOutput struct {
	Path           string `json:"path" yaml:"path"`
	MaxOperations  uint64 `json:"max_operations" yaml:"max_operations"`
	MaxBytes       uint64 `json:"max_bytes" yaml:"max_bytes"`
	WarningPercent int    `json:"warning_percent" yaml:"warning_percent"`
	Cleared        bool   `json:"cleared" yaml:"cleared"`
}

// unixOrZero returns t as Unix seconds, or 0 for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func newDEKOutput(info *dek.DEKInfo) dekOutput {
	return dekOutput{
		Path:           info.Path,
		Algorithm:      info.Algorithm,
		Version:        info.Version,
		Status:         info.Status,
		IsDefault:      info.IsDefault,
		CreatedAt:      unixOrZero(info.CreatedAt),
		RotatedAt:      unixOrZero(info.RotatedAt),
		Description:    info.Description,
		BackendType:    info.BackendType,
		UsageCount:     info.UsageCount,
		BytesUsed:      info.BytesUsed,
		MaxUsageCount:  info.MaxUsageCount,
		MaxBytesUsed:   info.MaxBytesUsed,
		WarningPercent: info.WarningPercent,
	}
}

// dekAction is the body of one `kms dek` verb once the client is open.
type dekAction func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error

// runDEK opens the SDK DEK client from the CLI flags and runs action.
func runDEK(flags *cli.CommonFlags, action dekAction) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openDEKClient(base)
	if err != nil {
		return err
	}
	return action(base.Context(), client, base.Printer())
}

// NewDEKCommand creates the DEK management command
func NewDEKCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dek",
		Short: "Data Encryption Key operations",
		Long: `Create, retrieve, rotate, and manage Data Encryption Keys (DEKs).

DEKs are used for encrypting data at rest. They are wrapped by Key Encryption Keys (KEKs)
and support hierarchical path-based organization for multi-tenant isolation.
Every verb calls the go-quicbaas SDK DEK client.

Examples:
  # Create a new DEK
  platformctl kms dek create /tenant/myapp/default --algorithm AES-256-GCM

  # Get DEK metadata
  platformctl kms dek get /tenant/myapp/default

  # List all DEKs
  platformctl kms dek list

  # List DEKs under a specific path
  platformctl kms dek list --prefix /tenant/myapp

  # Rotate a DEK
  platformctl kms dek rotate /tenant/myapp/default

  # Delete a DEK
  platformctl kms dek delete /tenant/myapp/default --force

  # Set safety limits
  platformctl kms dek set-safety /tenant/myapp/default --max-operations 1000000

  # Clear safety limits
  platformctl kms dek clear-safety /tenant/myapp/default`,
	}

	cmd.AddCommand(newDEKCreateCommand(getFlags))
	cmd.AddCommand(newDEKGetCommand(getFlags))
	cmd.AddCommand(newDEKListCommand(getFlags))
	cmd.AddCommand(newDEKDeleteCommand(getFlags))
	cmd.AddCommand(newDEKRotateCommand(getFlags))
	cmd.AddCommand(newDEKStatusCommand(getFlags))
	cmd.AddCommand(newDEKSetDefaultCommand(getFlags))
	cmd.AddCommand(newDEKSetSafetyCommand(getFlags))
	cmd.AddCommand(newDEKClearSafetyCommand(getFlags))

	return cmd
}

func newDEKCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := dek.CreateDEKRequest{}
	cmd := &cobra.Command{
		Use:   "create <path>",
		Short: "Create a new DEK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Path = args[0]
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKCreate(ctx, client, printer, req)
			})
		},
	}
	cmd.Flags().StringVar(&req.Algorithm, "algorithm", defaultDEKAlgorithm, "encryption algorithm")
	cmd.Flags().StringVar(&req.Description, "description", "", "description of the DEK")
	cmd.Flags().Uint64Var(&req.MaxOperations, "max-operations", 0, "max number of encrypt operations (0 for the server default)")
	cmd.Flags().Uint64Var(&req.MaxBytes, "max-bytes", 0, "max bytes encrypted (0 for the server default)")
	cmd.Flags().IntVar(&req.WarningPercent, "warning-percent", 0, "usage warning threshold percentage (0 for the server default)")
	return cmd
}

func executeDEKCreate(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, req dek.CreateDEKRequest) error {
	resp, err := client.CreateDEK(ctx, &req)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "create", Path: req.Path, Err: err}
	}
	if resp == nil || resp.DEK == nil {
		return ErrDEKEmptyResponse{Operation: "create", Path: req.Path}
	}
	return printer.Print(dekEnvelope{DEK: newDEKOutput(resp.DEK)})
}

func newDEKGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <path>",
		Short: "Get DEK metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKGet(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKGet(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, path string) error {
	info, err := client.GetDEK(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "get", Path: path, Err: err}
	}
	if info == nil {
		return ErrDEKEmptyResponse{Operation: "get", Path: path}
	}
	return printer.Print(dekEnvelope{DEK: newDEKOutput(info)})
}

func newDEKListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := dek.ListDEKsRequest{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List DEKs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKList(ctx, client, printer, req)
			})
		},
	}
	cmd.Flags().StringVar(&req.Prefix, "prefix", "", "filter by path prefix")
	cmd.Flags().BoolVar(&req.Recursive, "recursive", false, "list recursively")
	cmd.Flags().IntVar(&req.Limit, "limit", 100, "maximum number of results")
	return cmd
}

func executeDEKList(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, req dek.ListDEKsRequest) error {
	resp, err := client.ListDEKs(ctx, &req)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "list", Path: req.Prefix, Err: err}
	}
	out := dekListOutput{DEKs: []dekOutput{}}
	if resp != nil {
		for i := range resp.DEKs {
			out.DEKs = append(out.DEKs, newDEKOutput(&resp.DEKs[i]))
		}
		out.TotalCount = resp.TotalCount
	}
	out.HasMore = out.TotalCount > len(out.DEKs)
	return printer.Print(out)
}

func newDEKDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := dek.DeleteDEKRequest{}
	cmd := &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete a DEK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Path = args[0]
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKDelete(ctx, client, printer, req)
			})
		},
	}
	cmd.Flags().BoolVar(&req.Force, "force", false, "bypass deletion protection")
	cmd.Flags().StringVar(&req.MigrateTo, "migrate-to", "", "DEK path to migrate data to before deletion")
	return cmd
}

func executeDEKDelete(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, req dek.DeleteDEKRequest) error {
	resp, err := client.DeleteDEK(ctx, &req)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "delete", Path: req.Path, Err: err}
	}
	out := dekDeleteOutput{Path: req.Path}
	if resp != nil {
		out.Deleted = resp.Deleted
		if resp.Path != "" {
			out.Path = resp.Path
		}
	}
	return printer.Print(out)
}

func newDEKRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := dek.RotateDEKRequest{}
	cmd := &cobra.Command{
		Use:   "rotate <path>",
		Short: "Rotate a DEK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Path = args[0]
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKRotate(ctx, client, printer, req)
			})
		},
	}
	cmd.Flags().BoolVar(&req.Background, "background", false, "re-encrypt existing data in the background")
	return cmd
}

func executeDEKRotate(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, req dek.RotateDEKRequest) error {
	resp, err := client.RotateDEK(ctx, &req)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "rotate", Path: req.Path, Err: err}
	}
	if resp == nil {
		return ErrDEKEmptyResponse{Operation: "rotate", Path: req.Path}
	}
	out := dekRotateOutput{Path: resp.Path, OldVersion: resp.OldVersion, NewVersion: resp.NewVersion}
	if out.Path == "" {
		out.Path = req.Path
	}
	return printer.Print(out)
}

func newDEKStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status <path>",
		Short: "Get DEK status, usage and re-encryption progress",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKStatus(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKStatus(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, path string) error {
	resp, err := client.GetDEKStatus(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "status", Path: path, Err: err}
	}
	if resp == nil || resp.DEK == nil {
		return ErrDEKEmptyResponse{Operation: "status", Path: path}
	}
	out := dekStatusOutput{dekOutput: newDEKOutput(resp.DEK)}
	if progress := resp.ReencryptionProgress; progress != nil {
		out.ReencryptionInProgress = progress.InProgress
		out.ProcessedKeys = progress.ProcessedKeys
		out.TotalKeys = progress.TotalKeys
		out.FailedKeys = progress.FailedKeys
		out.PercentComplete = progress.PercentComplete
		out.ReencryptionStartedAt = unixOrZero(progress.StartedAt)
		out.ReencryptionError = progress.ErrorMessage
	}
	return printer.Print(out)
}

func newDEKSetDefaultCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set-default <path>",
		Short: "Mark a DEK as the default for its path level",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKSetDefault(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKSetDefault(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, path string) error {
	resp, err := client.SetDefaultDEK(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Operation: "set-default", Path: path, Err: err}
	}
	out := dekSetDefaultOutput{Path: path}
	if resp != nil {
		out.PreviousDefault = resp.PreviousDefault
	}
	return printer.Print(out)
}

func newDEKSetSafetyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := dek.SetDEKSafetyRequest{}
	cmd := &cobra.Command{
		Use:   "set-safety <path>",
		Short: "Set DEK AEAD safety limits",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Path = args[0]
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKSetSafety(ctx, client, printer, req)
			})
		},
	}
	cmd.Flags().Uint64Var(&req.MaxOperations, "max-operations", 0, "max number of operations")
	cmd.Flags().Uint64Var(&req.MaxBytes, "max-bytes", 0, "max bytes encrypted")
	cmd.Flags().IntVar(&req.WarningPercent, "warning-percent", 80, "warning threshold percentage")
	return cmd
}

func executeDEKSetSafety(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, req dek.SetDEKSafetyRequest) error {
	if err := client.SetDEKSafety(ctx, &req); err != nil {
		return ErrDEKOperationFailed{Operation: "set-safety", Path: req.Path, Err: err}
	}
	return printer.Print(dekSafetyOutput{
		Path:           req.Path,
		MaxOperations:  req.MaxOperations,
		MaxBytes:       req.MaxBytes,
		WarningPercent: req.WarningPercent,
	})
}

func newDEKClearSafetyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "clear-safety <path>",
		Short: "Clear custom DEK AEAD safety limits",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer) error {
				return executeDEKClearSafety(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKClearSafety(ctx context.Context, client quicbaassdk.DEKClient, printer *cli.Printer, path string) error {
	if err := client.ClearDEKSafety(ctx, path); err != nil {
		return ErrDEKOperationFailed{Operation: "clear-safety", Path: path, Err: err}
	}
	return printer.Print(dekSafetyOutput{Path: path, Cleared: true})
}

func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", ts)
}
