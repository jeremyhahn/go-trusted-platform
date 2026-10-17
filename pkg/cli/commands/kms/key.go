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
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrInvalidKeyUsage is returned when an invalid key usage is specified
type ErrInvalidKeyUsage struct {
	Usage string
}

func (e ErrInvalidKeyUsage) Error() string {
	return fmt.Sprintf("invalid key usage: %s", e.Usage)
}

// NewKeyCommand creates the key management command group
func NewKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage cryptographic keys",
		Long: `Manage cryptographic keys including generation, listing, rotation, and deletion.

Supported operations:
  - generate: Generate a new cryptographic key
  - get: Retrieve key details
  - list: List all keys in the key store
  - delete: Delete a key
  - rotate: Rotate an existing key
  - import: Import an external key
  - export: Export a wrapped key
  - unwrap: Import a wrapped key
  - versions: List all versions of a key
  - revoke: Revoke a key
  - status: Enable or disable a key
  - metadata: Get or update key metadata
  - policy: Manage key access policies
  - algorithms: List supported algorithms
  - backend-test: Test KMS backend functionality
  - safety: Manage AEAD safety limits`,
	}

	// Core key operations
	cmd.AddCommand(newKeyGenerateCommand(getFlags))
	cmd.AddCommand(newKeyGetCommand(getFlags))
	cmd.AddCommand(newKeyListCommand(getFlags))
	cmd.AddCommand(newKeyDeleteCommand(getFlags))
	cmd.AddCommand(newKeyRotateCommand(getFlags))
	cmd.AddCommand(newKeyCSRCommand(getFlags))

	// Key import/export operations
	cmd.AddCommand(newKeyImportCommand(getFlags))
	cmd.AddCommand(newKeyExportCommand(getFlags))
	cmd.AddCommand(newKeyUnwrapCommand(getFlags))

	// Key versioning and lifecycle
	cmd.AddCommand(newKeyVersionsCommand(getFlags))
	cmd.AddCommand(newKeyRevokeCommand(getFlags))
	cmd.AddCommand(newKeyStatusCommand(getFlags))

	// Key metadata and policy
	cmd.AddCommand(newKeyMetadataCommand(getFlags))
	cmd.AddCommand(newKeyPolicyCommand(getFlags))

	// Backend operations
	cmd.AddCommand(newKeyAlgorithmsCommand(getFlags))
	cmd.AddCommand(newKeyBackendTestCommand(getFlags))

	// Safety limits (requires key_safety build tag and go-quicbaas support)
	if safetyCmd := newKeySafetyCommand(getFlags); safetyCmd != nil {
		cmd.AddCommand(safetyCmd)
	}

	return cmd
}

// newKeyGenerateCommand creates the key generate subcommand
func newKeyGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var algorithm string
	var purpose string
	var exportable bool
	var deletionProtection bool
	var name string
	var description string
	var owner string

	cmd := &cobra.Command{
		Use:   "generate <key-id>",
		Short: "Generate a new cryptographic key",
		Long: `Generate a new cryptographic key with the specified parameters.

Supported algorithms:
  Symmetric:    aes-128, aes-192, aes-256, chacha20-poly1305
  RSA:          rsa-2048, rsa-3072, rsa-4096
  ECDSA:        ecdsa-p256, ecdsa-p384, ecdsa-p521
  EdDSA:        ed25519
  PQC:          dilithium2, dilithium3, dilithium5
  HMAC:         hmac-sha256, hmac-sha384, hmac-sha512

Supported purposes (comma-separated):
  encrypt, decrypt, sign, verify, wrap, unwrap, derive, hmac`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKeyGenerate(flags, args[0], algorithm, purpose, exportable, deletionProtection, name, description, owner)
		},
	}

	cmd.Flags().StringVarP(&algorithm, "algorithm", "a", "aes-256", "key algorithm")
	cmd.Flags().StringVarP(&purpose, "purpose", "p", "encrypt", "key purpose (comma-separated: encrypt, sign, wrap, etc.)")
	cmd.Flags().BoolVarP(&exportable, "exportable", "e", false, "allow key export")
	cmd.Flags().BoolVar(&deletionProtection, "deletion-protection", false, "enable deletion protection")
	cmd.Flags().StringVarP(&name, "name", "n", "", "human-readable key name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "key description")
	cmd.Flags().StringVar(&owner, "owner", "", "key owner identifier")

	return cmd
}

// newKeyGetCommand creates the key get subcommand
func newKeyGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var version uint64

	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get key information",
		Long:  "Retrieve information about a specific key by its ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKeyGet(flags, args[0], version)
		},
	}

	cmd.Flags().Uint64Var(&version, "version", 0, "specific key version (0 for latest)")

	return cmd
}

// newKeyListCommand creates the key list subcommand
func newKeyListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limit int32
	var cursor string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all keys",
		Long:  "Display a list of all cryptographic keys with pagination support",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKeyList(flags, limit, cursor)
		},
	}

	cmd.Flags().Int32VarP(&limit, "limit", "l", 50, "maximum number of keys to return")
	cmd.Flags().StringVar(&cursor, "cursor", "", "pagination cursor for next page")

	return cmd
}

// newKeyDeleteCommand creates the key delete subcommand
func newKeyDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var pendingWindowDays int32
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <key-id>",
		Short: "Delete a key",
		Long: `Delete a cryptographic key. By default, keys enter a pending deletion state
for a configurable number of days before permanent removal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKeyDelete(flags, args[0], pendingWindowDays, force)
		},
	}

	cmd.Flags().Int32VarP(&pendingWindowDays, "pending-days", "p", 7, "days to wait before permanent deletion")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip pending deletion window (immediate delete)")

	return cmd
}

// newKeyRotateCommand creates the key rotate subcommand
func newKeyRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var retainOldVersion bool

	cmd := &cobra.Command{
		Use:   "rotate <key-id>",
		Short: "Rotate a key",
		Long:  "Create a new version of an existing key while optionally retaining the old version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKeyRotate(flags, args[0], retainOldVersion)
		},
	}

	cmd.Flags().BoolVarP(&retainOldVersion, "retain-old", "r", true, "retain the old key version")

	return cmd
}

func runKeyGenerate(flags *cli.CommonFlags, keyID, algorithm, purpose string, exportable, deletionProtection bool, name, description, owner string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	keyAlg, err := kmssvc.ParseKeyAlgorithm(algorithm)
	if err != nil {
		return ErrInvalidKeyAlgorithm{Algorithm: algorithm}
	}

	keyUsages, err := kmssvc.ParseKeyUsages(purpose)
	if err != nil {
		return err
	}

	params := &kmssvc.GenerateKeyParams{
		KeyID:              keyID,
		Algorithm:          keyAlg,
		Usages:             keyUsages,
		Exportable:         exportable,
		DeletionProtection: deletionProtection,
		Name:               name,
		Description:        description,
		Owner:              owner,
	}

	ctx := base.Context()
	resp, err := sdkClient.GenerateKeyDomain(ctx, params)
	if err != nil {
		return &WrappedError{Msg: "failed to generate key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Key generated successfully: %s", resp.Key.KeyID))
		fmt.Println()
		printer.PrintKeyValue("Key ID", resp.Key.KeyID)
		printer.PrintKeyValue("Version", fmt.Sprintf("%d", resp.Key.Version))
		printer.PrintKeyValue("Algorithm", string(resp.Key.Algorithm))
		printer.PrintKeyValue("Status", string(resp.Key.Status))
		printer.PrintKeyValue("Created At", formatKeyTimestamp(resp.Key.CreatedAt))
		if resp.Metadata != nil {
			if resp.Metadata.Name != "" {
				printer.PrintKeyValue("Name", resp.Metadata.Name)
			}
			if resp.Metadata.Description != "" {
				printer.PrintKeyValue("Description", resp.Metadata.Description)
			}
			printer.PrintKeyValue("Exportable", fmt.Sprintf("%t", resp.Metadata.Exportable))
			printer.PrintKeyValue("Deletion Protection", fmt.Sprintf("%t", resp.Metadata.DeletionProtection))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runKeyGet(flags *cli.CommonFlags, keyID string, version uint64) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.GetKeyDomain(ctx, keyID, version)
	if err != nil {
		return &WrappedError{Msg: "failed to get key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Key ID", resp.Key.KeyID)
		printer.PrintKeyValue("Version", fmt.Sprintf("%d", resp.Key.Version))
		printer.PrintKeyValue("Algorithm", string(resp.Key.Algorithm))
		printer.PrintKeyValue("Status", string(resp.Key.Status))
		printer.PrintKeyValue("Created At", formatKeyTimestamp(resp.Key.CreatedAt))
		if resp.Metadata != nil {
			if resp.Metadata.Name != "" {
				printer.PrintKeyValue("Name", resp.Metadata.Name)
			}
			if resp.Metadata.Description != "" {
				printer.PrintKeyValue("Description", resp.Metadata.Description)
			}
			printer.PrintKeyValue("Exportable", fmt.Sprintf("%t", resp.Metadata.Exportable))
			printer.PrintKeyValue("Deletion Protection", fmt.Sprintf("%t", resp.Metadata.DeletionProtection))
			if resp.Metadata.Owner != "" {
				printer.PrintKeyValue("Owner", resp.Metadata.Owner)
			}
			if resp.Metadata.UpdatedAt > 0 {
				printer.PrintKeyValue("Updated At", formatKeyTimestamp(resp.Metadata.UpdatedAt))
			}
			if resp.Metadata.LastUsedAt > 0 {
				printer.PrintKeyValue("Last Used At", formatKeyTimestamp(resp.Metadata.LastUsedAt))
			}
			if len(resp.Metadata.Usage) > 0 {
				printer.PrintKeyValue("Usage", formatDomainKeyUsages(resp.Metadata.Usage))
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runKeyList(flags *cli.CommonFlags, limit int32, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.ListKeysDomain(ctx, limit, cursor)
	if err != nil {
		return &WrappedError{Msg: "failed to list keys", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Keys) == 0 {
			printer.PrintInfo("No keys found")
			return nil
		}

		table := cli.NewTableData("Key ID", "Version", "Algorithm", "Status", "Created At")
		for _, key := range resp.Keys {
			table.AddRow(
				key.KeyID,
				fmt.Sprintf("%d", key.Version),
				string(key.Algorithm),
				string(key.Status),
				formatKeyTimestamp(key.CreatedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", resp.TotalCount))
		if resp.HasMore {
			printer.PrintKeyValue("Next Cursor", resp.NextCursor)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runKeyDelete(flags *cli.CommonFlags, keyID string, pendingWindowDays int32, force bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.DeleteKeyDomain(ctx, keyID, pendingWindowDays, force)
	if err != nil {
		return &WrappedError{Msg: "failed to delete key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if force {
			printer.PrintSuccess(fmt.Sprintf("Key %s deleted permanently", resp.KeyID))
		} else {
			printer.PrintSuccess(fmt.Sprintf("Key %s scheduled for deletion", resp.KeyID))
			printer.PrintKeyValue("Deletion Date", formatKeyTimestamp(resp.DeletionDate))
		}
		printer.PrintKeyValue("Status", string(resp.KeyStatus))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runKeyRotate(flags *cli.CommonFlags, keyID string, retainOldVersion bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.RotateKeyDomain(ctx, keyID, retainOldVersion)
	if err != nil {
		return &WrappedError{Msg: "failed to rotate key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Key %s rotated successfully", resp.KeyID))
		fmt.Println()
		printer.PrintKeyValue("Key ID", resp.KeyID)
		printer.PrintKeyValue("Old Version", fmt.Sprintf("%d", resp.OldVersion))
		printer.PrintKeyValue("New Version", fmt.Sprintf("%d", resp.NewVersion))
		printer.PrintKeyValue("Rotated At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatDomainKeyUsages converts a slice of domain key usages to a comma-separated string
func formatDomainKeyUsages(usages []kmssvc.KeyUsage) string {
	if len(usages) == 0 {
		return "none"
	}
	strs := make([]string, 0, len(usages))
	for _, u := range usages {
		strs = append(strs, string(u))
	}
	return strings.Join(strs, ", ")
}

// formatKeyTimestamp formats a Unix timestamp for display
func formatKeyTimestamp(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return time.Unix(ts, 0).Format(time.RFC3339)
}
