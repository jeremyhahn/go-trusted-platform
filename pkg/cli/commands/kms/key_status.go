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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// ErrUpdateKeyStatusFailed is returned when updating key status fails
type ErrUpdateKeyStatusFailed struct {
	KeyID string
	Err   error
}

func (e ErrUpdateKeyStatusFailed) Error() string {
	return fmt.Sprintf("failed to update status for key %s: %v", e.KeyID, e.Err)
}

func (e ErrUpdateKeyStatusFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidKeyStatus is returned when an invalid key status is specified
type ErrInvalidKeyStatus struct {
	Status string
}

func (e ErrInvalidKeyStatus) Error() string {
	return fmt.Sprintf("invalid key status: %s (valid values: enabled, disabled)", e.Status)
}

// keyStatusClient is the part of the platform KMS client that enables and
// disables keys.
type keyStatusClient interface {
	UpdateKeyStatus(ctx context.Context, keyID string, version uint64, status platformv1.KeyStatus) (*platformv1.UpdateKeyStatusResponse, error)
}

// keyStatusOutput is the result of `kms key status enable|disable`.
type keyStatusOutput struct {
	KeyID     string `json:"key_id" yaml:"key_id"`
	Version   uint64 `json:"version" yaml:"version"`
	Status    string `json:"status" yaml:"status"`
	UpdatedAt int64  `json:"updated_at" yaml:"updated_at"`
}

// newKeyStatusCommand creates the key status subcommand group
func newKeyStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Manage key status",
		Long: `Enable or disable a key or specific key version.

A disabled key cannot be used for cryptographic operations but can be
re-enabled later. Use this for temporary access control or key suspension.`,
	}

	cmd.AddCommand(newKeyStatusVerbCommand(getFlags, "enable", platformv1.KeyStatus_KEY_STATUS_ENABLED,
		"Enable a key or key version",
		`Enable a previously disabled key or key version.

Examples:
  platformctl kms key status enable my-key
  platformctl kms key status enable my-key --version 2`))
	cmd.AddCommand(newKeyStatusVerbCommand(getFlags, "disable", platformv1.KeyStatus_KEY_STATUS_DISABLED,
		"Disable a key or key version",
		`Disable a key or key version, preventing it from being used.

Examples:
  platformctl kms key status disable my-key
  platformctl kms key status disable my-key --version 1`))

	return cmd
}

// newKeyStatusVerbCommand creates `key status enable` or `key status disable`,
// which set the key, or one version of it, to status.
func newKeyStatusVerbCommand(getFlags func() *cli.CommonFlags, verb string, status platformv1.KeyStatus, short, long string) *cobra.Command {
	var version uint64

	cmd := &cobra.Command{
		Use:   verb + " <key-id>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyStatus(getFlags(), args[0], version, status)
		},
	}

	cmd.Flags().Uint64Var(&version, "version", 0, "specific key version (0 for all versions)")

	return cmd
}

// runKeyStatus sets a key's status through platformd's KMS service.
func runKeyStatus(flags *cli.CommonFlags, keyID string, version uint64, status platformv1.KeyStatus) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := kmssvc.NewClientFromGRPC(base.Client().KMS())
	out, err := updateKeyStatus(base.Context(), client, keyID, version, status)
	if err != nil {
		return err
	}
	return printKeyStatus(base.Printer(), flags.OutputFormat, out)
}

// updateKeyStatus sets the status of a key, or of one version when version
// is not 0.
func updateKeyStatus(ctx context.Context, client keyStatusClient, keyID string, version uint64, status platformv1.KeyStatus) (*keyStatusOutput, error) {
	resp, err := client.UpdateKeyStatus(ctx, keyID, version, status)
	if err != nil {
		return nil, ErrUpdateKeyStatusFailed{KeyID: keyID, Err: err}
	}
	return &keyStatusOutput{
		KeyID:     resp.GetKeyId(),
		Version:   resp.GetVersion(),
		Status:    resp.GetKeyStatus().String(),
		UpdatedAt: resp.GetTimestamp(),
	}, nil
}

// printKeyStatus prints the result of a status change in the selected format.
func printKeyStatus(printer *cli.Printer, format cli.OutputFormat, out *keyStatusOutput) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(out)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Key %s is now %s", out.KeyID, out.Status))
		printer.PrintKeyValue("Key ID", out.KeyID)
		printer.PrintKeyValue("Version", fmt.Sprintf("%d", out.Version))
		printer.PrintKeyValue("Status", out.Status)
		printer.PrintKeyValue("Updated At", formatKeyTimestamp(out.UpdatedAt))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}
