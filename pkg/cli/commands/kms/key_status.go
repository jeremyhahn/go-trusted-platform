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
	"math"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

// ErrKeyVersionOutOfRange is returned when --version exceeds the largest
// version the quicbaas KMS client can carry.
type ErrKeyVersionOutOfRange struct {
	Version uint64
}

func (e ErrKeyVersionOutOfRange) Error() string {
	return fmt.Sprintf("key version %d is out of range (maximum %d)", e.Version, math.MaxInt)
}

// keyStatusClient is the part of the quicbaas KMS client that enables and
// disables keys.
type keyStatusClient interface {
	UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error)
}

// keyStatusOutput is the result of `kms key status enable|disable`.
type keyStatusOutput struct {
	KeyID   string `json:"key_id" yaml:"key_id"`
	Version uint64 `json:"version" yaml:"version"`
	Status  string `json:"status" yaml:"status"`
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

	cmd.AddCommand(newKeyStatusVerbCommand(getFlags, "enable", kms.KeyStatusEnabled,
		"Enable a key or key version",
		`Enable a previously disabled key or key version.

Examples:
  platformctl kms key status enable my-key
  platformctl kms key status enable my-key --version 2`))
	cmd.AddCommand(newKeyStatusVerbCommand(getFlags, "disable", kms.KeyStatusDisabled,
		"Disable a key or key version",
		`Disable a key or key version, preventing it from being used.

Examples:
  platformctl kms key status disable my-key
  platformctl kms key status disable my-key --version 1`))

	return cmd
}

// newKeyStatusVerbCommand creates `key status enable` or `key status disable`,
// which set the key, or one version of it, to status.
func newKeyStatusVerbCommand(getFlags func() *cli.CommonFlags, verb string, status kms.KeyStatus, short, long string) *cobra.Command {
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
func runKeyStatus(flags *cli.CommonFlags, keyID string, version uint64, status kms.KeyStatus) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	out, err := updateKeyStatus(base.Context(), client, keyID, version, status)
	if err != nil {
		return err
	}
	return printKeyStatus(base.Printer(), flags.OutputFormat, out)
}

// updateKeyStatus sets the status of a key, or of one version when version
// is not 0.
func updateKeyStatus(ctx context.Context, client keyStatusClient, keyID string, version uint64, status kms.KeyStatus) (*keyStatusOutput, error) {
	if version > math.MaxInt {
		return nil, ErrKeyVersionOutOfRange{Version: version}
	}
	resp, err := client.UpdateKeyStatus(ctx, &kms.UpdateKeyStatusRequest{
		KeyID:   keyID,
		Version: int(version),
		Status:  status,
	})
	if err != nil {
		return nil, ErrUpdateKeyStatusFailed{KeyID: keyID, Err: err}
	}
	return &keyStatusOutput{
		KeyID:   resp.KeyID,
		Version: uint64(max(resp.Version, 0)),
		Status:  resp.Status.String(),
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
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}
