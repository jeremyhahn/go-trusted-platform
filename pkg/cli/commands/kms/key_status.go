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

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
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

// ErrKeyStatusFlagRequired is returned when `key status` is not given
// exactly one of --enable and --disable.
type ErrKeyStatusFlagRequired struct{}

func (e ErrKeyStatusFlagRequired) Error() string {
	return "exactly one of --enable or --disable is required"
}

// ErrInvalidKeyStatusVersion is returned when --version is negative.
type ErrInvalidKeyStatusVersion struct {
	Version int
}

func (e ErrInvalidKeyStatusVersion) Error() string {
	return fmt.Sprintf("invalid key version %d: must be 0 (all versions) or a positive version number", e.Version)
}

// keyStatusOutput is the printed result of `key status`.
type keyStatusOutput struct {
	KeyID   string `json:"key_id" yaml:"key_id"`
	Version int    `json:"version,omitempty" yaml:"version,omitempty"`
	Status  string `json:"status" yaml:"status"`
}

// newKeyStatusCommand creates the key status command
func newKeyStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var enable, disable bool
	var version int

	cmd := &cobra.Command{
		Use:   "status <key-id>",
		Short: "Enable or disable a key or key version",
		Long: `Enable or disable a key or a specific key version.

A disabled key cannot be used for cryptographic operations but can be
re-enabled later. Use this for temporary access control or key suspension.
Exactly one of --enable and --disable is required.

Examples:
  platformctl kms key status my-key --disable
  platformctl kms key status my-key --enable --version 2`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := keyStatusFromFlags(enable, disable, version)
			if err != nil {
				return err
			}
			return runKeyStatus(getFlags(), args[0], version, status)
		},
	}

	cmd.Flags().BoolVar(&enable, "enable", false, "enable the key")
	cmd.Flags().BoolVar(&disable, "disable", false, "disable the key")
	cmd.Flags().IntVar(&version, "version", 0, "specific key version (0 for all versions)")

	return cmd
}

// keyStatusFromFlags validates the flags before any connection is made and
// returns the requested status.
func keyStatusFromFlags(enable, disable bool, version int) (kms.KeyStatus, error) {
	if enable == disable {
		return 0, ErrKeyStatusFlagRequired{}
	}
	if version < 0 {
		return 0, ErrInvalidKeyStatusVersion{Version: version}
	}
	if enable {
		return kms.KeyStatusEnabled, nil
	}
	return kms.KeyStatusDisabled, nil
}

// runKeyStatus connects to the KMS and updates the key status.
func runKeyStatus(flags *cli.CommonFlags, keyID string, version int, status kms.KeyStatus) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyStatus(base.Context(), client, base.Printer(), keyID, version, status)
}

// executeKeyStatus updates the key status and prints the status the KMS reports.
func executeKeyStatus(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID string, version int, status kms.KeyStatus) error {
	resp, err := client.UpdateKeyStatus(ctx, &kms.UpdateKeyStatusRequest{
		KeyID:   keyID,
		Version: version,
		Status:  status,
	})
	if err != nil {
		return ErrUpdateKeyStatusFailed{KeyID: keyID, Err: err}
	}

	return printer.Print(keyStatusOutput{
		KeyID:   resp.KeyID,
		Version: resp.Version,
		Status:  resp.Status.String(),
	})
}
