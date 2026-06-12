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

package bmc

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// Errors
// =============================================================================

// ErrFactoryFlagRequired is returned when --factory is not passed to cert restore.
// Only factory-cert restore is currently supported; this flag is required to make
// the intent explicit and guard against accidental invocation.
type ErrFactoryFlagRequired struct{}

// Error implements the error interface.
func (e ErrFactoryFlagRequired) Error() string {
	return "bmc: --factory is required (only factory certificate restore is supported)"
}

// =============================================================================
// SDK seam interface (injectable for unit tests)
// =============================================================================

// bmcRestorer is the minimal interface over the SDK client used by runCertRestore.
// Tests inject a stub; production code uses the real *bmcsvc.Client.
type bmcRestorer interface {
	// RestoreFactoryCert runs the BMC factory-certificate restore ceremony for profileID.
	RestoreFactoryCert(ctx context.Context, profileID uint64) (*bmcsvc.RestoreResult, error)
}

// =============================================================================
// Internal flag state
// =============================================================================

// certRestoreFlags holds parsed flag values for the cert restore subcommand.
type certRestoreFlags struct {
	profileID string
	factory   bool
}

// =============================================================================
// Command constructor
// =============================================================================

// newCertRestoreCommand creates the cert restore subcommand that runs the BMC
// factory-certificate restore ceremony for the device identified by --profile-id.
func newCertRestoreCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags certRestoreFlags

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore the BMC factory TLS certificate",
		Long: `Run the BMC factory-certificate restore ceremony for the device identified
by --profile-id.

The ceremony instructs the BMC to regenerate its default self-signed certificate
and cleans up platform-side trust state: the SPKI pin is deleted, the DANE TLSA
record is removed (if present), and the Device entity is updated to reflect the
restored state.

The --factory flag is required and must be explicit, as this is a destructive
operation that removes the platform-issued certificate from the BMC.

Examples:
  platformctl bmc cert restore --profile-id 7 --factory`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertRestore(cmd, &flags, getFlags, nil)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	cmd.Flags().BoolVar(&flags.factory, "factory", false, "restore the factory default certificate (required)")

	return cmd
}

// =============================================================================
// Core run logic (SDK seam injected via restorer parameter)
// =============================================================================

// runCertRestore is the testable core of the cert restore subcommand. When
// client is nil the real SDK client is constructed from the daemon connection.
func runCertRestore(
	cmd *cobra.Command,
	flags *certRestoreFlags,
	getFlags func() *cli.CommonFlags,
	client bmcRestorer,
) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if !flags.factory {
		return ErrFactoryFlagRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	var restorer bmcRestorer
	if client != nil {
		restorer = client
	} else {
		commonFlags := getFlags()
		base, initErr := cli.NewBaseCommand(commonFlags)
		if initErr != nil {
			return initErr
		}
		defer base.Close()

		grpcClient := base.Client().BMC()
		if grpcClient == nil {
			return ErrBMCClientNotInitialized{}
		}
		restorer = bmcsvc.NewClientFromGRPC(grpcClient)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	result, err := restorer.RestoreFactoryCert(ctx, profileID)
	if err != nil {
		return err
	}

	return finishCertRestore(getFlags, result)
}

// =============================================================================
// Output helpers
// =============================================================================

// finishCertRestore prints the restore result in the requested output format.
func finishCertRestore(getFlags func() *cli.CommonFlags, result *bmcsvc.RestoreResult) error {
	done, emitErr := emitJSON(getFlags, result)
	if emitErr != nil || done {
		return emitErr
	}

	printRestoreSummary(result)
	return nil
}

// printRestoreSummary renders the human-readable restore result summary to stdout.
func printRestoreSummary(result *bmcsvc.RestoreResult) {
	fmt.Fprintf(os.Stdout, "Device ID:  %d\n", result.DeviceID)
	fmt.Fprintf(os.Stdout, "Endpoint:   %s\n", result.Endpoint)
	fmt.Fprintf(os.Stdout, "Hostname:   %s\n", result.Hostname)

	if result.NewCertMeta.Subject != "" {
		fmt.Fprintf(os.Stdout, "New Cert Subject: %s\n", result.NewCertMeta.Subject)
	}
	if result.NewCertMeta.SPKISHA256 != "" {
		fmt.Fprintf(os.Stdout, "New Cert SPKI:    %s\n", result.NewCertMeta.SPKISHA256)
	}

	if len(result.Steps) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nCeremony Steps:")
	for _, step := range result.Steps {
		mark := "✓"
		if !step.OK {
			mark = "✗"
		}
		if step.Detail != "" {
			fmt.Fprintf(os.Stdout, "  %s %-20s %s\n", mark, step.Name, step.Detail)
		} else {
			fmt.Fprintf(os.Stdout, "  %s %s\n", mark, step.Name)
		}
	}
}
