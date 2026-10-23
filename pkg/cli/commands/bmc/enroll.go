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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// Errors
// =============================================================================

// ErrBackupsDirCreateFailed is returned when the backup directory cannot be
// created during an enrollment backup write.
type ErrBackupsDirCreateFailed struct {
	// Path is the directory path that could not be created.
	Path string
	// Cause is the underlying OS error.
	Cause error
}

// Error implements the error interface.
func (e ErrBackupsDirCreateFailed) Error() string {
	return "bmc: failed to create backup directory " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e ErrBackupsDirCreateFailed) Unwrap() error { return e.Cause }

// ErrBackupFileWriteFailed is returned when a backup file cannot be written
// to disk during an enrollment backup write.
type ErrBackupFileWriteFailed struct {
	// Path is the file path that could not be written.
	Path string
	// Cause is the underlying OS error.
	Cause error
}

// Error implements the error interface.
func (e ErrBackupFileWriteFailed) Error() string {
	return "bmc: failed to write backup file " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e ErrBackupFileWriteFailed) Unwrap() error { return e.Cause }

// =============================================================================
// SDK seam interface (injectable for unit tests)
// =============================================================================

// bmcEnroller is the minimal interface over the SDK client used by runEnroll.
// Tests inject a stub; production code uses the real *bmcsvc.Client.
type bmcEnroller interface {
	// EnrollBMC runs the BMC enrollment ceremony for profileID.
	EnrollBMC(ctx context.Context, profileID uint64, opts *bmcsvc.EnrollOptions) (*bmcsvc.EnrollResult, error)
}

// =============================================================================
// Internal flag state
// =============================================================================

// enrollFlags holds parsed flag values for the enroll subcommand.
type enrollFlags struct {
	profileID          string
	backupsDir         string
	replaceCertificate bool
	rotatePassword     bool
	dnsRegister        bool
	danePublish        bool
}

// enrollJSONOutput is the JSON envelope emitted when --output json is requested.
type enrollJSONOutput struct {
	*bmcsvc.EnrollResult
	// BackupDir is the resolved backup directory path, or empty when skipped.
	BackupDir string `json:"backup_dir,omitempty"`
}

// =============================================================================
// Command constructor
// =============================================================================

// newEnrollCommand creates the enroll subcommand that runs the BMC enrollment
// ceremony for the device identified by --profile-id.
func newEnrollCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags enrollFlags

	// Per-command viper instance so PLATFORMCTL_BACKUPS_DIR binds without
	// polluting the global viper state used by other commands.
	v := viper.New()
	v.SetEnvPrefix("PLATFORMCTL")
	_ = v.BindEnv("backups_dir", "PLATFORMCTL_BACKUPS_DIR")

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a BMC device into the platform PKI",
		Long: `Run the BMC enrollment ceremony for the device identified by --profile-id.

The ceremony connects to the BMC, captures the factory TLS certificate, issues a
platform-signed replacement certificate from the Trust CA, optionally rotates the
BMC credentials, and optionally registers the device in platform DNS / DANE.

The four override flags --replace-certificate, --rotate-password, --dns-register,
and --dane-publish are tri-state: when passed they override the profile's stored
enrollment config; when omitted the profile defaults are used.

Set PLATFORMCTL_BACKUPS_DIR (or --backups-dir) to persist the factory certificate
and full enrollment result under <dir>/<hostname>/bmc/ with mode 0700/0600.

Examples:
  # Enroll using profile defaults
  platformctl bmc enroll --profile-id 7

  # Enroll with explicit overrides
  platformctl bmc enroll --profile-id 7 \
    --replace-certificate --rotate-password --dns-register

  # Enroll and save factory cert backup
  platformctl bmc enroll --profile-id 7 --backups-dir /var/lib/platform/backups`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Flag wins over env var.
			backupsDir := flags.backupsDir
			if backupsDir == "" {
				backupsDir = v.GetString("backups_dir")
			}
			return runEnroll(cmd, &flags, backupsDir, getFlags, nil)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	cmd.Flags().StringVar(&flags.backupsDir, "backups-dir", "", "directory to persist factory cert and enrollment result (overrides PLATFORMCTL_BACKUPS_DIR)")
	cmd.Flags().BoolVar(&flags.replaceCertificate, "replace-certificate", false, "override profile: replace the factory TLS certificate")
	cmd.Flags().BoolVar(&flags.rotatePassword, "rotate-password", false, "override profile: rotate BMC credentials")
	cmd.Flags().BoolVar(&flags.dnsRegister, "dns-register", false, "override profile: register hostname in platform DNS")
	cmd.Flags().BoolVar(&flags.danePublish, "dane-publish", false, "override profile: publish DANE TLSA record")

	if err := v.BindPFlag("backups_dir", cmd.Flags().Lookup("backups-dir")); err != nil {
		panic(cli.ErrFlagSetup{Command: cmd.Name(), Flag: "backups-dir", Err: err})
	}

	return cmd
}

// =============================================================================
// Core run logic (SDK seam injected via enroller parameter)
// =============================================================================

// runEnroll is the testable core of the enroll subcommand.  When client is nil
// the real SDK client is constructed from the daemon connection.
func runEnroll(
	cmd *cobra.Command,
	flags *enrollFlags,
	backupsDir string,
	getFlags func() *cli.CommonFlags,
	client bmcEnroller,
) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	opts := buildEnrollOptions(cmd, flags)

	var enroll bmcEnroller
	if client != nil {
		enroll = client
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
		enroll = bmcsvc.NewClientFromGRPC(grpcClient)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	result, err := enroll.EnrollBMC(ctx, profileID, opts)
	if err != nil {
		return err
	}

	return finishEnroll(getFlags, result, backupsDir)
}

// =============================================================================
// Option parsing
// =============================================================================

// buildEnrollOptions constructs a *bmcsvc.EnrollOptions from the parsed flags.
// Returns nil when no override flag was explicitly set so the server uses the
// profile's stored enrollment config defaults unchanged.
func buildEnrollOptions(cmd *cobra.Command, flags *enrollFlags) *bmcsvc.EnrollOptions {
	overrideNames := []string{"replace-certificate", "rotate-password", "dns-register", "dane-publish"}
	anyChanged := false
	for _, name := range overrideNames {
		if cmd.Flags().Changed(name) {
			anyChanged = true
			break
		}
	}
	if !anyChanged {
		return nil
	}

	opts := &bmcsvc.EnrollOptions{}
	if cmd.Flags().Changed("replace-certificate") {
		v := flags.replaceCertificate
		opts.ReplaceCertificate = &v
	}
	if cmd.Flags().Changed("rotate-password") {
		v := flags.rotatePassword
		opts.RotatePassword = &v
	}
	if cmd.Flags().Changed("dns-register") {
		v := flags.dnsRegister
		opts.DNSRegister = &v
	}
	if cmd.Flags().Changed("dane-publish") {
		v := flags.danePublish
		opts.DANEPublish = &v
	}
	return opts
}

// =============================================================================
// Output and backup helpers
// =============================================================================

// finishEnroll writes backup files when requested and prints the enrollment
// summary.  Separated from runEnroll so it can be tested without a gRPC call.
func finishEnroll(getFlags func() *cli.CommonFlags, result *bmcsvc.EnrollResult, backupsDir string) error {
	resolvedDir := ""

	if backupsDir != "" && result.FactoryCertPEM != "" {
		dir := filepath.Join(backupsDir, result.Hostname, "bmc")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ErrBackupsDirCreateFailed{Path: dir, Cause: err}
		}
		resolvedDir = dir

		if err := writeBackupFile(filepath.Join(dir, "factory-cert.pem"), []byte(result.FactoryCertPEM)); err != nil {
			return err
		}

		metaBytes, err := json.MarshalIndent(result.FactoryCertMeta, "", "  ")
		if err != nil {
			return ErrBackupFileWriteFailed{Path: filepath.Join(dir, "factory-cert.json"), Cause: err}
		}
		if err := writeBackupFile(filepath.Join(dir, "factory-cert.json"), metaBytes); err != nil {
			return err
		}

		enrollBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return ErrBackupFileWriteFailed{Path: filepath.Join(dir, "enrollment.json"), Cause: err}
		}
		if err := writeBackupFile(filepath.Join(dir, "enrollment.json"), enrollBytes); err != nil {
			return err
		}
	} else if backupsDir == "" {
		fmt.Fprintln(os.Stderr, "notice: --backups-dir not set; no client-side backup was written")
	}

	out := &enrollJSONOutput{EnrollResult: result, BackupDir: resolvedDir}
	done, emitErr := emitJSON(getFlags, out)
	if emitErr != nil || done {
		return emitErr
	}

	printEnrollSummary(result, resolvedDir)
	return nil
}

// writeBackupFile writes data to path with mode 0600.
func writeBackupFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return ErrBackupFileWriteFailed{Path: path, Cause: err}
	}
	return nil
}

// printEnrollSummary renders the human-readable enrollment result summary to
// stdout.
func printEnrollSummary(result *bmcsvc.EnrollResult, backupDir string) {
	fmt.Fprintf(os.Stdout, "Device ID: %d\n", result.DeviceID)
	fmt.Fprintf(os.Stdout, "Endpoint:  %s\n", result.Endpoint)
	fmt.Fprintf(os.Stdout, "Hostname:  %s\n", result.Hostname)
	if result.DNSName != "" {
		fmt.Fprintf(os.Stdout, "DNS Name:  %s\n", result.DNSName)
	}
	fmt.Fprintf(os.Stdout, "SPKI Pin:  %s\n", result.PinSPKISHA256)
	if backupDir != "" {
		fmt.Fprintf(os.Stdout, "Backup:    %s\n", backupDir)
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
