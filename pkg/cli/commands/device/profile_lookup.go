// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"strconv"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// NewProfileLookupCommands returns the get, list, delete and match verbs of
// `platformctl device profile`. The top-level `platformctl profile` group
// mounts these same commands, so both trees run one implementation.
func NewProfileLookupCommands(getFlags func() *cli.CommonFlags) []*cobra.Command {
	return []*cobra.Command{
		newProfileGetCommand(getFlags),
		newProfileListCommand(getFlags),
		newProfileDeleteCommand(getFlags),
		newProfileMatchCommand(getFlags),
		newProfileFindConfigCommand(getFlags),
	}
}

// isNotFound reports whether the control plane answered NotFound. Every SDK
// transport reports a missing profile with that gRPC status.
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// newProfileDeleteCommand creates the profile delete subcommand.
func newProfileDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a device profile",
		Long: `Delete a device profile from the control plane. A profile that does not
exist is an error.

Examples:
  platformctl device profile delete 123
  platformctl device profile delete 123 --output json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidProfileID{ID: args[0]}
			}
			return runProfileDelete(getFlags(), id)
		},
	}
}

// runProfileDelete deletes the profile via the SDK device service.
func runProfileDelete(flags *cli.CommonFlags, id uint64) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	if err := deviceClient.DeleteProfile(base.Context(), id); err != nil {
		if isNotFound(err) {
			return ErrProfileNotFound{ID: id}
		}
		return ErrProfileDeleteFailed{ID: id, Cause: err}
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		base.Printer().PrintSuccess("Profile " + strconv.FormatUint(id, 10) + " deleted")
		return nil
	}
	return base.Output(map[string]interface{}{
		"id":      strconv.FormatUint(id, 10),
		"deleted": true,
	})
}

// profileMatchOptions are the device attributes match looks a profile up by.
type profileMatchOptions struct {
	MACAddress string
	Serial     string
	Model      string
}

// newProfileMatchCommand creates the profile match subcommand.
func newProfileMatchCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts profileMatchOptions
	cmd := &cobra.Command{
		Use:   "match",
		Short: "Find the device profile that matches a device",
		Long: `Find the device profile whose match rules fit a device's MAC address,
serial number or model. MAC and serial match by prefix, model exactly, and a
profile matches when any one of its rules fits. At least one attribute is
required. No matching profile is an error.

Examples:
  platformctl device profile match --mac 00:25:90:ff:aa:02
  platformctl device profile match --serial SN100-XYZ --output json
  platformctl device profile match --model R640`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileMatch(getFlags(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.MACAddress, "mac", "", "device MAC address")
	cmd.Flags().StringVar(&opts.Serial, "serial", "", "device serial number")
	cmd.Flags().StringVar(&opts.Model, "model", "", "device model")
	return cmd
}

// runProfileMatch looks up the matching profile via the SDK device service
// and renders it.
func runProfileMatch(flags *cli.CommonFlags, opts profileMatchOptions) error {
	if opts.MACAddress == "" && opts.Serial == "" && opts.Model == "" {
		return ErrProfileMatchCriteriaRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	profile, err := deviceClient.FindMatchingProfile(base.Context(), opts.MACAddress, opts.Serial, opts.Model)
	if err != nil {
		if isNotFound(err) {
			return ErrNoMatchingProfile(opts)
		}
		return ErrProfileMatchFailed{Cause: err}
	}
	return outputProfile(base, flags, profile)
}

// profileFindConfigOptions holds the device identity find-config looks up.
type profileFindConfigOptions struct {
	EKSerial   string
	MACAddress string
}

// newProfileFindConfigCommand creates the profile find-config subcommand.
func newProfileFindConfigCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts profileFindConfigOptions
	cmd := &cobra.Command{
		Use:   "find-config",
		Short: "Find the device profile stored for a device's identity",
		Long: `Find the device profile stored for a device's EK serial or MAC address.
Unlike match, this compares the identity a profile was created for, not its
match rules. At least one of --ek-serial or --mac is required. No profile for
the identity is an error.

Examples:
  platformctl device profile find-config --ek-serial 0123456789ABCDEF
  platformctl device profile find-config --mac 52:54:00:aa:bb:01 --output json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileFindConfig(getFlags(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.EKSerial, "ek-serial", "", "device EK certificate serial")
	cmd.Flags().StringVar(&opts.MACAddress, "mac", "", "device MAC address")
	return cmd
}

// runProfileFindConfig looks up the profile stored for a device identity and
// renders it like profile get.
func runProfileFindConfig(flags *cli.CommonFlags, opts profileFindConfigOptions) error {
	if opts.EKSerial == "" && opts.MACAddress == "" {
		return ErrProfileConfigIdentityRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	profile, err := deviceClient.FindConfigForDevice(base.Context(), opts.EKSerial, opts.MACAddress)
	if err != nil {
		if isNotFound(err) {
			return ErrNoConfigForDevice(opts)
		}
		return ErrProfileFindConfigFailed{Cause: err}
	}
	return outputProfile(base, flags, profile)
}
