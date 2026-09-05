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

package device

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// assignFlags holds the flags for the profile assign subcommand.
type assignFlags struct {
	deviceID string
	ekSerial string
	mac      string
	ekCert   string
}

// newProfileAssignCommand creates the profile assign subcommand.
func newProfileAssignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var af assignFlags

	cmd := &cobra.Command{
		Use:   "assign <profile-id>",
		Short: "Assign a device profile to a device",
		Long: `Bind a device profile to a specific device identity.

The binding sets the profile's TPM EK certificate serial and/or MAC
address, optionally prestages the device's PEM-encoded EK certificate,
and marks the profile assigned. The EK certificate is source-agnostic:
it may come from a swtpm-backed vTPM or a physical hardware TPM.

The device identity can be supplied two ways:

  --device <id>   bind to an already-registered device: the control
                  plane derives the EK serial from the device's stored
                  EK certificate and prestages that certificate (the
                  device must carry one unless --ek-serial or --mac is
                  also given)
  --ek-serial / --mac / --ek-cert
                  supply the identity explicitly (--ek-cert accepts a
                  PEM file path or an inline PEM string)

Explicit flags override values derived from --device. At least one of
the EK serial or MAC address must resolve to a non-empty value.

Examples:
  # Bind a profile to a registered device's EK
  platformctl device profile assign 123 --device 42

  # Bind a profile to a hardware TPM EK explicitly
  platformctl device profile assign 123 \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /path/to/ek-cert.pem`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileID, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidProfileID{ID: args[0]}
			}
			return runProfileAssign(getFlags(), profileID, &af)
		},
	}

	cmd.Flags().StringVar(&af.deviceID, "device", "", "registered device ID to bind to; the control plane derives the EK identity from its stored EK certificate")
	cmd.Flags().StringVar(&af.ekSerial, "ek-serial", "", "TPM EK certificate serial number identifying the device")
	cmd.Flags().StringVar(&af.mac, "mac", "", "exact MAC address identifying the device")
	cmd.Flags().StringVar(&af.ekCert, "ek-cert", "", "prestaged TPM EK certificate: path to a PEM file or an inline PEM string")

	return cmd
}

// newProfileUnassignCommand creates the profile unassign subcommand.
func newProfileUnassignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unassign <profile-id>",
		Short: "Clear a device profile's device binding",
		Long: `Clear a device profile's device binding.

The profile's EK serial, MAC address, prestaged EK certificate, and
assignment state are all reset so the profile returns to the
unassigned pool.

Example:
  platformctl device profile unassign 123`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileID, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidProfileID{ID: args[0]}
			}
			return runProfileUnassign(getFlags(), profileID)
		},
	}

	return cmd
}

// runProfileAssign binds the profile via the SDK device service. With
// --device the daemon derives the EK serial and the prestaged certificate
// from the device's stored EK certificate itself; the CLI never parses a
// certificate. Explicit flags travel alongside and win on the server.
func runProfileAssign(flags *cli.CommonFlags, profileID uint64, af *assignFlags) error {
	// Fail fast before connecting: without --device there must be an
	// explicit identity to bind.
	if af.deviceID == "" && af.ekSerial == "" && af.mac == "" {
		return ErrAssignIdentityRequired{}
	}
	var deviceID uint64
	if af.deviceID != "" {
		parsed, err := strconv.ParseUint(af.deviceID, 10, 64)
		if err != nil || parsed == 0 {
			return ErrInvalidDeviceID{ID: af.deviceID}
		}
		deviceID = parsed
	}

	ekCertPEM, err := resolveEKCertPEM(af.ekCert)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	profile, err := deviceClient.AssignProfileToRegisteredDevice(base.Context(), profileID, deviceID, af.ekSerial, af.mac, ekCertPEM)
	if err != nil {
		return ErrProfileAssignFailed{ID: profileID, Cause: err}
	}

	return outputProfile(base, flags, profile)
}

// runProfileUnassign clears the profile's device binding via the SDK
// device service.
func runProfileUnassign(flags *cli.CommonFlags, profileID uint64) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	profile, err := deviceClient.UnassignProfile(base.Context(), profileID)
	if err != nil {
		return ErrProfileUnassignFailed{ID: profileID, Cause: err}
	}

	return outputProfile(base, flags, profile)
}
