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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	"github.com/spf13/cobra"
)

// registerFlags holds the flags for the device register command.
type registerFlags struct {
	serial     string
	model      string
	ekCert     string
	attestPub  string
	attestCert string
	signingPub string
	hashAlgo   uint32
}

// deviceCreator is the SDK device client call register needs.
type deviceCreator interface {
	Create(ctx context.Context, d *platformv1.Device) (*platformv1.Device, error)
}

// newRegisterCommand creates the register subcommand, which records a device
// on the control plane through the SDK's CreateDevice call.
func newRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var rf registerFlags

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a device with the control plane",
		Long: `Register a device with the platform control plane.

The register command creates a device record from its serial number and,
optionally, its TPM identity material, and prints the device the control
plane stored. It connects through the selected platformctl context, like
every other device command.

Device profiles are a separate resource: create one with
'platformctl device profile create'.

Examples:
  # Register a device by serial number
  platformctl device register --serial SN-0001 --model r640

  # Register with its EK certificate (a file path or inline PEM)
  platformctl device register \
    --serial SN-0002 \
    --model r640 \
    --ek-cert /var/lib/platform/ek.pem \
    --hash-algo 11`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegister(getFlags(), &rf)
		},
	}

	cmd.Flags().StringVar(&rf.serial, "serial", "", "device serial number (required)")
	cmd.Flags().StringVar(&rf.model, "model", "", "device model")
	cmd.Flags().StringVar(&rf.ekCert, "ek-cert", "", "TPM EK certificate: a PEM file path or inline PEM")
	cmd.Flags().StringVar(&rf.attestPub, "attest-pub", "", "attestation public key")
	cmd.Flags().StringVar(&rf.attestCert, "attest-cert", "", "PEM attestation (IAK/AK) certificate")
	cmd.Flags().StringVar(&rf.signingPub, "signing-pub", "", "signing public key")
	cmd.Flags().Uint32Var(&rf.hashAlgo, "hash-algo", 0, "TPM hash algorithm ID (e.g. 11 for SHA-256)")

	return cmd
}

// runRegister validates the flags, connects through the selected context and
// registers the device.
func runRegister(flags *cli.CommonFlags, rf *registerFlags) error {
	request, err := buildRegisterDevice(rf)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	return registerAndPrint(base.Context(), deviceClient, base.Printer(), flags.OutputFormat, request)
}

// registerAndPrint registers the device and prints the record the control
// plane stored in the requested output format.
func registerAndPrint(ctx context.Context, client deviceCreator, printer *cli.Printer, format cli.OutputFormat, request *platformv1.Device) error {
	created, err := registerDevice(ctx, client, request)
	if err != nil {
		return err
	}

	detail := toDeviceDetail(created)
	if format == cli.OutputFormatTable {
		printDeviceDetails(printer, detail)
		return nil
	}
	return printer.Print(buildGetOutput(detail))
}

// buildRegisterDevice validates the register flags and builds the device to
// create. The EK certificate is resolved from a file path or inline PEM and
// must parse as an X.509 certificate.
func buildRegisterDevice(rf *registerFlags) (*platformv1.Device, error) {
	if rf.serial == "" {
		return nil, ErrRegisterSerialRequired{}
	}

	ekCert, err := resolveEKCertPEM(rf.ekCert)
	if err != nil {
		return nil, err
	}

	return &platformv1.Device{
		Serial:     rf.serial,
		Model:      rf.model,
		EkCert:     ekCert,
		AttestPub:  rf.attestPub,
		AttestCert: rf.attestCert,
		SigningPub: rf.signingPub,
		HashAlgoId: rf.hashAlgo,
	}, nil
}

// registerDevice creates the device through the SDK and returns the record
// the control plane stored.
func registerDevice(ctx context.Context, client deviceCreator, request *platformv1.Device) (*platformv1.Device, error) {
	created, err := client.Create(ctx, request)
	if err != nil {
		return nil, ErrRegisterCreateDeviceFailed{Serial: request.Serial, Cause: err}
	}
	if created == nil {
		return nil, ErrRegisterEmptyResponse{Serial: request.Serial}
	}
	return created, nil
}
