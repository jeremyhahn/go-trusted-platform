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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// updateFlags are the device fields `device update` can change. An empty
// flag keeps the stored value; hashAlgoSet records whether --hash-algo was
// given, since zero is not a usable "unset" for it.
type updateFlags struct {
	model       string
	ekCert      string
	attestPub   string
	attestCert  string
	signingPub  string
	hashAlgo    uint32
	hashAlgoSet bool
}

// changes reports whether any flag names a field to change.
func (uf *updateFlags) changes() bool {
	return uf.model != "" || uf.ekCert != "" || uf.attestPub != "" ||
		uf.attestCert != "" || uf.signingPub != "" || uf.hashAlgoSet
}

func newUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var uf updateFlags

	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a registered device",
		Long: `Update the fields of a registered device.

The command reads the device, changes only the fields whose flags are given,
and stores it; every other field keeps its value. The serial number is the
device's identity and cannot be changed. A lifecycle state is changed with
'device disable' and 'device enable', not here.

Examples:
  platformctl device update 1234567890 --model r650
  platformctl device update 1234567890 --ek-cert /var/lib/platform/ek.pem --hash-algo 11`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			uf.hashAlgoSet = cmd.Flags().Changed("hash-algo")
			return runUpdate(getFlags(), args[0], &uf)
		},
	}

	cmd.Flags().StringVar(&uf.model, "model", "", "device model")
	cmd.Flags().StringVar(&uf.ekCert, "ek-cert", "", "TPM EK certificate: a PEM file path or inline PEM")
	cmd.Flags().StringVar(&uf.attestPub, "attest-pub", "", "attestation public key")
	cmd.Flags().StringVar(&uf.attestCert, "attest-cert", "", "PEM attestation (IAK/AK) certificate")
	cmd.Flags().StringVar(&uf.signingPub, "signing-pub", "", "signing public key")
	cmd.Flags().Uint32Var(&uf.hashAlgo, "hash-algo", 0, "TPM hash algorithm ID (e.g. 11 for SHA-256)")

	return cmd
}

// runUpdate validates the arguments before it connects, so a bad id or an
// empty change set never reaches the control plane.
func runUpdate(flags *cli.CommonFlags, idStr string, uf *updateFlags) error {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return ErrInvalidDeviceID{ID: idStr}
	}
	if !uf.changes() {
		return ErrDeviceUpdateNoChanges{ID: id}
	}
	ekCert, err := resolveEKCertPEM(uf.ekCert)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	return updateAndPrint(base.Context(), deviceClient, base.Printer(), flags.OutputFormat, id, uf, ekCert)
}

// updateAndPrint reads device id, applies the flags, stores it and prints
// the device the control plane returned, in the shape `device get` prints.
func updateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, id uint64, uf *updateFlags, ekCertPEM string) error {
	current, err := client.Get(ctx, id)
	if err != nil {
		return ErrGetDeviceFailed{ID: id, Reason: err.Error()}
	}
	if current == nil {
		return ErrDeviceNotFound{ID: id}
	}
	applyUpdateFlags(current, uf, ekCertPEM)

	updated, err := client.Update(ctx, current)
	if err != nil {
		return ErrDeviceUpdateFailed{ID: id, Cause: err}
	}

	detail := toDeviceDetail(updated)
	if format == cli.OutputFormatTable {
		printDeviceDetails(printer, detail)
		return nil
	}
	return printer.Print(buildGetOutput(detail))
}

// applyUpdateFlags sets each field whose flag was given and leaves the rest.
func applyUpdateFlags(d *platformv1.Device, uf *updateFlags, ekCertPEM string) {
	if uf.model != "" {
		d.Model = uf.model
	}
	if ekCertPEM != "" {
		d.EkCert = ekCertPEM
	}
	if uf.attestPub != "" {
		d.AttestPub = uf.attestPub
	}
	if uf.attestCert != "" {
		d.AttestCert = uf.attestCert
	}
	if uf.signingPub != "" {
		d.SigningPub = uf.signingPub
	}
	if uf.hashAlgoSet {
		d.HashAlgoId = uf.hashAlgo
	}
}
