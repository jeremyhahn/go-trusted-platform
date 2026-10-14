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

package luks

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// enrollTPMFlags holds the flag values for "luks enroll-tpm".
type enrollTPMFlags struct {
	device             string
	existingPassphrase string
	pcrs               []int32
}

// newEnrollTPMCommand creates the "luks enroll-tpm" subcommand.
func newEnrollTPMCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &enrollTPMFlags{}

	cmd := &cobra.Command{
		Use:   "enroll-tpm",
		Short: "Enroll a TPM2-sealed keyslot",
		Long: `Add a TPM2-sealed keyslot to a LUKS device. The passphrase is sealed under
the Platform SRK and bound to the platform PCR policy; --pcrs applies only
when platformd seals under the Shared SRK for systemd-cryptsetup.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrollTPM(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().StringVar(&f.existingPassphrase, "existing-passphrase", "", "existing passphrase")
	cmd.Flags().Int32SliceVar(&f.pcrs, "pcrs", nil, "PCR indices to bind to (comma-separated)")

	return cmd
}

// runEnrollTPM dispatches "luks enroll-tpm" to the SDK.
func runEnrollTPM(commonFlags *cli.CommonFlags, f *enrollTPMFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.existingPassphrase == "" {
		return ErrExistingPassphraseRequired{}
	}
	device, err := resolveDevice(f.device)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := newService(base.Client())
	if err != nil {
		return err
	}
	resp, err := client.EnrollTPM(base.Context(), &lukssvc.EnrollTPMRequest{
		Device:             device,
		ExistingPassphrase: f.existingPassphrase,
		PCRs:               f.pcrs,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
