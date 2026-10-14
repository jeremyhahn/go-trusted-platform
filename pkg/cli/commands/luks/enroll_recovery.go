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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// enrollRecoveryFlags holds the flag values for "luks enroll-recovery".
type enrollRecoveryFlags struct {
	device             string
	existingPassphrase string
	output             string
}

// newEnrollRecoveryCommand creates the "luks enroll-recovery" subcommand.
func newEnrollRecoveryCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &enrollRecoveryFlags{}

	cmd := &cobra.Command{
		Use:   "enroll-recovery",
		Short: "Enroll a recovery-key keyslot",
		Long: `Generate a new recovery-key keyslot on a LUKS device. The recovery key
is only returned once and is written to the --output path with mode 0600;
store it offline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrollRecovery(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().StringVar(&f.existingPassphrase, "existing-passphrase", "", "existing passphrase")
	cmd.Flags().StringVar(&f.output, "output", "", "path to write the recovery key")

	return cmd
}

// runEnrollRecovery dispatches "luks enroll-recovery" to the SDK.
func runEnrollRecovery(commonFlags *cli.CommonFlags, f *enrollRecoveryFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.existingPassphrase == "" {
		return ErrExistingPassphraseRequired{}
	}
	if f.output == "" {
		return ErrOutputPathRequired{}
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
	resp, err := client.EnrollRecovery(base.Context(), &lukssvc.EnrollRecoveryRequest{
		Device:             device,
		ExistingPassphrase: f.existingPassphrase,
	})
	if err != nil {
		return err
	}

	if resp.RecoveryKey != "" {
		if err := os.WriteFile(f.output, []byte(resp.RecoveryKey), 0o600); err != nil {
			return ErrRecoveryKeyWrite{Path: f.output, Cause: err}
		}
	}

	return base.Output(resp)
}
