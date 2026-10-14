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

// enrollPassphraseFlags holds the flag values for "luks enroll-passphrase".
type enrollPassphraseFlags struct {
	device             string
	existingPassphrase string
	newPassphrase      string
}

// newEnrollPassphraseCommand creates the "luks enroll-passphrase" subcommand.
func newEnrollPassphraseCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &enrollPassphraseFlags{}

	cmd := &cobra.Command{
		Use:   "enroll-passphrase",
		Short: "Enroll a passphrase keyslot",
		Long:  `Add a new passphrase keyslot to a LUKS device using an existing passphrase.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrollPassphrase(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().StringVar(&f.existingPassphrase, "existing-passphrase", "", "existing passphrase")
	cmd.Flags().StringVar(&f.newPassphrase, "new-passphrase", "", "new passphrase to enroll")

	return cmd
}

// runEnrollPassphrase dispatches "luks enroll-passphrase" to the SDK.
func runEnrollPassphrase(commonFlags *cli.CommonFlags, f *enrollPassphraseFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.existingPassphrase == "" {
		return ErrExistingPassphraseRequired{}
	}
	if f.newPassphrase == "" {
		return ErrNewPassphraseRequired{}
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
	resp, err := client.EnrollPassphrase(base.Context(), &lukssvc.EnrollPassphraseRequest{
		Device:             device,
		ExistingPassphrase: f.existingPassphrase,
		NewPassphrase:      f.newPassphrase,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
