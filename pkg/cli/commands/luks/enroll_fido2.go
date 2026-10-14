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

// enrollFIDO2Flags holds the flag values for "luks enroll-fido2".
type enrollFIDO2Flags struct {
	device             string
	existingPassphrase string
	credentialID       string
	requirePIN         bool
	requireUV          bool
}

// newEnrollFIDO2Command creates the "luks enroll-fido2" subcommand. It
// replaces the legacy "platformctl fido2 enroll" command.
func newEnrollFIDO2Command(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &enrollFIDO2Flags{}

	cmd := &cobra.Command{
		Use:   "enroll-fido2",
		Short: "Enroll a FIDO2 keyslot",
		Long: `Add a FIDO2 keyslot to a LUKS device using the hmac-secret extension.

Replaces the legacy "platformctl fido2 enroll" command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrollFIDO2(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().StringVar(&f.existingPassphrase, "existing-passphrase", "", "existing passphrase")
	cmd.Flags().StringVar(&f.credentialID, "credential-id", "", "FIDO2 credential id")
	cmd.Flags().BoolVar(&f.requirePIN, "require-pin", false, "require PIN during the ceremony")
	cmd.Flags().BoolVar(&f.requireUV, "require-uv", false, "require user verification (biometric / PIN)")

	return cmd
}

// runEnrollFIDO2 dispatches "luks enroll-fido2" to the SDK.
func runEnrollFIDO2(commonFlags *cli.CommonFlags, f *enrollFIDO2Flags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.existingPassphrase == "" {
		return ErrExistingPassphraseRequired{}
	}
	if f.credentialID == "" {
		return ErrCredentialIDRequired{}
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
	resp, err := client.EnrollFIDO2(base.Context(), &lukssvc.EnrollFIDO2Request{
		Device:             device,
		ExistingPassphrase: f.existingPassphrase,
		CredentialID:       f.credentialID,
		RequirePIN:         f.requirePIN,
		RequireUV:          f.requireUV,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
