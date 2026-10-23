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

package fido2

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	fido2svc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// authenticateFlags holds the flag values for "fido2 authenticate".
type authenticateFlags struct {
	credentialID string
}

// newAuthenticateCommand creates the "fido2 authenticate" subcommand.
func newAuthenticateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &authenticateFlags{}

	cmd := &cobra.Command{
		Use:   "authenticate",
		Short: "Test authentication against a WebAuthn credential",
		Long:  `Perform an authentication ceremony against a previously registered WebAuthn credential. Useful to verify a credential still works without side effects.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthenticate(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.credentialID, "credential-id", "", "credential id printed by \"fido2 register\" (hex)")

	return cmd
}

// runAuthenticate dispatches "fido2 authenticate" to the SDK.
func runAuthenticate(commonFlags *cli.CommonFlags, f *authenticateFlags) error {
	if f.credentialID == "" {
		return ErrCredentialIDRequired{}
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
	resp, err := client.Authenticate(base.Context(), &fido2svc.AuthenticateRequest{CredentialID: f.credentialID})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
