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

// roles maps CLI --role values to SDK enum values.
var roles = map[string]fido2svc.Role{
	"":      fido2svc.RoleUnspecified,
	"so":    fido2svc.RoleSO,
	"admin": fido2svc.RoleAdmin,
	"user":  fido2svc.RoleUser,
}

// registerFlags holds the flag values for "fido2 register".
type registerFlags struct {
	username   string
	role       string
	requirePIN bool
	requireUV  bool
	rpID       string
}

// newRegisterCommand creates the "fido2 register" subcommand.
func newRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &registerFlags{}

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a WebAuthn credential",
		Long: `Register a new WebAuthn credential for a user.

The credential can optionally be bound to a ceremony role (so, admin, user)
and require PIN / user verification at registration time.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegister(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "username to register the credential to")
	cmd.Flags().StringVar(&f.role, "role", "", "ceremony role (so, admin, user); optional")
	cmd.Flags().BoolVar(&f.requirePIN, "require-pin", false, "require authenticator PIN")
	cmd.Flags().BoolVar(&f.requireUV, "require-uv", false, "require user verification (biometric / PIN)")
	cmd.Flags().StringVar(&f.rpID, "rp-id", "", "relying party id override")

	return cmd
}

// runRegister dispatches "fido2 register" to the SDK.
func runRegister(commonFlags *cli.CommonFlags, f *registerFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}
	role, ok := roles[f.role]
	if !ok {
		return ErrInvalidRole{Value: f.role}
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
	resp, err := client.Register(base.Context(), &fido2svc.RegisterRequest{
		Username:   f.username,
		Role:       role,
		RequirePIN: f.requirePIN,
		RequireUV:  f.requireUV,
		RPID:       f.rpID,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
