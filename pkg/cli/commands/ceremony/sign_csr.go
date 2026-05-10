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

package ceremony

import (
	"encoding/base64"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// officerRoles maps CLI strings to SDK enum values.
var officerRoles = map[string]ceremonysvc.OfficerRole{
	"so":    ceremonysvc.RoleSO,
	"admin": ceremonysvc.RoleAdmin,
	"user":  ceremonysvc.RoleUser,
}

// signCSRFlags holds the flag values for "ceremony sign-csr".
type signCSRFlags struct {
	username string
	soPIN    string
	csrFile  string
	role     string
}

// newSignCSRCommand creates the "ceremony sign-csr" subcommand.
func newSignCSRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &signCSRFlags{}

	cmd := &cobra.Command{
		Use:   "sign-csr",
		Short: "Sign a CSR with the ceremony CA",
		Long: `Submit a CSR to the ceremony CA for signing by the Security Officer.

The CSR is read from --csr-file (PEM) and base64-encoded for transport. The
signed certificate and intermediate chain are returned in the response.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSignCSR(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")
	cmd.Flags().StringVar(&f.soPIN, "so-pin", "", "Security Officer PIN")
	cmd.Flags().StringVar(&f.csrFile, "csr-file", "", "path to the PEM CSR file")
	cmd.Flags().StringVar(&f.role, "role", "", "target role (so, admin, user)")

	return cmd
}

// runSignCSR dispatches "ceremony sign-csr" to the SDK.
func runSignCSR(commonFlags *cli.CommonFlags, f *signCSRFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}
	if f.soPIN == "" {
		return ErrSOPinRequired{}
	}
	if f.csrFile == "" {
		return ErrCSRFileRequired{}
	}

	role, ok := officerRoles[f.role]
	if !ok {
		return ErrInvalidRole{Value: f.role}
	}

	csrBytes, err := os.ReadFile(f.csrFile)
	if err != nil {
		return ErrCSRFileRead{Path: f.csrFile, Cause: err}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := ceremonysvc.NewClient()

	req := &ceremonysvc.SignCSRRequest{
		Username: f.username,
		SOPIN:    f.soPIN,
		CSRPEM:   base64.StdEncoding.EncodeToString(csrBytes),
		Role:     role,
	}

	resp, err := client.SignCSR(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}
