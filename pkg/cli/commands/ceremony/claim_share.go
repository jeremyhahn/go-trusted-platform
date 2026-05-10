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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// claimShareFlags holds the flag values for "ceremony claim-share".
type claimShareFlags struct {
	username string
}

// newClaimShareCommand creates the "ceremony claim-share" subcommand.
func newClaimShareCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &claimShareFlags{}

	cmd := &cobra.Command{
		Use:   "claim-share",
		Short: "Claim the officer's Shamir share",
		Long: `Retrieve the officer's Shamir secret share.

The share is returned only once; the officer is responsible for storing it
securely. A lost share must be regenerated via rekey.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimShare(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")

	return cmd
}

// runClaimShare dispatches "ceremony claim-share" to the SDK.
func runClaimShare(commonFlags *cli.CommonFlags, f *claimShareFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := ceremonysvc.NewClient()

	req := &ceremonysvc.ClaimShareRequest{Username: f.username}

	resp, err := client.ClaimShare(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}
