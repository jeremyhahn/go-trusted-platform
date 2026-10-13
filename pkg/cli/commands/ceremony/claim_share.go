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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// claimShareBeginFlags holds the flag values for "ceremony claim-share begin".
type claimShareBeginFlags struct {
	username string
}

// claimShareCompleteFlags holds the flag values for
// "ceremony claim-share complete".
type claimShareCompleteFlags struct {
	username  string
	nonce     string
	signature string
}

// newClaimShareCommand creates the "ceremony claim-share" subcommand tree.
func newClaimShareCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim-share",
		Short: "Begin or complete an officer share-claim ceremony",
		Long: `Retrieve the officer's Shamir secret share via a challenge handshake.

"begin" issues a nonce the officer must sign with the private key matching
their claimed certificate; "complete" submits the signature and returns the
share. The share is returned only once; the officer is responsible for
storing it securely. A lost share must be regenerated via rekey.`,
	}

	cmd.AddCommand(newClaimShareBeginCommand(getFlags))
	cmd.AddCommand(newClaimShareCompleteCommand(getFlags))

	return cmd
}

// newClaimShareBeginCommand creates the "ceremony claim-share begin" subcommand.
func newClaimShareBeginCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &claimShareBeginFlags{}

	cmd := &cobra.Command{
		Use:   "begin",
		Short: "Begin an officer share-claim ceremony",
		Long: `Request a share-claim challenge nonce. Sign the nonce with the private
key matching the officer's claimed certificate, then submit it via
"claim-share complete".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimShareBegin(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")

	return cmd
}

// runClaimShareBegin dispatches "ceremony claim-share begin" to the SDK.
func runClaimShareBegin(commonFlags *cli.CommonFlags, f *claimShareBeginFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := NewService(base.Client())
	if err != nil {
		return err
	}

	req := &ceremonysvc.ClaimShareBeginRequest{Username: f.username}

	resp, err := client.ClaimShareBegin(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}

// newClaimShareCompleteCommand creates the "ceremony claim-share complete"
// subcommand.
func newClaimShareCompleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &claimShareCompleteFlags{}

	cmd := &cobra.Command{
		Use:   "complete",
		Short: "Complete an officer share-claim ceremony",
		Long: `Submit the officer's signature over the "begin" nonce. On success the
server returns the officer's Shamir share.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimShareComplete(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")
	cmd.Flags().StringVar(&f.nonce, "nonce", "", "nonce returned from \"claim-share begin\"")
	cmd.Flags().StringVar(&f.signature, "signature", "", "officer signature over the nonce (base64)")

	return cmd
}

// runClaimShareComplete dispatches "ceremony claim-share complete" to the SDK.
func runClaimShareComplete(commonFlags *cli.CommonFlags, f *claimShareCompleteFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}
	if f.nonce == "" {
		return ErrNonceRequired{}
	}
	if f.signature == "" {
		return ErrSignatureRequired{}
	}

	signature, err := base64.StdEncoding.DecodeString(f.signature)
	if err != nil {
		return ErrSignatureDecode{Cause: err}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := NewService(base.Client())
	if err != nil {
		return err
	}

	req := &ceremonysvc.ClaimShareCompleteRequest{
		Username:  f.username,
		Nonce:     f.nonce,
		Signature: signature,
	}

	resp, err := client.ClaimShareComplete(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}
