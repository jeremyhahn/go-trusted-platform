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

// authenticatorTypes maps CLI strings to SDK enum values. Using a map makes
// validation branchless and keeps parity with the SDK source of truth.
var authenticatorTypes = map[string]ceremonysvc.AuthenticatorType{
	"piv":      ceremonysvc.AuthenticatorPIV,
	"fido2":    ceremonysvc.AuthenticatorFIDO2,
	"software": ceremonysvc.AuthenticatorSoftware,
}

// claimCertBeginFlags holds the flag values for "ceremony claim-cert begin".
type claimCertBeginFlags struct {
	username          string
	authenticatorType string
	slot              string
	credentialID      string
}

// claimCertCompleteFlags holds the flag values for "ceremony claim-cert complete".
type claimCertCompleteFlags struct {
	username  string
	nonce     string
	signature string
}

// newClaimCertCommand creates the "ceremony claim-cert" subcommand tree.
func newClaimCertCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim-cert",
		Short: "Begin or complete an officer cert-claim ceremony",
		Long: `Drive the officer cert-claim challenge / response.

"begin" requests a server-issued nonce bound to the officer's authenticator.
"complete" submits the officer's signature over the nonce and returns the
issued officer certificate.`,
	}

	cmd.AddCommand(newClaimCertBeginCommand(getFlags))
	cmd.AddCommand(newClaimCertCompleteCommand(getFlags))

	return cmd
}

// newClaimCertBeginCommand creates the "ceremony claim-cert begin" subcommand.
func newClaimCertBeginCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &claimCertBeginFlags{}

	cmd := &cobra.Command{
		Use:   "begin",
		Short: "Begin an officer cert-claim ceremony",
		Long: `Start a cert-claim challenge. The server issues a nonce that the officer
must sign with their authenticator and submit back via "claim-cert complete".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimCertBegin(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")
	cmd.Flags().StringVar(&f.authenticatorType, "authenticator-type", "",
		"authenticator type (piv, fido2, software)")
	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id (required when authenticator-type is piv)")
	cmd.Flags().StringVar(&f.credentialID, "credential-id", "",
		"FIDO2 credential id (required when authenticator-type is fido2)")

	return cmd
}

// runClaimCertBegin dispatches "ceremony claim-cert begin" to the SDK.
func runClaimCertBegin(commonFlags *cli.CommonFlags, f *claimCertBeginFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}

	authType, ok := authenticatorTypes[f.authenticatorType]
	if !ok {
		return ErrInvalidAuthenticatorType{Value: f.authenticatorType}
	}

	switch authType {
	case ceremonysvc.AuthenticatorPIV:
		if f.slot == "" {
			return ErrAuthenticatorSelectorRequired{Type: "piv", Flag: "--slot"}
		}
	case ceremonysvc.AuthenticatorFIDO2:
		if f.credentialID == "" {
			return ErrAuthenticatorSelectorRequired{Type: "fido2", Flag: "--credential-id"}
		}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := ceremonysvc.NewClient()

	req := &ceremonysvc.ClaimCertBeginRequest{
		Username:          f.username,
		AuthenticatorType: authType,
		Slot:              f.slot,
		CredentialID:      f.credentialID,
	}

	resp, err := client.ClaimCertBegin(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}

// newClaimCertCompleteCommand creates the "ceremony claim-cert complete" subcommand.
func newClaimCertCompleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &claimCertCompleteFlags{}

	cmd := &cobra.Command{
		Use:   "complete",
		Short: "Complete an officer cert-claim ceremony",
		Long: `Submit the officer's signature over the "begin" nonce. On success the
server returns the issued officer certificate and intermediate chain.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimCertComplete(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.username, "username", "", "officer username")
	cmd.Flags().StringVar(&f.nonce, "nonce", "", "nonce returned from \"claim-cert begin\"")
	cmd.Flags().StringVar(&f.signature, "signature", "", "officer signature over the nonce (base64)")

	return cmd
}

// runClaimCertComplete dispatches "ceremony claim-cert complete" to the SDK.
func runClaimCertComplete(commonFlags *cli.CommonFlags, f *claimCertCompleteFlags) error {
	if f.username == "" {
		return ErrUsernameRequired{}
	}
	if f.nonce == "" {
		return ErrNonceRequired{}
	}
	if f.signature == "" {
		return ErrSignatureRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := ceremonysvc.NewClient()

	req := &ceremonysvc.ClaimCertCompleteRequest{
		Username:  f.username,
		Nonce:     f.nonce,
		Signature: f.signature,
	}

	resp, err := client.ClaimCertComplete(base.Context(), req)
	if err != nil {
		return err
	}

	return base.Output(resp)
}
