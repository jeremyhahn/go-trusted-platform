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

package tpm

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// certifyOptions holds the options for the certify command. Handle and
// Nonce are the raw flag values; they are parsed when the command runs.
type certifyOptions struct {
	Handle   string
	Password string
	Nonce    string
}

// newCertifyCommand creates the certify command
func newCertifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &certifyOptions{}

	cmd := &cobra.Command{
		Use:   "certify",
		Short: "Certify a persistent key with the attestation key",
		Long: `Asks the daemon's TPM to certify a persistent key (TPM2_Certify).

The TPM signs a TPMS_ATTEST structure naming the key with the attestation
key, so a verifier holding the attestation key's public half can prove the
key lives in this TPM. The optional nonce is a hex string of at most 64
bytes; it is echoed inside the signed structure as qualifying data.

The key handle must be persistent (0x81000000-0x81FFFFFF).

Byte fields in the output are hex encoded.

Examples:
  # Certify the key at a persistent handle
  platformctl tpm certify --handle 0x81000001

  # Certify with a verifier nonce and the key's password
  platformctl tpm certify --handle 0x81000001 --nonce 0011aabb --password secret -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertify(getFlags(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Handle, "handle", "", "persistent key handle (hex 0x... or decimal)")
	cmd.Flags().StringVar(&opts.Password, "password", "", "authorization password of the key")
	cmd.Flags().StringVar(&opts.Nonce, "nonce", "", "verifier nonce as hex (at most 64 bytes)")

	_ = cmd.MarkFlagRequired("handle")

	return cmd
}

// runCertify executes the certify command
func runCertify(flags *cli.CommonFlags, opts *certifyOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runCertifyWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runCertifyWithClient runs certify with a testable interface
func runCertifyWithClient(base TPMBaseCommandInterface, opts *certifyOptions) error {
	defer base.Close()

	handle, err := parseTPMHandle(opts.Handle)
	if err != nil {
		return err
	}
	nonce, err := hex.DecodeString(opts.Nonce)
	if err != nil {
		return ErrInvalidCertifyNonce{Nonce: opts.Nonce}
	}

	sdkClient := tpmsvc.NewClientFromGRPC(base.TPMClient())
	resp, err := sdkClient.Certify(base.Context(), handle, opts.Password, nonce)
	if err != nil {
		return ErrCertifyFailed{Handle: handle, Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]string{
		"key_handle":           fmt.Sprintf("0x%08X", handle),
		"certify_info":         hex.EncodeToString(resp.GetCertifyInfo()),
		"signature":            hex.EncodeToString(resp.GetSignature()),
		"signature_algorithm":  resp.GetSignatureAlgorithm(),
		"attesting_key_public": hex.EncodeToString(resp.GetAttestingKeyPublic()),
		"attested_key_public":  hex.EncodeToString(resp.GetAttestedKeyPublic()),
		"nonce":                hex.EncodeToString(resp.GetNonce()),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Key Handle", output["key_handle"])
		printer.PrintKeyValue("Signature Algorithm", resp.GetSignatureAlgorithm())
		printer.PrintKeyValue("Certify Info", output["certify_info"])
		printer.PrintKeyValue("Signature", output["signature"])
		printer.PrintKeyValue("Attesting Key", output["attesting_key_public"])
		printer.PrintKeyValue("Attested Key", output["attested_key_public"])
		printer.PrintKeyValue("Nonce", output["nonce"])
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
