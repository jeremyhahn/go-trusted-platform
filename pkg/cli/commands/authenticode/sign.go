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

package authenticode

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newSignCommand creates the sign subcommand for signing PE/COFF files
func newSignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var keyPath, certPath, input, output string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a PE/COFF file with Authenticode",
		Long: `Sign a PE/COFF executable (EFI binary, Windows executable) using
Authenticode/PKCS#7 signing for UEFI Secure Boot compatibility.

This command replaces sbsigntool with native Go implementation.

Examples:
  # Sign an EFI binary
  platformctl authenticode sign \
    --key /path/to/key.pem \
    --cert /path/to/cert.pem \
    --input unsigned.efi \
    --output signed.efi

  # Sign a Windows executable
  platformctl authenticode sign \
    --key signing-key.pem \
    --cert signing-cert.pem \
    --input app.exe \
    --output app-signed.exe`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSign(cmd.Context(), flags, keyPath, certPath, input, output)
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "path to signing private key (PEM)")
	cmd.Flags().StringVar(&certPath, "cert", "", "path to signing certificate (PEM)")
	cmd.Flags().StringVar(&input, "input", "", "path to input PE/COFF file")
	cmd.Flags().StringVar(&output, "output", "", "path to output signed file")

	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

// runSign executes the sign command
func runSign(ctx context.Context, flags *cli.CommonFlags, keyPath, certPath, input, output string) error {
	logger := logging.DefaultLogger()
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	privateKey, err := authenticode.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		return mapKeyFileError(keyPath, err)
	}
	cert, err := authenticode.LoadCertificate(certPath)
	if err != nil {
		return mapCertFileError(certPath, err)
	}
	signer, err := authenticode.NewCryptoSigner(ctx, privateKey.(crypto.Signer), cert, logger)
	if err != nil {
		return ErrCreateSignerFailed{Reason: err.Error()}
	}

	// Sign the file
	logger.Info("[AUTHENTICODE] Signing file", "input", input, "output", output)
	if err := signer.SignFile(input, output); err != nil {
		return ErrSignFileFailed{Input: input, Reason: err.Error()}
	}

	// Output result
	result := map[string]interface{}{
		"input":   input,
		"output":  output,
		"success": true,
		"message": "file signed successfully",
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printer.PrintSuccess(fmt.Sprintf("File signed successfully: %s", output))
		return nil
	}

	return printer.Print(result)
}

// mapKeyFileError keeps the command's own error types for the three
// stages a key load can fail at, now that the loading itself lives in
// pkg/authenticode.
func mapKeyFileError(path string, err error) error {
	var kerr *authenticode.KeyFileError
	if !errors.As(err, &kerr) {
		return ErrParseKeyFailed{Reason: err.Error()}
	}
	switch kerr.Stage {
	case authenticode.KeyFileRead:
		return ErrReadKeyFailed{Path: path, Reason: kerr.Err.Error()}
	case authenticode.KeyFileDecode:
		return ErrDecodeKeyFailed{Path: path}
	default:
		return ErrParseKeyFailed{Reason: kerr.Err.Error()}
	}
}

// mapCertFileError is mapKeyFileError for the certificate.
func mapCertFileError(path string, err error) error {
	var cerr *authenticode.CertFileError
	if !errors.As(err, &cerr) {
		return ErrParseCertificateFailed{Reason: err.Error()}
	}
	switch cerr.Stage {
	case authenticode.KeyFileRead:
		return ErrReadCertificateFailed{Path: path, Reason: cerr.Err.Error()}
	default:
		return ErrParseCertificateFailed{Reason: cerr.Err.Error()}
	}
}
