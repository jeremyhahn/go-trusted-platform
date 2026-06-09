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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newVerifyCommand creates the verify subcommand for verifying Authenticode signatures
func newVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var certPath, input string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an Authenticode signature on a PE/COFF file",
		Long: `Verify the Authenticode/PKCS#7 signature on a PE/COFF executable.
This includes cryptographic verification of the RSA/ECDSA signature.

This command replaces sbverify with native Go implementation.

Examples:
  # Verify a signed file (basic verification)
  platformctl authenticode verify --input signed.efi

  # Verify with specific certificate for trust verification
  platformctl authenticode verify \
    --cert /path/to/cert.pem \
    --input signed.efi

  # Verify and output as JSON
  platformctl authenticode verify --input signed.efi -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runVerify(cmd.Context(), flags, certPath, input)
		},
	}

	cmd.Flags().StringVar(&certPath, "cert", "", "path to signing certificate (PEM) for trust verification (optional)")
	cmd.Flags().StringVar(&input, "input", "", "path to signed PE/COFF file")

	_ = cmd.MarkFlagRequired("input")

	return cmd
}

// runVerify executes the verify command
func runVerify(ctx context.Context, flags *cli.CommonFlags, certPath, input string) error {
	logger := logging.DefaultLogger()
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	// Read certificate if provided (optional for basic verification)
	var cert *x509.Certificate
	if certPath != "" {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return ErrReadCertificateFailed{Path: certPath, Reason: err.Error()}
		}

		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return ErrDecodeCertificateFailed{Path: certPath}
		}

		var parseErr error
		cert, parseErr = x509.ParseCertificate(certBlock.Bytes)
		if parseErr != nil {
			return ErrParseCertificateFailed{Reason: parseErr.Error()}
		}
	}

	// Create a minimal backend for verification (no private key needed)
	verifyBackend := &cliVerifyBackend{
		logger: logger,
	}

	// Create authenticode signer (also used for verification)
	signer, err := authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      verifyBackend,
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "verify"},
		Certificate:   cert,
		Logger:        logger,
	})
	if err != nil {
		return ErrCreateSignerFailed{Reason: err.Error()}
	}

	// Verify the file
	logger.Info("[AUTHENTICODE] Verifying file", "input", input)
	if err := signer.VerifyFile(input); err != nil {
		return ErrVerifyFileFailed{Input: input, Reason: err.Error()}
	}

	// Output result
	result := map[string]interface{}{
		"input":    input,
		"verified": true,
		"message":  "signature verification OK",
	}

	if certPath != "" {
		result["certificate"] = certPath
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printer.PrintSuccess(fmt.Sprintf("Signature verification OK: %s", input))
		return nil
	}

	return printer.Print(result)
}

// cliVerifyBackend is a minimal Backend for verification (no signing needed)
type cliVerifyBackend struct {
	logger *logging.Logger
}

func (b *cliVerifyBackend) Type() xkmssdk.BackendType {
	return "verify"
}

func (b *cliVerifyBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{
		Keys:           false,
		HardwareBacked: false,
		Signing:        false,
		Decryption:     false,
		KeyRotation:    false,
	}
}

func (b *cliVerifyBackend) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	return nil, ErrNotImplemented{Operation: "Signer (verification only)"}
}

func (b *cliVerifyBackend) GenerateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrNotImplemented{Operation: "GenerateKey"}
}

func (b *cliVerifyBackend) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrNotImplemented{Operation: "GetKey"}
}

func (b *cliVerifyBackend) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return ErrNotImplemented{Operation: "DeleteKey"}
}

func (b *cliVerifyBackend) ListKeys(ctx context.Context) ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *cliVerifyBackend) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrNotImplemented{Operation: "Decrypter"}
}

func (b *cliVerifyBackend) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return ErrNotImplemented{Operation: "RotateKey"}
}

func (b *cliVerifyBackend) Close() error {
	return nil
}
