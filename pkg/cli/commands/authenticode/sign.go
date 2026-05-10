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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
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
			return runSign(flags, keyPath, certPath, input, output)
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
func runSign(flags *cli.CommonFlags, keyPath, certPath, input, output string) error {
	logger := logging.DefaultLogger()
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	// Read private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return ErrReadKeyFailed{Path: keyPath, Reason: err.Error()}
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return ErrDecodeKeyFailed{Path: keyPath}
	}

	// Parse the private key (support both PKCS#1 and PKCS#8)
	var privateKey crypto.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else {
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return ErrParseKeyFailed{Reason: err.Error()}
	}

	// Read certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return ErrReadCertificateFailed{Path: certPath, Reason: err.Error()}
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return ErrDecodeCertificateFailed{Path: certPath}
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return ErrParseCertificateFailed{Reason: err.Error()}
	}

	// Create keystore backend for signing
	signingBackend := &cliSigningBackend{
		privateKey: privateKey,
		logger:     logger,
	}

	// Create authenticode signer
	signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
		KeyStore:      signingBackend,
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "cli-signing"},
		Certificate:   cert,
		Logger:        logger,
	})
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

// cliSigningBackend is a minimal Backend implementation for CLI signing
type cliSigningBackend struct {
	privateKey crypto.PrivateKey
	logger     *logging.Logger
}

func (b *cliSigningBackend) Type() xkmssdk.BackendType {
	return "cli-signing"
}

func (b *cliSigningBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     false,
		KeyRotation:    false,
	}
}

func (b *cliSigningBackend) Signer(attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if signer, ok := b.privateKey.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, ErrKeyNotSigner{}
}

func (b *cliSigningBackend) GenerateKey(attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrNotImplemented{Operation: "GenerateKey"}
}

func (b *cliSigningBackend) GetKey(attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return b.privateKey, nil
}

func (b *cliSigningBackend) DeleteKey(attrs *xkmssdk.KeyAttributes) error {
	return ErrNotImplemented{Operation: "DeleteKey"}
}

func (b *cliSigningBackend) ListKeys() ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *cliSigningBackend) Decrypter(attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrNotImplemented{Operation: "Decrypter"}
}

func (b *cliSigningBackend) RotateKey(attrs *xkmssdk.KeyAttributes) error {
	return ErrNotImplemented{Operation: "RotateKey"}
}

func (b *cliSigningBackend) Close() error {
	return nil
}
