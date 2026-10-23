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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// validAlgorithms defines the supported device key algorithms
var validAlgorithms = []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072"}

// NewIDevIDCommand creates the idevid command group for IDevID key management
func NewIDevIDCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "idevid",
		Short: "Manage IDevID (Initial Device Identifier) keys",
		Long: `Manage IDevID keys in the TPM per TCG specifications.

IDevID is the Initial Device Identifier, a cryptographic key pair
provisioned by the device manufacturer during production. It provides
a hardware-bound device identity for authentication and secure enrollment.

Supported operations:
  - generate: Create a new IDevID key in the TPM
  - info: Retrieve information about the existing IDevID key
  - delete: Refused; the IDevID key is TPM-resident and is not evicted

Examples:
  # Generate IDevID with default algorithm (ECDSA-P256)
  platformctl tpm idevid generate

  # Generate IDevID with specific algorithm
  platformctl tpm idevid generate --algorithm RSA-2048

  # Overwrite existing IDevID key
  platformctl tpm idevid generate --algorithm ECDSA-P384 --overwrite

  # Get IDevID key information
  platformctl tpm idevid info

  # Get IDevID info as JSON (for scripting)
  platformctl tpm idevid info -o json`,
	}

	cmd.AddCommand(newIDevIDGenerateCommand(getFlags))
	cmd.AddCommand(newIDevIDInfoCommand(getFlags))
	cmd.AddCommand(newIDevIDDeleteCommand(getFlags))
	cmd.AddCommand(newIDevIDCSRCommand(getFlags))
	cmd.AddCommand(newIDevIDInstallCommand(getFlags))
	cmd.AddCommand(newIDevIDCertCommand(getFlags))
	cmd.AddCommand(NewLDevIDCommand(getFlags))

	return cmd
}

// newIDevIDGenerateCommand creates the generate subcommand
func newIDevIDGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var algorithm string
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new IDevID key in the TPM",
		Long: `Generate a new IDevID (Initial Device Identifier) key in the TPM.

Supported algorithms:
  - ECDSA-P256 (default, recommended by TCG)
  - ECDSA-P384
  - RSA-2048
  - RSA-3072`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDGenerate(flags, algorithm, overwrite)
		},
	}

	cmd.Flags().StringVar(&algorithm, "algorithm", "ECDSA-P256",
		"key algorithm: ECDSA-P256, ECDSA-P384, RSA-2048, RSA-3072")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false,
		"overwrite existing IDevID key if present")

	return cmd
}

// newIDevIDInfoCommand creates the info subcommand
func newIDevIDInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Get IDevID key information",
		Long:  "Retrieve information about the IDevID key in the TPM.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDInfo(flags)
		},
	}
}

// newIDevIDDeleteCommand creates the delete subcommand
func newIDevIDDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete the IDevID key (refused: the key is not evicted)",
		Long: `Ask the daemon to delete the IDevID key.

The daemon refuses on every transport until the owner rules on eviction:
the key is TPM-resident and is not evicted, and nothing is changed. The
command exits non-zero with the refusal.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDDelete(flags)
		},
	}
}

// runIDevIDGenerate executes the IDevID generate command
func runIDevIDGenerate(flags *cli.CommonFlags, algorithm string, overwrite bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDGenerateWithClient(&baseCommandAdapter{base: base}, algorithm, overwrite)
}

// runIDevIDInfo executes the IDevID info command
func runIDevIDInfo(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDInfoWithClient(&baseCommandAdapter{base: base})
}

// runIDevIDDelete executes the IDevID delete command
func runIDevIDDelete(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDDeleteWithClient(&baseCommandAdapter{base: base})
}

// parseAlgorithm converts a string algorithm name to the SDK domain algorithm value
func parseAlgorithm(algorithm string) (idevidsvc.DeviceKeyAlgorithm, error) {
	normalized := strings.ToUpper(strings.TrimSpace(algorithm))

	switch normalized {
	case "ECDSA-P256", "ECDSAP256", "EC-P256", "P256":
		return idevidsvc.AlgorithmECDSAP256, nil
	case "ECDSA-P384", "ECDSAP384", "EC-P384", "P384":
		return idevidsvc.AlgorithmECDSAP384, nil
	case "RSA-2048", "RSA2048":
		return idevidsvc.AlgorithmRSA2048, nil
	case "RSA-3072", "RSA3072":
		return idevidsvc.AlgorithmRSA3072, nil
	default:
		return idevidsvc.AlgorithmUnspecified,
			ErrInvalidAlgorithm{Algorithm: algorithm, Valid: validAlgorithms}
	}
}

// buildGenerateKeyOutput creates the JSON output structure for generate commands
func buildGenerateKeyOutput(info *idevidsvc.DeviceKeyInfo, algorithm string) map[string]interface{} {
	output := map[string]interface{}{
		"algorithm": algorithm,
	}

	if info != nil {
		output["public_key_pem"] = info.PublicKeyPEM
		output["handle"] = fmt.Sprintf("0x%08X", info.Handle)
		if info.CreatedAt > 0 {
			output["created_at"] = info.CreatedAt
		}
	}

	return output
}

// buildKeyInfoOutput creates the JSON output structure for key info
func buildKeyInfoOutput(info *idevidsvc.DeviceKeyInfo) map[string]interface{} {
	output := map[string]interface{}{
		"public_key_pem": info.PublicKeyPEM,
		"algorithm":      string(info.Algorithm),
		"handle":         fmt.Sprintf("0x%08X", info.Handle),
		"exists":         true,
	}

	if info.CreatedAt > 0 {
		output["created_at"] = info.CreatedAt
	}

	output["has_certificate"] = info.HasCertificate

	if info.CertInfo != nil {
		certInfo := map[string]interface{}{
			"subject_cn":          info.CertInfo.SubjectCN,
			"issuer_cn":           info.CertInfo.IssuerCN,
			"serial_number":       info.CertInfo.SerialNumber,
			"fingerprint":         info.CertInfo.Fingerprint,
			"key_algorithm":       info.CertInfo.KeyAlgorithm,
			"signature_algorithm": info.CertInfo.SignatureAlgorithm,
			"key_size":            info.CertInfo.KeySize,
		}
		if info.CertInfo.IssuedAt > 0 {
			certInfo["issued_at"] = info.CertInfo.IssuedAt
		}
		if info.CertInfo.ExpiresAt > 0 {
			certInfo["expires_at"] = info.CertInfo.ExpiresAt
		}
		output["certificate_info"] = certInfo
	}

	return output
}

// printKeyInfoDetails prints key information in table format
func printKeyInfoDetails(printer *cli.Printer, info *idevidsvc.DeviceKeyInfo, keyType string) {
	printer.PrintKeyValue("Key Type", keyType)
	printer.PrintKeyValue("Handle", fmt.Sprintf("0x%08X", info.Handle))
	printer.PrintKeyValue("Algorithm", string(info.Algorithm))

	if info.CreatedAt > 0 {
		printer.PrintKeyValue("Created At", formatTimestampSeconds(info.CreatedAt))
	}

	printer.PrintKeyValue("Has Certificate", formatBool(info.HasCertificate))

	if info.PublicKeyPEM != "" {
		fmt.Println()
		printer.PrintKeyValue("Public Key (PEM)", "")
		fmt.Print(info.PublicKeyPEM)
	}

	if info.CertInfo != nil {
		fmt.Println()
		printer.PrintKeyValue("Certificate", "")
		printer.PrintKeyValue("  Subject CN", info.CertInfo.SubjectCN)
		printer.PrintKeyValue("  Issuer CN", info.CertInfo.IssuerCN)
		printer.PrintKeyValue("  Serial Number", info.CertInfo.SerialNumber)
		printer.PrintKeyValue("  Fingerprint", info.CertInfo.Fingerprint)
		if info.CertInfo.IssuedAt > 0 {
			printer.PrintKeyValue("  Issued At", formatTimestampSeconds(info.CertInfo.IssuedAt))
		}
		if info.CertInfo.ExpiresAt > 0 {
			printer.PrintKeyValue("  Expires At", formatTimestampSeconds(info.CertInfo.ExpiresAt))
		}
	}
}

// =============================================================================
// IDevID CSR Command
// =============================================================================

func newIDevIDCSRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var commonName, organization, country, state, locality, orgUnit string

	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Create a Certificate Signing Request for the IDevID key",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDCSR(flags, commonName, organization, country, state, locality, orgUnit)
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "subject common name (required)")
	cmd.Flags().StringVar(&organization, "organization", "", "subject organization")
	cmd.Flags().StringVar(&country, "country", "", "subject country code (2 letters)")
	cmd.Flags().StringVar(&state, "state", "", "subject state or province")
	cmd.Flags().StringVar(&locality, "locality", "", "subject city or locality")
	cmd.Flags().StringVar(&orgUnit, "organizational-unit", "", "subject organizational unit")

	return cmd
}

func runIDevIDCSR(flags *cli.CommonFlags, cn, org, country, state, locality, orgUnit string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDCSRWithClient(&baseCommandAdapter{base: base}, cn, org, country, state, locality, orgUnit)
}

// =============================================================================
// IDevID Install Command
// =============================================================================

func newIDevIDInstallCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var certFile string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install a certificate for the IDevID key",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDInstall(flags, certFile)
		},
	}

	cmd.Flags().StringVar(&certFile, "cert-file", "", "path to certificate file (PEM format)")
	cli.MarkFlagsRequired(cmd, "cert-file")

	return cmd
}

func runIDevIDInstall(flags *cli.CommonFlags, certFile string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDInstallWithClient(&baseCommandAdapter{base: base}, certFile)
}

// =============================================================================
// IDevID Cert Command
// =============================================================================

func newIDevIDCertCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	// Canonical name is "certificate" to match EK/IAK; "cert" kept as
	// a hidden alias for muscle memory.
	return &cobra.Command{
		Use:     "certificate",
		Aliases: []string{"cert"},
		Short:   "Get the IDevID certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDCert(flags)
		},
	}
}

func runIDevIDCert(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runIDevIDCertWithClient(&baseCommandAdapter{base: base})
}

// =============================================================================
// Helper Functions
// =============================================================================

// buildCertificateOutput creates the JSON output structure for certificate retrieval
func buildCertificateOutput(cert *idevidsvc.DeviceIdentityCertificate) map[string]interface{} {
	output := map[string]interface{}{
		"certificate_pem": cert.PEM,
		"subject":         cert.SubjectCN,
		"issuer":          cert.IssuerCN,
		"serial_number":   cert.SerialNumber,
	}

	if cert.IssuedAt > 0 {
		output["not_before"] = cert.IssuedAt
	}
	if cert.ExpiresAt > 0 {
		output["not_after"] = cert.ExpiresAt
	}

	return output
}

// printCertificateDetails prints certificate information in table format
func printCertificateDetails(printer *cli.Printer, cert *idevidsvc.DeviceIdentityCertificate, keyType string) {
	printer.PrintKeyValue("Key Type", keyType)
	printer.PrintKeyValue("Subject CN", cert.SubjectCN)
	printer.PrintKeyValue("Issuer CN", cert.IssuerCN)
	printer.PrintKeyValue("Serial Number", cert.SerialNumber)
	printer.PrintKeyValue("Fingerprint", cert.Fingerprint)
	printer.PrintKeyValue("Key Algorithm", cert.KeyAlgorithm)
	printer.PrintKeyValue("Signature Algorithm", cert.SignatureAlgorithm)

	if cert.IssuedAt > 0 {
		printer.PrintKeyValue("Issued At", formatTimestampSeconds(cert.IssuedAt))
	}
	if cert.ExpiresAt > 0 {
		printer.PrintKeyValue("Expires At", formatTimestampSeconds(cert.ExpiresAt))
	}

	fmt.Println()
	printer.PrintKeyValue("Certificate (PEM)", "")
	fmt.Print(cert.PEM)
}

// readFile reads the contents of a file
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
