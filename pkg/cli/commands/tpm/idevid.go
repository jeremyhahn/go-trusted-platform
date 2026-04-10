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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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
  - delete: Remove the IDevID key from the TPM

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
  platformctl tpm idevid info -o json

  # Delete IDevID key
  platformctl tpm idevid delete`,
	}

	cmd.AddCommand(newIDevIDGenerateCommand(getFlags))
	cmd.AddCommand(newIDevIDInfoCommand(getFlags))
	cmd.AddCommand(newIDevIDDeleteCommand(getFlags))
	cmd.AddCommand(newIDevIDCSRCommand(getFlags))
	cmd.AddCommand(newIDevIDInstallCommand(getFlags))
	cmd.AddCommand(newIDevIDCertCommand(getFlags))

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

The IDevID key is created in the TPM's endorsement hierarchy and
persisted at the standard TCG handle. The key can be used for
device authentication and certificate enrollment.

Supported algorithms:
  - ECDSA-P256 (default, recommended by TCG)
  - ECDSA-P384
  - RSA-2048
  - RSA-3072

Examples:
  # Generate with default algorithm
  platformctl tpm idevid generate

  # Generate with specific algorithm
  platformctl tpm idevid generate --algorithm RSA-2048

  # Overwrite existing key
  platformctl tpm idevid generate --overwrite`,
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
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Get IDevID key information",
		Long: `Retrieve information about the IDevID key in the TPM.

Returns details including:
  - TPM handle
  - Key algorithm
  - Public key (PEM encoded)
  - Creation timestamp
  - Certificate status (if installed)

Examples:
  # Get IDevID info in table format
  platformctl tpm idevid info

  # Get IDevID info as JSON
  platformctl tpm idevid info -o json

  # Get IDevID info as YAML
  platformctl tpm idevid info -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDInfo(flags)
		},
	}

	return cmd
}

// newIDevIDDeleteCommand creates the delete subcommand
func newIDevIDDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete the IDevID key from the TPM",
		Long: `Delete the IDevID key from the TPM.

WARNING: This operation is irreversible. Once deleted, the IDevID
key cannot be recovered. Any certificates issued for this key
will become invalid.

Examples:
  # Delete IDevID key
  platformctl tpm idevid delete`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDDelete(flags)
		},
	}

	return cmd
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

// parseAlgorithm converts a string algorithm name to the proto enum value
func parseAlgorithm(algorithm string) (platformv1.DeviceKeyAlgorithm, error) {
	normalized := strings.ToUpper(strings.TrimSpace(algorithm))

	switch normalized {
	case "ECDSA-P256", "ECDSAP256", "EC-P256", "P256":
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256, nil
	case "ECDSA-P384", "ECDSAP384", "EC-P384", "P384":
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384, nil
	case "RSA-2048", "RSA2048":
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048, nil
	case "RSA-3072", "RSA3072":
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072, nil
	default:
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED,
			ErrInvalidAlgorithm{Algorithm: algorithm, Valid: validAlgorithms}
	}
}

// algorithmToString converts a proto enum value to a human-readable string
func algorithmToString(alg platformv1.DeviceKeyAlgorithm) string {
	switch alg {
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256:
		return "ECDSA-P256"
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384:
		return "ECDSA-P384"
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048:
		return "RSA-2048"
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072:
		return "RSA-3072"
	default:
		return "UNSPECIFIED"
	}
}

// buildGenerateKeyOutput creates the JSON output structure for generate commands
// This format is compatible with test adapter expectations
func buildGenerateKeyOutput(info *platformv1.DeviceKeyInfo, algorithm string) map[string]interface{} {
	output := map[string]interface{}{
		"algorithm": algorithm,
	}

	if info != nil {
		output["public_key_pem"] = string(info.PublicKeyPem)
		output["handle"] = fmt.Sprintf("0x%08X", info.Handle)
		if info.CreatedAt != nil {
			output["created_at"] = info.CreatedAt.Seconds
		}
	}

	return output
}

// buildKeyInfoOutput creates the JSON output structure for key info
// This format is compatible with test adapter expectations
func buildKeyInfoOutput(info *platformv1.DeviceKeyInfo) map[string]interface{} {
	output := map[string]interface{}{
		"public_key_pem": string(info.PublicKeyPem),
		"algorithm":      algorithmToString(info.Algorithm),
		"handle":         fmt.Sprintf("0x%08X", info.Handle),
		"exists":         true, // If we have info, key exists
	}

	if info.CreatedAt != nil {
		output["created_at"] = info.CreatedAt.Seconds
	}

	output["has_certificate"] = info.HasCertificate

	if info.CertificateInfo != nil {
		certInfo := map[string]interface{}{
			"subject_cn":          info.CertificateInfo.SubjectCn,
			"issuer_cn":           info.CertificateInfo.IssuerCn,
			"serial_number":       info.CertificateInfo.SerialNumber,
			"fingerprint":         info.CertificateInfo.Fingerprint,
			"key_algorithm":       info.CertificateInfo.KeyAlgorithm,
			"signature_algorithm": info.CertificateInfo.SignatureAlgorithm,
			"key_size":            info.CertificateInfo.KeySize,
		}
		if info.CertificateInfo.IssuedAt != nil {
			certInfo["issued_at"] = info.CertificateInfo.IssuedAt.Seconds
		}
		if info.CertificateInfo.ExpiresAt != nil {
			certInfo["expires_at"] = info.CertificateInfo.ExpiresAt.Seconds
		}
		output["certificate_info"] = certInfo
	}

	return output
}

// printStatusDetails prints status information in table format
func printStatusDetails(printer *cli.Printer, status *platformv1.Status, algorithm string) {
	printer.PrintKeyValue("Algorithm", algorithm)
	if status != nil {
		printer.PrintKeyValue("Success", formatBool(status.Success))
		if status.Message != "" {
			printer.PrintKeyValue("Message", status.Message)
		}
	}
}

// printKeyInfoDetails prints key information in table format
func printKeyInfoDetails(printer *cli.Printer, info *platformv1.DeviceKeyInfo, keyType string) {
	printer.PrintKeyValue("Key Type", keyType)
	printer.PrintKeyValue("Handle", fmt.Sprintf("0x%08X", info.Handle))
	printer.PrintKeyValue("Algorithm", algorithmToString(info.Algorithm))

	if info.CreatedAt != nil {
		printer.PrintKeyValue("Created At", formatTimestamp(info.CreatedAt))
	}

	printer.PrintKeyValue("Has Certificate", formatBool(info.HasCertificate))

	if len(info.PublicKeyPem) > 0 {
		fmt.Println()
		printer.PrintKeyValue("Public Key (PEM)", "")
		fmt.Print(string(info.PublicKeyPem))
	}

	if info.CertificateInfo != nil {
		fmt.Println()
		printer.PrintKeyValue("Certificate", "")
		printer.PrintKeyValue("  Subject CN", info.CertificateInfo.SubjectCn)
		printer.PrintKeyValue("  Issuer CN", info.CertificateInfo.IssuerCn)
		printer.PrintKeyValue("  Serial Number", info.CertificateInfo.SerialNumber)
		printer.PrintKeyValue("  Fingerprint", info.CertificateInfo.Fingerprint)
		if info.CertificateInfo.IssuedAt != nil {
			printer.PrintKeyValue("  Issued At", formatTimestamp(info.CertificateInfo.IssuedAt))
		}
		if info.CertificateInfo.ExpiresAt != nil {
			printer.PrintKeyValue("  Expires At", formatTimestamp(info.CertificateInfo.ExpiresAt))
		}
	}
}

// =============================================================================
// IDevID CSR Command
// =============================================================================

// newIDevIDCSRCommand creates the csr subcommand for creating CSRs
func newIDevIDCSRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var commonName, organization, country, state, locality, orgUnit string

	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Create a Certificate Signing Request for the IDevID key",
		Long: `Create a Certificate Signing Request (CSR) for the IDevID key.

The CSR can be submitted to a Certificate Authority (CA) to obtain
a certificate for the IDevID key.

Examples:
  # Create CSR with full subject
  platformctl tpm idevid csr \
    --common-name device.example.com \
    --organization "Example Corp" \
    --country US \
    --state California \
    --locality "San Francisco"

  # Create CSR with minimal subject
  platformctl tpm idevid csr --common-name my-device

  # Output as JSON
  platformctl tpm idevid csr --common-name my-device -o json`,
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

// runIDevIDCSR executes the IDevID CSR command
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

// newIDevIDInstallCommand creates the install subcommand for installing certificates
func newIDevIDInstallCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var certFile string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install a certificate for the IDevID key",
		Long: `Install a certificate for the IDevID key.

The certificate must be in PEM format and must correspond to the
existing IDevID key in the TPM.

Examples:
  # Install certificate from file
  platformctl tpm idevid install --cert-file /path/to/cert.pem

  # Install and verify
  platformctl tpm idevid install --cert-file cert.pem && platformctl tpm idevid info`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDInstall(flags, certFile)
		},
	}

	cmd.Flags().StringVar(&certFile, "cert-file", "", "path to certificate file (PEM format)")
	_ = cmd.MarkFlagRequired("cert-file")

	return cmd
}

// runIDevIDInstall executes the IDevID install command
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

// newIDevIDCertCommand creates the cert subcommand for retrieving certificates
func newIDevIDCertCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Get the IDevID certificate",
		Long: `Retrieve the installed IDevID certificate.

Returns the certificate in PEM format along with metadata including
subject, issuer, validity period, and serial number.

Examples:
  # Get certificate in table format
  platformctl tpm idevid cert

  # Get certificate as JSON (for scripting)
  platformctl tpm idevid cert -o json

  # Save certificate to file
  platformctl tpm idevid cert -o json | jq -r '.certificate_pem' > cert.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIDevIDCert(flags)
		},
	}

	return cmd
}

// runIDevIDCert executes the IDevID cert command
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
func buildCertificateOutput(cert *platformv1.DeviceIdentityCertificate) map[string]interface{} {
	output := map[string]interface{}{
		"certificate_pem": string(cert.Pem),
		"subject":         cert.SubjectCn,
		"issuer":          cert.IssuerCn,
		"serial_number":   cert.SerialNumber,
	}

	if cert.IssuedAt != nil {
		output["not_before"] = cert.IssuedAt.Seconds
	}
	if cert.ExpiresAt != nil {
		output["not_after"] = cert.ExpiresAt.Seconds
	}

	return output
}

// printCertificateDetails prints certificate information in table format
func printCertificateDetails(printer *cli.Printer, cert *platformv1.DeviceIdentityCertificate, keyType string) {
	printer.PrintKeyValue("Key Type", keyType)
	printer.PrintKeyValue("Subject CN", cert.SubjectCn)
	printer.PrintKeyValue("Issuer CN", cert.IssuerCn)
	printer.PrintKeyValue("Serial Number", cert.SerialNumber)
	printer.PrintKeyValue("Fingerprint", cert.Fingerprint)
	printer.PrintKeyValue("Key Algorithm", cert.KeyAlgorithm)
	printer.PrintKeyValue("Signature Algorithm", cert.SignatureAlgorithm)

	if cert.IssuedAt != nil {
		printer.PrintKeyValue("Issued At", formatTimestamp(cert.IssuedAt))
	}
	if cert.ExpiresAt != nil {
		printer.PrintKeyValue("Expires At", formatTimestamp(cert.ExpiresAt))
	}

	fmt.Println()
	printer.PrintKeyValue("Certificate (PEM)", "")
	fmt.Print(string(cert.Pem))
}

// readFile reads the contents of a file
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
