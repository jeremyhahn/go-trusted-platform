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

package ca

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newIssueCommand creates the issue subcommand for certificate issuance
func newIssueCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		keySize     int
		validDays   int
		sansDNS     string
		sansIPs     string
		sansEmail   string
		keyUsage    string
		extKeyUsage string
	)

	cmd := &cobra.Command{
		Use:   "issue [cn] [store] [algorithm]",
		Short: "Issue a new x509 certificate",
		Long: `Issue a new x509 certificate from the Certificate Authority.

Arguments:
  cn        - Common Name for the certificate
  store     - Key store type (pkcs8, pkcs11, tpm)
  algorithm - Key algorithm (RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519)

Supported store types:
  - pkcs8  : Software-based key storage
  - pkcs11 : Hardware security module (HSM)
  - tpm    : Trusted Platform Module

Supported algorithms:
  - RSA-2048, RSA-3072, RSA-4096
  - ECDSA-P256, ECDSA-P384
  - Ed25519

Examples:
  # Issue certificate with ECDSA key
  platformctl ca issue example.com pkcs8 ECDSA-P256

  # Issue certificate with RSA key
  platformctl ca issue example.com pkcs8 RSA-2048

  # Issue certificate with Subject Alternative Names
  platformctl ca issue example.com pkcs8 ECDSA-P256 \
    --sans-dns "www.example.com,api.example.com" \
    --sans-ips "192.168.1.1,10.0.0.1"

  # Issue certificate to TPM
  platformctl ca issue device.example.com tpm ECDSA-P256`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIssue(flags, args[0], args[1], args[2], keySize, validDays,
				sansDNS, sansIPs, sansEmail, keyUsage, extKeyUsage)
		},
	}

	cmd.Flags().IntVar(&keySize, "key-size", 0, "RSA key size (2048, 3072, 4096)")
	cmd.Flags().IntVar(&validDays, "valid-days", 365, "Certificate validity period in days")
	cmd.Flags().StringVar(&sansDNS, "sans-dns", "", "Subject Alternative Names - DNS (comma-separated)")
	cmd.Flags().StringVar(&sansIPs, "sans-ips", "", "Subject Alternative Names - IPs (comma-separated)")
	cmd.Flags().StringVar(&sansEmail, "sans-email", "", "Subject Alternative Names - Email (comma-separated)")
	cmd.Flags().StringVar(&keyUsage, "key-usage", "", "Key usage (comma-separated): digitalSignature, keyEncipherment, etc.")
	cmd.Flags().StringVar(&extKeyUsage, "ext-key-usage", "", "Extended key usage (comma-separated): serverAuth, clientAuth, etc.")

	return cmd
}

// runIssue executes the certificate issue command
func runIssue(flags *cli.CommonFlags, cn, store, algorithm string, keySize, validDays int,
	sansDNS, sansIPs, sansEmail, keyUsage, extKeyUsage string) error {

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	grpcClient := base.Client().CA()
	if grpcClient == nil {
		return ErrCANotInitialized{}
	}

	sdkClient := casvc.NewClientFromGRPC(grpcClient)

	// Parse key algorithm
	keyAlg, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return err
	}

	// Build certificate request
	params := &casvc.IssueCertificateParams{
		Subject: &casvc.Subject{
			CommonName: cn,
		},
		KeyAlgorithm: keyAlg,
		StoreType:    store,
		ValidDays:    int32(validDays),
	}

	// Add SANs if specified
	if sansDNS != "" || sansIPs != "" || sansEmail != "" {
		params.SANs = &casvc.SubjectAlternativeNames{}
		if sansDNS != "" {
			params.SANs.DNSNames = splitCSV(sansDNS)
		}
		if sansIPs != "" {
			params.SANs.IPAddresses = splitCSV(sansIPs)
		}
		if sansEmail != "" {
			params.SANs.EmailAddresses = splitCSV(sansEmail)
		}
	}

	// Add key usage if specified
	if keyUsage != "" {
		params.KeyUsage = splitCSV(keyUsage)
	}
	if extKeyUsage != "" {
		params.ExtKeyUsage = splitCSV(extKeyUsage)
	}

	ctx := base.Context()
	result, err := sdkClient.IssueCertificateDomain(ctx, params)
	if err != nil {
		return ErrIssueCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if result.Certificate != nil {
			printer.PrintSuccess(fmt.Sprintf("Certificate issued successfully: %s", result.Certificate.Serial))
			fmt.Println()
			printCertificateDetails(printer, result.Certificate)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printCertificateDetails prints full certificate details
func printCertificateDetails(printer *cli.Printer, cert *casvc.Certificate) {
	if cert == nil {
		return
	}

	printer.PrintKeyValue("Serial", cert.Serial)
	if cert.Subject != nil {
		printer.PrintKeyValue("Common Name", cert.Subject.CommonName)
		if cert.Subject.Organization != "" {
			printer.PrintKeyValue("Organization", cert.Subject.Organization)
		}
	}
	printer.PrintKeyValue("Issuer", cert.Issuer)
	printer.PrintKeyValue("Not Before", formatTime(cert.NotBefore))
	printer.PrintKeyValue("Not After", formatTime(cert.NotAfter))
	printer.PrintKeyValue("Status", string(cert.Status))
	printer.PrintKeyValue("Key Algorithm", string(cert.KeyAlgorithm))
	printer.PrintKeyValue("Signature Algorithm", cert.SignatureAlgorithm)
	printer.PrintKeyValue("Is CA", formatBool(cert.IsCa))
	if cert.FingerprintSha256 != "" {
		printer.PrintKeyValue("SHA-256 Fingerprint", cert.FingerprintSha256)
	}
}

// parseKeyAlgorithm parses a key algorithm string to the SDK domain type
func parseKeyAlgorithm(algorithm string) (casvc.KeyAlgorithm, error) {
	switch strings.ToUpper(algorithm) {
	case "RSA-2048":
		return casvc.KeyAlgorithmRSA2048, nil
	case "RSA-3072":
		return casvc.KeyAlgorithmRSA3072, nil
	case "RSA-4096":
		return casvc.KeyAlgorithmRSA4096, nil
	case "ECDSA-P256", "EC-P256":
		return casvc.KeyAlgorithmECDSAP256, nil
	case "ECDSA-P384", "EC-P384":
		return casvc.KeyAlgorithmECDSAP384, nil
	case "ED25519":
		return casvc.KeyAlgorithmEd25519, nil
	default:
		return casvc.KeyAlgorithmUnspecified, ErrInvalidKeyAlgorithm{Algorithm: algorithm}
	}
}

// splitCSV splits a comma-separated string into a slice
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
