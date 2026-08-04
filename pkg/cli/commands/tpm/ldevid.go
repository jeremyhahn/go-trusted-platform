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
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// ldevidCreateFlags collects the flags for `platformctl tpm idevid ldevid create`.
type ldevidCreateFlags struct {
	commonName         string
	organization       string
	organizationalUnit string
	country            string
	state              string
	locality           string
	algorithm          string
	handle             string
	profile            string
	validityDays       uint32
	overwrite          bool
	out                string
}

// NewLDevIDCommand creates the ldevid subcommand group under `tpm idevid`.
//
// LDevID (Local Device Identifier, IEEE 802.1AR) is a locally significant,
// CA-issued operational identity layered on top of the permanent IDevID birth
// identity. Issuance is refused unless the device has a proven, currently
// valid IDevID certificate installed.
func NewLDevIDCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ldevid",
		Short: "Manage LDevID (Local Device Identifier, IEEE 802.1AR) keys",
		Long: `Manage LDevID keys per IEEE 802.1AR.

An LDevID is a locally significant, CA-issued operational identity that layers
on top of the permanent IDevID birth identity. The platform creates a
TPM-resident LDevID signing key (default handle 0x81010102), builds a PKCS#10
CSR, and has the platform CA issue the certificate. Issuance requires a proven
IDevID.`,
	}

	cmd.AddCommand(newLDevIDCreateCommand(getFlags))
	return cmd
}

// newLDevIDCreateCommand creates the `ldevid create` subcommand.
func newLDevIDCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &ldevidCreateFlags{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Provision an LDevID key and issue its certificate from the platform CA",
		Long: `Provision an LDevID (IEEE 802.1AR) key and issue its certificate.

Creates a TPM-resident LDevID signing key distinct from the IDevID/IAK birth
keys, builds a PKCS#10 CSR signed by that key, and has the platform CA issue
the LDevID certificate. Requires a proven, currently-valid IDevID.

Supported algorithms:
  - ECDSA-P256 (default, TCG-preferred device identity algorithm)
  - ECDSA-P384
  - RSA-2048
  - RSA-3072`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLDevIDCreate(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.commonName, "common-name", "", "subject common name (defaults to the IDevID CN)")
	cmd.Flags().StringVar(&f.organization, "organization", "", "subject organization")
	cmd.Flags().StringVar(&f.organizationalUnit, "organizational-unit", "", "subject organizational unit")
	cmd.Flags().StringVar(&f.country, "country", "", "subject country code (2 letters)")
	cmd.Flags().StringVar(&f.state, "state", "", "subject state or province")
	cmd.Flags().StringVar(&f.locality, "locality", "", "subject city or locality")
	cmd.Flags().StringVar(&f.algorithm, "algorithm", "ECDSA-P256",
		"LDevID key algorithm: ECDSA-P256, ECDSA-P384, RSA-2048, RSA-3072")
	cmd.Flags().StringVar(&f.handle, "handle", "",
		"persistent TPM handle for the LDevID key (hex 0x... or decimal; default 0x81010102)")
	cmd.Flags().StringVar(&f.profile, "profile", "", "platform CA certificate profile used for issuance")
	cmd.Flags().Uint32Var(&f.validityDays, "validity-days", 0, "issued certificate validity in days (0 = CA/profile default)")
	cmd.Flags().BoolVar(&f.overwrite, "overwrite", false, "overwrite an existing LDevID key at the handle")
	cmd.Flags().StringVar(&f.out, "out", "",
		"write the issued certificate PEM to this path; the CSR is written to <out>.csr")

	return cmd
}

// runLDevIDCreate wires the concrete SDK client and invokes the testable core.
func runLDevIDCreate(flags *cli.CommonFlags, f *ldevidCreateFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runLDevIDCreateWithClient(&baseCommandAdapter{base: base}, f)
}

// runLDevIDCreateWithClient executes LDevID create against a testable client.
func runLDevIDCreateWithClient(base BaseCommandInterface, f *ldevidCreateFlags) error {
	defer base.Close()

	req, err := buildCreateLDevIDRequest(f)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().CreateLDevID(ctx, req)
	if err != nil {
		return ErrCreateLDevIDFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	csrPEM := string(resp.GetCsrPem())
	certPEM := string(resp.GetCertificatePem())

	output := map[string]interface{}{
		"status":          resp.GetStatus().GetMessage(),
		"success":         resp.GetStatus().GetSuccess(),
		"csr_pem":         csrPEM,
		"certificate_pem": certPEM,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		if err := writeLDevIDArtifacts(f, csrPEM, certPEM); err != nil {
			return err
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("LDevID certificate issued successfully")
		if err := writeLDevIDArtifacts(f, csrPEM, certPEM); err != nil {
			return err
		}
		if f.out == "" {
			fmt.Println()
			fmt.Print(certPEM)
		} else {
			printer.PrintKeyValue("Certificate", f.out)
			printer.PrintKeyValue("CSR", f.out+".csr")
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// buildCreateLDevIDRequest assembles the pb request from the CLI flags.
func buildCreateLDevIDRequest(f *ldevidCreateFlags) (*platformv1.CreateLDevIDRequest, error) {
	req := &platformv1.CreateLDevIDRequest{
		Profile:      f.profile,
		ValidityDays: f.validityDays,
		Overwrite:    f.overwrite,
	}

	if f.algorithm != "" {
		algo, ok := idevidsvc.AlgorithmToProto(f.algorithm)
		if !ok {
			return nil, ErrInvalidAlgorithm{Algorithm: f.algorithm, Valid: validAlgorithms}
		}
		req.Algorithm = algo
	}

	if f.handle != "" {
		handle, err := parseTPMHandle(f.handle)
		if err != nil {
			return nil, err
		}
		req.Handle = handle
	}

	if f.commonName != "" || f.organization != "" || f.organizationalUnit != "" ||
		f.country != "" || f.state != "" || f.locality != "" {
		req.Template = &platformv1.CSRTemplate{
			CommonName:         f.commonName,
			Organization:       f.organization,
			OrganizationalUnit: f.organizationalUnit,
			Country:            f.country,
			Province:           f.state,
			Locality:           f.locality,
		}
	}

	return req, nil
}

// writeLDevIDArtifacts writes the certificate and CSR PEM to disk when --out
// is set. The certificate goes to <out> and the CSR to <out>.csr.
func writeLDevIDArtifacts(f *ldevidCreateFlags, csrPEM, certPEM string) error {
	if f.out == "" {
		return nil
	}
	if err := os.WriteFile(f.out, []byte(certPEM), 0o644); err != nil {
		return ErrCreateLDevIDFailed{Reason: fmt.Sprintf("failed to write certificate: %v", err)}
	}
	if err := os.WriteFile(f.out+".csr", []byte(csrPEM), 0o644); err != nil {
		return ErrCreateLDevIDFailed{Reason: fmt.Sprintf("failed to write CSR: %v", err)}
	}
	return nil
}

// parseTPMHandle parses a persistent TPM handle from a hex (0x...) or decimal
// string.
func parseTPMHandle(s string) (uint32, error) {
	trimmed := strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
		base = 16
	}
	v, err := strconv.ParseUint(trimmed, base, 32)
	if err != nil {
		return 0, ErrInvalidTPMHandle{Handle: s}
	}
	return uint32(v), nil
}
