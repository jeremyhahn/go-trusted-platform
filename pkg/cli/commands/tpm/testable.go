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
	"context"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// BaseCommandInterface defines the interface for BaseCommand to enable testing
type BaseCommandInterface interface {
	Client() IDevIDClientProvider
	Printer() *cli.Printer
	Context() context.Context
	Close() error
	Flags() *cli.CommonFlags
}

// IDevIDClientProvider provides access to the IDevID SDK client
type IDevIDClientProvider interface {
	IDevID() *idevidsvc.Client
}

// baseCommandAdapter wraps cli.BaseCommand to implement BaseCommandInterface
type baseCommandAdapter struct {
	base *cli.BaseCommand
}

func (b *baseCommandAdapter) Client() IDevIDClientProvider {
	return &clientAdapter{base: b.base}
}

func (b *baseCommandAdapter) Printer() *cli.Printer {
	return b.base.Printer()
}

func (b *baseCommandAdapter) Context() context.Context {
	return b.base.Context()
}

func (b *baseCommandAdapter) Close() error {
	return b.base.Close()
}

func (b *baseCommandAdapter) Flags() *cli.CommonFlags {
	return b.base.Flags()
}

// clientAdapter wraps the platform client to provide an IDevID SDK client
type clientAdapter struct {
	base *cli.BaseCommand
}

func (c *clientAdapter) IDevID() *idevidsvc.Client {
	return idevidsvc.NewClientFromGRPC(c.base.Client().IDevID())
}

// =============================================================================
// Testable IDevID Functions
// =============================================================================

// runIDevIDGenerateWithClient runs IDevID generate with a testable interface
func runIDevIDGenerateWithClient(base BaseCommandInterface, algorithm string, overwrite bool) error {
	defer base.Close()

	alg, err := parseAlgorithm(algorithm)
	if err != nil {
		return err
	}

	ctx := base.Context()
	info, err := base.Client().IDevID().GenerateIDevIDDomain(ctx, alg, overwrite)
	if err != nil {
		return ErrGenerateIDevIDFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := buildGenerateKeyOutput(info, algorithm)
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IDevID key generated successfully")
		fmt.Println()
		printer.PrintKeyValue("Algorithm", algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDInfoWithClient runs IDevID info with a testable interface
func runIDevIDInfoWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	info, err := base.Client().IDevID().GetIDevIDInfoDomain(ctx)
	if err != nil {
		return ErrGetIDevIDInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildKeyInfoOutput(info)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printKeyInfoDetails(printer, info, "IDevID")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDDeleteWithClient runs IDevID delete with a testable interface
func runIDevIDDeleteWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	deleted, message, err := base.Client().IDevID().DeleteIDevIDDomain(ctx)
	if err != nil {
		return ErrDeleteIDevIDFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"deleted": deleted,
		"message": message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		if deleted {
			printer.PrintSuccess("IDevID key deleted successfully")
		} else {
			msg := "unknown error"
			if message != "" {
				msg = message
			}
			printer.PrintError(fmt.Sprintf("Failed to delete IDevID: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDCSRWithClient runs IDevID CSR with a testable interface
func runIDevIDCSRWithClient(base BaseCommandInterface, cn, org, country, state, locality, orgUnit string) error {
	defer base.Close()

	template := &idevidsvc.CSRTemplate{
		CommonName:         cn,
		Organization:       org,
		Country:            country,
		Province:           state,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
	}

	ctx := base.Context()
	csrPEM, err := base.Client().IDevID().CreateIDevIDCSRDomain(ctx, template)
	if err != nil {
		return ErrCreateIDevIDCSRFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"csr_pem": csrPEM,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IDevID CSR created successfully")
		fmt.Println()
		fmt.Print(string(csrPEM))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDInstallWithClient runs IDevID install with a testable interface
func runIDevIDInstallWithClient(base BaseCommandInterface, certFile string) error {
	defer base.Close()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return ErrInstallIDevIDCertificateFailed{Reason: fmt.Sprintf("failed to read certificate file: %v", err)}
	}

	ctx := base.Context()
	installed, message, err := base.Client().IDevID().InstallIDevIDCertificateDomain(ctx, certPEM)
	if err != nil {
		return ErrInstallIDevIDCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"installed": installed,
		"message":   message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		if installed {
			printer.PrintSuccess("IDevID certificate installed successfully")
		} else {
			msg := "unknown error"
			if message != "" {
				msg = message
			}
			printer.PrintError(fmt.Sprintf("Failed to install certificate: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDCertWithClient runs IDevID cert with a testable interface
func runIDevIDCertWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	cert, err := base.Client().IDevID().GetIDevIDCertificateDomain(ctx)
	if err != nil {
		return ErrGetIDevIDCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildCertificateOutput(cert)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printCertificateDetails(printer, cert, "IDevID")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// =============================================================================
// Testable IAK Functions
// =============================================================================

// runIAKGenerateWithClient runs IAK generate with a testable interface
func runIAKGenerateWithClient(base BaseCommandInterface, algorithm string, overwrite bool) error {
	defer base.Close()

	alg, err := parseAlgorithm(algorithm)
	if err != nil {
		return err
	}

	ctx := base.Context()
	info, err := base.Client().IDevID().GenerateIAKDomain(ctx, alg, overwrite)
	if err != nil {
		return ErrGenerateIAKFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := buildGenerateKeyOutput(info, algorithm)
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IAK key generated successfully")
		fmt.Println()
		printer.PrintKeyValue("Algorithm", algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKInfoWithClient runs IAK info with a testable interface
func runIAKInfoWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	info, err := base.Client().IDevID().GetIAKInfoDomain(ctx)
	if err != nil {
		return ErrGetIAKInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildKeyInfoOutput(info)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printKeyInfoDetails(printer, info, "IAK")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKDeleteWithClient runs IAK delete with a testable interface
func runIAKDeleteWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	deleted, message, err := base.Client().IDevID().DeleteIAKDomain(ctx)
	if err != nil {
		return ErrDeleteIAKFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"deleted": deleted,
		"message": message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		if deleted {
			printer.PrintSuccess("IAK key deleted successfully")
		} else {
			msg := "unknown error"
			if message != "" {
				msg = message
			}
			printer.PrintError(fmt.Sprintf("Failed to delete IAK: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKCSRWithClient runs IAK CSR with a testable interface
func runIAKCSRWithClient(base BaseCommandInterface, cn, org, country, state, locality, orgUnit string) error {
	defer base.Close()

	template := &idevidsvc.CSRTemplate{
		CommonName:         cn,
		Organization:       org,
		Country:            country,
		Province:           state,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
	}

	ctx := base.Context()
	csrPEM, err := base.Client().IDevID().CreateIAKCSRDomain(ctx, template)
	if err != nil {
		return ErrCreateIAKCSRFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"csr_pem": csrPEM,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IAK CSR created successfully")
		fmt.Println()
		fmt.Print(string(csrPEM))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKInstallWithClient runs IAK install with a testable interface
func runIAKInstallWithClient(base BaseCommandInterface, certFile string) error {
	defer base.Close()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return ErrInstallIAKCertificateFailed{Reason: fmt.Sprintf("failed to read certificate file: %v", err)}
	}

	ctx := base.Context()
	installed, message, err := base.Client().IDevID().InstallIAKCertificateDomain(ctx, certPEM)
	if err != nil {
		return ErrInstallIAKCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"installed": installed,
		"message":   message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		if installed {
			printer.PrintSuccess("IAK certificate installed successfully")
		} else {
			msg := "unknown error"
			if message != "" {
				msg = message
			}
			printer.PrintError(fmt.Sprintf("Failed to install certificate: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKCertWithClient runs IAK cert with a testable interface
func runIAKCertWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	cert, err := base.Client().IDevID().GetIAKCertificateDomain(ctx)
	if err != nil {
		return ErrGetIAKCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildCertificateOutput(cert)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printCertificateDetails(printer, cert, "IAK")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// =============================================================================
// Testable TPM Device Functions
// =============================================================================

// runFlushWithClient runs flush with a testable interface
func runFlushWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	flushedCount, message, err := base.Client().IDevID().FlushTransientContextsDomain(ctx)
	if err != nil {
		return ErrFlushFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"flushed_count": flushedCount,
		"message":       message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Flushed %d transient TPM contexts", flushedCount))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runDeviceAttributesWithClient runs device attributes with a testable interface
func runDeviceAttributesWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	attrs, err := base.Client().IDevID().GetDeviceAttributesDomain(ctx)
	if err != nil {
		return ErrGetDeviceAttributesFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"manufacturer": attrs.TPMManufacturer,
		"model":        attrs.TPMModel,
		"version":      attrs.TPMVersion,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("TPM Manufacturer", attrs.TPMManufacturer)
		printer.PrintKeyValue("TPM Model", attrs.TPMModel)
		printer.PrintKeyValue("TPM Version", attrs.TPMVersion)
		printer.PrintKeyValue("Platform Manufacturer", attrs.PlatformManufacturer)
		printer.PrintKeyValue("Platform Model", attrs.PlatformModel)
		printer.PrintKeyValue("Platform Version", attrs.PlatformVersion)
		printer.PrintKeyValue("Platform Serial", attrs.PlatformSerial)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
