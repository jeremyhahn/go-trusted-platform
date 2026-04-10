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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// BaseCommandInterface defines the interface for BaseCommand to enable testing
type BaseCommandInterface interface {
	Client() IDevIDClientProvider
	Printer() *cli.Printer
	Context() context.Context
	Close() error
	Flags() *cli.CommonFlags
}

// IDevIDClientProvider provides access to the IDevID client
type IDevIDClientProvider interface {
	IDevID() platformv1.IDevIDServiceClient
}

// baseCommandAdapter wraps cli.BaseCommand to implement BaseCommandInterface
type baseCommandAdapter struct {
	base *cli.BaseCommand
}

func (b *baseCommandAdapter) Client() IDevIDClientProvider {
	return &clientAdapter{client: b.base.Client()}
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

// clientAdapter wraps platform.Client to implement IDevIDClientProvider
type clientAdapter struct {
	client platform.Client
}

func (c *clientAdapter) IDevID() platformv1.IDevIDServiceClient {
	return c.client.IDevID()
}

// =============================================================================
// TPM Service Interface (for TPMService commands)
// =============================================================================

// TPMBaseCommandInterface defines the interface for TPM service commands
type TPMBaseCommandInterface interface {
	TPMClient() platformv1.TPMServiceClient
	Printer() *cli.Printer
	Context() context.Context
	Close() error
	Flags() *cli.CommonFlags
}

// tpmBaseCommandAdapter wraps cli.BaseCommand to implement TPMBaseCommandInterface
type tpmBaseCommandAdapter struct {
	base *cli.BaseCommand
}

func (b *tpmBaseCommandAdapter) TPMClient() platformv1.TPMServiceClient {
	return b.base.Client().TPM()
}

func (b *tpmBaseCommandAdapter) Printer() *cli.Printer {
	return b.base.Printer()
}

func (b *tpmBaseCommandAdapter) Context() context.Context {
	return b.base.Context()
}

func (b *tpmBaseCommandAdapter) Close() error {
	return b.base.Close()
}

func (b *tpmBaseCommandAdapter) Flags() *cli.CommonFlags {
	return b.base.Flags()
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

	req := &platformv1.GenerateIDevIDRequest{
		Config: &platformv1.IDevIDConfig{
			Algorithm: alg,
			Overwrite: overwrite,
		},
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().GenerateIDevID(ctx, req)
	if err != nil {
		return ErrGenerateIDevIDFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrGenerateIDevIDFailed{Reason: msg}
	}

	// Fetch key info after successful generation
	infoResp, err := base.Client().IDevID().GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		return ErrGetIDevIDInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := buildGenerateKeyOutput(infoResp.KeyInfo, algorithm)
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IDevID key generated successfully")
		fmt.Println()
		printStatusDetails(printer, resp.Status, algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDInfoWithClient runs IDevID info with a testable interface
func runIDevIDInfoWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().IDevID().GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		return ErrGetIDevIDInfoFailed{Reason: err.Error()}
	}

	if resp.KeyInfo == nil {
		return ErrIDevIDNotFound{}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildKeyInfoOutput(resp.KeyInfo)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printKeyInfoDetails(printer, resp.KeyInfo, "IDevID")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIDevIDDeleteWithClient runs IDevID delete with a testable interface
func runIDevIDDeleteWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().IDevID().DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
	if err != nil {
		return ErrDeleteIDevIDFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	deleted := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
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

	template := &platformv1.CSRTemplate{
		CommonName:         cn,
		Organization:       org,
		Country:            country,
		Province:           state,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
	}

	req := &platformv1.CreateIDevIDCSRRequest{
		Template: template,
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().CreateIDevIDCSR(ctx, req)
	if err != nil {
		return ErrCreateIDevIDCSRFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"csr_pem": resp.CsrPem,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IDevID CSR created successfully")
		fmt.Println()
		fmt.Print(string(resp.CsrPem))
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

	req := &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: certPEM,
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().InstallIDevIDCertificate(ctx, req)
	if err != nil {
		return ErrInstallIDevIDCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	installed := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
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
	resp, err := base.Client().IDevID().GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		return ErrGetIDevIDCertificateFailed{Reason: err.Error()}
	}

	if resp.Certificate == nil {
		return ErrIDevIDCertificateNotFound{}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildCertificateOutput(resp.Certificate)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printCertificateDetails(printer, resp.Certificate, "IDevID")
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

	req := &platformv1.GenerateIAKRequest{
		Config: &platformv1.IAKConfig{
			Algorithm: alg,
			Overwrite: overwrite,
		},
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().GenerateIAK(ctx, req)
	if err != nil {
		return ErrGenerateIAKFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrGenerateIAKFailed{Reason: msg}
	}

	// Fetch key info after successful generation
	infoResp, err := base.Client().IDevID().GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
	if err != nil {
		return ErrGetIAKInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := buildGenerateKeyOutput(infoResp.KeyInfo, algorithm)
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IAK key generated successfully")
		fmt.Println()
		printStatusDetails(printer, resp.Status, algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKInfoWithClient runs IAK info with a testable interface
func runIAKInfoWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().IDevID().GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
	if err != nil {
		return ErrGetIAKInfoFailed{Reason: err.Error()}
	}

	if resp.KeyInfo == nil {
		return ErrIAKNotFound{}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildKeyInfoOutput(resp.KeyInfo)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printKeyInfoDetails(printer, resp.KeyInfo, "IAK")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runIAKDeleteWithClient runs IAK delete with a testable interface
func runIAKDeleteWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().IDevID().DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
	if err != nil {
		return ErrDeleteIAKFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	deleted := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
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

	template := &platformv1.CSRTemplate{
		CommonName:         cn,
		Organization:       org,
		Country:            country,
		Province:           state,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
	}

	req := &platformv1.CreateIAKCSRRequest{
		Template: template,
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().CreateIAKCSR(ctx, req)
	if err != nil {
		return ErrCreateIAKCSRFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"csr_pem": resp.CsrPem,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("IAK CSR created successfully")
		fmt.Println()
		fmt.Print(string(resp.CsrPem))
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

	req := &platformv1.InstallIAKCertificateRequest{
		CertificatePem: certPEM,
	}

	ctx := base.Context()
	resp, err := base.Client().IDevID().InstallIAKCertificate(ctx, req)
	if err != nil {
		return ErrInstallIAKCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	installed := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
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
	resp, err := base.Client().IDevID().GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	if err != nil {
		return ErrGetIAKCertificateFailed{Reason: err.Error()}
	}

	if resp.Certificate == nil {
		return ErrIAKCertificateNotFound{}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildCertificateOutput(resp.Certificate)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printCertificateDetails(printer, resp.Certificate, "IAK")
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
	resp, err := base.Client().IDevID().FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})
	if err != nil {
		return ErrFlushFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"flushed_count": resp.FlushedCount,
		"message":       resp.Status.GetMessage(),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Flushed %d transient TPM contexts", resp.FlushedCount))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runDeviceAttributesWithClient runs device attributes with a testable interface
func runDeviceAttributesWithClient(base BaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().IDevID().GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})
	if err != nil {
		return ErrGetDeviceAttributesFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	attrs := resp.GetAttributes()
	if attrs == nil {
		return ErrGetDeviceAttributesFailed{Reason: "no attributes returned"}
	}

	output := map[string]interface{}{
		"manufacturer": attrs.GetTpmManufacturer(),
		"model":        attrs.GetTpmModel(),
		"version":      attrs.GetTpmVersion(),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("TPM Manufacturer", attrs.GetTpmManufacturer())
		printer.PrintKeyValue("TPM Model", attrs.GetTpmModel())
		printer.PrintKeyValue("TPM Version", attrs.GetTpmVersion())
		printer.PrintKeyValue("Platform Manufacturer", attrs.GetPlatformManufacturer())
		printer.PrintKeyValue("Platform Model", attrs.GetPlatformModel())
		printer.PrintKeyValue("Platform Version", attrs.GetPlatformVersion())
		printer.PrintKeyValue("Platform Serial", attrs.GetPlatformSerial())
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
