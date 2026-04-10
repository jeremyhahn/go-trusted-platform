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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newListCommand creates the list subcommand for listing certificates
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		status   string
		issuer   string
		page     uint32
		pageSize uint32
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued certificates",
		Long: `List all certificates issued by the Certificate Authority.

Certificates can be filtered by status, issuer, and limited to a specific count.
Output can be formatted as a table, JSON, or YAML.

Status filters:
  - all     : All certificates (default)
  - valid   : Non-expired, non-revoked certificates
  - revoked : Revoked certificates
  - expired : Expired certificates

Examples:
  # List all certificates
  platformctl ca list

  # List only valid certificates
  platformctl ca list --status valid

  # List revoked certificates in JSON format
  platformctl ca list --status revoked -o json

  # List certificates issued by a specific CA
  platformctl ca list --issuer "My Intermediate CA"

  # List with pagination
  platformctl ca list --page 1 --page-size 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, status, issuer, page, pageSize)
		},
	}

	cmd.Flags().StringVar(&status, "status", "all", "Filter by status: valid, revoked, expired, all")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Filter by issuer Common Name")
	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "Page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "Maximum number of certificates per page")

	return cmd
}

// runList executes the certificate list command
func runList(flags *cli.CommonFlags, status, issuer string, page, pageSize uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().CA()
	if client == nil {
		return ErrCANotInitialized{}
	}

	// Parse status filter
	statusFilter, err := parseStatusFilter(status)
	if err != nil {
		return err
	}

	req := &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
		StatusFilter: statusFilter,
		IssuerFilter: issuer,
	}

	ctx := base.Context()
	resp, err := client.ListCertificates(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Certificates) == 0 {
			printer.PrintInfo("No certificates found")
			return nil
		}

		table := cli.NewTableData("Serial", "Common Name", "Issuer", "Status", "Algorithm", "Not After")
		for _, cert := range resp.Certificates {
			table.AddRow(
				truncateSerial(cert.Serial, 16),
				truncateString(cert.CommonName, 30),
				truncateString(cert.Issuer, 20),
				cert.Status.String(),
				cert.KeyAlgorithm.String(),
				formatTimestamp(cert.NotAfter),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		if resp.Pagination != nil {
			printer.PrintKeyValue("Page", fmt.Sprintf("%d of %d", resp.Pagination.Page, resp.Pagination.TotalPages))
			printer.PrintKeyValue("Total", fmt.Sprintf("%d certificates", resp.Pagination.TotalItems))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseStatusFilter parses a status string to the protobuf enum
func parseStatusFilter(status string) (platformv1.CertificateStatus, error) {
	switch strings.ToLower(status) {
	case "all", "":
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED, nil
	case "valid", "active":
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, nil
	case "revoked":
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED, nil
	case "expired":
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED, nil
	case "pending":
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING, nil
	default:
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED, ErrInvalidStatus{Status: status}
	}
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// truncateSerial truncates a serial number for display
func truncateSerial(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
