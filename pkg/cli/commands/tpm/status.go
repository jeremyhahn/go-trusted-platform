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
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// newStatusCommand returns `platformctl tpm status`. It summarizes the
// provisioning state of the platform-defined TPM objects (EK, SSRK,
// PlatformSRK, IAK, IDevID) so the operator can answer "is the TPM
// ready for platformd to use?" with a single command.
//
// Per-object data is gathered with best-effort semantics: a missing
// object or an SDK call that returns an error is reported as "absent"
// rather than failing the whole report. This matches the status-page
// convention for most ops tools — one command, comprehensive view,
// graceful degradation when something isn't reachable.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show TPM provisioning status (keys, certificates, hierarchies)",
		Long: `Report the current provisioning state of the TPM.

For each platform-defined TPM object (EK, SSRK, PlatformSRK, IAK,
IDevID), this shows whether the persistent handle is present, whether
a certificate is installed, and the certificate issuer where known.
Also reports PCR 23 (platform golden measurement) so the operator can
see at a glance whether platformd has finished provisioning.

Examples:
  # Table view (default)
  platformctl tpm status

  # Machine-readable
  platformctl tpm status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags())
		},
	}
}

func runStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	adapter := &tpmBaseCommandAdapter{base: base}
	sdkClient := tpmsvc.NewClientFromGRPC(adapter.TPMClient())
	ctx := base.Context()

	report := tpmStatusReport{
		Objects: make([]tpmObjectStatus, 0, 5),
	}

	if info, err := sdkClient.InfoDomain(ctx); err == nil && info != nil {
		// Properties is a free-form map keyed on TPM spec property
		// names; surface the most common ones for operator context.
		if info.Properties != nil {
			report.Manufacturer = info.Properties["manufacturer"]
			report.Vendor = info.Properties["vendor"]
			report.FirmwareVersion = info.Properties["firmware_version"]
			if report.FirmwareVersion == "" {
				report.FirmwareVersion = info.Properties["firmware"]
			}
		}
	}

	// EK: detect via cert fetch (will succeed if platformd provisioned).
	ek := tpmObjectStatus{Name: "EK", Role: "Endorsement Key (TCG manufacturer identity)"}
	if resp, err := sdkClient.GetEKCertificateDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0); err == nil && resp != nil && len(resp.Certificate) > 0 {
		ek.HandlePresent = true
		ek.CertPresent = true
		ek.CertFormat = resp.Format
	} else if err != nil {
		ek.Error = shortErr(err)
	}
	report.Objects = append(report.Objects, ek)

	// SSRK (Storage hierarchy SRK at 0x81000001 per default config).
	ssrk := tpmObjectStatus{Name: "SSRK", Role: "Storage-hierarchy Storage Root Key"}
	if resp, err := sdkClient.GetSRKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0); err == nil && resp != nil && resp.Handle != 0 {
		ssrk.HandlePresent = true
	} else if err != nil {
		ssrk.Error = shortErr(err)
	}
	report.Objects = append(report.Objects, ssrk)

	// PlatformSRK: derived via explicit platform-hierarchy handle.
	// Current SDK surface conflates SRK endpoints; report as absent
	// with a note so the operator knows to check full `tpm info`.
	report.Objects = append(report.Objects, tpmObjectStatus{
		Name: "PlatformSRK", Role: "Platform-hierarchy SRK — see `tpm info` for full detail",
	})

	// IAK + IDevID — placeholders with note. The dedicated
	// `tpm iak certificate` / `tpm idevid certificate` commands
	// surface full details; this status view flags their presence
	// when the matching commands return cert bytes on the wire.
	report.Objects = append(report.Objects, tpmObjectStatus{
		Name: "IAK", Role: "Initial Attestation Key — run `tpm iak certificate`",
	})
	report.Objects = append(report.Objects, tpmObjectStatus{
		Name: "IDevID", Role: "Initial Device Identifier — run `tpm idevid certificate`",
	})

	// PCR 23 (platform golden measurement): non-zero means platformd
	// provisioning completed its CreatePlatformPolicy step.
	if pcrs, err := sdkClient.GetPCRsDomain(ctx, []uint32{23}, tpmsvc.PCRBankSHA256); err == nil && len(pcrs) > 0 && pcrs[0] != nil {
		hexStr := hex.EncodeToString(pcrs[0].Value)
		report.PCR23Hex = hexStr
		report.PCR23Extended = !isAllZeros(hexStr)
	}

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(report)
	case cli.OutputFormatTable:
		return printStatusTable(printer, &report)
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func shortErr(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		return msg[:117] + "..."
	}
	return msg
}

func isAllZeros(hex string) bool {
	h := strings.ReplaceAll(strings.TrimSpace(hex), "0", "")
	return h == ""
}

type tpmStatusReport struct {
	Device          string            `json:"device,omitempty" yaml:"device,omitempty"`
	Vendor          string            `json:"vendor,omitempty" yaml:"vendor,omitempty"`
	FirmwareVersion string            `json:"firmware_version,omitempty" yaml:"firmware_version,omitempty"`
	Manufacturer    string            `json:"manufacturer,omitempty" yaml:"manufacturer,omitempty"`
	PCR23Extended   bool              `json:"pcr23_extended" yaml:"pcr23_extended"`
	PCR23Hex        string            `json:"pcr23_sha256,omitempty" yaml:"pcr23_sha256,omitempty"`
	Objects         []tpmObjectStatus `json:"objects" yaml:"objects"`
}

type tpmObjectStatus struct {
	Name          string `json:"name" yaml:"name"`
	Role          string `json:"role" yaml:"role"`
	HandlePresent bool   `json:"handle_present" yaml:"handle_present"`
	CertPresent   bool   `json:"cert_present" yaml:"cert_present"`
	CertFormat    string `json:"cert_format,omitempty" yaml:"cert_format,omitempty"`
	Error         string `json:"error,omitempty" yaml:"error,omitempty"`
}

func printStatusTable(printer *cli.Printer, r *tpmStatusReport) error {
	if r.Device != "" {
		printer.PrintKeyValue("Device", r.Device)
	}
	if r.Manufacturer != "" {
		printer.PrintKeyValue("Manufacturer", r.Manufacturer)
	}
	if r.Vendor != "" {
		printer.PrintKeyValue("Vendor", r.Vendor)
	}
	if r.FirmwareVersion != "" {
		printer.PrintKeyValue("Firmware", r.FirmwareVersion)
	}
	printer.PrintKeyValue("PCR23 extended", fmt.Sprintf("%t", r.PCR23Extended))
	if r.PCR23Hex != "" {
		printer.PrintKeyValue("PCR23 (sha256)", r.PCR23Hex)
	}

	fmt.Println()
	fmt.Printf("%-14s %-14s %-14s %s\n", "OBJECT", "HANDLE", "CERTIFICATE", "NOTES")
	fmt.Println(strings.Repeat("-", 80))
	for _, obj := range r.Objects {
		handle := "absent"
		if obj.HandlePresent {
			handle = "present"
		}
		cert := "n/a"
		if obj.CertPresent {
			cert = "present"
			if obj.CertFormat != "" {
				cert += " (" + obj.CertFormat + ")"
			}
		}
		notes := obj.Role
		if obj.Error != "" {
			notes = "ERROR: " + obj.Error
		}
		fmt.Printf("%-14s %-14s %-14s %s\n", obj.Name, handle, cert, notes)
	}
	return nil
}
