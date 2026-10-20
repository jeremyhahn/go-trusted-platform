// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newAttestCommand creates the device attest command.
func newAttestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var evidenceFile string
	cmd := &cobra.Command{
		Use:   "attest <id>",
		Short: "Verify TPM quote evidence for a device",
		Long: `Verify TPM quote evidence the caller supplies against a registered device.
It does not ask the device for a fresh quote: it answers whether the evidence
attests the device.

--evidence-file is the JSON DeviceQuoteEvidence document
({"quote", "signature", "nonce", "pcrs"}, base64 values), the same document
every transport carries.

A failed verification is not an error: the command succeeds and reports
verified false with the result of each check. It fails only when the evidence
could not be evaluated.

Examples:
  platformctl device attest 123 --evidence-file quote.json
  platformctl device attest 123 --evidence-file quote.json -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(getFlags(), args[0], evidenceFile)
		},
	}
	cmd.Flags().StringVar(&evidenceFile, "evidence-file", "", "path to the JSON DeviceQuoteEvidence document (required)")
	return cmd
}

// attestOutput is the attestation verdict, shaped like the REST response.
type attestOutput struct {
	DeviceID              uint64     `json:"device_id"`
	Serial                string     `json:"serial,omitempty"`
	Model                 string     `json:"model,omitempty"`
	Verified              bool       `json:"verified"`
	SignatureValid        bool       `json:"signature_valid"`
	NonceValid            bool       `json:"nonce_valid"`
	PCRsValid             bool       `json:"pcrs_valid"`
	AKCertificateVerified bool       `json:"ak_certificate_verified"`
	AttestationStatus     string     `json:"attestation_status"`
	Message               string     `json:"message,omitempty"`
	AttestedAt            *time.Time `json:"attested_at,omitempty"`
	PCRBaselineSource     string     `json:"pcr_baseline_source,omitempty"`
	PCRBaselineCaptured   bool       `json:"pcr_baseline_captured"`
}

// runAttest submits the evidence file for a device and renders the verdict.
func runAttest(flags *cli.CommonFlags, idStr, evidenceFile string) error {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		return ErrInvalidDeviceID{ID: idStr}
	}
	if evidenceFile == "" {
		return ErrAttestEvidenceRequired{}
	}
	evidence, err := os.ReadFile(evidenceFile)
	if err != nil {
		return ErrAttestEvidenceReadFailed{Path: evidenceFile, Cause: err}
	}
	if len(evidence) == 0 {
		return ErrAttestEvidenceEmpty{Path: evidenceFile}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	resp, err := deviceClient.AttestDevice(base.Context(), id, evidence)
	if err != nil {
		if isNotFound(err) {
			return ErrDeviceNotFound{ID: id}
		}
		return ErrAttestFailed{ID: id, Cause: err}
	}

	out := attestOutput{
		DeviceID:              resp.GetDeviceId(),
		Serial:                resp.GetSerial(),
		Model:                 resp.GetModel(),
		Verified:              resp.GetVerified(),
		SignatureValid:        resp.GetSignatureValid(),
		NonceValid:            resp.GetNonceValid(),
		PCRsValid:             resp.GetPcrsValid(),
		AKCertificateVerified: resp.GetAkCertificateVerified(),
		AttestationStatus:     resp.GetAttestationStatus(),
		Message:               resp.GetMessage(),
		PCRBaselineSource:     resp.GetPcrBaselineSource(),
		PCRBaselineCaptured:   resp.GetPcrBaselineCaptured(),
	}
	if ts := resp.GetAttestedAt(); ts != nil {
		t := ts.AsTime()
		out.AttestedAt = &t
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printAttest(base.Printer(), out)
		return nil
	}
	return base.Output(out)
}

// printAttest renders the verdict as a key/value table, leading with the
// overall result.
func printAttest(printer *cli.Printer, out attestOutput) {
	if out.Verified {
		printer.PrintSuccess("Device attestation verified")
	} else {
		printer.PrintWarning("Device attestation not verified")
	}
	printer.PrintKeyValue("ID", strconv.FormatUint(out.DeviceID, 10))
	printer.PrintKeyValue("Serial", out.Serial)
	printer.PrintKeyValue("Model", out.Model)
	printer.PrintKeyValue("Status", out.AttestationStatus)
	printer.PrintKeyValue("Signature Valid", strconv.FormatBool(out.SignatureValid))
	printer.PrintKeyValue("Nonce Valid", strconv.FormatBool(out.NonceValid))
	printer.PrintKeyValue("PCRs Valid", strconv.FormatBool(out.PCRsValid))
	printer.PrintKeyValue("AK Certificate Verified", strconv.FormatBool(out.AKCertificateVerified))
	if out.Message != "" {
		printer.PrintKeyValue("Message", out.Message)
	}
	if out.PCRBaselineSource != "" {
		printer.PrintKeyValue("PCR Baseline", out.PCRBaselineSource)
	}
	if out.AttestedAt != nil {
		printer.PrintKeyValue("Attested At", out.AttestedAt.UTC().Format(time.RFC3339))
	}
}
