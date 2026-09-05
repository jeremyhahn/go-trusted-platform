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
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newAttestCertCommand creates the attest-cert command group.
func newAttestCertCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest-cert",
		Short: "Manage a device's attestation certificate",
		Long: `Manage the attestation (IAK/AK) certificate recorded on a device.

The recorded certificate is the trust anchor the control plane verifies the
device's TPM quotes against. A device enrolled before the control plane
recorded certificates at enrollment has none, and its quotes are denied until
one is recorded.`,
	}
	cmd.AddCommand(newAttestCertRecordCommand(getFlags))
	return cmd
}

// newAttestCertRecordCommand creates the record subcommand.
func newAttestCertRecordCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var reissue bool
	cmd := &cobra.Command{
		Use:   "record <id>",
		Short: "Record the device's attestation certificate without re-enrolling it",
		Long: `Record (or re-record) a device's attestation certificate on its platform
record without re-enrolling the device.

The control plane fails closed. It records only a certificate that parses,
chains to the platform CA, carries tcg-cap-verifiedTPMRestricted
(2.23.133.11.1.3) and certifies the device's enrolled attestation key; any
other candidate is refused and nothing is written. There is no override: a
certificate without the attribute would be classified as a cryptographic
failure on the device's next quote and quarantine it.

Candidates are tried in order: the certificate already on the record, the
platform CA's certificate store, and -- only with --reissue -- a fresh
certificate the CA issues over the device's enrolled attestation public key.
Re-issuance does not involve the device; whether the CA stamps the attribute
depends on the CA's own profile, and a re-issued certificate without it is
refused like any other.

After a successful record the attestation collector's next sweep verifies a
quote against the new certificate and produces the device's verdict.

Examples:
  # Record the certificate the CA already holds for device 123
  platformctl device attest-cert record 123

  # Let the CA issue a fresh certificate over the enrolled attestation key
  platformctl device attest-cert record 123 --reissue

  # Machine-readable output
  platformctl device attest-cert record 123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestCertRecord(getFlags(), args[0], reissue)
		},
	}
	cmd.Flags().BoolVar(&reissue, "reissue", false,
		"Ask the platform CA to issue a fresh attestation certificate over the device's enrolled attestation public key when no stored certificate passes the preflight")
	return cmd
}

// attestCertRecordOutput is the machine-readable result of record.
type attestCertRecordOutput struct {
	ID                uint64     `json:"id"`
	Serial            string     `json:"serial,omitempty"`
	Model             string     `json:"model,omitempty"`
	Changed           bool       `json:"changed"`
	Source            string     `json:"source"`
	SourceDetail      string     `json:"source_detail,omitempty"`
	Reissued          bool       `json:"reissued"`
	Subject           string     `json:"subject"`
	CertificateSerial string     `json:"certificate_serial"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	AttestCert        string     `json:"attest_cert"`
}

// runAttestCertRecord executes the record command using the SDK client.
func runAttestCertRecord(flags *cli.CommonFlags, idStr string, reissue bool) error {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		return ErrInvalidDeviceID{ID: idStr}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	resp, err := deviceClient.RecordAttestationCertificate(base.Context(), id, reissue)
	if err != nil {
		return ErrRecordAttestCertFailed{ID: id, Reason: err.Error()}
	}

	out := attestCertRecordOutput{
		ID:                resp.GetDeviceId(),
		Serial:            resp.GetSerial(),
		Model:             resp.GetModel(),
		Changed:           resp.GetChanged(),
		Source:            resp.GetSource(),
		SourceDetail:      resp.GetSourceDetail(),
		Reissued:          resp.GetReissued(),
		Subject:           resp.GetSubject(),
		CertificateSerial: resp.GetCertificateSerial(),
		AttestCert:        resp.GetAttestCert(),
	}
	if ts := resp.GetNotAfter(); ts != nil {
		t := ts.AsTime()
		out.NotAfter = &t
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printAttestCertRecord(base.Printer(), out)
		return nil
	}
	return base.Output(out)
}

// printAttestCertRecord renders the record result as a table.
func printAttestCertRecord(printer *cli.Printer, out attestCertRecordOutput) {
	if out.Changed {
		printer.PrintSuccess("Attestation certificate recorded")
	} else {
		printer.PrintInfo("Attestation certificate already recorded; nothing changed")
	}
	printer.PrintKeyValue("ID", strconv.FormatUint(out.ID, 10))
	printer.PrintKeyValue("Serial", out.Serial)
	printer.PrintKeyValue("Model", out.Model)
	printer.PrintKeyValue("Source", attestCertSourceLabel(out.Source, out.SourceDetail))
	printer.PrintKeyValue("Reissued", strconv.FormatBool(out.Reissued))
	printer.PrintKeyValue("Subject", out.Subject)
	printer.PrintKeyValue("Certificate Serial", out.CertificateSerial)
	if out.NotAfter != nil {
		printer.PrintKeyValue("Not After", out.NotAfter.UTC().Format(time.RFC3339))
	}
}

// attestCertSourceLabel names where the certificate came from for a reader.
func attestCertSourceLabel(source, detail string) string {
	labels := map[string]string{
		"device":   "already on the device record",
		"ca":       "platform CA certificate store",
		"reissued": "re-issued by the platform CA",
	}
	label, ok := labels[source]
	if !ok {
		label = source
	}
	if detail != "" {
		label += " (" + detail + ")"
	}
	return label
}
