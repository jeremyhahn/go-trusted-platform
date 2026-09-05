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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// defaultPlatformSRKHandle is the Platform KeyStore SRK handle platformd
// falls back to when `tpm.platform-srk.handle` is not configured. It
// mirrors the fallback in pkg/firstboot (getPlatformKeystoreSRKHandle);
// the daemon does not expose the configured value over the API, so the
// CLI can only assume it or be told with --platform-srk-handle.
const defaultPlatformSRKHandle uint32 = 0x81000002

// platformSRKHandleFlag is the name of the status flag that overrides
// defaultPlatformSRKHandle.
const platformSRKHandleFlag = "platform-srk-handle"

// verifiedTPMRestrictedNote is the certificate-column annotation for an
// IAK certificate that does not carry tcg-cap-verifiedTPMRestricted.
const verifiedTPMRestrictedNote = "cert lacks verifiedTPMRestricted"

// newStatusCommand returns `platformctl tpm status`. It summarizes the
// provisioning state of the platform-defined TPM objects (EK, SSRK,
// PlatformSRK, IAK, IDevID) so the operator can answer "is the TPM
// ready for platformd to use?" with a single command.
//
// Every row is backed by the same SDK call the dedicated verb uses
// (`tpm ek certificate`, `tpm srk info`, `tpm iak info`, `tpm idevid
// info`), so status can never disagree with them. A row reads `absent`
// only when the SDK positively reports the object missing; an SDK call
// that fails for any other reason is reported as `error: <reason>`
// rather than failing the whole report or being mistaken for absence.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var platformSRKHandle uint32
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show TPM provisioning status (keys, certificates, hierarchies)",
		Long: `Report the current provisioning state of the TPM.

For each platform-defined TPM object (EK, SSRK, PlatformSRK, IAK,
IDevID), this shows whether the persistent handle is present, whether
a certificate is installed, and the certificate issuer where known.
The IAK row also reports whether its certificate carries the TCG
verifiedTPMRestricted policy (2.23.133.11.1.3), which the attestation
verifier requires. Also reports PCR 23 (platform golden measurement)
so the operator can see at a glance whether platformd has finished
provisioning.

A row reads "absent" only when the daemon positively reports the object
missing. A failed lookup is reported as "error: <reason>".

The PlatformSRK handle is not exposed by the daemon API; the default
0x81000002 is assumed unless --platform-srk-handle says otherwise.

Examples:
  # Table view (default)
  platformctl tpm status

  # Machine-readable
  platformctl tpm status -o json

  # Non-default Platform KeyStore SRK handle
  platformctl tpm status --platform-srk-handle 0x81000005`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := statusOptions{
				PlatformSRKHandle:         platformSRKHandle,
				PlatformSRKHandleExplicit: cmd.Flags().Changed(platformSRKHandleFlag),
			}
			return runStatus(getFlags(), opts)
		},
	}
	cmd.Flags().Uint32Var(&platformSRKHandle, platformSRKHandleFlag, defaultPlatformSRKHandle,
		"Platform KeyStore SRK handle to probe (the daemon's configured value is not exposed over the API)")
	return cmd
}

// statusOptions carries the per-invocation inputs to the status report.
type statusOptions struct {
	// PlatformSRKHandle is the persistent handle probed for the
	// PlatformSRK row.
	PlatformSRKHandle uint32
	// PlatformSRKHandleExplicit is true when the operator supplied the
	// handle rather than the CLI assuming the default.
	PlatformSRKHandleExplicit bool
}

// statusClients are the SDK clients the status report queries. Both are
// the same clients the dedicated verbs construct, so the rows can never
// disagree with `tpm srk info`, `tpm iak info` or `tpm idevid info`.
type statusClients struct {
	tpm    *tpmsvc.Client
	idevid *idevidsvc.Client
}

func runStatus(flags *cli.CommonFlags, opts statusOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	clients := statusClients{
		tpm:    tpmsvc.NewClientFromGRPC(base.Client().TPM()),
		idevid: idevidsvc.NewClientFromGRPC(base.Client().IDevID()),
	}
	report := buildStatusReport(base.Context(), clients, opts)

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(report)
	case cli.OutputFormatTable:
		return printStatusTable(printer, report)
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// buildStatusReport gathers every row of the status report. It never
// returns an error: a failed lookup is recorded on its row so the rest
// of the report still renders.
func buildStatusReport(ctx context.Context, clients statusClients, opts statusOptions) *tpmStatusReport {
	report := &tpmStatusReport{
		Objects: make([]tpmObjectStatus, 0, 5),
	}

	if info, err := clients.tpm.InfoDomain(ctx); err == nil && info != nil && info.Properties != nil {
		// Properties is a free-form map keyed on TPM spec property
		// names; surface the most common ones for operator context.
		report.Manufacturer = info.Properties["manufacturer"]
		report.Vendor = info.Properties["vendor"]
		report.FirmwareVersion = info.Properties["firmware_version"]
		if report.FirmwareVersion == "" {
			report.FirmwareVersion = info.Properties["firmware"]
		}
	}

	report.Objects = append(report.Objects, ekStatus(ctx, clients.tpm))
	report.Objects = append(report.Objects, srkStatus(ctx, clients.tpm, srkRow{
		name:   "SSRK",
		role:   "Storage-hierarchy Storage Root Key",
		handle: 0,
	}))
	report.Objects = append(report.Objects, srkStatus(ctx, clients.tpm, srkRow{
		name:   "PlatformSRK",
		role:   "Platform-hierarchy SRK (Platform KeyStore parent)",
		handle: opts.PlatformSRKHandle,
		note:   platformSRKHandleNote(opts),
	}))
	report.Objects = append(report.Objects, deviceKeyStatus(ctx, deviceKeyRow{
		name:              "IAK",
		role:              "Initial Attestation Key",
		absentHint:        "run `tpm iak generate` then `tpm iak certificate`",
		requireRestricted: true,
		has:               clients.idevid.HasIAK,
		info:              clients.idevid.GetIAKInfoDomain,
		cert:              clients.idevid.GetIAKCertificateDomain,
	}))
	report.Objects = append(report.Objects, deviceKeyStatus(ctx, deviceKeyRow{
		name:       "IDevID",
		role:       "Initial Device Identifier",
		absentHint: "run `tpm idevid generate` then `tpm idevid certificate`",
		has:        clients.idevid.HasIDevID,
		info:       clients.idevid.GetIDevIDInfoDomain,
		cert:       clients.idevid.GetIDevIDCertificateDomain,
	}))

	// PCR 23 (platform golden measurement): non-zero means platformd
	// provisioning completed its CreatePlatformPolicy step.
	if pcrs, err := clients.tpm.GetPCRsDomain(ctx, []uint32{23}, tpmsvc.PCRBankSHA256); err == nil && len(pcrs) > 0 && pcrs[0] != nil {
		hexStr := hex.EncodeToString(pcrs[0].Value)
		report.PCR23Hex = hexStr
		report.PCR23Extended = !isAllZeros(hexStr)
	}

	return report
}

// ekStatus probes the EK the way `tpm ek certificate` does: the daemon
// returns the certificate when platformd provisioned the EK.
func ekStatus(ctx context.Context, client *tpmsvc.Client) tpmObjectStatus {
	ek := tpmObjectStatus{Name: "EK", Role: "Endorsement Key (TCG manufacturer identity)"}
	resp, err := client.GetEKCertificateDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0)
	switch {
	case isNotFound(err):
		return ek
	case err != nil:
		ek.Error = shortErr(err)
		return ek
	case resp != nil && len(resp.Certificate) > 0:
		ek.HandlePresent = true
		ek.CertPresent = true
		ek.CertFormat = resp.Format
	}
	return ek
}

// srkRow describes one SRK row of the report.
type srkRow struct {
	name   string
	role   string
	handle uint32
	note   string
}

// srkStatus probes an SRK the way `tpm srk info --handle` does.
func srkStatus(ctx context.Context, client *tpmsvc.Client, row srkRow) tpmObjectStatus {
	obj := tpmObjectStatus{Name: row.name, Role: row.role, Note: row.note}
	if row.handle != 0 {
		// Record the probed handle even when the object is absent so the
		// operator can see which handle the verdict is about.
		obj.Handle = formatHandle(row.handle)
	}
	resp, err := client.GetSRKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, row.handle)
	switch {
	case isNotFound(err):
		return obj
	case err != nil:
		obj.Error = shortErr(err)
		return obj
	case resp != nil && resp.Handle != 0:
		obj.HandlePresent = true
		obj.Handle = formatHandle(resp.Handle)
	}
	return obj
}

// platformSRKHandleNote tells the operator where the probed PlatformSRK
// handle came from, because the CLI cannot read the daemon's TPM config.
func platformSRKHandleNote(opts statusOptions) string {
	if opts.PlatformSRKHandleExplicit {
		return "handle from --" + platformSRKHandleFlag
	}
	return "default handle assumed (daemon config not exposed); override with --" + platformSRKHandleFlag
}

// deviceKeyRow describes one TCG device-identity row (IAK or IDevID) and
// the SDK calls that back it. has/info/cert are the exact methods the
// `tpm iak info`, `tpm idevid info` and `... certificate` verbs use.
type deviceKeyRow struct {
	name       string
	role       string
	absentHint string
	// requireRestricted turns on the tcg-cap-verifiedTPMRestricted
	// verdict. It is set for the IAK only: the attestation verifier
	// requires the policy on the attestation key, not on the IDevID.
	requireRestricted bool
	has               func(ctx context.Context) (bool, error)
	info              func(ctx context.Context) (*idevidsvc.DeviceKeyInfo, error)
	cert              func(ctx context.Context) (*idevidsvc.DeviceIdentityCertificate, error)
}

// deviceKeyStatus probes an IAK or IDevID. Absence is established
// positively through the Has* RPC; every other failure is an error.
func deviceKeyStatus(ctx context.Context, row deviceKeyRow) tpmObjectStatus {
	obj := tpmObjectStatus{Name: row.name, Role: row.role}

	exists, err := row.has(ctx)
	if err != nil {
		obj.Error = shortErr(err)
		return obj
	}
	if !exists {
		obj.Note = row.absentHint
		return obj
	}

	info, err := row.info(ctx)
	switch {
	case isNotFound(err):
		obj.Note = row.absentHint
		return obj
	case err != nil:
		obj.Error = shortErr(err)
		return obj
	case info == nil:
		obj.Note = row.absentHint
		return obj
	}

	obj.HandlePresent = true
	obj.Handle = formatHandle(info.Handle)
	if !info.HasCertificate {
		return obj
	}
	obj.CertPresent = true
	if info.CertInfo != nil {
		obj.Issuer = info.CertInfo.IssuerCN
	}

	cert, err := row.cert(ctx)
	if err != nil || cert == nil {
		obj.Note = "certificate detail unavailable: " + shortErrOrNil(err)
		return obj
	}
	applyCertificatePolicies(&obj, cert.PEM, row.requireRestricted)
	return obj
}

// applyCertificatePolicies parses the certificate PEM and records its
// certificatePolicies OIDs. When requireRestricted is set it also records
// whether tcg-cap-verifiedTPMRestricted is present, using the same
// predicate as the attestation verifier.
func applyCertificatePolicies(obj *tpmObjectStatus, certPEM string, requireRestricted bool) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		obj.Note = "certificate unparseable: " + shortErr(err)
		return
	}
	if obj.Issuer == "" {
		obj.Issuer = cert.Issuer.CommonName
	}
	obj.CertPolicies = make([]string, 0, len(cert.Policies))
	for _, p := range cert.Policies {
		obj.CertPolicies = append(obj.CertPolicies, p.String())
	}
	if requireRestricted {
		restricted := vm.CarriesVerifiedTPMRestricted(cert)
		obj.VerifiedTPMRestricted = &restricted
	}
}

// parseCertificatePEM decodes a single PEM block into an X.509 certificate.
func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, ErrStatusCertificatePEM{}
	}
	return x509.ParseCertificate(block.Bytes)
}

// isNotFound reports whether err is the daemon positively saying the
// object does not exist. The SDK error types unwrap to the gRPC status,
// and the idevid client has dedicated not-found types for a nil payload.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var iakMissing *idevidsvc.ErrIAKNotFound
	var idevidMissing *idevidsvc.ErrIDevIDNotFound
	if errors.As(err, &iakMissing) || errors.As(err, &idevidMissing) {
		return true
	}
	return status.Code(err) == codes.NotFound
}

func formatHandle(handle uint32) string {
	return fmt.Sprintf("0x%08X", handle)
}

func shortErr(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		return msg[:117] + "..."
	}
	return msg
}

func shortErrOrNil(err error) string {
	if err == nil {
		return "empty response"
	}
	return shortErr(err)
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

// tpmObjectStatus is one row of the report. The pre-#471 fields keep their
// names; the fields after Error were added by #471 and are omitted when
// empty so existing consumers see the same document.
type tpmObjectStatus struct {
	Name          string `json:"name" yaml:"name"`
	Role          string `json:"role" yaml:"role"`
	HandlePresent bool   `json:"handle_present" yaml:"handle_present"`
	CertPresent   bool   `json:"cert_present" yaml:"cert_present"`
	CertFormat    string `json:"cert_format,omitempty" yaml:"cert_format,omitempty"`
	Error         string `json:"error,omitempty" yaml:"error,omitempty"`
	// Handle is the persistent handle in 0x%08X form when known.
	Handle string `json:"handle,omitempty" yaml:"handle,omitempty"`
	// Issuer is the certificate issuer CN when a certificate is installed.
	Issuer string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	// CertPolicies lists the certificatePolicies OIDs of the installed
	// certificate.
	CertPolicies []string `json:"cert_policies,omitempty" yaml:"cert_policies,omitempty"`
	// VerifiedTPMRestricted is set on the IAK row only: whether the
	// certificate carries tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3).
	VerifiedTPMRestricted *bool `json:"verified_tpm_restricted,omitempty" yaml:"verified_tpm_restricted,omitempty"`
	// Note carries operator guidance that is not an error: the absent-row
	// remedy, the probed PlatformSRK handle, or a certificate caveat.
	Note string `json:"note,omitempty" yaml:"note,omitempty"`
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

	printer.Println("")
	printer.Println(fmt.Sprintf("%-14s %-14s %-42s %s", "OBJECT", "HANDLE", "CERTIFICATE", "NOTES"))
	printer.Println(strings.Repeat("-", 100))
	for _, obj := range r.Objects {
		printer.Println(fmt.Sprintf("%-14s %-14s %-42s %s",
			obj.Name, handleColumn(obj), certificateColumn(obj), notesColumn(obj)))
	}
	return nil
}

// handleColumn renders present/absent/error. "absent" is reserved for a
// positive not-found answer; an error never masquerades as absence.
func handleColumn(obj tpmObjectStatus) string {
	switch {
	case obj.Error != "":
		return "error"
	case obj.HandlePresent:
		return "present"
	default:
		return "absent"
	}
}

// certificateColumn renders the certificate state, annotating an IAK
// certificate that the attestation verifier would reject.
func certificateColumn(obj tpmObjectStatus) string {
	if !obj.CertPresent {
		return "n/a"
	}
	cert := "present"
	if obj.CertFormat != "" {
		cert += " (" + obj.CertFormat + ")"
	}
	if obj.VerifiedTPMRestricted != nil && !*obj.VerifiedTPMRestricted {
		cert += " (" + verifiedTPMRestrictedNote + ")"
	}
	return cert
}

// notesColumn renders the error, or the role (absent rows only) followed by
// the handle, issuer, policy verdict and note that are known.
func notesColumn(obj tpmObjectStatus) string {
	if obj.Error != "" {
		return "error: " + obj.Error
	}
	parts := make([]string, 0, 5)
	if !obj.HandlePresent {
		parts = append(parts, obj.Role)
	}
	if obj.Handle != "" {
		parts = append(parts, obj.Handle)
	}
	if obj.Issuer != "" {
		parts = append(parts, "issuer "+obj.Issuer)
	}
	if obj.VerifiedTPMRestricted != nil && *obj.VerifiedTPMRestricted {
		parts = append(parts, "verifiedTPMRestricted")
	}
	if obj.Note != "" {
		parts = append(parts, obj.Note)
	}
	return strings.Join(parts, "; ")
}
