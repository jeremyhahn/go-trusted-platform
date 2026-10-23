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
	"context"
	"crypto/x509"
	"log/slog"
	"strings"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ControlPlaneTPM is the slice of the platform TPM the control-plane
// self-registration reads: the certificates the enrollment issued and the
// public areas of the keys they certify. The quicbaas SDK's
// TrustedPlatformModule satisfies it.
type ControlPlaneTPM interface {
	// EKCertificate returns the endorsement certificate.
	EKCertificate() (*x509.Certificate, error)
	// IAKCertificate returns the attestation-key certificate stored in the
	// TPM certificate store.
	IAKCertificate() (*x509.Certificate, error)
	// IDevIDCertificate returns the IDevID certificate stored in the TPM
	// certificate store.
	IDevIDCertificate() (*x509.Certificate, error)
	// IAKAttributes returns the attestation key's attributes, including its
	// TPMT_PUBLIC public area.
	IAKAttributes() (*xkmssdk.KeyAttributes, error)
	// IDevIDAttributes returns the IDevID signing key's attributes.
	IDevIDAttributes() (*xkmssdk.KeyAttributes, error)
	// EventLog returns the TCG boot event log.
	EventLog() ([]byte, error)
}

// ControlPlaneRegistrarConfig configures a ControlPlaneRegistrar.
type ControlPlaneRegistrarConfig struct {
	// TPM is the control plane's own TPM. Required.
	TPM ControlPlaneTPM
	// Devices is the registry to write into. Required.
	Devices Registrar
	// Model and Serial are the TCG product model and serial for this
	// machine, resolved by the caller exactly as the enrollment resolves
	// them (configured value first, else SMBIOS discovery). Serial is
	// required: it is the registry identity.
	Model  string
	Serial string
	// Logger is optional.
	Logger *slog.Logger
	// Now is the clock; nil uses time.Now in UTC.
	Now func() time.Time
}

// ControlPlaneRegistrar enrolls the control plane as a device in its own
// registry (#472, owner ruling 2026-09-06).
//
// # Why the control plane is an ordinary device record
//
// The attestation collector iterates device records. A control plane with
// no record is never collected, so the one machine that decides every other
// machine's verdict is the one machine nothing can attest — and the
// mutual-attestation design (docs/attestation/architecture.md) has no AK
// anchor or PCR baseline to distribute to nodes without it. Making the
// control plane a device is what closes that, and it must be the *same*
// kind of record, not a special case: a parallel "self report" path would
// be a second implementation of verification whose divergence nobody would
// notice until it mattered.
//
// # Why it does not enrol over ACME against itself
//
// The control plane already holds everything a TCG-CSR-IDEVID enrollment
// produces: its own CA issued its IAK and IDevID certificates from its own
// TPM during platform identity completion (pkg/app, CompletePlatformIdentity).
// Driving ACME at itself would re-run a ceremony whose output is already on
// disk, over a listener that is not up yet at that point in the boot. The
// registrar therefore reads the same material the finalize hook would have
// received and hands it to the same device.Register, so the two paths write
// identical records. It is idempotent by construction — find-or-create by
// product serial — which is also what lets an already-provisioned control
// plane acquire its record on the next restart rather than needing a
// re-install.
//
// # Fail closed
//
// A control plane with no attestation-key public area is refused
// (ErrControlPlaneNoAttestationKey) rather than registered: a record the
// collector will dial and can never verdict is worse than no record, because
// it reports "no evidence" forever while looking configured.
type ControlPlaneRegistrar struct {
	tpm     ControlPlaneTPM
	devices Registrar
	model   string
	serial  string
	logger  *slog.Logger
	now     func() time.Time
}

// NewControlPlaneRegistrar constructs the registrar. It fails closed on a
// missing TPM, registry or product serial.
func NewControlPlaneRegistrar(cfg ControlPlaneRegistrarConfig) (*ControlPlaneRegistrar, error) {
	if cfg.TPM == nil {
		return nil, ErrControlPlaneNoTPM{}
	}
	if cfg.Devices == nil {
		return nil, ErrRegistrationNoRegistrar{}
	}
	serial := strings.TrimSpace(cfg.Serial)
	if serial == "" {
		return nil, ErrRegistrationNoSerial{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ControlPlaneRegistrar{
		tpm:     cfg.TPM,
		devices: cfg.Devices,
		model:   strings.TrimSpace(cfg.Model),
		serial:  serial,
		logger:  logger,
		now:     now,
	}, nil
}

// Register reads the control plane's own TPM identity and writes it to the
// device registry through the shared enrollment path.
func (r *ControlPlaneRegistrar) Register(ctx context.Context) (*RegistrationResult, error) {
	reg, err := r.identity()
	if err != nil {
		return nil, err
	}
	result, err := Register(ctx, r.devices, reg, r.now())
	if err != nil {
		return nil, err
	}
	if result.AttestCertWarning != "" {
		r.logger.Warn("device registration: the control plane's attestation certificate was not recorded",
			"serial", r.serial,
			"reason", result.AttestCertWarning)
	}
	if result.LookupWarning != "" {
		r.logger.Warn("device registration: the control plane's existing record was not reused",
			"serial", r.serial,
			"reason", result.LookupWarning)
	}
	r.logger.Info("device registration: the control plane is a device in its own registry",
		"device_id", result.Device.ID,
		"created", result.Created,
		"serial", result.Device.Serial,
		"model", result.Device.Model,
		"hostname", result.Device.Hostname,
		"attest_cert", result.Device.AttestCert != "",
		"ek_cert", result.Device.EKCert != "")
	return result, nil
}

// identity assembles the registration from the TPM.
//
// The endorsement certificate, the IDevID certificate and the event log are
// best-effort: a TPM with no manufacturer EK certificate, a platform whose
// IDevID has not been issued, and a kernel that exposes no measurement log
// are all real and none of them stops the machine being attestable. The
// attestation key's public area is not optional — it is the anchor.
func (r *ControlPlaneRegistrar) identity() (Registration, error) {
	iakAttrs, err := r.tpm.IAKAttributes()
	if err != nil {
		return Registration{}, ErrControlPlaneIdentityUnavailable{Name: "attestation key", Cause: err}
	}
	attestPub := publicArea(iakAttrs)
	if len(attestPub) == 0 {
		return Registration{}, ErrControlPlaneNoAttestationKey{}
	}

	reg := Registration{
		Model:     r.model,
		Serial:    r.serial,
		AttestPub: attestPub,
	}

	if ekCert, err := r.tpm.EKCertificate(); err != nil {
		r.logger.Warn("device registration: the control plane's endorsement certificate is unavailable; registering without it",
			"error", err)
	} else {
		reg.EKCertPEM = EncodeCertificatePEM(ekCert)
	}

	if iakCert, err := r.tpm.IAKCertificate(); err != nil {
		// #374: the attestation certificate is the trust anchor the quote
		// verifier prefers. Without it the verifier falls back to the bare
		// public key, which is weaker but still verifies, so this is a
		// warning rather than a refusal — and `device attest-cert record`
		// is the operator's repair.
		r.logger.Warn("device registration: the control plane's attestation certificate is unavailable; the record will carry only the attestation public key",
			"error", err)
	} else {
		reg.AttestCertPEM = EncodeCertificatePEM(iakCert)
	}

	if idevidCert, err := r.tpm.IDevIDCertificate(); err != nil {
		r.logger.Warn("device registration: the control plane's IDevID certificate is unavailable; the record will carry no hostname",
			"error", err)
	} else if idevidCert != nil {
		reg.Hostname = strings.TrimSpace(idevidCert.Subject.CommonName)
		reg.IDevIDCertPEM = EncodeCertificatePEM(idevidCert)
	}

	if idevidAttrs, err := r.tpm.IDevIDAttributes(); err != nil {
		r.logger.Warn("device registration: the control plane's IDevID public area is unavailable; the record will carry no signing key",
			"error", err)
	} else {
		reg.SigningPub = publicArea(idevidAttrs)
	}

	if eventLog, err := r.tpm.EventLog(); err != nil {
		r.logger.Warn("device registration: the control plane's boot event log is unavailable; registering without it",
			"error", err)
	} else {
		reg.EventLog = eventLog
	}

	return reg, nil
}

// publicArea returns the key's TPMT_PUBLIC bytes — the same encoding the
// TCG-CSR-IDEVID carries as AttestPub and SigningPub, and the one
// vm.ParseAKPublicArea reads back off the device record.
func publicArea(attrs *xkmssdk.KeyAttributes) []byte {
	if attrs == nil || attrs.TPMAttributes == nil {
		return nil
	}
	return attrs.TPMAttributes.BPublic.Bytes()
}
