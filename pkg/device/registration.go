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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// Registrar is the minimal device-registry surface a registration needs:
// find the device by its product serial, then create or update it. It is
// defined narrowly so the ACME finalize hook, the control-plane
// self-registration and their tests all satisfy it without a datastore.
type Registrar interface {
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)
	Save(ctx context.Context, device *entities.Device) error
	Update(ctx context.Context, device *entities.Device) error
}

// Registration is the identity material one enrollment writes onto a
// platform device record.
//
// It is deliberately the TCG-CSR-IDEVID field set, because that is what an
// enrollment proves: the endorsement certificate that identifies the TPM,
// the attestation key's public area and the certificate the CA issued over
// it, the IDevID signing key's public area, and the boot event log. Two
// callers fill it — the ACME order-finalize hook from the CA's
// `TCGEnrollmentData`, and the control plane from its own TPM (#472) — and
// both then take the same path into the registry, so a device the platform
// enrolled and the control plane itself are the same kind of record.
type Registration struct {
	// Model and Serial are the TCG product model and serial. Serial is the
	// registry's identity for find-or-create and is required.
	Model  string
	Serial string
	// Hostname is the IDevID Common Name. Optional: the ACME path leaves it
	// to the DNS registration hook, the control plane sets it from its own
	// IDevID certificate.
	Hostname string
	// EKCertPEM is the PEM endorsement certificate.
	EKCertPEM string
	// AttestCertPEM is the PEM attestation (IAK) certificate the CA issued.
	// It is the trust anchor the device quote verifier uses (#374, #404).
	AttestCertPEM string
	// AttestPub is the attestation key's TPMT_PUBLIC public area.
	AttestPub []byte
	// SigningPub is the IDevID signing key's TPMT_PUBLIC public area.
	SigningPub []byte
	// EventLog is the TCG boot event log captured at enrollment.
	EventLog []byte
}

// RegistrationResult reports what a registration did.
type RegistrationResult struct {
	// Device is the stored record as it now stands.
	Device *entities.Device
	// Created is true when the record did not exist and was allocated.
	Created bool
	// LookupWarning explains why the serial lookup produced no existing
	// record when something came back: a storage failure that was treated
	// as a miss, or an index hit whose serial disagreed with the query.
	// Empty in the ordinary case. Callers log it; the registration itself
	// never fails on it, because both cases end in a usable record.
	LookupWarning string
}

// Register materialises an enrolled device in the platform registry.
//
// It is find-or-create by product serial, and every field it writes is
// written only when the registration carries it: a re-enrollment that omits
// the event log must not erase the one already recorded.
//
// The serial lookup is verified rather than trusted. The qrdb-backed
// DeviceDAO's secondary-index path can return a record without checking the
// key actually matches — an incomplete index yields the first record of the
// entity type — so a returned record whose serial disagrees is treated as a
// miss and a new record is created. A lookup error that is not a not-found
// is also treated as a miss rather than failing the enrollment, because
// refusing to register a device the platform just issued certificates to
// leaves the fleet with an identity nothing can join against.
func Register(ctx context.Context, registrar Registrar, reg Registration, now time.Time) (*RegistrationResult, error) {
	if registrar == nil {
		return nil, ErrRegistrationNoRegistrar{}
	}
	serial := strings.TrimSpace(reg.Serial)
	if serial == "" {
		return nil, ErrRegistrationNoSerial{}
	}
	reg.Serial = serial
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var warning string
	existing, err := registrar.FindBySerial(ctx, serial)
	if err != nil && !IsRecordNotFound(err) {
		warning = "the serial lookup failed and was treated as a miss: " + err.Error()
		existing = nil
	}
	if existing != nil && existing.Serial != serial {
		warning = "the serial lookup returned a record for " + strconv.Quote(existing.Serial) +
			"; treating as a miss rather than overwriting an unrelated device"
		existing = nil
	}

	if existing != nil && existing.ID != 0 {
		reg.apply(existing, now)
		if err := registrar.Update(ctx, existing); err != nil {
			return nil, ErrRegistrationUpdateFailed{Serial: serial, Cause: err}
		}
		return &RegistrationResult{Device: existing, LookupWarning: warning}, nil
	}

	dev := &entities.Device{
		ID:        NewID(),
		Serial:    serial,
		State:     entities.DeviceStateRegistered,
		CreatedAt: now,
	}
	reg.apply(dev, now)
	if err := registrar.Save(ctx, dev); err != nil {
		return nil, ErrRegistrationSaveFailed{Serial: serial, Cause: err}
	}
	return &RegistrationResult{Device: dev, Created: true, LookupWarning: warning}, nil
}

// apply copies the registration onto the record. Empty values are skipped
// so a partial re-enrollment never erases material an earlier one proved.
func (r Registration) apply(dev *entities.Device, now time.Time) {
	dev.Model = r.Model
	dev.Serial = r.Serial
	if r.Hostname != "" {
		dev.Hostname = r.Hostname
	}
	if r.EKCertPEM != "" {
		dev.EKCert = r.EKCertPEM
	}
	if r.AttestCertPEM != "" {
		dev.AttestCert = r.AttestCertPEM
	}
	if len(r.AttestPub) > 0 {
		dev.AttestPub = hex.EncodeToString(r.AttestPub)
	}
	if len(r.SigningPub) > 0 {
		dev.SigningPub = hex.EncodeToString(r.SigningPub)
	}
	if len(r.EventLog) > 0 {
		dev.EventLog = r.EventLog
	}
	dev.State = entities.DeviceStateRegistered
	dev.UpdatedAt = now
}

// EncodeCertificatePEM PEM-encodes a parsed certificate, returning "" when
// there is nothing to encode. The device record stores certificates as PEM
// strings, which is what every API client already expects.
func EncodeCertificatePEM(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	return EncodeCertificateDERPEM(cert.Raw)
}

// EncodeCertificateDERPEM PEM-encodes a DER certificate, returning "" when
// the input is empty. The IAK certificate reaches the ACME finalize hook as
// raw DER (TCGEnrollmentData.IAKCertificateDER) rather than a parsed
// certificate.
func EncodeCertificateDERPEM(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// IsRecordNotFound is a heuristic that detects storage-layer "no rows"
// errors. Not-found errors get wrapped through several layers (qrdb ->
// baas-transport -> sdk -> service) and the device service exposes no
// canonical sentinel, so the textual signatures the layers use today are
// matched after the cheap errors.Is path.
func IsRecordNotFound(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range knownNotFoundErrors {
		if errors.Is(err, target) {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range notFoundSignatures {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// notFoundSignatures are the textual not-found markers the storage layers
// use. Deliberately short: it is expanded as new signatures appear rather
// than widened to swallow arbitrary errors.
var notFoundSignatures = []string{"not found", "no such", "does not exist", "no rows"}

// knownNotFoundErrors collects the sentinels the device service surfaces
// today. Empty, and expanded as sentinels are added rather than by guessing.
var knownNotFoundErrors []error
