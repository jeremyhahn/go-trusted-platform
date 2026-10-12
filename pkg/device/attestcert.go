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
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// AttestationCertificateAuthority is the slice of the platform CA the
// attestation-certificate recorder consumes: the certificate store lookup,
// attestation-key re-issuance and the trust anchor the recorded certificate
// must chain to. The quicbaas SDK's CA surface satisfies it.
type AttestationCertificateAuthority interface {
	// CertificatePEM returns the certificate stored under cn.
	CertificatePEM(ctx context.Context, cn string) ([]byte, error)
	// IssueAKCertificate issues an attestation-key certificate over pubKey.
	IssueAKCertificate(ctx context.Context, request *quicbaasca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)
	// TrustedRoot returns the CA root certificate.
	TrustedRoot() (*x509.Certificate, error)
	// TrustedIntermediate returns the CA intermediate certificate, or nil.
	TrustedIntermediate() (*x509.Certificate, error)
	// Revoke revokes a certificate the CA issued, by serial, with an RFC 5280
	// reason code. The recorder uses it to withdraw a re-issued certificate
	// the preflight refused, so the CA does not accumulate non-compliant
	// attestation certificates.
	Revoke(ctx context.Context, serial *big.Int, reason int) error
}

// IAKCertificateReader is the CA store read the recorder prefers when the CA
// offers it: the IAK certificate under its own name, `iak-<model>-<serial>`,
// distinct from the IDevID record. go-xkms gains it with the fix for the
// CN collision (go-xkms#371, PR #383); the platform's CA handle satisfies it
// once the go-quicbaas re-export lands, and the recorder picks it up by this
// type assertion — an alias swap, no platform change. Until then the CA
// handle does not implement it and the recorder falls back to the CN
// lookups in attestCertCandidateNames.
type IAKCertificateReader interface {
	IAKCertificate(ctx context.Context, model, serial string) (*x509.Certificate, error)
}

// AttestCertClearer is the device-service write behind a clear. A generic
// Update cannot express it: Update keeps the stored certificate when the
// incoming one is empty (#252). ClearAttestCert removes the certificate only
// while the record still holds expected, and otherwise returns
// ErrAttestCertClearConflict. device.Service implements it.
type AttestCertClearer interface {
	ClearAttestCert(ctx context.Context, id uint64, expected string) error
}

// revocationReasonSuperseded is the RFC 5280 CRLReason for a certificate
// that is being replaced: a re-issued attestation certificate the preflight
// refused will be superseded by a compliant one once the CA stamps the
// attribute.
const revocationReasonSuperseded = 4

// AttestCertSource names where a recorded attestation certificate came from.
type AttestCertSource string

const (
	// AttestCertSourceDevice is the certificate already on the device record,
	// re-verified against the current CA and recorded unchanged.
	AttestCertSourceDevice AttestCertSource = "device"
	// AttestCertSourceCA is a certificate pulled from the platform CA's
	// certificate store under one of the device's identity names.
	AttestCertSourceCA AttestCertSource = "ca"
	// AttestCertSourceReissued is a certificate the CA issued during the
	// attempt over the device's enrolled attestation public key.
	AttestCertSourceReissued AttestCertSource = "reissued"
)

// AttestCertRecord describes a recorded attestation certificate.
type AttestCertRecord struct {
	DeviceID uint64
	Serial   string
	Model    string
	// Source is where the certificate came from; SourceDetail is the CA
	// store name it was found under when Source is AttestCertSourceCA.
	Source       AttestCertSource
	SourceDetail string
	// Changed is false when the device record already held this exact
	// certificate and nothing was written.
	Changed bool
	// Reissued is true when the CA was asked to issue a new certificate.
	Reissued bool
	// Cleared is true when every candidate was refused and, as the caller
	// asked with ClearOnRefusal, the certificate the record held was
	// removed. Source and CertificatePEM are then empty, Subject and
	// CertificateSerial name the removed certificate when it parsed, and
	// Refusal carries the refusal that justified the clear.
	Cleared           bool
	Refusal           string
	Subject           string
	CertificateSerial string
	NotAfter          time.Time
	CertificatePEM    string
}

// AttestCertRecordOptions are the caller's choices for one Record call.
type AttestCertRecordOptions struct {
	// Reissue lets the CA issue a fresh certificate over the enrolled
	// attestation public key when no stored candidate passes.
	Reissue bool
	// ClearOnRefusal removes the certificate the record holds when every
	// candidate — that certificate included — is refused. A record holding
	// a certificate that fails to verify is quarantined on every quote; one
	// holding none is only denied service. Off by default: a refusal writes
	// nothing.
	ClearOnRefusal bool
}

// AttestCertAttempt is one candidate the recorder evaluated and refused.
type AttestCertAttempt struct {
	Source AttestCertSource
	Detail string
	Err    error
}

// AttestCertRecorderOption configures an AttestCertRecorder.
type AttestCertRecorderOption func(*AttestCertRecorder)

// WithAttestCertAuditor supplies the sink that receives the audit event for
// every attempt. Nil means attempts are only logged.
func WithAttestCertAuditor(sink verdict.AttestCertSink) AttestCertRecorderOption {
	return func(r *AttestCertRecorder) { r.audit = sink }
}

// WithAttestCertLogger supplies the logger.
func WithAttestCertLogger(logger *slog.Logger) AttestCertRecorderOption {
	return func(r *AttestCertRecorder) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithAttestCertClock supplies the clock the certificate validity is checked
// against.
func WithAttestCertClock(now func() time.Time) AttestCertRecorderOption {
	return func(r *AttestCertRecorder) {
		if now != nil {
			r.now = now
		}
	}
}

// AttestCertRecorder records a device's attestation (IAK/AK) certificate on
// its platform record without re-enrolling the device.
//
// The recorded certificate is the trust anchor the device quote verifier
// uses (#374, #405): a certificate that chains to the platform CA but lacks
// tcg-cap-verifiedTPMRestricted is classified there as a cryptographic
// failure and quarantines the device, and one that certifies a key other
// than the device's attestation key fails every quote signature the same
// way. The recorder therefore fails closed: it writes only a certificate
// that parses, chains to the platform CA, carries the attribute and
// certifies the device's enrolled attestation public key — the same
// vm.VerifyAKCertificate the verifier runs, so the two agree by
// construction. There is no override.
type AttestCertRecorder struct {
	devices DeviceService
	ca      AttestationCertificateAuthority
	audit   verdict.AttestCertSink
	now     func() time.Time
	logger  *slog.Logger
}

// NewAttestCertRecorder constructs a recorder over the device service and
// the platform CA. Both are required.
func NewAttestCertRecorder(devices DeviceService, ca AttestationCertificateAuthority, opts ...AttestCertRecorderOption) (*AttestCertRecorder, error) {
	if devices == nil {
		return nil, ErrAttestCertRecorderDependency{Name: "device service"}
	}
	if ca == nil {
		return nil, ErrAttestCertRecorderDependency{Name: "certificate authority"}
	}
	r := &AttestCertRecorder{
		devices: devices,
		ca:      ca,
		now:     func() time.Time { return time.Now().UTC() },
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Record records the attestation certificate for the device.
//
// Candidates are evaluated in order and the first that passes the preflight
// is recorded: the certificate already on the device record; the platform
// CA's certificate store under the device's identity names; and, only when
// opts.Reissue is set, a certificate the CA issues over the device's enrolled
// attestation public key. Re-issuance does not involve the device: the
// enrollment already proved the key TPM-resident, and the recorder
// re-establishes from the recorded public area that it is a Restricted
// signing key before asking the CA. Whether the CA stamps
// tcg-cap-verifiedTPMRestricted is the CA's decision; a re-issued
// certificate without it is refused like any other.
//
// When no candidate passes, Record returns ErrAttestCertRefused naming every
// attempt and its reason, and the device record is untouched — unless
// opts.ClearOnRefusal is set and the record held a certificate. That
// certificate was then refused too, and keeping it quarantines the device on
// every quote, so it is removed and the returned record is Cleared: the
// device moves to an absent certificate and is denied service instead. Only a
// plain refusal clears; a CA failure, a missing enrolled key or a refused
// re-issue the CA could not revoke leaves the record untouched.
func (r *AttestCertRecorder) Record(ctx context.Context, deviceID uint64, opts AttestCertRecordOptions) (*AttestCertRecord, error) {
	if deviceID == 0 {
		return nil, ErrInvalidDeviceID
	}
	dev, err := r.devices.Get(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	rec, err := r.record(ctx, dev, opts.Reissue)
	if err != nil && opts.ClearOnRefusal {
		rec, err = clearRefused(dev, err)
	}
	if err == nil {
		if commitErr := r.commit(ctx, dev, rec); commitErr != nil {
			rec, err = nil, ErrAttestCertWriteFailed{DeviceID: dev.ID, Cause: commitErr}
		}
	}
	r.auditAttempt(ctx, dev, rec, opts.Reissue, err)
	return rec, err
}

// clearRefused turns a refusal into a clear of the certificate the record
// holds. It returns recErr unchanged when there is nothing to clear or when
// recErr is not a plain refusal. The type assertion is deliberate:
// ErrAttestCertReissuedRevokeFailed wraps a refusal, and errors.As would let
// a re-issue the CA could not withdraw clear the record.
func clearRefused(dev *entities.Device, recErr error) (*AttestCertRecord, error) {
	refused, ok := recErr.(ErrAttestCertRefused)
	existing := strings.TrimSpace(dev.AttestCert)
	if !ok || existing == "" {
		return nil, recErr
	}
	rec := &AttestCertRecord{
		DeviceID: dev.ID,
		Serial:   dev.Serial,
		Model:    dev.Model,
		Changed:  true,
		Reissued: refused.Reissued,
		Cleared:  true,
		Refusal:  refused.Error(),
	}
	if cert := parseFirstCertificate([]byte(existing)); cert != nil {
		rec.Subject = cert.Subject.String()
		rec.CertificateSerial = cert.SerialNumber.String()
		rec.NotAfter = cert.NotAfter
	}
	return rec, nil
}

func (r *AttestCertRecorder) record(ctx context.Context, dev *entities.Device, reissue bool) (*AttestCertRecord, error) {
	roots, intermediates, err := r.trustPools()
	if err != nil {
		return nil, err
	}
	area, err := r.enrolledPublicArea(dev)
	if err != nil {
		return nil, err
	}

	var attempts []AttestCertAttempt
	refuse := func(source AttestCertSource, detail string, cause error) {
		attempts = append(attempts, AttestCertAttempt{Source: source, Detail: detail, Err: cause})
	}

	// 1. The certificate already on the record.
	if existing := strings.TrimSpace(dev.AttestCert); existing != "" {
		cert, err := r.preflight([]byte(existing), roots, intermediates, area.PublicKey)
		if err == nil {
			return r.describe(dev, cert, AttestCertSourceDevice, "", false, false), nil
		}
		refuse(AttestCertSourceDevice, "", err)
	}

	// 2. The CA's certificate store: the IAK under its own name when the CA
	// can read it (IAKCertificateReader), then the CN lookups.
	var idevid *x509.Certificate
	if reader, ok := r.ca.(IAKCertificateReader); ok && dev.Model != "" && dev.Serial != "" {
		iakName := reissueCommonName(dev)
		cert, err := reader.IAKCertificate(ctx, dev.Model, dev.Serial)
		switch {
		case err != nil:
			refuse(AttestCertSourceCA, iakName, ErrAttestCertNotInStore{CN: iakName, Cause: err})
		case cert == nil:
			refuse(AttestCertSourceCA, iakName, ErrAttestCertNotInStore{CN: iakName})
		default:
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			verified, err := r.preflight(pemBytes, roots, intermediates, area.PublicKey)
			if err == nil {
				return r.describe(dev, verified, AttestCertSourceCA, iakName, false, true), nil
			}
			refuse(AttestCertSourceCA, iakName, err)
		}
	}
	for _, cn := range attestCertCandidateNames(dev) {
		pemBytes, err := r.ca.CertificatePEM(ctx, cn)
		if err != nil {
			refuse(AttestCertSourceCA, cn, ErrAttestCertNotInStore{CN: cn, Cause: err})
			continue
		}
		cert, err := r.preflight(pemBytes, roots, intermediates, area.PublicKey)
		if err == nil {
			return r.describe(dev, cert, AttestCertSourceCA, cn, false, true), nil
		}
		refuse(AttestCertSourceCA, cn, err)
		if idevid == nil {
			idevid = parseFirstCertificate(pemBytes)
		}
	}

	if !reissue {
		return nil, ErrAttestCertRefused{DeviceID: dev.ID, Attempts: attempts}
	}

	// 3. Re-issue from the enrolled public area.
	if err := area.VerifyRestrictedSigningKey(); err != nil {
		return nil, ErrAttestCertPublicAreaNotRestricted{DeviceID: dev.ID, Cause: err}
	}
	cert, err := r.ca.IssueAKCertificate(ctx, reissueRequest(dev, idevid), area.PublicKey)
	if err != nil {
		return nil, ErrAttestCertReissueFailed{DeviceID: dev.ID, Cause: err}
	}
	if cert == nil {
		return nil, ErrAttestCertReissueFailed{DeviceID: dev.ID, Cause: ErrAttestCertNotInStore{CN: reissueCommonName(dev)}}
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	verified, err := r.preflight(pemBytes, roots, intermediates, area.PublicKey)
	if err != nil {
		refuse(AttestCertSourceReissued, cert.Subject.CommonName, err)
		refused := ErrAttestCertRefused{DeviceID: dev.ID, Reissued: true, Attempts: attempts}
		// The CA stored what it issued. Withdraw it so the CA does not
		// accumulate attestation certificates the platform will never trust.
		if revokeErr := r.ca.Revoke(ctx, cert.SerialNumber, revocationReasonSuperseded); revokeErr != nil {
			return nil, ErrAttestCertReissuedRevokeFailed{
				DeviceID: dev.ID,
				Serial:   cert.SerialNumber.String(),
				Subject:  cert.Subject.String(),
				Refusal:  refused,
				Cause:    revokeErr,
			}
		}
		return nil, refused
	}
	return r.describe(dev, verified, AttestCertSourceReissued, cert.Subject.CommonName, true, true), nil
}

// preflight is the fail-closed gate: parse, chain, tcg-cap-verifiedTPMRestricted
// (all three via the verifier's own VerifyAKCertificate) and then that the
// certified key is the device's enrolled attestation key.
func (r *AttestCertRecorder) preflight(certPEM []byte, roots, intermediates *x509.CertPool, expected crypto.PublicKey) (*x509.Certificate, error) {
	certified, err := vm.VerifyAKCertificate(certPEM, roots, intermediates, r.now())
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(certified, expected) {
		return nil, ErrAttestCertKeyMismatch{}
	}
	cert := parseFirstCertificate(certPEM)
	if cert == nil {
		return nil, vm.ErrAKCertificateInvalid{Reason: "not a PEM CERTIFICATE block"}
	}
	return cert, nil
}

// describe writes the certificate to the device record when it differs from
// what is already there and returns the record.
func (r *AttestCertRecorder) describe(dev *entities.Device, cert *x509.Certificate, source AttestCertSource, detail string, reissued, write bool) *AttestCertRecord {
	rec := &AttestCertRecord{
		DeviceID:          dev.ID,
		Serial:            dev.Serial,
		Model:             dev.Model,
		Source:            source,
		SourceDetail:      detail,
		Reissued:          reissued,
		Subject:           cert.Subject.String(),
		CertificateSerial: cert.SerialNumber.String(),
		NotAfter:          cert.NotAfter,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	rec.Changed = write && strings.TrimSpace(dev.AttestCert) != strings.TrimSpace(rec.CertificatePEM)
	return rec
}

// commit is the write half. Only Record calls it, and only after record
// returned without error, so a refusal never reaches the device DAO. A
// cleared record — the one refusal the caller asked to act on — goes through
// the compare-and-clear write, never through Update.
func (r *AttestCertRecorder) commit(ctx context.Context, dev *entities.Device, rec *AttestCertRecord) error {
	if !rec.Changed {
		return nil
	}
	if rec.Cleared {
		clearer, ok := r.devices.(AttestCertClearer)
		if !ok {
			return ErrAttestCertClearUnsupported{}
		}
		return clearer.ClearAttestCert(ctx, dev.ID, dev.AttestCert)
	}
	dev.AttestCert = rec.CertificatePEM
	return r.devices.Update(ctx, dev)
}

// auditAttempt emits the audit event for the attempt. An audit failure is
// logged, never returned: the device record is already what the result
// says it is.
func (r *AttestCertRecorder) auditAttempt(ctx context.Context, dev *entities.Device, rec *AttestCertRecord, reissue bool, recErr error) {
	if r.audit == nil {
		return
	}
	ev := verdict.AttestCertEvent{
		DeviceID: dev.ID,
		HostID:   dev.Hostname,
		Serial:   dev.Serial,
		Reissued: reissue && reissueWasAttempted(rec, recErr),
	}
	switch {
	case recErr == nil && rec != nil && rec.Cleared:
		ev.Cleared = true
		ev.Subject = rec.Subject
		ev.Reason = rec.Refusal
	case recErr == nil && rec != nil:
		ev.Recorded = true
		ev.Source = string(rec.Source)
		ev.Subject = rec.Subject
	case recErr != nil:
		ev.Reason = recErr.Error()
	}
	if err := r.audit.RecordAttestCert(ctx, ev); err != nil {
		r.logger.Error("attestation certificate record event could not be written",
			"device_id", dev.ID,
			"recorded", ev.Recorded,
			"cleared", ev.Cleared,
			"error", err,
		)
	}
}

// trustPools builds the verification pools from the platform CA. No root
// means no certificate can be chained, which refuses every candidate.
func (r *AttestCertRecorder) trustPools() (*x509.CertPool, *x509.CertPool, error) {
	root, err := r.ca.TrustedRoot()
	if err != nil {
		return nil, nil, ErrAttestCertTrustAnchorUnavailable{Cause: err}
	}
	if root == nil {
		return nil, nil, ErrAttestCertTrustAnchorUnavailable{}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	var intermediates *x509.CertPool
	if intermediate, err := r.ca.TrustedIntermediate(); err == nil && intermediate != nil {
		intermediates = x509.NewCertPool()
		intermediates.AddCert(intermediate)
	}
	return roots, intermediates, nil
}

// enrolledPublicArea parses the attestation public area recorded at
// enrollment. Without it no certificate can be tied to the device's key, and
// a certificate over some other key would fail every quote signature and
// quarantine the device, so its absence refuses the attempt.
func (r *AttestCertRecorder) enrolledPublicArea(dev *entities.Device) (*vm.AKPublicArea, error) {
	raw := strings.TrimSpace(dev.AttestPub)
	if raw == "" {
		return nil, ErrAttestCertNoAttestPub{DeviceID: dev.ID}
	}
	tpmtPublic, err := hex.DecodeString(raw)
	if err != nil {
		return nil, ErrAttestCertAttestPubInvalid{DeviceID: dev.ID, Cause: err}
	}
	area, err := vm.ParseAKPublicArea(tpmtPublic)
	if err != nil {
		return nil, ErrAttestCertAttestPubInvalid{DeviceID: dev.ID, Cause: err}
	}
	return area, nil
}

// attestCertCandidateNames lists the names the CA may hold the device's
// certificates under, in lookup order: the IDevID CN as enrolled (the device
// hostname), the TCG-CSR-IDEVID subject `<model>-<serial>` the ACME
// finalize path issues both certificates under, and `iak-<model>-<serial>`,
// the distinct IAK name that path computes (go-xkms#371).
func attestCertCandidateNames(dev *entities.Device) []string {
	var names []string
	seen := map[string]struct{}{}
	add := func(cn string) {
		cn = strings.TrimSpace(cn)
		if cn == "" {
			return
		}
		if _, dup := seen[cn]; dup {
			return
		}
		seen[cn] = struct{}{}
		names = append(names, cn)
	}
	add(dev.Hostname)
	if dev.Model != "" && dev.Serial != "" {
		add(fmt.Sprintf("%s-%s", dev.Model, dev.Serial))
	}
	add(reissueCommonName(dev))
	return names
}

// reissueCommonName is the subject CN of a re-issued IAK certificate. It is
// distinct from the IDevID CN because the CA's certificate store keys by
// CN, and issuing under the IDevID name would overwrite the CA's IDevID
// record (go-xkms#371). The verifier does not consult the subject.
func reissueCommonName(dev *entities.Device) string {
	if dev.Model == "" || dev.Serial == "" {
		return ""
	}
	return fmt.Sprintf("iak-%s-%s", dev.Model, dev.Serial)
}

// reissueRequest builds the CA request for a re-issued IAK certificate. The
// non-CN subject attributes are copied from the device's IDevID certificate
// when the CA store still holds it, so the re-issued certificate carries the
// organisation the enrollment did.
func reissueRequest(dev *entities.Device, idevid *x509.Certificate) *quicbaasca.CACertificateRequest {
	req := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{CommonName: reissueCommonName(dev)},
	}
	if idevid != nil {
		req.Subject.Organization = first(idevid.Subject.Organization)
		req.Subject.OrganizationalUnit = first(idevid.Subject.OrganizationalUnit)
		req.Subject.Country = first(idevid.Subject.Country)
		req.Subject.Province = first(idevid.Subject.Province)
		req.Subject.Locality = first(idevid.Subject.Locality)
	}
	return req
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// reissueWasAttempted reports whether the attempt reached the CA's issuer:
// either a re-issued certificate was recorded, or the refusal names one.
func reissueWasAttempted(rec *AttestCertRecord, err error) bool {
	if rec != nil && rec.Reissued {
		return true
	}
	var refused ErrAttestCertRefused
	if errors.As(err, &refused) {
		return refused.Reissued
	}
	var failed ErrAttestCertReissueFailed
	if errors.As(err, &failed) {
		return true
	}
	var revoke ErrAttestCertReissuedRevokeFailed
	return errors.As(err, &revoke)
}

func parseFirstCertificate(pemBytes []byte) *x509.Certificate {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// publicKeysEqual compares two public keys through the crypto.PublicKey
// Equal contract every standard-library key type implements.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || b == nil {
		return false
	}
	return eq.Equal(b)
}
