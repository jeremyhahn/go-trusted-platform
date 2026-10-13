// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"log/slog"
	"strconv"
	"time"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// Compile-time contract checks.
var (
	_ bmcattestation.AttestationProvider = (*Backend)(nil)
	_ CertAttester                       = (*Backend)(nil)
)

// oidUCCSEvidence is tcg-dice-UCCS-evidence, TCG DICE Attestation
// Architecture r23 §6.1.4. Its PRESENCE is all this package reads; the claims
// set inside it is go-xkms's to decode.
var oidUCCSEvidence = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 6}

// CertAttester is implemented by a backend that can mint an enrolment-time
// alias certificate.
//
// It is a separate one-method interface rather than a seventh method on
// [bmcattestation.AttestationProvider], because a BMC has no enrolment
// ceremony and widening the shared contract for one backend would leave every
// other backend with a method it must refuse. A caller that needs enrolment
// asks for this interface; a caller that only appraises does not learn it
// exists.
type CertAttester interface {
	// AttestCert asks the device to mint an alias certificate carrying the
	// enrolment challenge, and returns it as opaque evidence.
	AttestCert(ctx context.Context, nonce []byte) (*bmcattestation.Evidence, error)
}

// Backend is one attached trusted-firmware device, presented as an attestation
// provider for one tenant.
//
// It holds the device's CAPS reply, read once at construction and never
// re-read, and the element serial when the part has a secure element. Both
// describe what the device IS, and a backend that had to ask again on every
// call would have to invent an answer whenever the device did not reply — an
// invented answer about the strength of a root of trust. Asking once means a
// backend either exists and knows what it is talking to, or does not exist.
//
// The link belongs to whoever opened it. This type does not close it.
type Backend struct {
	config *Config
	device *tfw.Device
	caps   tfw.Caps
	logger *slog.Logger

	// elementSerial is the secure element's nine-byte serial, hex-encoded,
	// or "" on a device with no element.
	elementSerial string

	timeout time.Duration
	now     func() time.Time
}

// New attaches a backend to an already-open device.
//
// Construction reads CAPS, so it fails when the device is not there, does not
// answer, or shipped without the attestation command compiled in. On a
// secure-element part it also reads PROV_INFO, which writes nothing and is
// what binds recorded evidence to a specific piece of silicon; a
// secure-element device that cannot say which element it holds is refused
// rather than recorded anonymously.
func New(ctx context.Context, config *Config, device *tfw.Device) (*Backend, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrNilDevice{}
	}

	b := &Backend{
		config:  config,
		device:  device,
		logger:  config.logger().With("component", "avr_attestation", "tenant", config.TenantID),
		timeout: config.requestTimeout(),
		now:     config.clock(),
	}

	callCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	caps, err := device.Caps(callCtx)
	if err != nil {
		return nil, b.deviceFailure(bmcattestation.ActionGetInfo, "CAPS", err)
	}
	if caps == nil {
		return nil, bmcattestation.ErrInvalidEvidence{Reason: "device returned no capabilities"}
	}
	b.caps = *caps

	if !caps.Has(tfw.FeatureAttest) {
		return nil, ErrAttestationNotCompiledIn{
			BoardID:    uint8(caps.BoardID),
			CryptoTier: caps.CryptoTier.String(),
		}
	}

	if caps.CryptoTier == tfw.CryptoSecureElement {
		info, err := device.ProvInfo(callCtx)
		if err != nil {
			return nil, b.deviceFailure(bmcattestation.ActionGetInfo, "PROV_INFO", err)
		}
		b.elementSerial = hexOrEmpty(info.Serial[:])
	}

	b.logger.Info("avr attestation provider attached",
		"device_ref", config.DeviceRef,
		"platform", config.Platform,
		"board_id", caps.BoardID,
		"crypto_tier", caps.CryptoTier.String(),
		"protocol", b.protocolVersion(),
		"firmware", b.firmwareVersion(),
		"element_serial", b.elementSerial,
	)
	return b, nil
}

// TenantID reports the tenant this provider is bound to.
func (b *Backend) TenantID() string { return b.config.TenantID }

// Caps reports the device's capabilities as read at construction.
func (b *Backend) Caps() tfw.Caps { return b.caps }

// Dump asks the device for nonce-bound runtime evidence.
//
// The nonce is the VERIFIER's and this backend never generates one: freshness
// on a device with no clock is the challenge and nothing else. A nonce of the
// wrong width is refused here, before a frame is built, because the device's
// other challenge is 32 bytes and a device handed the wrong one cannot tell
// it was truncated.
//
// The returned Raw is exactly the bytes the device sent. CreatedAt is stamped
// by THIS gateway at relay time — the device contributed no time and this
// field must never be read as one it did.
func (b *Backend) Dump(ctx context.Context, nonce []byte) (*bmcattestation.Evidence, error) {
	if len(nonce) != tfw.AttestNonceLen {
		return nil, ErrNonceLength{Flow: "runtime", Got: len(nonce), Want: tfw.AttestNonceLen}
	}

	callCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	raw, err := b.device.Attest(callCtx, nonce)
	if err != nil {
		return nil, b.deviceFailure(bmcattestation.ActionDump, "ATTEST", err)
	}
	if len(raw) != tfw.EvidenceLen {
		return nil, ErrEvidenceLength{Got: len(raw), Want: tfw.EvidenceLen}
	}

	return b.wrap(ActionDump, FormatFrame, nonce, raw), nil
}

// AttestCert asks the device to mint an alias certificate carrying the
// enrolment challenge.
//
// The device builds and signs the whole certificate, so what comes back is a
// document the device determined. This backend relays the DER verbatim: a
// re-encoding is a different document and the signature is over the original.
//
// The challenge is 32 bytes and is SHA-256 of the ACME key authorization when
// this is driven by device-attest-01. THIS FUNCTION DOES NOT HASH — a caller
// that passed a raw key authorization is refused for its width rather than
// quietly enrolled against something else.
func (b *Backend) AttestCert(ctx context.Context, nonce []byte) (*bmcattestation.Evidence, error) {
	if len(nonce) != tfw.AliasNonceLen {
		return nil, ErrNonceLength{Flow: "enrolment", Got: len(nonce), Want: tfw.AliasNonceLen}
	}

	callCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	der, err := b.device.AttestCert(callCtx, nonce)
	if err != nil {
		return nil, b.deviceFailure(ActionAttestCert, "ATTEST_CERT", err)
	}
	if len(der) == 0 {
		return nil, bmcattestation.ErrInvalidEvidence{Reason: "device returned an empty alias certificate"}
	}

	return b.wrap(ActionAttestCert, FormatDICE, nonce, der), nil
}

// List enumerates evidence already present on the device.
//
// There is never any. The device regenerates evidence per nonce and caches
// nothing: no part in this family has room to hold the document, which is the
// same reason both attestation commands page. This is a terminal condition,
// not a deferred implementation.
func (b *Backend) List(ctx context.Context) ([]bmcattestation.EvidenceMetadata, error) {
	return nil, b.noEvidenceStore(bmcattestation.ActionList)
}

// Download retrieves stored evidence by ID. See [Backend.List]: there is no
// evidence store to retrieve from.
func (b *Backend) Download(ctx context.Context, id string) (*bmcattestation.Evidence, error) {
	return nil, b.noEvidenceStore(bmcattestation.ActionDownload)
}

// Delete removes stored evidence. See [Backend.List]: there is no evidence
// store to delete from.
func (b *Backend) Delete(ctx context.Context, id string) error {
	return b.noEvidenceStore(bmcattestation.ActionDelete)
}

// GetInfo parses opaque evidence into a structured measurement.
//
// THIS IS THE SINGLE PARSE POINT. Nothing else in this package reads
// Evidence.Raw — Compare and Verify both come through here — so there is one
// place where the wire layout is known and one place a layout change lands.
//
// Every byte slice in the result is copied out of Raw, so a caller cannot
// reach back through a Measurement and alter the evidence.
func (b *Backend) GetInfo(ctx context.Context, ev *bmcattestation.Evidence) (*bmcattestation.Measurement, error) {
	if ev == nil {
		return nil, bmcattestation.ErrInvalidEvidence{Reason: "nil evidence"}
	}
	if ev.Vendor != Vendor {
		return nil, bmcattestation.ErrInvalidEvidence{
			Reason: "evidence vendor " + strconv.Quote(string(ev.Vendor)) +
				" is not " + strconv.Quote(string(Vendor)),
		}
	}
	if err := b.checkTenant(ev); err != nil {
		return nil, err
	}

	switch ev.Action {
	case ActionDump:
		return b.measureFrame(ev)
	case ActionAttestCert:
		return b.measureCertificate(ev)
	default:
		return nil, ErrUnsupportedAction{Action: ev.Action}
	}
}

// Compare runs the golden-build comparison between live evidence and a known
// good reference.
//
// SIGNIFICANT fields are the ones a golden build fixes: the frame version,
// the device identity, the signature algorithm, and the application
// measurement. The nonce, boot count, uptime and signature are excluded
// BY DESIGN — they differ between any two readings of a healthy device, and
// a comparison that flagged them would report every device as drifted.
//
// Only evidence frames compare. An alias certificate's comparable content is
// its UCCS claims set, and decoding that belongs to go-xkms.
func (b *Backend) Compare(ctx context.Context, live, ref *bmcattestation.Evidence) (*bmcattestation.CompareResult, error) {
	if live == nil || ref == nil {
		return nil, bmcattestation.ErrInvalidEvidence{Reason: "compare requires both live and reference evidence"}
	}
	if live.Action != ActionDump || ref.Action != ActionDump {
		return nil, ErrUnsupportedCompare{Live: live.Action, Ref: ref.Action}
	}

	liveInfo, err := b.GetInfo(ctx, live)
	if err != nil {
		return nil, err
	}
	refInfo, err := b.GetInfo(ctx, ref)
	if err != nil {
		return nil, err
	}

	var diffs []bmcattestation.Difference
	compare := func(field, got, want string) {
		if got != want {
			diffs = append(diffs, bmcattestation.Difference{Field: field, Live: got, Ref: want})
		}
	}
	compare(AttrFrameVersion, liveInfo.Attributes[AttrFrameVersion], refInfo.Attributes[AttrFrameVersion])
	compare(AttrDeviceID, liveInfo.Attributes[AttrDeviceID], refInfo.Attributes[AttrDeviceID])
	compare(AttrAlgorithm, liveInfo.Attributes[AttrAlgorithm], refInfo.Attributes[AttrAlgorithm])
	compare("pcr["+strconv.FormatUint(uint64(PCRApplication), 10)+"]",
		hexOrEmpty(liveInfo.PCRBank[PCRApplication]),
		hexOrEmpty(refInfo.PCRBank[PCRApplication]))

	return &bmcattestation.CompareResult{Match: len(diffs) == 0, Differences: diffs}, nil
}

// measureFrame parses a signed evidence frame.
func (b *Backend) measureFrame(ev *bmcattestation.Evidence) (*bmcattestation.Measurement, error) {
	f, err := parseFrame(ev.Raw)
	if err != nil {
		return nil, err
	}

	m := b.newMeasurement(ev)
	m.NonceEcho = f.nonce
	m.Digest = contentDigest(ev.Raw)
	// PCRBootloader is absent, not zero: a verifier must be able to tell
	// "not reported" from "reported as zeroes", and an all-zero FWHash is
	// exactly what an unprovisioned device sends.
	m.PCRBank = map[uint32][]byte{PCRApplication: f.fwHash}
	m.Attributes[AttrFrameVersion] = strconv.Itoa(int(f.version))
	m.Attributes[AttrDeviceID] = hexOrEmpty(f.deviceID)
	m.Attributes[AttrBootCount] = strconv.FormatUint(uint64(f.bootCount), 10)
	m.Attributes[AttrUptimeMillis] = strconv.FormatUint(uint64(f.uptimeMs), 10)
	m.Attributes[AttrAlgorithm] = strconv.Itoa(int(f.algorithm))
	m.Attributes[AttrSignature] = hexOrEmpty(f.signature)
	return m, nil
}

// measureCertificate parses an alias certificate.
//
// NonceEcho is left nil. The challenge is inside the UCCS claims set, this
// package does not decode that, and reporting a nonce it had not read would
// be reporting a check it had not performed. Nonce verification on this path
// is dice.Verify's, through go-xkms.
func (b *Backend) measureCertificate(ev *bmcattestation.Evidence) (*bmcattestation.Measurement, error) {
	leaf, err := x509.ParseCertificate(ev.Raw)
	if err != nil {
		return nil, bmcattestation.ErrAttestationFailed{
			Vendor: Vendor,
			Action: bmcattestation.ActionGetInfo,
			Reason: "alias certificate does not parse",
			Cause:  err,
		}
	}

	m := b.newMeasurement(ev)
	m.CertChain = []*x509.Certificate{leaf}
	m.Digest = contentDigest(ev.Raw)
	m.Attributes[AttrCertSubject] = leaf.Subject.String()
	m.Attributes[AttrCertIssuer] = leaf.Issuer.String()
	m.Attributes[AttrCertSerial] = leaf.SerialNumber.String()
	m.Attributes[AttrUCCSPresent] = strconv.FormatBool(hasUCCSEvidence(leaf))
	return m, nil
}

// newMeasurement builds the parts of a measurement that do not depend on the
// evidence format.
//
// CreatedAt is left ZERO. The contract documents it as the vendor-side
// generation time, and this device generated no time: the relay stamp lives
// on the Evidence, where it is visibly the gateway's.
func (b *Backend) newMeasurement(ev *bmcattestation.Evidence) *bmcattestation.Measurement {
	attrs := map[string]string{
		AttrTenantID:          b.config.TenantID,
		MetadataCryptoTier:    b.caps.CryptoTier.String(),
		MetadataBoardID:       strconv.Itoa(int(b.caps.BoardID)),
		MetadataFirmware:      b.firmwareVersion(),
		MetadataProtocol:      b.protocolVersion(),
		MetadataElementSerial: b.elementSerial,
	}
	if ev.Metadata[MetadataDeviceRef] != "" {
		attrs[MetadataDeviceRef] = ev.Metadata[MetadataDeviceRef]
	}
	return &bmcattestation.Measurement{
		Vendor:     Vendor,
		Attributes: attrs,
	}
}

// wrap builds the evidence envelope around bytes the device sent.
//
// Raw is the device's bytes, unmodified. Nonce is the challenge THIS host
// issued, never the device's echo of it — that is what makes a later echo
// check mean anything.
func (b *Backend) wrap(action bmcattestation.Action, format string, nonce, raw []byte) *bmcattestation.Evidence {
	metadata := map[string]string{
		MetadataTenantID:   b.config.TenantID,
		MetadataFormat:     format,
		MetadataCryptoTier: b.caps.CryptoTier.String(),
		MetadataBoardID:    strconv.Itoa(int(b.caps.BoardID)),
		MetadataFirmware:   b.firmwareVersion(),
		MetadataProtocol:   b.protocolVersion(),
	}
	if b.config.DeviceRef != "" {
		metadata[MetadataDeviceRef] = b.config.DeviceRef
	}
	if b.elementSerial != "" {
		metadata[MetadataElementSerial] = b.elementSerial
	}
	return &bmcattestation.Evidence{
		Vendor:    Vendor,
		Action:    action,
		Nonce:     clone(nonce),
		CreatedAt: b.now().UTC(),
		Raw:       raw,
		Metadata:  metadata,
	}
}

// checkTenant is the tenancy gate. Evidence with no tenant, or one that is
// not this provider's, is refused rather than appraised.
func (b *Backend) checkTenant(ev *bmcattestation.Evidence) error {
	if got := TenantOf(ev); got != b.config.TenantID {
		return ErrTenantMismatch{Want: b.config.TenantID, Got: got}
	}
	return nil
}

// noEvidenceStore builds the terminal refusal for the store-backed verbs.
func (b *Backend) noEvidenceStore(action bmcattestation.Action) error {
	return bmcattestation.ErrAttestationUnsupported{
		Vendor:   Vendor,
		Platform: b.config.Platform,
		Reason: string(action) + " needs a device-side evidence store; this device " +
			"regenerates evidence per nonce and caches none",
	}
}

// deviceFailure wraps an SDK error, naming the wire command that produced it.
func (b *Backend) deviceFailure(action bmcattestation.Action, command string, cause error) error {
	return bmcattestation.ErrAttestationFailed{
		Vendor: Vendor,
		Action: action,
		Reason: command + " failed on device " + strconv.Quote(b.config.DeviceRef),
		Cause:  cause,
	}
}

// protocolVersion renders the wire protocol version CAPS reported.
func (b *Backend) protocolVersion() string {
	return strconv.Itoa(int(b.caps.ProtoMajor)) + "." + strconv.Itoa(int(b.caps.ProtoMinor))
}

// firmwareVersion renders the firmware version CAPS reported.
func (b *Backend) firmwareVersion() string {
	return strconv.Itoa(int(b.caps.FirmwareMajor)) + "." +
		strconv.Itoa(int(b.caps.FirmwareMinor)) + "." +
		strconv.Itoa(int(b.caps.FirmwarePatch))
}

// contentDigest summarises an evidence blob for audit trails and dedupe.
//
// IT IS NOT A DEVICE MEASUREMENT. It is this host's hash of bytes it
// received, so it says two records hold the same document and nothing about
// what the device measured. The device's measurement is PCRApplication.
func contentDigest(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// hasUCCSEvidence reports whether a leaf carries tcg-dice-UCCS-evidence.
func hasUCCSEvidence(leaf *x509.Certificate) bool {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidUCCSEvidence) {
			return true
		}
	}
	return false
}
