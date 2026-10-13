// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"encoding/binary"
	"encoding/hex"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// Vendor identifies trusted-firmware evidence inside the vendor-neutral
// contract.
//
// The backend keeps no evidence store (see [Backend.noEvidenceStore]): every
// Evidence it checks in [Backend.GetInfo] was produced by this build's own
// Dump, so the value can change without stranding evidence written under an
// earlier name.
//
// [bmcattestation.Vendor] is an open string type whose named constants are BMC
// manufacturers, and [bmcattestation.DetectVendor] can never return this one:
// an AVR part is reached over a serial link and has no manufacturer string to
// sniff. So this backend is NOT registered with the BMC dispatcher — routing
// to it is the caller's decision, made from the transport, not from a Redfish
// reply.
const Vendor bmcattestation.Vendor = "trusted-firmware"

// Attestation operations this backend performs.
//
// ActionDump is the contract's own verb for "produce a fresh measurement
// bound to this nonce" and is the runtime freshness flow. ActionAttestCert
// extends the verb set: a BMC has no enrolment ceremony, so the contract has
// no verb for one. Actions extend and never renumber.
const (
	// ActionDump is the runtime freshness flow: the 164-byte signed
	// evidence frame, bound to a 16-byte nonce.
	ActionDump = bmcattestation.ActionDump

	// ActionAttestCert is the enrolment flow: a DICE alias certificate
	// bound to a 32-byte nonce.
	ActionAttestCert bmcattestation.Action = "attestcert"
)

// Evidence formats, recorded in [bmcattestation.Evidence.Metadata] under
// MetadataFormat so a caller routing on format does not have to learn a
// second name for the same bytes.
const (
	// FormatFrame is the fixed-layout signed evidence frame defined by
	// include/tfw/protocol.h in trusted-firmware.
	FormatFrame = "ag-attest-v1"

	// FormatDICE is the alias certificate. The string matches the format
	// go-xkms and ACME device-attest-01 use for the same evidence.
	FormatDICE = "dice"
)

// Metadata keys set on every [bmcattestation.Evidence] this backend emits.
// They are constants because a stringly-typed key invented at each call site
// is a key that eventually differs by one character.
const (
	// MetadataTenantID is the tenant the device belongs to. Present on
	// every record; evidence without it is refused.
	MetadataTenantID = "tenant_id"

	// MetadataFormat is one of FormatFrame or FormatDICE.
	MetadataFormat = "format"

	// MetadataDeviceRef is the operator's label for the link this device
	// is reached on, for audit trails.
	MetadataDeviceRef = "device_ref"

	// MetadataElementSerial is the secure element's nine-byte serial,
	// hex-encoded. Present only on secure-element devices.
	MetadataElementSerial = "element_serial"

	// MetadataCryptoTier is the device's crypto tier as CAPS reported it.
	MetadataCryptoTier = "crypto_tier"

	// MetadataBoardID is the board identifier as CAPS reported it.
	MetadataBoardID = "board_id"

	// MetadataFirmware is the device firmware version, "major.minor.patch".
	MetadataFirmware = "firmware_version"

	// MetadataProtocol is the wire protocol version, "major.minor".
	MetadataProtocol = "protocol_version"
)

// Measurement attribute keys, set by GetInfo.
const (
	// AttrFrameVersion is the evidence frame's version byte.
	AttrFrameVersion = "frame_version"

	// AttrDeviceID is the 16-byte device identifier the trusted
	// bootloader supplied, hex-encoded. All zeroes on an unprovisioned
	// device, deliberately: a fabricated value would be believed.
	AttrDeviceID = "device_id"

	// AttrBootCount is the device's monotonic boot counter, decimal.
	AttrBootCount = "boot_count"

	// AttrUptimeMillis is how long the device has been up, in
	// milliseconds. NOT A TIMESTAMP — no part in this family has a clock.
	// The name says millis rather than time so it cannot be read as one.
	AttrUptimeMillis = "uptime_millis"

	// AttrAlgorithm is the signature algorithm identifier from the frame,
	// as the device reported it. Recorded verbatim rather than decoded,
	// because identifiers extend and an unknown one must read as unknown.
	AttrAlgorithm = "algorithm_id"

	// AttrSignature is the device's 64-byte raw signature, hex-encoded.
	AttrSignature = "signature"

	// AttrCertSubject, AttrCertIssuer and AttrCertSerial describe an alias
	// certificate's leaf.
	AttrCertSubject = "cert_subject"
	AttrCertIssuer  = "cert_issuer"
	AttrCertSerial  = "cert_serial"

	// AttrUCCSPresent is "true" when the leaf carries the critical
	// tcg-dice-UCCS-evidence extension. Its CONTENT is not decoded here;
	// go-xkms owns the DICE profile.
	AttrUCCSPresent = "uccs_evidence_present"

	// AttrTenantID mirrors MetadataTenantID onto the parsed view so a
	// Measurement is as tenant-bound as the Evidence it came from.
	AttrTenantID = "tenant_id"
)

// Synthetic PCR indices.
//
// DICE has no PCRs and this device performs no extend operation, so these are
// RAW measurements at indices in this package's own namespace. They are not
// TPM PCRs and a verifier must never compare them against one. See the
// package documentation for the full rationale.
const (
	// PCRBootloader is reserved for tfw-boot's measurement of its own boot
	// section. The wire protocol does not carry it today, so this index is
	// ABSENT from every PCRBank this backend produces. It is reserved so
	// that when the bootloader does report it, PCRApplication does not
	// have to move.
	PCRBootloader uint32 = 0

	// PCRApplication is FWHash: SHA-256 over the application flash, taken
	// by tfw-boot before it jumps to the application. This is the
	// reproducible golden-build value Policy.Reference compares.
	PCRApplication uint32 = 1
)

// The evidence frame layout, mirroring include/tfw/protocol.h:
//
//	[Version:1][Nonce:16][DeviceID:16][FWHash:32][BootCount:4]
//	[UptimeMs:4][AlgID:1][Signature:64][Reserved:26]
//
// THIS IS A SECOND COPY OF A WIRE DEFINITION trusted-firmware owns, and it is
// here only because its Go SDK returns the frame as opaque bytes and exposes
// no parser for it. The gap is filed upstream; when the SDK grows a
// ParseEvidence, these offsets are deleted rather than kept in step. The
// total length and both nonce widths already come from the SDK, so the one
// thing a consumer must not guess at is not guessed at here.
const (
	offFrameVersion = 0
	offFrameNonce   = 1
	offFrameDevice  = 17
	offFrameFWHash  = 33
	offFrameBoot    = 65
	offFrameUptime  = 69
	offFrameAlg     = 73
	offFrameSig     = 74
	offFrameEnd     = 138 // reserved tail runs from here to EvidenceLen

	lenFrameDeviceID = 16
	lenFrameFWHash   = 32
	lenFrameSig      = 64

	// frameVersion is the only frame version this host parses.
	frameVersion uint8 = 1
)

// frame is the parsed evidence frame. Every byte slice in it is COPIED out of
// the raw evidence, never aliased, so nothing downstream can reach back and
// change what the device is recorded as having said.
type frame struct {
	version   uint8
	nonce     []byte
	deviceID  []byte
	fwHash    []byte
	bootCount uint32
	uptimeMs  uint32
	algorithm uint8
	signature []byte
}

// parseFrame decodes a signed evidence frame.
//
// It is called from exactly one place, [Backend.GetInfo], which is the
// contract's single parse point. Nothing else in this package — not Verify,
// not Compare — reads Raw.
func parseFrame(raw []byte) (*frame, error) {
	if len(raw) != tfw.EvidenceLen {
		return nil, ErrEvidenceLength{Got: len(raw), Want: tfw.EvidenceLen}
	}
	version := raw[offFrameVersion]
	if version != frameVersion {
		return nil, ErrEvidenceVersion{Got: version, Want: frameVersion}
	}
	return &frame{
		version:   version,
		nonce:     clone(raw[offFrameNonce : offFrameNonce+tfw.AttestNonceLen]),
		deviceID:  clone(raw[offFrameDevice : offFrameDevice+lenFrameDeviceID]),
		fwHash:    clone(raw[offFrameFWHash : offFrameFWHash+lenFrameFWHash]),
		bootCount: binary.LittleEndian.Uint32(raw[offFrameBoot : offFrameBoot+4]),
		uptimeMs:  binary.LittleEndian.Uint32(raw[offFrameUptime : offFrameUptime+4]),
		algorithm: raw[offFrameAlg],
		signature: clone(raw[offFrameSig:offFrameEnd]),
	}, nil
}

// clone copies a slice so the result shares no backing array with the source.
func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// hexOrEmpty hex-encodes b, returning "" for an empty slice so an attribute
// map never carries a meaningless empty hex string.
func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}

// TenantOf returns the tenant an evidence blob belongs to, or "" when the
// blob carries none.
//
// The vendor-neutral Evidence has no typed tenant field, so the binding rides
// in Metadata under MetadataTenantID. This helper exists so no caller has to
// know that key.
func TenantOf(ev *bmcattestation.Evidence) string {
	if ev == nil {
		return ""
	}
	return ev.Metadata[MetadataTenantID]
}
