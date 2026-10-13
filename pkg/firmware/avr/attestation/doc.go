// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

// Package attestation implements the platform's attestation provider for
// trusted-firmware AVR devices.
//
// It satisfies [bmcattestation.AttestationProvider] — the vendor-neutral
// contract the BMC attestation subsystem defines — so an AVR part appraises
// through the same Evidence, Measurement, Policy and Verifier types as a
// server BMC. Nothing about that contract is BMC-specific except the package
// it currently lives in; see docs/firmware/avr-attestation.md §"What did not
// fit" for the misfits that reuse exposed.
//
// # Two device flows, two nonce widths
//
// The device answers two different questions and they take different
// challenges. Merging the widths is a wire break, so this package refuses
// each command the other's width before a frame is built:
//
//	Dump        tfw.AttestNonceLen (16)        RUNTIME FRESHNESS.  Returns the
//	                                           164-byte signed evidence frame:
//	                                           is this device reporting now?
//	AttestCert  tfw.AliasNonceLen  (32)        ENROLMENT.  Returns a DICE alias
//	                                           certificate whose critical
//	                                           tcg-dice-UCCS-evidence extension
//	                                           carries the challenge: is this
//	                                           key on this device?
//
// # The device has no clock
//
// No part in this family has an RTC, so freshness is ALWAYS the verifier's
// nonce. Nothing here compares a device-supplied value against time.Now: the
// frame's UptimeMs is context, not a timestamp, and it is recorded as an
// attribute named so it cannot be mistaken for one. [Evidence.CreatedAt] is
// stamped by this gateway when it relays, and that — never anything the
// device said — is what [Policy.MaxAgeSeconds] ages.
//
// # Evidence is relayed verbatim
//
// The provider never re-signs, re-encodes or normalises device-signed bytes.
// Evidence.Raw is exactly what the device sent, and every parsed view copies
// out of it rather than aliasing it, so a caller cannot reach back through a
// Measurement and change what the device is recorded as having said. A
// compromised gateway may lie about which devices exist; it must not be able
// to lie about what a given device measured, and that containment property is
// what the whole design rests on.
//
// # Synthetic PCR mapping
//
// DICE has no PCRs and this device performs no extend operation, so
// [bmcattestation.Measurement.PCRBank] carries RAW measurements at synthetic
// indices in this package's own namespace. They are NOT TPM PCRs and must
// never be compared against one:
//
//	index 0  PCRBootloader   tfw-boot's measurement of its own boot section.
//	                         RESERVED AND ABSENT: the wire protocol does not
//	                         carry it today (the bootloader is anchored out of
//	                         band by the public-key hash pinned in reserved
//	                         EEPROM, which the device does not report). The
//	                         index is reserved so that when tfw-boot does
//	                         report it, nothing below has to renumber.
//	index 1  PCRApplication  FWHash: SHA-256 over the application flash,
//	                         taken by tfw-boot before it jumps. This is the
//	                         reproducible golden-build value, and it is what
//	                         Policy.Reference compares.
//
// An absent index is absent from the map. It is never zero-filled: a
// verifier must be able to tell "the device did not report this" from "the
// device reported thirty-two zero bytes", and an all-zero FWHash is exactly
// what an unprovisioned device sends.
//
// # Where verification stops
//
// This package appraises what it can read without decoding DICE: the nonce
// echo in the evidence frame, the golden FWHash, the vendor, the certificate
// issuer, and the gateway's relay age. It does NOT decode the UCCS claims set
// in the alias certificate and does not verify a DICE chain — go-xkms owns
// the DICE profile and the verifier, and a second implementation of what DICE
// evidence means is exactly the duplication the layer rules exist to prevent.
// Consequently [bmcattestation.Policy.RequireNonceEcho] FAILS on alias
// certificate evidence rather than silently passing: this package will not
// report a check it did not perform.
//
// # Tenancy
//
// Every provider is bound to one tenant at construction and every record it
// emits carries that tenant. Evidence from another tenant is refused by
// GetInfo, Compare and Verify with [ErrTenantMismatch] — a refusal, not a
// failed appraisal score.
//
// See docs/firmware/avr-attestation.md for the full design.
package attestation
