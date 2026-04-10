// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"crypto/x509"
	"time"
)

// Measurement is a parsed, structured view of an [Evidence] blob. Not all
// fields are populated for every vendor; backends fill in what they can
// derive from the opaque Raw payload in [AttestationProvider.GetInfo].
type Measurement struct {
	// Vendor is copied from the source evidence.
	Vendor Vendor

	// CreatedAt is the BMC-side generation time, when known.
	CreatedAt time.Time

	// NonceEcho is the nonce as echoed by the BMC inside the signed
	// measurement. Verifiers must confirm it equals the requested nonce.
	NonceEcho []byte

	// CertChain is the attestation certificate chain (leaf first) when
	// the backend is able to extract one.
	CertChain []*x509.Certificate

	// PCRBank is an optional map of TPM-style PCR index to digest for
	// backends that expose PCR-shaped measurements.
	PCRBank map[uint32][]byte

	// Digest is a vendor-opaque summary digest of the measurement body.
	Digest []byte

	// Attributes holds vendor-specific key/value data extracted during
	// parsing (for example, firmware versions, BMC serial, SUM report
	// fields).
	Attributes map[string]string
}
