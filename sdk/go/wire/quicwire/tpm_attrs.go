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

package quicwire

// Wire bodies of the physical-TPM capability, platform-attribute and PCR
// extend sub-opcodes (OpTPM2Category · SubOpTPM2Capabilities /
// SubOpTPM2PlatformAttrs / SubOpTPM2ExtendPCR). The server handler and the
// SDK QUIC transport share them, so both ends encode one shape (#704).

// TPM2StatusResponse represents a generic status response.
type TPM2StatusResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2ExtendPCRRequest represents a PCR extend request.
type TPM2ExtendPCRRequest struct {
	PCRIndex int    `codec:"pcr_index"`
	HashAlg  string `codec:"hash_alg"`
	Data     []byte `codec:"data"`
}

// TPM2CapabilitiesResponse represents TPM capabilities.
type TPM2CapabilitiesResponse struct {
	Algorithms []string `codec:"algorithms"`
	Commands   []string `codec:"commands"`
	ECCCurves  []string `codec:"ecc_curves"`
	Timestamp  int64    `codec:"timestamp"`
}

// TPM2PlatformAttributesResponse represents platform attributes.
type TPM2PlatformAttributesResponse struct {
	Device       string      `codec:"device"`
	IsFIPS       bool        `codec:"is_fips"`
	PCRExtended  bool        `codec:"pcr_extended"`
	CanSeal      bool        `codec:"can_seal"`
	IsSimulator  bool        `codec:"is_simulator"`
	Manufacturer string      `codec:"manufacturer"`
	EK           *TPM2KeyRef `codec:"ek,omitempty"`
	SRK          *TPM2KeyRef `codec:"srk,omitempty"`
	IAK          *TPM2KeyRef `codec:"iak,omitempty"`
	Timestamp    int64       `codec:"timestamp"`
}

// TPM2KeyRef names a provisioned key by its persistent handle and
// algorithm. It is absent from TPM2PlatformAttributesResponse when the
// key is not provisioned.
type TPM2KeyRef struct {
	Handle    uint32 `codec:"handle"`
	Algorithm string `codec:"algorithm"`
}
