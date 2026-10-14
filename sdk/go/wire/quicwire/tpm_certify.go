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

// Wire bodies of the physical-TPM certify sub-opcode (OpTPM2Category ·
// SubOpTPM2Certify). The server handler and the SDK QUIC transport share
// them, so both ends encode one shape. Field names mirror the gRPC
// CertifyRequest / CertifyResponse protos.

// TPM2CertifyRequest asks the TPM to certify the key at a persistent handle.
type TPM2CertifyRequest struct {
	KeyHandle   uint32 `codec:"key_handle"`
	KeyPassword string `codec:"key_password"`
	Nonce       []byte `codec:"nonce"`
}

// TPM2CertifyResponse carries the IAK-signed TPMS_ATTEST and the keys
// needed to verify it.
type TPM2CertifyResponse struct {
	CertifyInfo            []byte `codec:"certify_info"`
	Signature              []byte `codec:"signature"`
	SignatureAlgorithm     string `codec:"signature_algorithm"`
	CertifyInfoSignature   []byte `codec:"certify_info_signature"`
	AttestingKeyPublic     []byte `codec:"attesting_key_public"`
	AttestedKeyPublic      []byte `codec:"attested_key_public"`
	AttestingKeyPublicArea []byte `codec:"attesting_key_public_area"`
	AttestedKeyPublicArea  []byte `codec:"attested_key_public_area"`
	Nonce                  []byte `codec:"nonce"`
}
