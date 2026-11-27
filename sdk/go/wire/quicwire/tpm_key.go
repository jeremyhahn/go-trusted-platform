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

// TPM2KeyResponse represents a TPM key response: the reply of the EK,
// SRK, IAK and AK key sub-ops. The server (pkg/api/quic) and the SDK QUIC
// transport share this one type so the codec tags cannot drift (#2069).
type TPM2KeyResponse struct {
	Handle    uint32 `codec:"handle"`
	PublicKey []byte `codec:"public_key"`
	Algorithm string `codec:"algorithm"`
	Timestamp int64  `codec:"timestamp"`
	// Name is the key's TPM name (TPM2B_NAME bytes); set by GetIAK (#2069).
	Name []byte `codec:"name,omitempty"`
}
