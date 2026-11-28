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

// Wire bodies of the physical-TPM random and credential sub-opcodes
// (OpTPM2Category · SubOpTPM2Random / SubOpTPM2MakeCredential /
// SubOpTPM2ActivateCredential). The server handler and the SDK QUIC
// transport share them, so both ends encode one shape (#2069).

// TPM2MakeCredentialRequest represents a TPM2_MakeCredential request.
type TPM2MakeCredentialRequest struct {
	AKName []byte `codec:"ak_name"`
	Secret []byte `codec:"secret"`
	EKCert []byte `codec:"ek_cert"`
	IAKPub []byte `codec:"iak_pub"`
}

// TPM2MakeCredentialResponse represents a TPM2_MakeCredential response.
type TPM2MakeCredentialResponse struct {
	CredentialBlob  []byte `codec:"credential_blob"`
	EncryptedSecret []byte `codec:"encrypted_secret"`
	Secret          []byte `codec:"secret"`
	Timestamp       int64  `codec:"timestamp"`
}

// TPM2ActivateCredentialRequest represents a TPM2_ActivateCredential request.
type TPM2ActivateCredentialRequest struct {
	CredentialBlob  []byte `codec:"credential_blob"`
	EncryptedSecret []byte `codec:"encrypted_secret"`
}

// TPM2ActivateCredentialResponse represents a TPM2_ActivateCredential response.
type TPM2ActivateCredentialResponse struct {
	Secret    []byte `codec:"secret"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2RandomRequest represents a random bytes request.
type TPM2RandomRequest struct {
	NumBytes uint32 `codec:"num_bytes"`
}

// TPM2RandomResponse represents a random bytes response.
type TPM2RandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}
