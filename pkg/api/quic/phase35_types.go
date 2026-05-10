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

package quic

import "time"

// Ceremony QUIC request/response payloads. Field tags use the `codec`
// convention matched by go-codec (MessagePack, JSON, CBOR) per project
// conventions.

// CeremonyInitReq is the QUIC ceremony init request payload.
type CeremonyInitReq struct {
	SOPIN                  string   `codec:"so_pin"`
	UserPIN                string   `codec:"user_pin"`
	Threshold              string   `codec:"threshold"`
	Hostname               string   `codec:"hostname"`
	SANs                   []string `codec:"sans"`
	CredentialSealStrategy string   `codec:"credential_seal_strategy"`
}

// CeremonyInitResp is the QUIC ceremony init response payload.
type CeremonyInitResp struct {
	CeremonyID    string    `codec:"ceremony_id"`
	State         string    `codec:"state"`
	InitializedAt time.Time `codec:"initialized_at"`
}

// CeremonyStatusResp is the QUIC ceremony status response payload.
type CeremonyStatusResp struct {
	CeremonyID       string    `codec:"ceremony_id"`
	State            string    `codec:"state"`
	Threshold        string    `codec:"threshold"`
	OfficersEnrolled int32     `codec:"officers_enrolled"`
	OfficersRequired int32     `codec:"officers_required"`
	InitializedAt    time.Time `codec:"initialized_at"`
}

// CeremonyClaimCertBeginReq is the QUIC claim-cert begin request payload.
type CeremonyClaimCertBeginReq struct {
	Username          string `codec:"username"`
	AuthenticatorType string `codec:"authenticator_type"`
	Slot              string `codec:"slot"`
	CredentialID      string `codec:"credential_id"`
}

// CeremonyClaimCertBeginResp is the QUIC claim-cert begin response payload.
type CeremonyClaimCertBeginResp struct {
	Nonce       string    `codec:"nonce"`
	ChallengeID string    `codec:"challenge_id"`
	ExpiresAt   time.Time `codec:"expires_at"`
}

// CeremonyClaimCertCompleteReq is the QUIC claim-cert complete request payload.
type CeremonyClaimCertCompleteReq struct {
	Username  string `codec:"username"`
	Nonce     string `codec:"nonce"`
	Signature string `codec:"signature"`
}

// CeremonyClaimCertCompleteResp is the QUIC claim-cert complete response payload.
type CeremonyClaimCertCompleteResp struct {
	CertificatePEM string `codec:"certificate_pem"`
	ChainPEM       string `codec:"chain_pem"`
}

// CeremonyClaimShareReq is the QUIC claim-share request payload.
type CeremonyClaimShareReq struct {
	Username string `codec:"username"`
}

// CeremonyClaimShareResp is the QUIC claim-share response payload.
type CeremonyClaimShareResp struct {
	Share string `codec:"share"`
	Index int32  `codec:"index"`
}

// CeremonySignCSRReq is the QUIC sign-csr request payload.
type CeremonySignCSRReq struct {
	Username string `codec:"username"`
	SOPIN    string `codec:"so_pin"`
	CSRPEM   string `codec:"csr_pem"`
	Role     string `codec:"role"`
}

// CeremonySignCSRResp is the QUIC sign-csr response payload.
type CeremonySignCSRResp struct {
	CertificatePEM string `codec:"certificate_pem"`
	ChainPEM       string `codec:"chain_pem"`
}

// PIV QUIC request/response payloads.

// PIVDevice is the QUIC PIV device payload.
type PIVDevice struct {
	ID              string `codec:"id"`
	Name            string `codec:"name"`
	Manufacturer    string `codec:"manufacturer"`
	Model           string `codec:"model"`
	Serial          string `codec:"serial"`
	FirmwareVersion string `codec:"firmware_version"`
}

// PIVSlot is the QUIC PIV slot payload.
type PIVSlot struct {
	ID             string `codec:"id"`
	Name           string `codec:"name"`
	Algorithm      string `codec:"algorithm"`
	HasKey         bool   `codec:"has_key"`
	HasCertificate bool   `codec:"has_certificate"`
}

// PIVListDevicesResp is the QUIC list-devices response payload.
type PIVListDevicesResp struct {
	Devices []PIVDevice `codec:"devices"`
}

// PIVListSlotsReq is the QUIC list-slots request payload.
type PIVListSlotsReq struct {
	Device string `codec:"device"`
}

// PIVListSlotsResp is the QUIC list-slots response payload.
type PIVListSlotsResp struct {
	Slots []PIVSlot `codec:"slots"`
}

// PIVSlotInfoReq is the QUIC slot-info request payload.
type PIVSlotInfoReq struct {
	Slot   string `codec:"slot"`
	Device string `codec:"device"`
}

// PIVSlotInfoResp is the QUIC slot-info response payload.
type PIVSlotInfoResp struct {
	Slot           PIVSlot `codec:"slot"`
	PublicKeyPEM   string  `codec:"public_key_pem"`
	CertificatePEM string  `codec:"certificate_pem"`
}

// PIVGenerateReq is the QUIC generate request payload.
type PIVGenerateReq struct {
	Slot      string `codec:"slot"`
	Algorithm string `codec:"algorithm"`
	PIN       string `codec:"pin"`
}

// PIVGenerateResp is the QUIC generate response payload.
type PIVGenerateResp struct {
	PublicKeyPEM string `codec:"public_key_pem"`
}

// PIVImportReq is the QUIC import request payload.
type PIVImportReq struct {
	Slot          string `codec:"slot"`
	PrivateKeyPEM string `codec:"private_key_pem"`
	PIN           string `codec:"pin"`
}

// PIVImportResp is the QUIC import response payload.
type PIVImportResp struct {
	Imported bool `codec:"imported"`
}

// PIVSignReq is the QUIC sign request payload.
type PIVSignReq struct {
	Slot    string `codec:"slot"`
	Payload []byte `codec:"payload"`
	PIN     string `codec:"pin"`
}

// PIVSignResp is the QUIC sign response payload.
type PIVSignResp struct {
	Signature []byte `codec:"signature"`
}

// PIVAttestReq is the QUIC attest request payload.
type PIVAttestReq struct {
	Slot string `codec:"slot"`
}

// PIVAttestResp is the QUIC attest response payload.
type PIVAttestResp struct {
	AttestationCertPEM  string `codec:"attestation_cert_pem"`
	AttestationChainPEM string `codec:"attestation_chain_pem"`
}

// PIVResetReq is the QUIC reset request payload.
type PIVResetReq struct {
	Device string `codec:"device"`
}

// PIVResetResp is the QUIC reset response payload.
type PIVResetResp struct {
	Reset bool `codec:"reset"`
}

// LUKS QUIC request/response payloads.

// LUKSKeyslot is the QUIC LUKS keyslot payload.
type LUKSKeyslot struct {
	Slot     int32  `codec:"slot"`
	Type     string `codec:"type"`
	KeySize  int32  `codec:"key_size"`
	Priority int32  `codec:"priority"`
}

// LUKSStatusReq is the QUIC status request payload.
type LUKSStatusReq struct {
	Device string `codec:"device"`
}

// LUKSStatusResp is the QUIC status response payload.
type LUKSStatusResp struct {
	Device      string  `codec:"device"`
	IsLUKS      bool    `codec:"is_luks"`
	Version     int32   `codec:"version"`
	UUID        string  `codec:"uuid"`
	Label       string  `codec:"label"`
	Cipher      string  `codec:"cipher"`
	ActiveSlots []int32 `codec:"active_slots"`
}

// LUKSListSlotsReq is the QUIC list-slots request payload.
type LUKSListSlotsReq struct {
	Device string `codec:"device"`
}

// LUKSListSlotsResp is the QUIC list-slots response payload.
type LUKSListSlotsResp struct {
	Device string        `codec:"device"`
	Slots  []LUKSKeyslot `codec:"slots"`
}

// LUKSInfoReq is the QUIC info request payload.
type LUKSInfoReq struct {
	Device string `codec:"device"`
}

// LUKSInfoResp is the QUIC info response payload.
type LUKSInfoResp struct {
	Device       string        `codec:"device"`
	UUID         string        `codec:"uuid"`
	Label        string        `codec:"label"`
	Version      int32         `codec:"version"`
	Cipher       string        `codec:"cipher"`
	KeySize      int32         `codec:"key_size"`
	SectorSize   int32         `codec:"sector_size"`
	Slots        []LUKSKeyslot `codec:"slots"`
	MetadataJSON string        `codec:"metadata_json"`
}

// LUKSEnrollPassphraseReq is the QUIC enroll-passphrase request payload.
type LUKSEnrollPassphraseReq struct {
	Device             string `codec:"device"`
	ExistingPassphrase string `codec:"existing_passphrase"`
	NewPassphrase      string `codec:"new_passphrase"`
}

// LUKSEnrollPassphraseResp is the QUIC enroll-passphrase response payload.
type LUKSEnrollPassphraseResp struct {
	Slot int32 `codec:"slot"`
}

// LUKSEnrollFIDO2Req is the QUIC enroll-fido2 request payload.
type LUKSEnrollFIDO2Req struct {
	Device             string `codec:"device"`
	ExistingPassphrase string `codec:"existing_passphrase"`
	CredentialID       string `codec:"credential_id"`
	RequirePIN         bool   `codec:"require_pin"`
	RequireUV          bool   `codec:"require_uv"`
}

// LUKSEnrollFIDO2Resp is the QUIC enroll-fido2 response payload.
type LUKSEnrollFIDO2Resp struct {
	Slot    int32  `codec:"slot"`
	TokenID string `codec:"token_id"`
}

// LUKSEnrollTPMReq is the QUIC enroll-tpm request payload.
type LUKSEnrollTPMReq struct {
	Device             string  `codec:"device"`
	ExistingPassphrase string  `codec:"existing_passphrase"`
	PCRs               []int32 `codec:"pcrs"`
	Handle             string  `codec:"handle"`
}

// LUKSEnrollTPMResp is the QUIC enroll-tpm response payload.
type LUKSEnrollTPMResp struct {
	Slot    int32  `codec:"slot"`
	TokenID string `codec:"token_id"`
}

// LUKSEnrollRecoveryReq is the QUIC enroll-recovery request payload.
type LUKSEnrollRecoveryReq struct {
	Device             string `codec:"device"`
	ExistingPassphrase string `codec:"existing_passphrase"`
}

// LUKSEnrollRecoveryResp is the QUIC enroll-recovery response payload.
type LUKSEnrollRecoveryResp struct {
	Slot        int32  `codec:"slot"`
	RecoveryKey string `codec:"recovery_key"`
}

// LUKSRemoveKeyReq is the QUIC remove-key request payload.
type LUKSRemoveKeyReq struct {
	Device string `codec:"device"`
	Slot   int32  `codec:"slot"`
}

// LUKSRemoveKeyResp is the QUIC remove-key response payload.
type LUKSRemoveKeyResp struct {
	Removed bool `codec:"removed"`
}

// LUKSTestUnlockReq is the QUIC test-unlock request payload.
type LUKSTestUnlockReq struct {
	Device string `codec:"device"`
	Slot   int32  `codec:"slot"`
}

// LUKSTestUnlockResp is the QUIC test-unlock response payload.
type LUKSTestUnlockResp struct {
	Unlocked bool `codec:"unlocked"`
}

// LUKSChangePassphraseReq is the QUIC change-passphrase request payload.
type LUKSChangePassphraseReq struct {
	Device        string `codec:"device"`
	Slot          int32  `codec:"slot"`
	OldPassphrase string `codec:"old_passphrase"`
	NewPassphrase string `codec:"new_passphrase"`
}

// LUKSChangePassphraseResp is the QUIC change-passphrase response payload.
type LUKSChangePassphraseResp struct {
	Changed bool `codec:"changed"`
}

// FIDO2 QUIC request/response payloads.

// FIDO2Device is the QUIC FIDO2 device payload.
type FIDO2Device struct {
	ID           string `codec:"id"`
	Path         string `codec:"path"`
	Manufacturer string `codec:"manufacturer"`
	Product      string `codec:"product"`
	ProductID    uint32 `codec:"product_id"`
	VendorID     uint32 `codec:"vendor_id"`
}

// FIDO2ListDevicesResp is the QUIC list-devices response payload.
type FIDO2ListDevicesResp struct {
	Devices []FIDO2Device `codec:"devices"`
}

// FIDO2WaitDeviceReq is the QUIC wait-device request payload.
type FIDO2WaitDeviceReq struct {
	TimeoutSeconds int32 `codec:"timeout_seconds"`
}

// FIDO2WaitDeviceResp is the QUIC wait-device response payload.
type FIDO2WaitDeviceResp struct {
	Device FIDO2Device `codec:"device"`
}

// FIDO2InfoReq is the QUIC info request payload.
type FIDO2InfoReq struct {
	Device string `codec:"device"`
}

// FIDO2InfoResp is the QUIC info response payload.
type FIDO2InfoResp struct {
	Device          FIDO2Device     `codec:"device"`
	AAGUID          string          `codec:"aaguid"`
	FirmwareVersion string          `codec:"firmware_version"`
	Extensions      []string        `codec:"extensions"`
	Options         map[string]bool `codec:"options"`
	MaxMsgSize      uint32          `codec:"max_msg_size"`
}

// FIDO2RegisterReq is the QUIC register request payload.
type FIDO2RegisterReq struct {
	Username   string `codec:"username"`
	Role       string `codec:"role"`
	RequirePIN bool   `codec:"require_pin"`
	RequireUV  bool   `codec:"require_uv"`
	RPID       string `codec:"rp_id"`
}

// FIDO2RegisterResp is the QUIC register response payload.
type FIDO2RegisterResp struct {
	CredentialID string `codec:"credential_id"`
	AAGUID       string `codec:"aaguid"`
	PublicKeyPEM string `codec:"public_key_pem"`
}

// FIDO2AuthenticateReq is the QUIC authenticate request payload.
type FIDO2AuthenticateReq struct {
	CredentialID string `codec:"credential_id"`
}

// FIDO2AuthenticateResp is the QUIC authenticate response payload.
type FIDO2AuthenticateResp struct {
	Authenticated bool   `codec:"authenticated"`
	Counter       uint32 `codec:"counter"`
}
