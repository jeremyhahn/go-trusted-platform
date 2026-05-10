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

package tpm

import (
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// String-to-domain enum maps

// StringToKeyAlgorithm maps user-facing algorithm strings to domain KeyAlgorithm.
var StringToKeyAlgorithm = map[string]KeyAlgorithm{
	"RSA-2048":   KeyAlgorithmRSA2048,
	"RSA2048":    KeyAlgorithmRSA2048,
	"RSA-3072":   KeyAlgorithmRSA3072,
	"RSA3072":    KeyAlgorithmRSA3072,
	"RSA-4096":   KeyAlgorithmRSA4096,
	"RSA4096":    KeyAlgorithmRSA4096,
	"ECDSA-P256": KeyAlgorithmECDSAP256,
	"ECDSAP256":  KeyAlgorithmECDSAP256,
	"P256":       KeyAlgorithmECDSAP256,
	"ECDSA-P384": KeyAlgorithmECDSAP384,
	"ECDSAP384":  KeyAlgorithmECDSAP384,
	"P384":       KeyAlgorithmECDSAP384,
	"ECDSA-P521": KeyAlgorithmECDSAP521,
	"ECDSAP521":  KeyAlgorithmECDSAP521,
	"P521":       KeyAlgorithmECDSAP521,
}

// StringToPCRBank maps user-facing PCR bank strings to domain PCRBank.
var StringToPCRBank = map[string]PCRBank{
	"sha1":    PCRBankSHA1,
	"SHA1":    PCRBankSHA1,
	"sha256":  PCRBankSHA256,
	"SHA256":  PCRBankSHA256,
	"sha384":  PCRBankSHA384,
	"SHA384":  PCRBankSHA384,
	"sha512":  PCRBankSHA512,
	"SHA512":  PCRBankSHA512,
	"sm3_256": PCRBankSM3256,
	"SM3_256": PCRBankSM3256,
}

// StringToDeviceKeyAlgorithm maps user-facing algorithm strings to domain DeviceKeyAlgorithm.
var StringToDeviceKeyAlgorithm = map[string]DeviceKeyAlgorithm{
	"ECDSA-P256": DeviceKeyAlgorithmECDSAP256,
	"ECDSAP256":  DeviceKeyAlgorithmECDSAP256,
	"EC-P256":    DeviceKeyAlgorithmECDSAP256,
	"P256":       DeviceKeyAlgorithmECDSAP256,
	"ECDSA-P384": DeviceKeyAlgorithmECDSAP384,
	"ECDSAP384":  DeviceKeyAlgorithmECDSAP384,
	"EC-P384":    DeviceKeyAlgorithmECDSAP384,
	"P384":       DeviceKeyAlgorithmECDSAP384,
	"RSA-2048":   DeviceKeyAlgorithmRSA2048,
	"RSA2048":    DeviceKeyAlgorithmRSA2048,
	"RSA-3072":   DeviceKeyAlgorithmRSA3072,
	"RSA3072":    DeviceKeyAlgorithmRSA3072,
}

// ParseKeyAlgorithm parses a user-facing algorithm string to a domain KeyAlgorithm.
func ParseKeyAlgorithm(s string) (KeyAlgorithm, bool) {
	alg, ok := StringToKeyAlgorithm[strings.TrimSpace(s)]
	return alg, ok
}

// ParsePCRBank parses a user-facing PCR bank string to a domain PCRBank.
func ParsePCRBank(s string) PCRBank {
	bank, ok := StringToPCRBank[strings.TrimSpace(s)]
	if !ok {
		return PCRBankSHA256
	}
	return bank
}

// ParseDeviceKeyAlgorithm parses a user-facing algorithm string to a domain DeviceKeyAlgorithm.
func ParseDeviceKeyAlgorithm(s string) (DeviceKeyAlgorithm, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(s))
	alg, ok := StringToDeviceKeyAlgorithm[normalized]
	return alg, ok
}

// Domain-to-proto enum maps

var keyAlgorithmToProto = map[KeyAlgorithm]platformv1.KeyAlgorithm{
	KeyAlgorithmUnspecified: platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
	KeyAlgorithmRSA2048:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
	KeyAlgorithmRSA3072:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
	KeyAlgorithmRSA4096:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
	KeyAlgorithmECDSAP256:  platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
	KeyAlgorithmECDSAP384:  platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
	KeyAlgorithmECDSAP521:  platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
}

var protoToKeyAlgorithm = map[platformv1.KeyAlgorithm]KeyAlgorithm{
	platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: KeyAlgorithmUnspecified,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    KeyAlgorithmRSA2048,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    KeyAlgorithmRSA3072,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    KeyAlgorithmRSA4096,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  KeyAlgorithmECDSAP256,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  KeyAlgorithmECDSAP384,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:  KeyAlgorithmECDSAP521,
}

var pcrBankToProto = map[PCRBank]platformv1.PCRBank{
	PCRBankSHA1:   platformv1.PCRBank_PCR_BANK_SHA1,
	PCRBankSHA256: platformv1.PCRBank_PCR_BANK_SHA256,
	PCRBankSHA384: platformv1.PCRBank_PCR_BANK_SHA384,
	PCRBankSHA512: platformv1.PCRBank_PCR_BANK_SHA512,
	PCRBankSM3256: platformv1.PCRBank_PCR_BANK_SM3_256,
}

var deviceKeyAlgorithmToProto = map[DeviceKeyAlgorithm]platformv1.DeviceKeyAlgorithm{
	DeviceKeyAlgorithmUnspecified: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED,
	DeviceKeyAlgorithmECDSAP256:  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	DeviceKeyAlgorithmECDSAP384:  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
	DeviceKeyAlgorithmRSA2048:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
	DeviceKeyAlgorithmRSA3072:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
}

var protoToDeviceKeyAlgorithm = map[platformv1.DeviceKeyAlgorithm]DeviceKeyAlgorithm{
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED: DeviceKeyAlgorithmUnspecified,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256:  DeviceKeyAlgorithmECDSAP256,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384:  DeviceKeyAlgorithmECDSAP384,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048:    DeviceKeyAlgorithmRSA2048,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072:    DeviceKeyAlgorithmRSA3072,
}

// KeyAlgorithmToProto converts a domain KeyAlgorithm to a proto KeyAlgorithm.
func KeyAlgorithmToProto(alg KeyAlgorithm) platformv1.KeyAlgorithm {
	p, ok := keyAlgorithmToProto[alg]
	if !ok {
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
	return p
}

// KeyAlgorithmFromProto converts a proto KeyAlgorithm to a domain KeyAlgorithm.
func KeyAlgorithmFromProto(alg platformv1.KeyAlgorithm) KeyAlgorithm {
	d, ok := protoToKeyAlgorithm[alg]
	if !ok {
		return KeyAlgorithmUnspecified
	}
	return d
}

// PCRBankToProto converts a domain PCRBank to a proto PCRBank.
func PCRBankToProto(bank PCRBank) platformv1.PCRBank {
	p, ok := pcrBankToProto[bank]
	if !ok {
		return platformv1.PCRBank_PCR_BANK_SHA256
	}
	return p
}

// DeviceKeyAlgorithmToProto converts a domain DeviceKeyAlgorithm to a proto DeviceKeyAlgorithm.
func DeviceKeyAlgorithmToProto(alg DeviceKeyAlgorithm) platformv1.DeviceKeyAlgorithm {
	p, ok := deviceKeyAlgorithmToProto[alg]
	if !ok {
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED
	}
	return p
}

// DeviceKeyAlgorithmFromProto converts a proto DeviceKeyAlgorithm to a domain DeviceKeyAlgorithm.
func DeviceKeyAlgorithmFromProto(alg platformv1.DeviceKeyAlgorithm) DeviceKeyAlgorithm {
	d, ok := protoToDeviceKeyAlgorithm[alg]
	if !ok {
		return DeviceKeyAlgorithmUnspecified
	}
	return d
}

// StatusFromProto converts a proto Status to a domain Status.
func StatusFromProto(s *platformv1.Status) *Status {
	if s == nil {
		return nil
	}
	return &Status{
		Success: s.Success,
		Message: s.Message,
	}
}

// InfoResponseFromProto converts a proto TPMInfoResponse to a domain InfoResponse.
func InfoResponseFromProto(resp *platformv1.TPMInfoResponse) *InfoResponse {
	if resp == nil {
		return nil
	}
	return &InfoResponse{
		Properties:  resp.Properties,
		IsSimulator: resp.IsSimulator,
	}
}

// ProvisionResponseFromProto converts a proto TPMProvisionResponse to a domain ProvisionResponse.
func ProvisionResponseFromProto(resp *platformv1.TPMProvisionResponse) *ProvisionResponse {
	if resp == nil {
		return nil
	}
	return &ProvisionResponse{
		Status:    StatusFromProto(resp.Status),
		EKPublic:  resp.EkPublic,
		SRKPublic: resp.SrkPublic,
		AKPublic:  resp.AkPublic,
	}
}

// ClearResponseFromProto converts a proto TPMClearResponse to a domain ClearResponse.
func ClearResponseFromProto(resp *platformv1.TPMClearResponse) *ClearResponse {
	if resp == nil {
		return nil
	}
	return &ClearResponse{
		Status: StatusFromProto(resp.Status),
	}
}

// CreateKeyResponseFromEK converts a proto CreateEKResponse to a domain CreateKeyResponse.
func CreateKeyResponseFromEK(resp *platformv1.CreateEKResponse) *CreateKeyResponse {
	if resp == nil {
		return nil
	}
	return &CreateKeyResponse{
		Status:    StatusFromProto(resp.Status),
		Handle:    resp.Handle,
		PublicKey: resp.PublicKey,
	}
}

// CreateKeyResponseFromSRK converts a proto CreateSRKResponse to a domain CreateKeyResponse.
func CreateKeyResponseFromSRK(resp *platformv1.CreateSRKResponse) *CreateKeyResponse {
	if resp == nil {
		return nil
	}
	return &CreateKeyResponse{
		Status:    StatusFromProto(resp.Status),
		Handle:    resp.Handle,
		PublicKey: resp.PublicKey,
	}
}

// KeyInfoResponseFromEK converts a proto GetEKResponse to a domain KeyInfoResponse.
func KeyInfoResponseFromEK(resp *platformv1.GetEKResponse) *KeyInfoResponse {
	if resp == nil {
		return nil
	}
	return &KeyInfoResponse{
		Handle:    resp.Handle,
		Algorithm: KeyAlgorithmFromProto(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}
}

// KeyInfoResponseFromSRK converts a proto GetSRKResponse to a domain KeyInfoResponse.
func KeyInfoResponseFromSRK(resp *platformv1.GetSRKResponse) *KeyInfoResponse {
	if resp == nil {
		return nil
	}
	return &KeyInfoResponse{
		Handle:    resp.Handle,
		Algorithm: KeyAlgorithmFromProto(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}
}

// DeleteKeyResponseFromProto converts a proto delete response status to a domain DeleteKeyResponse.
func DeleteKeyResponseFromProto(status *platformv1.Status) *DeleteKeyResponse {
	return &DeleteKeyResponse{
		Status: StatusFromProto(status),
	}
}

// EKCertificateResponseFromProto converts a proto GetEKCertificateResponse to a domain EKCertificateResponse.
func EKCertificateResponseFromProto(resp *platformv1.GetEKCertificateResponse) *EKCertificateResponse {
	if resp == nil {
		return nil
	}
	return &EKCertificateResponse{
		Certificate: resp.Certificate,
		Format:      resp.Format,
	}
}

// SealRequestToProto converts a domain SealRequest to a proto SealRequest.
func SealRequestToProto(req *SealRequest) *platformv1.SealRequest {
	if req == nil {
		return nil
	}
	return &platformv1.SealRequest{
		Cn:             req.CN,
		Data:           req.Data,
		Password:       req.Password,
		ParentHandle:   req.ParentHandle,
		ParentPassword: req.ParentPassword,
		PcrIndices:     req.PCRIndices,
		PcrBank:        PCRBankToProto(req.PCRBank),
		Overwrite:      req.Overwrite,
	}
}

// SealResponseFromProto converts a proto SealResponse to a domain SealResponse.
func SealResponseFromProto(resp *platformv1.SealResponse) *SealResponse {
	if resp == nil {
		return nil
	}
	return &SealResponse{
		Status: StatusFromProto(resp.Status),
	}
}

// UnsealRequestToProto converts a domain UnsealRequest to a proto UnsealRequest.
func UnsealRequestToProto(req *UnsealRequest) *platformv1.UnsealRequest {
	if req == nil {
		return nil
	}
	return &platformv1.UnsealRequest{
		Cn:             req.CN,
		Password:       req.Password,
		ParentHandle:   req.ParentHandle,
		ParentPassword: req.ParentPassword,
		PcrIndices:     req.PCRIndices,
		PcrBank:        PCRBankToProto(req.PCRBank),
	}
}

// UnsealResponseFromProto converts a proto UnsealResponse to a domain UnsealResponse.
func UnsealResponseFromProto(resp *platformv1.UnsealResponse) *UnsealResponse {
	if resp == nil {
		return nil
	}
	return &UnsealResponse{
		Status: StatusFromProto(resp.Status),
		Data:   resp.Data,
	}
}

// EventLogResponseFromProto converts a proto GetEventLogResponse to a domain EventLogResponse.
func EventLogResponseFromProto(resp *platformv1.GetEventLogResponse) *EventLogResponse {
	if resp == nil {
		return nil
	}
	return &EventLogResponse{
		Format:     resp.Format,
		EventCount: resp.EventCount,
		EventLog:   resp.EventLog,
	}
}

// NVRAMDefineResponseFromProto converts a proto DefineNVRAMResponse to a domain NVRAMDefineResponse.
func NVRAMDefineResponseFromProto(resp *platformv1.DefineNVRAMResponse) *NVRAMDefineResponse {
	if resp == nil {
		return nil
	}
	return &NVRAMDefineResponse{
		Status: StatusFromProto(resp.Status),
	}
}

// NVRAMWriteResponseFromProto converts a proto WriteNVRAMResponse to a domain NVRAMWriteResponse.
func NVRAMWriteResponseFromProto(resp *platformv1.WriteNVRAMResponse) *NVRAMWriteResponse {
	if resp == nil {
		return nil
	}
	return &NVRAMWriteResponse{
		Status: StatusFromProto(resp.Status),
	}
}

// NVRAMReadResponseFromProto converts a proto ReadNVRAMResponse to a domain NVRAMReadResponse.
func NVRAMReadResponseFromProto(resp *platformv1.ReadNVRAMResponse) *NVRAMReadResponse {
	if resp == nil {
		return nil
	}
	return &NVRAMReadResponse{
		Data: resp.Data,
	}
}

// NVRAMUndefineResponseFromProto converts a proto UndefineNVRAMResponse to a domain NVRAMUndefineResponse.
func NVRAMUndefineResponseFromProto(resp *platformv1.UndefineNVRAMResponse) *NVRAMUndefineResponse {
	if resp == nil {
		return nil
	}
	return &NVRAMUndefineResponse{
		Status: StatusFromProto(resp.Status),
	}
}

// DeviceKeyInfoFromProto converts a proto DeviceKeyInfo to a domain DeviceKeyInfo.
func DeviceKeyInfoFromProto(info *platformv1.DeviceKeyInfo) *DeviceKeyInfo {
	if info == nil {
		return nil
	}
	result := &DeviceKeyInfo{
		Handle:         info.Handle,
		Algorithm:      DeviceKeyAlgorithmFromProto(info.Algorithm),
		PublicKeyPEM:   info.PublicKeyPem,
		HasCertificate: info.HasCertificate,
	}
	if info.CreatedAt != nil {
		t := info.CreatedAt.AsTime()
		result.CreatedAt = &t
	}
	if info.CertificateInfo != nil {
		result.CertificateInfo = DeviceKeyCertificateInfoFromProto(info.CertificateInfo)
	}
	return result
}

// DeviceKeyCertificateInfoFromProto converts a proto DeviceKeyCertificateInfo to a domain DeviceKeyCertificateInfo.
func DeviceKeyCertificateInfoFromProto(info *platformv1.DeviceIdentityCertificate) *DeviceKeyCertificateInfo {
	if info == nil {
		return nil
	}
	result := &DeviceKeyCertificateInfo{
		SubjectCN:          info.SubjectCn,
		IssuerCN:           info.IssuerCn,
		SerialNumber:       info.SerialNumber,
		Fingerprint:        info.Fingerprint,
		KeyAlgorithm:       info.KeyAlgorithm,
		SignatureAlgorithm: info.SignatureAlgorithm,
		KeySize:            info.KeySize,
	}
	if info.IssuedAt != nil {
		t := info.IssuedAt.AsTime()
		result.IssuedAt = &t
	}
	if info.ExpiresAt != nil {
		t := info.ExpiresAt.AsTime()
		result.ExpiresAt = &t
	}
	return result
}

// DeviceIdentityCertificateFromProto converts a proto DeviceIdentityCertificate to a domain DeviceIdentityCertificate.
func DeviceIdentityCertificateFromProto(cert *platformv1.DeviceIdentityCertificate) *DeviceIdentityCertificate {
	if cert == nil {
		return nil
	}
	result := &DeviceIdentityCertificate{
		PEM:                cert.Pem,
		SubjectCN:          cert.SubjectCn,
		IssuerCN:           cert.IssuerCn,
		SerialNumber:       cert.SerialNumber,
		Fingerprint:        cert.Fingerprint,
		KeyAlgorithm:       cert.KeyAlgorithm,
		SignatureAlgorithm: cert.SignatureAlgorithm,
	}
	if cert.IssuedAt != nil {
		t := cert.IssuedAt.AsTime()
		result.IssuedAt = &t
	}
	if cert.ExpiresAt != nil {
		t := cert.ExpiresAt.AsTime()
		result.ExpiresAt = &t
	}
	return result
}

// CSRTemplateToProto converts a domain CSRTemplate to a proto CSRTemplate.
func CSRTemplateToProto(tmpl *CSRTemplate) *platformv1.CSRTemplate {
	if tmpl == nil {
		return nil
	}
	return &platformv1.CSRTemplate{
		CommonName:         tmpl.CommonName,
		Organization:       tmpl.Organization,
		Country:            tmpl.Country,
		Province:           tmpl.Province,
		Locality:           tmpl.Locality,
		OrganizationalUnit: tmpl.OrganizationalUnit,
	}
}

// DeviceAttributesFromProto converts a proto DeviceAttributes to a domain DeviceAttributes.
func DeviceAttributesFromProto(attrs *platformv1.TCGDeviceAttributes) *DeviceAttributes {
	if attrs == nil {
		return nil
	}
	return &DeviceAttributes{
		TPMManufacturer:      attrs.GetTpmManufacturer(),
		TPMModel:             attrs.GetTpmModel(),
		TPMVersion:           attrs.GetTpmVersion(),
		PlatformManufacturer: attrs.GetPlatformManufacturer(),
		PlatformModel:        attrs.GetPlatformModel(),
		PlatformVersion:      attrs.GetPlatformVersion(),
		PlatformSerial:       attrs.GetPlatformSerial(),
	}
}

// timestampToTime converts a protobuf timestamp to a Go time.Time pointer.
func timestampToTime(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}
