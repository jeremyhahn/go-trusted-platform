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

package bmc

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Proto-to-domain enum maps

// protoPowerStateToState maps proto BMCPowerState to domain PowerState.
var protoPowerStateToState = map[platformv1.BMCPowerState]PowerState{
	platformv1.BMCPowerState_BMC_POWER_STATE_UNSPECIFIED: PowerStateUnspecified,
	platformv1.BMCPowerState_BMC_POWER_STATE_ON:          PowerStateOn,
	platformv1.BMCPowerState_BMC_POWER_STATE_OFF:         PowerStateOff,
	platformv1.BMCPowerState_BMC_POWER_STATE_UNKNOWN:     PowerStateUnknown,
}

// protoBootDeviceToDevice maps proto BMCBootDevice to domain BootDevice.
var protoBootDeviceToDevice = map[platformv1.BMCBootDevice]BootDevice{
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED:   BootDeviceUnspecified,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE:           BootDevicePXE,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK:          BootDeviceDisk,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_CDROM:         BootDeviceCDROM,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA: BootDeviceVirtualMedia,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_NONE:          BootDeviceNone,
}

// protoProvisioningStatusToState maps proto BMCProvisioningStatus to domain ProvisioningState.
var protoProvisioningStatusToState = map[platformv1.BMCProvisioningStatus]ProvisioningState{
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_UNSPECIFIED:  ProvisioningStateUnspecified,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING:      ProvisioningStatePending,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_CONNECTING:   ProvisioningStateConnecting,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_SETTING_BOOT: ProvisioningStateSettingBoot,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_MOUNTING_ISO: ProvisioningStateMountingISO,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_POWERING_ON:  ProvisioningStatePoweringOn,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING:   ProvisioningStateInstalling,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FINALIZING:   ProvisioningStateFinalizing,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_COMPLETE:     ProvisioningStateComplete,
	platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FAILED:       ProvisioningStateFailed,
}

// protoPrivilegeToPrivilege maps proto BMCUserPrivilege to domain Privilege.
var protoPrivilegeToPrivilege = map[platformv1.BMCUserPrivilege]Privilege{
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED:   PrivilegeUnspecified,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK:      PrivilegeCallback,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER:          PrivilegeUser,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR:      PrivilegeOperator,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR: PrivilegeAdministrator,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS:     PrivilegeNoAccess,
}

// Domain-to-proto enum maps

// bootDeviceToProto maps domain BootDevice to proto BMCBootDevice.
var bootDeviceToProto = map[BootDevice]platformv1.BMCBootDevice{
	BootDeviceUnspecified:  platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED,
	BootDevicePXE:          platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE,
	BootDeviceDisk:         platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK,
	BootDeviceCDROM:        platformv1.BMCBootDevice_BMC_BOOT_DEVICE_CDROM,
	BootDeviceVirtualMedia: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA,
	BootDeviceNone:         platformv1.BMCBootDevice_BMC_BOOT_DEVICE_NONE,
}

// privilegeToProto maps domain Privilege to proto BMCUserPrivilege.
var privilegeToProto = map[Privilege]platformv1.BMCUserPrivilege{
	PrivilegeUnspecified:   platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED,
	PrivilegeCallback:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK,
	PrivilegeUser:          platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER,
	PrivilegeOperator:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	PrivilegeAdministrator: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
	PrivilegeNoAccess:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS,
}

// String-to-domain enum maps (for CLI input parsing)

// StringToPowerState maps user-facing power state strings to domain PowerState.
var StringToPowerState = map[string]PowerState{
	"ON":      PowerStateOn,
	"OFF":     PowerStateOff,
	"UNKNOWN": PowerStateUnknown,
}

// StringToBootDevice maps user-facing boot device strings to domain BootDevice.
var StringToBootDevice = map[string]BootDevice{
	"PXE":           BootDevicePXE,
	"DISK":          BootDeviceDisk,
	"CDROM":         BootDeviceCDROM,
	"VIRTUAL_MEDIA": BootDeviceVirtualMedia,
	"NONE":          BootDeviceNone,
}

// StringToProvisioningState maps user-facing provisioning state strings to domain ProvisioningState.
var StringToProvisioningState = map[string]ProvisioningState{
	"PENDING":      ProvisioningStatePending,
	"CONNECTING":   ProvisioningStateConnecting,
	"SETTING_BOOT": ProvisioningStateSettingBoot,
	"MOUNTING_ISO": ProvisioningStateMountingISO,
	"POWERING_ON":  ProvisioningStatePoweringOn,
	"INSTALLING":   ProvisioningStateInstalling,
	"FINALIZING":   ProvisioningStateFinalizing,
	"COMPLETE":     ProvisioningStateComplete,
	"FAILED":       ProvisioningStateFailed,
}

// StringToPrivilege maps user-facing privilege strings to domain Privilege.
var StringToPrivilege = map[string]Privilege{
	"CALLBACK":      PrivilegeCallback,
	"USER":          PrivilegeUser,
	"OPERATOR":      PrivilegeOperator,
	"ADMINISTRATOR": PrivilegeAdministrator,
	"NO_ACCESS":     PrivilegeNoAccess,
}

// ParsePowerState parses a user-facing power state string to a domain PowerState.
// Returns the PowerState and true if found, or PowerStateUnspecified and false otherwise.
func ParsePowerState(state string) (PowerState, bool) {
	s, ok := StringToPowerState[strings.ToUpper(strings.TrimSpace(state))]
	return s, ok
}

// ParseBootDevice parses a user-facing boot device string to a domain BootDevice.
// Returns the BootDevice and true if found, or BootDeviceUnspecified and false otherwise.
func ParseBootDevice(device string) (BootDevice, bool) {
	d, ok := StringToBootDevice[strings.ToUpper(strings.TrimSpace(device))]
	return d, ok
}

// ParseProvisioningState parses a user-facing provisioning state string to a domain ProvisioningState.
// Returns the ProvisioningState and true if found, or ProvisioningStateUnspecified and false otherwise.
func ParseProvisioningState(state string) (ProvisioningState, bool) {
	s, ok := StringToProvisioningState[strings.ToUpper(strings.TrimSpace(state))]
	return s, ok
}

// ParsePrivilege parses a user-facing privilege string to a domain Privilege.
// Returns the Privilege and true if found, or PrivilegeUnspecified and false otherwise.
func ParsePrivilege(priv string) (Privilege, bool) {
	p, ok := StringToPrivilege[strings.ToUpper(strings.TrimSpace(priv))]
	return p, ok
}

// Proto-to-domain converter functions

// PowerStateFromProto converts a proto BMCPowerState to a domain PowerState.
// Returns PowerStateUnspecified for unknown values.
func PowerStateFromProto(s platformv1.BMCPowerState) PowerState {
	if state, ok := protoPowerStateToState[s]; ok {
		return state
	}
	return PowerStateUnspecified
}

// BootDeviceFromProto converts a proto BMCBootDevice to a domain BootDevice.
// Returns BootDeviceUnspecified for unknown values.
func BootDeviceFromProto(d platformv1.BMCBootDevice) BootDevice {
	if device, ok := protoBootDeviceToDevice[d]; ok {
		return device
	}
	return BootDeviceUnspecified
}

// BootDeviceToProto converts a domain BootDevice to a proto BMCBootDevice.
// Returns BMC_BOOT_DEVICE_UNSPECIFIED for unknown values.
func BootDeviceToProto(d BootDevice) platformv1.BMCBootDevice {
	if proto, ok := bootDeviceToProto[d]; ok {
		return proto
	}
	return platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED
}

// ProvisioningStateFromProto converts a proto BMCProvisioningStatus to a domain ProvisioningState.
// Returns ProvisioningStateUnspecified for unknown values.
func ProvisioningStateFromProto(s platformv1.BMCProvisioningStatus) ProvisioningState {
	if state, ok := protoProvisioningStatusToState[s]; ok {
		return state
	}
	return ProvisioningStateUnspecified
}

// PrivilegeFromProto converts a proto BMCUserPrivilege to a domain Privilege.
// Returns PrivilegeUnspecified for unknown values.
func PrivilegeFromProto(p platformv1.BMCUserPrivilege) Privilege {
	if priv, ok := protoPrivilegeToPrivilege[p]; ok {
		return priv
	}
	return PrivilegeUnspecified
}

// PrivilegeToProto converts a domain Privilege to a proto BMCUserPrivilege.
// Returns BMC_USER_PRIVILEGE_UNSPECIFIED for unknown values.
func PrivilegeToProto(p Privilege) platformv1.BMCUserPrivilege {
	if proto, ok := privilegeToProto[p]; ok {
		return proto
	}
	return platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED
}

// powerResponseFromProto converts a proto BMCPowerResponse to a domain PowerResponse.
func powerResponseFromProto(p *platformv1.BMCPowerResponse) *PowerResponse {
	if p == nil {
		return nil
	}
	return &PowerResponse{
		PreviousState: PowerStateFromProto(p.PreviousState),
		CurrentState:  PowerStateFromProto(p.CurrentState),
	}
}

// sensorFromProto converts a proto BMCSensorReading to a domain SensorReading.
func sensorFromProto(p *platformv1.BMCSensorReading) SensorReading {
	if p == nil {
		return SensorReading{}
	}
	return SensorReading{
		Name:   p.Name,
		Value:  p.Value,
		Units:  p.Units,
		Status: SensorStatus(p.Status),
	}
}

// sensorsFromProto converts a slice of proto BMCSensorReading to domain SensorReading slice.
func sensorsFromProto(sensors []*platformv1.BMCSensorReading) []SensorReading {
	if len(sensors) == 0 {
		return nil
	}
	result := make([]SensorReading, len(sensors))
	for i, s := range sensors {
		result[i] = sensorFromProto(s)
	}
	return result
}

// systemInfoFromProto converts a proto BMCGetSystemInfoResponse to a domain SystemInfo.
func systemInfoFromProto(p *platformv1.BMCGetSystemInfoResponse) *SystemInfo {
	if p == nil {
		return nil
	}
	return &SystemInfo{
		Manufacturer:    p.Manufacturer,
		Product:         p.Product,
		SerialNumber:    p.SerialNumber,
		FirmwareVersion: p.FirmwareVersion,
		BIOSVersion:     p.BiosVersion,
		PowerState:      PowerStateFromProto(p.PowerState),
	}
}

// virtualMediaFromProto converts a proto BMCVirtualMediaStatusResponse to a domain VirtualMediaInfo.
func virtualMediaFromProto(p *platformv1.BMCVirtualMediaStatusResponse) *VirtualMediaInfo {
	if p == nil {
		return nil
	}
	return &VirtualMediaInfo{
		Mounted:   p.Mounted,
		ImageURL:  p.ImageUrl,
		MediaType: p.MediaType,
	}
}

// provisionResultFromProto converts a proto BMCProvisionResponse to a domain ProvisionResult.
func provisionResultFromProto(p *platformv1.BMCProvisionResponse) *ProvisionResult {
	if p == nil {
		return nil
	}
	return &ProvisionResult{
		ProvisionID: p.ProvisionId,
		State:       ProvisioningStateFromProto(p.Status),
	}
}

// provisioningStatusFromProto converts a proto BMCProvisionStatusResponse to a domain ProvisioningStatus.
func provisioningStatusFromProto(p *platformv1.BMCProvisionStatusResponse) *ProvisioningStatus {
	if p == nil {
		return nil
	}
	return &ProvisioningStatus{
		State:     ProvisioningStateFromProto(p.Status),
		Message:   p.Message,
		StartedAt: timestampToTime(p.StartedAt),
		UpdatedAt: timestampToTime(p.UpdatedAt),
	}
}

// certificateInfoFromProto converts a proto BMCGetWebCertificateResponse to a domain CertificateInfo.
func certificateInfoFromProto(p *platformv1.BMCGetWebCertificateResponse) *CertificateInfo {
	if p == nil {
		return nil
	}
	return &CertificateInfo{
		Subject:                 p.Subject,
		Issuer:                  p.Issuer,
		SerialNumber:            p.SerialNumber,
		NotBefore:               timestampToTime(p.NotBefore),
		NotAfter:                timestampToTime(p.NotAfter),
		DaysRemaining:           p.DaysRemaining,
		SubjectAlternativeNames: p.SubjectAlternativeNames,
		Fingerprint:             p.Fingerprint,
	}
}

// userFromProto converts a proto BMCUser to a domain User.
func userFromProto(p *platformv1.BMCUser) User {
	if p == nil {
		return User{}
	}
	return User{
		Slot:      p.Slot,
		Username:  p.Username,
		Enabled:   p.Enabled,
		Privilege: PrivilegeFromProto(p.Privilege),
		Channel:   p.Channel,
	}
}

// usersFromProto converts a slice of proto BMCUser to domain User slice.
func usersFromProto(users []*platformv1.BMCUser) []User {
	if len(users) == 0 {
		return nil
	}
	result := make([]User, len(users))
	for i, u := range users {
		result[i] = userFromProto(u)
	}
	return result
}

// userToProto converts a domain User to a proto BMCUser.
func userToProto(u *User) *platformv1.BMCUser {
	if u == nil {
		return nil
	}
	return &platformv1.BMCUser{
		Slot:      u.Slot,
		Username:  u.Username,
		Enabled:   u.Enabled,
		Privilege: PrivilegeToProto(u.Privilege),
		Channel:   u.Channel,
	}
}

// timestampToTime converts a protobuf Timestamp to time.Time.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// =============================================================================
// Enrollment converters
// =============================================================================

// enrollStepFromProto converts a proto BMCEnrollStep to a domain EnrollStep.
func enrollStepFromProto(p *platformv1.BMCEnrollStep) EnrollStep {
	if p == nil {
		return EnrollStep{}
	}
	return EnrollStep{
		Name:   p.Name,
		OK:     p.Ok,
		Detail: p.Detail,
	}
}

// enrollStepsFromProto converts a slice of proto BMCEnrollStep to domain EnrollStep slice.
func enrollStepsFromProto(steps []*platformv1.BMCEnrollStep) []EnrollStep {
	if len(steps) == 0 {
		return nil
	}
	result := make([]EnrollStep, len(steps))
	for i, s := range steps {
		result[i] = enrollStepFromProto(s)
	}
	return result
}

// factoryCertMetaFromProto converts a proto BMCFactoryCertMeta to a domain FactoryCertMeta.
func factoryCertMetaFromProto(p *platformv1.BMCFactoryCertMeta) FactoryCertMeta {
	if p == nil {
		return FactoryCertMeta{}
	}
	return FactoryCertMeta{
		Subject:      p.Subject,
		Issuer:       p.Issuer,
		SerialNumber: p.SerialNumber,
		NotBefore:    timestampToTime(p.NotBefore),
		NotAfter:     timestampToTime(p.NotAfter),
		SPKISHA256:   p.SpkiSha256,
		SHA256:       p.Sha256,
		CapturedAt:   timestampToTime(p.CapturedAt),
	}
}

// enrollResultFromProto converts a proto BMCEnrollResponse to a domain EnrollResult.
// Returns nil when the input is nil.
func enrollResultFromProto(p *platformv1.BMCEnrollResponse) *EnrollResult {
	if p == nil {
		return nil
	}
	return &EnrollResult{
		DeviceID:        p.DeviceId,
		Endpoint:        p.Endpoint,
		Hostname:        p.Hostname,
		DNSName:         p.DnsName,
		PinSPKISHA256:   p.PinSpkiSha256,
		FactoryCertPEM:  string(p.FactoryCertPem),
		FactoryCertMeta: factoryCertMetaFromProto(p.FactoryCertMeta),
		NewCertPEM:      string(p.NewCertPem),
		CACertPEM:       string(p.CaCertPem),
		Steps:           enrollStepsFromProto(p.Steps),
	}
}

// enrollOptionsToProto converts an EnrollOptions (may be nil) and profileID to
// a proto BMCEnrollRequest. Nil opts leaves all optional bool fields unset.
func enrollOptionsToProto(profileID uint64, opts *EnrollOptions) *platformv1.BMCEnrollRequest {
	req := &platformv1.BMCEnrollRequest{ProfileId: profileID}
	if opts == nil {
		return req
	}
	req.ReplaceCertificate = opts.ReplaceCertificate
	req.RotatePassword = opts.RotatePassword
	req.DnsRegister = opts.DNSRegister
	req.DanePublish = opts.DANEPublish
	return req
}

// =============================================================================
// Restore converters
// =============================================================================

// restoreResultFromProto converts a proto BMCRestoreResponse to a domain
// RestoreResult. Returns nil when the input is nil.
func restoreResultFromProto(p *platformv1.BMCRestoreResponse) *RestoreResult {
	if p == nil {
		return nil
	}
	return &RestoreResult{
		DeviceID:    p.DeviceId,
		Endpoint:    p.Endpoint,
		Hostname:    p.Hostname,
		NewCertMeta: factoryCertMetaFromProto(p.NewCertMeta),
		NewCertPEM:  string(p.NewCertPem),
		Steps:       enrollStepsFromProto(p.Steps),
	}
}
