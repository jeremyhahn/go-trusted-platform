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
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Parse* tests (string parsing)
// =============================================================================

func TestBMCParsePowerState_AllValues(t *testing.T) {
	cases := []struct {
		in    string
		want  PowerState
		valid bool
	}{
		{"ON", PowerStateOn, true},
		{"OFF", PowerStateOff, true},
		{"UNKNOWN", PowerStateUnknown, true},
		{"  on  ", PowerStateOn, true}, // trim + case
		{"off", PowerStateOff, true},   // lowercase
		{"", "", false},
		{"garbage", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParsePowerState(tc.in)
			if ok != tc.valid {
				t.Errorf("ParsePowerState(%q) ok = %v, want %v", tc.in, ok, tc.valid)
			}
			if got != tc.want {
				t.Errorf("ParsePowerState(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestBMCParseBootDevice_AllValues(t *testing.T) {
	cases := []struct {
		in    string
		want  BootDevice
		valid bool
	}{
		{"PXE", BootDevicePXE, true},
		{"DISK", BootDeviceDisk, true},
		{"CDROM", BootDeviceCDROM, true},
		{"VIRTUAL_MEDIA", BootDeviceVirtualMedia, true},
		{"NONE", BootDeviceNone, true},
		{"  pxe  ", BootDevicePXE, true},
		{"", "", false},
		{"garbage", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseBootDevice(tc.in)
			if ok != tc.valid || got != tc.want {
				t.Errorf("ParseBootDevice(%q) = (%v, %v), want (%v, %v)",
					tc.in, got, ok, tc.want, tc.valid)
			}
		})
	}
}

func TestBMCParseProvisioningState_AllValues(t *testing.T) {
	cases := []struct {
		in    string
		want  ProvisioningState
		valid bool
	}{
		{"PENDING", ProvisioningStatePending, true},
		{"CONNECTING", ProvisioningStateConnecting, true},
		{"SETTING_BOOT", ProvisioningStateSettingBoot, true},
		{"MOUNTING_ISO", ProvisioningStateMountingISO, true},
		{"POWERING_ON", ProvisioningStatePoweringOn, true},
		{"INSTALLING", ProvisioningStateInstalling, true},
		{"FINALIZING", ProvisioningStateFinalizing, true},
		{"COMPLETE", ProvisioningStateComplete, true},
		{"FAILED", ProvisioningStateFailed, true},
		{"  pending  ", ProvisioningStatePending, true},
		{"", "", false},
		{"garbage", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseProvisioningState(tc.in)
			if ok != tc.valid || got != tc.want {
				t.Errorf("ParseProvisioningState(%q) = (%v, %v), want (%v, %v)",
					tc.in, got, ok, tc.want, tc.valid)
			}
		})
	}
}

func TestBMCParsePrivilege_AllValues(t *testing.T) {
	cases := []struct {
		in    string
		want  Privilege
		valid bool
	}{
		{"CALLBACK", PrivilegeCallback, true},
		{"USER", PrivilegeUser, true},
		{"OPERATOR", PrivilegeOperator, true},
		{"ADMINISTRATOR", PrivilegeAdministrator, true},
		{"NO_ACCESS", PrivilegeNoAccess, true},
		{"  administrator  ", PrivilegeAdministrator, true},
		{"", "", false},
		{"garbage", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParsePrivilege(tc.in)
			if ok != tc.valid || got != tc.want {
				t.Errorf("ParsePrivilege(%q) = (%v, %v), want (%v, %v)",
					tc.in, got, ok, tc.want, tc.valid)
			}
		})
	}
}

// =============================================================================
// Proto <-> domain enum converters
// =============================================================================

func TestBMCPowerStateFromProto_RoundTrip(t *testing.T) {
	cases := []struct {
		in   platformv1.BMCPowerState
		want PowerState
	}{
		{platformv1.BMCPowerState_BMC_POWER_STATE_UNSPECIFIED, PowerStateUnspecified},
		{platformv1.BMCPowerState_BMC_POWER_STATE_ON, PowerStateOn},
		{platformv1.BMCPowerState_BMC_POWER_STATE_OFF, PowerStateOff},
		{platformv1.BMCPowerState_BMC_POWER_STATE_UNKNOWN, PowerStateUnknown},
		{platformv1.BMCPowerState(9999), PowerStateUnspecified}, // unknown proto value
	}
	for _, tc := range cases {
		if got := PowerStateFromProto(tc.in); got != tc.want {
			t.Errorf("PowerStateFromProto(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBMCBootDevice_RoundTrip(t *testing.T) {
	devices := []BootDevice{
		BootDeviceUnspecified,
		BootDevicePXE,
		BootDeviceDisk,
		BootDeviceCDROM,
		BootDeviceVirtualMedia,
		BootDeviceNone,
	}
	for _, d := range devices {
		proto := BootDeviceToProto(d)
		back := BootDeviceFromProto(proto)
		if back != d {
			t.Errorf("round trip %v -> %v -> %v", d, proto, back)
		}
	}
	// unknown domain value
	if got := BootDeviceToProto(BootDevice("garbage")); got != platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED {
		t.Errorf("unknown domain -> %v, want UNSPECIFIED", got)
	}
	// unknown proto value
	if got := BootDeviceFromProto(platformv1.BMCBootDevice(9999)); got != BootDeviceUnspecified {
		t.Errorf("unknown proto -> %v, want UNSPECIFIED", got)
	}
}

func TestBMCProvisioningStateFromProto_AllValues(t *testing.T) {
	cases := []struct {
		in   platformv1.BMCProvisioningStatus
		want ProvisioningState
	}{
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_UNSPECIFIED, ProvisioningStateUnspecified},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING, ProvisioningStatePending},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_CONNECTING, ProvisioningStateConnecting},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_SETTING_BOOT, ProvisioningStateSettingBoot},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_MOUNTING_ISO, ProvisioningStateMountingISO},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_POWERING_ON, ProvisioningStatePoweringOn},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING, ProvisioningStateInstalling},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FINALIZING, ProvisioningStateFinalizing},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_COMPLETE, ProvisioningStateComplete},
		{platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FAILED, ProvisioningStateFailed},
		{platformv1.BMCProvisioningStatus(9999), ProvisioningStateUnspecified},
	}
	for _, tc := range cases {
		if got := ProvisioningStateFromProto(tc.in); got != tc.want {
			t.Errorf("ProvisioningStateFromProto(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBMCPrivilege_RoundTrip(t *testing.T) {
	privs := []Privilege{
		PrivilegeUnspecified,
		PrivilegeCallback,
		PrivilegeUser,
		PrivilegeOperator,
		PrivilegeAdministrator,
		PrivilegeNoAccess,
	}
	for _, p := range privs {
		proto := PrivilegeToProto(p)
		back := PrivilegeFromProto(proto)
		if back != p {
			t.Errorf("round trip %v -> %v -> %v", p, proto, back)
		}
	}
	if got := PrivilegeToProto(Privilege("garbage")); got != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED {
		t.Errorf("unknown domain -> %v, want UNSPECIFIED", got)
	}
	if got := PrivilegeFromProto(platformv1.BMCUserPrivilege(9999)); got != PrivilegeUnspecified {
		t.Errorf("unknown proto -> %v, want UNSPECIFIED", got)
	}
}

// =============================================================================
// Struct converters
// =============================================================================

func TestBMCPowerResponseFromProto_Nil(t *testing.T) {
	if got := powerResponseFromProto(nil); got != nil {
		t.Errorf("powerResponseFromProto(nil) = %+v, want nil", got)
	}
}

func TestBMCPowerResponseFromProto_Populated(t *testing.T) {
	in := &platformv1.BMCPowerResponse{
		PreviousState: platformv1.BMCPowerState_BMC_POWER_STATE_OFF,
		CurrentState:  platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}
	got := powerResponseFromProto(in)
	if got.PreviousState != PowerStateOff || got.CurrentState != PowerStateOn {
		t.Errorf("got %+v", got)
	}
}

func TestBMCSensorFromProto_Nil(t *testing.T) {
	zero := sensorFromProto(nil)
	if zero != (SensorReading{}) {
		t.Errorf("expected zero value, got %+v", zero)
	}
}

func TestBMCSensorFromProto_Populated(t *testing.T) {
	in := &platformv1.BMCSensorReading{Name: "cpu", Value: 42.5, Units: "C", Status: "OK"}
	got := sensorFromProto(in)
	if got.Name != "cpu" || got.Value != 42.5 || got.Units != "C" || got.Status != SensorStatusOK {
		t.Errorf("got %+v", got)
	}
}

func TestBMCSensorsFromProto_Empty(t *testing.T) {
	if got := sensorsFromProto(nil); got != nil {
		t.Errorf("sensorsFromProto(nil) = %v, want nil", got)
	}
	if got := sensorsFromProto([]*platformv1.BMCSensorReading{}); got != nil {
		t.Errorf("sensorsFromProto(empty) = %v, want nil", got)
	}
}

func TestBMCSensorsFromProto_Multiple(t *testing.T) {
	in := []*platformv1.BMCSensorReading{
		{Name: "a", Value: 1},
		{Name: "b", Value: 2},
	}
	out := sensorsFromProto(in)
	if len(out) != 2 || out[0].Name != "a" || out[1].Name != "b" {
		t.Errorf("out = %+v", out)
	}
}

func TestBMCSystemInfoFromProto_Nil(t *testing.T) {
	if got := systemInfoFromProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCSystemInfoFromProto_Populated(t *testing.T) {
	in := &platformv1.BMCGetSystemInfoResponse{
		Manufacturer:    "SM",
		Product:         "X10",
		SerialNumber:    "S",
		FirmwareVersion: "F",
		BiosVersion:     "B",
		PowerState:      platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}
	got := systemInfoFromProto(in)
	if got.Manufacturer != "SM" || got.Product != "X10" || got.SerialNumber != "S" ||
		got.FirmwareVersion != "F" || got.BIOSVersion != "B" || got.PowerState != PowerStateOn {
		t.Errorf("got %+v", got)
	}
}

func TestBMCVirtualMediaFromProto_Nil(t *testing.T) {
	if got := virtualMediaFromProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCVirtualMediaFromProto_Populated(t *testing.T) {
	in := &platformv1.BMCVirtualMediaStatusResponse{Mounted: true, ImageUrl: "x", MediaType: "iso"}
	got := virtualMediaFromProto(in)
	if !got.Mounted || got.ImageURL != "x" || got.MediaType != "iso" {
		t.Errorf("got %+v", got)
	}
}

func TestBMCProvisionResultFromProto_Nil(t *testing.T) {
	if got := provisionResultFromProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCProvisionResultFromProto_Populated(t *testing.T) {
	in := &platformv1.BMCProvisionResponse{
		ProvisionId: "p-1",
		Status:      platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING,
	}
	got := provisionResultFromProto(in)
	if got.ProvisionID != "p-1" || got.State != ProvisioningStateInstalling {
		t.Errorf("got %+v", got)
	}
}

func TestBMCProvisioningStatusFromProto_Nil(t *testing.T) {
	if got := provisioningStatusFromProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCProvisioningStatusFromProto_Populated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := &platformv1.BMCProvisionStatusResponse{
		Status:    platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FINALIZING,
		Message:   "wrapping up",
		StartedAt: timestamppb.New(now),
		UpdatedAt: timestamppb.New(now),
	}
	got := provisioningStatusFromProto(in)
	if got.State != ProvisioningStateFinalizing || got.Message != "wrapping up" ||
		!got.StartedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
		t.Errorf("got %+v", got)
	}
}

func TestBMCCertificateInfoFromProto_Nil(t *testing.T) {
	if got := certificateInfoFromProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCCertificateInfoFromProto_Populated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := &platformv1.BMCGetWebCertificateResponse{
		Subject:                 "CN=x",
		Issuer:                  "CN=issuer",
		SerialNumber:            "AB",
		NotBefore:               timestamppb.New(now),
		NotAfter:                timestamppb.New(now.Add(time.Hour)),
		DaysRemaining:           7,
		SubjectAlternativeNames: []string{"x.example"},
		Fingerprint:             "fp",
	}
	got := certificateInfoFromProto(in)
	if got.Subject != "CN=x" || got.DaysRemaining != 7 || got.Fingerprint != "fp" ||
		len(got.SubjectAlternativeNames) != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestBMCUserFromProto_Nil(t *testing.T) {
	if got := userFromProto(nil); got != (User{}) {
		t.Errorf("expected zero, got %+v", got)
	}
}

func TestBMCUser_RoundTrip(t *testing.T) {
	in := &User{
		Slot:      1,
		Username:  "admin",
		Enabled:   true,
		Privilege: PrivilegeAdministrator,
		Channel:   2,
	}
	proto := userToProto(in)
	if proto == nil {
		t.Fatal("userToProto returned nil")
	}
	if proto.Privilege != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR ||
		proto.Slot != 1 || proto.Username != "admin" ||
		!proto.Enabled || proto.Channel != 2 {
		t.Errorf("proto = %+v", proto)
	}
	back := userFromProto(proto)
	if back.Slot != in.Slot || back.Username != in.Username ||
		back.Enabled != in.Enabled || back.Privilege != in.Privilege ||
		back.Channel != in.Channel {
		t.Errorf("round trip: %+v -> %+v", in, back)
	}
}

func TestBMCUserToProto_Nil(t *testing.T) {
	if got := userToProto(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBMCUsersFromProto_Empty(t *testing.T) {
	if got := usersFromProto(nil); got != nil {
		t.Errorf("usersFromProto(nil) = %v, want nil", got)
	}
	if got := usersFromProto([]*platformv1.BMCUser{}); got != nil {
		t.Errorf("usersFromProto(empty) = %v, want nil", got)
	}
}

func TestBMCUsersFromProto_Multiple(t *testing.T) {
	in := []*platformv1.BMCUser{
		{Slot: 1, Username: "a"},
		{Slot: 2, Username: "b"},
	}
	out := usersFromProto(in)
	if len(out) != 2 || out[0].Username != "a" || out[1].Username != "b" {
		t.Errorf("out = %+v", out)
	}
}

func TestBMCTimestampToTime_Nil(t *testing.T) {
	if got := timestampToTime(nil); !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}

func TestBMCTimestampToTime_NonNil(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	got := timestampToTime(timestamppb.New(now))
	if !got.Equal(now) {
		t.Errorf("got %v, want %v", got, now)
	}
}
