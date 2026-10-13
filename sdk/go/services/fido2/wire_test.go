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

package fido2

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestRoleToWire(t *testing.T) {
	for pb, wire := range map[platformv1.FIDO2Role]string{
		platformv1.FIDO2Role_FIDO2_ROLE_UNSPECIFIED: "",
		platformv1.FIDO2Role_FIDO2_ROLE_SO:          "so",
		platformv1.FIDO2Role_FIDO2_ROLE_ADMIN:       "admin",
		platformv1.FIDO2Role_FIDO2_ROLE_USER:        "user",
	} {
		got, err := RoleToWire(pb)
		if err != nil || got != wire {
			t.Errorf("RoleToWire(%v) = %q, %v; want %q", pb, got, err, wire)
		}
	}
}

func TestRoleToWireRejectsUnknown(t *testing.T) {
	var unknown *ErrUnknownWireValue
	if _, err := RoleToWire(platformv1.FIDO2Role(99)); !errors.As(err, &unknown) {
		t.Fatalf("RoleToWire(99) error = %v; want ErrUnknownWireValue", err)
	}
}

const deviceBody = `{"ID":"d1","Path":"/dev/hidraw0","Manufacturer":"Yubico","Product":"YubiKey","ProductID":1031,"VendorID":4176}`

func TestDecodeDeviceJSON(t *testing.T) {
	list, err := DecodeListDevicesJSON([]byte(`{"devices":[` + deviceBody + `]}`))
	if err != nil || len(list.GetDevices()) != 1 {
		t.Fatalf("DecodeListDevicesJSON = %v, %v", list, err)
	}
	d := list.GetDevices()[0]
	if d.GetId() != "d1" || d.GetProductId() != 1031 || d.GetVendorId() != 4176 || d.GetPath() != "/dev/hidraw0" {
		t.Fatalf("device = %v", d)
	}
	wait, err := DecodeWaitDeviceJSON([]byte(deviceBody))
	if err != nil || wait.GetDevice().GetProduct() != "YubiKey" {
		t.Fatalf("DecodeWaitDeviceJSON = %v, %v", wait, err)
	}
}

func TestDecodeInfoJSON(t *testing.T) {
	out, err := DecodeInfoJSON([]byte(`{"Device":` + deviceBody + `,"AAGUID":"aa","FirmwareVersion":"5.4","Extensions":["hmac-secret"],"Options":{"clientPin":true},"MaxMsgSize":1200}`))
	if err != nil {
		t.Fatalf("DecodeInfoJSON: %v", err)
	}
	info := out.GetInfo()
	if info.GetAaguid() != "aa" || info.GetMaxMsgSize() != 1200 || !info.GetOptions()["clientPin"] ||
		info.GetExtensions()[0] != "hmac-secret" || info.GetDevice().GetId() != "d1" {
		t.Fatalf("DecodeInfoJSON = %v", out)
	}
}

func TestDecodeRegisterAndAuthenticateJSON(t *testing.T) {
	reg, err := DecodeRegisterJSON([]byte(`{"CredentialID":"cred","AAGUID":"aa","PublicKeyPEM":"PUB"}`))
	if err != nil || reg.GetCredentialId() != "cred" || reg.GetAaguid() != "aa" || reg.GetPublicKeyPem() != "PUB" {
		t.Fatalf("DecodeRegisterJSON = %v, %v", reg, err)
	}
	auth, err := DecodeAuthenticateJSON([]byte(`{"Authenticated":true,"Counter":7}`))
	if err != nil || !auth.GetAuthenticated() || auth.GetCounter() != 7 {
		t.Fatalf("DecodeAuthenticateJSON = %v, %v", auth, err)
	}
}

func TestDecodeJSONRejectsBadInput(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"list":         func(b []byte) error { _, err := DecodeListDevicesJSON(b); return err },
		"wait":         func(b []byte) error { _, err := DecodeWaitDeviceJSON(b); return err },
		"info":         func(b []byte) error { _, err := DecodeInfoJSON(b); return err },
		"register":     func(b []byte) error { _, err := DecodeRegisterJSON(b); return err },
		"authenticate": func(b []byte) error { _, err := DecodeAuthenticateJSON(b); return err },
	}
	for name, decode := range decoders {
		var wireErr *ErrWireDecode
		if err := decode([]byte(`not json`)); !errors.As(err, &wireErr) {
			t.Errorf("%s: malformed JSON error = %v; want ErrWireDecode", name, err)
		}
	}
}
