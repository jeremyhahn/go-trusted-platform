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

package luks

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestKeyTypeFromWire(t *testing.T) {
	for wire, want := range keyTypeToProto {
		got, err := KeyTypeFromWire(string(wire))
		if err != nil || got != want {
			t.Errorf("KeyTypeFromWire(%q) = %v, %v; want %v", wire, got, err, want)
		}
		// Every wire value must round-trip through the gRPC client mapping.
		if back := keyTypeFromProto[got]; back != wire {
			t.Errorf("keyTypeFromProto[%v] = %q; want %q", got, back, wire)
		}
	}
}

func TestKeyTypeFromWireRejectsUnknown(t *testing.T) {
	var unknown *ErrUnknownWireValue
	if _, err := KeyTypeFromWire("smartcard"); !errors.As(err, &unknown) || unknown.Value != "smartcard" {
		t.Fatalf("KeyTypeFromWire(smartcard) error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := KeyslotFromWire(1, "smartcard", 512, 1); !errors.As(err, &unknown) {
		t.Fatalf("KeyslotFromWire error = %v; want ErrUnknownWireValue", err)
	}
}

func TestDecodeStatusJSON(t *testing.T) {
	out, err := DecodeStatusJSON([]byte(`{"Device":"/dev/sda2","IsLUKS":true,"Version":2,"UUID":"u-1","Label":"root","Cipher":"aes-xts-plain64","ActiveSlots":[0,2]}`))
	if err != nil {
		t.Fatalf("DecodeStatusJSON: %v", err)
	}
	want := &platformv1.LUKSStatusResponse{
		Device: "/dev/sda2", IsLuks: true, Version: 2, Uuid: "u-1", Label: "root",
		Cipher: "aes-xts-plain64", ActiveSlots: []int32{0, 2},
	}
	if !proto.Equal(out, want) {
		t.Fatalf("status = %v; want %v", out, want)
	}
}

func TestDecodeListSlotsJSON(t *testing.T) {
	out, err := DecodeListSlotsJSON([]byte(`{"Device":"/dev/sda2","Slots":[{"Slot":1,"Type":"tpm","KeySize":512,"Priority":1}]}`))
	if err != nil {
		t.Fatalf("DecodeListSlotsJSON: %v", err)
	}
	want := &platformv1.LUKSListSlotsResponse{
		Device: "/dev/sda2",
		Slots:  []*platformv1.LUKSKeyslot{{Slot: 1, Type: platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM, KeySize: 512, Priority: 1}},
	}
	if !proto.Equal(out, want) {
		t.Fatalf("slots = %v; want %v", out, want)
	}
}

func TestDecodeInfoJSON(t *testing.T) {
	out, err := DecodeInfoJSON([]byte(`{"Device":"/dev/sda2","UUID":"u-1","Label":"root","Version":2,"Cipher":"aes-xts-plain64","KeySize":512,"SectorSize":4096,"Slots":[{"Slot":0,"Type":"passphrase"}],"MetadataJSON":"{}"}`))
	if err != nil {
		t.Fatalf("DecodeInfoJSON: %v", err)
	}
	want := &platformv1.LUKSInfoResponse{
		Device: "/dev/sda2", Uuid: "u-1", Label: "root", Version: 2, Cipher: "aes-xts-plain64",
		KeySize: 512, SectorSize: 4096, MetadataJson: "{}",
		Slots: []*platformv1.LUKSKeyslot{{Slot: 0, Type: platformv1.LUKSKeyType_LUKS_KEY_TYPE_PASSPHRASE}},
	}
	if !proto.Equal(out, want) {
		t.Fatalf("info = %v; want %v", out, want)
	}
}

func TestDecodeEnrollJSON(t *testing.T) {
	passphrase, err := DecodeEnrollPassphraseJSON([]byte(`{"Slot":3}`))
	if err != nil || passphrase.GetSlot() != 3 {
		t.Errorf("DecodeEnrollPassphraseJSON = %v, %v", passphrase, err)
	}
	fido2, err := DecodeEnrollFIDO2JSON([]byte(`{"Slot":4,"TokenID":"tok-f"}`))
	if err != nil || fido2.GetSlot() != 4 || fido2.GetTokenId() != "tok-f" {
		t.Errorf("DecodeEnrollFIDO2JSON = %v, %v", fido2, err)
	}
	tpm, err := DecodeEnrollTPMJSON([]byte(`{"Slot":5,"TokenID":"tok-t"}`))
	if err != nil || tpm.GetSlot() != 5 || tpm.GetTokenId() != "tok-t" {
		t.Errorf("DecodeEnrollTPMJSON = %v, %v", tpm, err)
	}
	recovery, err := DecodeEnrollRecoveryJSON([]byte(`{"Slot":6,"RecoveryKey":"abcd-efgh"}`))
	if err != nil || recovery.GetSlot() != 6 || recovery.GetRecoveryKey() != "abcd-efgh" {
		t.Errorf("DecodeEnrollRecoveryJSON = %v, %v", recovery, err)
	}
}

func TestDecodeJSONRejectsBadInput(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"status":            func(b []byte) error { _, err := DecodeStatusJSON(b); return err },
		"list slots":        func(b []byte) error { _, err := DecodeListSlotsJSON(b); return err },
		"info":              func(b []byte) error { _, err := DecodeInfoJSON(b); return err },
		"enroll passphrase": func(b []byte) error { _, err := DecodeEnrollPassphraseJSON(b); return err },
		"enroll fido2":      func(b []byte) error { _, err := DecodeEnrollFIDO2JSON(b); return err },
		"enroll tpm":        func(b []byte) error { _, err := DecodeEnrollTPMJSON(b); return err },
		"enroll recovery":   func(b []byte) error { _, err := DecodeEnrollRecoveryJSON(b); return err },
	}
	for name, decode := range decoders {
		var wireErr *ErrWireDecode
		if err := decode([]byte(`not json`)); !errors.As(err, &wireErr) || wireErr.Message != name {
			t.Errorf("%s: malformed JSON error = %v; want ErrWireDecode", name, err)
		}
	}
	var unknown *ErrUnknownWireValue
	if _, err := DecodeListSlotsJSON([]byte(`{"Slots":[{"Type":"smartcard"}]}`)); !errors.As(err, &unknown) {
		t.Errorf("list slots unknown type error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := DecodeInfoJSON([]byte(`{"Slots":[{"Type":"smartcard"}]}`)); !errors.As(err, &unknown) {
		t.Errorf("info unknown type error = %v; want ErrUnknownWireValue", err)
	}
}
