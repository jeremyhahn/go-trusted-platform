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

package piv

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestAlgorithmWire(t *testing.T) {
	for wire, pb := range map[string]platformv1.PIVAlgorithm{
		"":        platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED,
		"rsa":     platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA,
		"ecdsa":   platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA,
		"ed25519": platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519,
	} {
		got, err := AlgorithmFromWire(wire)
		if err != nil || got != pb {
			t.Errorf("AlgorithmFromWire(%q) = %v, %v; want %v", wire, got, err, pb)
		}
		back, err := AlgorithmToWire(pb)
		if err != nil || back != wire {
			t.Errorf("AlgorithmToWire(%v) = %q, %v; want %q", pb, back, err, wire)
		}
	}
}

func TestAlgorithmWireRejectsUnknown(t *testing.T) {
	var unknown *ErrUnknownWireValue
	if _, err := AlgorithmFromWire("dsa"); !errors.As(err, &unknown) {
		t.Fatalf("AlgorithmFromWire(dsa) error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := AlgorithmToWire(platformv1.PIVAlgorithm(99)); !errors.As(err, &unknown) {
		t.Fatalf("AlgorithmToWire(99) error = %v; want ErrUnknownWireValue", err)
	}
}

func TestDecodeListDevicesJSON(t *testing.T) {
	out, err := DecodeListDevicesJSON([]byte(`{"devices":[{"ID":"d1","Name":"YubiKey","Manufacturer":"Yubico","Model":"5","Serial":"123","FirmwareVersion":"5.4.3"}]}`))
	if err != nil {
		t.Fatalf("DecodeListDevicesJSON: %v", err)
	}
	d := out.GetDevices()
	if len(d) != 1 || d[0].GetId() != "d1" || d[0].GetFirmwareVersion() != "5.4.3" || d[0].GetSerial() != "123" {
		t.Fatalf("devices = %v", d)
	}
}

func TestDecodeListSlotsJSON(t *testing.T) {
	out, err := DecodeListSlotsJSON([]byte(`{"slots":[{"ID":"9a","Name":"PIV Auth","Algorithm":"ecdsa","HasKey":true,"HasCertificate":false}]}`))
	if err != nil {
		t.Fatalf("DecodeListSlotsJSON: %v", err)
	}
	s := out.GetSlots()
	if len(s) != 1 || s[0].GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA || !s[0].GetHasKey() || s[0].GetHasCertificate() {
		t.Fatalf("slots = %v", s)
	}
}

func TestDecodeSlotInfoJSON(t *testing.T) {
	out, err := DecodeSlotInfoJSON([]byte(`{"Slot":{"ID":"9a","Name":"PIV Auth","Algorithm":"rsa","HasKey":true,"HasCertificate":true},"PublicKeyPEM":"PUB","CertificatePEM":"CERT"}`))
	if err != nil {
		t.Fatalf("DecodeSlotInfoJSON: %v", err)
	}
	if out.GetSlot().GetId() != "9a" || out.GetPublicKeyPem() != "PUB" || out.GetCertificatePem() != "CERT" ||
		out.GetSlot().GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA {
		t.Fatalf("DecodeSlotInfoJSON = %v", out)
	}
}

func TestDecodeJSONRejectsBadInput(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"devices": func(b []byte) error { _, err := DecodeListDevicesJSON(b); return err },
		"slots":   func(b []byte) error { _, err := DecodeListSlotsJSON(b); return err },
		"info":    func(b []byte) error { _, err := DecodeSlotInfoJSON(b); return err },
	}
	for name, decode := range decoders {
		var wireErr *ErrWireDecode
		if err := decode([]byte(`not json`)); !errors.As(err, &wireErr) {
			t.Errorf("%s: malformed JSON error = %v; want ErrWireDecode", name, err)
		}
	}
	var unknown *ErrUnknownWireValue
	if _, err := DecodeListSlotsJSON([]byte(`{"slots":[{"Algorithm":"dsa"}]}`)); !errors.As(err, &unknown) {
		t.Errorf("slots unknown algorithm error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := DecodeSlotInfoJSON([]byte(`{"Slot":{"Algorithm":"dsa"}}`)); !errors.As(err, &unknown) {
		t.Errorf("info unknown algorithm error = %v; want ErrUnknownWireValue", err)
	}
}
