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

package uefi

import (
	"encoding/binary"
	"testing"
)

// The variable-header layout is a property of the STORE, not of an individual
// variable's attributes. Writing a 32-byte (non-authenticated) header into an
// AUTHENTICATED variable store produces a store the firmware cannot walk — it
// faults the EDK2 variable driver with #UD on the next boot. These tests pin
// the corrected contract so the regression cannot return.

// buildStore assembles a minimal firmware volume containing a variable store
// with the given signature GUID and an empty (0xFF) variable area.
func buildStore(t *testing.T, storeGUID GUID, size int) []byte {
	t.Helper()

	const fvHeaderLen = 0x48
	data := make([]byte, size)
	for i := range data {
		data[i] = 0xFF
	}

	// Firmware volume header.
	copy(data[16:32], NVRAMVariableStoreGUID.Bytes())
	binary.LittleEndian.PutUint64(data[32:40], uint64(size))
	copy(data[40:44], FirmwareVolumeSignature[:])
	binary.LittleEndian.PutUint16(data[48:50], fvHeaderLen)

	// Variable store header (28 bytes).
	copy(data[fvHeaderLen:fvHeaderLen+16], storeGUID.Bytes())
	binary.LittleEndian.PutUint32(data[fvHeaderLen+16:], uint32(size-fvHeaderLen))
	data[fvHeaderLen+20] = 0x5A // Format: VARIABLE_STORE_FORMATTED
	data[fvHeaderLen+21] = 0xFE // State:  VARIABLE_STORE_HEALTHY

	return data
}

func TestAuthenticatedStoreUsesAuthHeaderForEveryVariable(t *testing.T) {
	nvram, err := ParseNVRAM(buildStore(t, AuthenticatedVariableGUID, 0x4000), "")
	if err != nil {
		t.Fatalf("ParseNVRAM: %v", err)
	}
	if !nvram.IsAuthenticatedStore() {
		t.Fatal("store with the authenticated signature GUID not detected as authenticated")
	}

	// A variable WITHOUT the time-based-auth attribute (like the firmware's
	// SetupMode / SecureBoot) must still be serialized with the 60-byte
	// authenticated header inside an authenticated store.
	plainAttrs := AttrNonVolatile | AttrBootserviceAccess | AttrRuntimeAccess
	if err := nvram.SetVariable("PlainVar", EFIGlobalVariable, plainAttrs, []byte{0x01}); err != nil {
		t.Fatalf("SetVariable: %v", err)
	}
	// And an authenticated one alongside it.
	if err := nvram.SetVariable("AuthVar", EFIGlobalVariable, SecureBootAttributes, []byte{0x02, 0x03}); err != nil {
		t.Fatalf("SetVariable: %v", err)
	}

	out, err := nvram.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	// Round-tripping must recover both variables. A mixed-header store would
	// misparse the second variable (or worse, walk into garbage).
	reparsed, err := ParseNVRAM(out, "")
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	plain, err := reparsed.GetVariable("PlainVar", EFIGlobalVariable)
	if err != nil {
		t.Fatalf("PlainVar not recovered: %v", err)
	}
	if len(plain.Data) != 1 || plain.Data[0] != 0x01 {
		t.Errorf("PlainVar data = %v, want [1]", plain.Data)
	}
	auth, err := reparsed.GetVariable("AuthVar", EFIGlobalVariable)
	if err != nil {
		t.Fatalf("AuthVar not recovered: %v", err)
	}
	if len(auth.Data) != 2 || auth.Data[0] != 0x02 || auth.Data[1] != 0x03 {
		t.Errorf("AuthVar data = %v, want [2 3]", auth.Data)
	}

	// Byte-level assertion: the FIRST variable's NameSize must live at the
	// authenticated-header offset (+36), not the standard offset (+8).
	varStart := 0x48 + VariableStoreHeaderSize
	if got := binary.LittleEndian.Uint16(out[varStart : varStart+2]); got != VariableHeaderStartID {
		t.Fatalf("no variable start ID at %#x: %#x", varStart, got)
	}
	nameSize := binary.LittleEndian.Uint32(out[varStart+36 : varStart+40])
	wantNameSize := uint32(len(encodeUTF16LE("PlainVar")))
	if nameSize != wantNameSize {
		t.Errorf("NameSize at authenticated offset +36 = %d, want %d (header written in the wrong format)", nameSize, wantNameSize)
	}
}

func TestNonAuthenticatedStoreUsesStandardHeader(t *testing.T) {
	nvram, err := ParseNVRAM(buildStore(t, NVRAMVariableStoreGUID, 0x4000), "")
	if err != nil {
		t.Fatalf("ParseNVRAM: %v", err)
	}
	if nvram.IsAuthenticatedStore() {
		t.Fatal("plain variable store misdetected as authenticated")
	}

	// Even a variable carrying the time-based-auth ATTRIBUTE must use the
	// 32-byte header in a non-authenticated store — the store dictates.
	if err := nvram.SetVariable("Var", EFIGlobalVariable, SecureBootAttributes, []byte{0x09}); err != nil {
		t.Fatalf("SetVariable: %v", err)
	}
	out, err := nvram.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	varStart := 0x48 + VariableStoreHeaderSize
	nameSize := binary.LittleEndian.Uint32(out[varStart+8 : varStart+12])
	wantNameSize := uint32(len(encodeUTF16LE("Var")))
	if nameSize != wantNameSize {
		t.Errorf("NameSize at standard offset +8 = %d, want %d", nameSize, wantNameSize)
	}

	reparsed, err := ParseNVRAM(out, "")
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if _, err := reparsed.GetVariable("Var", EFIGlobalVariable); err != nil {
		t.Fatalf("Var not recovered: %v", err)
	}
}
