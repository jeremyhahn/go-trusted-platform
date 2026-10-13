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

package backends

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

const testLUKSPassphrase = "initialpass"

// newLUKSImage formats a sparse file in t.TempDir() as a LUKS2 volume whose
// keyslot 0 opens with testLUKSPassphrase. Header I/O needs no block device,
// and PBKDF2 at a 1 ms budget keeps each keyslot cheap while staying
// FIPS-approved.
func newLUKSImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volume.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		f.Close()
		t.Fatalf("truncate image: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
	if err := luks2.Format(luks2.FormatOptions{
		Device:        path,
		Passphrase:    []byte(testLUKSPassphrase),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("format image: %v", err)
	}
	return path
}

// addTestKeyslot adds a cheap PBKDF2 keyslot and returns its index.
func addTestKeyslot(t *testing.T, device, passphrase string) int {
	t.Helper()
	before, err := luks2.ListKeyslots(device)
	if err != nil {
		t.Fatalf("list keyslots: %v", err)
	}
	if err := luks2.AddKey(device, []byte(testLUKSPassphrase), []byte(passphrase), &luks2.AddKeyOptions{
		KDFType:       "pbkdf2",
		Hash:          "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	slot, err := detectNewSlot(device, before)
	if err != nil {
		t.Fatalf("detect new slot: %v", err)
	}
	return slot
}

// keyslotIDs returns the occupied keyslot indexes of device.
func keyslotIDs(t *testing.T, device string) map[int]bool {
	t.Helper()
	slots, err := luks2.ListKeyslots(device)
	if err != nil {
		t.Fatalf("list keyslots: %v", err)
	}
	ids := make(map[int]bool, len(slots))
	for _, s := range slots {
		ids[s.ID] = true
	}
	return ids
}

// exportedToken reads token tokenID back from device.
func exportedToken(t *testing.T, device string, tokenID int) map[string]any {
	t.Helper()
	raw, err := luks2.ExportToken(device, tokenID)
	if err != nil {
		t.Fatalf("export token %d: %v", tokenID, err)
	}
	var tok map[string]any
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatalf("decode token %d: %v", tokenID, err)
	}
	return tok
}

// assertKeyslots checks the token names exactly the keyslot slot.
func assertKeyslots(t *testing.T, tok map[string]any, slot string) {
	t.Helper()
	got, ok := tok["keyslots"].([]any)
	if !ok || len(got) != 1 || got[0] != slot {
		t.Fatalf("token keyslots = %v, want [%q]", tok["keyslots"], slot)
	}
}

func TestDetectNewSlot_ReportsAFreedLowerSlot(t *testing.T) {
	device := newLUKSImage(t)
	addTestKeyslot(t, device, "second-pass")
	addTestKeyslot(t, device, "third-pass")
	if err := luks2.KillKeyslot(device, 1); err != nil {
		t.Fatalf("kill keyslot 1: %v", err)
	}

	// Slots {0, 2} are occupied: the new key lands in 1, below the highest.
	if got := addTestKeyslot(t, device, "fourth-pass"); got != 1 {
		t.Fatalf("detectNewSlot = %d, want 1", got)
	}
}

func TestDetectNewSlot_NoNewSlotIsAnError(t *testing.T) {
	device := newLUKSImage(t)
	before, err := luks2.ListKeyslots(device)
	if err != nil {
		t.Fatalf("list keyslots: %v", err)
	}

	slot, err := detectNewSlot(device, before)
	if !errors.Is(err, ErrLUKSNewSlotNotFound) {
		t.Fatalf("detectNewSlot = (%d, %v), want ErrLUKSNewSlotNotFound", slot, err)
	}
}

func TestDetectNewSlot_NotLUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := detectNewSlot(path, nil); err == nil {
		t.Fatal("detectNewSlot on a non-LUKS file returned no error")
	}
}

func TestWriteEnrollToken_HandlerTokenNamesTheNewSlot(t *testing.T) {
	device := newLUKSImage(t)
	slot := addTestKeyslot(t, device, "tpm-sealed-pass")

	tokenID, err := writeEnrollToken(device, slot,
		[]byte(`{"type":"systemd-tpm2","keyslots":["9"],"tpm2-pcrs":[7]}`), nil)
	if err != nil {
		t.Fatalf("writeEnrollToken: %v", err)
	}

	tok := exportedToken(t, device, tokenID)
	if tok["type"] != "systemd-tpm2" {
		t.Fatalf("token type = %v, want systemd-tpm2", tok["type"])
	}
	assertKeyslots(t, tok, "1")
}

func TestWriteEnrollToken_FallbackTokenNamesTheNewSlot(t *testing.T) {
	device := newLUKSImage(t)
	slot := addTestKeyslot(t, device, "fido2-derived-pass")

	tokenID, err := writeEnrollToken(device, slot, nil,
		&luks2.Token{Type: "fido2-manual", FIDO2Credential: "Y3JlZA"})
	if err != nil {
		t.Fatalf("writeEnrollToken: %v", err)
	}

	tok := exportedToken(t, device, tokenID)
	if tok["type"] != "fido2-manual" {
		t.Fatalf("token type = %v, want fido2-manual", tok["type"])
	}
	assertKeyslots(t, tok, "1")
}

// go-luks2 v0.1.8 fixed the header area: metadata that does not fit is
// refused with ErrMetadataTooLarge instead of growing the header. The keyslot
// added for the token must not survive without it.
func TestWriteEnrollToken_MetadataTooLargeRemovesTheKeyslot(t *testing.T) {
	device := newLUKSImage(t)
	slot := addTestKeyslot(t, device, "tpm-sealed-pass")
	oversized := `{"type":"systemd-tpm2","tpm2-blob":"` + strings.Repeat("A", 64<<10) + `"}`

	_, err := writeEnrollToken(device, slot, []byte(oversized), nil)

	var writeErr *LUKSTokenWriteError
	if !errors.As(err, &writeErr) {
		t.Fatalf("writeEnrollToken error = %v, want *LUKSTokenWriteError", err)
	}
	if !errors.Is(err, luks2.ErrMetadataTooLarge) {
		t.Fatalf("writeEnrollToken error = %v, want luks2.ErrMetadataTooLarge", err)
	}
	if writeErr.Slot != slot || writeErr.RollbackErr != nil {
		t.Fatalf("LUKSTokenWriteError = %+v, want slot %d rolled back", writeErr, slot)
	}
	if ids := keyslotIDs(t, device); ids[slot] || !ids[0] {
		t.Fatalf("keyslots after rollback = %v, want only slot 0", ids)
	}
}

func TestWriteEnrollToken_MissingTokenRemovesTheKeyslot(t *testing.T) {
	device := newLUKSImage(t)
	slot := addTestKeyslot(t, device, "tpm-sealed-pass")

	_, err := writeEnrollToken(device, slot, nil, nil)

	if !errors.Is(err, ErrLUKSTokenMissing) {
		t.Fatalf("writeEnrollToken error = %v, want ErrLUKSTokenMissing", err)
	}
	if ids := keyslotIDs(t, device); ids[slot] {
		t.Fatalf("keyslot %d survived a missing token", slot)
	}
}

func TestWriteEnrollToken_ReportsAFailedRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := writeEnrollToken(path, 1, []byte(`{"type":"systemd-tpm2"}`), nil)

	var writeErr *LUKSTokenWriteError
	if !errors.As(err, &writeErr) || writeErr.RollbackErr == nil {
		t.Fatalf("writeEnrollToken error = %v, want a rollback failure", err)
	}
	if !strings.Contains(err.Error(), "still on the volume") {
		t.Fatalf("error %q does not say the keyslot is still on the volume", err)
	}
}

func TestImportEnrollToken_InvalidTokenJSONWritesNothing(t *testing.T) {
	device := newLUKSImage(t)

	if _, err := importEnrollToken(device, 0, []byte(`{not json`), nil); err == nil {
		t.Fatal("importEnrollToken accepted invalid token JSON")
	}
	if _, err := luks2.ExportToken(device, 0); !errors.Is(err, luks2.ErrTokenNotFound) {
		t.Fatalf("ExportToken(0) error = %v, want luks2.ErrTokenNotFound", err)
	}
}

func TestImportEnrollToken_UsesTheFirstFreeTokenSlot(t *testing.T) {
	device := newLUKSImage(t)
	token := []byte(`{"type":"systemd-tpm2"}`)

	first, err := importEnrollToken(device, 0, token, nil)
	if err != nil {
		t.Fatalf("first importEnrollToken: %v", err)
	}
	second, err := importEnrollToken(device, 0, token, nil)
	if err != nil {
		t.Fatalf("second importEnrollToken: %v", err)
	}
	if first != 0 || second != 1 {
		t.Fatalf("token IDs = %d, %d, want 0, 1", first, second)
	}
}

func TestLUKSTokenWriteError(t *testing.T) {
	cause := errors.New("cause")
	rollback := errors.New("rollback")

	removed := &LUKSTokenWriteError{Slot: 3, Err: cause}
	if !errors.Is(removed, cause) || errors.Is(removed, rollback) {
		t.Fatalf("Unwrap without rollback = %v", removed.Unwrap())
	}
	if !strings.Contains(removed.Error(), "keyslot 3") || !strings.HasSuffix(removed.Error(), "the keyslot was removed") {
		t.Fatalf("Error() = %q", removed.Error())
	}

	stranded := &LUKSTokenWriteError{Slot: 3, Err: cause, RollbackErr: rollback}
	if !errors.Is(stranded, cause) || !errors.Is(stranded, rollback) {
		t.Fatalf("Unwrap with rollback = %v", stranded.Unwrap())
	}
	if !strings.Contains(stranded.Error(), "still on the volume: rollback") {
		t.Fatalf("Error() = %q", stranded.Error())
	}
}

// EnrollRecovery reports RecoveryKey.Keyslot. Before go-luks2 v0.2.0 (#42)
// that was the highest slot, not the one written; pin the fixed behaviour.
func TestAddRecoveryKey_ReportsTheSlotItWrote(t *testing.T) {
	device := newLUKSImage(t)
	addTestKeyslot(t, device, "second-pass")
	addTestKeyslot(t, device, "third-pass")
	if err := luks2.KillKeyslot(device, 1); err != nil {
		t.Fatalf("kill keyslot 1: %v", err)
	}

	rk, err := luks2.AddRecoveryKey(device, []byte(testLUKSPassphrase), &luks2.RecoveryKeyOptions{KDFType: "pbkdf2"})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	defer rk.Clear()

	if rk.Keyslot != 1 || !keyslotIDs(t, device)[1] {
		t.Fatalf("RecoveryKey.Keyslot = %d, want 1 (the freed slot it filled)", rk.Keyslot)
	}
}

func TestAddRecoveryKey_WrongPassphrase(t *testing.T) {
	device := newLUKSImage(t)

	if _, err := luks2.AddRecoveryKey(device, []byte("not-the-passphrase"), &luks2.RecoveryKeyOptions{KDFType: "pbkdf2"}); err == nil {
		t.Fatal("AddRecoveryKey accepted a wrong existing passphrase")
	}
	if ids := keyslotIDs(t, device); len(ids) != 1 {
		t.Fatalf("keyslots after a refused AddRecoveryKey = %v, want only slot 0", ids)
	}
}
