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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// These tests drive LUKSBackend against a LUKS2 header formatted into a
// sparse image file (newLUKSImage): go-luks2 reads and writes the header
// without root, a loop device or device-mapper.

var errStubHandler = errors.New("stub handler failure")

// newTestLUKSBackend returns a backend whose keyslots use a minimal KDF cost
// so each keyslot write takes milliseconds instead of a calibrated second.
func newTestLUKSBackend(opts ...LUKSBackendOption) *LUKSBackend {
	b := NewLUKSBackend(nil, opts...)
	b.kdfCost = &luksKDFCost{
		kdfType:        "pbkdf2",
		hash:           "sha256",
		pbkdfIterTime:  1,
		argon2Time:     1,
		argon2Memory:   1024,
		argon2Parallel: 1,
	}
	return b
}

// stubFIDO2Key is a minimal LUKSFIDO2Handler returning a fixed key.
type stubFIDO2Key struct {
	key []byte
	err error
}

func (s *stubFIDO2Key) EnrollCredential(context.Context, string, bool, bool) ([]byte, error) {
	return s.key, s.err
}

// stubFIDO2Rich also implements LUKSFIDO2EnrollingHandler.
type stubFIDO2Rich struct {
	stubFIDO2Key
	res *LUKSFIDO2EnrollResult
	err error
}

func (s *stubFIDO2Rich) DeriveEnroll(context.Context, string, bool, bool) (*LUKSFIDO2EnrollResult, error) {
	return s.res, s.err
}

// stubTPMSealer is a LUKSTPMHandler recording what it was asked to seal.
type stubTPMSealer struct {
	passphrase []byte
	token      []byte
	err        error
	handle     string
	pcrs       []int32
}

func (s *stubTPMSealer) Seal(_ context.Context, handle string, pcrs []int32) ([]byte, []byte, error) {
	s.handle = handle
	s.pcrs = pcrs
	return s.passphrase, s.token, s.err
}

// tokenByID returns the decoded token with the given ID.
func tokenByID(t *testing.T, device string, tokenID string) map[string]any {
	t.Helper()
	id, err := strconv.Atoi(tokenID)
	if err != nil {
		t.Fatalf("token id %q: %v", tokenID, err)
	}
	return exportedToken(t, device, id)
}

func TestLUKSBackend_Status(t *testing.T) {
	device := newLUKSImage(t)
	b := newTestLUKSBackend()

	st, err := b.Status(context.Background(), device)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Device != device || !st.IsLUKS || st.Version != 2 {
		t.Fatalf("Status = %+v, want device %q, IsLUKS, version 2", st, device)
	}
	if st.UUID == "" || st.Cipher == "" {
		t.Fatalf("Status = %+v, want the header UUID and cipher", st)
	}
	if !reflect.DeepEqual(st.ActiveSlots, []int32{0}) {
		t.Fatalf("ActiveSlots = %v, want [0]", st.ActiveSlots)
	}
}

func TestLUKSBackend_ReadsRejectANonLUKSDevice(t *testing.T) {
	b := newTestLUKSBackend()
	ctx := context.Background()

	if _, err := b.ListSlots(ctx, "/dev/null"); err == nil {
		t.Fatal("ListSlots(/dev/null) succeeded, want an error")
	}
	if _, err := b.Info(ctx, "/dev/null"); err == nil {
		t.Fatal("Info(/dev/null) succeeded, want an error")
	}
	ok, err := b.TestUnlock(ctx, &daemon.LUKSTestUnlockRequest{Device: "/dev/null", Slot: 0})
	if err == nil || ok {
		t.Fatalf("TestUnlock(/dev/null) = %v, %v; want false and an error", ok, err)
	}
}

func TestLUKSBackend_ListSlotsTypesSlotsFromTheirTokens(t *testing.T) {
	device := newLUKSImage(t)
	fido2Slot := addTestKeyslot(t, device, "fido2-derived-key")
	tpmSlot := addTestKeyslot(t, device, "tpm-sealed-key")
	unknownSlot := addTestKeyslot(t, device, "unknown-token-key")

	tokens := []string{
		`{"type":"fido2-manual","keyslots":["` + strconv.Itoa(fido2Slot) + `"]}`,
		`{"type":"systemd-tpm2","keyslots":["` + strconv.Itoa(tpmSlot) + `"]}`,
		// An unrecognised token type leaves its slot at the passphrase default.
		`{"type":"vendor-specific","keyslots":["` + strconv.Itoa(unknownSlot) + `"]}`,
	}
	for id, tok := range tokens {
		if err := luks2.ImportTokenJSON(device, id, []byte(tok)); err != nil {
			t.Fatalf("import token %d: %v", id, err)
		}
	}

	res, err := newTestLUKSBackend().ListSlots(context.Background(), device)
	if err != nil {
		t.Fatalf("ListSlots: %v", err)
	}
	if res.Device != device {
		t.Fatalf("Device = %q, want %q", res.Device, device)
	}
	want := map[int32]daemon.LUKSKeyType{
		0:                  daemon.LUKSKeyTypePassphrase,
		int32(fido2Slot):   daemon.LUKSKeyTypeFIDO2,
		int32(tpmSlot):     daemon.LUKSKeyTypeTPM,
		int32(unknownSlot): daemon.LUKSKeyTypePassphrase,
	}
	got := make(map[int32]daemon.LUKSKeyType, len(res.Slots))
	for _, s := range res.Slots {
		if s.KeySize <= 0 {
			t.Fatalf("slot %d KeySize = %d, want the keyslot key size", s.Slot, s.KeySize)
		}
		got[s.Slot] = s.Type
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("slot types = %v, want %v", got, want)
	}
}

func TestResolveSlotTypes(t *testing.T) {
	t.Run("not LUKS yields no types", func(t *testing.T) {
		if got := resolveSlotTypes("/dev/null"); len(got) != 0 {
			t.Fatalf("resolveSlotTypes(/dev/null) = %v, want empty", got)
		}
	})
	t.Run("skips keyslot names that are not numbers", func(t *testing.T) {
		device := newLUKSImage(t)
		raw := []byte(`{"type":"tpm2","keyslots":["0","not-a-slot"]}`)
		if err := luks2.ImportTokenJSON(device, 0, raw); err != nil {
			t.Fatalf("import token: %v", err)
		}
		got := resolveSlotTypes(device)
		want := map[int]daemon.LUKSKeyType{0: daemon.LUKSKeyTypeTPM}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("resolveSlotTypes = %v, want %v", got, want)
		}
	})
}

func TestLUKSBackend_Info(t *testing.T) {
	device := newLUKSImage(t)
	info, err := newTestLUKSBackend().Info(context.Background(), device)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Device != device || info.Version != 2 || info.UUID == "" || info.Cipher == "" {
		t.Fatalf("Info = %+v, want the header identity", info)
	}
	// newLUKSImage formats with go-luks2's default 512-bit volume key, which
	// each keyslot stores as 64 bytes. go-luks2 leaves VolumeInfo.KeySize
	// zero, so this reported 0 until Info derived it from the keyslots.
	if info.KeySize != 512 || info.SectorSize != 512 {
		t.Fatalf("Info key size %d bits, sector size %d; want 512 and 512", info.KeySize, info.SectorSize)
	}
	if info.Slots[0].KeySize != 64 {
		t.Fatalf("slot 0 key size = %d bytes, want 64", info.Slots[0].KeySize)
	}
	if len(info.Slots) != 1 || info.Slots[0].Slot != 0 || info.Slots[0].Type != daemon.LUKSKeyTypePassphrase {
		t.Fatalf("Info.Slots = %+v, want the single passphrase slot 0", info.Slots)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(info.MetadataJSON), &meta); err != nil {
		t.Fatalf("MetadataJSON is not JSON: %v", err)
	}
	if _, ok := meta["keyslots"]; !ok {
		t.Fatalf("MetadataJSON has no keyslots section: %s", info.MetadataJSON)
	}
}

func TestVolumeKeyBits(t *testing.T) {
	tests := []struct {
		name  string
		info  *luks2.VolumeInfo
		slots []daemon.LUKSKeyslot
		want  int32
	}{
		{name: "header value wins", info: &luks2.VolumeInfo{KeySize: 256}, slots: []daemon.LUKSKeyslot{{KeySize: 64}}, want: 256},
		{name: "from the first sized keyslot", info: &luks2.VolumeInfo{}, slots: []daemon.LUKSKeyslot{{KeySize: 0}, {KeySize: 32}}, want: 256},
		{name: "no keyslots", info: &luks2.VolumeInfo{}, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := volumeKeyBits(tc.info, tc.slots); got != tc.want {
				t.Fatalf("volumeKeyBits = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLUKSBackend_EnrollPassphrase(t *testing.T) {
	device := newLUKSImage(t)
	b := newTestLUKSBackend()

	res, err := b.EnrollPassphrase(context.Background(), &daemon.LUKSEnrollPassphraseRequest{
		Device:             device,
		ExistingPassphrase: testLUKSPassphrase,
		NewPassphrase:      "second-passphrase",
	})
	if err != nil {
		t.Fatalf("EnrollPassphrase: %v", err)
	}
	if res.Slot != 1 || !keyslotIDs(t, device)[1] {
		t.Fatalf("EnrollPassphrase slot = %d, want the new slot 1 on the volume", res.Slot)
	}
	if err := luks2.TestKey(device, []byte("second-passphrase")); err != nil {
		t.Fatalf("the enrolled passphrase does not open the volume: %v", err)
	}
}

func TestLUKSBackend_EnrollPassphraseErrors(t *testing.T) {
	device := newLUKSImage(t)
	b := newTestLUKSBackend()
	ctx := context.Background()

	if _, err := b.EnrollPassphrase(ctx, &daemon.LUKSEnrollPassphraseRequest{
		Device: "/dev/null", ExistingPassphrase: testLUKSPassphrase, NewPassphrase: "second-passphrase",
	}); err == nil {
		t.Fatal("EnrollPassphrase on /dev/null succeeded, want an error")
	}
	if _, err := b.EnrollPassphrase(ctx, &daemon.LUKSEnrollPassphraseRequest{
		Device: device, ExistingPassphrase: "wrong-passphrase", NewPassphrase: "second-passphrase",
	}); err == nil {
		t.Fatal("EnrollPassphrase with a wrong existing passphrase succeeded, want an error")
	}
	if got := keyslotIDs(t, device); len(got) != 1 {
		t.Fatalf("keyslots after the failed enrolls = %v, want only slot 0", got)
	}
}

func TestLUKSBackend_EnrollFIDO2(t *testing.T) {
	t.Run("minimal handler writes a fido2-manual token", func(t *testing.T) {
		device := newLUKSImage(t)
		key := []byte("fido2-hmac-secret-derived-key-32")
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(&stubFIDO2Key{key: append([]byte(nil), key...)}))
		handlerKey := b.fido2.(*stubFIDO2Key).key

		res, err := b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
			Device:             device,
			ExistingPassphrase: testLUKSPassphrase,
			CredentialID:       "Y3JlZGVudGlhbA",
			RequireUV:          true,
		})
		if err != nil {
			t.Fatalf("EnrollFIDO2: %v", err)
		}
		if res.Slot != 1 {
			t.Fatalf("EnrollFIDO2 slot = %d, want 1", res.Slot)
		}
		tok := tokenByID(t, device, res.TokenID)
		if tok["type"] != "fido2-manual" {
			t.Fatalf("token type = %v, want fido2-manual", tok["type"])
		}
		assertKeyslots(t, tok, "1")
		if !bytes.Equal(handlerKey, make([]byte, len(key))) {
			t.Fatal("the derived key was not wiped after the enroll")
		}
		if err := luks2.TestKey(device, key); err != nil {
			t.Fatalf("the derived key does not open the volume: %v", err)
		}
	})

	t.Run("rich handler token is written for the new slot", func(t *testing.T) {
		device := newLUKSImage(t)
		rich := &stubFIDO2Rich{res: &LUKSFIDO2EnrollResult{
			DerivedKey: []byte("fido2-hmac-secret-derived-key-32"),
			TokenJSON:  []byte(`{"type":"fido2-manual","fido2-credential":"Y3JlZA","fido2-salt":"c2FsdA","keyslots":[]}`),
		}}
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(rich))

		res, err := b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
			Device: device, ExistingPassphrase: testLUKSPassphrase, CredentialID: "Y3JlZA",
		})
		if err != nil {
			t.Fatalf("EnrollFIDO2: %v", err)
		}
		tok := tokenByID(t, device, res.TokenID)
		if tok["fido2-salt"] != "c2FsdA" {
			t.Fatalf("token = %v, want the handler's salt preserved", tok)
		}
		assertKeyslots(t, tok, strconv.Itoa(int(res.Slot)))
	})
}

func TestLUKSBackend_EnrollFIDO2Errors(t *testing.T) {
	key := []byte("fido2-hmac-secret-derived-key-32")
	tests := []struct {
		name       string
		handler    LUKSFIDO2Handler
		device     string // "" = a fresh LUKS image
		passphrase string
		wantErr    error
	}{
		{
			name:       "minimal handler failure",
			handler:    &stubFIDO2Key{err: errStubHandler},
			passphrase: testLUKSPassphrase,
			wantErr:    errStubHandler,
		},
		{
			name:       "rich handler failure",
			handler:    &stubFIDO2Rich{err: errStubHandler},
			passphrase: testLUKSPassphrase,
			wantErr:    errStubHandler,
		},
		{
			name:       "not a LUKS device",
			handler:    &stubFIDO2Key{key: key},
			device:     "/dev/null",
			passphrase: testLUKSPassphrase,
		},
		{
			name:       "wrong existing passphrase",
			handler:    &stubFIDO2Key{key: key},
			passphrase: "wrong-passphrase",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			device := tc.device
			if device == "" {
				device = newLUKSImage(t)
			}
			b := newTestLUKSBackend(WithLUKSFIDO2Handler(tc.handler))
			res, err := b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
				Device: device, ExistingPassphrase: tc.passphrase, CredentialID: "Y3JlZA",
			})
			if err == nil {
				t.Fatalf("EnrollFIDO2 = %+v, want an error", res)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("EnrollFIDO2 error = %v, want %v", err, tc.wantErr)
			}
			if tc.device == "" {
				if got := keyslotIDs(t, device); len(got) != 1 {
					t.Fatalf("keyslots after the failed enroll = %v, want only slot 0", got)
				}
			}
		})
	}
}

func TestLUKSBackend_EnrollTPM(t *testing.T) {
	device := newLUKSImage(t)
	sealer := &stubTPMSealer{
		passphrase: []byte("tpm-sealed-volume-passphrase"),
		token:      []byte(`{"type":"tpm2","tpm2-blob":"YmxvYg","keyslots":[]}`),
	}
	b := newTestLUKSBackend(WithLUKSTPMHandler(sealer))

	res, err := b.EnrollTPM(context.Background(), &daemon.LUKSEnrollTPMRequest{
		Device:             device,
		ExistingPassphrase: testLUKSPassphrase,
		Handle:             "0x81000001",
		PCRs:               []int32{0, 7},
	})
	if err != nil {
		t.Fatalf("EnrollTPM: %v", err)
	}
	if sealer.handle != "0x81000001" || !reflect.DeepEqual(sealer.pcrs, []int32{0, 7}) {
		t.Fatalf("Seal got handle %q pcrs %v, want the request's", sealer.handle, sealer.pcrs)
	}
	if res.Slot != 1 {
		t.Fatalf("EnrollTPM slot = %d, want 1", res.Slot)
	}
	tok := tokenByID(t, device, res.TokenID)
	if tok["type"] != "tpm2" || tok["tpm2-blob"] != "YmxvYg" {
		t.Fatalf("token = %v, want the sealer's token", tok)
	}
	assertKeyslots(t, tok, "1")
	if !bytes.Equal(sealer.passphrase, make([]byte, len(sealer.passphrase))) {
		t.Fatal("the sealed passphrase was not wiped after the enroll")
	}
}

func TestLUKSBackend_EnrollTPMErrors(t *testing.T) {
	ctx := context.Background()
	newSealer := func() *stubTPMSealer {
		return &stubTPMSealer{
			passphrase: []byte("tpm-sealed-volume-passphrase"),
			token:      []byte(`{"type":"tpm2","keyslots":[]}`),
		}
	}

	t.Run("seal failure", func(t *testing.T) {
		b := newTestLUKSBackend(WithLUKSTPMHandler(&stubTPMSealer{err: errStubHandler}))
		_, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{Device: newLUKSImage(t)})
		if !errors.Is(err, errStubHandler) {
			t.Fatalf("EnrollTPM error = %v, want %v", err, errStubHandler)
		}
	})
	t.Run("not a LUKS device", func(t *testing.T) {
		b := newTestLUKSBackend(WithLUKSTPMHandler(newSealer()))
		if _, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{
			Device: "/dev/null", ExistingPassphrase: testLUKSPassphrase,
		}); err == nil {
			t.Fatal("EnrollTPM on /dev/null succeeded, want an error")
		}
	})
	t.Run("wrong existing passphrase", func(t *testing.T) {
		device := newLUKSImage(t)
		b := newTestLUKSBackend(WithLUKSTPMHandler(newSealer()))
		if _, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{
			Device: device, ExistingPassphrase: "wrong-passphrase",
		}); err == nil {
			t.Fatal("EnrollTPM with a wrong passphrase succeeded, want an error")
		}
		if got := keyslotIDs(t, device); len(got) != 1 {
			t.Fatalf("keyslots = %v, want only slot 0", got)
		}
	})
	t.Run("no token removes the keyslot", func(t *testing.T) {
		device := newLUKSImage(t)
		sealer := newSealer()
		sealer.token = nil
		b := newTestLUKSBackend(WithLUKSTPMHandler(sealer))
		_, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{
			Device: device, ExistingPassphrase: testLUKSPassphrase,
		})
		var writeErr *LUKSTokenWriteError
		if !errors.As(err, &writeErr) || !errors.Is(err, ErrLUKSTokenMissing) {
			t.Fatalf("EnrollTPM error = %v, want a LUKSTokenWriteError for ErrLUKSTokenMissing", err)
		}
		if writeErr.RollbackErr != nil || keyslotIDs(t, device)[writeErr.Slot] {
			t.Fatalf("keyslot %d was not rolled back: %v", writeErr.Slot, writeErr.RollbackErr)
		}
	})
}

func TestLUKSBackend_EnrollRecovery(t *testing.T) {
	device := newLUKSImage(t)
	res, err := newTestLUKSBackend().EnrollRecovery(context.Background(), &daemon.LUKSEnrollRecoveryRequest{
		Device: device, ExistingPassphrase: testLUKSPassphrase,
	})
	if err != nil {
		t.Fatalf("EnrollRecovery: %v", err)
	}
	if res.Slot != 1 || !keyslotIDs(t, device)[1] {
		t.Fatalf("EnrollRecovery slot = %d, want the new slot 1", res.Slot)
	}
	// In FIPS mode the recovery keyslot must use an approved KDF; outside it
	// go-luks2's argon2id default stands.
	wantKDF := "argon2id"
	if luksFIPSActive() {
		wantKDF = fips.KDFPBKDF2
	}
	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	slot := metadata.Keyslots[strconv.Itoa(int(res.Slot))]
	if slot == nil || slot.KDF == nil || slot.KDF.Type != wantKDF {
		t.Fatalf("recovery keyslot %d KDF = %+v, want type %q", res.Slot, slot, wantKDF)
	}
	// The dashed format groups the key with '-' separators for the operator.
	if !bytes.Contains([]byte(res.RecoveryKey), []byte("-")) {
		t.Fatalf("RecoveryKey = %q, want the dashed format", res.RecoveryKey)
	}
}

func TestLUKSBackend_EnrollRecoveryWrongPassphrase(t *testing.T) {
	device := newLUKSImage(t)
	res, err := newTestLUKSBackend().EnrollRecovery(context.Background(), &daemon.LUKSEnrollRecoveryRequest{
		Device: device, ExistingPassphrase: "wrong-passphrase",
	})
	if err == nil {
		t.Fatalf("EnrollRecovery = %+v, want an error", res)
	}
	if got := keyslotIDs(t, device); len(got) != 1 {
		t.Fatalf("keyslots = %v, want only slot 0", got)
	}
}

func TestLUKSBackend_RemoveKey(t *testing.T) {
	device := newLUKSImage(t)
	slot := addTestKeyslot(t, device, "second-passphrase")
	b := newTestLUKSBackend()
	ctx := context.Background()

	if err := b.RemoveKey(ctx, &daemon.LUKSRemoveKeyRequest{Device: device, Slot: int32(slot)}); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if keyslotIDs(t, device)[slot] {
		t.Fatalf("keyslot %d is still on the volume", slot)
	}
	if err := b.RemoveKey(ctx, &daemon.LUKSRemoveKeyRequest{Device: device, Slot: int32(slot)}); err == nil {
		t.Fatal("RemoveKey of an absent keyslot succeeded, want an error")
	}
}

func TestLUKSBackend_TestUnlockRefusesWithoutVerification(t *testing.T) {
	device := newLUKSImage(t)
	b := newTestLUKSBackend()
	ok, err := b.TestUnlock(context.Background(), &daemon.LUKSTestUnlockRequest{Device: device, Slot: 0})
	if ok || !errors.Is(err, ErrLUKSTestUnlockUnverified) {
		t.Fatalf("TestUnlock(slot 0) = %v, %v; want false and ErrLUKSTestUnlockUnverified", ok, err)
	}
}

// perCredentialFIDO2Key derives a distinct key per credential ID and returns
// a fresh slice on every call, since the backend wipes the returned key.
type perCredentialFIDO2Key struct{}

func (perCredentialFIDO2Key) EnrollCredential(_ context.Context, credentialID string, _, _ bool) ([]byte, error) {
	return []byte("fido2-key-" + credentialID), nil
}

func TestLUKSBackend_ConcurrentEnrollmentGetsDistinctSlots(t *testing.T) {
	const n = 4

	t.Run("passphrase", func(t *testing.T) {
		device := newLUKSImage(t)
		b := newTestLUKSBackend()
		start := make(chan struct{})
		slots := make([]int32, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				res, err := b.EnrollPassphrase(context.Background(), &daemon.LUKSEnrollPassphraseRequest{
					Device:             device,
					ExistingPassphrase: testLUKSPassphrase,
					NewPassphrase:      "concurrent-pass-" + strconv.Itoa(i),
				})
				errs[i] = err
				if res != nil {
					slots[i] = res.Slot
				}
			}(i)
		}
		close(start)
		wg.Wait()

		seen := map[int32]int{}
		ids := keyslotIDs(t, device)
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("EnrollPassphrase %d: %v", i, errs[i])
			}
			if j, dup := seen[slots[i]]; dup {
				t.Fatalf("enrollments %d and %d both reported slot %d", j, i, slots[i])
			}
			seen[slots[i]] = i
			if !ids[int(slots[i])] {
				t.Fatalf("slot %d of enrollment %d is not on the device (%v)", slots[i], i, ids)
			}
			if err := luks2.TestKey(device, []byte("concurrent-pass-"+strconv.Itoa(i))); err != nil {
				t.Fatalf("passphrase %d does not open the volume: %v", i, err)
			}
		}
	})

	t.Run("fido2", func(t *testing.T) {
		device := newLUKSImage(t)
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(perCredentialFIDO2Key{}))
		start := make(chan struct{})
		results := make([]*daemon.LUKSEnrollFIDO2Result, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i], errs[i] = b.EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
					Device:             device,
					ExistingPassphrase: testLUKSPassphrase,
					CredentialID:       "cred" + strconv.Itoa(i),
				})
			}(i)
		}
		close(start)
		wg.Wait()

		slotSeen := map[int32]int{}
		tokenSeen := map[string]int{}
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("EnrollFIDO2 %d: %v", i, errs[i])
			}
			res := results[i]
			if j, dup := slotSeen[res.Slot]; dup {
				t.Fatalf("enrollments %d and %d both reported slot %d", j, i, res.Slot)
			}
			slotSeen[res.Slot] = i
			if j, dup := tokenSeen[res.TokenID]; dup {
				t.Fatalf("enrollments %d and %d both reported token %s", j, i, res.TokenID)
			}
			tokenSeen[res.TokenID] = i
			assertKeyslots(t, tokenByID(t, device, res.TokenID), strconv.Itoa(int(res.Slot)))
			if err := luks2.TestKey(device, []byte("fido2-key-cred"+strconv.Itoa(i))); err != nil {
				t.Fatalf("credential %d does not open the volume: %v", i, err)
			}
		}
	})
}

// TestLUKSVolumeKey_AliasesShareAKey proves a symlink to a volume and the
// volume's own path select the same mutation lock.
func TestLUKSVolumeKey_AliasesShareAKey(t *testing.T) {
	device := newLUKSImage(t)
	link := filepath.Join(t.TempDir(), "by-uuid-alias")
	if err := os.Symlink(device, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if got, want := luksVolumeKey(link), luksVolumeKey(device); got != want {
		t.Fatalf("alias key %q differs from device key %q", got, want)
	}
}

// TestLUKSBackend_ConcurrentEnrollmentThroughAliasesGetsDistinctSlots proves
// enrollments that name one volume by two paths are still serialized.
func TestLUKSBackend_ConcurrentEnrollmentThroughAliasesGetsDistinctSlots(t *testing.T) {
	const n = 4
	device := newLUKSImage(t)
	link := filepath.Join(t.TempDir(), "by-uuid-alias")
	if err := os.Symlink(device, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	b := newTestLUKSBackend()
	start := make(chan struct{})
	slots := make([]int32, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			path := device
			if i%2 == 1 {
				path = link
			}
			res, err := b.EnrollPassphrase(context.Background(), &daemon.LUKSEnrollPassphraseRequest{
				Device:             path,
				ExistingPassphrase: testLUKSPassphrase,
				NewPassphrase:      "alias-pass-" + strconv.Itoa(i),
			})
			errs[i] = err
			if res != nil {
				slots[i] = res.Slot
			}
		}(i)
	}
	close(start)
	wg.Wait()

	seen := map[int32]int{}
	ids := keyslotIDs(t, device)
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("EnrollPassphrase %d: %v", i, errs[i])
		}
		if j, dup := seen[slots[i]]; dup {
			t.Fatalf("enrollments %d and %d both reported slot %d", j, i, slots[i])
		}
		seen[slots[i]] = i
		if !ids[int(slots[i])] {
			t.Fatalf("slot %d of enrollment %d is not on the device (%v)", slots[i], i, ids)
		}
		if err := luks2.TestKey(device, []byte("alias-pass-"+strconv.Itoa(i))); err != nil {
			t.Fatalf("passphrase %d does not open the volume: %v", i, err)
		}
	}
}

// TestLUKSBackend_ChangePassphraseRefusesArgon2SlotUnderFIPS proves rotation
// does not carry a non-approved KDF forward when the FIPS policy is active.
func TestLUKSBackend_ChangePassphraseRefusesArgon2SlotUnderFIPS(t *testing.T) {
	device := newLUKSImage(t)
	before, err := luks2.ListKeyslots(device)
	if err != nil {
		t.Fatalf("list keyslots: %v", err)
	}
	if err := luks2.AddKey(device, []byte(testLUKSPassphrase), []byte("argon-pass"), &luks2.AddKeyOptions{
		KDFType:        "argon2id",
		Argon2Time:     1,
		Argon2Memory:   1024,
		Argon2Parallel: 1,
	}); err != nil {
		t.Skipf("argon2id keyslot refused in this environment (Go FIPS mode?): %v", err)
	}
	slot, err := detectNewSlot(device, before)
	if err != nil {
		t.Fatalf("detect new slot: %v", err)
	}

	b := newTestLUKSBackend()
	b.fipsActive = func() bool { return true }
	err = b.ChangePassphrase(context.Background(), &daemon.LUKSChangePassphraseRequest{
		Device:        device,
		Slot:          int32(slot),
		OldPassphrase: "argon-pass",
		NewPassphrase: "rotated-pass",
	})
	if !errors.Is(err, ErrLUKSRotationKDFNotApproved) {
		t.Fatalf("ChangePassphrase error = %v, want ErrLUKSRotationKDFNotApproved", err)
	}
	var notApproved fips.ErrKDFNotApproved
	if !errors.As(err, &notApproved) {
		t.Fatalf("ChangePassphrase error = %v, want a fips.ErrKDFNotApproved in its chain", err)
	}
	if err := luks2.TestKey(device, []byte("argon-pass")); err != nil {
		t.Fatalf("old passphrase no longer opens the volume: %v", err)
	}
	if err := luks2.TestKey(device, []byte("rotated-pass")); err == nil {
		t.Fatal("refused rotation still installed the new passphrase")
	}
}

// TestLUKSBackend_ChangePassphraseRotatesPBKDF2SlotUnderFIPS proves an
// approved PBKDF2 slot still rotates under the FIPS policy.
func TestLUKSBackend_ChangePassphraseRotatesPBKDF2SlotUnderFIPS(t *testing.T) {
	device := newLUKSImage(t)
	b := newTestLUKSBackend()
	b.fipsActive = func() bool { return true }
	if err := b.ChangePassphrase(context.Background(), &daemon.LUKSChangePassphraseRequest{
		Device:        device,
		Slot:          0,
		OldPassphrase: testLUKSPassphrase,
		NewPassphrase: "rotated-pass",
	}); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if err := luks2.TestKey(device, []byte("rotated-pass")); err != nil {
		t.Fatalf("new passphrase does not open the volume: %v", err)
	}
}

func TestLUKSBackend_ChangePassphraseWrongOldPassphrase(t *testing.T) {
	device := newLUKSImage(t)
	err := newTestLUKSBackend().ChangePassphrase(context.Background(), &daemon.LUKSChangePassphraseRequest{
		Device: device, OldPassphrase: "wrong-passphrase", NewPassphrase: "changed-passphrase", Slot: 0,
	})
	if err == nil {
		t.Fatal("ChangePassphrase with a wrong old passphrase succeeded, want an error")
	}
	if err := luks2.TestKey(device, []byte(testLUKSPassphrase)); err != nil {
		t.Fatalf("the original passphrase no longer opens the volume: %v", err)
	}
}

func TestLUKSKDFCost(t *testing.T) {
	t.Run("nil cost keeps the policy options", func(t *testing.T) {
		var cost *luksKDFCost
		add := &luks2.AddKeyOptions{KDFType: "argon2id", Hash: "sha512"}
		cost.applyAddKey(add)
		if !reflect.DeepEqual(add, &luks2.AddKeyOptions{KDFType: "argon2id", Hash: "sha512"}) {
			t.Fatalf("applyAddKey changed the options: %+v", add)
		}
		rec := &luks2.RecoveryKeyOptions{KDFType: "argon2id"}
		cost.applyRecovery(rec)
		if !reflect.DeepEqual(rec, &luks2.RecoveryKeyOptions{KDFType: "argon2id"}) {
			t.Fatalf("applyRecovery changed the options: %+v", rec)
		}
	})
	t.Run("set cost fixes the KDF", func(t *testing.T) {
		cost := newTestLUKSBackend().kdfCost
		add := &luks2.AddKeyOptions{KDFType: "argon2id"}
		cost.applyAddKey(add)
		if add.KDFType != "pbkdf2" || add.Hash != "sha256" || add.PBKDFIterTime != 1 {
			t.Fatalf("applyAddKey = %+v, want pbkdf2/sha256 at 1 ms", add)
		}
		rec := &luks2.RecoveryKeyOptions{KDFType: "argon2id"}
		cost.applyRecovery(rec)
		if rec.KDFType != "argon2id" || rec.Argon2Time != 1 || rec.Argon2Memory != 1024 || rec.Argon2Parallel != 1 {
			t.Fatalf("applyRecovery = %+v, want the policy KDF at the fixed Argon2 cost", rec)
		}
	})
}

func TestLUKSBackendOptions(t *testing.T) {
	fido2 := &stubFIDO2Key{}
	tpm := &stubTPMSealer{}

	t.Run("explicit handlers", func(t *testing.T) {
		b := NewLUKSBackend(nil, WithLUKSFIDO2Handler(fido2), WithLUKSTPMHandler(tpm))
		if b.fido2 != fido2 || b.tpm != tpm {
			t.Fatalf("handlers = %v, %v; want the injected ones", b.fido2, b.tpm)
		}
	})
	t.Run("defaults keep injected handlers", func(t *testing.T) {
		b := NewLUKSBackend(nil, WithLUKSFIDO2Handler(fido2), WithLUKSTPMHandler(tpm), WithDefaultLUKSHandlers())
		if b.fido2 != fido2 || b.tpm != tpm {
			t.Fatalf("handlers = %v, %v; want the injected ones kept", b.fido2, b.tpm)
		}
	})
	t.Run("defaults fill unset handlers", func(t *testing.T) {
		// Both default handlers open their hardware lazily, so building
		// them touches no device.
		b := NewLUKSBackend(nil, WithDefaultLUKSHandlers())
		if _, ok := b.fido2.(LUKSFIDO2EnrollingHandler); !ok {
			t.Fatalf("fido2 handler = %T, want the default enrolling handler", b.fido2)
		}
		if b.tpm == nil {
			t.Fatal("tpm handler = nil, want the default TPM sealer")
		}
	})
}
