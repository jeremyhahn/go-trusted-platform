// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package luks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
)

// errFakeTPM is the error the fake TPM returns from a method set to fail.
var errFakeTPM = errors.New("fake tpm failure")

// fakeTPM overrides the four TPM methods the Manager calls. Any other method
// reaches the nil embedded interface and panics, which flags an unexpected call.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	randomErr error
	srkErr    error
	sealErr   error
	unsealErr error

	srk        *xkmssdk.KeyAttributes
	sealOpts   *xkmssdk.SealOptions
	unsealOpts *xkmssdk.UnsealOptions
}

func (f *fakeTPM) RandomBytes(n int) ([]byte, error) {
	if f.randomErr != nil {
		return nil, f.randomErr
	}
	return make([]byte, n), nil
}

func (f *fakeTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	if f.srkErr != nil {
		return nil, f.srkErr
	}
	if f.srk == nil {
		f.srk = &xkmssdk.KeyAttributes{CN: "ssrk"}
	}
	return f.srk, nil
}

func (f *fakeTPM) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.sealOpts = opts
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return &xkmssdk.SealedData{}, nil
}

func (f *fakeTPM) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	f.unsealOpts = opts
	if f.unsealErr != nil {
		return nil, f.unsealErr
	}
	return make([]byte, 32), nil
}

// newVolumeFile formats a sparse LUKS2 volume in a temp file with a fast
// PBKDF2 keyslot and returns the handler, the path and the passphrase.
func newVolumeFile(t *testing.T) (*CryptsetupHandler, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volume.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create volume file: %v", err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		t.Fatalf("truncate volume file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close volume file: %v", err)
	}

	h, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	pass := []byte("coverage-964-passphrase")
	opts := &FormatOptions{Label: "cov964", KDFType: "pbkdf2", PBKDFIterTime: 1}
	if err := h.Format(context.Background(), path, pass, opts); err != nil {
		t.Fatalf("format volume file: %v", err)
	}
	return h, path, pass
}

func TestCoverage964_DumpHeaderAndStatusDescribeFormattedVolume(t *testing.T) {
	ctx := context.Background()
	h, path, _ := newVolumeFile(t)

	header, err := h.DumpHeader(ctx, path)
	if err != nil {
		t.Fatalf("DumpHeader: %v", err)
	}
	if magic, _ := header["magic"].(string); !strings.HasPrefix(magic, "LUKS") {
		t.Errorf("magic = %q, want LUKS prefix", magic)
	}
	if label, _ := header["label"].(string); !strings.HasPrefix(label, "cov964") {
		t.Errorf("label = %q, want cov964 prefix", label)
	}
	for _, key := range []string{"keyslots", "segments", "digests", "config", "uuid"} {
		if _, ok := header[key]; !ok {
			t.Errorf("header has no %q entry", key)
		}
	}

	status, err := h.Status(ctx, path)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Version != LUKSVersion2 {
		t.Errorf("Version = %v, want LUKSVersion2", status.Version)
	}
	if status.DevicePath != path || status.Cipher == "" {
		t.Errorf("status = %+v, want device %s and a cipher", status, path)
	}
	if len(status.ActiveSlots) != 1 || status.ActiveSlots[0] != 0 {
		t.Errorf("ActiveSlots = %v, want [0]", status.ActiveSlots)
	}
	isLUKS, err := h.IsLUKS(ctx, path)
	if err != nil || !isLUKS {
		t.Errorf("IsLUKS = %v, %v; want true, nil", isLUKS, err)
	}
	version, err := h.Version(ctx, path)
	if err != nil || version != LUKSVersion2 {
		t.Errorf("Version = %v, %v; want LUKSVersion2, nil", version, err)
	}
	uuid, err := h.UUID(ctx, path)
	if err != nil {
		t.Fatalf("UUID: %v", err)
	}
	if status.UUID != uuid {
		t.Errorf("Status UUID %q differs from UUID() %q", status.UUID, uuid)
	}
}

func TestCoverage964_DumpHeaderAndStatusRejectMissingDevice(t *testing.T) {
	ctx := context.Background()
	h, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.img")

	if header, err := h.DumpHeader(ctx, missing); err == nil || header != nil {
		t.Errorf("DumpHeader(missing) = %v, %v; want nil, error", header, err)
	}
	if status, err := h.Status(ctx, missing); err == nil || status != nil {
		t.Errorf("Status(missing) = %v, %v; want nil, error", status, err)
	}
	if h.IsOpen(ctx, "cov964-mapping-that-does-not-exist") {
		t.Error("IsOpen reported an unknown mapping as open")
	}
}

func TestCoverage964_TokenLifecycle(t *testing.T) {
	ctx := context.Background()
	h, path, _ := newVolumeFile(t)

	count, err := h.TokenCount(ctx, path)
	if err != nil || count != 0 {
		t.Fatalf("TokenCount on fresh volume = %d, %v; want 0, nil", count, err)
	}

	tpmToken := &Token{Type: TokenTypeTPM2, Keyslots: []string{"0"}, TPM2PCRs: []int{7}, TPM2PCRBank: "sha256"}
	id, err := h.TokenCreate(ctx, path, tpmToken)
	if err != nil || id != 0 {
		t.Fatalf("TokenCreate = %d, %v; want 0, nil", id, err)
	}

	read, err := h.TokenRead(ctx, path, id)
	if err != nil {
		t.Fatalf("TokenRead: %v", err)
	}
	if read.Type != TokenTypeTPM2 || read.TPM2PCRBank != "sha256" || len(read.Keyslots) != 1 || read.Keyslots[0] != "0" {
		t.Errorf("TokenRead = %+v, want the created TPM2 token", read)
	}

	var occupied *TokenSlotOccupiedError
	if err := h.TokenCreateAt(ctx, path, id, tpmToken); !errors.As(err, &occupied) || occupied.ID != id {
		t.Errorf("TokenCreateAt on occupied slot = %v, want TokenSlotOccupiedError{%d}", err, id)
	}
	if err := h.TokenCreateAt(ctx, path, 5, &Token{Type: TokenTypeFIDO2, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("TokenCreateAt(5): %v", err)
	}

	exists, err := h.TokenExists(ctx, path, 5)
	if err != nil || !exists {
		t.Errorf("TokenExists(5) = %v, %v; want true, nil", exists, err)
	}
	list, err := h.TokenList(ctx, path)
	if err != nil {
		t.Fatalf("TokenList: %v", err)
	}
	if len(list) != 2 || list[0] == nil || list[5] == nil || list[5].Type != TokenTypeFIDO2 {
		t.Errorf("TokenList = %v, want tokens at 0 (tpm2) and 5 (fido2)", list)
	}

	if err := h.TokenUpdate(ctx, path, 5, &Token{Type: TokenTypePlatform, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("TokenUpdate(5): %v", err)
	}
	if updated, err := h.TokenRead(ctx, path, 5); err != nil || updated.Type != TokenTypePlatform {
		t.Errorf("TokenRead after update = %+v, %v; want type %s", updated, err, TokenTypePlatform)
	}

	var notFound *TokenNotFoundError
	if err := h.TokenUpdate(ctx, path, 7, tpmToken); !errors.As(err, &notFound) || notFound.ID != 7 {
		t.Errorf("TokenUpdate on empty slot = %v, want TokenNotFoundError{7}", err)
	}
	if err := h.TokenDelete(ctx, path, 5); err != nil {
		t.Fatalf("TokenDelete(5): %v", err)
	}
	if err := h.TokenDelete(ctx, path, 5); !errors.As(err, &notFound) || notFound.ID != 5 {
		t.Errorf("second TokenDelete(5) = %v, want TokenNotFoundError{5}", err)
	}
	if exists, err := h.TokenExists(ctx, path, 5); err != nil || exists {
		t.Errorf("TokenExists after delete = %v, %v; want false, nil", exists, err)
	}
	if _, err := h.TokenRead(ctx, path, 5); !errors.As(err, &notFound) {
		t.Errorf("TokenRead of deleted token = %v, want TokenNotFoundError", err)
	}
	if count, err := h.TokenCount(ctx, path); err != nil || count != 1 {
		t.Errorf("TokenCount after delete = %d, %v; want 1, nil", count, err)
	}
}

func TestCoverage964_TokenCreateReportsFullTable(t *testing.T) {
	ctx := context.Background()
	h, path, _ := newVolumeFile(t)

	for id := 0; id < MaxTokenSlots; id++ {
		if err := h.TokenCreateAt(ctx, path, id, &Token{Type: TokenTypeKeyring, Keyslots: []string{"0"}}); err != nil {
			t.Fatalf("TokenCreateAt(%d): %v", id, err)
		}
	}
	id, err := h.TokenCreate(ctx, path, &Token{Type: TokenTypeKeyring, Keyslots: []string{"0"}})
	if !errors.Is(err, ErrTokenNoFreeSlot) || id != -1 {
		t.Errorf("TokenCreate on full table = %d, %v; want -1, ErrTokenNoFreeSlot", id, err)
	}
}

func TestCoverage964_TokenWritesWrapImportErrors(t *testing.T) {
	ctx := context.Background()
	h, path, _ := newVolumeFile(t)
	if err := h.TokenCreateAt(ctx, path, 1, &Token{Type: TokenTypeKeyring, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("TokenCreateAt(1): %v", err)
	}
	// A blob larger than the whole LUKS2 header cannot fit its JSON area.
	bad := &Token{Type: TokenTypeTPM2, Keyslots: []string{"0"}, TPM2Blob: strings.Repeat("A", 1<<20)}

	tests := []struct {
		op   string
		call func() error
	}{
		{"create", func() error { _, err := h.TokenCreate(ctx, path, bad); return err }},
		{"create_at", func() error { return h.TokenCreateAt(ctx, path, 2, bad) }},
		{"update", func() error { return h.TokenUpdate(ctx, path, 1, bad) }},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			var opErr *TokenOperationError
			if err := tt.call(); !errors.As(err, &opErr) || opErr.Op != tt.op {
				t.Errorf("err = %v, want TokenOperationError{Op: %q}", err, tt.op)
			}
		})
	}
}

func TestCoverage964_TokenOperationsRejectInvalidIDs(t *testing.T) {
	ctx := context.Background()
	h, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	token := &Token{Type: TokenTypeTPM2}

	for _, id := range []int{-1, MaxTokenSlots} {
		ops := map[string]error{}
		_, ops["read"] = h.TokenRead(ctx, "unused", id)
		ops["delete"] = h.TokenDelete(ctx, "unused", id)
		_, ops["exists"] = h.TokenExists(ctx, "unused", id)
		ops["update"] = h.TokenUpdate(ctx, "unused", id, token)
		ops["create_at"] = h.TokenCreateAt(ctx, "unused", id, token)
		for op, err := range ops {
			var invalid *TokenInvalidIDError
			if !errors.As(err, &invalid) || invalid.ID != id {
				t.Errorf("%s(%d) = %v, want TokenInvalidIDError{%d}", op, id, err, id)
			}
		}
	}
}

func TestCoverage964_TokenOperationsWrapDeviceErrors(t *testing.T) {
	ctx := context.Background()
	h, err := NewCryptsetupHandlerImpl(nil, nil)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.img")
	token := &Token{Type: TokenTypeTPM2}

	tests := []struct {
		op   string
		call func() error
	}{
		{"find_free_slot", func() error { _, err := h.TokenCreate(ctx, missing, token); return err }},
		{"check_exists", func() error { return h.TokenCreateAt(ctx, missing, 1, token) }},
		{"read", func() error { _, err := h.TokenRead(ctx, missing, 1); return err }},
		{"delete", func() error { return h.TokenDelete(ctx, missing, 1) }},
		{"check_exists", func() error { return h.TokenUpdate(ctx, missing, 1, token) }},
		{"list", func() error { _, err := h.TokenList(ctx, missing); return err }},
		{"exists", func() error { _, err := h.TokenExists(ctx, missing, 1); return err }},
		{"count", func() error { _, err := h.TokenCount(ctx, missing); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			var opErr *TokenOperationError
			err := tt.call()
			if !errors.As(err, &opErr) || opErr.Op != tt.op || opErr.Err == nil {
				t.Errorf("err = %v, want TokenOperationError{Op: %q}", err, tt.op)
			}
		})
	}
}

// tpmPartition returns a partition whose device path does not exist, so every
// go-luks2 call on it fails after the TPM steps have run.
func tpmPartition() *drive.PartitionConfig {
	return &drive.PartitionConfig{
		ID:    "data",
		Label: "cov964-no-such-partlabel",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "cov964-crypt",
			TPMSealing:  &drive.TPMSealingConfig{Enabled: true, KeySlot: 1, PCRPolicy: true},
		},
	}
}

func newFakeTPMManager(t *testing.T, tpm *fakeTPM) *Manager {
	t.Helper()
	m, err := NewManager(nil, tpm, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestCoverage964_AddTPMSealedKeyFailures(t *testing.T) {
	tests := []struct {
		name    string
		tpm     *fakeTPM
		wantMsg string
		sealed  bool
	}{
		{"random bytes", &fakeTPM{randomErr: errFakeTPM}, "failed to generate random key", false},
		{"srk attributes", &fakeTPM{srkErr: errFakeTPM}, "failed to get SRK attributes", false},
		{"seal", &fakeTPM{sealErr: errFakeTPM}, "failed to seal key to TPM", true},
		{"luks add key", &fakeTPM{}, "failed to add key to LUKS", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			part := tpmPartition()
			m := newFakeTPMManager(t, tt.tpm)

			err := m.AddTPMSealedKey(context.Background(), part, []byte("pass"))
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tt.wantMsg {
				t.Fatalf("err = %v, want WrappedError %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), tt.wantMsg+": ") {
				t.Errorf("Error() = %q, want %q prefix", err.Error(), tt.wantMsg)
			}
			if part.Encryption.TPMSealing.SealedData != nil || part.Encryption.TPMSealing.KeyAttributes != nil {
				t.Error("a failed AddTPMSealedKey stored sealed data on the partition")
			}
			if !tt.sealed {
				return
			}
			attrs := tt.tpm.sealOpts.KeyAttributes
			if attrs.CN != "luks-data" || attrs.KeyType != xkmssdk.KeyTypeHMAC || !attrs.PlatformPolicy {
				t.Errorf("sealed attrs = %+v, want CN luks-data, HMAC, platform policy", attrs)
			}
			if attrs.Parent != tt.tpm.srk {
				t.Error("sealed key is not parented to the SSRK")
			}
		})
	}
}

func TestCoverage964_UnlockWithTPMRejectsMissingConfiguration(t *testing.T) {
	disabled := tpmPartition()
	disabled.Encryption.TPMSealing.Enabled = false
	unset := tpmPartition()
	unset.Encryption.TPMSealing = nil
	unsealed := tpmPartition()

	tests := []struct {
		name    string
		tpm     *fakeTPM
		part    *drive.PartitionConfig
		wantMsg string
	}{
		{"no tpm", nil, tpmPartition(), "TPM not available"},
		{"sealing disabled", &fakeTPM{}, disabled, "TPM sealing not configured for partition data"},
		{"sealing unset", &fakeTPM{}, unset, "TPM sealing not configured for partition data"},
		{"no sealed data", &fakeTPM{}, unsealed, "no sealed data available for partition data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m *Manager
			if tt.tpm == nil {
				var err error
				if m, err = NewManager(nil, nil, nil, nil); err != nil {
					t.Fatalf("NewManager: %v", err)
				}
			} else {
				m = newFakeTPMManager(t, tt.tpm)
			}
			var msgErr *MessageError
			err := m.UnlockWithTPM(context.Background(), tt.part)
			if !errors.As(err, &msgErr) || msgErr.Msg != tt.wantMsg {
				t.Errorf("err = %v, want MessageError %q", err, tt.wantMsg)
			}
		})
	}
}

func TestCoverage964_UnlockWithTPMFailures(t *testing.T) {
	tests := []struct {
		name     string
		tpm      *fakeTPM
		wantMsg  string
		unsealed bool
	}{
		{"srk attributes", &fakeTPM{srkErr: errFakeTPM}, "failed to get SRK attributes", false},
		{"unseal", &fakeTPM{unsealErr: errFakeTPM}, "failed to unseal key from TPM", true},
		{"luks unlock", &fakeTPM{srk: &xkmssdk.KeyAttributes{CN: "ssrk", TPMAttributes: &xkmssdk.TPMAttributes{}}}, "failed to unlock LUKS volume", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			part := tpmPartition()
			part.Encryption.TPMSealing.KeyName = "named-key"
			part.Encryption.TPMSealing.SealedData = &xkmssdk.SealedData{}
			m := newFakeTPMManager(t, tt.tpm)

			err := m.UnlockWithTPM(context.Background(), part)
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tt.wantMsg || !errors.Is(err, wrapped.Err) {
				t.Fatalf("err = %v, want WrappedError %q", err, tt.wantMsg)
			}
			if _, tracked := m.volumes[part.ID]; tracked {
				t.Error("a failed UnlockWithTPM tracked the volume as unlocked")
			}
			if !tt.unsealed {
				return
			}
			attrs := tt.tpm.unsealOpts.KeyAttributes
			if attrs.CN != "named-key" || attrs.KeyType != xkmssdk.KeyTypeHMAC {
				t.Errorf("unseal attrs = %+v, want CN named-key and HMAC", attrs)
			}
			if attrs.Parent != tt.tpm.srk || attrs.Parent.Password != nil {
				t.Error("unseal parent is not the SSRK with its password cleared")
			}
		})
	}
}

func TestCoverage964_FormatVolumeFailures(t *testing.T) {
	m, err := NewManager(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	plain := &drive.PartitionConfig{ID: "plain", Encryption: &drive.EncryptionConfig{Enabled: false}}
	var msgErr *MessageError
	if err := m.FormatVolume(context.Background(), plain, []byte("pass")); !errors.As(err, &msgErr) {
		t.Errorf("FormatVolume(unencrypted) = %v, want MessageError", err)
	}

	part := tpmPartition()
	var wrapped *WrappedError
	err = m.FormatVolume(context.Background(), part, []byte("pass"))
	if !errors.As(err, &wrapped) || wrapped.Msg != "failed to format LUKS volume" {
		t.Errorf("FormatVolume(missing device) = %v, want WrappedError %q", err, "failed to format LUKS volume")
	}
}
