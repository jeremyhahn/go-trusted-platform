package backends

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// roundTripSealer stands in for the TPM: Seal returns the passphrase and the
// systemd-tpm2 token JSON that enrolment writes to the LUKS2 header.
type roundTripSealer struct {
	pass  []byte
	token []byte
	pcrs  []int32
}

func (s *roundTripSealer) Seal(_ context.Context, _ string, pcrs []int32) ([]byte, []byte, error) {
	s.pcrs = pcrs
	return s.pass, s.token, nil
}

// roundTripUnsealer stands in for the initrd TPM unseal: it returns the
// passphrase only for the blob enrolment sealed.
type roundTripUnsealer struct {
	blob string
	pass []byte
}

func (u *roundTripUnsealer) Unseal(_ context.Context, token *luks.Token) ([]byte, error) {
	if token == nil || token.TPM2Blob != u.blob {
		return nil, errors.New("blob does not match the sealed one")
	}
	return u.pass, nil
}

// roundTripLUKS is a header with one systemd-tpm2 token; Open records the
// slot and passphrase it was called with.
type roundTripLUKS struct {
	luks.Handler
	token    *luks.Token
	openPass []byte
	openSlot *int
}

func (l *roundTripLUKS) Open(_ context.Context, _, _ string, password []byte, opts *luks.OpenOptions) error {
	l.openPass = append([]byte(nil), password...)
	if opts != nil && opts.KeySlot != nil {
		slot := *opts.KeySlot
		l.openSlot = &slot
	}
	return nil
}

func (l *roundTripLUKS) IsOpen(context.Context, string) bool { return false }

func (l *roundTripLUKS) TokenCreate(context.Context, string, *luks.Token) (int, error) {
	return 0, errors.New("not used")
}

func (l *roundTripLUKS) TokenCreateAt(context.Context, string, int, *luks.Token) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenRead(_ context.Context, _ string, id int) (*luks.Token, error) {
	if id != 0 {
		return nil, errors.New("no token")
	}
	return l.token, nil
}

func (l *roundTripLUKS) TokenDelete(context.Context, string, int) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenUpdate(context.Context, string, int, *luks.Token) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenList(context.Context, string) (map[int]*luks.Token, error) {
	return map[int]*luks.Token{0: l.token}, nil
}

func (l *roundTripLUKS) TokenExists(_ context.Context, _ string, id int) (bool, error) {
	return id == 0, nil
}

func (l *roundTripLUKS) TokenCount(context.Context, string) (int, error) { return 1, nil }

// TestLUKSTPMBootRoundTrip_InitrdUnsealsWhatEnrolmentSealed seals through the
// PCR-checked handler WireSDKBackends installs, writes the token the way
// enrolment does (keyslot 1), and has the initrd TPM-token strategy unlock
// the volume: it must open keyslot 1 with the sealed passphrase.
func TestLUKSTPMBootRoundTrip_InitrdUnsealsWhatEnrolmentSealed(t *testing.T) {
	ctx := context.Background()
	pass := []byte("sealed-volume-passphrase")
	tokenJSON := []byte(`{"type":"systemd-tpm2","keyslots":[],"tpm2-blob":"c2VhbGVkLWJsb2I=","tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"}`)

	sealer := &roundTripSealer{pass: pass, token: tokenJSON}
	handler := pcrCheckedTPMHandler(sealer)
	if handler == nil {
		t.Fatal("pcrCheckedTPMHandler returned nil for a non-nil handler")
	}
	gotPass, gotToken, err := handler.Seal(ctx, "/dev/vda2", []int32{7})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealer.pcrs) != 1 || sealer.pcrs[0] != 7 {
		t.Fatalf("Seal reached the TPM with PCRs %v, want [7]", sealer.pcrs)
	}

	var token luks.Token
	if err := json.Unmarshal(gotToken, &token); err != nil {
		t.Fatalf("token JSON: %v", err)
	}
	token.Keyslots = []string{"1"}

	header := &roundTripLUKS{token: &token}
	strategy := initrd.NewTPMTokenStrategy(&initrd.Platform{LUKS: header}, nil)
	strategy.SetUnsealer(&roundTripUnsealer{blob: token.TPM2Blob, pass: gotPass})

	volume := &luks.VolumeConfig{DevicePath: "/dev/vda2", MappingName: "cryptroot"}
	if !strategy.CanUnlock(ctx, volume) {
		t.Fatal("CanUnlock is false for a volume with a systemd-tpm2 token")
	}
	if err := strategy.Unlock(ctx, volume); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if header.openSlot == nil || *header.openSlot != 1 {
		t.Fatalf("Open used keyslot %v, want 1", header.openSlot)
	}
	// The strategy wipes the unsealed buffer after Open, so compare with a
	// literal and not with the slice the sealer handed out.
	if !bytes.Equal(header.openPass, []byte("sealed-volume-passphrase")) {
		t.Fatal("Open was not given the sealed passphrase")
	}
}
