package initrd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// fakeTokenUnsealer stands in for the go-xkms TPM sealer: it returns a
// fixed passphrase for any systemd-tpm2 token, or a fixed error.
type fakeTokenUnsealer struct {
	passphrase []byte
	err        error
	calls      int
	lastToken  *luks.Token
}

func (f *fakeTokenUnsealer) Unseal(_ context.Context, token *luks.Token) ([]byte, error) {
	f.calls++
	cp := *token
	f.lastToken = &cp
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.passphrase...), nil
}

// tpmTokenPlatform gives a test platform a token area holding tokens.
func tpmTokenPlatform(tokens map[int]*luks.Token) (*Platform, *MockLUKSHandler) {
	platform := createTestPlatform()
	m := platform.LUKS.(*MockLUKSHandler)
	tl := newTokenLUKS(m)
	for id, tok := range tokens {
		tl.tokens[id] = tok
	}
	platform.LUKS = tl
	return platform, m
}

func tpmTokenVolume() *luks.VolumeConfig {
	return &luks.VolumeConfig{DevicePath: "/dev/sda2", MappingName: "cryptroot"}
}

func TestTPMTokenStrategy_UnsealsTheTokenSlot(t *testing.T) {
	platform, m := tpmTokenPlatform(map[int]*luks.Token{
		0: {Type: "fido2-manual", Keyslots: []string{"1"}, FIDO2Credential: "x"},
		2: {Type: "systemd-tpm2", Keyslots: []string{"4"}, TPM2Blob: "c2VhbGVk", TPM2PCRs: []int{7}, TPM2PCRBank: "sha256"},
	})
	m.On("Open", mock.Anything, "/dev/sda2", "cryptroot", []byte("sealed-pass"),
		mock.MatchedBy(func(o *luks.OpenOptions) bool { return o != nil && o.KeySlot != nil && *o.KeySlot == 4 })).Return(nil)

	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	fake := &fakeTokenUnsealer{passphrase: []byte("sealed-pass")}
	s.unsealer = fake

	if s.Name() != StrategyNameTPMToken {
		t.Errorf("Name() = %q, want %q", s.Name(), StrategyNameTPMToken)
	}
	if !s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Fatal("CanUnlock = false with a systemd-tpm2 token in the header")
	}
	if err := s.Unlock(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if fake.calls != 1 || fake.lastToken.TPM2Blob != "c2VhbGVk" {
		t.Errorf("unsealer calls = %d, token = %+v; want one call with the systemd-tpm2 token", fake.calls, fake.lastToken)
	}
	m.AssertExpectations(t)
}

func TestTPMTokenStrategy_CannotUnlockWithoutAToken(t *testing.T) {
	platform, _ := tpmTokenPlatform(map[int]*luks.Token{
		0: {Type: "fido2-manual", Keyslots: []string{"1"}, FIDO2Credential: "x"},
	})
	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	s.unsealer = &fakeTokenUnsealer{passphrase: []byte("p")}
	if s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Error("CanUnlock = true without a systemd-tpm2 token")
	}

	// A handler that cannot list tokens cannot unlock either.
	plain := createTestPlatform()
	s = NewTPMTokenStrategy(plain, logging.DefaultLogger())
	s.unsealer = &fakeTokenUnsealer{passphrase: []byte("p")}
	if s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Error("CanUnlock = true on a handler without a token area")
	}
}

func TestTPMTokenStrategy_UnsealFailureFallsThrough(t *testing.T) {
	platform, _ := tpmTokenPlatform(map[int]*luks.Token{
		1: {Type: "systemd-tpm2", Keyslots: []string{"3"}, TPM2Blob: "YQ=="},
	})
	errUnseal := errors.New("pcr policy mismatch")
	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	s.unsealer = &fakeTokenUnsealer{err: errUnseal}

	if err := s.Unlock(context.Background(), tpmTokenVolume()); err == nil {
		t.Fatal("Unlock succeeded although the unseal failed")
	}

	next := &fallbackStrategy{}
	chain := NewStrategyChain(logging.DefaultLogger())
	chain.SetMarkerPath(t.TempDir() + "/unlock-strategy")
	chain.Add(s)
	chain.Add(next)
	if err := chain.Execute(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !next.unlocked {
		t.Error("the chain did not move on to the next strategy after the failed unseal")
	}
}

// fallbackStrategy always unlocks, after every other strategy.
type fallbackStrategy struct{ unlocked bool }

func (f *fallbackStrategy) Name() string                                       { return "Fallback" }
func (f *fallbackStrategy) Priority() int                                      { return 1000 }
func (f *fallbackStrategy) CanUnlock(context.Context, *luks.VolumeConfig) bool { return true }
func (f *fallbackStrategy) Unlock(context.Context, *luks.VolumeConfig) error {
	f.unlocked = true
	return nil
}
func (f *fallbackStrategy) Install(context.Context, *luks.VolumeConfig, []byte) error { return nil }
