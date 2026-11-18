package initrd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// tpmPCRStandIn answers to the TPM-PCR name, the only strategy whose win
// confirms the firstboot seal.
type tpmPCRStandIn struct{ fallbackStrategy }

func (f *tpmPCRStandIn) Name() string  { return StrategyNameTPMPCR }
func (f *tpmPCRStandIn) Priority() int { return 1 }

// Codex P1 (#1894): TPM enrolment before the reboot that confirms the
// firstboot seal must not let the token win that boot, or installer.luks
// (the plain key behind a documented password) is never wiped.
func TestTPMTokenStrategy_StandsAsideWhileFirstbootSealPending(t *testing.T) {
	platform, _ := tpmTokenPlatform(map[int]*luks.Token{
		2: {Type: "systemd-tpm2", Keyslots: []string{"4"}, TPM2Blob: "c2VhbGVk"},
	})
	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	fake := &fakeTokenUnsealer{passphrase: []byte("sealed-pass")}
	s.unsealer = fake
	s.sealPending = func() bool { return true }

	if s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Fatal("CanUnlock = true while the firstboot seal is unconfirmed")
	}

	pcr := &tpmPCRStandIn{}
	marker := t.TempDir() + "/unlock-strategy"
	chain := NewStrategyChain(logging.DefaultLogger())
	chain.SetMarkerPath(marker)
	chain.Add(s)
	chain.Add(pcr)
	if err := chain.Execute(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !pcr.unlocked || fake.calls != 0 {
		t.Fatalf("TPM-PCR unlocked = %v, token unseals = %d; want TPM-PCR to win and no token unseal", pcr.unlocked, fake.calls)
	}
	got, err := os.ReadFile(marker)
	if err != nil || strings.TrimSpace(string(got)) != StrategyNameTPMPCR {
		t.Fatalf("marker = %q (%v), want %q so the seal confirmation runs", got, err, StrategyNameTPMPCR)
	}

	// Once the seal is confirmed the token is used again.
	s.sealPending = func() bool { return false }
	if !s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Fatal("CanUnlock = false after the seal is confirmed")
	}
}

// The upgrade seals on the ESP are deleted only by a TPM-PCR unlock, so the
// token stands aside while they exist and TPM-PCR's cleanup runs (#1692).
func TestTPMTokenStrategy_StandsAsideWhileUpgradeSealsPresent(t *testing.T) {
	platform, _ := tpmTokenPlatform(map[int]*luks.Token{
		2: {Type: "systemd-tpm2", Keyslots: []string{"4"}, TPM2Blob: "c2VhbGVk"},
	})
	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	fake := &fakeTokenUnsealer{passphrase: []byte("sealed-pass")}
	s.unsealer = fake
	s.sealPending = func() bool { return false }
	s.upgradeSealsPending = func() bool { return true }

	if s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Fatal("CanUnlock = true while upgrade seals are on the ESP")
	}

	pcr := &tpmPCRStandIn{}
	marker := t.TempDir() + "/unlock-strategy"
	chain := NewStrategyChain(logging.DefaultLogger())
	chain.SetMarkerPath(marker)
	chain.Add(s)
	chain.Add(pcr)
	if err := chain.Execute(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !pcr.unlocked || fake.calls != 0 {
		t.Fatalf("TPM-PCR unlocked = %v, token unseals = %d; want TPM-PCR to win and no token unseal", pcr.unlocked, fake.calls)
	}
	got, err := os.ReadFile(marker)
	if err != nil || strings.TrimSpace(string(got)) != StrategyNameTPMPCR {
		t.Fatalf("marker = %q (%v), want %q", got, err, StrategyNameTPMPCR)
	}

	// Once TPM-PCR has removed the upgrade seals the token is used again.
	s.upgradeSealsPending = func() bool { return false }
	if !s.CanUnlock(context.Background(), tpmTokenVolume()) {
		t.Fatal("CanUnlock = false after the upgrade seals are gone")
	}
}

func TestUpgradeSealsUnder(t *testing.T) {
	writeSeal := func(t *testing.T, root, name string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte("seal"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	root := t.TempDir()
	if upgradeSealsUnder(root) {
		t.Fatal("upgradeSealsUnder = true on an empty ESP")
	}
	writeSeal(t, root, pcrUpgradePublicFile)
	if !upgradeSealsUnder(root) {
		t.Fatal("upgradeSealsUnder = false with the upgrade .pub present")
	}

	privRoot := t.TempDir()
	writeSeal(t, privRoot, pcrUpgradePrivateFile)
	if !upgradeSealsUnder(privRoot) {
		t.Fatal("upgradeSealsUnder = false with the upgrade .priv present")
	}
}

// pcrGatedUnsealer unseals only once the platform PCR carries the golden
// measurement, as a token sealed against the runtime PCR 23 does.
type pcrGatedUnsealer struct {
	tpm  *cov964bTPM
	pass []byte
}

func (u *pcrGatedUnsealer) Unseal(context.Context, *luks.Token) ([]byte, error) {
	if !u.tpm.extended {
		return nil, errors.New("TPM_RC_POLICY_FAIL: platform PCR not extended")
	}
	return append([]byte(nil), u.pass...), nil
}

// Codex P1 (#1894): on a cold boot the platform PCR is not yet extended
// when the token strategy runs ahead of TPM-PCR; it must extend it before
// unsealing a token bound to it.
func TestTPMTokenStrategy_ColdBootExtendsPlatformPCRBeforeUnseal(t *testing.T) {
	platform, m := tpmTokenPlatform(map[int]*luks.Token{
		2: {Type: "systemd-tpm2", Keyslots: []string{"4"}, TPM2Blob: "c2VhbGVk", TPM2PCRs: []int{7, 23}},
	})
	tpm := &cov964bTPM{}
	platform.TPM = tpm
	m.On("Open", mock.Anything, "/dev/sda2", "cryptroot", []byte("sealed-pass"),
		mock.MatchedBy(func(o *luks.OpenOptions) bool { return o != nil && o.KeySlot != nil && *o.KeySlot == 4 })).Return(nil)

	s := NewTPMTokenStrategy(platform, logging.DefaultLogger())
	s.unsealer = &pcrGatedUnsealer{tpm: tpm, pass: []byte("sealed-pass")}
	s.sealPending = func() bool { return false }

	if err := s.Unlock(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("Unlock on a cold boot: %v", err)
	}
	if tpm.policyCalls != 1 {
		t.Errorf("CreatePlatformPolicy calls = %d, want 1", tpm.policyCalls)
	}
	// Already extended: no second extension.
	if err := s.Unlock(context.Background(), tpmTokenVolume()); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
	if tpm.policyCalls != 1 {
		t.Errorf("CreatePlatformPolicy calls = %d after a warm unlock, want 1", tpm.policyCalls)
	}
	m.AssertExpectations(t)
}
