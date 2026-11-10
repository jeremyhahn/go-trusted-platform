// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package initrd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	"github.com/stretchr/testify/mock"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// cov964aError is the typed error the fakes inject.
type cov964aError struct {
	op string
}

func (e *cov964aError) Error() string { return "cov964a: " + e.op + " failed" }

// cov964aSealMismatchError is returned by the fake Unseal when the blobs it
// is handed are not the ones its Seal produced.
type cov964aSealMismatchError struct{}

func (e *cov964aSealMismatchError) Error() string { return "cov964a: sealed blobs do not match" }

var (
	cov964aPubBlob  = []byte("cov964a-tpm-public")
	cov964aPrivBlob = []byte("cov964a-tpm-private")
)

const cov964aSRKHandle = uint32(0x81000005)

// cov964aTPM fakes the TPM methods the initrd strategies call. Any other
// method panics on the nil embedded interface.
type cov964aTPM struct {
	xkmssdk.TrustedPlatformModule

	cfg *xkmssdk.TPMConfig

	attrsErr   error
	sealErr    error
	unsealErr  error
	installErr error
	closeErr   error

	attrsHandle  xkmssdk.TPMHandle
	sealOpts     *xkmssdk.SealOptions
	unsealOpts   *xkmssdk.UnsealOptions
	sealed       *xkmssdk.SealedData
	sealedKey    []byte
	installCalls int
	closeCalls   int
}

func (f *cov964aTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *cov964aTPM) KeyAttributes(handle xkmssdk.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	f.attrsHandle = handle
	if f.attrsErr != nil {
		return nil, f.attrsErr
	}
	return &xkmssdk.KeyAttributes{CN: "platform-srk", PlatformPolicy: true}, nil
}

func (f *cov964aTPM) Seal(_ context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.sealOpts = opts
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	f.sealedKey = append([]byte(nil), data...)
	f.sealed = &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		TPMPublic:  cov964aPubBlob,
		TPMPrivate: cov964aPrivBlob,
	}
	return f.sealed, nil
}

func (f *cov964aTPM) Unseal(_ context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	f.unsealOpts = opts
	if f.unsealErr != nil {
		return nil, f.unsealErr
	}
	if f.sealed == nil ||
		!bytes.Equal(sealed.TPMPublic, f.sealed.TPMPublic) ||
		!bytes.Equal(sealed.TPMPrivate, f.sealed.TPMPrivate) {
		return nil, &cov964aSealMismatchError{}
	}
	return f.sealedKey, nil
}

func (f *cov964aTPM) Install(_ xkmssdk.Password, _ *xkmssdk.InstallOptions) error {
	f.installCalls++
	return f.installErr
}

func (f *cov964aTPM) Close() error {
	f.closeCalls++
	return f.closeErr
}

// cov964aFIDO2 fakes the FIDO2 handler methods the initrd strategy calls.
type cov964aFIDO2 struct {
	fido2.Handler

	enrollErr error
	unlockErr error
	closeErr  error

	credentialID []byte
	key          []byte

	enrollConfig  *fido2.EnrollmentConfig
	unlockConfigs []*fido2.AuthenticationConfig
	closeCalls    int
}

func (f *cov964aFIDO2) EnrollKey(config *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	f.enrollConfig = config
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	return &fido2.EnrollmentResult{CredentialID: f.credentialID}, nil
}

func (f *cov964aFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	f.unlockConfigs = append(f.unlockConfigs, config)
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	return f.key, nil
}

func (f *cov964aFIDO2) Close() error {
	f.closeCalls++
	return f.closeErr
}

// cov964aBackend stands in for the TPM key backend. The strategies only pass
// it through to Seal and Unseal, so the tests compare its identity.
// MockKeyBackend does not satisfy xkmssdk.TPMKeyBackend.
type cov964aBackend struct {
	xkmssdk.TPMKeyBackend
}

// cov964aPlatform builds a test platform whose paths all live under
// t.TempDir(). A nil tpm or fido leaves that handler unset.
func cov964aPlatform(t *testing.T, tpm *cov964aTPM, fido *cov964aFIDO2) (*Platform, *MockLUKSHandler) {
	t.Helper()
	p := createTestPlatform()
	p.Config.XKMSPath = filepath.Join(t.TempDir(), "xkms")
	p.Config.RootDevice = filepath.Join(t.TempDir(), "root.img")
	if tpm != nil {
		p.TPM = tpm
	}
	if fido != nil {
		p.FIDO2 = fido
	}
	p.Backend = &cov964aBackend{}
	return p, p.LUKS.(*MockLUKSHandler)
}

func cov964aManager(p *Platform) *initrdManager {
	logger := logging.DefaultLogger()
	return &initrdManager{platform: p, chain: NewStrategyChain(logger), logger: logger}
}

func cov964aVolume(p *Platform, slots ...luks.KeySlot) *luks.VolumeConfig {
	return &luks.VolumeConfig{
		DevicePath:    p.Config.RootDevice,
		MappingName:   "cov964a-root",
		AllowDiscards: true,
		Timeout:       7,
		KeySlots:      slots,
	}
}

// cov964aSeedSealed writes the fake's blobs to XKMSPath and primes the fake
// as if Seal had produced them for key.
func cov964aSeedSealed(t *testing.T, p *Platform, tpm *cov964aTPM, key []byte) {
	t.Helper()
	if err := os.MkdirAll(p.Config.XKMSPath, 0o700); err != nil {
		t.Fatalf("mkdir xkms: %v", err)
	}
	cov964aWrite(t, filepath.Join(p.Config.XKMSPath, "seal.pub"), cov964aPubBlob)
	cov964aWrite(t, filepath.Join(p.Config.XKMSPath, "seal.priv"), cov964aPrivBlob)
	tpm.sealed = &xkmssdk.SealedData{TPMPublic: cov964aPubBlob, TPMPrivate: cov964aPrivBlob}
	tpm.sealedKey = key
}

func cov964aWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// cov964aRegularFile returns a path to an existing regular file, so any
// path beneath it cannot be created.
func cov964aRegularFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "regular-file")
	cov964aWrite(t, path, []byte("not a directory"))
	return path
}

func cov964aWantErr(t *testing.T, err error, msg string, cause error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", msg)
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("error %q does not contain %q", err.Error(), msg)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Errorf("error %q does not wrap %v", err.Error(), cause)
	}
}

// cov964aAssertSealAttrs checks the attributes both Seal and Unseal receive.
func cov964aAssertSealAttrs(t *testing.T, attrs *xkmssdk.KeyAttributes, parentPolicy bool) {
	t.Helper()
	if attrs == nil {
		t.Fatal("KeyAttributes not passed")
	}
	if attrs.CN != "luks-root-nopcr" {
		t.Errorf("CN = %q, want luks-root-nopcr", attrs.CN)
	}
	if attrs.KeyType != xkmssdk.KeyTypeHMAC {
		t.Errorf("KeyType = %v, want HMAC", attrs.KeyType)
	}
	if attrs.PlatformPolicy {
		t.Error("sealed object PlatformPolicy = true, want false")
	}
	if attrs.Parent == nil {
		t.Fatal("Parent attributes not set")
	}
	if attrs.Parent.PlatformPolicy != parentPolicy {
		t.Errorf("parent PlatformPolicy = %v, want %v", attrs.Parent.PlatformPolicy, parentPolicy)
	}
}

func cov964aConfig(handle uint32, policy bool) *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: handle, PlatformPolicy: policy},
	}
}

// --- errors.go ---

func TestCov964aErrorMessages(t *testing.T) {
	base := &MessageError{Msg: "exit status 1"}
	sentinel := &MessageError{Msg: "sentinel"}
	cause := &MessageError{Msg: "cause"}

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"MessageError", &MessageError{Msg: "plain message"}, "plain message"},
		{"CommandError", &CommandError{Err: base, Output: "device busy"}, "exit status 1: device busy"},
		{"SentinelCauseError", &SentinelCauseError{Sentinel: sentinel, Cause: cause}, "sentinel: cause"},
		{"ResealNoSlotError", &ResealNoSlotError{DevicePath: "/dev/vda2"},
			"reseal: no TPM-PCR key slot configured for /dev/vda2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}

	if !errors.Is(&CommandError{Err: base, Output: "x"}, base) {
		t.Error("CommandError does not unwrap to its Err")
	}
	sce := &SentinelCauseError{Sentinel: sentinel, Cause: cause}
	if !errors.Is(sce, sentinel) {
		t.Error("SentinelCauseError does not match its Sentinel")
	}
	if !errors.Is(sce, cause) {
		t.Error("SentinelCauseError does not match its Cause")
	}
}

// --- types.go / initrd.go / strategy.go ---

func TestCov964aRootDevice(t *testing.T) {
	var nilPlatform *Platform
	if got := nilPlatform.rootDevice(); got != "" {
		t.Errorf("nil platform rootDevice = %q, want empty", got)
	}
	if got := (&Platform{}).rootDevice(); got != "" {
		t.Errorf("nil config rootDevice = %q, want empty", got)
	}
	p, _ := cov964aPlatform(t, nil, nil)
	if got := p.rootDevice(); got != p.Config.RootDevice {
		t.Errorf("rootDevice = %q, want %q", got, p.Config.RootDevice)
	}
}

func TestCov964aUnlockedWith(t *testing.T) {
	m := &initrdManager{}
	if got := m.UnlockedWith(); got != "" {
		t.Errorf("UnlockedWith before unlock = %q, want empty", got)
	}
	m.unlockedWith = "TPM-NoPCR"
	if got := m.UnlockedWith(); got != "TPM-NoPCR" {
		t.Errorf("UnlockedWith = %q, want TPM-NoPCR", got)
	}
}

func TestCov964aManagerClose(t *testing.T) {
	t.Run("no handlers", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, nil)
		if err := cov964aManager(p).Close(); err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
	})

	t.Run("both handlers closed", func(t *testing.T) {
		tpm, fido := &cov964aTPM{}, &cov964aFIDO2{}
		p, _ := cov964aPlatform(t, tpm, fido)
		if err := cov964aManager(p).Close(); err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
		if tpm.closeCalls != 1 || fido.closeCalls != 1 {
			t.Errorf("close calls tpm=%d fido2=%d, want 1 each", tpm.closeCalls, fido.closeCalls)
		}
	})

	t.Run("close errors are logged not returned", func(t *testing.T) {
		tpm := &cov964aTPM{closeErr: &cov964aError{op: "tpm close"}}
		fido := &cov964aFIDO2{closeErr: &cov964aError{op: "fido2 close"}}
		p, _ := cov964aPlatform(t, tpm, fido)
		if err := cov964aManager(p).Close(); err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
		if tpm.closeCalls != 1 || fido.closeCalls != 1 {
			t.Errorf("close calls tpm=%d fido2=%d, want 1 each", tpm.closeCalls, fido.closeCalls)
		}
	})
}

func TestCov964aRecordWinner(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("writes marker", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "run", "unlock-strategy")
		chain := NewStrategyChain(logger)
		chain.SetMarkerPath(marker)
		chain.recordWinner("TPM-PCR")
		data, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("marker not written: %v", err)
		}
		if string(data) != "TPM-PCR\n" {
			t.Errorf("marker = %q, want %q", data, "TPM-PCR\n")
		}
	})

	t.Run("parent is a regular file", func(t *testing.T) {
		file := cov964aRegularFile(t)
		marker := filepath.Join(file, "sub", "unlock-strategy")
		chain := NewStrategyChain(logger)
		chain.SetMarkerPath(marker)
		chain.recordWinner("TPM-PCR")
		if _, err := os.Stat(marker); err == nil {
			t.Error("marker written beneath a regular file")
		}
		data, err := os.ReadFile(file)
		if err != nil || string(data) != "not a directory" {
			t.Errorf("regular file changed: %q, %v", data, err)
		}
	})

	t.Run("marker path is a directory", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "unlock-strategy")
		if err := os.Mkdir(marker, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		chain := NewStrategyChain(logger)
		chain.SetMarkerPath(marker)
		chain.recordWinner("TPM-PCR")
		info, err := os.Stat(marker)
		if err != nil || !info.IsDir() {
			t.Errorf("marker directory replaced: %v, %v", info, err)
		}
		entries, err := os.ReadDir(marker)
		if err != nil || len(entries) != 0 {
			t.Errorf("marker directory gained entries: %v, %v", entries, err)
		}
	})
}

// --- strategy_tpm_nopcr.go ---

func TestCov964aNoPCRPlatformSRKSettings(t *testing.T) {
	const defaultHandle = uint32(0x81000002)

	cases := []struct {
		name       string
		tpm        *cov964aTPM
		wantHandle uint32
		wantPolicy bool
	}{
		{"TPM nil", nil, defaultHandle, true},
		{"Config nil", &cov964aTPM{}, defaultHandle, true},
		{"PlatformSRK nil", &cov964aTPM{cfg: &xkmssdk.TPMConfig{}}, defaultHandle, true},
		{"zero handle", &cov964aTPM{cfg: cov964aConfig(0, false)}, defaultHandle, false},
		{"handle and policy set", &cov964aTPM{cfg: cov964aConfig(cov964aSRKHandle, false)}, cov964aSRKHandle, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := cov964aPlatform(t, tc.tpm, nil)
			s := NewTPMNoPCRStrategy(p, logging.DefaultLogger())
			if got := s.getPlatformKeystoreSRKHandle(); got != tc.wantHandle {
				t.Errorf("handle = %#x, want %#x", got, tc.wantHandle)
			}
			if got := s.getPlatformPolicy(); got != tc.wantPolicy {
				t.Errorf("policy = %v, want %v", got, tc.wantPolicy)
			}
		})
	}
}

func TestCov964aNoPCRCanUnlock(t *testing.T) {
	ctx := context.Background()

	t.Run("TPM nil", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, nil)
		cov964aSeedSealed(t, p, &cov964aTPM{}, nil)
		if NewTPMNoPCRStrategy(p, logging.DefaultLogger()).CanUnlock(ctx, cov964aVolume(p)) {
			t.Error("CanUnlock = true without a TPM")
		}
	})

	t.Run("seal.pub missing", func(t *testing.T) {
		p, _ := cov964aPlatform(t, &cov964aTPM{}, nil)
		if NewTPMNoPCRStrategy(p, logging.DefaultLogger()).CanUnlock(ctx, cov964aVolume(p)) {
			t.Error("CanUnlock = true without seal.pub")
		}
	})

	t.Run("seal.priv missing", func(t *testing.T) {
		p, _ := cov964aPlatform(t, &cov964aTPM{}, nil)
		if err := os.MkdirAll(p.Config.XKMSPath, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		cov964aWrite(t, filepath.Join(p.Config.XKMSPath, "seal.pub"), cov964aPubBlob)
		if NewTPMNoPCRStrategy(p, logging.DefaultLogger()).CanUnlock(ctx, cov964aVolume(p)) {
			t.Error("CanUnlock = true without seal.priv")
		}
	})

	t.Run("both blobs present", func(t *testing.T) {
		tpm := &cov964aTPM{}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, nil)
		if !NewTPMNoPCRStrategy(p, logging.DefaultLogger()).CanUnlock(ctx, cov964aVolume(p)) {
			t.Error("CanUnlock = false with both blobs present")
		}
	})
}

func TestCov964aNoPCRInstall(t *testing.T) {
	ctx := context.Background()
	password := []byte("install-password")

	t.Run("KeyAttributes error", func(t *testing.T) {
		attrsErr := &cov964aError{op: "key attributes"}
		p, _ := cov964aPlatform(t, &cov964aTPM{attrsErr: attrsErr}, nil)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "failed to get Platform KeyStore SRK attributes", attrsErr)
	})

	t.Run("Seal error", func(t *testing.T) {
		sealErr := &cov964aError{op: "seal"}
		p, _ := cov964aPlatform(t, &cov964aTPM{sealErr: sealErr}, nil)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "failed to seal key", sealErr)
		if _, statErr := os.Stat(p.Config.XKMSPath); statErr == nil {
			t.Error("xkms directory created after a failed seal")
		}
	})

	t.Run("XKMSPath under a regular file", func(t *testing.T) {
		p, _ := cov964aPlatform(t, &cov964aTPM{}, nil)
		p.Config.XKMSPath = filepath.Join(cov964aRegularFile(t), "xkms")
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "failed to create xkms directory", nil)
	})

	t.Run("AddKey error", func(t *testing.T) {
		addErr := &cov964aError{op: "add key"}
		p, luksMock := cov964aPlatform(t, &cov964aTPM{}, nil)
		luksMock.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).Return(addErr)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "failed to add key to LUKS", addErr)
		luksMock.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		tpm := &cov964aTPM{cfg: cov964aConfig(cov964aSRKHandle, false)}
		p, luksMock := cov964aPlatform(t, tpm, nil)
		var addedKey []byte
		var addOpts *luks.AddKeyOptions
		luksMock.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				addedKey = args.Get(3).([]byte)
				addOpts = args.Get(4).(*luks.AddKeyOptions)
			}).Return(nil)

		if err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password); err != nil {
			t.Fatalf("Install: %v", err)
		}

		if tpm.attrsHandle != xkmssdk.TPMHandle(cov964aSRKHandle) {
			t.Errorf("KeyAttributes handle = %#x, want %#x", tpm.attrsHandle, cov964aSRKHandle)
		}
		cov964aAssertSealAttrs(t, tpm.sealOpts.KeyAttributes, false)
		if tpm.sealOpts.Backend != p.Backend {
			t.Errorf("Seal backend = %v, want the platform backend", tpm.sealOpts.Backend)
		}
		if len(addedKey) != 32 || !bytes.Equal(addedKey, tpm.sealedKey) {
			t.Errorf("AddKey key (%d bytes) is not the 32-byte sealed key", len(addedKey))
		}
		if addOpts.KeySlot != nil {
			t.Errorf("AddKey KeySlot = %d, want nil", *addOpts.KeySlot)
		}
		if addOpts.KDFType != fips.GetKDF() || addOpts.Hash != fips.GetHash() {
			t.Errorf("AddKey KDF/Hash = %q/%q, want %q/%q", addOpts.KDFType, addOpts.Hash, fips.GetKDF(), fips.GetHash())
		}
		for name, want := range map[string][]byte{"seal.pub": cov964aPubBlob, "seal.priv": cov964aPrivBlob} {
			got, err := os.ReadFile(filepath.Join(p.Config.XKMSPath, name))
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s = %q, %v; want %q", name, got, err, want)
			}
		}
		luksMock.AssertExpectations(t)
	})
}

func TestCov964aNoPCRUnlock(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x5a}, 32)

	t.Run("KeyAttributes error", func(t *testing.T) {
		attrsErr := &cov964aError{op: "key attributes"}
		tpm := &cov964aTPM{attrsErr: attrsErr}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, key)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		cov964aWantErr(t, err, "failed to get Platform KeyStore SRK attributes", attrsErr)
	})

	t.Run("seal.pub missing", func(t *testing.T) {
		p, _ := cov964aPlatform(t, &cov964aTPM{}, nil)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		cov964aWantErr(t, err, "failed to read seal.pub", os.ErrNotExist)
	})

	t.Run("seal.priv missing", func(t *testing.T) {
		tpm := &cov964aTPM{}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, key)
		if err := os.Remove(filepath.Join(p.Config.XKMSPath, "seal.priv")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		cov964aWantErr(t, err, "failed to read seal.priv", os.ErrNotExist)
	})

	t.Run("Unseal error", func(t *testing.T) {
		unsealErr := &cov964aError{op: "unseal"}
		tpm := &cov964aTPM{unsealErr: unsealErr}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, key)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		cov964aWantErr(t, err, "failed to unseal key", unsealErr)
	})

	t.Run("tampered blob fails to unseal", func(t *testing.T) {
		tpm := &cov964aTPM{}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, key)
		cov964aWrite(t, filepath.Join(p.Config.XKMSPath, "seal.priv"), []byte("tampered"))
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		var mismatch *cov964aSealMismatchError
		if !errors.As(err, &mismatch) {
			t.Errorf("Unlock error = %v, want a seal mismatch", err)
		}
	})

	t.Run("Open error", func(t *testing.T) {
		openErr := &cov964aError{op: "open"}
		tpm := &cov964aTPM{}
		p, luksMock := cov964aPlatform(t, tpm, nil)
		cov964aSeedSealed(t, p, tpm, key)
		luksMock.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", key, mock.Anything).Return(openErr)
		err := NewTPMNoPCRStrategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p))
		cov964aWantErr(t, err, "LUKS open failed", openErr)
		luksMock.AssertExpectations(t)
	})

	t.Run("Install then Unlock round trip", func(t *testing.T) {
		tpm := &cov964aTPM{cfg: cov964aConfig(cov964aSRKHandle, true)}
		p, luksMock := cov964aPlatform(t, tpm, nil)
		volume := cov964aVolume(p)
		password := []byte("install-password")

		var addedKey, openedKey []byte
		var openOpts *luks.OpenOptions
		luksMock.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { addedKey = args.Get(3).([]byte) }).Return(nil)
		luksMock.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				openedKey = args.Get(3).([]byte)
				openOpts = args.Get(4).(*luks.OpenOptions)
			}).Return(nil)

		s := NewTPMNoPCRStrategy(p, logging.DefaultLogger())
		if err := s.Install(ctx, volume, password); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if err := s.Unlock(ctx, volume); err != nil {
			t.Fatalf("Unlock: %v", err)
		}

		if len(addedKey) != 32 || !bytes.Equal(openedKey, addedKey) {
			t.Error("Open did not receive the key AddKey enrolled")
		}
		if openOpts.KeySlot != nil || !openOpts.AllowDiscards || openOpts.Timeout != 7 {
			t.Errorf("OpenOptions = %+v, want KeySlot nil, AllowDiscards, Timeout 7", openOpts)
		}
		cov964aAssertSealAttrs(t, tpm.unsealOpts.KeyAttributes, true)
		if tpm.unsealOpts.Backend != p.Backend {
			t.Errorf("Unseal backend = %v, want the platform backend", tpm.unsealOpts.Backend)
		}
		luksMock.AssertExpectations(t)
	})
}

// --- strategy_fido2.go ---

var cov964aFIDO2Slot = luks.KeySlot{Index: 2, Type: luks.UnlockFIDO2}

func TestCov964aFIDO2CanUnlock(t *testing.T) {
	ctx := context.Background()

	t.Run("FIDO2 nil", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, nil)
		if NewFIDO2Strategy(p, logging.DefaultLogger()).CanUnlock(ctx, cov964aVolume(p, cov964aFIDO2Slot)) {
			t.Error("CanUnlock = true without a FIDO2 handler")
		}
	})

	t.Run("no FIDO2 slot", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, &cov964aFIDO2{})
		volume := cov964aVolume(p, luks.KeySlot{Index: 0, Type: luks.UnlockPassword})
		if NewFIDO2Strategy(p, logging.DefaultLogger()).CanUnlock(ctx, volume) {
			t.Error("CanUnlock = true without a FIDO2 slot")
		}
	})

	t.Run("FIDO2 slot", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, &cov964aFIDO2{})
		volume := cov964aVolume(p, luks.KeySlot{Index: 0, Type: luks.UnlockPassword}, cov964aFIDO2Slot)
		if !NewFIDO2Strategy(p, logging.DefaultLogger()).CanUnlock(ctx, volume) {
			t.Error("CanUnlock = false with a FIDO2 slot")
		}
	})
}

// cov964aTokenLUKS is the round-trip tokenLUKS with AddKey and Open routed
// back to its testify mock, so a case can make them fail and inspect their
// arguments. The LUKS2 tokens stay in the tokenLUKS.
type cov964aTokenLUKS struct {
	*tokenLUKS
}

func (l *cov964aTokenLUKS) AddKey(ctx context.Context, devicePath string, existingPassword, newPassword []byte, opts *luks.AddKeyOptions) error {
	return l.MockLUKSHandler.AddKey(ctx, devicePath, existingPassword, newPassword, opts)
}

func (l *cov964aTokenLUKS) Open(ctx context.Context, devicePath, mappingName string, password []byte, opts *luks.OpenOptions) error {
	return l.MockLUKSHandler.Open(ctx, devicePath, mappingName, password, opts)
}

// cov964aTokenPlatform is cov964aPlatform with a token-capable LUKS handler.
// Each enrolled slot is installed through the strategy first, so the header
// holds the token Unlock reads; the fake's recorded calls start empty.
func cov964aTokenPlatform(t *testing.T, fido *cov964aFIDO2, enrolled ...luks.KeySlot) (*Platform, *cov964aTokenLUKS) {
	t.Helper()
	p, _ := cov964aPlatform(t, nil, fido)
	header := newTokenLUKS()
	p.LUKS = header
	for _, slot := range enrolled {
		// Install zeroes the key the fake hands out.
		key := bytes.Clone(fido.key)
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(context.Background(), cov964aVolume(p, slot), []byte("install-password"))
		if err != nil {
			t.Fatalf("Install slot %d: %v", slot.Index, err)
		}
		fido.key = key
	}
	if fido != nil {
		fido.enrollConfig = nil
		fido.unlockConfigs = nil
	}
	volume := &cov964aTokenLUKS{tokenLUKS: header}
	p.LUKS = volume
	return p, volume
}

func TestCov964aFIDO2Unlock(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 32)
	credentialID := bytes.Repeat([]byte{0x11, 0x22}, 24) // 48 bytes

	t.Run("cancelled context", func(t *testing.T) {
		fido := &cov964aFIDO2{credentialID: credentialID, key: bytes.Clone(key)}
		p, _ := cov964aTokenPlatform(t, fido, cov964aFIDO2Slot)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(ctx, cov964aVolume(p, cov964aFIDO2Slot))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Unlock = %v, want context.Canceled", err)
		}
		if len(fido.unlockConfigs) != 0 {
			t.Error("UnlockWithKey called after cancellation")
		}
	})

	t.Run("every slot fails authentication", func(t *testing.T) {
		fido := &cov964aFIDO2{credentialID: credentialID, key: bytes.Clone(key)}
		secondSlot := luks.KeySlot{Index: 4, Type: luks.UnlockFIDO2}
		p, _ := cov964aTokenPlatform(t, fido, cov964aFIDO2Slot, secondSlot)
		fido.unlockErr = &cov964aError{op: "assertion"}
		volume := cov964aVolume(p, cov964aFIDO2Slot, secondSlot)
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(context.Background(), volume)
		cov964aWantErr(t, err, "all FIDO2 slots failed", fido.unlockErr)
		if len(fido.unlockConfigs) != 2 {
			t.Errorf("UnlockWithKey calls = %d, want 2", len(fido.unlockConfigs))
		}
	})

	t.Run("Open fails", func(t *testing.T) {
		fido := &cov964aFIDO2{credentialID: credentialID, key: bytes.Clone(key)}
		p, luksMock := cov964aTokenPlatform(t, fido, cov964aFIDO2Slot)
		luksMock.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", key, mock.Anything).
			Return(&cov964aError{op: "open"})
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(context.Background(), cov964aVolume(p, cov964aFIDO2Slot))
		cov964aWantErr(t, err, "all FIDO2 slots failed", nil)
		luksMock.AssertExpectations(t)
	})

	t.Run("success opens the FIDO2 slot", func(t *testing.T) {
		fido := &cov964aFIDO2{credentialID: credentialID, key: bytes.Clone(key)}
		p, luksMock := cov964aTokenPlatform(t, fido, cov964aFIDO2Slot)
		var openOpts *luks.OpenOptions
		luksMock.On("Open", mock.Anything, p.Config.RootDevice, "cov964a-root", key, mock.Anything).
			Run(func(args mock.Arguments) { openOpts = args.Get(4).(*luks.OpenOptions) }).Return(nil)
		volume := cov964aVolume(p, luks.KeySlot{Index: 0, Type: luks.UnlockPassword}, cov964aFIDO2Slot)

		if err := NewFIDO2Strategy(p, logging.DefaultLogger()).Unlock(context.Background(), volume); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		if openOpts.KeySlot == nil || *openOpts.KeySlot != cov964aFIDO2Slot.Index {
			t.Errorf("OpenOptions.KeySlot = %v, want %d", openOpts.KeySlot, cov964aFIDO2Slot.Index)
		}
		if !openOpts.AllowDiscards || openOpts.Timeout != 7 {
			t.Errorf("OpenOptions = %+v, want AllowDiscards and Timeout 7", openOpts)
		}
		if len(fido.unlockConfigs) != 1 || fido.unlockConfigs[0].RelyingPartyID != "luks-root" {
			t.Errorf("UnlockWithKey configs = %+v, want one for luks-root", fido.unlockConfigs)
		}
		luksMock.AssertExpectations(t)
	})
}

func TestCov964aFIDO2Install(t *testing.T) {
	ctx := context.Background()
	password := []byte("install-password")
	credentialID := bytes.Repeat([]byte{0x11, 0x22}, 24) // 48 bytes

	t.Run("FIDO2 nil", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, nil)
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p, cov964aFIDO2Slot), password)
		cov964aWantErr(t, err, "FIDO2 handler not available", nil)
	})

	t.Run("no FIDO2 slot", func(t *testing.T) {
		fido := &cov964aFIDO2{credentialID: credentialID}
		p, _ := cov964aPlatform(t, nil, fido)
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "no FIDO2 key slot configured", nil)
		if fido.enrollConfig != nil {
			t.Error("EnrollKey called without a FIDO2 slot")
		}
	})

	t.Run("EnrollKey error", func(t *testing.T) {
		enrollErr := &cov964aError{op: "enroll"}
		p, _ := cov964aTokenPlatform(t, &cov964aFIDO2{enrollErr: enrollErr})
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p, cov964aFIDO2Slot), password)
		cov964aWantErr(t, err, "failed to enroll FIDO2 key", enrollErr)
	})

	t.Run("AddKey error", func(t *testing.T) {
		addErr := &cov964aError{op: "add key"}
		p, luksMock := cov964aTokenPlatform(t, &cov964aFIDO2{credentialID: credentialID, key: bytes.Repeat([]byte{0xa5}, 32)})
		luksMock.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).Return(addErr)
		err := NewFIDO2Strategy(p, logging.DefaultLogger()).Install(ctx, cov964aVolume(p, cov964aFIDO2Slot), password)
		cov964aWantErr(t, err, "failed to add key to LUKS slot 2", addErr)
		luksMock.AssertExpectations(t)
		if len(luksMock.tokens) != 0 {
			t.Errorf("%d token(s) written after a failed AddKey", len(luksMock.tokens))
		}
	})
}

// --- install.go ---

func TestCov964aFormatLUKSVolume(t *testing.T) {
	ctx := context.Background()
	password := []byte("format-password")

	t.Run("Format error", func(t *testing.T) {
		formatErr := &cov964aError{op: "format"}
		p, luksMock := cov964aPlatform(t, nil, nil)
		luksMock.On("Format", mock.Anything, p.Config.RootDevice, password, mock.Anything).Return(formatErr)
		cov964aWantErr(t, cov964aManager(p).formatLUKSVolume(ctx, password), "LUKS format failed", formatErr)
		luksMock.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		p, luksMock := cov964aPlatform(t, nil, nil)
		var opts *luks.FormatOptions
		luksMock.On("Format", mock.Anything, p.Config.RootDevice, password, mock.Anything).
			Run(func(args mock.Arguments) { opts = args.Get(3).(*luks.FormatOptions) }).Return(nil)
		if err := cov964aManager(p).formatLUKSVolume(ctx, password); err != nil {
			t.Fatalf("formatLUKSVolume: %v", err)
		}
		if opts.Cipher != "aes-xts-plain64" || opts.KeySize != 512 || opts.HashAlgorithm != "sha256" ||
			opts.Label != "cryptroot" || opts.KDFType != fips.GetKDF() {
			t.Errorf("FormatOptions = %+v", opts)
		}
		luksMock.AssertExpectations(t)
	})
}

func TestCov964aInstallUnlockStrategies(t *testing.T) {
	ctx := context.Background()
	password := []byte("install-password")

	t.Run("TPM-NoPCR error is wrapped", func(t *testing.T) {
		sealErr := &cov964aError{op: "seal"}
		p, _ := cov964aPlatform(t, &cov964aTPM{sealErr: sealErr}, nil)
		err := cov964aManager(p).installUnlockStrategies(ctx, cov964aVolume(p), password)
		cov964aWantErr(t, err, "failed to install TPM-NoPCR strategy", sealErr)
	})

	t.Run("success seals and enrolls", func(t *testing.T) {
		tpm := &cov964aTPM{}
		p, luksMock := cov964aPlatform(t, tpm, nil)
		luksMock.On("AddKey", mock.Anything, p.Config.RootDevice, password, mock.Anything, mock.Anything).Return(nil)
		if err := cov964aManager(p).installUnlockStrategies(ctx, cov964aVolume(p), password); err != nil {
			t.Fatalf("installUnlockStrategies: %v", err)
		}
		if tpm.sealOpts == nil {
			t.Error("key was not sealed")
		}
		luksMock.AssertExpectations(t)
	})
}

func TestCov964aVerifyInstallation(t *testing.T) {
	ctx := context.Background()

	t.Run("Status error", func(t *testing.T) {
		statusErr := &cov964aError{op: "status"}
		p, luksMock := cov964aPlatform(t, nil, nil)
		luksMock.On("Status", mock.Anything, p.Config.RootDevice).Return(nil, statusErr)
		cov964aWantErr(t, cov964aManager(p).VerifyInstallation(ctx), "failed to get LUKS status", statusErr)
	})

	t.Run("LUKS1 rejected", func(t *testing.T) {
		p, luksMock := cov964aPlatform(t, nil, nil)
		luksMock.On("Status", mock.Anything, p.Config.RootDevice).Return(&luks.VolumeStatus{Version: luks.LUKS1}, nil)
		cov964aWantErr(t, cov964aManager(p).VerifyInstallation(ctx), "expected LUKS2, got 1", nil)
	})

	t.Run("LUKS2 accepted", func(t *testing.T) {
		p, luksMock := cov964aPlatform(t, nil, nil)
		luksMock.On("Status", mock.Anything, p.Config.RootDevice).Return(&luks.VolumeStatus{Version: luks.LUKS2}, nil)
		if err := cov964aManager(p).VerifyInstallation(ctx); err != nil {
			t.Errorf("VerifyInstallation = %v, want nil", err)
		}
	})
}

// TestCov964aInstallEarlyErrors covers Install only up to TPM.Install. The
// fake never lets TPM.Install succeed, because the next step partitions the
// root device with wipefs and parted.
func TestCov964aInstallEarlyErrors(t *testing.T) {
	ctx := context.Background()
	password := []byte("install-password")

	t.Run("invalid config", func(t *testing.T) {
		tpm := &cov964aTPM{installErr: &cov964aError{op: "install"}}
		p, _ := cov964aPlatform(t, tpm, nil)
		p.Config.PCRSelection = nil
		cov964aWantErr(t, cov964aManager(p).Install(ctx, password), "invalid configuration", ErrInvalidConfig)
		if tpm.installCalls != 0 {
			t.Error("TPM.Install called with an invalid config")
		}
	})

	t.Run("XKMSPath under a regular file", func(t *testing.T) {
		tpm := &cov964aTPM{installErr: &cov964aError{op: "install"}}
		p, _ := cov964aPlatform(t, tpm, nil)
		p.Config.XKMSPath = filepath.Join(cov964aRegularFile(t), "xkms")
		cov964aWantErr(t, cov964aManager(p).Install(ctx, password), "failed to create xkms directory", nil)
		if tpm.installCalls != 0 {
			t.Error("TPM.Install called without an xkms directory")
		}
	})

	t.Run("TPM nil", func(t *testing.T) {
		p, _ := cov964aPlatform(t, nil, nil)
		cov964aWantErr(t, cov964aManager(p).Install(ctx, password), "TPM not initialized", nil)
	})

	t.Run("TPM.Install error", func(t *testing.T) {
		installErr := &cov964aError{op: "install"}
		tpm := &cov964aTPM{installErr: installErr}
		p, _ := cov964aPlatform(t, tpm, nil)
		cov964aWantErr(t, cov964aManager(p).Install(ctx, password), "failed to initialize TPM", installErr)
		if tpm.installCalls != 1 {
			t.Errorf("TPM.Install calls = %d, want 1", tpm.installCalls)
		}
	})
}

// --- multidrive.go ---

func cov964aStorageConfig(partitions ...drive.PartitionConfig) *drive.StorageConfig {
	return &drive.StorageConfig{
		Drives: []drive.DriveConfig{{
			ID:         "system",
			Device:     "/dev/sda",
			Role:       drive.DriveRoleSystem,
			Partitions: partitions,
		}},
	}
}

func cov964aPartition(id string, number int, mountpoint, mapping string) drive.PartitionConfig {
	part := drive.PartitionConfig{ID: id, Number: number, Size: "10G"}
	if mountpoint != "" {
		part.Mount = &drive.MountConfig{Mountpoint: mountpoint}
	}
	if mapping != "" {
		part.Encryption = &drive.EncryptionConfig{Enabled: true, MappingName: mapping}
	}
	return part
}

func cov964aMultiDrive(t *testing.T, cfg *drive.StorageConfig, strategy UnlockStrategy) *MultiDriveManager {
	t.Helper()
	p, _ := cov964aPlatform(t, nil, nil)
	mgr, err := NewMultiDriveManager(p, cfg, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("NewMultiDriveManager: %v", err)
	}
	mgr.chain.SetMarkerPath(filepath.Join(t.TempDir(), "unlock-strategy"))
	if strategy != nil {
		mgr.RegisterStrategy(strategy)
	}
	return mgr
}

func TestCov964aUnlockAllVolumes(t *testing.T) {
	ctx := context.Background()

	t.Run("no encrypted partitions", func(t *testing.T) {
		strategy := &mockSuccessStrategy{mockStrategy: mockStrategy{name: "success", priority: 1}}
		mgr := cov964aMultiDrive(t, cov964aStorageConfig(cov964aPartition("root", 1, "/", "")), strategy)
		if err := mgr.UnlockAllVolumes(ctx); err != nil {
			t.Fatalf("UnlockAllVolumes: %v", err)
		}
		if strategy.unlockCalled {
			t.Error("strategy ran with no encrypted partitions")
		}
	})

	t.Run("encrypted root unlocks", func(t *testing.T) {
		strategy := &mockSuccessStrategy{mockStrategy: mockStrategy{name: "success", priority: 1}}
		mgr := cov964aMultiDrive(t, cov964aStorageConfig(
			cov964aPartition("root", 1, "/", "cov964a-nonexistent-root")), strategy)
		if err := mgr.UnlockAllVolumes(ctx); err != nil {
			t.Fatalf("UnlockAllVolumes: %v", err)
		}
		if !strategy.unlockCalled {
			t.Error("strategy did not unlock the encrypted root")
		}
	})

	t.Run("encrypted root fails", func(t *testing.T) {
		strategy := &mockFailStrategy{mockStrategy: mockStrategy{name: "fail", priority: 1}}
		mgr := cov964aMultiDrive(t, cov964aStorageConfig(
			cov964aPartition("root", 1, "/", "cov964a-nonexistent-root")), strategy)
		cov964aWantErr(t, mgr.UnlockAllVolumes(ctx), "failed to unlock root partition", ErrUnlockFailed)
	})

	t.Run("non-root failure is skipped", func(t *testing.T) {
		strategy := &mockFailStrategy{mockStrategy: mockStrategy{name: "fail", priority: 1}}
		mgr := cov964aMultiDrive(t, cov964aStorageConfig(
			cov964aPartition("root", 1, "/", ""),
			cov964aPartition("var", 2, "/var", "cov964a-nonexistent-var")), strategy)
		if err := mgr.UnlockAllVolumes(ctx); err != nil {
			t.Errorf("UnlockAllVolumes = %v, want nil when only a data partition fails", err)
		}
	})
}

func TestCov964aInstallAllVolumesNoEncryption(t *testing.T) {
	strategy := &mockSuccessStrategy{mockStrategy: mockStrategy{name: "success", priority: 1}}
	mgr := cov964aMultiDrive(t, cov964aStorageConfig(cov964aPartition("root", 1, "/", "")), strategy)
	if err := mgr.InstallAllVolumes(context.Background(), []byte("passphrase")); err != nil {
		t.Fatalf("InstallAllVolumes: %v", err)
	}
	if strategy.installCalled {
		t.Error("strategy installed with no encrypted partitions")
	}
}

func TestCov964aMountAndLockSkipLockedVolumes(t *testing.T) {
	ctx := context.Background()
	mgr := cov964aMultiDrive(t, cov964aStorageConfig(
		cov964aPartition("root", 1, "/", "cov964a-nonexistent-root"),
		cov964aPartition("var", 2, "/var", "cov964a-nonexistent-var"),
		cov964aPartition("swap", 3, "", "")), nil)

	if err := mgr.MountAllVolumes(ctx); err != nil {
		t.Errorf("MountAllVolumes = %v, want nil for volumes that are not unlocked", err)
	}
	if err := mgr.LockAllVolumes(ctx); err != nil {
		t.Errorf("LockAllVolumes = %v, want nil for volumes that are not unlocked", err)
	}
}

func TestCov964aUnmountAllVolumesSkipsPlainPartitions(t *testing.T) {
	mgr := cov964aMultiDrive(t, cov964aStorageConfig(
		cov964aPartition("root", 1, "/", ""),
		cov964aPartition("swap", 2, "", "")), nil)
	if err := mgr.UnmountAllVolumes(context.Background()); err != nil {
		t.Errorf("UnmountAllVolumes = %v, want nil", err)
	}
}
