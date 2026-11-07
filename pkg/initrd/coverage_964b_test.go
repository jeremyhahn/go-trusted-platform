// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package initrd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// cov964bError is the typed error the slice-b fakes inject.
type cov964bError string

func (e cov964bError) Error() string { return string(e) }

const (
	cov964bErrKeyAttrs     cov964bError = "cov964b: key attributes failed"
	cov964bErrSeal         cov964bError = "cov964b: seal failed"
	cov964bErrUnseal       cov964bError = "cov964b: unseal failed"
	cov964bErrSealMismatch cov964bError = "cov964b: sealed blobs do not match"
	cov964bErrRandom       cov964bError = "cov964b: random failed"
	cov964bErrExtended     cov964bError = "cov964b: pcr state unreadable"
	cov964bErrPolicy       cov964bError = "cov964b: platform policy failed"
	cov964bErrInfo         cov964bError = "cov964b: info failed"
	cov964bErrProps        cov964bError = "cov964b: fixed properties failed"
	cov964bErrEK           cov964bError = "cov964b: ek unavailable"
	cov964bErrSSRK         cov964bError = "cov964b: ssrk unavailable"
	cov964bErrReadPCRs     cov964bError = "cov964b: read pcrs failed"
	cov964bErrOpen         cov964bError = "cov964b: luks open failed"
	cov964bErrAddKey       cov964bError = "cov964b: luks add key failed"
)

// cov964bTPM fakes the TPM methods slice b reaches. Every other method
// panics on the nil embedded interface, which flags a test that strayed
// outside the slice.
type cov964bTPM struct {
	xkmssdk.TrustedPlatformModule

	config *xkmssdk.TPMConfig

	keyAttrsErr error
	sealErr     error
	unsealErr   error
	randomErr   error
	extendedErr error
	policyErr   error
	infoErr     error
	propsErr    error
	ekErr       error
	ssrkErr     error
	// readPCRsErrs[i] is returned by the i-th ReadPCRs call.
	readPCRsErrs []error

	extended    bool
	policyCalls int
	banks       []xkmssdk.PCRBank

	// What the fake received.
	keyAttrsHandles []xkmssdk.TPMHandle
	sealOpts        *xkmssdk.SealOptions
	unsealOpts      *xkmssdk.UnsealOptions
	unsealedData    *xkmssdk.SealedData
	readPCRsCalls   [][]uint

	// What Seal produced: Unseal releases sealedKey only for these blobs.
	sealedKey []byte
	sealed    *xkmssdk.SealedData
}

func (f *cov964bTPM) Config() *xkmssdk.TPMConfig { return f.config }

func (f *cov964bTPM) KeyAttributes(handle xkmssdk.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	f.keyAttrsHandles = append(f.keyAttrsHandles, handle)
	if f.keyAttrsErr != nil {
		return nil, f.keyAttrsErr
	}
	return &xkmssdk.KeyAttributes{CN: "cov964b-srk"}, nil
}

func (f *cov964bTPM) Seal(_ context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.sealOpts = opts
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	f.sealedKey = append([]byte(nil), data...)
	f.sealed = &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		TPMPublic:  []byte("cov964b-public"),
		TPMPrivate: []byte("cov964b-private"),
	}
	return f.sealed, nil
}

func (f *cov964bTPM) Unseal(_ context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	f.unsealOpts = opts
	f.unsealedData = sealed
	if f.unsealErr != nil {
		return nil, f.unsealErr
	}
	if f.sealed == nil || sealed == nil ||
		!bytes.Equal(sealed.TPMPublic, f.sealed.TPMPublic) ||
		!bytes.Equal(sealed.TPMPrivate, f.sealed.TPMPrivate) {
		return nil, cov964bErrSealMismatch
	}
	return append([]byte(nil), f.sealedKey...), nil
}

func (f *cov964bTPM) RandomBytes(n int) ([]byte, error) {
	if f.randomErr != nil {
		return nil, f.randomErr
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (f *cov964bTPM) IsPlatformPCRExtended() (bool, error) {
	if f.extendedErr != nil {
		return false, f.extendedErr
	}
	return f.extended, nil
}

func (f *cov964bTPM) CreatePlatformPolicy() error {
	f.policyCalls++
	if f.policyErr != nil {
		return f.policyErr
	}
	f.extended = true
	f.extendedErr = nil
	return nil
}

func (f *cov964bTPM) Info() (string, error) {
	if f.infoErr != nil {
		return "", f.infoErr
	}
	return "cov964b TPM info", nil
}

func (f *cov964bTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	if f.propsErr != nil {
		return nil, f.propsErr
	}
	return &xkmssdk.PropertiesFixed{Manufacturer: "cov964b-mfr", Model: "cov964b-model", FwMajor: 1, FwMinor: 2}, nil
}

func (f *cov964bTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if f.ekErr != nil {
		return nil, f.ekErr
	}
	return &xkmssdk.KeyAttributes{CN: "cov964b-ek", TPMAttributes: &xkmssdk.TPMAttributes{}}, nil
}

func (f *cov964bTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	if f.ssrkErr != nil {
		return nil, f.ssrkErr
	}
	return &xkmssdk.KeyAttributes{CN: "cov964b-ssrk", TPMAttributes: &xkmssdk.TPMAttributes{}}, nil
}

func (f *cov964bTPM) ReadPCRs(selection []uint) ([]xkmssdk.PCRBank, error) {
	call := len(f.readPCRsCalls)
	f.readPCRsCalls = append(f.readPCRsCalls, selection)
	if call < len(f.readPCRsErrs) && f.readPCRsErrs[call] != nil {
		return nil, f.readPCRsErrs[call]
	}
	return f.banks, nil
}

// cov964bBackend is an opaque key backend: slice b only passes it through
// to Seal and Unseal, so any method call panics on the nil interface.
type cov964bBackend struct {
	xkmssdk.TPMKeyBackend
}

// cov964bPlatform is createTestPlatform with the given TPM and a key backend.
func cov964bPlatform(tpm xkmssdk.TrustedPlatformModule) *Platform {
	p := createTestPlatform()
	p.TPM = tpm
	p.Backend = &cov964bBackend{}
	return p
}

// cov964bManager builds the manager directly so the chain starts empty and
// records its winner under t.TempDir(), never the default marker path.
func cov964bManager(t *testing.T, tpm xkmssdk.TrustedPlatformModule) *initrdManager {
	t.Helper()
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)
	chain.SetMarkerPath(filepath.Join(t.TempDir(), "unlock-strategy"))
	return &initrdManager{platform: cov964bPlatform(tpm), chain: chain, logger: logger}
}

func cov964bLUKS(t *testing.T, p *Platform) *MockLUKSHandler {
	t.Helper()
	m, ok := p.LUKS.(*MockLUKSHandler)
	if !ok {
		t.Fatalf("platform LUKS is %T, want *MockLUKSHandler", p.LUKS)
	}
	return m
}

func cov964bMessage(t *testing.T, err error, want string) {
	t.Helper()
	var msgErr *MessageError
	if !errors.As(err, &msgErr) || msgErr.Msg != want {
		t.Fatalf("err = %v, want *MessageError %q", err, want)
	}
}

func cov964bWrapped(t *testing.T, err error, msg string, cause error) {
	t.Helper()
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != msg {
		t.Fatalf("err = %v, want *WrappedError %q", err, msg)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to wrap %v", err, cause)
	}
}

func TestCov964bTPMConfigGetters(t *testing.T) {
	tests := []struct {
		name       string
		tpm        xkmssdk.TrustedPlatformModule
		wantPKSRK  xkmssdk.TPMHandle
		wantPolicy bool
		wantSSRK   xkmssdk.TPMHandle
	}{
		{"no TPM", nil, 0x81000002, true, 0x81000001},
		{"nil config", &cov964bTPM{}, 0x81000002, true, 0x81000001},
		{"no SRK sections", &cov964bTPM{config: &xkmssdk.TPMConfig{}}, 0x81000002, true, 0x81000001},
		{
			"zero handles keep the defaults, policy read as set",
			&cov964bTPM{config: &xkmssdk.TPMConfig{
				PlatformSRK: &xkmssdk.PlatformSRKConfig{PlatformPolicy: false},
				SSRK:        &xkmssdk.SRKConfig{},
			}},
			0x81000002, false, 0x81000001,
		},
		{
			"configured handles and policy",
			&cov964bTPM{config: &xkmssdk.TPMConfig{
				PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000010, PlatformPolicy: true},
				SSRK:        &xkmssdk.SRKConfig{Handle: 0x81000011},
			}},
			0x81000010, true, 0x81000011,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := cov964bPlatform(tt.tpm)
			pcr := NewTPMPCRStrategy(p, logging.DefaultLogger())
			upgrade := NewTPMUpgradeStrategy(p, logging.DefaultLogger())
			if got := pcr.getPlatformKeystoreSRKHandle(); got != tt.wantPKSRK {
				t.Errorf("getPlatformKeystoreSRKHandle = %#x, want %#x", got, tt.wantPKSRK)
			}
			if got := pcr.getPlatformPolicy(); got != tt.wantPolicy {
				t.Errorf("getPlatformPolicy = %v, want %v", got, tt.wantPolicy)
			}
			if got := upgrade.getSSRKHandle(); got != tt.wantSSRK {
				t.Errorf("getSSRKHandle = %#x, want %#x", got, tt.wantSSRK)
			}
		})
	}
}

func TestCov964bExtendPlatformPCR(t *testing.T) {
	t.Run("no TPM", func(t *testing.T) {
		s := NewTPMPCRStrategy(cov964bPlatform(nil), logging.DefaultLogger())
		cov964bMessage(t, s.extendPlatformPCR(context.Background()), "TPM not available for PCR extension")
	})

	tests := []struct {
		name         string
		tpm          *cov964bTPM
		wantErr      error
		wantPolicies int
	}{
		{"already extended", &cov964bTPM{extended: true}, nil, 0},
		{"state unreadable still extends", &cov964bTPM{extendedErr: cov964bErrExtended}, nil, 1},
		{"policy fails", &cov964bTPM{policyErr: cov964bErrPolicy}, cov964bErrPolicy, 1},
		{"extends", &cov964bTPM{}, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTPMPCRStrategy(cov964bPlatform(tt.tpm), logging.DefaultLogger())
			err := s.extendPlatformPCR(context.Background())
			if tt.wantErr != nil {
				cov964bWrapped(t, err, "failed to extend platform PCR", tt.wantErr)
			} else if err != nil {
				t.Fatalf("extendPlatformPCR: %v", err)
			}
			if tt.tpm.policyCalls != tt.wantPolicies {
				t.Errorf("CreatePlatformPolicy calls = %d, want %d", tt.tpm.policyCalls, tt.wantPolicies)
			}
			extended, readErr := tt.tpm.IsPlatformPCRExtended()
			if readErr != nil || extended != (tt.wantErr == nil) {
				t.Errorf("IsPlatformPCRExtended = %v, %v; want %v", extended, readErr, tt.wantErr == nil)
			}
		})
	}
}

func TestCov964bUnsealPlatformKeyStore(t *testing.T) {
	key := []byte("cov964b-luks-key")
	backend := &cov964bBackend{}

	// newTPM seals key once so the files below hold the blobs Unseal accepts.
	newTPM := func(t *testing.T) (*cov964bTPM, string, string) {
		t.Helper()
		tpm := &cov964bTPM{config: &xkmssdk.TPMConfig{
			PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000010, PlatformPolicy: false},
		}}
		sealed, err := tpm.Seal(context.Background(), key, &xkmssdk.SealOptions{})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		dir := t.TempDir()
		pub, priv := filepath.Join(dir, pcrPublicFile), filepath.Join(dir, pcrPrivateFile)
		if err := os.MkdirAll(filepath.Dir(pub), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(pub, sealed.TPMPublic, 0o600); err != nil {
			t.Fatalf("write pub: %v", err)
		}
		if err := os.WriteFile(priv, sealed.TPMPrivate, 0o600); err != nil {
			t.Fatalf("write priv: %v", err)
		}
		return tpm, pub, priv
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T, tpm *cov964bTPM, pub, priv string) (string, string)
		check   func(t *testing.T, err error)
	}{
		{
			name: "key attributes fail",
			prepare: func(_ *testing.T, tpm *cov964bTPM, pub, priv string) (string, string) {
				tpm.keyAttrsErr = cov964bErrKeyAttrs
				return pub, priv
			},
			check: func(t *testing.T, err error) {
				cov964bWrapped(t, err, "failed to get Platform KeyStore SRK attributes", cov964bErrKeyAttrs)
			},
		},
		{
			name: "public blob missing",
			prepare: func(_ *testing.T, _ *cov964bTPM, pub, priv string) (string, string) {
				return pub + ".missing", priv
			},
			check: func(t *testing.T, err error) {
				cov964bWrapped(t, err, "failed to read seal public", fs.ErrNotExist)
			},
		},
		{
			name: "private blob missing",
			prepare: func(_ *testing.T, _ *cov964bTPM, pub, priv string) (string, string) {
				return pub, priv + ".missing"
			},
			check: func(t *testing.T, err error) {
				cov964bWrapped(t, err, "failed to read seal private", fs.ErrNotExist)
			},
		},
		{
			name: "unseal fails",
			prepare: func(_ *testing.T, tpm *cov964bTPM, pub, priv string) (string, string) {
				tpm.unsealErr = cov964bErrUnseal
				return pub, priv
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, cov964bErrUnseal) {
					t.Fatalf("err = %v, want %v", err, cov964bErrUnseal)
				}
			},
		},
		{
			name: "tampered public blob is refused",
			prepare: func(t *testing.T, _ *cov964bTPM, pub, priv string) (string, string) {
				if err := os.WriteFile(pub, []byte("tampered"), 0o600); err != nil {
					t.Fatalf("write pub: %v", err)
				}
				return pub, priv
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, cov964bErrSealMismatch) {
					t.Fatalf("err = %v, want %v", err, cov964bErrSealMismatch)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm, pub, priv := newTPM(t)
			pub, priv = tt.prepare(t, tpm, pub, priv)
			s := NewTPMPCRStrategy(cov964bPlatform(tpm), logging.DefaultLogger())
			got, err := s.unsealPlatformKeyStore(context.Background(), pub, priv, backend)
			if got != nil {
				t.Errorf("key = %x, want nil on failure", got)
			}
			tt.check(t, err)
		})
	}

	t.Run("unseals with the platform keystore SRK", func(t *testing.T) {
		tpm, pub, priv := newTPM(t)
		s := NewTPMPCRStrategy(cov964bPlatform(tpm), logging.DefaultLogger())
		got, err := s.unsealPlatformKeyStore(context.Background(), pub, priv, backend)
		if err != nil {
			t.Fatalf("unsealPlatformKeyStore: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Errorf("key = %q, want %q", got, key)
		}
		if !reflect.DeepEqual(tpm.keyAttrsHandles, []xkmssdk.TPMHandle{0x81000010}) {
			t.Errorf("KeyAttributes handles = %v, want [0x81000010]", tpm.keyAttrsHandles)
		}
		attrs := tpm.unsealOpts.KeyAttributes
		if attrs.CN != "luks-root" || attrs.StoreType != xkmssdk.StoreSoftware || !attrs.PlatformPolicy {
			t.Errorf("unseal attrs = CN %q store %v policy %v; want luks-root, software, PCR-bound",
				attrs.CN, attrs.StoreType, attrs.PlatformPolicy)
		}
		if attrs.Parent == nil || attrs.Parent.CN != "cov964b-srk" || attrs.Parent.PlatformPolicy {
			t.Errorf("parent = %+v, want the SRK with the configured policy (false)", attrs.Parent)
		}
		if tpm.unsealedData.Backend != xkmssdk.BackendTypeTPM2 {
			t.Errorf("sealed data backend = %v, want %v", tpm.unsealedData.Backend, xkmssdk.BackendTypeTPM2)
		}
		if tpm.unsealOpts.Backend != backend {
			t.Errorf("unseal backend = %v, want the backend passed in", tpm.unsealOpts.Backend)
		}
	})
}

func TestCov964bUnlockLUKS(t *testing.T) {
	key := []byte("cov964b-key")
	volume := &luks.VolumeConfig{DevicePath: "/dev/cov964b", MappingName: "cryptroot", AllowDiscards: true, Timeout: 42}
	wantOpts := mock.MatchedBy(func(o *luks.OpenOptions) bool { return o.AllowDiscards && o.Timeout == 42 })

	tests := []struct {
		name    string
		openErr error
	}{
		{"opens", nil},
		{"open fails", cov964bErrOpen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := cov964bPlatform(&cov964bTPM{})
			lm := cov964bLUKS(t, p)
			lm.On("Open", mock.Anything, "/dev/cov964b", "cryptroot", key, wantOpts).Return(tt.openErr)

			err := NewTPMPCRStrategy(p, logging.DefaultLogger()).unlockLUKS(context.Background(), volume, key)
			if tt.openErr != nil {
				cov964bWrapped(t, err, "LUKS unlock failed", tt.openErr)
			} else if err != nil {
				t.Fatalf("unlockLUKS: %v", err)
			}
			lm.AssertExpectations(t)
		})
	}
}

func TestCov964bPCRInstall(t *testing.T) {
	password := []byte("cov964b-password")
	slots := func() []luks.KeySlot {
		return []luks.KeySlot{{Index: 0, Type: luks.UnlockPassword}, {Index: 3, Type: luks.UnlockTPMPCR}}
	}

	tests := []struct {
		name     string
		tpm      *cov964bTPM
		slots    []luks.KeySlot
		addErr   error
		wantMsg  string
		wantErr  error
		wantMsgE bool
	}{
		{name: "random fails", tpm: &cov964bTPM{randomErr: cov964bErrRandom}, slots: slots(),
			wantMsg: "failed to generate random key", wantErr: cov964bErrRandom},
		{name: "key attributes fail", tpm: &cov964bTPM{keyAttrsErr: cov964bErrKeyAttrs}, slots: slots(),
			wantMsg: "failed to get Platform KeyStore SRK attributes", wantErr: cov964bErrKeyAttrs},
		{name: "seal fails", tpm: &cov964bTPM{sealErr: cov964bErrSeal}, slots: slots(),
			wantMsg: "failed to seal key", wantErr: cov964bErrSeal},
		{name: "no TPM-PCR slot", tpm: &cov964bTPM{}, slots: []luks.KeySlot{{Index: 0, Type: luks.UnlockPassword}},
			wantMsg: "no TPM-PCR key slot configured", wantMsgE: true},
		{name: "add key fails", tpm: &cov964bTPM{}, slots: slots(), addErr: cov964bErrAddKey,
			wantMsg: "failed to add key to LUKS slot 3", wantErr: cov964bErrAddKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := cov964bPlatform(tt.tpm)
			lm := cov964bLUKS(t, p)
			if tt.addErr != nil {
				lm.On("AddKey", mock.Anything, "/dev/cov964b", password, mock.Anything, mock.Anything).Return(tt.addErr)
			}
			volume := &luks.VolumeConfig{DevicePath: "/dev/cov964b", MappingName: "cryptroot", KeySlots: tt.slots}

			err := NewTPMPCRStrategy(p, logging.DefaultLogger()).Install(context.Background(), volume, password)
			if tt.wantMsgE {
				cov964bMessage(t, err, tt.wantMsg)
			} else {
				cov964bWrapped(t, err, tt.wantMsg, tt.wantErr)
			}
			for _, slot := range volume.KeySlots {
				if slot.Attrs != nil || slot.SealedData != nil {
					t.Errorf("slot %d carries seal data after a failed install", slot.Index)
				}
			}
			lm.AssertExpectations(t)
		})
	}

	t.Run("installs the sealed key in the TPM-PCR slot", func(t *testing.T) {
		tpm := &cov964bTPM{}
		p := cov964bPlatform(tpm)
		lm := cov964bLUKS(t, p)
		lm.On("AddKey", mock.Anything, "/dev/cov964b", password, mock.Anything, mock.Anything).Return(nil)
		volume := &luks.VolumeConfig{DevicePath: "/dev/cov964b", MappingName: "cryptroot", KeySlots: slots()}

		if err := NewTPMPCRStrategy(p, logging.DefaultLogger()).Install(context.Background(), volume, password); err != nil {
			t.Fatalf("Install: %v", err)
		}

		attrs := tpm.sealOpts.KeyAttributes
		if attrs.CN != "luks-root-platform-cryptroot" || !attrs.PlatformPolicy {
			t.Errorf("seal attrs = CN %q policy %v; want luks-root-platform-cryptroot, PCR-bound", attrs.CN, attrs.PlatformPolicy)
		}
		if tpm.sealOpts.Backend != p.Backend {
			t.Errorf("seal backend = %v, want the platform backend", tpm.sealOpts.Backend)
		}
		if len(tpm.sealedKey) != 32 {
			t.Errorf("sealed key is %d bytes, want 32", len(tpm.sealedKey))
		}

		args := lm.Calls[0].Arguments
		if added := args.Get(3).([]byte); !bytes.Equal(added, tpm.sealedKey) {
			t.Errorf("LUKS got key %x, want the sealed key", added)
		}
		if opts := args.Get(4).(*luks.AddKeyOptions); opts.KeySlot == nil || *opts.KeySlot != 3 {
			t.Errorf("AddKey slot = %v, want 3", opts.KeySlot)
		}

		slot := volume.KeySlots[1]
		if slot.Attrs != attrs || slot.SealedData != tpm.sealed {
			t.Errorf("slot 3 = attrs %p sealed %p; want the sealed attrs and data", slot.Attrs, slot.SealedData)
		}
		if volume.KeySlots[0].Attrs != nil {
			t.Error("password slot was given seal data")
		}
		unsealed, err := tpm.Unseal(context.Background(), slot.SealedData, &xkmssdk.UnsealOptions{KeyAttributes: attrs})
		if err != nil || !bytes.Equal(unsealed, tpm.sealedKey) {
			t.Errorf("stored seal unseals to %x, %v; want the LUKS key", unsealed, err)
		}
	})
}

func TestCov964bDeleteInsecureUpgradeSealsWithoutSeals(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, pcrPublicFile)
	if err := os.MkdirAll(filepath.Dir(keep), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(keep, []byte("platform seal"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	NewTPMPCRStrategy(cov964bPlatform(&cov964bTPM{}), logging.DefaultLogger()).deleteInsecureUpgradeSeals(dir)

	entries, err := os.ReadDir(filepath.Dir(keep))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(keep) {
		t.Errorf("dir entries = %v, want only %s", entries, filepath.Base(keep))
	}
	if got, err := os.ReadFile(keep); err != nil || string(got) != "platform seal" {
		t.Errorf("platform seal = %q, %v; want it untouched", got, err)
	}
}

func TestCov964bCreateUpgradeSealEmptyKey(t *testing.T) {
	for _, key := range [][]byte{nil, {}} {
		tpm := &cov964bTPM{}
		err := NewTPMUpgradeStrategy(cov964bPlatform(tpm), logging.DefaultLogger()).CreateUpgradeSeal(key)
		cov964bMessage(t, err, "key cannot be empty")
		if tpm.sealOpts != nil {
			t.Error("an empty key reached Seal")
		}
	}
}

func TestCov964bInitializePlatform(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *Platform)
		wantMsg string
	}{
		{"no TPM", func(p *Platform) { p.TPM = nil }, "TPM not initialized"},
		{"no LUKS", func(p *Platform) { p.LUKS = nil }, "LUKS handler not initialized"},
		{"no XKMS or backend", func(p *Platform) { p.Backend = nil }, "neither xkms nor backend initialized"},
		{"minimal boot without FIDO2", func(p *Platform) { p.FIDO2 = nil }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := cov964bManager(t, &cov964bTPM{})
			tt.mutate(m.platform)
			err := m.initializePlatform(context.Background())
			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("initializePlatform: %v", err)
				}
				return
			}
			cov964bMessage(t, err, tt.wantMsg)
		})
	}
}

func TestCov964bBoot(t *testing.T) {
	t.Run("platform not initialized", func(t *testing.T) {
		m := cov964bManager(t, nil)
		err := m.Boot(context.Background())
		cov964bWrapped(t, err, "failed to initialize platform", nil)
		cov964bMessage(t, errors.Unwrap(err), "TPM not initialized")
	})

	for name, audit := range map[string]bool{"unlocks, audit log on": true, "unlocks, audit log off": false} {
		t.Run(name, func(t *testing.T) {
			m := cov964bManager(t, &cov964bTPM{})
			m.platform.Config.EnableAuditLog = audit
			ok := &mockSuccessStrategy{mockStrategy: mockStrategy{name: "cov964b-ok", priority: 2}}
			m.chain.Add(&mockFailStrategy{mockStrategy: mockStrategy{name: "cov964b-fail", priority: 1}})
			m.chain.Add(ok)

			if err := m.Boot(context.Background()); err != nil {
				t.Fatalf("Boot (audit %v): %v", audit, err)
			}
			if !ok.unlockCalled || m.UnlockedWith() != "cov964b-ok" {
				t.Errorf("unlockCalled %v, UnlockedWith %q; want true, cov964b-ok", ok.unlockCalled, m.UnlockedWith())
			}
			if got, err := os.ReadFile(m.chain.markerPath); err != nil || string(got) != "cov964b-ok\n" {
				t.Errorf("winner marker = %q, %v; want cov964b-ok", got, err)
			}
		})
	}

	t.Run("every strategy fails", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		m.chain.Add(&mockFailStrategy{mockStrategy: mockStrategy{name: "cov964b-fail", priority: 1}})
		err := m.Boot(context.Background())
		cov964bWrapped(t, err, "failed to unlock volume", ErrUnlockFailed)
		if m.UnlockedWith() != "" {
			t.Errorf("UnlockedWith = %q after a failed boot", m.UnlockedWith())
		}
		if _, statErr := os.Stat(m.chain.markerPath); !errors.Is(statErr, fs.ErrNotExist) {
			t.Errorf("winner marker written after a failed boot: %v", statErr)
		}
	})
}

func TestCov964bRecovery(t *testing.T) {
	t.Run("platform not initialized", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		m.platform.LUKS = nil
		err := m.Recovery(context.Background())
		cov964bWrapped(t, err, "failed to initialize platform", nil)
	})

	t.Run("unlocks", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		ok := &mockSuccessStrategy{mockStrategy: mockStrategy{name: "cov964b-ok", priority: 1}}
		m.chain.Add(ok)
		var err error
		out := captureStdout(t, func() { err = m.Recovery(context.Background()) })
		if err != nil {
			t.Fatalf("Recovery: %v", err)
		}
		if !ok.unlockCalled || !strings.Contains(out, "1. cov964b-ok") {
			t.Errorf("unlockCalled %v; menu %q should list the strategy", ok.unlockCalled, out)
		}
	})

	t.Run("every strategy fails", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		m.chain.Add(&mockFailStrategy{mockStrategy: mockStrategy{name: "cov964b-fail", priority: 1}})
		var err error
		captureStdout(t, func() { err = m.Recovery(context.Background()) })
		if !errors.Is(err, ErrRecoveryFailed) || !errors.Is(err, ErrUnlockFailed) {
			t.Fatalf("err = %v, want ErrRecoveryFailed caused by ErrUnlockFailed", err)
		}
	})
}

func TestCov964bShowTPMDiagnostics(t *testing.T) {
	t.Run("info fails", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{infoErr: cov964bErrInfo})
		var err error
		captureStdout(t, func() { err = m.showTPMDiagnostics(context.Background()) })
		cov964bWrapped(t, err, "failed to get TPM info", cov964bErrInfo)
	})

	t.Run("prints every section", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		var err error
		out := captureStdout(t, func() { err = m.showTPMDiagnostics(context.Background()) })
		if err != nil {
			t.Fatalf("showTPMDiagnostics: %v", err)
		}
		for _, want := range []string{
			"cov964b TPM info", "Manufacturer: cov964b-mfr", "Model: cov964b-model",
			"Firmware Version: 1.2", "CN: cov964b-ek", "CN: cov964b-ssrk",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("optional sections unavailable", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{propsErr: cov964bErrProps, ekErr: cov964bErrEK, ssrkErr: cov964bErrSSRK})
		var err error
		out := captureStdout(t, func() { err = m.showTPMDiagnostics(context.Background()) })
		if err != nil {
			t.Fatalf("showTPMDiagnostics: %v", err)
		}
		if !strings.Contains(out, "SRK not available: "+string(cov964bErrSSRK)) {
			t.Errorf("output lacks the SRK error:\n%s", out)
		}
		for _, absent := range []string{"Manufacturer:", "Endorsement Key Information", "Storage Root Key Information"} {
			if strings.Contains(out, absent) {
				t.Errorf("output prints %q for an unavailable section", absent)
			}
		}
	})
}

func TestCov964bShowPCRComparison(t *testing.T) {
	banks := []xkmssdk.PCRBank{
		{Algorithm: "SHA256", PCRs: []xkmssdk.PCR{{ID: 7, Value: []byte{0xab, 0xcd}}}},
		{Algorithm: "SHA1", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte{0x01}}}},
	}

	t.Run("read fails", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{readPCRsErrs: []error{cov964bErrReadPCRs}})
		var err error
		captureStdout(t, func() { err = m.showPCRComparison(context.Background()) })
		cov964bWrapped(t, err, "failed to read PCR values", cov964bErrReadPCRs)
	})

	tests := []struct {
		name        string
		upgrade     []uint
		errs        []error
		wantCalls   int
		wantUpgrade bool
	}{
		{"boot selection only", nil, nil, 1, false},
		{"upgrade selection", []uint{7}, nil, 2, true},
		{"upgrade selection unreadable", []uint{7}, []error{nil, cov964bErrReadPCRs}, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := &cov964bTPM{banks: banks, readPCRsErrs: tt.errs}
			m := cov964bManager(t, tpm)
			m.platform.Config.UpgradePCRSelection = tt.upgrade
			var err error
			out := captureStdout(t, func() { err = m.showPCRComparison(context.Background()) })
			if err != nil {
				t.Fatalf("showPCRComparison: %v", err)
			}
			for _, want := range []string{"Bank: SHA256", "PCR[07]: abcd", "Bank: SHA1", "PCR[00]: 01"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if len(tpm.readPCRsCalls) != tt.wantCalls ||
				!reflect.DeepEqual(tpm.readPCRsCalls[0], m.platform.Config.PCRSelection) {
				t.Fatalf("ReadPCRs calls = %v, want %d starting with %v", tpm.readPCRsCalls, tt.wantCalls, m.platform.Config.PCRSelection)
			}
			if tt.wantCalls == 2 && !reflect.DeepEqual(tpm.readPCRsCalls[1], tt.upgrade) {
				t.Errorf("upgrade ReadPCRs = %v, want %v", tpm.readPCRsCalls[1], tt.upgrade)
			}
			if got := strings.Contains(out, "Upgrade PCR Values (relaxed set):"); got != tt.wantUpgrade {
				t.Errorf("upgrade section printed = %v, want %v", got, tt.wantUpgrade)
			}
		})
	}
}

func TestCov964bResealKeysInteractive(t *testing.T) {
	t.Run("confirmed reseal fails", func(t *testing.T) {
		tpm := &cov964bTPM{readPCRsErrs: []error{cov964bErrReadPCRs}}
		m := cov964bManager(t, tpm)
		var err error
		withStdin(t, "y\n", func() {
			captureStdout(t, func() { err = m.resealKeysInteractive(context.Background()) })
		})
		cov964bWrapped(t, err, "reseal failed", cov964bErrReadPCRs)
		if len(tpm.readPCRsCalls) != 1 {
			t.Errorf("ReadPCRs calls = %d, want 1", len(tpm.readPCRsCalls))
		}
	})

	t.Run("no confirmation", func(t *testing.T) {
		tpm := &cov964bTPM{}
		m := cov964bManager(t, tpm)
		var err error
		withStdin(t, "", func() {
			captureStdout(t, func() { err = m.resealKeysInteractive(context.Background()) })
		})
		cov964bWrapped(t, err, "failed to read confirmation", io.EOF)
		if len(tpm.readPCRsCalls) != 0 {
			t.Error("reseal ran without a confirmation")
		}
	})
}

func TestCov964bInteractiveRecovery(t *testing.T) {
	t.Run("platform not initialized", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		m.platform.Backend = nil
		err := m.InteractiveRecovery(context.Background())
		cov964bWrapped(t, err, "failed to initialize platform", nil)
		cov964bMessage(t, errors.Unwrap(err), "neither xkms nor backend initialized")
	})

	t.Run("exit choice", func(t *testing.T) {
		m := cov964bManager(t, &cov964bTPM{})
		var err error
		var out string
		// Exactly one line: each prompt builds its own bufio.Reader on stdin.
		withStdin(t, "0\n", func() {
			out = captureStdout(t, func() { err = m.InteractiveRecovery(context.Background()) })
		})
		if err != nil {
			t.Fatalf("InteractiveRecovery: %v", err)
		}
		if !strings.Contains(out, "INTERACTIVE RECOVERY MODE") || !strings.Contains(out, "Exiting recovery mode") {
			t.Errorf("output lacks the menu or the exit:\n%s", out)
		}
	})
}
