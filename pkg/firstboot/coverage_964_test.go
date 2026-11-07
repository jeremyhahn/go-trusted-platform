package firstboot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// errFakeTPM is the failure the fake TPM returns when a test arms it.
var errFakeTPM = errors.New("fake tpm failure")

// fakeTPM implements the methods of the SDK TrustedPlatformModule that the
// firstboot seal paths call. The embedded interface is nil, so a call to any
// other method panics and shows the test reached code it did not expect.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	cfg *xkmssdk.TPMConfig

	keyAttrsErr error
	sealErr     error
	readPCRsErr error
	closeErr    error
	resetErr    error

	keyAttrsHandles []xkmssdk.TPMHandle
	sealOpts        *xkmssdk.SealOptions
	sealedKey       []byte
	resetCalls      int
	resetClearCalls int
}

func (f *fakeTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *fakeTPM) KeyAttributes(handle xkmssdk.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	f.keyAttrsHandles = append(f.keyAttrsHandles, handle)
	if f.keyAttrsErr != nil {
		return nil, f.keyAttrsErr
	}
	return &xkmssdk.KeyAttributes{CN: "parent", PlatformPolicy: true}, nil
}

func (f *fakeTPM) Seal(_ context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.sealOpts = opts
	f.sealedKey = data
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return &xkmssdk.SealedData{TPMPublic: []byte("pub"), TPMPrivate: []byte("priv")}, nil
}

func (f *fakeTPM) ReadPCRs(_ []uint) ([]xkmssdk.PCRBank, error) {
	return nil, f.readPCRsErr
}

func (f *fakeTPM) Close() error { return f.closeErr }

func (f *fakeTPM) FactoryReset(_ []byte) error {
	f.resetCalls++
	return f.resetErr
}

func (f *fakeTPM) FactoryResetWithClear(_ []byte) error {
	f.resetClearCalls++
	return f.resetErr
}

// fullTPMConfig is a TPM config with every handle the seal paths read set to
// a non-default value, so a test can tell a configured value from a default.
func fullTPMConfig() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		PlatformPCR:     23,
		PlatformPCRBank: "sha256",
		GoldenPCRs:      []uint{0, 7},
		PlatformSRK:     &xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000010, PlatformPolicy: false},
		SSRK:            &xkmssdk.SRKConfig{Handle: 0x81000011},
	}
}

func newFakeExecutor(tpm *fakeTPM, cfg *Config) *Executor {
	e := &Executor{logger: testLogger(), config: cfg}
	if tpm != nil {
		e.tpm = tpm
	}
	return e
}

func TestErrorTypes_MessagesAndUnwrap(t *testing.T) {
	cause := errors.New("cause")
	sentinel := errors.New("sentinel")

	tests := []struct {
		name    string
		err     error
		wantMsg string
		wantIs  []error
	}{
		{"message", &MessageError{Msg: "plain"}, "plain", nil},
		{"wrapped", &WrappedError{Msg: "outer", Err: cause}, "outer: cause", []error{cause}},
		{"command output", &CommandOutputError{Msg: "cmd", Err: cause, Detail: " (stderr)"}, "cmd: cause (stderr)", []error{cause}},
		{"sentinel cause", &SentinelCauseError{Sentinel: sentinel, Cause: cause}, "sentinel: cause", []error{sentinel, cause}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
			for _, target := range tt.wantIs {
				if !errors.Is(tt.err, target) {
					t.Errorf("errors.Is(%v, %v) = false", tt.err, target)
				}
			}
		})
	}
}

func TestExecutor_HandleGetters(t *testing.T) {
	tests := []struct {
		name         string
		tpm          *fakeTPM
		wantSRK      xkmssdk.TPMHandle
		wantSSRK     xkmssdk.TPMHandle
		wantPolicy   bool
		wantStratSRK uint32
	}{
		{"no tpm uses defaults", nil, 0x81000002, 0x81000001, true, 0x81000002},
		{"nil config uses defaults", &fakeTPM{}, 0x81000002, 0x81000001, true, 0x81000002},
		{"zero handles use defaults", &fakeTPM{cfg: &xkmssdk.TPMConfig{
			PlatformSRK: &xkmssdk.PlatformSRKConfig{PlatformPolicy: false},
			SSRK:        &xkmssdk.SRKConfig{},
		}}, 0x81000002, 0x81000001, false, 0x81000002},
		{"configured handles win", &fakeTPM{cfg: fullTPMConfig()}, 0x81000010, 0x81000011, false, 0x81000010},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFakeExecutor(tt.tpm, DefaultConfig())
			s := NewFirstbootSealStrategy(e, nil, testLogger())

			if got := e.getPlatformKeystoreSRKHandle(); got != tt.wantSRK {
				t.Errorf("executor SRK handle = 0x%x, want 0x%x", got, tt.wantSRK)
			}
			if got := e.getSSRKHandle(); got != tt.wantSSRK {
				t.Errorf("executor SSRK handle = 0x%x, want 0x%x", got, tt.wantSSRK)
			}
			if got := e.getPlatformPolicy(); got != tt.wantPolicy {
				t.Errorf("executor platform policy = %v, want %v", got, tt.wantPolicy)
			}
			if got := s.getPlatformKeystoreSRKHandle(); got != tt.wantStratSRK {
				t.Errorf("strategy SRK handle = 0x%x, want 0x%x", got, tt.wantStratSRK)
			}
			if got := s.getSSRKHandle(); got != uint32(tt.wantSSRK) {
				t.Errorf("strategy SSRK handle = 0x%x, want 0x%x", got, tt.wantSSRK)
			}
			if got := s.getPlatformPolicy(); got != tt.wantPolicy {
				t.Errorf("strategy platform policy = %v, want %v", got, tt.wantPolicy)
			}
			// Without an installer config the LUKS seal parent is the
			// Platform KeyStore SRK.
			if got := s.getLUKSSealParentHandle(); got != tt.wantStratSRK {
				t.Errorf("LUKS seal parent = 0x%x, want 0x%x", got, tt.wantStratSRK)
			}
		})
	}
}

func TestExecutor_CloseAndBackend(t *testing.T) {
	e := newFakeExecutor(&fakeTPM{closeErr: errFakeTPM}, DefaultConfig())
	if err := e.Close(); !errors.Is(err, errFakeTPM) {
		t.Errorf("Close() = %v, want the TPM close error", err)
	}
	if e.Backend() != nil {
		t.Error("Backend() should return the unset backend as nil")
	}

	e = newFakeExecutor(&fakeTPM{}, DefaultConfig())
	if err := e.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	e.flushTPMContext()
}

// sealFunc is the shape shared by the three executor seal constructors.
type sealFunc func(e *Executor, ctx context.Context, key []byte) ([]byte, []byte, error)

func TestExecutor_CreateSealedObjects(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	constructors := []struct {
		name          string
		seal          sealFunc
		wantHandle    xkmssdk.TPMHandle
		parentErr     error
		wantCN        string
		wantObjPolicy bool
	}{
		{"pcr seal", func(e *Executor, ctx context.Context, k []byte) ([]byte, []byte, error) {
			return e.createPCRSealedObjects(ctx, k, []uint{7})
		}, 0x81000011, ErrSSRKNotAccessible, "luks-root-pcr", true},
		{"upgrade seal", (*Executor).createSealedObjects, 0x81000011, ErrSSRKNotAccessible, "luks-upgrade-seal", false},
		{"platform keystore seal", (*Executor).createPlatformKeystoreSealedObjects, 0x81000010, ErrPlatformSRKNotAccessible, "", true},
	}

	for _, c := range constructors {
		t.Run(c.name+"/no tpm", func(t *testing.T) {
			_, _, err := c.seal(newFakeExecutor(nil, DefaultConfig()), context.Background(), key)
			if !errors.Is(err, ErrTPMNotAvailable) {
				t.Errorf("err = %v, want ErrTPMNotAvailable", err)
			}
		})
		t.Run(c.name+"/parent unavailable", func(t *testing.T) {
			tpm := &fakeTPM{cfg: fullTPMConfig(), keyAttrsErr: errFakeTPM}
			_, _, err := c.seal(newFakeExecutor(tpm, DefaultConfig()), context.Background(), key)
			if !errors.Is(err, c.parentErr) {
				t.Errorf("err = %v, want %v", err, c.parentErr)
			}
			if tpm.sealOpts != nil {
				t.Error("Seal must not run when the parent is unavailable")
			}
		})
		t.Run(c.name+"/seal fails", func(t *testing.T) {
			tpm := &fakeTPM{cfg: fullTPMConfig(), sealErr: errFakeTPM}
			_, _, err := c.seal(newFakeExecutor(tpm, DefaultConfig()), context.Background(), key)
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || !errors.Is(err, errFakeTPM) {
				t.Errorf("err = %v, want a WrappedError around the seal failure", err)
			}
		})
		t.Run(c.name+"/success", func(t *testing.T) {
			tpm := &fakeTPM{cfg: fullTPMConfig()}
			pub, priv, err := c.seal(newFakeExecutor(tpm, DefaultConfig()), context.Background(), key)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if string(pub) != "pub" || string(priv) != "priv" {
				t.Errorf("blobs = %q/%q, want the TPM's pub/priv", pub, priv)
			}
			if len(tpm.keyAttrsHandles) != 1 || tpm.keyAttrsHandles[0] != c.wantHandle {
				t.Errorf("parent handles = %v, want [0x%x]", tpm.keyAttrsHandles, c.wantHandle)
			}
			attrs := tpm.sealOpts.KeyAttributes
			if c.wantCN != "" && attrs.CN != c.wantCN {
				t.Errorf("sealed object CN = %q, want %q", attrs.CN, c.wantCN)
			}
			if attrs.PlatformPolicy != c.wantObjPolicy {
				t.Errorf("sealed object platform policy = %v, want %v", attrs.PlatformPolicy, c.wantObjPolicy)
			}
			if string(tpm.sealedKey) != string(key) {
				t.Error("the key handed to Seal is not the caller's key")
			}
		})
	}
}

func TestExecutor_CreatePlatformKeystoreSealedObjects_ParentPolicyFromConfig(t *testing.T) {
	tpm := &fakeTPM{cfg: fullTPMConfig()}
	e := newFakeExecutor(tpm, DefaultConfig())
	if _, _, err := e.createPlatformKeystoreSealedObjects(context.Background(), []byte("k")); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The fake returns a parent with PlatformPolicy=true; the configured
	// platform-srk policy (false) must override it.
	if tpm.sealOpts.KeyAttributes.Parent.PlatformPolicy {
		t.Error("parent platform policy should follow tpm.platform-srk.platform-policy (false)")
	}
}

func TestExecutor_WritePCRBanks_RefusesIncompleteConfig(t *testing.T) {
	noSSRK := fullTPMConfig()
	noSSRK.SSRK = nil
	noSRK := fullTPMConfig()
	noSRK.PlatformSRK = nil

	tests := []struct {
		name    string
		tpm     *fakeTPM
		pcrs    []uint
		wantMsg string
	}{
		{"no pcrs", &fakeTPM{cfg: fullTPMConfig()}, nil, "seal-pcrs not configured"},
		{"no tpm", nil, []uint{7}, "TPM not initialized"},
		{"no config", &fakeTPM{}, []uint{7}, "TPM config not loaded"},
		{"no platform srk", &fakeTPM{cfg: noSRK}, []uint{7}, "PlatformSRK config not set"},
		{"no ssrk", &fakeTPM{cfg: noSSRK}, []uint{7}, "SSRK config not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newFakeExecutor(tt.tpm, DefaultConfig()).writePCRBanks(tt.pcrs)
			var msgErr *MessageError
			if !errors.As(err, &msgErr) || !strings.Contains(msgErr.Msg, tt.wantMsg) {
				t.Errorf("err = %v, want a MessageError containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestExecutor_SavePCRValues_Errors(t *testing.T) {
	if err := newFakeExecutor(nil, DefaultConfig()).savePCRValues([]uint{7}); !errors.Is(err, ErrTPMNotAvailable) {
		t.Errorf("no tpm: err = %v, want ErrTPMNotAvailable", err)
	}
	tpm := &fakeTPM{readPCRsErr: errFakeTPM}
	if err := newFakeExecutor(tpm, DefaultConfig()).savePCRValues([]uint{7}); !errors.Is(err, errFakeTPM) {
		t.Errorf("read failure: err = %v, want the ReadPCRs error", err)
	}
}

func TestExecutor_ReadKeyFromUpgradeSeals_NoTPM(t *testing.T) {
	key, err := newFakeExecutor(nil, DefaultConfig()).readKeyFromUpgradeSeals(context.Background())
	if !errors.Is(err, ErrTPMNotAvailable) || key != nil {
		t.Errorf("got (%v, %v), want (nil, ErrTPMNotAvailable)", key, err)
	}
}

// newSealEFIDir returns an EFI mount point with the tpm2 directory sealing
// writes into, holding stale upgrade seals that a successful seal deletes.
func newSealEFIDir(t *testing.T) string {
	t.Helper()
	efi := t.TempDir()
	if err := os.MkdirAll(filepath.Join(efi, "tpm2"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strategyUpgradePub, strategyUpgradePriv} {
		if err := os.WriteFile(filepath.Join(efi, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return efi
}

func TestFirstbootSealStrategy_SealKeyToTPM_Success(t *testing.T) {
	efi := newSealEFIDir(t)
	tpm := &fakeTPM{cfg: fullTPMConfig()}
	s := NewFirstbootSealStrategy(newFakeExecutor(tpm, &Config{PCRSelection: []uint{0, 7}}), nil, testLogger())

	if err := s.sealKeyToTPM(context.Background(), []byte("key"), efi); err != nil {
		t.Fatalf("sealKeyToTPM: %v", err)
	}

	for name, want := range map[string]string{strategySealPub: "pub", strategySealPriv: "priv"} {
		got, err := os.ReadFile(filepath.Join(efi, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q (%v), want %q", name, got, err, want)
		}
	}
	banks, err := os.ReadFile(filepath.Join(efi, strategyPCRBanks))
	if err != nil {
		t.Fatalf("read pcr-banks: %v", err)
	}
	for _, line := range []string{
		"seal-pcrs=0,7", "platform-pcr=23", "platform-pcr-bank=sha256", "golden-pcrs=0,7",
		"keystore-srk-handle=0x81000010", "keystore-platform-policy=false", "ssrk-handle=0x81000011",
	} {
		if !strings.Contains(string(banks), line+"\n") {
			t.Errorf("pcr-banks missing %q:\n%s", line, banks)
		}
	}
	for _, name := range []string{strategyUpgradePub, strategyUpgradePriv} {
		if _, err := os.Stat(filepath.Join(efi, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should be deleted after sealing, stat err = %v", name, err)
		}
	}
	attrs := tpm.sealOpts.KeyAttributes
	if attrs.CN != "luks-root" || !attrs.PlatformPolicy {
		t.Errorf("sealed object = %q policy=%v, want luks-root bound to the PCR policy", attrs.CN, attrs.PlatformPolicy)
	}
	if attrs.Parent.PlatformPolicy {
		t.Error("parent policy should follow the configured platform-srk policy (false)")
	}
}

func TestFirstbootSealStrategy_SealKeyToTPM_Errors(t *testing.T) {
	withPCRs := &Config{PCRSelection: []uint{7}}
	tests := []struct {
		name     string
		tpm      *fakeTPM
		cfg      *Config
		noTPMDir bool
		wantIs   error
		wantMsg  string
	}{
		{name: "no tpm", cfg: withPCRs, wantIs: ErrTPMNotAvailable},
		{name: "parent unavailable", tpm: &fakeTPM{cfg: fullTPMConfig(), keyAttrsErr: errFakeTPM}, cfg: withPCRs, wantIs: errFakeTPM, wantMsg: "seal parent key not available at 0x81000010"},
		{name: "no pcr selection", tpm: &fakeTPM{cfg: fullTPMConfig()}, cfg: &Config{}, wantMsg: "seal-pcrs not configured"},
		{name: "seal fails", tpm: &fakeTPM{cfg: fullTPMConfig(), sealErr: errFakeTPM}, cfg: withPCRs, wantIs: errFakeTPM, wantMsg: "failed to seal key"},
		{name: "efi not writable", tpm: &fakeTPM{cfg: fullTPMConfig()}, cfg: withPCRs, noTPMDir: true, wantMsg: "failed to write seal-platform.pub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			efi := newSealEFIDir(t)
			if tt.noTPMDir {
				efi = filepath.Join(t.TempDir(), "missing")
			}
			s := NewFirstbootSealStrategy(newFakeExecutor(tt.tpm, tt.cfg), nil, testLogger())
			err := s.sealKeyToTPM(context.Background(), []byte("key"), efi)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("err = %v, want errors.Is %v", err, tt.wantIs)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want it to contain %q", err, tt.wantMsg)
			}
			if !tt.noTPMDir {
				if _, statErr := os.Stat(filepath.Join(efi, strategySealPub)); !errors.Is(statErr, os.ErrNotExist) {
					t.Error("no seal blob may be written when sealing fails")
				}
			}
		})
	}
}

func TestFirstbootSealStrategy_EnsurePlatformSRK_Errors(t *testing.T) {
	s := NewFirstbootSealStrategy(newFakeExecutor(nil, DefaultConfig()), nil, testLogger())
	if err := s.ensurePlatformSRK(); !errors.Is(err, ErrTPMNotAvailable) {
		t.Errorf("no tpm: err = %v, want ErrTPMNotAvailable", err)
	}

	for _, cfg := range []*xkmssdk.TPMConfig{nil, {}} {
		s = NewFirstbootSealStrategy(newFakeExecutor(&fakeTPM{cfg: cfg}, DefaultConfig()), nil, testLogger())
		var msgErr *MessageError
		if err := s.ensurePlatformSRK(); !errors.As(err, &msgErr) {
			t.Errorf("config %v: err = %v, want a MessageError for the missing platform-srk", cfg, err)
		}
	}
}

func TestFirstbootSealStrategy_EvictStaleHandles(t *testing.T) {
	for _, resetErr := range []error{nil, errFakeTPM} {
		tpm := &fakeTPM{resetErr: resetErr}
		s := NewFirstbootSealStrategy(newFakeExecutor(tpm, DefaultConfig()), nil, testLogger())
		s.evictStaleHandles()
		if tpm.resetCalls != 1 || tpm.resetClearCalls != 0 {
			t.Errorf("resetErr=%v: FactoryReset=%d FactoryResetWithClear=%d, want 1 and 0 (never TPM2_Clear)",
				resetErr, tpm.resetCalls, tpm.resetClearCalls)
		}
	}
}

func TestFirstbootSealStrategy_ClearTPM_NonAuthFailureDoesNotEscalate(t *testing.T) {
	// A failure that is not an auth error never escalates to a PPI
	// ForceClear; the fake panics if ForceClear is called.
	tpm := &fakeTPM{resetErr: errFakeTPM}
	s := NewFirstbootSealStrategy(newFakeExecutor(tpm, DefaultConfig()), nil, testLogger())
	s.clearTPM()
	if tpm.resetClearCalls != 1 {
		t.Errorf("FactoryResetWithClear calls = %d, want 1", tpm.resetClearCalls)
	}
}

func TestIsTPMAuthError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("TPM_RC_BAD_AUTH: session 1"), true},
		{errors.New("wrapped: TPM_RC_AUTH_FAIL"), true},
		{errors.New("TPM_RC_LOCKOUT"), true},
		{errors.New("TPM_RC_HANDLE"), false},
	}
	for _, tt := range tests {
		if got := isTPMAuthError(tt.err); got != tt.want {
			t.Errorf("isTPMAuthError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestFormatPCRListAndClearString(t *testing.T) {
	s := NewFirstbootSealStrategy(newFakeExecutor(nil, DefaultConfig()), nil, testLogger())
	for _, tt := range []struct {
		pcrs []uint
		want string
	}{{nil, ""}, {[]uint{7}, "7"}, {[]uint{0, 7, 14}, "0,7,14"}} {
		if got := s.formatPCRList(tt.pcrs); got != tt.want {
			t.Errorf("formatPCRList(%v) = %q, want %q", tt.pcrs, got, tt.want)
		}
	}

	secret := "recovery-passphrase"
	clearString(&secret)
	if secret != "" {
		t.Errorf("clearString left %q", secret)
	}
	empty := ""
	clearString(&empty)
	clearString(nil)
}

func TestFirstbootSealStrategy_InstallerConfigDefaults(t *testing.T) {
	// Without an installer config the opt-in destructive behaviours stay off
	// and the recovery key is escrowed, never destroyed.
	s := NewFirstbootSealStrategy(newFakeExecutor(nil, DefaultConfig()), nil, testLogger())
	if s.shouldFactoryResetWithClear() {
		t.Error("factory reset with clear must default to off")
	}
	if s.shouldForceClearViaPPI() {
		t.Error("PPI force clear must default to off")
	}
	if got := s.recoveryKeyStrategy(); got != installer.RecoveryKeyStrategyEscrow {
		t.Errorf("recoveryKeyStrategy() = %q, want escrow", got)
	}
	strategy, err := s.applyRecoveryKeyStrategy("/dev/null", "")
	if err != nil || strategy != installer.RecoveryKeyStrategyEscrow {
		t.Errorf("empty recovery key: got (%q, %v), want (escrow, nil) as a no-op", strategy, err)
	}
}
