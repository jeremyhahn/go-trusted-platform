package commands

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/internal/fido2hid"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestSrkHandleHex(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil", nil, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := srkHandleHex(nil)
			if result != "none" {
				t.Errorf("expected 'none' for nil input, got %s", result)
			}
		})
	}
	_ = tests
}

func TestSsrkHandleHex(t *testing.T) {
	result := ssrkHandleHex(nil)
	if result != "none" {
		t.Errorf("expected 'none' for nil input, got %s", result)
	}
}

func TestDecodePlatformTPMConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	// A kms:// reference elsewhere in the document must not stop the tpm
	// section from decoding (#778).
	doc := []byte("tpm:\n  platform-pcr: 23\ncertificate-authority:\n  identity:\n    - keys:\n        - password: \"kms://ca/root/keys/0/password?ensure=true\"\n")
	got := decodePlatformTPMConfig(doc, "/etc/trusted-platform/config.yaml", logger)
	if got == nil || got.PlatformPCR != 23 {
		t.Fatalf("tpm config = %+v", got)
	}
}

func TestDecodePlatformTPMConfig_Invalid(t *testing.T) {
	logger := logging.DefaultLogger()
	if got := decodePlatformTPMConfig([]byte("tpm: [unterminated\n"), "bad.yaml", logger); got != nil {
		t.Errorf("malformed candidate = %+v, want nil", got)
	}
	if got := decodePlatformTPMConfig([]byte("other: 1\n"), "none.yaml", logger); got != nil {
		t.Errorf("candidate without tpm = %+v, want nil", got)
	}
}

func TestParsePCRBanksConfig_NonexistentFile(t *testing.T) {
	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig("/nonexistent/path", logger)
	if result != nil {
		t.Error("expected nil for nonexistent file")
	}
}

func TestParsePCRBanksConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	if err := os.WriteFile(pcrFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for empty file")
	}
}

func TestParsePCRBanksConfig_OldFormat(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	// Old format without key=value pairs
	content := "sha256\n0,7,9\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for old format (no equals sign)")
	}
}

func TestParsePCRBanksConfig_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `seal-pcrs=0,7,9
platform-pcr=23
platform-pcr-bank=sha256
golden-pcrs=0,7,9,10
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config for valid file")
	}
	if result.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", result.PlatformPCR)
	}
	if result.PlatformPCRBank != "sha256" {
		t.Errorf("expected PlatformPCRBank sha256, got %s", result.PlatformPCRBank)
	}
	if result.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set")
	}
	if result.PlatformSRK.SRKHandle != 0x81000002 {
		t.Errorf("expected SRK handle 0x81000002, got 0x%08x", result.PlatformSRK.SRKHandle)
	}
	if result.SSRK == nil {
		t.Fatal("expected SSRK to be set")
	}
	if result.SSRK.Handle != 0x81000001 {
		t.Errorf("expected SSRK handle 0x81000001, got 0x%08x", result.SSRK.Handle)
	}
}

func TestParsePCRBanksConfig_MissingPlatformPCR(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when platform-pcr is missing")
	}
}

func TestParsePCRBanksConfig_MissingPlatformPCRBank(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when platform-pcr-bank is missing")
	}
}

func TestParsePCRBanksConfig_MissingKeystoreSRKHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when keystore-srk-handle is missing")
	}
}

func TestParsePCRBanksConfig_MissingSSRKHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when ssrk-handle is missing")
	}
}

func TestParsePCRBanksConfig_InvalidPlatformPCR(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=abc
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for invalid platform-pcr")
	}
}

func TestParsePCRBanksConfig_DecimalHandles(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=2164260866
ssrk-handle=2164260865
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config for decimal handles")
	}
	if result.PlatformSRK.SRKHandle != 2164260866 {
		t.Errorf("unexpected SRK handle: %d", result.PlatformSRK.SRKHandle)
	}
}

func TestParsePCRBanksConfig_WithComments(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `# Platform PCR configuration
platform-pcr=23
platform-pcr-bank=sha256

# Handles
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config when comments are present")
	}
	if result.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", result.PlatformPCR)
	}
}

func TestParsePCRBanksConfig_GoldenPCRs(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
golden-pcrs=0,7,9,10
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config")
	}
	if len(result.GoldenPCRs) != 4 {
		t.Errorf("expected 4 golden PCRs, got %d", len(result.GoldenPCRs))
	}
}

func TestPlatformConfigStruct(t *testing.T) {
	cfg := &PlatformConfig{}
	if cfg.TPM != nil {
		t.Error("expected nil TPM for zero-value PlatformConfig")
	}
}

// TestParsePCRBanksConfig_KeystorePlatformPolicy asserts the parent
// authorization mode is read from pcr-banks and never assumed (#52): the
// unseal must replay the mode the seal actually used, and an absent key
// defaults to false — the seal side's own default.
func TestParsePCRBanksConfig_KeystorePlatformPolicy(t *testing.T) {
	base := `seal-pcrs=0,7,9
platform-pcr=23
platform-pcr-bank=sha256
golden-pcrs=7,9
keystore-srk-handle=0x81000001
ssrk-handle=0x81000001
`
	cases := []struct {
		name    string
		line    string
		want    bool
		wantNil bool
	}{
		{"explicit false", "keystore-platform-policy=false\n", false, false},
		{"explicit true", "keystore-platform-policy=true\n", true, false},
		{"absent defaults to false (seal-side default)", "", false, false},
		{"invalid value rejects the file", "keystore-platform-policy=maybe\n", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcrFile := filepath.Join(t.TempDir(), "pcr-banks")
			if err := os.WriteFile(pcrFile, []byte(base+tc.line), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			result := parsePCRBanksConfig(pcrFile, logging.DefaultLogger())
			if tc.wantNil {
				if result != nil {
					t.Fatal("expected nil config for invalid keystore-platform-policy")
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil config")
			}
			if result.PlatformSRK.PlatformPolicy != tc.want {
				t.Errorf("PlatformPolicy = %v, want %v", result.PlatformSRK.PlatformPolicy, tc.want)
			}
		})
	}
}

// bootFakeFIDO2 is an authenticator whose key is a hash of the credential
// and salt it is asked about.
type bootFakeFIDO2 struct {
	unlocks []*fido2.AuthenticationConfig
	closed  int
}

func bootFIDO2Key(credentialID, salt []byte) []byte {
	sum := sha256.Sum256(append(append([]byte{}, credentialID...), salt...))
	return sum[:]
}

func (f *bootFakeFIDO2) EnrollKey(*fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	return nil, errors.New("enrolment is not part of boot")
}

func (f *bootFakeFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	f.unlocks = append(f.unlocks, config)
	return bootFIDO2Key(config.CredentialID, config.Salt), nil
}

func (f *bootFakeFIDO2) ListDevices() ([]fido2.Device, error) { return nil, nil }

func (f *bootFakeFIDO2) WaitForDevice(context.Context) (*fido2.Device, error) {
	return &fido2.Device{}, nil
}

func (f *bootFakeFIDO2) Close() error {
	f.closed++
	return nil
}

// bootTokenLUKS is a LUKS2 header holding tokens. Open records the key and
// keyslot it is given and then refuses, so that the chain never records a
// winner on the host.
type bootTokenLUKS struct {
	storageluks.Handler
	storageluks.TokenHandler
	tokens map[int]*storageluks.Token
	opens  []bootOpen
}

type bootOpen struct {
	device, mapping string
	key             []byte
	slot            int
}

var errBootOpenRecorded = errors.New("open recorded")

func (l *bootTokenLUKS) TokenList(context.Context, string) (map[int]*storageluks.Token, error) {
	return l.tokens, nil
}

func (l *bootTokenLUKS) Open(_ context.Context, device, mapping string, key []byte, opts *storageluks.OpenOptions) error {
	slot := -1
	if opts != nil && opts.KeySlot != nil {
		slot = *opts.KeySlot
	}
	l.opens = append(l.opens, bootOpen{device: device, mapping: mapping, key: append([]byte{}, key...), slot: slot})
	return errBootOpenRecorded
}

// bootEnumerator is an HID bus with no authenticator on it.
type bootEnumerator struct{}

func (bootEnumerator) Enumerate(uint16, uint16) ([]fido2.HIDDevice, error) { return nil, nil }

func (bootEnumerator) Open(string) (fido2.HIDDevice, error) {
	return nil, errors.New("no HID device")
}

func useBootFIDO2Handler(t *testing.T, factory func(*fido2.Config) (fido2.Handler, error)) {
	t.Helper()
	old := newBootFIDO2Handler
	t.Cleanup(func() { newBootFIDO2Handler = old })
	newBootFIDO2Handler = factory
}

func bootFIDO2Config() *platforminitrd.Config {
	config := platforminitrd.DefaultConfig()
	config.Mode = platforminitrd.ModeBoot
	config.RootDevice = "/dev/boot-test-root"
	config.PCRSelection = []uint{7}
	config.FallbackMethods = []storageluks.UnlockMethod{storageluks.UnlockFIDO2}
	return config
}

// TestNewBootManagerRegistersFIDO2 builds the boot manager through the
// production path with only the authenticator faked, and unlocks the
// installer's token (type fido2, keyslot 3) through the registered chain.
func TestNewBootManagerRegistersFIDO2(t *testing.T) {
	device := &bootFakeFIDO2{}
	useBootFIDO2Handler(t, func(*fido2.Config) (fido2.Handler, error) { return device, nil })

	credentialID := []byte("installer-credential")
	salt := []byte("0123456789abcdef0123456789abcdef")
	header := &bootTokenLUKS{tokens: map[int]*storageluks.Token{
		0: {
			Type:            storageluks.TokenTypeFIDO2,
			Keyslots:        []string{"3"},
			FIDO2Credential: base64.StdEncoding.EncodeToString(credentialID),
			FIDO2Salt:       base64.StdEncoding.EncodeToString(salt),
			FIDO2RP:         "luks-alpine",
			FIDO2UPRequired: true,
		},
	}}
	bundle := &platforminitrd.Platform{LUKS: header, Config: bootFIDO2Config()}

	manager, err := newBootManager(logging.DefaultLogger(), bundle)
	if err != nil {
		t.Fatalf("newBootManager: %v", err)
	}
	if bundle.FIDO2 != device {
		t.Fatalf("platform FIDO2 handler = %v, want the SDK handler", bundle.FIDO2)
	}

	err = manager.UnlockVolumes(context.Background())
	if !errors.Is(err, errBootOpenRecorded) {
		t.Fatalf("UnlockVolumes error = %v, want the recorded open", err)
	}
	if len(device.unlocks) != 1 {
		t.Fatalf("authenticator asked %d times, want 1", len(device.unlocks))
	}
	if got := device.unlocks[0].RelyingPartyID; got != "luks-alpine" {
		t.Errorf("relying party = %q, want luks-alpine", got)
	}
	if len(header.opens) != 1 {
		t.Fatalf("Open called %d times, want 1", len(header.opens))
	}
	open := header.opens[0]
	if open.device != "/dev/boot-test-root" || open.mapping != "cryptroot" || open.slot != 3 {
		t.Errorf("Open(%q, %q, slot %d), want (/dev/boot-test-root, cryptroot, slot 3)", open.device, open.mapping, open.slot)
	}
	if string(open.key) != string(bootFIDO2Key(credentialID, salt)) {
		t.Error("Open was not given the authenticator's key for the installer token")
	}
}

// TestNewBootManagerSDKHandler opens the real SDK handler on an HID bus with
// no authenticator: the initrd can build it before a key is plugged in.
// TestBootFIDO2HandlerUsesHIDRawEnumerator covers Codex review round 4 P1:
// the production boot factory opens the handler on the enumerator the
// installer enrols through, which prefixes the hidraw report ID on Linux.
// The SDK's own Linux enumerator drops a leading zero byte of each frame.
func TestBootFIDO2HandlerUsesHIDRawEnumerator(t *testing.T) {
	if runtime.GOOS == "linux" {
		if _, ok := bootFIDO2Enumerator().(fido2hid.Enumerator); !ok {
			t.Fatalf("boot FIDO2 enumerator is %T, want the hidraw report-ID wrapper", bootFIDO2Enumerator())
		}
	}

	old := bootFIDO2Enumerator
	t.Cleanup(func() { bootFIDO2Enumerator = old })
	var calls int
	bootFIDO2Enumerator = func() fido2.HIDDeviceEnumerator {
		calls++
		return bootEnumerator{}
	}
	cfg := fido2.DefaultConfig
	handler, err := newBootFIDO2Handler(&cfg)
	if err != nil {
		t.Fatalf("newBootFIDO2Handler: %v", err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	if calls != 1 {
		t.Fatalf("newBootFIDO2Handler built %d enumerators from bootFIDO2Enumerator, want 1", calls)
	}
}

func TestNewBootManagerSDKHandler(t *testing.T) {
	useBootFIDO2Handler(t, func(cfg *fido2.Config) (fido2.Handler, error) {
		return fido2.NewHandler(cfg, bootEnumerator{})
	})
	bundle := &platforminitrd.Platform{LUKS: &bootTokenLUKS{}, Config: bootFIDO2Config()}

	manager, err := newBootManager(logging.DefaultLogger(), bundle)
	if err != nil {
		t.Fatalf("newBootManager: %v", err)
	}
	if bundle.FIDO2 == nil {
		t.Fatal("platform FIDO2 handler is nil, want the SDK handler")
	}
	if err := manager.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNewBootManagerFIDO2Unavailable leaves FIDO2 out of the chain when the
// handler cannot be opened, and boot carries on without it.
func TestNewBootManagerFIDO2Unavailable(t *testing.T) {
	useBootFIDO2Handler(t, func(*fido2.Config) (fido2.Handler, error) {
		return nil, errors.New("no HID transport")
	})
	header := &bootTokenLUKS{}
	bundle := &platforminitrd.Platform{LUKS: header, Config: bootFIDO2Config()}

	manager, err := newBootManager(logging.DefaultLogger(), bundle)
	if err != nil {
		t.Fatalf("newBootManager: %v", err)
	}
	if bundle.FIDO2 != nil {
		t.Fatalf("platform FIDO2 handler = %v, want nil", bundle.FIDO2)
	}
	if err := manager.UnlockVolumes(context.Background()); !errors.Is(err, platforminitrd.ErrUnlockFailed) {
		t.Fatalf("UnlockVolumes error = %v, want ErrUnlockFailed", err)
	}
	if len(header.opens) != 0 {
		t.Errorf("Open called %d times without a FIDO2 handler, want 0", len(header.opens))
	}
}

// TestNewBootManagerInvalidConfig closes the FIDO2 handler when the manager
// cannot be built.
func TestNewBootManagerInvalidConfig(t *testing.T) {
	device := &bootFakeFIDO2{}
	useBootFIDO2Handler(t, func(*fido2.Config) (fido2.Handler, error) { return device, nil })
	config := bootFIDO2Config()
	config.RootDevice = ""
	bundle := &platforminitrd.Platform{LUKS: &bootTokenLUKS{}, Config: config}

	manager, err := newBootManager(logging.DefaultLogger(), bundle)
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("newBootManager error = %v, want WrappedError", err)
	}
	if manager != nil {
		t.Errorf("manager = %v, want nil", manager)
	}
	if device.closed != 1 {
		t.Errorf("FIDO2 handler closed %d times, want 1", device.closed)
	}
}
