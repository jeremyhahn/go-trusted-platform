package backends

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	luks2 "github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// roundTripSRKHandle is the persistent storage SRK the SDK sealer seals under
// by default (TCG PC Client 0x81000001).
const roundTripSRKHandle = 0x81000001

// newRoundTripSimulator starts the TPM simulator, persists an ECC storage
// SRK at roundTripSRKHandle and returns the simulator transport.
func newRoundTripSimulator(t *testing.T) transport.TPM {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		t.Fatalf("simulator: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	tpm := transport.FromReadWriter(sim)

	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("create SRK: %v", err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		PersistentHandle: roundTripSRKHandle,
	}).Execute(tpm); err != nil {
		t.Fatalf("persist SRK: %v", err)
	}
	if _, err := (tpm2.FlushContext{FlushHandle: srk.ObjectHandle}).Execute(tpm); err != nil {
		t.Fatalf("flush SRK: %v", err)
	}
	return tpm
}

// simModule is the platform TPM module over the simulator: the daemon and
// the initrd both reach the TPM through its Transport. The platform PCR
// reads as extended so the strategy's cold-boot extension does not reach
// the nil embedded module.
type simModule struct {
	xkmssdk.TrustedPlatformModule
	tpm transport.TPM
}

// Device is empty: the simulator is an in-process TPM, so the opener lends
// its transport.
func (simModule) Device() string { return "" }

func (m simModule) Transport() transport.TPM { return m.tpm }

func (simModule) IsPlatformPCRExtended() (bool, error) { return true, nil }

// roundTripLUKS is the initrd's view of the volume: tokens come from the
// real LUKS2 header and Open checks the passphrase against its keyslot.
// Methods the boot unlock does not reach panic on the nil embedded Handler.
type roundTripLUKS struct {
	luks.Handler
	device   string
	tokens   map[int]*luks.Token
	openSlot *int
	openErr  error
	opened   bool
}

func (l *roundTripLUKS) Open(_ context.Context, device, _ string, password []byte, opts *luks.OpenOptions) error {
	if opts != nil && opts.KeySlot != nil {
		slot := *opts.KeySlot
		l.openSlot = &slot
	}
	// The strategy wipes the buffer after Open, so test the key here.
	l.openErr = luks2.TestKey(device, password)
	l.opened = true
	return l.openErr
}

func (l *roundTripLUKS) IsOpen(context.Context, string) bool { return false }

func (l *roundTripLUKS) TokenCreate(context.Context, string, *luks.Token) (int, error) {
	return 0, errors.New("not used")
}

func (l *roundTripLUKS) TokenCreateAt(context.Context, string, int, *luks.Token) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenRead(_ context.Context, _ string, id int) (*luks.Token, error) {
	tok, ok := l.tokens[id]
	if !ok {
		return nil, errors.New("no token")
	}
	return tok, nil
}

func (l *roundTripLUKS) TokenDelete(context.Context, string, int) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenUpdate(context.Context, string, int, *luks.Token) error {
	return errors.New("not used")
}

func (l *roundTripLUKS) TokenList(context.Context, string) (map[int]*luks.Token, error) {
	return l.tokens, nil
}

func (l *roundTripLUKS) TokenExists(_ context.Context, _ string, id int) (bool, error) {
	_, ok := l.tokens[id]
	return ok, nil
}

func (l *roundTripLUKS) TokenCount(context.Context, string) (int, error) { return len(l.tokens), nil }

// TestLUKSTPMBootRoundTrip_InitrdUnsealsWhatEnrolmentSealed drives the TPM
// enrolment and the boot unlock on the TPM simulator through the real SDK
// sealer: the backend's EnrollTPM seals and writes the token into a LUKS2
// image, the token is re-read from the header, and the initrd TPM token
// strategy unseals it with the SDK sealer and opens the enrolled keyslot.
// roundTripEnrolment is a volume enrolled on the simulator with PCR 7 and
// the initrd strategy that unseals its header token.
type roundTripEnrolment struct {
	module   simModule
	device   string
	slot     int32
	raw      []byte
	header   *roundTripLUKS
	strategy *initrd.TPMTokenStrategy
	volume   *luks.VolumeConfig
}

// enrolRoundTrip enrols a fresh image with a PCR 7 TPM keyslot and builds
// the initrd strategy over its re-read header token.
func enrolRoundTrip(t *testing.T, ctx context.Context) *roundTripEnrolment {
	t.Helper()
	module := simModule{tpm: newRoundTripSimulator(t)}

	sealer, err := NewLUKSTPMHandler(nil, PlatformTPMOpener(func() xkmssdk.TrustedPlatformModule { return module }))
	if err != nil {
		t.Fatalf("NewLUKSTPMHandler: %v", err)
	}
	device := newLUKSImage(t)
	b := newTestLUKSBackend(WithLUKSTPMHandler(pcrCheckedTPMHandler(sealer)))

	res, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{
		Device:             device,
		ExistingPassphrase: testLUKSPassphrase,
		PCRs:               []int32{7},
	})
	if err != nil {
		t.Fatalf("EnrollTPM: %v", err)
	}

	tokenID, err := strconv.Atoi(res.TokenID)
	if err != nil {
		t.Fatalf("token id %q: %v", res.TokenID, err)
	}
	raw, err := luks2.ExportToken(device, tokenID)
	if err != nil {
		t.Fatalf("re-read token %d from the header: %v", tokenID, err)
	}
	var token luks.Token
	if err := json.Unmarshal(raw, &token); err != nil {
		t.Fatalf("header token JSON: %v", err)
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != strconv.Itoa(int(res.Slot)) {
		t.Fatalf("header token keyslots %v, want [%d]", token.Keyslots, res.Slot)
	}

	header := &roundTripLUKS{device: device, tokens: map[int]*luks.Token{tokenID: &token}}
	// No SetUnsealer: the strategy unseals over the platform's own TPM.
	return &roundTripEnrolment{
		module:   module,
		device:   device,
		slot:     res.Slot,
		raw:      raw,
		header:   header,
		strategy: initrd.NewTPMTokenStrategy(&initrd.Platform{LUKS: header, TPM: module}, nil),
		volume:   &luks.VolumeConfig{DevicePath: device, MappingName: "cryptroot"},
	}
}

func TestLUKSTPMBootRoundTrip_InitrdUnsealsWhatEnrolmentSealed(t *testing.T) {
	ctx := context.Background()
	e := enrolRoundTrip(t, ctx)
	strategy, volume, header, raw := e.strategy, e.volume, e.header, e.raw

	if !strategy.CanUnlock(ctx, volume) {
		t.Fatalf("CanUnlock is false for the enrolled header token %s", raw)
	}
	if err := strategy.Unlock(ctx, volume); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !header.opened {
		t.Fatal("Unlock never opened the volume")
	}
	if header.openSlot == nil || *header.openSlot != int(e.slot) {
		t.Fatalf("Open used keyslot %v, want %d", header.openSlot, e.slot)
	}
	if header.openErr != nil {
		t.Fatalf("the unsealed passphrase does not open the enrolled keyslot: %v", header.openErr)
	}
}

// TestLUKSTPMBootRoundTrip_ChangedPCRRefusesTheUnseal: once a sealed PCR
// moves, the initrd cannot unseal the passphrase enrolment sealed.
func TestLUKSTPMBootRoundTrip_ChangedPCRRefusesTheUnseal(t *testing.T) {
	ctx := context.Background()
	e := enrolRoundTrip(t, ctx)

	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(7), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
			{HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32)},
		}},
	}).Execute(e.module.tpm); err != nil {
		t.Fatalf("extend PCR 7: %v", err)
	}

	if !e.strategy.CanUnlock(ctx, e.volume) {
		t.Fatalf("CanUnlock is false for the enrolled header token %s", e.raw)
	}
	if err := e.strategy.Unlock(ctx, e.volume); err == nil {
		t.Fatal("Unlock succeeded after PCR 7 changed, want the unseal refused")
	}
	if e.header.opened {
		t.Fatal("Unlock opened the volume after PCR 7 changed")
	}
}
