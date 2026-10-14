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

// recovery_reseal_test.go pins the recovery reseal. The TPM-PCR unlock reads
// its seal from the EFI partition files first boot writes, and the initrd has
// no writer for them, so ResealKeys refuses before it unseals anything and
// the recovery menu never reports a reseal it did not achieve.

package initrd

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

var (
	errReadPCRs = errors.New("tpm: PCR read failed")
	errUnseal   = errors.New("tpm: unseal failed")
)

// resealTPM answers ReadPCRs, fails every Unseal, and refuses every Seal with
// the go-xkms seal protection refusal. It counts both calls, so a test can
// prove the reseal never reached them.
type resealTPM struct {
	xkmssdk.TrustedPlatformModule
	readErr error
	unseals int
	seals   int
}

func (f *resealTPM) ReadPCRs([]uint) ([]xkmssdk.PCRBank, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return []xkmssdk.PCRBank{{Algorithm: "SHA256"}}, nil
}

func (f *resealTPM) Unseal(context.Context, *xkmssdk.SealedData, *xkmssdk.UnsealOptions) ([]byte, error) {
	f.unseals++
	return nil, errUnseal
}

func (f *resealTPM) Seal(context.Context, []byte, *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.seals++
	return nil, errSealUnprotected
}

// newResealManager returns a manager over tpm whose volume has the given
// unlock methods, in slot order. NewManager registers the TPM-PCR strategy
// when the methods include it.
func newResealManager(t *testing.T, tpm *resealTPM, methods ...luks.UnlockMethod) *initrdManager {
	t.Helper()
	platform := createTestPlatform()
	platform.TPM = tpm
	platform.Config.FallbackMethods = methods

	mgr, err := NewManager(platform, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr.(*initrdManager)
}

// assertNoTPMSealCalls fails the test if the reseal reached Unseal or Seal.
func assertNoTPMSealCalls(t *testing.T, tpm *resealTPM) {
	t.Helper()
	if tpm.unseals != 0 || tpm.seals != 0 {
		t.Fatalf("Unseal calls = %d, Seal calls = %d, want none", tpm.unseals, tpm.seals)
	}
}

// TestResealKeys_RefusesWithoutSealStore stands in for the success path:
// with a TPM-PCR slot and strategy in place, ResealKeys refuses, names the
// slot, and never unseals or seals, so neither the failing unseal nor the
// seal protection refusal of the test TPM is reached.
func TestResealKeys_RefusesWithoutSealStore(t *testing.T) {
	tpm := &resealTPM{}
	m := newResealManager(t, tpm, luks.UnlockPassword, luks.UnlockTPMPCR)

	err := m.ResealKeys(context.Background())

	var refused *ResealStoreError
	if !errors.As(err, &refused) {
		t.Fatalf("ResealKeys error = %v, want *ResealStoreError", err)
	}
	if !reflect.DeepEqual(refused.Slots, []int{1}) {
		t.Fatalf("refused slots = %v, want [1]", refused.Slots)
	}
	if !strings.Contains(err.Error(), "cannot be stored") {
		t.Fatalf("error %q does not say the resealed data cannot be stored", err)
	}
	assertNoTPMSealCalls(t, tpm)
}

// TestResealKeys_ReadPCRsFails asserts a PCR read failure is returned, not
// logged and passed over.
func TestResealKeys_ReadPCRsFails(t *testing.T) {
	tpm := &resealTPM{readErr: errReadPCRs}
	m := newResealManager(t, tpm, luks.UnlockTPMPCR)

	err := m.ResealKeys(context.Background())
	if !errors.Is(err, errReadPCRs) {
		t.Fatalf("ResealKeys error = %v, want the PCR read failure", err)
	}
	assertNoTPMSealCalls(t, tpm)
}

// TestResealKeys_VolumeNotConfigured asserts a missing root device is an
// error.
func TestResealKeys_VolumeNotConfigured(t *testing.T) {
	tpm := &resealTPM{}
	m := newResealManager(t, tpm, luks.UnlockTPMPCR)
	m.platform.Config.RootDevice = ""

	err := m.ResealKeys(context.Background())
	if !errors.Is(err, ErrVolumeNotConfigured) {
		t.Fatalf("ResealKeys error = %v, want ErrVolumeNotConfigured", err)
	}
	assertNoTPMSealCalls(t, tpm)
}

// TestResealKeys_NoTPMPCRStrategy asserts a chain without the TPM-PCR
// strategy is an error.
func TestResealKeys_NoTPMPCRStrategy(t *testing.T) {
	tpm := &resealTPM{}
	m := newResealManager(t, tpm, luks.UnlockTPMPCR)
	m.chain = NewStrategyChain(m.logger)

	err := m.ResealKeys(context.Background())

	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("ResealKeys error = %v, want *MessageError", err)
	}
	assertNoTPMSealCalls(t, tpm)
}

// TestResealKeys_NoTPMPCRSlot asserts a volume without a TPM-PCR slot is an
// error, not a reseal of nothing reported as success.
func TestResealKeys_NoTPMPCRSlot(t *testing.T) {
	tpm := &resealTPM{}
	m := newResealManager(t, tpm, luks.UnlockPassword)
	m.chain.Add(NewTPMPCRStrategy(m.platform, m.logger))

	err := m.ResealKeys(context.Background())

	var noSlot *ResealNoSlotError
	if !errors.As(err, &noSlot) {
		t.Fatalf("ResealKeys error = %v, want *ResealNoSlotError", err)
	}
	if noSlot.DevicePath != m.platform.Config.RootDevice {
		t.Fatalf("no-slot device = %q, want %q", noSlot.DevicePath, m.platform.Config.RootDevice)
	}
	assertNoTPMSealCalls(t, tpm)
}

// TestResealKeysInteractive_RefusalIsNotSuccess drives the recovery menu's
// reseal option with a confirmed "yes": the refusal comes back as the error
// the menu prints, and success is never printed.
func TestResealKeysInteractive_RefusalIsNotSuccess(t *testing.T) {
	tpm := &resealTPM{}
	m := newResealManager(t, tpm, luks.UnlockTPMPCR)

	var err error
	out := captureStdout(t, func() {
		withStdin(t, "yes\n", func() {
			err = m.resealKeysInteractive(context.Background())
		})
	})

	var refused *ResealStoreError
	if !errors.As(err, &refused) {
		t.Fatalf("resealKeysInteractive error = %v, want *ResealStoreError", err)
	}
	if strings.Contains(out, "successfully resealed") {
		t.Fatalf("recovery reseal printed success after a refusal:\n%s", out)
	}
	assertNoTPMSealCalls(t, tpm)
}

// withStdin runs fn with os.Stdin reading input.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}

	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	fn()
}

// captureStdout runs fn and returns what it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	done := make(chan string)
	go func() {
		out, readErr := io.ReadAll(r)
		if readErr != nil {
			t.Errorf("read stdout: %v", readErr)
		}
		done <- string(out)
	}()

	old := os.Stdout
	os.Stdout = w
	func() {
		defer func() { os.Stdout = old }()
		fn()
	}()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	return <-done
}
