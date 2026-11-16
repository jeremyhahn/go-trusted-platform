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

package backends

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

// TestMain points the per-volume lock directory at a temporary directory, so
// the package's tests never touch /run.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "luks-locks-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "luks lock dir:", err)
		os.Exit(1)
	}
	luksLockDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestLUKSVolumeLock_HeldAcrossBackends proves two separate backends (as
// platformd and an embedded platformctl host build) serialize on one volume,
// even when the second names it through a symlink alias.
func TestLUKSVolumeLock_HeldAcrossBackends(t *testing.T) {
	dir := t.TempDir()
	device := filepath.Join(dir, "volume.img")
	if err := os.WriteFile(device, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(device, alias); err != nil {
		t.Fatal(err)
	}
	if got, want := luksVolumeLockPath(alias), luksVolumeLockPath(device); got != want {
		t.Fatalf("lock path of alias = %q, want %q", got, want)
	}

	a := newTestLUKSBackend()
	b := newTestLUKSBackend()
	unlockA, err := a.lockDevice(context.Background(), device)
	if err != nil {
		t.Fatalf("A lockDevice: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		unlockB, err := b.lockDevice(context.Background(), alias)
		if err == nil {
			unlockB()
		}
		done <- err
	}()
	select {
	case err := <-done:
		unlockA()
		t.Fatalf("B took the volume lock while A held it (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlockA()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("B lockDevice: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B did not take the volume lock after A released it")
	}
}

// TestLUKSVolumeLock_CancelWhileHeld: while one backend holds the volume
// lock, a RemoveKey whose context ends gives up waiting with the context
// error and kills no keyslot, both when it queues on the same backend's
// in-process lock and when it queues on another backend's flock. A context
// that is already done never takes the lock either.
func TestLUKSVolumeLock_CancelWhileHeld(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sameOwner bool
		preCancel bool
	}{
		{"same backend, cancelled while waiting", true, false},
		{"other backend, cancelled while waiting", false, false},
		{"other backend, cancelled before the call", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device := newLUKSImage(t)
			before := keyslotIDs(t, device)
			slot := -1
			for id := range before {
				slot = id
				break
			}
			if slot < 0 {
				t.Fatal("the test image has no keyslot")
			}

			holder := newTestLUKSBackend()
			caller := holder
			if !tc.sameOwner {
				caller = newTestLUKSBackend()
			}
			unlock, err := holder.lockDevice(context.Background(), device)
			if err != nil {
				t.Fatalf("holder lockDevice: %v", err)
			}
			defer func() { unlock() }()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.preCancel {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				done <- caller.RemoveKey(ctx, &daemon.LUKSRemoveKeyRequest{Device: device, Slot: int32(slot)})
			}()
			if !tc.preCancel {
				select {
				case err := <-done:
					t.Fatalf("RemoveKey returned while the volume lock was held: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("RemoveKey = %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RemoveKey kept waiting for the volume lock after its context ended")
			}

			unlock()
			unlock = func() {}
			after := keyslotIDs(t, device)
			if len(after) != len(before) || !after[slot] {
				t.Fatalf("keyslots changed by a cancelled RemoveKey: before %v, after %v", before, after)
			}
		})
	}
}

// TestLUKSBackend_ConcurrentEnrollmentAcrossBackendsGetsDistinctSlots runs
// concurrent enrollments on one volume through two separate backends.
func TestLUKSBackend_ConcurrentEnrollmentAcrossBackendsGetsDistinctSlots(t *testing.T) {
	const n = 4

	t.Run("passphrase", func(t *testing.T) {
		device := newLUKSImage(t)
		bs := []*LUKSBackend{newTestLUKSBackend(), newTestLUKSBackend()}
		start := make(chan struct{})
		slots := make([]int32, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				res, err := bs[i%2].EnrollPassphrase(context.Background(), &daemon.LUKSEnrollPassphraseRequest{
					Device:             device,
					ExistingPassphrase: testLUKSPassphrase,
					NewPassphrase:      "cross-pass-" + strconv.Itoa(i),
				})
				errs[i] = err
				if res != nil {
					slots[i] = res.Slot
				}
			}(i)
		}
		close(start)
		wg.Wait()

		seen := map[int32]int{}
		ids := keyslotIDs(t, device)
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("EnrollPassphrase %d: %v", i, errs[i])
			}
			if j, dup := seen[slots[i]]; dup {
				t.Fatalf("enrollments %d and %d both reported slot %d", j, i, slots[i])
			}
			seen[slots[i]] = i
			if !ids[int(slots[i])] {
				t.Fatalf("slot %d of enrollment %d is not on the device (%v)", slots[i], i, ids)
			}
			if err := luks2.TestKey(device, []byte("cross-pass-"+strconv.Itoa(i))); err != nil {
				t.Fatalf("passphrase %d does not open the volume: %v", i, err)
			}
		}
	})

	t.Run("fido2", func(t *testing.T) {
		device := newLUKSImage(t)
		bs := []*LUKSBackend{
			newTestLUKSBackend(WithLUKSFIDO2Handler(perCredentialFIDO2Key{})),
			newTestLUKSBackend(WithLUKSFIDO2Handler(perCredentialFIDO2Key{})),
		}
		start := make(chan struct{})
		results := make([]*daemon.LUKSEnrollFIDO2Result, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i], errs[i] = bs[i%2].EnrollFIDO2(context.Background(), &daemon.LUKSEnrollFIDO2Request{
					Device:             device,
					ExistingPassphrase: testLUKSPassphrase,
					CredentialID:       "cred" + strconv.Itoa(i),
				})
			}(i)
		}
		close(start)
		wg.Wait()

		slotSeen := map[int32]int{}
		tokenSeen := map[string]int{}
		ids := keyslotIDs(t, device)
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("EnrollFIDO2 %d: %v", i, errs[i])
			}
			res := results[i]
			if j, dup := slotSeen[res.Slot]; dup {
				t.Fatalf("enrollments %d and %d both reported slot %d", j, i, res.Slot)
			}
			slotSeen[res.Slot] = i
			if !ids[int(res.Slot)] {
				t.Fatalf("slot %d of enrollment %d is not on the device (%v)", res.Slot, i, ids)
			}
			if j, dup := tokenSeen[res.TokenID]; dup {
				t.Fatalf("enrollments %d and %d both reported token %s", j, i, res.TokenID)
			}
			tokenSeen[res.TokenID] = i
			assertKeyslots(t, tokenByID(t, device, res.TokenID), strconv.Itoa(int(res.Slot)))
			if err := luks2.TestKey(device, []byte("fido2-key-cred"+strconv.Itoa(i))); err != nil {
				t.Fatalf("credential %d does not open the volume: %v", i, err)
			}
		}
	})
}

// TestLUKSVolumeLock_DirUnwritableFailsClosed proves a keyslot mutation is
// refused, and writes nothing, when the volume lock cannot be taken.
func TestLUKSVolumeLock_DirUnwritableFailsClosed(t *testing.T) {
	device := newLUKSImage(t)
	before := keyslotIDs(t, device)

	notADir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := luksLockDir
	luksLockDir = notADir
	t.Cleanup(func() { luksLockDir = saved })

	b := newTestLUKSBackend()
	if _, err := b.EnrollPassphrase(context.Background(), &daemon.LUKSEnrollPassphraseRequest{
		Device:             device,
		ExistingPassphrase: testLUKSPassphrase,
		NewPassphrase:      "unlocked-pass",
	}); err == nil {
		t.Fatal("EnrollPassphrase succeeded without the volume lock")
	}
	after := keyslotIDs(t, device)
	if len(after) != len(before) {
		t.Fatalf("keyslots changed without the volume lock: before %v, after %v", before, after)
	}
	if err := luks2.TestKey(device, []byte("unlocked-pass")); err == nil {
		t.Fatal("the refused passphrase opens the volume")
	}
}
