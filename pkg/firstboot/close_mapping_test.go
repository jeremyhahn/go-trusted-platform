package firstboot

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// mappingCloseRecorder answers lock with lockErrs in order (nil past the end)
// and records every call closeInstallerMapping makes.
type mappingCloseRecorder struct {
	lockErrs    []error
	lockCalls   int
	forceCalls  int
	waits       []time.Duration
	forceRemove error
}

func (r *mappingCloseRecorder) closer() installerMappingCloser {
	return installerMappingCloser{
		lock: func(name string) error {
			r.lockCalls++
			if name != "installer" {
				return errors.New("unexpected mapping " + name)
			}
			if r.lockCalls <= len(r.lockErrs) {
				return r.lockErrs[r.lockCalls-1]
			}
			return nil
		},
		forceRemove: func(string) error { r.forceCalls++; return r.forceRemove },
		wait:        func(d time.Duration) { r.waits = append(r.waits, d) },
	}
}

func TestCloseInstallerMapping_ClosesFirstTime(t *testing.T) {
	r := &mappingCloseRecorder{}

	if err := closeInstallerMapping(r.closer()); err != nil {
		t.Fatalf("closeInstallerMapping: %v", err)
	}
	if r.lockCalls != 1 || r.forceCalls != 0 || len(r.waits) != 0 {
		t.Fatalf("calls = lock %d, force %d, waits %v; want one lock and nothing else", r.lockCalls, r.forceCalls, r.waits)
	}
}

// A forced removal deletes the mapping; go-luks2 v0.2.0's Lock then reports
// luks2.ErrVolumeNotUnlocked, which is closed, not another failure.
func TestCloseInstallerMapping_GoneAfterForcedRemovalIsClosed(t *testing.T) {
	busy := &WrappedError{Msg: "installer still held", Err: luks2.ErrMappingBusy}
	r := &mappingCloseRecorder{lockErrs: []error{busy, luks2.ErrVolumeNotUnlocked}}

	if err := closeInstallerMapping(r.closer()); err != nil {
		t.Fatalf("closeInstallerMapping: %v", err)
	}
	if r.lockCalls != 2 || r.forceCalls != 1 {
		t.Fatalf("calls = lock %d, force %d; want 2 and 1", r.lockCalls, r.forceCalls)
	}
	if len(r.waits) != 1 || r.waits[0] != installerMappingCloseDelay {
		t.Fatalf("waits = %v, want [%v]", r.waits, installerMappingCloseDelay)
	}
}

func TestCloseInstallerMapping_ReportsAMappingThatStaysOpen(t *testing.T) {
	busy := &WrappedError{Msg: "installer still held", Err: luks2.ErrMappingBusy}
	errs := make([]error, installerMappingCloseAttempts)
	for i := range errs {
		errs[i] = busy
	}
	r := &mappingCloseRecorder{lockErrs: errs, forceRemove: errors.New("dmsetup failed")}

	err := closeInstallerMapping(r.closer())

	if !errors.Is(err, luks2.ErrMappingBusy) {
		t.Fatalf("closeInstallerMapping error = %v, want luks2.ErrMappingBusy", err)
	}
	if r.lockCalls != installerMappingCloseAttempts || r.forceCalls != installerMappingCloseAttempts-1 {
		t.Fatalf("calls = lock %d, force %d; want %d and %d",
			r.lockCalls, r.forceCalls, installerMappingCloseAttempts, installerMappingCloseAttempts-1)
	}
	for i, d := range r.waits {
		if want := time.Duration(i+1) * installerMappingCloseDelay; d != want {
			t.Fatalf("wait %d = %v, want %v", i, d, want)
		}
	}
}

func TestDefaultInstallerMappingCloser_IsComplete(t *testing.T) {
	ops := defaultInstallerMappingCloser()
	if ops.lock == nil || ops.forceRemove == nil || ops.wait == nil {
		t.Fatalf("defaultInstallerMappingCloser has a nil operation: %+v", ops)
	}
}
