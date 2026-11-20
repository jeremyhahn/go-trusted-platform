//go:build eventlog_live

package measure

import (
	"crypto"
	"errors"
	"io/fs"
	"os"
	"sort"
	"testing"
)

// liveEventLogPath is the firmware event log the kernel exposes, or the path
// in DISKIMAGE_EVENTLOG (a log copied out of a booted x86 or QEMU aarch64
// guest; CI runs this test under the eventlog_live tag on that guest).
func liveEventLogPath() string {
	if p := os.Getenv("DISKIMAGE_EVENTLOG"); p != "" {
		return p
	}
	return "/sys/kernel/security/tpm0/binary_bios_measurements"
}

// TestLiveEventLogReplaysToItsPrediction parses a real firmware event log,
// replays every bank it carries (PCR 0 seeded from its StartupLocality record)
// and checks CheckEventLog accepts a prediction of the same records: the
// parser and the replay agree with firmware's encoding, not only with the
// fixtures (docs/SPEC.md:158, factory-image/architecture.md §8).
func TestLiveEventLogReplaysToItsPrediction(t *testing.T) {
	path := liveEventLogPath()
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		t.Skipf("no event log at %s", path)
	case errors.Is(err, fs.ErrPermission):
		t.Skipf("event log %s is not readable: %v", path, err)
	case err != nil:
		t.Fatal(err)
	}
	events, err := ParseEventLog(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if len(events) == 0 {
		t.Fatalf("%s holds no events after its Spec ID header", path)
	}

	var hashes []crypto.Hash
	for _, e := range events {
		if e.Type == EventNoAction {
			continue
		}
		for h := range e.Digests {
			hashes = append(hashes, h)
		}
		break
	}
	if len(hashes) == 0 {
		t.Fatalf("%s extends no PCR", path)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })

	banks := make([]Bank, 0, len(hashes))
	for _, h := range hashes {
		pcrs, err := ReplayEventLog(events, h)
		if err != nil {
			t.Fatalf("replaying the %v bank: %v", h, err)
		}
		for pcr, v := range pcrs {
			if len(v) != h.Size() {
				t.Fatalf("%v PCR %d replays to %d bytes, want %d", h, pcr, len(v), h.Size())
			}
		}
		banks = append(banks, Bank{Hash: h, PCRs: pcrs})
	}
	if err := CheckEventLog(raw, banks); err != nil {
		t.Fatalf("CheckEventLog against the log's own replay: %v", err)
	}
}
