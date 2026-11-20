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

// givenEventLogPath is the firmware event log the test is given: the path in
// DISKIMAGE_EVENTLOG (a log copied out of a booted guest), or else the
// kernel's binary_bios_measurements.
func givenEventLogPath() string {
	if p := os.Getenv("DISKIMAGE_EVENTLOG"); p != "" {
		return p
	}
	return "/sys/kernel/security/tpm0/binary_bios_measurements"
}

// TestEventLogReplayAgreesWithCheckEventLog parses the firmware event log it
// is given, replays every bank it carries (PCR 0 seeded from its
// StartupLocality record) and checks CheckEventLog accepts that same replay.
// It checks only that the parser, the replay and CheckEventLog agree on a
// firmware-written log. It uses neither Predict nor a manifest, so it does
// not check an image's predicted PCRs against a boot: that check is the
// follow-up PR (row/669-live-eventlog) for the factory-image row of
// docs/SPEC.md (factory-image/architecture.md §8). No CI job runs it; run it
// with -tags eventlog_live and DISKIMAGE_EVENTLOG.
func TestEventLogReplayAgreesWithCheckEventLog(t *testing.T) {
	path := givenEventLogPath()
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
