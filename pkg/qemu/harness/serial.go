package harness

import (
	"context"
	"os"
	"strings"
	"time"
)

// serialPollInterval is how often WaitForSerial re-reads the transcript.
const serialPollInterval = 250 * time.Millisecond

// serialTailBytes is how much of the transcript a timeout error carries.
const serialTailBytes = 4096

// WaitForSerial returns once needle appears in the serial transcript at
// path, or when ctx ends. QEMU appends to the file as the guest writes,
// so the file is re-read on a ticker; the transcript can be absent for a
// moment after the VM starts, which is not an error. A timeout reports
// the tail of what the guest did print, which is the diagnostic.
func WaitForSerial(ctx context.Context, path, needle string) error {
	return WaitForSerialAfter(ctx, path, needle, 0)
}

// WaitForSerialAfter is WaitForSerial that ignores the first offset bytes
// of the transcript, so a milestone that also appeared in an earlier
// boot of the same VM is not mistaken for this boot's.
func WaitForSerialAfter(ctx context.Context, path, needle string, offset int64) error {
	ticker := time.NewTicker(serialPollInterval)
	defer ticker.Stop()
	for {
		found, err := serialContains(path, needle, offset)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		select {
		case <-ctx.Done():
			return &SerialTimeoutError{Path: path, Needle: needle, Tail: serialTail(path)}
		case <-ticker.C:
		}
	}
}

// SerialSize returns the transcript's current size, the offset to pass
// to WaitForSerialAfter for the next boot; a missing file is size 0.
func SerialSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, &SerialError{Path: path, Err: err}
	}
	return info.Size(), nil
}

// SerialContains reports whether needle appears in the transcript.
func SerialContains(path, needle string) (bool, error) {
	return serialContains(path, needle, 0)
}

func serialContains(path, needle string, offset int64) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, &SerialError{Path: path, Err: err}
	}
	if offset > int64(len(data)) {
		return false, nil
	}
	return strings.Contains(string(data[offset:]), needle), nil
}

// serialTail returns the last serialTailBytes of the transcript for an
// error message; failures reading it yield an empty tail.
func serialTail(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > serialTailBytes {
		data = data[len(data)-serialTailBytes:]
	}
	return string(data)
}

// MissingMilestone names the first of milestones absent from the transcript
// at path, in order, so a failed boot says where the chain stopped. An
// unreadable transcript counts as lacking the first milestone.
func MissingMilestone(path string, milestones []string) string {
	for _, m := range milestones {
		found, err := SerialContains(path, m)
		if err != nil || !found {
			return "first missing milestone: " + m
		}
	}
	return "every milestone present"
}
