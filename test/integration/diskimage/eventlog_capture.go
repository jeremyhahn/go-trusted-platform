//go:build integration

package diskimage

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// The guest prints its event log base64 encoded between these two lines,
// each on a line of its own, so the capture can be cut out of a console
// transcript that also holds the boot output and the echoed command.
const (
	eventLogBeginMarker = "EVENTLOG-BEGIN"
	eventLogEndMarker   = "EVENTLOG-END"
)

// ErrEventLogCaptureEmpty is returned when the markers enclose no bytes.
var ErrEventLogCaptureEmpty = errors.New("diskimage: the captured event log is empty")

// EventLogMarkerError reports a marker missing from a console transcript.
type EventLogMarkerError struct {
	Marker string
}

func (e *EventLogMarkerError) Error() string {
	return fmt.Sprintf("diskimage: no %s line in the console transcript", e.Marker)
}

// EventLogDecodeError reports a capture body that is not base64.
type EventLogDecodeError struct {
	Err error
}

func (e *EventLogDecodeError) Error() string {
	return fmt.Sprintf("diskimage: the captured event log is not base64: %v", e.Err)
}

func (e *EventLogDecodeError) Unwrap() error { return e.Err }

// decodeEventLogCapture returns the bytes the guest printed between the last
// EVENTLOG-BEGIN line and the next EVENTLOG-END line of transcript. A marker
// counts only on a line of its own (CR and surrounding blanks ignored), so
// the echoed command that prints the markers is not taken for them.
func decodeEventLogCapture(transcript string) ([]byte, error) {
	lines := strings.Split(transcript, "\n")
	begin := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == eventLogBeginMarker {
			begin = i
			break
		}
	}
	if begin < 0 {
		return nil, &EventLogMarkerError{Marker: eventLogBeginMarker}
	}
	end := -1
	for i := begin + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == eventLogEndMarker {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, &EventLogMarkerError{Marker: eventLogEndMarker}
	}
	body := strings.Join(strings.Fields(strings.Join(lines[begin+1:end], "")), "")
	log, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, &EventLogDecodeError{Err: err}
	}
	if len(log) == 0 {
		return nil, ErrEventLogCaptureEmpty
	}
	return log, nil
}
