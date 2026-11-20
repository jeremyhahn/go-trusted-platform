//go:build integration

package diskimage

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeEventLogCapture checks the helper that pulls a guest's TCG event
// log out of a serial console transcript, where the guest printed it base64
// encoded between an EVENTLOG-BEGIN and an EVENTLOG-END line.
func TestDecodeEventLogCapture(t *testing.T) {
	log := make([]byte, 300)
	for i := range log {
		log[i] = byte(i * 7)
	}
	encoded := base64.StdEncoding.EncodeToString(log)
	wrapped := wrapLines(encoded, 76)
	command := "echo EVENTLOG-BEGIN; base64 /sys/kernel/security/tpm0/binary_bios_measurements; echo EVENTLOG-END"

	tests := []struct {
		name       string
		transcript string
		want       []byte
		wantErr    bool
	}{
		{
			name:       "a clean capture round-trips the bytes",
			transcript: "EVENTLOG-BEGIN\n" + encoded + "\nEVENTLOG-END\n",
			want:       log,
		},
		{
			name: "wrapped lines with CRLF decode",
			transcript: "\r\nEVENTLOG-BEGIN\r\n" +
				strings.ReplaceAll(wrapped, "\n", "\r\n") +
				"\r\nEVENTLOG-END\r\n# ",
			want: log,
		},
		{
			name: "the echoed command line is not mistaken for the markers",
			transcript: "root@gtp:~# " + command + "\r\n" +
				"EVENTLOG-BEGIN\r\n" + wrapped + "\r\nEVENTLOG-END\r\nroot@gtp:~# ",
			want: log,
		},
		{
			name:       "no BEGIN marker is an error",
			transcript: "root@gtp:~# " + command + "\r\n" + encoded + "\r\nEVENTLOG-END\r\n",
			wantErr:    true,
		},
		{
			name:       "no END marker is an error",
			transcript: "root@gtp:~# " + command + "\r\nEVENTLOG-BEGIN\r\n" + encoded + "\r\n",
			wantErr:    true,
		},
		{
			name:       "bad base64 is an error",
			transcript: "EVENTLOG-BEGIN\n!!not base64!!\nEVENTLOG-END\n",
			wantErr:    true,
		},
		{
			name:       "an empty body is an error",
			transcript: "EVENTLOG-BEGIN\r\n\r\nEVENTLOG-END\r\n",
			wantErr:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeEventLogCapture(tc.transcript)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeEventLogCapture: got %d bytes and no error, want an error", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeEventLogCapture: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("decodeEventLogCapture: got %d bytes, want the %d logged bytes", len(got), len(tc.want))
			}
		})
	}
}

// wrapLines splits s into lines of at most n characters, the way base64(1)
// wraps its output.
func wrapLines(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n])
		b.WriteByte('\n')
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}
