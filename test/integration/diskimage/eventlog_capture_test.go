//go:build integration

package diskimage

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
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

func TestConsoleCredentialsFromEnv(t *testing.T) {
	got := consoleCredentialsFromEnv(lookup(nil))
	if want := (consoleCredentials{login: "root", password: "password"}); got != want {
		t.Fatalf("empty env: got %+v, want %+v", got, want)
	}
	got = consoleCredentialsFromEnv(lookup(map[string]string{
		"DISKIMAGE_CONSOLE_LOGIN":    "ops",
		"DISKIMAGE_CONSOLE_PASSWORD": "s3cret",
	}))
	if want := (consoleCredentials{login: "ops", password: "s3cret"}); got != want {
		t.Fatalf("set env: got %+v, want %+v", got, want)
	}
}

func TestManifestRootsFromEnv(t *testing.T) {
	path, err := manifestRootsFromEnv(lookup(map[string]string{"DISKIMAGE_MANIFEST_ROOTS": "/workspace/roots.pem"}))
	if err != nil || path != "/workspace/roots.pem" {
		t.Fatalf("set: got %q, %v", path, err)
	}
	_, err = manifestRootsFromEnv(lookup(nil))
	var missing *MissingInputError
	if !errors.As(err, &missing) {
		t.Fatalf("unset: got %v, want a *MissingInputError", err)
	}
	if missing.Variable != "DISKIMAGE_MANIFEST_ROOTS" {
		t.Fatalf("unset: Variable = %q", missing.Variable)
	}
}

// fakeConsole shows a Password: prompt after the first line when prompt is
// set; otherwise Expect waits for its context to end.
type fakeConsole struct {
	prompt  bool
	sent    []string
	sendErr error
}

func (f *fakeConsole) SendLine(text string) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, text)
	return nil
}

func (f *fakeConsole) Expect(ctx context.Context, needle string) (string, error) {
	if f.prompt && len(f.sent) == 1 {
		return "login: root\r\nPassword:", nil
	}
	<-ctx.Done()
	return "", &harness.ConsoleTimeoutError{Needle: needle}
}

func TestLoginAtConsole(t *testing.T) {
	cred := consoleCredentials{login: "root", password: "password"}

	t.Run("prompt", func(t *testing.T) {
		c := &fakeConsole{prompt: true}
		if err := loginAtConsole(context.Background(), c, cred, time.Second); err != nil {
			t.Fatal(err)
		}
		if want := []string{"root", "password"}; !slicesEqual(c.sent, want) {
			t.Fatalf("sent %q, want %q", c.sent, want)
		}
	})
	t.Run("no prompt", func(t *testing.T) {
		c := &fakeConsole{}
		if err := loginAtConsole(context.Background(), c, cred, 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if want := []string{"root"}; !slicesEqual(c.sent, want) {
			t.Fatalf("sent %q, want %q", c.sent, want)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := loginAtConsole(ctx, &fakeConsole{}, cred, time.Second); err == nil {
			t.Fatal("a cancelled context logged in")
		}
	})
	t.Run("send fails", func(t *testing.T) {
		sendErr := errors.New("console closed")
		err := loginAtConsole(context.Background(), &fakeConsole{sendErr: sendErr}, cred, time.Second)
		if !errors.Is(err, sendErr) {
			t.Fatalf("got %v, want %v", err, sendErr)
		}
	})
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
