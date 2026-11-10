package prompt

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// cov964Pipe returns both ends of an os.Pipe, closed when the test ends.
// A pipe is never a terminal, so term.ReadPassword fails on it at once.
func cov964Pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("close read end: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("close write end: %v", err)
		}
	})
	return r, w
}

func TestCov964TermPasswordReader_NonTerminalFails(t *testing.T) {
	r, _ := cov964Pipe(t)

	reader := &TermPasswordReader{}
	password, err := reader.ReadPassword(int(r.Fd()))
	if err == nil {
		t.Fatal("ReadPassword on a pipe returned no error")
	}
	if password != nil {
		t.Errorf("ReadPassword returned %q with an error, want nil", password)
	}
}

func TestCov964Prompter_DefaultPasswordReaderWrapsTerminalError(t *testing.T) {
	r, _ := cov964Pipe(t)
	var out bytes.Buffer

	// NewPrompter's default password reader is the terminal reader.
	p := NewPrompter(WithWriter(&out), WithStdinFd(int(r.Fd())))
	password, err := p.KeyPassword()

	var readErr *PasswordReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("KeyPassword error = %v, want *PasswordReadError", err)
	}
	if readErr.Unwrap() == nil {
		t.Error("PasswordReadError carries no underlying terminal error")
	}
	if password != nil {
		t.Errorf("KeyPassword returned %q with an error, want nil", password)
	}
	if got, want := out.String(), "Key Password: \n"+userPrompt; got != want {
		t.Errorf("prompt output = %q, want %q", got, want)
	}
}
