package uefi

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

var cov964Cause = errors.New("cov964 cause")

// TestCov964_TypedErrorMessagesAndUnwrap checks each typed error renders its
// message from its fields and unwraps to the cause it carries.
func TestCov964_TypedErrorMessagesAndUnwrap(t *testing.T) {
	sentinel := errors.New("cov964 sentinel")
	tests := []struct {
		name    string
		err     error
		wantMsg string
		causes  []error
	}{
		{
			name:    "ErrEnrollWrite",
			err:     &ErrEnrollWrite{Var: "db", Cause: cov964Cause},
			wantMsg: "uefi: failed to write secure boot variable db: cov964 cause",
			causes:  []error{cov964Cause},
		},
		{
			name:    "ErrUKIVerify",
			err:     &ErrUKIVerify{Cause: cov964Cause},
			wantMsg: "uefi: signed uki verification failed: cov964 cause",
			causes:  []error{cov964Cause},
		},
		{
			name:    "ErrEfivarRead",
			err:     &ErrEfivarRead{Var: "SetupMode", Cause: cov964Cause},
			wantMsg: "uefi: failed to read efi variable SetupMode: cov964 cause",
			causes:  []error{cov964Cause},
		},
		{
			name:    "SentinelCauseError",
			err:     &SentinelCauseError{Sentinel: sentinel, Cause: cov964Cause},
			wantMsg: "cov964 sentinel: cov964 cause",
			causes:  []error{sentinel, cov964Cause},
		},
		{
			name:    "WrappedError",
			err:     &WrappedError{Msg: "cov964 context", Err: cov964Cause},
			wantMsg: "cov964 context: cov964 cause",
			causes:  []error{cov964Cause},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.wantMsg)
			}
			for _, cause := range tt.causes {
				if !errors.Is(tt.err, cause) {
					t.Fatalf("errors.Is(%v, %v) = false", tt.err, cause)
				}
			}
			if errors.Is(tt.err, errors.New("cov964 unrelated")) {
				t.Fatal("errors.Is matched an unrelated error")
			}
		})
	}
}

// TestCov964_TypedErrorsAs checks errors.As recovers each typed error and its
// fields through an outer wrapper.
func TestCov964_TypedErrorsAs(t *testing.T) {
	outer := &WrappedError{Msg: "outer", Err: &ErrEnrollWrite{Var: "KEK", Cause: cov964Cause}}
	var enrollErr *ErrEnrollWrite
	if !errors.As(outer, &enrollErr) {
		t.Fatal("errors.As did not find *ErrEnrollWrite")
	}
	if enrollErr.Var != "KEK" {
		t.Fatalf("Var = %q, want KEK", enrollErr.Var)
	}

	var readErr *ErrEfivarRead
	if errors.As(outer, &readErr) {
		t.Fatal("errors.As found *ErrEfivarRead in a chain that has none")
	}
}

// TestCov964_ReadEfivarBoolFile covers the missing-variable and unreadable
// variable branches against an efivarfs-layout directory.
func TestCov964_ReadEfivarBoolFile(t *testing.T) {
	dir := t.TempDir()

	got, err := readEfivarBoolFile(filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable)))
	if err != nil {
		t.Fatalf("missing variable: unexpected error %v", err)
	}
	if got {
		t.Fatal("missing variable must read as false")
	}

	// A directory where the variable file belongs cannot be read.
	if _, err := readEfivarBoolFile(dir); err == nil {
		t.Fatal("reading a directory as a variable must fail")
	}
}

// TestCov964_WriteAuthenticatedVarFileFailure checks a write to a target that
// cannot be created returns ErrEnrollWrite naming the variable and its cause.
func TestCov964_WriteAuthenticatedVarFileFailure(t *testing.T) {
	name := efivarFileName("db", EFIImageSecurityDatabase)
	path := filepath.Join(t.TempDir(), "missing-dir", name)

	err := writeAuthenticatedVarFile(path, []byte{0x07, 0, 0, 0})
	var enrollErr *ErrEnrollWrite
	if !errors.As(err, &enrollErr) {
		t.Fatalf("err = %v, want *ErrEnrollWrite", err)
	}
	if enrollErr.Var != name {
		t.Fatalf("Var = %q, want %q", enrollErr.Var, name)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("cause = %v, want fs.ErrNotExist", enrollErr.Cause)
	}
}

// TestCov964_ParseGUIDMalformed checks each malformed GUID segment is
// rejected with a MessageError naming that segment.
func TestCov964_ParseGUIDMalformed(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMsg string
	}{
		{"too few parts", "8be4df61-93ca-11d2-aa0d", "expected 5 parts, got 4"},
		{"bad Data1", "zze4df61-93ca-11d2-aa0d-00e098032b8c", "invalid GUID Data1"},
		{"bad Data2", "8be4df61-93c-11d2-aa0d-00e098032b8c", "invalid GUID Data2"},
		{"bad Data3", "8be4df61-93ca-11dz-aa0d-00e098032b8c", "invalid GUID Data3"},
		{"bad Data4a", "8be4df61-93ca-11d2-aa-00e098032b8c", "invalid GUID Data4a"},
		{"bad Data4b", "8be4df61-93ca-11d2-aa0d-00e098032b", "invalid GUID Data4b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseGUID(tt.input)
			var msgErr *MessageError
			if !errors.As(err, &msgErr) {
				t.Fatalf("err = %v, want *MessageError", err)
			}
			if !strings.Contains(msgErr.Msg, tt.wantMsg) {
				t.Fatalf("Msg = %q, want it to contain %q", msgErr.Msg, tt.wantMsg)
			}
		})
	}

	g, err := ParseGUID("{8be4df61-93ca-11d2-aa0d-00e098032b8c}")
	if err != nil {
		t.Fatalf("valid GUID: %v", err)
	}
	if g != EFIGlobalVariable {
		t.Fatalf("ParseGUID = %v, want EFIGlobalVariable", g)
	}
}
