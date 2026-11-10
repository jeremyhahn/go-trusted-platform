package memguard

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
)

// seam964Error is the host failure a swapped seam returns.
type seam964Error struct{ msg string }

func (e seam964Error) Error() string { return e.msg }

// seam964Info is a regular-file os.FileInfo of a fixed size.
type seam964Info struct{ size int64 }

func (i seam964Info) Name() string       { return "secret" }
func (i seam964Info) Size() int64        { return i.size }
func (i seam964Info) Mode() os.FileMode  { return 0o600 }
func (i seam964Info) ModTime() time.Time { return time.Time{} }
func (i seam964Info) IsDir() bool        { return false }
func (i seam964Info) Sys() any           { return nil }

// seam964File is an in-memory enclaveFile whose Stat, Read and Seek can
// each be made to fail, and whose Seek can report a grown file.
type seam964File struct {
	data    *bytes.Reader
	size    int64
	statErr error
	seekErr error
	seekEnd int64
}

func (f *seam964File) Read(p []byte) (int, error) { return f.data.Read(p) }
func (f *seam964File) Close() error               { return nil }

func (f *seam964File) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return seam964Info{size: f.size}, nil
}

func (f *seam964File) Seek(int64, int) (int64, error) {
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return f.seekEnd, nil
}

// swapLockBuffer makes every lock fail and records the bytes it was
// handed, so a test can assert the caller wiped them afterwards.
func swapLockBuffer(t *testing.T) *[]byte {
	t.Helper()
	var seen []byte
	orig := lockBuffer
	lockBuffer = func(b []byte) (*secure.Buffer, error) {
		seen = b
		return nil, seam964Error{msg: "mlock: cannot allocate memory"}
	}
	t.Cleanup(func() { lockBuffer = orig })
	return &seen
}

func swapOpenFile(t *testing.T, f enclaveFile) {
	t.Helper()
	orig := openFile
	openFile = func(string) (enclaveFile, error) { return f, nil }
	t.Cleanup(func() { openFile = orig })
}

func assertWiped(t *testing.T, b []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("lock seam was not handed the plaintext")
	}
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("plaintext not wiped after lock failure: %x", b)
	}
}

func assertLockFailed(t *testing.T, err error) {
	t.Helper()
	var lockErr ErrLockFailed
	if !errors.As(err, &lockErr) {
		t.Fatalf("error = %v (%T), want ErrLockFailed", err, err)
	}
	if lockErr.Reason != "mlock: cannot allocate memory" {
		t.Fatalf("ErrLockFailed.Reason = %q", lockErr.Reason)
	}
}

func TestSeam964NewMemoryEnclaveLockFailure(t *testing.T) {
	swapLockBuffer(t)

	e := NewMemoryEnclave([]byte("secret"))
	if e.IsAlive() {
		t.Fatal("enclave whose lock failed reports alive")
	}
	called := false
	err := e.Open(func([]byte) error { called = true; return nil })
	assertLockFailed(t, err)
	if called {
		t.Fatal("Open lent the plaintext of an unlocked enclave")
	}
}

func TestSeam964NewRandomMemoryEnclaveLockFailure(t *testing.T) {
	seen := swapLockBuffer(t)

	e, err := NewRandomMemoryEnclave(16)
	assertLockFailed(t, err)
	if e != nil {
		t.Fatal("enclave returned on lock failure")
	}
	assertWiped(t, *seen)
}

func TestSeam964NewRandomMemoryEnclaveRandomFailure(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, seam964Error{msg: "getrandom: no entropy"} }
	t.Cleanup(func() { randRead = orig })

	e, err := NewRandomMemoryEnclave(16)
	var randErr ErrRandomSource
	if !errors.As(err, &randErr) {
		t.Fatalf("error = %v (%T), want ErrRandomSource", err, err)
	}
	if randErr.Reason != "getrandom: no entropy" {
		t.Fatalf("ErrRandomSource.Reason = %q", randErr.Reason)
	}
	if e != nil {
		t.Fatal("enclave returned on random-source failure")
	}
}

func TestSeam964NewMemoryEnclaveFromFileLockFailure(t *testing.T) {
	seen := swapLockBuffer(t)
	swapOpenFile(t, &seam964File{data: bytes.NewReader([]byte("secret")), size: 6, seekEnd: 6})

	e, err := NewMemoryEnclaveFromFile("/seam/secret")
	assertLockFailed(t, err)
	if e != nil {
		t.Fatal("enclave returned on lock failure")
	}
	assertWiped(t, *seen)
}

func TestSeam964NewMemoryEnclaveFromFileHostFailure(t *testing.T) {
	tests := []struct {
		name   string
		file   *seam964File
		reason string
	}{
		{
			name:   "stat fails",
			file:   &seam964File{data: bytes.NewReader(nil), statErr: seam964Error{msg: "stat: EIO"}},
			reason: "stat: EIO",
		},
		{
			name:   "file shrinks before the read",
			file:   &seam964File{data: bytes.NewReader([]byte("abc")), size: 6, seekEnd: 3},
			reason: io.ErrUnexpectedEOF.Error(),
		},
		{
			name:   "seek fails",
			file:   &seam964File{data: bytes.NewReader([]byte("secret")), size: 6, seekErr: seam964Error{msg: "lseek: EIO"}},
			reason: "lseek: EIO",
		},
		{
			name:   "file grows while being read",
			file:   &seam964File{data: bytes.NewReader([]byte("secret!")), size: 6, seekEnd: 7},
			reason: "file changed while being read",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapOpenFile(t, tt.file)

			e, err := NewMemoryEnclaveFromFile("/seam/secret")
			var fileErr ErrFileUnreadable
			if !errors.As(err, &fileErr) {
				t.Fatalf("error = %v (%T), want ErrFileUnreadable", err, err)
			}
			if fileErr.Path != "/seam/secret" || fileErr.Reason != tt.reason {
				t.Fatalf("ErrFileUnreadable = %+v, want path /seam/secret reason %q", fileErr, tt.reason)
			}
			if e != nil {
				t.Fatal("enclave returned on file failure")
			}
		})
	}
}

func TestSeam964ResetLockFailure(t *testing.T) {
	e := NewMemoryEnclave([]byte("old"))
	swapLockBuffer(t)

	err := e.UnmarshalJSON([]byte(`"new-secret"`))
	assertLockFailed(t, err)
	if e.IsAlive() {
		t.Fatal("enclave whose re-lock failed reports alive")
	}
	assertLockFailed(t, e.Open(func([]byte) error { return nil }))
}
