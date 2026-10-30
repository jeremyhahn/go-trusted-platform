// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package secrets

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCov964_FileResolverErrorMessages resolves malformed, missing and
// empty file:// secrets and asserts the typed error and its message.
func TestCov964_FileResolverErrorMessages(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	tests := []struct {
		name    string
		raw     string
		check   func(t *testing.T, err error)
		message string
	}{
		{
			name: "malformed scheme",
			raw:  "notfile:///etc/secret",
			check: func(t *testing.T, err error) {
				var e ErrInvalidFileURI
				if !errors.As(err, &e) {
					t.Fatalf("expected ErrInvalidFileURI, got %T: %v", err, err)
				}
				if e.Raw != "notfile:///etc/secret" {
					t.Errorf("Raw = %q", e.Raw)
				}
			},
			message: `secrets: invalid file URI "notfile:///etc/secret": does not match file:// scheme`,
		},
		{
			name: "empty path",
			raw:  "file://",
			check: func(t *testing.T, err error) {
				var e ErrInvalidFileURI
				if !errors.As(err, &e) {
					t.Fatalf("expected ErrInvalidFileURI, got %T: %v", err, err)
				}
			},
			message: `secrets: invalid file URI "file://": empty path after file:// scheme`,
		},
		{
			name: "missing file",
			raw:  "file://" + missing,
			check: func(t *testing.T, err error) {
				var e ErrFileReadFailed
				if !errors.As(err, &e) {
					t.Fatalf("expected ErrFileReadFailed, got %T: %v", err, err)
				}
				if e.Path != missing {
					t.Errorf("Path = %q, want %q", e.Path, missing)
				}
				if !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("expected errors.Is(err, fs.ErrNotExist) through Unwrap")
				}
			},
			message: `secrets: failed to read file secret "` + missing + `"`,
		},
		{
			name: "empty file",
			raw:  "file://" + empty,
			check: func(t *testing.T, err error) {
				var e ErrFileEmpty
				if !errors.As(err, &e) {
					t.Fatalf("expected ErrFileEmpty, got %T: %v", err, err)
				}
				if e.Path != empty {
					t.Errorf("Path = %q, want %q", e.Path, empty)
				}
			},
			message: `secrets: file secret "` + empty + `" is empty`,
		},
	}

	r := NewFileResolver(nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := r.Resolve(context.Background(), tc.raw)
			if err == nil {
				t.Fatalf("expected an error, got value %v", v)
			}
			tc.check(t, err)
			if !strings.HasPrefix(err.Error(), tc.message) {
				t.Errorf("Error() = %q, want prefix %q", err.Error(), tc.message)
			}
		})
	}
}

// TestCov964_ErrFileReadFailedWithoutCause asserts the message and nil
// Unwrap of a read failure that carries no cause.
func TestCov964_ErrFileReadFailedWithoutCause(t *testing.T) {
	err := ErrFileReadFailed{Path: "/secret"}
	if got, want := err.Error(), `secrets: failed to read file secret "/secret"`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
	}
}

// cov964CtxErr is a context error that is neither Canceled nor
// DeadlineExceeded.
type cov964CtxErr struct{}

func (cov964CtxErr) Error() string { return "cov964 context error" }

// cov964Context reports done from the doneAfter-th call to Done onward,
// with err as its Err.
type cov964Context struct {
	context.Context
	calls     atomic.Int32
	doneAfter int32
	err       error
	closed    chan struct{}
	open      chan struct{}
}

func newCov964Context(doneAfter int32, err error) *cov964Context {
	closed := make(chan struct{})
	close(closed)
	return &cov964Context{
		Context:   context.Background(),
		doneAfter: doneAfter,
		err:       err,
		closed:    closed,
		open:      make(chan struct{}),
	}
}

func (c *cov964Context) Done() <-chan struct{} {
	if c.calls.Add(1) >= c.doneAfter {
		return c.closed
	}
	return c.open
}

func (c *cov964Context) Err() error {
	if c.calls.Load() >= c.doneAfter {
		return c.err
	}
	return nil
}

// TestCov964_CheckContextUnknownErr asserts that a done context with an
// error other than Canceled or DeadlineExceeded maps to ErrContextCanceled.
func TestCov964_CheckContextUnknownErr(t *testing.T) {
	err := checkContext(newCov964Context(1, cov964CtxErr{}))
	var canceled ErrContextCanceled
	if !errors.As(err, &canceled) {
		t.Fatalf("expected ErrContextCanceled, got %T: %v", err, err)
	}
	if canceled.Reason != "cov964 context error" {
		t.Errorf("Reason = %q", canceled.Reason)
	}
	if checkContext(newCov964Context(2, cov964CtxErr{})) != nil {
		t.Errorf("expected nil for a context that is not done")
	}
}

// cov964Decrypter decrypts with a real RSA key, as the IDevID key does,
// and then runs after (used to cancel the caller's context mid-call).
type cov964Decrypter struct {
	key   *rsa.PrivateKey
	after func()
}

func (d *cov964Decrypter) Public() crypto.PublicKey { return d.key.Public() }

func (d *cov964Decrypter) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	plaintext, err := d.key.Decrypt(r, msg, opts)
	if d.after != nil {
		d.after()
	}
	return plaintext, err
}

func cov964Encrypt(t *testing.T, key *rsa.PrivateKey, plaintext string) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return "idevid:" + base64.StdEncoding.EncodeToString(ct)
}

// TestCov964_IDevIDResolveContextChecks asserts that Resolve returns the
// context error when the context ends before or after decryption.
func TestCov964_IDevIDResolveContextChecks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	raw := cov964Encrypt(t, key, "s3cret")

	t.Run("succeeds with a live context", func(t *testing.T) {
		r := NewIDevIDResolver(&cov964Decrypter{key: key}, nil)
		v, err := r.Resolve(context.Background(), raw)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v == nil {
			t.Fatalf("Resolve returned a nil value")
		}
		if err := v.WithBytes(func(plaintext []byte) error {
			if string(plaintext) != "s3cret" {
				t.Errorf("plaintext = %q, want %q", plaintext, "s3cret")
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytes: %v", err)
		}
	})

	t.Run("cancelled before resolve", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := NewIDevIDResolver(&cov964Decrypter{key: key}, nil)
		_, err := r.Resolve(ctx, raw)
		var canceled ErrContextCanceled
		if !errors.As(err, &canceled) {
			t.Fatalf("expected ErrContextCanceled, got %T: %v", err, err)
		}
		if canceled.Reason != context.Canceled.Error() {
			t.Errorf("Reason = %q, want %q", canceled.Reason, context.Canceled.Error())
		}
	})

	t.Run("cancelled before decryption", func(t *testing.T) {
		called := false
		dec := &cov964Decrypter{key: key, after: func() { called = true }}
		r := NewIDevIDResolver(dec, nil)
		_, err := r.Resolve(newCov964Context(2, context.Canceled), raw)
		var canceled ErrContextCanceled
		if !errors.As(err, &canceled) {
			t.Fatalf("expected ErrContextCanceled, got %T: %v", err, err)
		}
		if called {
			t.Errorf("decrypter ran after the context was cancelled")
		}
	})

	t.Run("cancelled during decryption", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := NewIDevIDResolver(&cov964Decrypter{key: key, after: cancel}, nil)
		v, err := r.Resolve(ctx, raw)
		if v != nil {
			t.Errorf("expected no value after cancellation, got %v", v)
		}
		var canceled ErrContextCanceled
		if !errors.As(err, &canceled) {
			t.Fatalf("expected ErrContextCanceled, got %T: %v", err, err)
		}
	})
}
