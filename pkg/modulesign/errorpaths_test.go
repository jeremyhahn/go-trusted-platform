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

package modulesign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSigner is a crypto.Signer whose behavior is fully scripted, letting tests
// drive the buildDetachedCMS error branches that real keys cannot reach.
type fakeSigner struct {
	pub crypto.PublicKey
	sig []byte
	err error
}

func (f fakeSigner) Public() crypto.PublicKey { return f.pub }

func (f fakeSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return f.sig, f.err
}

func TestTypedErrors(t *testing.T) {
	base := errors.New("underlying cause")
	cases := []struct {
		err     error
		substr  string
		wrapped error
	}{
		{ErrNilSigner{}, "signer is nil", nil},
		{ErrNilCertificate{}, "certificate is nil", nil},
		{ErrUnsupportedCompressionCodec{Path: "/lib/modules/x.ko.xz", Codec: "xz", Dependency: "github.com/ulikunitz/xz"}, "github.com/ulikunitz/xz", nil},
		{ErrUnsupportedCompressionCodec{Path: "/lib/modules/x.ko.lz4", Codec: "lz4"}, "/lib/modules/x.ko.lz4", nil},
		{ErrUnsupportedKeyType{KeyType: "*foo.Key"}, "*foo.Key", nil},
		{ErrModuleRead{Path: "/x.ko", Err: base}, "/x.ko", base},
		{ErrModuleWrite{Path: "/x.ko", Err: base}, "/x.ko", base},
		{ErrDecompress{Path: "/x.ko.gz", Codec: "gzip", Err: base}, "/x.ko.gz", base},
		{ErrCompress{Path: "/x.ko.zst", Codec: "zstd", Err: base}, "recompress", base},
		{ErrSign{Err: base}, "signing failed", base},
		{ErrASN1Marshal{Stage: "content info", Err: base}, "content info", base},
		{ErrEnumerate{Path: "/lib/modules", Err: base}, "/lib/modules", base},
	}
	for _, tc := range cases {
		if msg := tc.err.Error(); !strings.Contains(msg, tc.substr) {
			t.Errorf("%T.Error() = %q, want substring %q", tc.err, msg, tc.substr)
		}
		if !strings.HasPrefix(tc.err.Error(), "modulesign: ") {
			t.Errorf("%T.Error() = %q, want modulesign: prefix", tc.err, tc.err.Error())
		}
		if tc.wrapped != nil && !errors.Is(tc.err, tc.wrapped) {
			t.Errorf("%T does not unwrap to the underlying cause", tc.err)
		}
	}
}

func TestBuildModuleSignatureSignerError(t *testing.T) {
	_, cert := rsaFixture(t)
	signer := fakeSigner{pub: nil, err: errors.New("hsm offline")}

	_, err := BuildModuleSignature([]byte("module"), signer, cert)
	var se ErrSign
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want ErrSign", err)
	}
	if !errors.Is(err, se.Err) || !strings.Contains(err.Error(), "hsm offline") {
		t.Errorf("ErrSign did not wrap the signer error: %v", err)
	}
}

func TestBuildModuleSignatureUnsupportedKey(t *testing.T) {
	_, cert := rsaFixture(t)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	// Sign succeeds (scripted) so the failure surfaces at signatureAlgorithm.
	signer := fakeSigner{pub: edPub, sig: []byte{0x01, 0x02}}

	_, err = BuildModuleSignature([]byte("module"), signer, cert)
	var ue ErrUnsupportedKeyType
	if !errors.As(err, &ue) {
		t.Fatalf("error = %v, want ErrUnsupportedKeyType", err)
	}
}

func TestAtomicWriteErrors(t *testing.T) {
	// CreateTemp failure: the parent directory does not exist.
	t.Run("createtemp", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent", "module.ko")
		err := atomicWrite(missing, []byte("data"), 0o644)
		var we ErrModuleWrite
		if !errors.As(err, &we) {
			t.Fatalf("error = %v, want ErrModuleWrite", err)
		}
	})

	// Rename failure: the destination path is an existing directory, so the
	// temp file is written, closed, and chmod'd, then rename fails with EISDIR.
	t.Run("rename", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "iam-a-directory")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		err := atomicWrite(target, []byte("data"), 0o644)
		var we ErrModuleWrite
		if !errors.As(err, &we) {
			t.Fatalf("error = %v, want ErrModuleWrite", err)
		}
		// The temp file must have been cleaned up on failure.
		entries, readErr := os.ReadDir(filepath.Dir(target))
		if readErr != nil {
			t.Fatalf("ReadDir: %v", readErr)
		}
		for _, e := range entries {
			if e.Name() != "iam-a-directory" {
				t.Errorf("stray temp file left behind: %s", e.Name())
			}
		}
	})
}

// TestSignModuleUnsupportedCodec guards that an xz-compressed module, which has
// no pure-Go codec in the module graph, is reported with a typed error naming
// the dependency that would unblock it and is left untouched on disk.
func TestSignModuleUnsupportedCodec(t *testing.T) {
	key, cert := rsaFixture(t)
	path := filepath.Join(t.TempDir(), "driver.ko.xz")
	original := []byte("\xfd7zXZ\x00 unsupported codec payload")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := SignModule(path, key, cert)
	var ue ErrUnsupportedCompressionCodec
	if !errors.As(err, &ue) {
		t.Fatalf("error = %v, want ErrUnsupportedCompressionCodec", err)
	}
	if ue.Path != path {
		t.Errorf("Path = %s, want %s", ue.Path, path)
	}
	if ue.Codec != "xz" {
		t.Errorf("Codec = %q, want xz", ue.Codec)
	}
	if ue.Dependency != "github.com/ulikunitz/xz" {
		t.Errorf("Dependency = %q, want github.com/ulikunitz/xz", ue.Dependency)
	}

	// The unsupported module must be left exactly as written.
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(got) != string(original) {
		t.Errorf("unsupported module was modified: %q", got)
	}
}

func TestSignModulePropagatesSignerError(t *testing.T) {
	_, cert := rsaFixture(t)
	path := filepath.Join(t.TempDir(), "module.ko")
	if err := os.WriteFile(path, []byte("module"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The module reads fine; the failure must surface from the build step.
	signer := fakeSigner{pub: nil, err: errors.New("token removed")}
	err := SignModule(path, signer, cert)
	var se ErrSign
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want ErrSign", err)
	}

	// On a build failure the original file must be left untouched.
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(got) != "module" {
		t.Errorf("module file was modified on failure: %q", got)
	}
}
