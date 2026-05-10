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

package encrypt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewCommand(t *testing.T) {
	t.Run("creates command with expected metadata", func(t *testing.T) {
		cmd := NewCommand(nil)
		if cmd == nil {
			t.Fatal("expected non-nil command")
		}
		if cmd.Use != "encrypt" {
			t.Errorf("expected Use=%q, got %q", "encrypt", cmd.Use)
		}
		if cmd.Short == "" {
			t.Error("expected non-empty Short description")
		}
	})

	t.Run("registers expected flags", func(t *testing.T) {
		cmd := NewCommand(nil)

		valueFlag := cmd.Flags().Lookup("value")
		if valueFlag == nil {
			t.Fatal("expected --value flag to be registered")
		}

		fileFlag := cmd.Flags().Lookup("file")
		if fileFlag == nil {
			t.Fatal("expected --file flag to be registered")
		}

		keyIDFlag := cmd.Flags().Lookup("key-id")
		if keyIDFlag == nil {
			t.Fatal("expected --key-id flag to be registered")
		}
		if keyIDFlag.DefValue != DefaultKeyID {
			t.Errorf("expected key-id default=%q, got %q", DefaultKeyID, keyIDFlag.DefValue)
		}
	})
}

func TestDefaultKeyID(t *testing.T) {
	if DefaultKeyID != "platform-config-key" {
		t.Errorf("expected DefaultKeyID=%q, got %q", "platform-config-key", DefaultKeyID)
	}
}

func TestReadPlaintext_Value(t *testing.T) {
	t.Run("reads from value flag", func(t *testing.T) {
		flags := &encryptFlags{value: "my-secret"}
		data, err := readPlaintext(flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "my-secret" {
			t.Errorf("expected %q, got %q", "my-secret", string(data))
		}
	})

	t.Run("prefers value over file when both set", func(t *testing.T) {
		// readPlaintext checks value first; if non-empty it returns immediately.
		flags := &encryptFlags{value: "inline", file: "/should/not/be/read"}
		data, err := readPlaintext(flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "inline" {
			t.Errorf("expected %q, got %q", "inline", string(data))
		}
	})
}

func TestReadPlaintext_File(t *testing.T) {
	t.Run("reads from file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.txt")
		if err := os.WriteFile(path, []byte("file-secret"), 0600); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		flags := &encryptFlags{file: path}
		data, err := readPlaintext(flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "file-secret" {
			t.Errorf("expected %q, got %q", "file-secret", string(data))
		}
	})

	t.Run("reads binary data from file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "binary.dat")
		binaryData := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80}
		if err := os.WriteFile(path, binaryData, 0600); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		flags := &encryptFlags{file: path}
		data, err := readPlaintext(flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != len(binaryData) {
			t.Fatalf("expected %d bytes, got %d", len(binaryData), len(data))
		}
		for i, b := range binaryData {
			if data[i] != b {
				t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, b, data[i])
			}
		}
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		flags := &encryptFlags{file: "/nonexistent/path/to/secret.txt"}
		_, err := readPlaintext(flags)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
		readErr, ok := err.(ErrReadSecretFile)
		if !ok {
			t.Fatalf("expected ErrReadSecretFile, got %T: %v", err, err)
		}
		if readErr.Path != "/nonexistent/path/to/secret.txt" {
			t.Errorf("expected path in error, got %q", readErr.Path)
		}
		if readErr.Cause == nil {
			t.Error("expected non-nil cause in ErrReadSecretFile")
		}
	})

	t.Run("returns error for directory as file", func(t *testing.T) {
		dir := t.TempDir()
		flags := &encryptFlags{file: dir}
		_, err := readPlaintext(flags)
		if err == nil {
			t.Fatal("expected error when file is a directory")
		}
		if _, ok := err.(ErrReadSecretFile); !ok {
			t.Fatalf("expected ErrReadSecretFile, got %T: %v", err, err)
		}
	})
}

func TestRunEncrypt_ValidationErrors(t *testing.T) {
	t.Run("returns error when neither value nor file provided", func(t *testing.T) {
		cmdFlags := &encryptFlags{}
		err := runEncrypt(nil, cmdFlags)
		if err == nil {
			t.Fatal("expected error")
		}
		if _, ok := err.(ErrValueOrFileRequired); !ok {
			t.Fatalf("expected ErrValueOrFileRequired, got %T: %v", err, err)
		}
	})

	t.Run("returns error when both value and file provided", func(t *testing.T) {
		cmdFlags := &encryptFlags{value: "secret", file: "/some/file"}
		err := runEncrypt(nil, cmdFlags)
		if err == nil {
			t.Fatal("expected error")
		}
		if _, ok := err.(ErrValueAndFileMutuallyExclusive); !ok {
			t.Fatalf("expected ErrValueAndFileMutuallyExclusive, got %T: %v", err, err)
		}
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		cmdFlags := &encryptFlags{file: "/nonexistent/secret.txt"}
		err := runEncrypt(nil, cmdFlags)
		if err == nil {
			t.Fatal("expected error")
		}
		if _, ok := err.(ErrReadSecretFile); !ok {
			t.Fatalf("expected ErrReadSecretFile, got %T: %v", err, err)
		}
	})

	t.Run("returns connection error with nil flags", func(t *testing.T) {
		// Valid value, but nil CommonFlags causes NewBaseCommand to fail
		cmdFlags := &encryptFlags{value: "secret"}
		err := runEncrypt(nil, cmdFlags)
		if err == nil {
			t.Fatal("expected error")
		}
		if _, ok := err.(ErrConnectionFailed); !ok {
			t.Fatalf("expected ErrConnectionFailed, got %T: %v", err, err)
		}
	})
}
