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

package luks

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
)

func TestManagerWithLogger(t *testing.T) {
	logger := logging.DefaultLogger()
	m, err := NewManager(logger, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestBuildFormatOptionsNilEncryption(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		// No encryption config
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	// Should still create valid options with defaults
	if opts.Device != "/dev/test" {
		t.Errorf("expected device /dev/test, got %s", opts.Device)
	}
	if opts.Label != "root-partition" {
		t.Errorf("expected label root-partition, got %s", opts.Label)
	}
}

func TestBuildFormatOptionsEmptyLUKS(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS:    &drive.LUKSConfig{},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	// Zero-valued LUKS fields leave go-luks2's defaults in place.
	if opts.Cipher != "" || opts.CipherMode != "" {
		t.Errorf("expected empty cipher and mode, got %q/%q", opts.Cipher, opts.CipherMode)
	}
	if opts.KeySize != 0 {
		t.Errorf("expected key size 0 (default), got %d", opts.KeySize)
	}
	if opts.HashAlgo != "" {
		t.Errorf("expected empty hash algo, got %s", opts.HashAlgo)
	}
	if opts.KDFType != "" {
		t.Errorf("expected empty KDF type, got %s", opts.KDFType)
	}
	if opts.Argon2Memory != 0 || opts.Argon2Time != 0 || opts.Argon2Parallel != 0 {
		t.Errorf("expected zero argon2 values, got %d/%d/%d", opts.Argon2Memory, opts.Argon2Time, opts.Argon2Parallel)
	}
}
