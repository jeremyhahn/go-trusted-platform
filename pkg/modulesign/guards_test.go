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
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildModuleSignatureMarshalError guards that a malformed certificate (a
// nil serial number, which cannot be DER-encoded) surfaces a typed error rather
// than panicking inside the ASN.1 encoder.
func TestBuildModuleSignatureMarshalError(t *testing.T) {
	key, _ := rsaFixture(t)
	cert := &x509.Certificate{RawIssuer: []byte{0x30, 0x00}} // SerialNumber is nil.

	_, err := BuildModuleSignature([]byte("module"), key, cert)
	var ae ErrASN1Marshal
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want ErrASN1Marshal", err)
	}
}

// TestSignModuleUnreadable guards that a path that stats successfully but cannot
// be read as a file (here, a directory) yields ErrModuleRead.
func TestSignModuleUnreadable(t *testing.T) {
	key, cert := rsaFixture(t)
	dir := filepath.Join(t.TempDir(), "notafile.ko")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	err := SignModule(dir, key, cert)
	var re ErrModuleRead
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want ErrModuleRead", err)
	}
}
