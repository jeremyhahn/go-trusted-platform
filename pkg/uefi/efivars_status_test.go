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

package uefi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBoolVar writes a 1-byte boolean efivar fixture (4-byte attribute word
// followed by the value byte) into dir.
func writeBoolVar(t *testing.T, dir, name string, value byte) {
	t.Helper()
	data := make([]byte, 5)
	binary.LittleEndian.PutUint32(data[0:4], SecureBootAttributes)
	data[4] = value
	path := filepath.Join(dir, efivarFileName(name, EFIGlobalVariable))
	require.NoError(t, os.WriteFile(path, data, 0644))
}

// writeCertVar writes a signature database efivar fixture holding one X.509
// EFI_SIGNATURE_LIST into dir.
func writeCertVar(t *testing.T, dir, name string, vendor GUID, certDER []byte) {
	t.Helper()
	esl := NewSignatureListFromCert(certDER, TrustedPlatformGUID).Bytes()
	data := make([]byte, 4, 4+len(esl))
	binary.LittleEndian.PutUint32(data[0:4], SecureBootAttributes)
	data = append(data, esl...)
	path := filepath.Join(dir, efivarFileName(name, vendor))
	require.NoError(t, os.WriteFile(path, data, 0644))
}

// TestReadSecureBootStatusFromDir_SetupMode asserts a Setup-Mode fixture (no
// keys enrolled) is reported as setup mode with all databases absent.
func TestReadSecureBootStatusFromDir_SetupMode(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x01)
	writeBoolVar(t, dir, "SecureBoot", 0x00)

	status, err := ReadSecureBootStatusFromDir(dir)
	require.NoError(t, err)
	assert.True(t, status.EfivarsAvailable)
	assert.True(t, status.SetupMode)
	assert.False(t, status.SecureBoot)
	assert.False(t, status.UserMode)
	assert.False(t, status.PK.Present)
	assert.False(t, status.KEK.Present)
	assert.False(t, status.DB.Present)
	assert.False(t, status.DBX.Present)
}

// TestReadSecureBootStatusFromDir_Enrolled asserts an enrolled fixture reports
// user mode, enforced Secure Boot, and per-database certificate summaries with
// subjects.
func TestReadSecureBootStatusFromDir_Enrolled(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x00)
	writeBoolVar(t, dir, "SecureBoot", 0x01)

	pk := testSelfSignedCert(t, "Test PK")
	kek := testSelfSignedCert(t, "Test KEK")
	db := testSelfSignedCert(t, "Test DB")
	writeCertVar(t, dir, "PK", EFIGlobalVariable, pk.Raw)
	writeCertVar(t, dir, "KEK", EFIGlobalVariable, kek.Raw)
	writeCertVar(t, dir, "db", EFIImageSecurityDatabase, db.Raw)

	status, err := ReadSecureBootStatusFromDir(dir)
	require.NoError(t, err)
	assert.True(t, status.SecureBoot)
	assert.False(t, status.SetupMode)
	assert.True(t, status.UserMode)

	assert.True(t, status.PK.Present)
	assert.Equal(t, 1, status.PK.Certificates)
	require.Len(t, status.PK.Subjects, 1)
	assert.Contains(t, status.PK.Subjects[0], "Test PK")

	assert.True(t, status.KEK.Present)
	assert.Equal(t, 1, status.KEK.Certificates)
	assert.True(t, status.DB.Present)
	assert.Equal(t, 1, status.DB.Certificates)
	require.Len(t, status.DB.Subjects, 1)
	assert.Contains(t, status.DB.Subjects[0], "Test DB")
	assert.False(t, status.DBX.Present)
}

// TestReadSecureBootStatusFromDir_DBXHashes asserts SHA-256 hash entries in
// dbx are counted as hashes, not certificates.
func TestReadSecureBootStatusFromDir_DBXHashes(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x00)
	writeBoolVar(t, dir, "SecureBoot", 0x01)

	hash := sha256.Sum256([]byte("revoked image"))
	esl := NewSignatureListFromHash(hash[:], EFISHA256, TrustedPlatformGUID).Bytes()
	data := make([]byte, 4, 4+len(esl))
	binary.LittleEndian.PutUint32(data[0:4], SecureBootAttributes)
	data = append(data, esl...)
	path := filepath.Join(dir, efivarFileName("dbx", EFIImageSecurityDatabase))
	require.NoError(t, os.WriteFile(path, data, 0644))

	status, err := ReadSecureBootStatusFromDir(dir)
	require.NoError(t, err)
	assert.True(t, status.DBX.Present)
	assert.Equal(t, 0, status.DBX.Certificates)
	assert.Equal(t, 1, status.DBX.Hashes)
}

// TestReadSecureBootStatusFromDir_MissingDir asserts a missing efivarfs
// directory yields ErrEfivarsUnavailable.
func TestReadSecureBootStatusFromDir_MissingDir(t *testing.T) {
	_, err := ReadSecureBootStatusFromDir(filepath.Join(t.TempDir(), "nonexistent"))
	assert.ErrorIs(t, err, ErrEfivarsUnavailable)
}

// TestReadSecureBootStatusFromDir_MalformedBoolVar asserts a truncated boolean
// variable produces a typed ErrEfivarRead identifying the variable.
func TestReadSecureBootStatusFromDir_MalformedBoolVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable))
	require.NoError(t, os.WriteFile(path, []byte{0x00, 0x01}, 0644))

	_, err := ReadSecureBootStatusFromDir(dir)
	var readErr *ErrEfivarRead
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "SetupMode", readErr.Var)
}

// TestReadSecureBootStatusFromDir_MalformedESL asserts a corrupt signature
// list yields a typed ErrEfivarRead identifying the database.
func TestReadSecureBootStatusFromDir_MalformedESL(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x01)
	writeBoolVar(t, dir, "SecureBoot", 0x00)

	// Attribute word plus garbage that cannot be an EFI_SIGNATURE_LIST.
	garbage := []byte{0x07, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01}
	path := filepath.Join(dir, efivarFileName("PK", EFIGlobalVariable))
	require.NoError(t, os.WriteFile(path, garbage, 0644))

	_, err := ReadSecureBootStatusFromDir(dir)
	var readErr *ErrEfivarRead
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "PK", readErr.Var)
}

// TestReadSecureBootStatusFromDir_TruncatedVar asserts a variable shorter than
// the 4-byte attribute word is rejected with ErrInvalidFormat.
func TestReadSecureBootStatusFromDir_TruncatedVar(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x01)
	writeBoolVar(t, dir, "SecureBoot", 0x00)

	path := filepath.Join(dir, efivarFileName("db", EFIImageSecurityDatabase))
	require.NoError(t, os.WriteFile(path, []byte{0x07}, 0644))

	_, err := ReadSecureBootStatusFromDir(dir)
	var readErr *ErrEfivarRead
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "db", readErr.Var)
	assert.True(t, errors.Is(err, ErrInvalidFormat))
}

// TestReadSecureBootStatus_RealPathBehavior asserts the standard-path reader
// either returns a coherent status (UEFI host) or ErrEfivarsUnavailable
// (non-UEFI host) — never a nil status without an error.
func TestReadSecureBootStatus_RealPathBehavior(t *testing.T) {
	status, err := ReadSecureBootStatus()
	if err != nil {
		assert.ErrorIs(t, err, ErrEfivarsUnavailable)
		assert.Nil(t, status)
		return
	}
	require.NotNil(t, status)
	assert.True(t, status.EfivarsAvailable)
}

// TestEnrollKeysToEfivarsDir_Happy asserts the guarded directory enroll writes
// db, KEK, and PK when the fixture reports Setup Mode.
func TestEnrollKeysToEfivarsDir_Happy(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x01)

	pk := testSelfSignedCert(t, "PK")
	kek := testSelfSignedCert(t, "KEK")
	db := testSelfSignedCert(t, "DB")

	err := EnrollKeysToEfivarsDir(context.Background(), dir, pk, kek, db, NewEFITime(fixedTestTime))
	require.NoError(t, err)

	for _, name := range []struct {
		varName string
		vendor  GUID
	}{
		{"db", EFIImageSecurityDatabase},
		{"KEK", EFIGlobalVariable},
		{"PK", EFIGlobalVariable},
	} {
		_, statErr := os.Stat(filepath.Join(dir, efivarFileName(name.varName, name.vendor)))
		assert.NoError(t, statErr, "expected %s to be written", name.varName)
	}

	// The write must round-trip through the status reader.
	status, err := ReadSecureBootStatusFromDir(dir)
	require.NoError(t, err)
	assert.True(t, status.PK.Present)
	assert.True(t, status.KEK.Present)
	assert.True(t, status.DB.Present)
	assert.Equal(t, 1, status.DB.Certificates)
}

// TestEnrollKeysToEfivarsDir_NotSetupMode asserts the directory enroll refuses
// to write when the fixture is not in Setup Mode.
func TestEnrollKeysToEfivarsDir_NotSetupMode(t *testing.T) {
	dir := t.TempDir()
	writeBoolVar(t, dir, "SetupMode", 0x00)

	pk := testSelfSignedCert(t, "PK")
	err := EnrollKeysToEfivarsDir(context.Background(), dir, pk, pk, pk, NewEFITime(fixedTestTime))
	assert.ErrorIs(t, err, ErrNotSetupMode)

	_, statErr := os.Stat(filepath.Join(dir, efivarFileName("db", EFIImageSecurityDatabase)))
	assert.True(t, os.IsNotExist(statErr), "db must not be written outside setup mode")
}

// TestEnrollKeysToEfivarsDir_MissingDir asserts a missing directory yields
// ErrEfivarsUnavailable.
func TestEnrollKeysToEfivarsDir_MissingDir(t *testing.T) {
	pk := testSelfSignedCert(t, "PK")
	err := EnrollKeysToEfivarsDir(context.Background(), filepath.Join(t.TempDir(), "missing"),
		pk, pk, pk, NewEFITime(fixedTestTime))
	assert.ErrorIs(t, err, ErrEfivarsUnavailable)
}

// TestEnrollKeysToEfivarsDir_MalformedSetupMode asserts a corrupt SetupMode
// variable is surfaced as a typed read error instead of being treated as
// "not setup mode".
func TestEnrollKeysToEfivarsDir_MalformedSetupMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable))
	require.NoError(t, os.WriteFile(path, []byte{0x01, 0x02}, 0644))

	pk := testSelfSignedCert(t, "PK")
	err := EnrollKeysToEfivarsDir(context.Background(), dir, pk, pk, pk, NewEFITime(fixedTestTime))
	var readErr *ErrEfivarRead
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "SetupMode", readErr.Var)
}
