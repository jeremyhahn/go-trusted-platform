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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fixedTestTime is a deterministic timestamp used so the encoders can be checked
// byte-for-byte without depending on the wall clock.
var fixedTestTime = time.Date(2026, time.June, 15, 13, 30, 45, 123456789, time.UTC)

func testSelfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestEFITimeBytes asserts the EFI_TIME 16-byte little-endian field layout.
func TestEFITimeBytes(t *testing.T) {
	et := EFITime{
		Year:       2026,
		Month:      6,
		Day:        15,
		Hour:       13,
		Minute:     30,
		Second:     45,
		Pad1:       0,
		Nanosecond: 0x01020304,
		TimeZone:   -120,
		Daylight:   1,
		Pad2:       0,
	}
	b := et.Bytes()
	require.Len(t, b, EFITimeSize)
	require.Len(t, b, 16)

	assert.Equal(t, uint16(2026), binary.LittleEndian.Uint16(b[0:2]), "Year @0")
	assert.Equal(t, byte(6), b[2], "Month @2")
	assert.Equal(t, byte(15), b[3], "Day @3")
	assert.Equal(t, byte(13), b[4], "Hour @4")
	assert.Equal(t, byte(30), b[5], "Minute @5")
	assert.Equal(t, byte(45), b[6], "Second @6")
	assert.Equal(t, byte(0), b[7], "Pad1 @7")
	assert.Equal(t, uint32(0x01020304), binary.LittleEndian.Uint32(b[8:12]), "Nanosecond @8")
	assert.Equal(t, int16(-120), int16(binary.LittleEndian.Uint16(b[12:14])), "TimeZone @12")
	assert.Equal(t, byte(1), b[14], "Daylight @14")
	assert.Equal(t, byte(0), b[15], "Pad2 @15")
}

// TestNewEFITime verifies a time.Time is normalised to UTC and the spec-mandated
// zero fields (Pad1/Nanosecond/TimeZone/Daylight/Pad2) are left zero.
func TestNewEFITime(t *testing.T) {
	// A non-UTC zone must be normalised to UTC before the fields are taken.
	loc := time.FixedZone("UTC+2", 2*3600)
	in := time.Date(2026, time.June, 15, 15, 30, 45, 999, loc) // 13:30:45 UTC
	et := NewEFITime(in)

	assert.Equal(t, uint16(2026), et.Year)
	assert.Equal(t, uint8(6), et.Month)
	assert.Equal(t, uint8(15), et.Day)
	assert.Equal(t, uint8(13), et.Hour, "hour must be UTC-normalised")
	assert.Equal(t, uint8(30), et.Minute)
	assert.Equal(t, uint8(45), et.Second)

	// UEFI requires these be zero for an authenticated-variable timestamp.
	assert.Equal(t, uint8(0), et.Pad1)
	assert.Equal(t, uint32(0), et.Nanosecond)
	assert.Equal(t, int16(0), et.TimeZone)
	assert.Equal(t, uint8(0), et.Daylight)
	assert.Equal(t, uint8(0), et.Pad2)
}

// TestMarshalAuthDescriptor asserts the EFI_VARIABLE_AUTHENTICATION_2 +
// WIN_CERTIFICATE_UEFI_GUID byte layout for a Setup-Mode (empty payload) enroll.
func TestMarshalAuthDescriptor(t *testing.T) {
	ts := NewEFITime(fixedTestTime)
	d := marshalAuthDescriptor(ts)

	// EFI_TIME(16) + WIN_CERTIFICATE header(8) + EFI_GUID(16), no CertData.
	require.Len(t, d, EFITimeSize+winCertHeaderSize+GUIDSize)
	require.Len(t, d, 40)

	// [0:16] EFI_TIME must equal the standalone EFITime encoding.
	assert.Equal(t, ts.Bytes(), d[0:16], "EFI_TIME @0")

	// [16:20] dwLength = header(8) + GUID(16) = 24, little-endian.
	assert.Equal(t, uint32(24), binary.LittleEndian.Uint32(d[16:20]), "dwLength @16")

	// [20:22] wRevision = 0x0200.
	assert.Equal(t, uint16(0x0200), binary.LittleEndian.Uint16(d[20:22]), "wRevision @20")
	assert.Equal(t, []byte{0x00, 0x02}, d[20:22], "wRevision LE bytes")

	// [22:24] wCertificateType = 0x0EF1 (WIN_CERT_TYPE_EFI_GUID).
	assert.Equal(t, uint16(0x0EF1), binary.LittleEndian.Uint16(d[22:24]), "wCertificateType @22")
	assert.Equal(t, []byte{0xF1, 0x0E}, d[22:24], "wCertificateType LE bytes")

	// [24:40] EFI_CERT_TYPE_PKCS7_GUID in UEFI mixed-endian form.
	assert.Equal(t, EFIPKCS7Cert.Bytes(), d[24:40], "PKCS7 GUID @24")
	// Spot-check the canonical PKCS7 GUID first bytes (4aafd29d -> LE 9d d2 af 4a).
	assert.Equal(t, []byte{0x9d, 0xd2, 0xaf, 0x4a}, d[24:28], "PKCS7 GUID Data1 LE")
}

// TestEncodeEfivarsAuthPayload verifies the attribute prefix and the
// descriptor||ESL ordering of an efivarfs authenticated write.
func TestEncodeEfivarsAuthPayload(t *testing.T) {
	ts := NewEFITime(fixedTestTime)
	cert := testSelfSignedCert(t, "DB")
	esl := NewSignatureListFromCert(cert.Raw, secureBootKeyOwnerGUID).Bytes()

	payload := encodeEfivarsAuthPayload(SecureBootAttributes, ts, esl)

	// [0:4] attributes, little-endian (NV|BS|RT|TIME_BASED = 0x27).
	assert.Equal(t, SecureBootAttributes, binary.LittleEndian.Uint32(payload[0:4]), "attrs @0")
	assert.Equal(t, uint32(0x27), SecureBootAttributes, "attribute constant value")

	desc := marshalAuthDescriptor(ts)
	assert.Equal(t, desc, payload[4:4+len(desc)], "descriptor follows attrs")
	assert.Equal(t, esl, payload[4+len(desc):], "ESL follows descriptor")
}

// TestParseEfivarBool covers the 4-byte attribute prefix + value byte parsing
// and the too-short error path.
func TestParseEfivarBool(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		wantErr bool
	}{
		{name: "true", data: []byte{0x06, 0x00, 0x00, 0x00, 0x01}, want: true},
		{name: "false", data: []byte{0x06, 0x00, 0x00, 0x00, 0x00}, want: false},
		{name: "non-one is false", data: []byte{0x06, 0x00, 0x00, 0x00, 0x02}, want: false},
		{name: "extra data ignored", data: []byte{0x07, 0x00, 0x00, 0x00, 0x01, 0xff}, want: true},
		{name: "too short (only attrs)", data: []byte{0x06, 0x00, 0x00, 0x00}, wantErr: true},
		{name: "empty", data: []byte{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEfivarBool(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidFormat)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestReadEfivarBoolFile exercises the file-backed read against a temp file
// standing in for the efivar, including the absent-file case.
func TestReadEfivarBoolFile(t *testing.T) {
	dir := t.TempDir()

	enabled := filepath.Join(dir, "SetupMode-enabled")
	require.NoError(t, os.WriteFile(enabled, []byte{0x06, 0x00, 0x00, 0x00, 0x01}, 0644))
	got, err := readEfivarBoolFile(enabled)
	require.NoError(t, err)
	assert.True(t, got)

	disabled := filepath.Join(dir, "SetupMode-disabled")
	require.NoError(t, os.WriteFile(disabled, []byte{0x06, 0x00, 0x00, 0x00, 0x00}, 0644))
	got, err = readEfivarBoolFile(disabled)
	require.NoError(t, err)
	assert.False(t, got)

	// A missing variable file (efivarfs absent) is not an error.
	got, err = readEfivarBoolFile(filepath.Join(dir, "does-not-exist"))
	require.NoError(t, err)
	assert.False(t, got)
}

// TestIsSetupModeAndSecureBootEnabled drives the exported readers against a
// temporary EfivarsPath so the variable-name/GUID filename mapping is covered
// without touching the real firmware.
func TestIsSetupModeAndSecureBootEnabled(t *testing.T) {
	dir := t.TempDir()
	orig := EfivarsPath
	EfivarsPath = dir
	t.Cleanup(func() { EfivarsPath = orig })

	// Nothing present yet -> both false, no error, efivarfs "available" (dir).
	assert.True(t, EfivarsAvailable())
	setup, err := IsSetupMode()
	require.NoError(t, err)
	assert.False(t, setup)
	sb, err := SecureBootEnabled()
	require.NoError(t, err)
	assert.False(t, sb)

	// Write SetupMode=1 and SecureBoot=1 using the real filename mapping.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable)),
		[]byte{0x06, 0x00, 0x00, 0x00, 0x01}, 0644))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, efivarFileName("SecureBoot", EFIGlobalVariable)),
		[]byte{0x06, 0x00, 0x00, 0x00, 0x01}, 0644))

	setup, err = IsSetupMode()
	require.NoError(t, err)
	assert.True(t, setup)
	sb, err = SecureBootEnabled()
	require.NoError(t, err)
	assert.True(t, sb)
}

// TestEfivarFileName checks the lowercase vendor-GUID filename convention.
func TestEfivarFileName(t *testing.T) {
	assert.Equal(t, "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		efivarFileName("db", EFIImageSecurityDatabase))
	assert.Equal(t, "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		efivarFileName("PK", EFIGlobalVariable))
}

// TestEnrollKeysToDir_OrderAndBytes verifies db/KEK/PK are all written with the
// correct authenticated-variable byte content into a temp directory.
func TestEnrollKeysToDir_OrderAndBytes(t *testing.T) {
	dir := t.TempDir()
	pk := testSelfSignedCert(t, "PK")
	kek := testSelfSignedCert(t, "KEK")
	db := testSelfSignedCert(t, "DB")
	ts := NewEFITime(fixedTestTime)

	err := enrollKeysToDir(context.Background(), dir, pk, kek, db, ts, logging.DefaultLogger())
	require.NoError(t, err)

	cases := []struct {
		name string
		guid GUID
		cert *x509.Certificate
	}{
		{"db", EFIImageSecurityDatabase, db},
		{"KEK", EFIGlobalVariable, kek},
		{"PK", EFIGlobalVariable, pk},
	}
	for _, c := range cases {
		path := filepath.Join(dir, efivarFileName(c.name, c.guid))
		got, readErr := os.ReadFile(path)
		require.NoError(t, readErr, "expected %s to be written", c.name)

		esl := NewSignatureListFromCert(c.cert.Raw, secureBootKeyOwnerGUID).Bytes()
		want := encodeEfivarsAuthPayload(SecureBootAttributes, ts, esl)
		assert.Equal(t, want, got, "byte content for %s", c.name)
	}
}

// TestEnrollKeysToDir_StopsBeforePK is the brick-safety test: a failure on an
// earlier key (here KEK is nil) must abort BEFORE PK is written, so the firmware
// never leaves Setup Mode and keeps booting unsigned.
func TestEnrollKeysToDir_StopsBeforePK(t *testing.T) {
	dir := t.TempDir()
	pk := testSelfSignedCert(t, "PK")
	db := testSelfSignedCert(t, "DB")
	ts := NewEFITime(fixedTestTime)

	err := enrollKeysToDir(context.Background(), dir, pk, nil /*kek*/, db, ts, logging.DefaultLogger())
	require.Error(t, err)
	var ew *ErrEnrollWrite
	require.ErrorAs(t, err, &ew)
	assert.Equal(t, "KEK", ew.Var)
	assert.ErrorIs(t, err, errNilEnrollCert)

	// db was written, but PK must NOT exist — Secure Boot never activates.
	_, dbErr := os.Stat(filepath.Join(dir, efivarFileName("db", EFIImageSecurityDatabase)))
	assert.NoError(t, dbErr, "db should have been written first")
	_, pkErr := os.Stat(filepath.Join(dir, efivarFileName("PK", EFIGlobalVariable)))
	assert.True(t, os.IsNotExist(pkErr), "PK must NOT be written after an earlier failure")
}

// TestEnrollKeysToDir_NilDB fails on the very first (db) write and writes
// nothing at all.
func TestEnrollKeysToDir_NilDB(t *testing.T) {
	dir := t.TempDir()
	pk := testSelfSignedCert(t, "PK")
	kek := testSelfSignedCert(t, "KEK")
	ts := NewEFITime(fixedTestTime)

	err := enrollKeysToDir(context.Background(), dir, pk, kek, nil /*db*/, ts, logging.DefaultLogger())
	require.Error(t, err)
	var ew *ErrEnrollWrite
	require.ErrorAs(t, err, &ew)
	assert.Equal(t, "db", ew.Var)

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "no variables should be written when db fails")
}

// TestEnrollKeysToDir_CanceledContext returns the context error before any
// write.
func TestEnrollKeysToDir_CanceledContext(t *testing.T) {
	dir := t.TempDir()
	pk := testSelfSignedCert(t, "PK")
	kek := testSelfSignedCert(t, "KEK")
	db := testSelfSignedCert(t, "DB")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := enrollKeysToDir(ctx, dir, pk, kek, db, NewEFITime(fixedTestTime), logging.DefaultLogger())
	require.ErrorIs(t, err, context.Canceled)

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

// TestEnrollKeysToEfivars_GuardsSetupMode drives the exported entry point
// against a temp EfivarsPath: it must refuse to write unless Setup Mode is set.
func TestEnrollKeysToEfivars_GuardsSetupMode(t *testing.T) {
	dir := t.TempDir()
	orig := EfivarsPath
	EfivarsPath = dir
	t.Cleanup(func() { EfivarsPath = orig })

	pk := testSelfSignedCert(t, "PK")
	kek := testSelfSignedCert(t, "KEK")
	db := testSelfSignedCert(t, "DB")
	ts := NewEFITime(fixedTestTime)

	// Not in Setup Mode (no SetupMode var) -> ErrNotSetupMode, nothing written.
	err := EnrollKeysToEfivars(context.Background(), pk, kek, db, ts)
	require.ErrorIs(t, err, ErrNotSetupMode)
	entries, _ := os.ReadDir(dir)
	assert.Len(t, entries, 0)

	// Enter Setup Mode, then enrollment proceeds and writes all three vars.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable)),
		[]byte{0x06, 0x00, 0x00, 0x00, 0x01}, 0644))
	require.NoError(t, EnrollKeysToEfivars(context.Background(), pk, kek, db, ts))
	for _, c := range []struct {
		name string
		guid GUID
	}{{"db", EFIImageSecurityDatabase}, {"KEK", EFIGlobalVariable}, {"PK", EFIGlobalVariable}} {
		_, statErr := os.Stat(filepath.Join(dir, efivarFileName(c.name, c.guid)))
		assert.NoError(t, statErr, "%s should be enrolled in Setup Mode", c.name)
	}
}

// TestEnrollKeysToEfivars_UnavailableEfivars returns ErrEfivarsUnavailable when
// the efivarfs mount point is absent.
func TestEnrollKeysToEfivars_UnavailableEfivars(t *testing.T) {
	orig := EfivarsPath
	EfivarsPath = filepath.Join(t.TempDir(), "no-such-efivars")
	t.Cleanup(func() { EfivarsPath = orig })

	err := EnrollKeysToEfivars(context.Background(),
		testSelfSignedCert(t, "PK"), testSelfSignedCert(t, "KEK"), testSelfSignedCert(t, "DB"),
		NewEFITime(fixedTestTime))
	require.ErrorIs(t, err, ErrEfivarsUnavailable)
}

// fakeUKIVerifier is a test double for UKIVerifier.
type fakeUKIVerifier struct {
	verifyErr   error
	extractCert *x509.Certificate
	extractErr  error
}

func (f *fakeUKIVerifier) VerifyFile(string) error { return f.verifyErr }
func (f *fakeUKIVerifier) ExtractCertificateFile(string) (*x509.Certificate, error) {
	return f.extractCert, f.extractErr
}

// TestVerifySignedUKI covers the verify-before-enforce brick guard: success only
// when the signature verifies AND the embedded cert matches dbCert.
func TestVerifySignedUKI(t *testing.T) {
	dbCert := testSelfSignedCert(t, "DB")
	otherCert := testSelfSignedCert(t, "OTHER")
	logger := logging.DefaultLogger()
	verifyBoom := errors.New("authenticode: bad signature")
	extractBoom := errors.New("authenticode: no certificate")

	t.Run("happy path", func(t *testing.T) {
		v := &fakeUKIVerifier{extractCert: dbCert}
		require.NoError(t, VerifySignedUKI(v, "/uki", dbCert, logger))
	})

	t.Run("signature invalid", func(t *testing.T) {
		v := &fakeUKIVerifier{verifyErr: verifyBoom, extractCert: dbCert}
		err := VerifySignedUKI(v, "/uki", dbCert, logger)
		require.Error(t, err)
		var ve *ErrUKIVerify
		require.ErrorAs(t, err, &ve)
		assert.ErrorIs(t, err, verifyBoom)
	})

	t.Run("extract fails", func(t *testing.T) {
		v := &fakeUKIVerifier{extractErr: extractBoom}
		err := VerifySignedUKI(v, "/uki", dbCert, logger)
		require.Error(t, err)
		assert.ErrorIs(t, err, extractBoom)
	})

	t.Run("certificate mismatch", func(t *testing.T) {
		v := &fakeUKIVerifier{extractCert: otherCert}
		err := VerifySignedUKI(v, "/uki", dbCert, logger)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUKICertMismatch)
	})

	t.Run("nil embedded cert", func(t *testing.T) {
		v := &fakeUKIVerifier{extractCert: nil}
		err := VerifySignedUKI(v, "/uki", dbCert, logger)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUKICertMismatch)
	})

	t.Run("nil verifier", func(t *testing.T) {
		err := VerifySignedUKI(nil, "/uki", dbCert, logger)
		require.Error(t, err)
		assert.ErrorIs(t, err, errNilVerifier)
	})

	t.Run("nil dbCert", func(t *testing.T) {
		v := &fakeUKIVerifier{extractCert: dbCert}
		err := VerifySignedUKI(v, "/uki", nil, logger)
		require.Error(t, err)
		assert.ErrorIs(t, err, errNilEnrollCert)
	})

	t.Run("nil logger tolerated", func(t *testing.T) {
		v := &fakeUKIVerifier{extractCert: dbCert}
		require.NoError(t, VerifySignedUKI(v, "/uki", dbCert, nil))
	})
}
