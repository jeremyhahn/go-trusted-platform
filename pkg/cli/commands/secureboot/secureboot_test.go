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

package secureboot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// testFlags returns CLI flags for JSON output (no interactive rendering).
func testFlags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
}

// newTestCert generates a self-signed certificate for the given CN.
func newTestCert(t *testing.T, cn string) *x509.Certificate {
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

// writeCertPEM writes a certificate as PEM to dir/name and returns its path.
func writeCertPEM(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

// writeBoolVar writes a boolean efivar fixture into dir.
func writeBoolVar(t *testing.T, dir, name string, value byte) {
	t.Helper()
	data := make([]byte, 5)
	binary.LittleEndian.PutUint32(data[0:4], uefi.SecureBootAttributes)
	data[4] = value
	path := filepath.Join(dir, name+"-"+"8be4df61-93ca-11d2-aa0d-00e098032b8c")
	require.NoError(t, os.WriteFile(path, data, 0644))
}

// testEnv builds a complete enroll fixture: efivars dir in Setup Mode, a keys
// dir with PK/KEK/DB certs, and a placeholder signed UKI file.
type testEnv struct {
	opts   *enrollOptions
	dbCert *x509.Certificate
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	efivars := t.TempDir()
	writeBoolVar(t, efivars, "SetupMode", 0x01)
	writeBoolVar(t, efivars, "SecureBoot", 0x00)

	keysDir := t.TempDir()
	pk := newTestCert(t, "Test PK")
	kek := newTestCert(t, "Test KEK")
	db := newTestCert(t, "Test DB")
	writeCertPEM(t, keysDir, "PK.crt", pk)
	writeCertPEM(t, keysDir, "KEK.crt", kek)
	writeCertPEM(t, keysDir, "DB.crt", db)

	ukiPath := filepath.Join(t.TempDir(), "BOOTX64.EFI")
	require.NoError(t, os.WriteFile(ukiPath, []byte("uki-placeholder"), 0644))

	return &testEnv{
		opts: &enrollOptions{
			efivarsDir: efivars,
			keysDir:    keysDir,
			ukiPath:    ukiPath,
		},
		dbCert: db,
	}
}

// fakeVerifier implements uefi.UKIVerifier for unit tests. It returns the
// configured certificate and errors, standing in for the Authenticode
// verifier whose happy path is exercised by the OVMF integration suite.
type fakeVerifier struct {
	verifyErr  error
	extractErr error
	cert       *x509.Certificate
}

func (f *fakeVerifier) VerifyFile(path string) error { return f.verifyErr }

func (f *fakeVerifier) ExtractCertificateFile(path string) (*x509.Certificate, error) {
	return f.cert, f.extractErr
}

// TestNewCommand asserts the command tree exposes status, enroll, and enforce.
func TestNewCommand(t *testing.T) {
	cmd := NewCommand(func() *cli.CommonFlags { return testFlags() })
	assert.Equal(t, "secure-boot", cmd.Use)

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["status"])
	assert.True(t, names["enroll"])
	assert.True(t, names["enforce"])
}

// TestRunStatus_Happy asserts status reads a fixture directory.
func TestRunStatus_Happy(t *testing.T) {
	env := newTestEnv(t)
	assert.NoError(t, runStatus(testFlags(), env.opts.efivarsDir))
	assert.NoError(t, runStatus(&cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true},
		env.opts.efivarsDir))
}

// TestRunStatus_MissingEfivars asserts status surfaces the typed unavailable
// error for a missing directory.
func TestRunStatus_MissingEfivars(t *testing.T) {
	err := runStatus(testFlags(), filepath.Join(t.TempDir(), "missing"))
	assert.ErrorIs(t, err, uefi.ErrEfivarsUnavailable)
}

// TestRunEnroll_DryRun asserts a dry run passes every guard and writes
// nothing.
func TestRunEnroll_DryRun(t *testing.T) {
	env := newTestEnv(t)
	result, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	assert.True(t, result.UKIVerified)
	assert.False(t, result.Enrolled)
	assert.Contains(t, result.DBSubject, "Test DB")
	assert.Equal(t, []string{"db", "KEK", "PK"}, result.EnrollOrder)

	status, err := uefi.ReadSecureBootStatusFromDir(env.opts.efivarsDir)
	require.NoError(t, err)
	assert.False(t, status.PK.Present, "dry run must not write PK")
	assert.False(t, status.DB.Present, "dry run must not write db")
}

// TestRunEnroll_Commit asserts a committed enroll writes db, KEK, and PK and
// reads back the post state.
func TestRunEnroll_Commit(t *testing.T) {
	env := newTestEnv(t)
	env.opts.commit = true
	result, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)
	assert.False(t, result.DryRun)
	assert.True(t, result.Enrolled)
	assert.True(t, result.PostPKPresent)

	status, err := uefi.ReadSecureBootStatusFromDir(env.opts.efivarsDir)
	require.NoError(t, err)
	assert.True(t, status.PK.Present)
	assert.True(t, status.KEK.Present)
	assert.True(t, status.DB.Present)
	assert.Equal(t, 1, status.DB.Certificates)
}

// TestRunEnroll_NotSetupMode asserts enrollment is refused outside Setup
// Mode.
func TestRunEnroll_NotSetupMode(t *testing.T) {
	env := newTestEnv(t)
	writeBoolVar(t, env.opts.efivarsDir, "SetupMode", 0x00)
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	assert.ErrorIs(t, err, uefi.ErrNotSetupMode)
}

// TestRunEnroll_MissingEfivars asserts a missing efivarfs fails with the
// typed error before anything else runs.
func TestRunEnroll_MissingEfivars(t *testing.T) {
	env := newTestEnv(t)
	env.opts.efivarsDir = filepath.Join(t.TempDir(), "missing")
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	assert.ErrorIs(t, err, uefi.ErrEfivarsUnavailable)
}

// TestRunEnroll_MissingCertificate asserts a missing certificate fails with
// the typed load error identifying the role.
func TestRunEnroll_MissingCertificate(t *testing.T) {
	env := newTestEnv(t)
	require.NoError(t, os.Remove(filepath.Join(env.opts.keysDir, "KEK.crt")))
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	var loadErr ErrCertificateLoad
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, "KEK", loadErr.Role)
}

// TestRunEnroll_MissingUKI asserts a missing UKI fails the brick guard with
// the typed error.
func TestRunEnroll_MissingUKI(t *testing.T) {
	env := newTestEnv(t)
	env.opts.ukiPath = filepath.Join(t.TempDir(), "missing.efi")
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	var ukiErr ErrUKINotFound
	require.ErrorAs(t, err, &ukiErr)
	assert.Equal(t, env.opts.ukiPath, ukiErr.Path)
}

// TestRunEnroll_UKIVerifyFailure asserts an invalid UKI signature blocks
// enrollment.
func TestRunEnroll_UKIVerifyFailure(t *testing.T) {
	env := newTestEnv(t)
	env.opts.commit = true
	verifyErr := errors.New("authenticode signature invalid")
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert, verifyErr: verifyErr})
	var ukiVerifyErr *uefi.ErrUKIVerify
	require.ErrorAs(t, err, &ukiVerifyErr)

	status, statusErr := uefi.ReadSecureBootStatusFromDir(env.opts.efivarsDir)
	require.NoError(t, statusErr)
	assert.False(t, status.DB.Present, "failed verify must block all writes")
}

// TestRunEnroll_UKICertMismatch asserts a UKI signed by a different
// certificate than the DB cert blocks enrollment.
func TestRunEnroll_UKICertMismatch(t *testing.T) {
	env := newTestEnv(t)
	other := newTestCert(t, "Wrong Signer")
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: other})
	var ukiVerifyErr *uefi.ErrUKIVerify
	require.ErrorAs(t, err, &ukiVerifyErr)
}

// TestRunEnforce_DryRun asserts the enforce gate dry-runs the enrollment
// pipeline without writing.
func TestRunEnforce_DryRun(t *testing.T) {
	env := newTestEnv(t)
	result, err := runEnforce(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)
	assert.False(t, result.AlreadyEnforced)
	require.NotNil(t, result.Enroll)
	assert.True(t, result.Enroll.DryRun)
}

// TestRunEnforce_Commit asserts a committed enforce enrolls the keys and
// confirms the Platform Key.
func TestRunEnforce_Commit(t *testing.T) {
	env := newTestEnv(t)
	env.opts.commit = true
	result, err := runEnforce(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)
	require.NotNil(t, result.Enroll)
	assert.True(t, result.Enroll.Enrolled)
	assert.True(t, result.Enroll.PostPKPresent)
}

// TestRunEnforce_AlreadyEnforced asserts an enforced firmware short-circuits
// without writes.
func TestRunEnforce_AlreadyEnforced(t *testing.T) {
	env := newTestEnv(t)
	writeBoolVar(t, env.opts.efivarsDir, "SetupMode", 0x00)
	writeBoolVar(t, env.opts.efivarsDir, "SecureBoot", 0x01)
	result, err := runEnforce(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)
	assert.True(t, result.AlreadyEnforced)
	assert.Nil(t, result.Enroll)
}

// TestRunEnforce_NotSetupModeNotEnforced asserts firmware that is neither
// enforced nor in Setup Mode is refused with the typed error.
func TestRunEnforce_NotSetupModeNotEnforced(t *testing.T) {
	env := newTestEnv(t)
	writeBoolVar(t, env.opts.efivarsDir, "SetupMode", 0x00)
	_, err := runEnforce(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	assert.ErrorIs(t, err, uefi.ErrNotSetupMode)
}

// TestLoadRoleCertificate_Errors asserts the certificate loader rejects
// missing files, non-PEM content, and non-certificate DER.
func TestLoadRoleCertificate_Errors(t *testing.T) {
	dir := t.TempDir()

	_, err := loadRoleCertificate("PK", "", dir, "PK.crt")
	var loadErr ErrCertificateLoad
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, "PK", loadErr.Role)

	badPEM := filepath.Join(dir, "bad.crt")
	require.NoError(t, os.WriteFile(badPEM, []byte("not pem"), 0644))
	_, err = loadRoleCertificate("KEK", badPEM, dir, "KEK.crt")
	require.ErrorAs(t, err, &loadErr)
	assert.ErrorIs(t, err, ErrNotPEMCertificate{Path: badPEM})

	badDER := filepath.Join(dir, "badder.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	require.NoError(t, os.WriteFile(badDER, block, 0644))
	_, err = loadRoleCertificate("DB", badDER, dir, "DB.crt")
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, "DB", loadErr.Role)
}

// TestLoadRoleCertificate_ExplicitOverride asserts an explicit path wins over
// the keys directory.
func TestLoadRoleCertificate_ExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	writeCertPEM(t, dir, "PK.crt", newTestCert(t, "Dir PK"))
	override := writeCertPEM(t, t.TempDir(), "custom.crt", newTestCert(t, "Override PK"))

	cert, err := loadRoleCertificate("PK", override, dir, "PK.crt")
	require.NoError(t, err)
	assert.Contains(t, cert.Subject.String(), "Override PK")
}

// TestNewUKIVerifier asserts the production verifier builds from a DB
// certificate and rejects an unsigned file, and that the verify-only backend
// refuses signing operations.
func TestNewUKIVerifier(t *testing.T) {
	db := newTestCert(t, "Verifier DB")
	verifier, err := newUKIVerifier(context.Background(), db, nil)
	require.NoError(t, err)
	require.NotNil(t, verifier)

	unsigned := filepath.Join(t.TempDir(), "unsigned.efi")
	require.NoError(t, os.WriteFile(unsigned, []byte("not a signed PE"), 0644))
	assert.Error(t, verifier.VerifyFile(unsigned))

	backend := &verifyOnlyBackend{public: db.PublicKey}
	signer, signerErr := backend.Signer(context.Background(), nil)
	require.NoError(t, signerErr)
	assert.Equal(t, db.PublicKey, signer.Public())
	_, signErr := signer.Sign(rand.Reader, []byte("digest"), nil)
	assert.ErrorIs(t, signErr, ErrVerifyOnlyBackend{Operation: "Sign"})
	_, keyErr := backend.GenerateKey(context.Background(), nil)
	assert.ErrorIs(t, keyErr, ErrVerifyOnlyBackend{Operation: "GenerateKey"})
	assert.NoError(t, backend.Close())
}

// TestErrorMessages asserts the typed errors render their diagnostic detail.
func TestErrorMessages(t *testing.T) {
	assert.Contains(t, ErrCertificateLoad{Role: "PK", Path: "/x", Cause: errors.New("boom")}.Error(), "PK")
	assert.Contains(t, ErrUKINotFound{Path: "/x/uki"}.Error(), "/x/uki")
	assert.Contains(t, ErrVerifierBuild{Cause: errors.New("boom")}.Error(), "boom")
	assert.Contains(t, ErrEnforceIncomplete{Reason: "no pk"}.Error(), "no pk")
	assert.Contains(t, ErrVerifyOnlyBackend{Operation: "Sign"}.Error(), "Sign")
	assert.Contains(t, ErrNotPEMCertificate{Path: "/x"}.Error(), "/x")
}
