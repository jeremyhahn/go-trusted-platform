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

package bmc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// Stub enroller
// =============================================================================

// stubEnroller is an in-process stub that satisfies bmcEnroller without any
// network or gRPC dependency.
type stubEnroller struct {
	result *bmcsvc.EnrollResult
	err    error
	// lastOpts captures the opts argument for assertion.
	lastOpts *bmcsvc.EnrollOptions
}

func (s *stubEnroller) EnrollBMC(_ context.Context, _ uint64, opts *bmcsvc.EnrollOptions) (*bmcsvc.EnrollResult, error) {
	s.lastOpts = opts
	return s.result, s.err
}

// goodEnrollResult returns a realistic EnrollResult for happy-path tests.
func goodEnrollResult() *bmcsvc.EnrollResult {
	now := time.Now()
	return &bmcsvc.EnrollResult{
		DeviceID:      42,
		Endpoint:      "10.0.0.1:443",
		Hostname:      "bmc-host",
		DNSName:       "bmc.internal.example.com",
		PinSPKISHA256: "sha256/abc123",
		FactoryCertPEM: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
		FactoryCertMeta: bmcsvc.FactoryCertMeta{
			Subject:      "CN=bmc",
			Issuer:       "CN=ca",
			SerialNumber: "deadbeef",
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SPKISHA256:   "aabbcc",
			SHA256:       "ddeeff",
			CapturedAt:   now,
		},
		NewCertPEM: "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n",
		CACertPEM:  "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
		Steps: []bmcsvc.EnrollStep{
			{Name: "trust", OK: true},
			{Name: "factory_cert", OK: true, Detail: "captured CN=bmc"},
			{Name: "credentials", OK: false, Detail: "rotate skipped"},
		},
	}
}

func jsonGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
}

func tableGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}
}

// =============================================================================
// newEnrollCommand — flag registration
// =============================================================================

func TestNewEnrollCommand_Flags(t *testing.T) {
	cmd := newEnrollCommand(jsonGetFlags())
	require.NotNil(t, cmd)
	assert.Equal(t, "enroll", cmd.Use)

	for _, name := range []string{
		"profile-id",
		"backups-dir",
		"replace-certificate",
		"rotate-password",
		"dns-register",
		"dane-publish",
	} {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "flag --%s must be registered", name)
	}
}

func TestNewEnrollCommand_HelpNonEmpty(t *testing.T) {
	cmd := newEnrollCommand(jsonGetFlags())
	assert.NotEmpty(t, cmd.Long)
	assert.Contains(t, cmd.Long, "--profile-id")
}

// =============================================================================
// buildEnrollOptions — tri-state flag logic
// =============================================================================

func TestBuildEnrollOptions_NoneChanged_ReturnsNil(t *testing.T) {
	flags := &enrollFlags{}
	cmd := newEnrollCommand(jsonGetFlags())
	// No flags set — simulate calling the command with no override args.
	opts := buildEnrollOptions(cmd, flags)
	assert.Nil(t, opts, "opts must be nil when no override flags are passed")
}

func TestBuildEnrollOptions_AllChanged(t *testing.T) {
	flags := &enrollFlags{
		replaceCertificate: true,
		rotatePassword:     false,
		dnsRegister:        true,
		danePublish:        false,
	}
	cmd := newEnrollCommand(jsonGetFlags())

	// Simulate the user explicitly passing all four flags.
	require.NoError(t, cmd.Flags().Set("replace-certificate", "true"))
	require.NoError(t, cmd.Flags().Set("rotate-password", "false"))
	require.NoError(t, cmd.Flags().Set("dns-register", "true"))
	require.NoError(t, cmd.Flags().Set("dane-publish", "false"))

	opts := buildEnrollOptions(cmd, flags)
	require.NotNil(t, opts)

	require.NotNil(t, opts.ReplaceCertificate)
	assert.True(t, *opts.ReplaceCertificate)

	require.NotNil(t, opts.RotatePassword)
	assert.False(t, *opts.RotatePassword)

	require.NotNil(t, opts.DNSRegister)
	assert.True(t, *opts.DNSRegister)

	require.NotNil(t, opts.DANEPublish)
	assert.False(t, *opts.DANEPublish)
}

func TestBuildEnrollOptions_OnlyOneChanged(t *testing.T) {
	flags := &enrollFlags{replaceCertificate: true}
	cmd := newEnrollCommand(jsonGetFlags())
	require.NoError(t, cmd.Flags().Set("replace-certificate", "true"))

	opts := buildEnrollOptions(cmd, flags)
	require.NotNil(t, opts)

	require.NotNil(t, opts.ReplaceCertificate)
	assert.True(t, *opts.ReplaceCertificate)

	// Un-changed flags must remain nil.
	assert.Nil(t, opts.RotatePassword)
	assert.Nil(t, opts.DNSRegister)
	assert.Nil(t, opts.DANEPublish)
}

// =============================================================================
// runEnroll — validation errors (no network, stub returns nil)
// =============================================================================

func TestRunEnroll_MissingProfileID(t *testing.T) {
	cmd := newEnrollCommand(jsonGetFlags())
	flags := &enrollFlags{}
	stub := &stubEnroller{}
	err := runEnroll(cmd, flags, "", jsonGetFlags(), stub)
	require.Error(t, err)
	var typed ErrProfileIDRequired
	require.ErrorAs(t, err, &typed)
}

func TestRunEnroll_InvalidProfileID(t *testing.T) {
	cmd := newEnrollCommand(jsonGetFlags())
	flags := &enrollFlags{profileID: "not-a-number"}
	stub := &stubEnroller{}
	err := runEnroll(cmd, flags, "", jsonGetFlags(), stub)
	require.Error(t, err)
	var typed ErrProfileIDParseFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "not-a-number", typed.Value)
}

// =============================================================================
// runEnroll — SDK error is propagated
// =============================================================================

func TestRunEnroll_SDKError(t *testing.T) {
	cause := errors.New("grpc: connection refused")
	stub := &stubEnroller{err: cause}
	cmd := newEnrollCommand(jsonGetFlags())
	flags := &enrollFlags{profileID: "7"}
	err := runEnroll(cmd, flags, "", jsonGetFlags(), stub)
	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
}

// =============================================================================
// runEnroll — happy path, no backups dir, table output
// =============================================================================

func TestRunEnroll_HappyPath_TableOutput(t *testing.T) {
	stub := &stubEnroller{result: goodEnrollResult()}
	cmd := newEnrollCommand(tableGetFlags())
	flags := &enrollFlags{profileID: "42"}
	err := runEnroll(cmd, flags, "", tableGetFlags(), stub)
	require.NoError(t, err)
	// opts must be nil because no override flags were set.
	assert.Nil(t, stub.lastOpts)
}

// =============================================================================
// runEnroll — happy path, JSON output
// =============================================================================

func TestRunEnroll_HappyPath_JSONOutput(t *testing.T) {
	stub := &stubEnroller{result: goodEnrollResult()}
	cmd := newEnrollCommand(jsonGetFlags())
	flags := &enrollFlags{profileID: "42"}
	err := runEnroll(cmd, flags, "", jsonGetFlags(), stub)
	require.NoError(t, err)
}

// =============================================================================
// runEnroll — override flags forwarded to SDK
// =============================================================================

func TestRunEnroll_OverrideFlagsForwarded(t *testing.T) {
	stub := &stubEnroller{result: goodEnrollResult()}
	cmd := newEnrollCommand(tableGetFlags())
	flags := &enrollFlags{profileID: "7", replaceCertificate: true, dnsRegister: true}

	require.NoError(t, cmd.Flags().Set("replace-certificate", "true"))
	require.NoError(t, cmd.Flags().Set("dns-register", "true"))

	err := runEnroll(cmd, flags, "", tableGetFlags(), stub)
	require.NoError(t, err)

	require.NotNil(t, stub.lastOpts)
	require.NotNil(t, stub.lastOpts.ReplaceCertificate)
	assert.True(t, *stub.lastOpts.ReplaceCertificate)
	require.NotNil(t, stub.lastOpts.DNSRegister)
	assert.True(t, *stub.lastOpts.DNSRegister)
	assert.Nil(t, stub.lastOpts.RotatePassword)
	assert.Nil(t, stub.lastOpts.DANEPublish)
}

// =============================================================================
// finishEnroll — backup file creation
// =============================================================================

func TestFinishEnroll_WritesBackupFiles(t *testing.T) {
	dir := t.TempDir()
	result := goodEnrollResult()

	err := finishEnroll(tableGetFlags(), result, dir)
	require.NoError(t, err)

	bmcDir := filepath.Join(dir, result.Hostname, "bmc")
	for _, name := range []string{"factory-cert.pem", "factory-cert.json", "enrollment.json"} {
		path := filepath.Join(bmcDir, name)
		info, statErr := os.Stat(path)
		require.NoError(t, statErr, "%s must exist", name)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s must have mode 0600", name)
	}

	// Directory must be 0700.
	dirInfo, err := os.Stat(bmcDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
}

func TestFinishEnroll_FactoryCertContent(t *testing.T) {
	dir := t.TempDir()
	result := goodEnrollResult()

	err := finishEnroll(tableGetFlags(), result, dir)
	require.NoError(t, err)

	certPath := filepath.Join(dir, result.Hostname, "bmc", "factory-cert.pem")
	data, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, result.FactoryCertPEM, string(data))
}

func TestFinishEnroll_SkipsBackupWhenNoPEM(t *testing.T) {
	dir := t.TempDir()
	result := goodEnrollResult()
	result.FactoryCertPEM = ""

	// Providing a non-empty backupsDir but empty FactoryCertPEM must not create
	// any files and must not return an error.
	err := finishEnroll(tableGetFlags(), result, dir)
	require.NoError(t, err)

	bmcDir := filepath.Join(dir, result.Hostname, "bmc")
	_, statErr := os.Stat(bmcDir)
	assert.True(t, os.IsNotExist(statErr), "bmc dir must not be created when FactoryCertPEM is empty")
}

func TestFinishEnroll_BackupsDirCreateError(t *testing.T) {
	// Use a path that cannot be created: a file as a parent directory component.
	tmpFile, err := os.CreateTemp(t.TempDir(), "blockfile-*")
	require.NoError(t, err)
	tmpFile.Close()

	// Attempt to create a directory under a regular file — must fail.
	result := goodEnrollResult()
	badDir := filepath.Join(tmpFile.Name(), "sub")
	err = finishEnroll(tableGetFlags(), result, badDir)
	require.Error(t, err)

	var typed ErrBackupsDirCreateFailed
	require.ErrorAs(t, err, &typed)
}

// =============================================================================
// writeBackupFile
// =============================================================================

func TestWriteBackupFile_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pem")
	data := []byte("pem data")
	err := writeBackupFile(path, data)
	require.NoError(t, err)

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, data, got)

	info, statErr := os.Stat(path)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteBackupFile_ErrorOnBadPath(t *testing.T) {
	err := writeBackupFile("/nonexistent-dir/file.pem", []byte("data"))
	require.Error(t, err)

	var typed ErrBackupFileWriteFailed
	require.ErrorAs(t, err, &typed)
	assert.NotEmpty(t, typed.Path)
	assert.NotNil(t, typed.Cause)
}

// =============================================================================
// Error type tests
// =============================================================================

func TestErrBackupsDirCreateFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("permission denied")
	e := ErrBackupsDirCreateFailed{Path: "/some/dir", Cause: cause}
	assert.Contains(t, e.Error(), "/some/dir")
	assert.ErrorIs(t, e, cause)
}

func TestErrBackupFileWriteFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	e := ErrBackupFileWriteFailed{Path: "/some/file.pem", Cause: cause}
	assert.Contains(t, e.Error(), "/some/file.pem")
	assert.ErrorIs(t, e, cause)
}

// =============================================================================
// printEnrollSummary — smoke test (does not crash with various inputs)
// =============================================================================

func TestPrintEnrollSummary_WithDNSAndBackup(t *testing.T) {
	result := goodEnrollResult()
	// Must not panic regardless of output destination.
	printEnrollSummary(result, "/var/lib/platform/backups/bmc-host/bmc")
}

func TestPrintEnrollSummary_NoDNSNoBackup(t *testing.T) {
	result := goodEnrollResult()
	result.DNSName = ""
	printEnrollSummary(result, "")
}

func TestPrintEnrollSummary_NoSteps(t *testing.T) {
	result := goodEnrollResult()
	result.Steps = nil
	printEnrollSummary(result, "")
}

// =============================================================================
// bmc_test.go compatibility: NewCommand subcommand count
// =============================================================================

func TestNewCommand_IncludesEnroll(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
	cmd := NewCommand(getFlags)
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "enroll" {
			found = true
			break
		}
	}
	assert.True(t, found, "enroll subcommand must be registered on the bmc command")
}
