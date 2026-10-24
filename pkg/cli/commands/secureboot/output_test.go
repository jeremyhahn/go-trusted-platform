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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// tableFlags selects the human-readable table output without ANSI colour,
// so the printed lines can be compared exactly.
func tableFlags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
}

// captureStdout runs f with os.Stdout redirected to a pipe and returns what
// f wrote. The printers in pkg/cli write to os.Stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	f()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// executeCommand runs the secure-boot command tree with args and returns the
// captured stdout and the command error.
func executeCommand(t *testing.T, flags *cli.CommonFlags, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	var err error
	out := captureStdout(t, func() {
		err = cmd.ExecuteContext(context.Background())
	})
	return out, err
}

func TestDescribeDatabase(t *testing.T) {
	tests := []struct {
		name string
		db   uefi.SignatureDatabase
		want string
	}{
		{
			name: "absent",
			db:   uefi.SignatureDatabase{Name: "PK"},
			want: "absent",
		},
		{
			name: "present and empty",
			db:   uefi.SignatureDatabase{Name: "db", Present: true},
			want: "0 certificate(s)",
		},
		{
			name: "certificates with subjects",
			db: uefi.SignatureDatabase{Name: "KEK", Present: true, Certificates: 2,
				Subjects: []string{"CN=A", "CN=B"}},
			want: "2 certificate(s), [CN=A; CN=B]",
		},
		{
			name: "hashes and other entries",
			db:   uefi.SignatureDatabase{Name: "dbx", Present: true, Hashes: 3, Other: 1},
			want: "0 certificate(s), 3 hash(es), 1 other",
		},
		{
			name: "every kind of entry",
			db: uefi.SignatureDatabase{Name: "db", Present: true, Certificates: 1, Hashes: 2,
				Other: 4, Subjects: []string{"CN=Only"}},
			want: "1 certificate(s), 2 hash(es), 4 other, [CN=Only]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describeDatabase(tt.db))
		})
	}
}

func TestBoolWord(t *testing.T) {
	assert.Equal(t, "enabled", boolWord(true))
	assert.Equal(t, "disabled", boolWord(false))
}

// TestRunStatus_TableAfterEnrollment checks that the table output reports the
// databases written by a committed enrollment, not just the mode flags. The
// mode flags are not asserted: clearing SetupMode is the firmware's job, and
// a fixture directory has no firmware.
func TestRunStatus_TableAfterEnrollment(t *testing.T) {
	env := newTestEnv(t)
	env.opts.commit = true
	_, err := runEnroll(context.Background(), env.opts, &fakeVerifier{cert: env.dbCert})
	require.NoError(t, err)

	var runErr error
	out := captureStdout(t, func() {
		runErr = runStatus(tableFlags(), env.opts.efivarsDir)
	})
	require.NoError(t, runErr)

	assert.Contains(t, out, "Efivars: "+env.opts.efivarsDir+"\n")
	assert.Regexp(t, `(?m)^PK: 1 certificate\(s\), \[.*Test PK.*\]$`, out)
	assert.Regexp(t, `(?m)^KEK: 1 certificate\(s\), \[.*Test KEK.*\]$`, out)
	assert.Regexp(t, `(?m)^db: 1 certificate\(s\), \[.*Test DB.*\]$`, out)
	assert.Contains(t, out, "dbx: absent\n")
}

func TestRunStatus_JSON(t *testing.T) {
	env := newTestEnv(t)
	var runErr error
	out := captureStdout(t, func() {
		runErr = runStatus(testFlags(), env.opts.efivarsDir)
	})
	require.NoError(t, runErr)

	var status uefi.SecureBootStatus
	require.NoError(t, json.Unmarshal([]byte(out), &status))
	assert.True(t, status.SetupMode)
	assert.False(t, status.SecureBoot)
	assert.False(t, status.PK.Present)
}

func sampleEnrollResult() *enrollResult {
	return &enrollResult{
		DryRun:      true,
		EfivarsDir:  "/fixture/efivars",
		UKIPath:     "/fixture/BOOTX64.EFI",
		UKIVerified: true,
		PKSubject:   "CN=Test PK",
		KEKSubject:  "CN=Test KEK",
		DBSubject:   "CN=Test DB",
		EnrollOrder: []string{"db", "KEK", "PK"},
	}
}

func TestPrintEnrollResult_TableDryRun(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = printEnrollResult(tableFlags(), sampleEnrollResult())
	})
	require.NoError(t, err)
	assert.Equal(t,
		"[WARNING] DRY RUN — no variables were written (pass --commit to enroll)\n"+
			"Efivars: /fixture/efivars\n"+
			"UKI: /fixture/BOOTX64.EFI (verified against DB certificate)\n"+
			"PK: CN=Test PK\n"+
			"KEK: CN=Test KEK\n"+
			"DB: CN=Test DB\n",
		out)
}

func TestPrintEnrollResult_TableEnrolled(t *testing.T) {
	result := sampleEnrollResult()
	result.DryRun = false
	result.Enrolled = true
	result.PostSetupMode = false
	result.PostSecureBoot = true

	var err error
	out := captureStdout(t, func() {
		err = printEnrollResult(tableFlags(), result)
	})
	require.NoError(t, err)
	assert.NotContains(t, out, "DRY RUN")
	assert.Contains(t, out,
		"DB: CN=Test DB\n"+
			"[SUCCESS] Secure Boot keys enrolled (db -> KEK -> PK)\n"+
			"SetupMode (post): disabled\n"+
			"SecureBoot (post): enabled\n")
}

func TestPrintEnrollResult_JSON(t *testing.T) {
	want := sampleEnrollResult()
	var err error
	out := captureStdout(t, func() {
		err = printEnrollResult(testFlags(), want)
	})
	require.NoError(t, err)

	var got enrollResult
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, *want, got)
}

func TestPrintEnforceResult_Table(t *testing.T) {
	enrolled := sampleEnrollResult()
	enrolled.DryRun = false
	enrolled.Enrolled = true

	tests := []struct {
		name        string
		result      *enforceResult
		contains    []string
		notContains []string
	}{
		{
			name:        "already enforced",
			result:      &enforceResult{AlreadyEnforced: true},
			contains:    []string{"[SUCCESS] Secure Boot is already enforced\n"},
			notContains: []string{"Efivars:", "armed"},
		},
		{
			name:        "dry run",
			result:      &enforceResult{Enroll: sampleEnrollResult()},
			contains:    []string{"[WARNING] DRY RUN", "PK: CN=Test PK\n"},
			notContains: []string{"armed", "already enforced"},
		},
		{
			name:   "committed",
			result: &enforceResult{Enroll: enrolled},
			contains: []string{
				"[SUCCESS] Secure Boot keys enrolled (db -> KEK -> PK)\n",
				"[SUCCESS] Secure Boot enforcement armed — active on next boot\n",
			},
			notContains: []string{"DRY RUN"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = printEnforceResult(tableFlags(), tt.result)
			})
			require.NoError(t, err)
			for _, s := range tt.contains {
				assert.Contains(t, out, s)
			}
			for _, s := range tt.notContains {
				assert.NotContains(t, out, s)
			}
		})
	}
}

func TestPrintEnforceResult_JSON(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = printEnforceResult(testFlags(), &enforceResult{AlreadyEnforced: true})
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"already_enforced": true}`, out)
}

func TestStatusCommand(t *testing.T) {
	env := newTestEnv(t)
	out, err := executeCommand(t, tableFlags(), "status", "--efivars", env.opts.efivarsDir)
	require.NoError(t, err)
	assert.Contains(t, out, "SetupMode: enabled\n")
	assert.Contains(t, out, "PK: absent\n")

	_, err = executeCommand(t, tableFlags(), "status", "--efivars", filepath.Join(t.TempDir(), "missing"))
	assert.ErrorIs(t, err, uefi.ErrEfivarsUnavailable)
}

func TestEnforceCommand_AlreadyEnforced(t *testing.T) {
	env := newTestEnv(t)
	writeBoolVar(t, env.opts.efivarsDir, "SetupMode", 0x00)
	writeBoolVar(t, env.opts.efivarsDir, "SecureBoot", 0x01)

	out, err := executeCommand(t, tableFlags(), "enforce", "--efivars", env.opts.efivarsDir)
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Secure Boot is already enforced\n", out)
}

// TestCommands_RefuseOutsideSetupMode drives enroll and enforce through cobra
// against firmware that is neither in Setup Mode nor enforced: both must
// refuse before touching certificates or the UKI.
func TestCommands_RefuseOutsideSetupMode(t *testing.T) {
	for _, sub := range []string{"enroll", "enforce"} {
		t.Run(sub, func(t *testing.T) {
			env := newTestEnv(t)
			writeBoolVar(t, env.opts.efivarsDir, "SetupMode", 0x00)

			out, err := executeCommand(t, tableFlags(), sub, "--commit",
				"--efivars", env.opts.efivarsDir,
				"--keys-dir", env.opts.keysDir,
				"--uki", env.opts.ukiPath)
			assert.ErrorIs(t, err, uefi.ErrNotSetupMode)
			assert.Empty(t, out)
		})
	}
}

// TestCommands_CertificateOverrideFlags checks the flag wiring for each role:
// an explicit --<role>-cert that does not exist must fail with that role
// named, proving the override took precedence over the valid certificate in
// --keys-dir and that the earlier roles loaded.
func TestCommands_CertificateOverrideFlags(t *testing.T) {
	roles := []struct {
		flag string
		role string
	}{
		{flag: "--pk-cert", role: "PK"},
		{flag: "--kek-cert", role: "KEK"},
		{flag: "--db-cert", role: "DB"},
	}
	for _, sub := range []string{"enroll", "enforce"} {
		for _, r := range roles {
			t.Run(sub+"/"+r.role, func(t *testing.T) {
				env := newTestEnv(t)
				missing := filepath.Join(t.TempDir(), "absent.crt")

				_, err := executeCommand(t, tableFlags(), sub,
					"--efivars", env.opts.efivarsDir,
					"--keys-dir", env.opts.keysDir,
					r.flag, missing,
					"--uki", env.opts.ukiPath)

				var loadErr ErrCertificateLoad
				require.ErrorAs(t, err, &loadErr)
				assert.Equal(t, r.role, loadErr.Role)
				assert.Equal(t, missing, loadErr.Path)
				assert.ErrorIs(t, err, os.ErrNotExist)
			})
		}
	}
}
