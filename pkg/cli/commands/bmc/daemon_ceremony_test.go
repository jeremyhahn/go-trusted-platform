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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// Daemon-mode enroll and cert restore: the commands reach platformd over
// gRPC through the SDK client, exercised here against an in-process server.

const daemonFactoryPEM = "-----BEGIN CERTIFICATE-----\nZmFjdG9yeQ==\n-----END CERTIFICATE-----\n"

var daemonPin = strings.Repeat("ab", 32)

func daemonEnrollResponse() *platformv1.BMCEnrollResponse {
	return &platformv1.BMCEnrollResponse{
		DeviceId:        12,
		Endpoint:        "192.0.2.10:443",
		Hostname:        "node-01-bmc",
		DnsName:         "node-01-bmc.internal.",
		PinSpkiSha256:   daemonPin,
		FactoryCertPem:  []byte(daemonFactoryPEM),
		FactoryCertMeta: &platformv1.BMCFactoryCertMeta{Subject: "CN=factory"},
		Steps: []*platformv1.BMCEnrollStep{
			{Name: "trust", Ok: true, Detail: "pinned"},
			{Name: "dns-register", Ok: false},
		},
	}
}

// wantEnrollTable is the table summary for daemonEnrollResponse with its
// backup written under backupDir.
func wantEnrollTable(backupDir string) string {
	return "Device ID: 12\n" +
		"Endpoint:  192.0.2.10:443\n" +
		"Hostname:  node-01-bmc\n" +
		"DNS Name:  node-01-bmc.internal.\n" +
		"SPKI Pin:  " + daemonPin + "\n" +
		"Backup:    " + backupDir + "\n" +
		"\nCeremony Steps:\n" +
		"  ✓ trust" + strings.Repeat(" ", 16) + "pinned\n" +
		"  ✗ dns-register\n"
}

func TestDaemonEnroll_TableWithBackup(t *testing.T) {
	srv := &inProcBMCServer{enrollResp: daemonEnrollResponse()}
	table, _ := serveInProcBMC(t, srv)
	backups := t.TempDir()

	out, err := runBMC(t, table, "enroll", "--profile-id", "7",
		"--backups-dir", backups, "--rotate-password", "--dane-publish=false")
	require.NoError(t, err)

	backupDir := filepath.Join(backups, "node-01-bmc", "bmc")
	assert.Equal(t, wantEnrollTable(backupDir), out)
	pem, err := os.ReadFile(filepath.Join(backupDir, "factory-cert.pem"))
	require.NoError(t, err)
	assert.Equal(t, daemonFactoryPEM, string(pem))

	// Only the overrides the operator passed reach the daemon; the rest
	// stay unset so the profile's stored defaults apply.
	req := srv.enrollReq
	require.NotNil(t, req)
	assert.Equal(t, uint64(7), req.GetProfileId())
	require.NotNil(t, req.RotatePassword)
	assert.True(t, req.GetRotatePassword())
	require.NotNil(t, req.DanePublish)
	assert.False(t, req.GetDanePublish())
	assert.Nil(t, req.ReplaceCertificate)
	assert.Nil(t, req.DnsRegister)
}

// PLATFORMCTL_BACKUPS_DIR stands in for --backups-dir when the flag is absent.
func TestDaemonEnroll_BackupsDirFromEnv(t *testing.T) {
	srv := &inProcBMCServer{enrollResp: daemonEnrollResponse()}
	_, jsonFlags := serveInProcBMC(t, srv)
	backups := t.TempDir()
	t.Setenv("PLATFORMCTL_BACKUPS_DIR", backups)

	out, err := runBMC(t, jsonFlags, "enroll", "--profile-id", "7")
	require.NoError(t, err)

	var got struct {
		DeviceID  uint64 `json:"device_id,string"`
		BackupDir string `json:"backup_dir"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, uint64(12), got.DeviceID)
	assert.Equal(t, filepath.Join(backups, "node-01-bmc", "bmc"), got.BackupDir)
	assert.FileExists(t, filepath.Join(got.BackupDir, "enrollment.json"))
	assert.Nil(t, srv.enrollReq.RotatePassword)
}

func TestDaemonEnroll_NoBackupsDirNotice(t *testing.T) {
	srv := &inProcBMCServer{enrollResp: daemonEnrollResponse()}
	table, _ := serveInProcBMC(t, srv)

	var out string
	stderr, err := captureStderr(t, func() error {
		var runErr error
		out, runErr = runBMC(t, table, "enroll", "--profile-id", "7")
		return runErr
	})
	require.NoError(t, err)
	assert.Equal(t, "notice: --backups-dir not set; no client-side backup was written\n", stderr)
	assert.NotContains(t, out, "Backup:")
}

func TestDaemonEnroll_ServerError(t *testing.T) {
	srv := &inProcBMCServer{err: status.Error(codes.FailedPrecondition, "profile has no endpoint")}
	table, _ := serveInProcBMC(t, srv)

	_, err := runBMC(t, table, "enroll", "--profile-id", "7")
	var enrollErr *bmcsvc.ErrEnrollFailed
	require.ErrorAs(t, err, &enrollErr)
	assert.Equal(t, uint64(7), enrollErr.ProfileID)
	assert.Equal(t, codes.FailedPrecondition, status.Code(enrollErr.Cause))
}

// Each backup file that cannot be written fails the command with its path,
// even though the daemon-side enrollment already succeeded.
func TestDaemonEnroll_BackupWriteErrors(t *testing.T) {
	for _, name := range []string{"factory-cert.pem", "factory-cert.json", "enrollment.json"} {
		t.Run(name, func(t *testing.T) {
			srv := &inProcBMCServer{enrollResp: daemonEnrollResponse()}
			table, _ := serveInProcBMC(t, srv)
			backups := t.TempDir()
			// A directory where the file belongs makes the write fail.
			blocked := filepath.Join(backups, "node-01-bmc", "bmc", name)
			require.NoError(t, os.MkdirAll(blocked, 0o700))

			_, err := runBMC(t, table, "enroll", "--profile-id", "7", "--backups-dir", backups)
			var writeErr ErrBackupFileWriteFailed
			require.ErrorAs(t, err, &writeErr)
			assert.Equal(t, blocked, writeErr.Path)
		})
	}
}

// Without a CLI context the command cannot reach platformd.
func TestDaemonCeremonies_NoContext(t *testing.T) {
	noContext := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	tests := map[string][]string{
		"enroll":       {"enroll", "--profile-id", "7"},
		"cert restore": {"cert", "restore", "--profile-id", "7", "--factory"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runBMC(t, noContext, args...)
			var noCtx cli.ErrNoContextSet
			require.ErrorAs(t, err, &noCtx)
		})
	}
}

func TestDaemonCertRestore_Table(t *testing.T) {
	srv := &inProcBMCServer{restoreResp: &platformv1.BMCRestoreResponse{
		DeviceId: 12,
		Endpoint: "192.0.2.10:443",
		Hostname: "node-01-bmc",
		NewCertMeta: &platformv1.BMCFactoryCertMeta{
			Subject:    "CN=bmc.example",
			SpkiSha256: daemonPin,
		},
		Steps: []*platformv1.BMCEnrollStep{{Name: "restore", Ok: true}},
	}}
	table, _ := serveInProcBMC(t, srv)

	out, err := runBMC(t, table, "cert", "restore", "--profile-id", "7", "--factory")
	require.NoError(t, err)
	assert.Equal(t,
		"Device ID:  12\n"+
			"Endpoint:   192.0.2.10:443\n"+
			"Hostname:   node-01-bmc\n"+
			"New Cert Subject: CN=bmc.example\n"+
			"New Cert SPKI:    "+daemonPin+"\n"+
			"\nCeremony Steps:\n"+
			"  ✓ restore\n",
		out)
	require.NotNil(t, srv.restoreReq)
	assert.Equal(t, uint64(7), srv.restoreReq.GetProfileId())
}

func TestDaemonCertRestore_ServerError(t *testing.T) {
	srv := &inProcBMCServer{err: status.Error(codes.Unavailable, "bmc offline")}
	table, _ := serveInProcBMC(t, srv)

	_, err := runBMC(t, table, "cert", "restore", "--profile-id", "7", "--factory")
	var restoreErr *bmcsvc.ErrRestoreFailed
	require.ErrorAs(t, err, &restoreErr)
	assert.Equal(t, uint64(7), restoreErr.ProfileID)
	assert.Equal(t, codes.Unavailable, status.Code(restoreErr.Cause))
}
